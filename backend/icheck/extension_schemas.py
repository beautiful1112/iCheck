"""Executable extension packages; authoring is not installation authority."""
import re
from copy import deepcopy
from uuid import UUID
from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from .schema_validation import validate_instance
from .studio_schemas import StudioStrictModel

EXTENSION_FORMAT = "icheck.mcp-extension/v1"
EXTENSION_RUNTIME = "icheck_netmiko_extension_v1"
NETMIKO_DEPENDENCY = "netmiko==4.8.0"
DEVICE_INPUT = {"type": "object", "properties": {"device_id": {"type": "string", "format": "uuid"}},
                "required": ["device_id"], "additionalProperties": False}
BACKUP_OUTPUT = {"type": "object", "properties": {
    "backup_id": {"type": "string", "format": "uuid"},
    "created_at": {"type": "string"}, "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "bytes": {"type": "integer", "minimum": 1}},
    "required": ["backup_id", "created_at", "sha256", "bytes"], "additionalProperties": False}


class ExtensionFixture(StudioStrictModel):
    name: str = Field(min_length=1, max_length=128)
    readings: list[str | dict[str, Any]] = Field(min_length=1, max_length=8)
    expected_output: dict[str, Any]


def _extension_tool_json_schema(schema: dict[str, Any]) -> None:
    """Expose operation-specific fixtures without changing stored package shapes."""
    base = deepcopy(schema)
    variants = []
    for operation in ("read", "backup"):
        variant = deepcopy(base)
        properties = variant["properties"]
        properties["operation"] = {"type": "string", "enum": [operation]}
        fixture = ExtensionFixture.model_json_schema()
        fixture["properties"]["readings"]["items"] = (
            {"type": "string"} if operation == "read" else deepcopy(BACKUP_OUTPUT)
        )
        if operation == "backup":
            properties["commands"]["maxItems"] = 1
            fixture["properties"]["readings"]["maxItems"] = 1
            fixture["properties"]["expected_output"] = deepcopy(BACKUP_OUTPUT)
        properties["fixtures"]["items"] = fixture
        variants.append(variant)
    schema.clear()
    schema.update({"title": base.get("title", "ExtensionTool"), "anyOf": variants})


class ExtensionTool(StudioStrictModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid", json_schema_extra=_extension_tool_json_schema)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    description: str = Field(min_length=1, max_length=2000)
    operation: Literal["read", "backup"]
    commands: list[str] = Field(min_length=1, max_length=8)
    # Generated code consumes acquired data, never a credential or a live SSH object.
    source: str = Field(min_length=1, max_length=16000)
    output_schema: dict[str, Any]
    fixtures: list[ExtensionFixture] = Field(min_length=1, max_length=5)

    @model_validator(mode="after")
    def read_boundary(self):
        backups = {"show running-config", "show configuration", "display current-configuration"}
        # Full commands only: aliases such as `show run` otherwise bypass the
        # protected backup path. New command families need a reviewed adapter policy.
        reads = re.compile(r"(?:show (?:interfaces?(?: (?:status|brief|description|descriptions|terse))?|ip interface brief|version)|display (?:interface(?: brief)?|ip interface brief|version))")
        for command in self.commands:
            if not re.fullmatch(r"(?:show|display) [A-Za-z0-9 /_.:-]{1,160}", command):
                raise ValueError("Extension commands must be fixed show/display reads without shell operators")
            is_backup = command in backups
            if self.operation == "backup" and (not is_backup or len(self.commands) != 1):
                raise ValueError("Backup tools require one supported configuration read")
            if self.operation == "read" and not reads.fullmatch(command):
                raise ValueError("This Netmiko runtime supports full interface/version reads; configurations require the protected backup operation")
        if len(set(self.commands)) != len(self.commands):
            raise ValueError("Extension commands must be unique")
        if len({fixture.name for fixture in self.fixtures}) != len(self.fixtures):
            raise ValueError("Extension fixture names must be unique")
        if self.operation == "backup" and self.output_schema != BACKUP_OUTPUT:
            raise ValueError("Backup tools return only the protected backup receipt schema")
        for fixture in self.fixtures:
            if len(fixture.readings) != len(self.commands):
                raise ValueError("Fixture must represent every declared command")
            if self.operation == "read":
                if any(not isinstance(item, str) for item in fixture.readings):
                    raise ValueError("Read fixtures require command output strings")
            else:
                # Reject stringified JSON; never silently repair a generated package.
                for receipt in (fixture.readings[0], fixture.expected_output):
                    validate_instance(receipt, BACKUP_OUTPUT, "synthetic protected backup receipt")
                    UUID(receipt["backup_id"])
        return self


class GeneratedExtensionSpec(StudioStrictModel):
    format_version: Literal["icheck.mcp-extension/v1"] = EXTENSION_FORMAT
    artifact_name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,79}$")
    description: str = Field(min_length=1, max_length=4000)
    runtime: Literal["icheck_netmiko_extension_v1"] = EXTENSION_RUNTIME
    # Native runtime resolves this audited dependency; generated installers and URLs are forbidden.
    dependencies: list[Literal["netmiko==4.8.0"]] = Field(min_length=1, max_length=1)
    device_type: Literal["cisco_ios", "cisco_nxos", "arista_eos", "juniper_junos", "huawei", "hp_comware"]
    tools: list[ExtensionTool] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def unique_tools(self):
        if len({tool.name for tool in self.tools}) != len(self.tools):
            raise ValueError("Extension tool names must be unique")
        return self


class ExtensionTargetTest(StudioStrictModel):
    request_key: UUID
    artifact_version_id: UUID
    connection_id: UUID
    tool_name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    host_public_key: str | None = Field(default=None, min_length=40, max_length=4096)


class SSHHostIdentityConfirm(StudioStrictModel):
    binding_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    host_public_key: str = Field(min_length=40, max_length=4096)
    accept_changed: bool = False


class SSHCompatibilityChange(StudioStrictModel):
    binding_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile: Literal["modern", "legacy_cisco_v1"]
    accept_legacy_risk: bool = False


class ExtensionInstall(StudioStrictModel):
    artifact_version_id: UUID
    expected_revision: int = Field(ge=0)
    access_mode: Literal["authorized_inventory"] | None = None
    test_ids: list[UUID] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def installation_authority(self):
        if self.access_mode and self.test_ids:
            raise ValueError("Choose package approval or legacy target tests, not both")
        if not self.access_mode and not self.test_ids:
            raise ValueError("Explicit package approval is required")
        return self


class ExtensionLifecycleChange(StudioStrictModel):
    expected_revision: int = Field(ge=1)
