"""Portable recipes compile into existing Artifact lifecycle objects locally."""
from typing import Literal
from uuid import UUID
from pydantic import Field, model_validator
from .collector_schemas import ArtifactBundleModel, ArtifactBundleSignature

FORMAT = "icheck.operations-package/v1"


class OperationComponent(ArtifactBundleModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,79}$")
    kind: Literal["workflow", "skill", "tool", "mcp", "collector", "connector"]
    spec: dict
    # Contracts exclude installation-local registry IDs. They are compared before
    # recompilation; merely matching a familiar tool name is insufficient.
    tool_contracts: list[dict] = Field(default_factory=list, max_length=100)


class OperationsPackage(ArtifactBundleModel):
    format_version: Literal["icheck.operations-package/v1"] = FORMAT
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,79}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    description: str = Field(min_length=1, max_length=4000)
    components: list[OperationComponent] = Field(min_length=1, max_length=20)
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def unique(self):
        if len({c.name for c in self.components}) != len(self.components):
            raise ValueError("Package component names must be unique")
        return self


class OperationsReview(ArtifactBundleModel):
    package: OperationsPackage
    signature: ArtifactBundleSignature | None = None
    # Connection selection is local, never a URL or an imported credential.
    connections: dict[str, UUID] = Field(default_factory=dict, max_length=20)
    mcp_servers: dict[str, str] = Field(default_factory=dict, max_length=20)


class OperationsInstall(OperationsReview):
    confirm: Literal[True]


class OperationsExport(ArtifactBundleModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,79}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    description: str = Field(min_length=1, max_length=4000)
    artifact_version_ids: list[UUID] = Field(default_factory=list, max_length=20)
    connector_providers: list[Literal["zabbix", "solarwinds_orion", "rest_webhook"]] = Field(default_factory=list, max_length=3)
