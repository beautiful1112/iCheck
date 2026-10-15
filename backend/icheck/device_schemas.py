from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .activation_schemas import DeviceConnectionActivationRead
from .schemas import APIModel, normalize_ip
from .http_metrics import HTTPMonitorSpec


DeviceKind = Literal[
    "firewall",
    "switch",
    "router",
    "linux_server",
    "windows_server",
    "wireless_controller",
    "wireless_access_point",
    "physical_server",
    "load_balancer",
    "storage",
    "hypervisor",
    "other",
]
DeviceProtocol = Literal[
    "snmp",
    "https_api",
    "ssh",
    "windows_exporter",
    "node_exporter",
    "cadvisor",
    "vmware_exporter",
    "winrm_https",
    "icmp",
]


def normalize_optional_site(value: str | None) -> str | None:
    return value.strip() or None if value is not None else None


class DeviceLocation(APIModel):
    """Descriptive placement, never a credential or Collector authorization scope."""
    model_config = ConfigDict(extra="forbid")
    zone: str | None = Field(default=None, max_length=128)
    building: str | None = Field(default=None, max_length=128)
    floor: str | None = Field(default=None, max_length=128)
    room: str | None = Field(default=None, max_length=128)
    rack: str | None = Field(default=None, max_length=128)
    height: int | None = Field(default=None, ge=1, le=1000, strict=True)

    @field_validator("zone", "building", "floor", "room", "rack")
    @classmethod
    def trim_location(cls, value: str | None) -> str | None:
        return normalize_optional_site(value)


class DeviceOnboardingModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


def normalize_device_labels(value: dict[str, str]) -> dict[str, str]:
    if len(value) > 50:
        raise ValueError("labels must not contain more than 50 entries")
    normalized: dict[str, str] = {}
    for key, item in value.items():
        normalized_key = key.strip()
        normalized_value = item.strip()
        if not normalized_key or len(normalized_key) > 64:
            raise ValueError("label names must contain 1 to 64 characters")
        if len(normalized_value) > 255:
            raise ValueError("label values must not exceed 255 characters")
        normalized[normalized_key] = normalized_value
    return normalized


class DeviceConnectionInput(DeviceOnboardingModel):
    protocol: DeviceProtocol
    port: int | None = Field(default=None, ge=1, le=65535)
    credential_profile_ref: str | None = Field(default=None, max_length=255)
    worker_selector: dict[str, str] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class DeviceNativeSSHCreate(DeviceOnboardingModel):
    expected_revision: int = Field(ge=1, strict=True)
    port: int = Field(default=22, ge=1, le=65535, strict=True)
    credential_profile_ref: str = Field(min_length=1, max_length=255)


class DeviceConnectionPreflightRead(DeviceOnboardingModel):
    id: str
    connection_id: str
    worker_id: str
    status: str
    lease_expires_at: datetime
    target_host: str | None
    site_snapshot: str | None
    started_at: datetime
    finished_at: datetime | None
    latency_ms: int | None
    evidence: dict[str, Any]
    error: str | None


class DeviceConnectionRead(DeviceConnectionInput):
    id: str
    device_id: str
    adapter_type: str
    verification_status: str
    last_verified_at: datetime | None
    last_verification_error: str | None
    last_verification_worker_id: str | None
    last_verification_latency_ms: int | None
    last_verification_evidence: dict[str, Any]
    verification_worker_id: str | None
    verification_lease_expires_at: datetime | None
    next_verification_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime
    activations: list[DeviceConnectionActivationRead] = Field(default_factory=list)
    activation: DeviceConnectionActivationRead | None = None


class DeviceOnboardCreate(DeviceOnboardingModel):
    name: str = Field(min_length=1, max_length=255)
    kind: DeviceKind
    management_ip: str
    vendor: str | None = Field(default=None, max_length=128)
    model: str | None = Field(default=None, max_length=128)
    site: str | None = Field(default=None, max_length=128)
    location: DeviceLocation = Field(default_factory=DeviceLocation)
    labels: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    request_monitoring: bool = False
    connections: list[DeviceConnectionInput] = Field(min_length=1, max_length=8)
    created_by: str = Field(min_length=1, max_length=255)

    @field_validator("site")
    @classmethod
    def optional_site(cls, value: str | None) -> str | None:
        return normalize_optional_site(value)

    @field_validator("management_ip")
    @classmethod
    def validate_management_ip(cls, value: str) -> str:
        return normalize_ip(value)

    @field_validator("labels")
    @classmethod
    def validate_labels(cls, value: dict[str, str]) -> dict[str, str]:
        return normalize_device_labels(value)

    @model_validator(mode="after")
    def validate_unique_protocols(self) -> DeviceOnboardCreate:
        protocols = [connection.protocol for connection in self.connections]
        if len(protocols) != len(set(protocols)):
            raise ValueError("each connection protocol may appear only once")
        return self


class DeviceOnboardRead(DeviceOnboardingModel):
    id: str
    name: str
    discovered_name: str | None = None
    kind: str
    # Imported/discovered inventory may not yet have a management address.
    # New monitoring enrollment and identity correction still require a valid IP.
    management_ip: str | None
    vendor: str | None
    model: str | None
    site: str | None
    location: DeviceLocation = Field(default_factory=DeviceLocation)
    labels: dict[str, str]
    onboarding_status: str
    enabled: bool
    revision: int
    identity_revision: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    connections: list[DeviceConnectionRead] = Field(default_factory=list)


AssetCategory = Literal["wired", "wireless", "firewalls", "servers", "storage", "other"]


class DeviceHealthConnectionRead(APIModel):
    connection_id: str
    protocol: str
    state: str
    observed_at: datetime | None
    sample_age_seconds: float | None
    freshness_limit_seconds: int
    reason: str
    source: str


class DeviceHealthRead(APIModel):
    device_id: str
    state: Literal["up", "poll_failed", "degraded", "stale", "unknown", "disabled", "pending", "not_monitored"]
    reason: str
    checked_at: datetime
    backend_id: str | None
    connections: list[DeviceHealthConnectionRead]


class DeviceHealthPage(APIModel):
    items: list[DeviceHealthRead]
    checked_at: datetime
    diagnostic: str | None
    boundary: str


class DeviceMetadataUpdate(DeviceOnboardingModel):
    expected_revision: int = Field(ge=1)
    kind: DeviceKind
    vendor: str | None = Field(default=None, max_length=128)
    model: str | None = Field(default=None, max_length=128)
    labels: dict[str, str] = Field(default_factory=dict)
    actor: str = Field(min_length=1, max_length=255)
    # Omitted by older clients: preserve existing placement, do not clear it.
    location: DeviceLocation | None = None

    @field_validator("labels")
    @classmethod
    def validate_labels(cls, value: dict[str, str]) -> dict[str, str]:
        return normalize_device_labels(value)


class DeviceSNMPConfigurationUpdate(DeviceOnboardingModel):
    expected_revision: int = Field(ge=1)
    modules: list[str] = Field(min_length=1, max_length=8)
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=1000)


class DeviceHTTPConfigurationUpdate(DeviceOnboardingModel):
    expected_revision: int = Field(ge=1)
    port: int = Field(ge=1, le=65535)
    http_monitor: HTTPMonitorSpec
    credential_profile_ref: str | None = Field(default=None, max_length=128)
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=1000)


class HTTPRequestPreview(DeviceOnboardingModel):
    curl: str = Field(min_length=1, max_length=8192)


class DeviceIdentityCorrectionInput(DeviceOnboardingModel):
    expected_revision: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=255)
    management_ip: str
    site: str | None = Field(default=None, max_length=128)
    credential_profile_refs: dict[str, str | None] = Field(default_factory=dict)

    @field_validator("site")
    @classmethod
    def optional_site(cls, value: str | None) -> str | None:
        return normalize_optional_site(value)

    @field_validator("name")
    @classmethod
    def normalize_identity_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("device name must not be blank")
        return normalized

    @field_validator("management_ip")
    @classmethod
    def validate_management_ip(cls, value: str) -> str:
        return normalize_ip(value)

    @field_validator("credential_profile_refs")
    @classmethod
    def validate_credential_refs(
        cls, value: dict[str, str | None]
    ) -> dict[str, str | None]:
        if len(value) > 8:
            raise ValueError("at most 8 connection credential references are allowed")
        for connection_id, reference in value.items():
            if not connection_id or len(connection_id) > 36:
                raise ValueError("invalid connection id in credential_profile_refs")
            if reference is not None and (not reference.strip() or len(reference) > 255):
                raise ValueError("invalid credential profile reference")
        return value


class DeviceIdentityCorrectionCommit(DeviceIdentityCorrectionInput):
    preview_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)


class DeviceIdentityCorrectionConnection(DeviceOnboardingModel):
    connection_id: str
    protocol: str
    current_credential_profile_ref: str | None
    proposed_credential_profile_ref: str | None
    proposed_worker_selector: dict[str, str]


class DeviceIdentityCorrectionPreview(DeviceOnboardingModel):
    device_id: str
    expected_revision: int
    current: dict[str, str | None]
    proposed: dict[str, str | None]
    connections: list[DeviceIdentityCorrectionConnection]
    blockers: list[str]
    warnings: list[str]
    preview_hash: str
    can_commit: bool


class DeviceOnboardPage(DeviceOnboardingModel):
    items: list[DeviceOnboardRead]
    next_cursor: str | None


class DevicePreflightClaim(DeviceOnboardingModel):
    max_assignments: int = Field(default=1, ge=1, le=20)
    lease_seconds: int = Field(default=60, ge=15, le=600)


class DevicePreflightAssignment(DeviceOnboardingModel):
    preflight_id: str
    lease_token: str
    lease_expires_at: datetime
    connection_id: str
    device_id: str
    device_name: str
    target_host: str
    protocol: DeviceProtocol
    adapter_type: str
    port: int | None
    configuration: dict[str, Any]
    credential_profile_ref: str | None
    credential_provider: str | None = None
    credential_revision: int | None = Field(default=None, ge=0)


class DevicePreflightComplete(DeviceOnboardingModel):
    lease_token: str = Field(min_length=20, max_length=512)
    status: Literal["verified", "failed"]
    latency_ms: int | None = Field(default=None, ge=0, le=300_000)
    evidence: dict[str, Any] = Field(default_factory=dict)
    error: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def validate_outcome(self) -> DevicePreflightComplete:
        if self.status == "verified" and self.error:
            raise ValueError("verified preflights cannot include an error")
        if self.status == "failed" and not self.error:
            raise ValueError("failed preflights require an error")
        return self


class DeviceConnectionStateChange(DeviceOnboardingModel):
    expected_revision: int = Field(ge=1)
    enabled: bool = Field(strict=True)
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=1000)


class DeviceVerificationRetry(DeviceOnboardingModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)
