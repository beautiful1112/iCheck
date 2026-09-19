from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .activation_schemas import DeviceConnectionActivationRead
from .schemas import APIModel, normalize_ip


DeviceKind = Literal[
    "firewall",
    "switch",
    "router",
    "linux_server",
    "windows_server",
    "wireless_controller",
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
    "winrm_https",
    "icmp",
]


class DeviceOnboardingModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class DeviceConnectionInput(DeviceOnboardingModel):
    protocol: DeviceProtocol
    port: int | None = Field(default=None, ge=1, le=65535)
    credential_profile_ref: str | None = Field(default=None, max_length=255)
    worker_selector: dict[str, str] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class DeviceConnectionPreflightRead(DeviceOnboardingModel):
    id: str
    connection_id: str
    worker_id: str
    status: str
    lease_expires_at: datetime
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
    activation: DeviceConnectionActivationRead | None = None


class DeviceOnboardCreate(DeviceOnboardingModel):
    name: str = Field(min_length=1, max_length=255)
    kind: DeviceKind
    management_ip: str
    vendor: str | None = Field(default=None, max_length=128)
    model: str | None = Field(default=None, max_length=128)
    site: str = Field(min_length=1, max_length=128)
    labels: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    connections: list[DeviceConnectionInput] = Field(min_length=1, max_length=8)
    created_by: str = Field(min_length=1, max_length=255)

    @field_validator("management_ip")
    @classmethod
    def validate_management_ip(cls, value: str) -> str:
        return normalize_ip(value)

    @field_validator("labels")
    @classmethod
    def validate_labels(cls, value: dict[str, str]) -> dict[str, str]:
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

    @model_validator(mode="after")
    def validate_unique_protocols(self) -> DeviceOnboardCreate:
        protocols = [connection.protocol for connection in self.connections]
        if len(protocols) != len(set(protocols)):
            raise ValueError("each connection protocol may appear only once")
        return self


class DeviceOnboardRead(DeviceOnboardingModel):
    id: str
    name: str
    kind: str
    management_ip: str
    vendor: str | None
    model: str | None
    site: str | None
    labels: dict[str, str]
    onboarding_status: str
    enabled: bool
    created_by: str
    created_at: datetime
    updated_at: datetime
    connections: list[DeviceConnectionRead] = Field(default_factory=list)


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


class DeviceVerificationRetry(DeviceOnboardingModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)
