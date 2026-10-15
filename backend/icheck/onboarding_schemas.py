from typing import Literal
from pydantic import ConfigDict, Field
from .device_schemas import DeviceKind, DeviceProtocol, DeviceLocation, normalize_optional_site
from .schemas import APIModel, normalize_ip
from pydantic import field_validator


class OnboardingTarget(APIModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    management_ip: str
    kind: DeviceKind = "other"
    location: DeviceLocation = Field(default_factory=DeviceLocation)

    @field_validator("management_ip")
    @classmethod
    def ip(cls, value):
        return normalize_ip(value)


class OnboardingInput(APIModel):
    model_config = ConfigDict(extra="forbid")
    site: str | None = Field(default=None, max_length=128)
    protocol: DeviceProtocol = "snmp"
    credential_profile_ref: str = Field(min_length=1, max_length=255)
    devices: list[OnboardingTarget] = Field(min_length=1, max_length=50)
    port: int | None = Field(default=None, ge=1, le=65535)
    modules: list[str] = Field(default_factory=lambda: ["if_mib"], min_length=1, max_length=8)

    @field_validator("site")
    @classmethod
    def optional_site(cls, value: str | None) -> str | None:
        return normalize_optional_site(value)


class OnboardingApprove(OnboardingInput):
    preview_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    reason: str = Field(min_length=1, max_length=1000)
