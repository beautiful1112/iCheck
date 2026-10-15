from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import Field, field_validator, model_validator

from .schemas import APIModel


LogProvider = Literal["loki"]
LogDirection = Literal["forward", "backward"]
LogBackendAuthType = Literal["none", "bearer", "basic", "header"]


class LogBackendCreate(APIModel):
    name: str = Field(min_length=1, max_length=255)
    provider: LogProvider
    query_base_url: str = Field(min_length=1, max_length=2048)
    auth_type: LogBackendAuthType = "none"
    auth_header_name: str | None = Field(default=None, max_length=128)
    credential_profile_ref: str | None = Field(default=None, max_length=255)
    device_label: str = Field(
        default="instance",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
    )
    allowed_labels: list[str] = Field(
        default_factory=lambda: [
            "instance",
            "job",
            "host",
            "hostname",
            "app",
            "service",
            "level",
            "severity",
            "namespace",
            "container",
            "source",
        ],
        min_length=1,
        max_length=32,
    )
    enabled: bool = True
    created_by: str = Field(min_length=1, max_length=255)

    @field_validator("allowed_labels")
    @classmethod
    def validate_allowed_labels(cls, value: list[str]) -> list[str]:
        import re

        normalized = list(dict.fromkeys(item.strip() for item in value))
        if len(normalized) != len(value) or any(
            not item
            or len(item) > 128
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item) is None
            for item in normalized
        ):
            raise ValueError("allowed_labels must contain unique Loki label names")
        return normalized

    @field_validator("auth_header_name", "credential_profile_ref")
    @classmethod
    def strip_optional_auth_value(cls, value: str | None) -> str | None:
        return value.strip() or None if value is not None else None

    @model_validator(mode="after")
    def validate_device_label(self) -> "LogBackendCreate":
        from .services.observability_auth import validate_backend_auth_contract

        if self.device_label not in self.allowed_labels:
            raise ValueError("device_label must be present in allowed_labels")
        validate_backend_auth_contract(
            auth_type=self.auth_type,
            auth_header_name=self.auth_header_name,
            credential_profile_ref=self.credential_profile_ref,
        )
        return self


class LogBackendUpdate(APIModel):
    expected_revision: int = Field(ge=0)
    name: str = Field(min_length=1, max_length=255)
    provider: LogProvider
    query_base_url: str = Field(min_length=1, max_length=2048)
    auth_type: LogBackendAuthType = "none"
    auth_header_name: str | None = Field(default=None, max_length=128)
    credential_profile_ref: str | None = Field(default=None, max_length=255)
    device_label: str = Field(
        default="instance",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
    )
    allowed_labels: list[str] = Field(min_length=1, max_length=32)
    enabled: bool = True
    actor: str = Field(min_length=1, max_length=255)

    @field_validator("allowed_labels")
    @classmethod
    def validate_allowed_labels(cls, value: list[str]) -> list[str]:
        import re

        normalized = list(dict.fromkeys(item.strip() for item in value))
        if len(normalized) != len(value) or any(
            not item
            or len(item) > 128
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item) is None
            for item in normalized
        ):
            raise ValueError("allowed_labels must contain unique Loki label names")
        return normalized

    @field_validator("auth_header_name", "credential_profile_ref")
    @classmethod
    def strip_optional_auth_value(cls, value: str | None) -> str | None:
        return value.strip() or None if value is not None else None

    @model_validator(mode="after")
    def validate_contract(self) -> "LogBackendUpdate":
        from .services.observability_auth import validate_backend_auth_contract

        if self.device_label not in self.allowed_labels:
            raise ValueError("device_label must be present in allowed_labels")
        validate_backend_auth_contract(
            auth_type=self.auth_type,
            auth_header_name=self.auth_header_name,
            credential_profile_ref=self.credential_profile_ref,
        )
        return self


class LogBackendRead(APIModel):
    id: str
    name: str
    provider: str
    query_base_url: str
    auth_type: LogBackendAuthType
    auth_header_name: str | None
    credential_profile_ref: str | None
    device_label: str
    allowed_labels: list[str]
    enabled: bool
    revision: int
    created_by: str
    last_checked_at: datetime | None
    last_health_status: str | None
    last_health_error: str | None
    created_at: datetime
    updated_at: datetime


class LogQueryRange(APIModel):
    query: str = Field(min_length=1, max_length=8192)
    start: datetime
    end: datetime
    direction: LogDirection = "backward"
    limit: int = Field(default=500, ge=1, le=5000)
    timeout_seconds: int = Field(default=15, ge=1, le=60)
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_range(self) -> "LogQueryRange":
        start = self.start.replace(tzinfo=UTC) if self.start.tzinfo is None else self.start.astimezone(UTC)
        end = self.end.replace(tzinfo=UTC) if self.end.tzinfo is None else self.end.astimezone(UTC)
        if end <= start:
            raise ValueError("end must be later than start")
        if end - start > timedelta(days=7):
            raise ValueError("log query range must not exceed seven days")
        return self


class DeviceLogQueryRange(APIModel):
    start: datetime
    end: datetime
    direction: LogDirection = "backward"
    limit: int = Field(default=500, ge=1, le=5000)
    timeout_seconds: int = Field(default=15, ge=1, le=60)
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_range(self) -> "DeviceLogQueryRange":
        start = self.start.replace(tzinfo=UTC) if self.start.tzinfo is None else self.start.astimezone(UTC)
        end = self.end.replace(tzinfo=UTC) if self.end.tzinfo is None else self.end.astimezone(UTC)
        if end <= start:
            raise ValueError("end must be later than start")
        if end - start > timedelta(days=7):
            raise ValueError("log query range must not exceed seven days")
        return self


class LogEntry(APIModel):
    timestamp: datetime
    labels: dict[str, str]
    line: str


class LogQueryResult(APIModel):
    backend_id: str
    provider: str
    entries: list[LogEntry]
    truncated: bool
    warnings: list[str] = Field(default_factory=list)
    queried_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class LogBackendHealth(APIModel):
    backend_id: str
    status: Literal["healthy", "unhealthy"]
    checked_at: datetime
    error: str | None = None
