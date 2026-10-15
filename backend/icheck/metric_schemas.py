from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .schemas import APIModel


MetricProvider = Literal["prometheus", "victoriametrics", "mimir", "thanos"]
MetricBackendAuthType = Literal["none", "bearer", "basic", "header"]


class MetricBackendCreate(APIModel):
    name: str = Field(min_length=1, max_length=255)
    provider: MetricProvider
    query_base_url: str = Field(min_length=1, max_length=2048)
    remote_write_url: str | None = Field(default=None, max_length=2048)
    auth_type: MetricBackendAuthType = "none"
    auth_header_name: str | None = Field(default=None, max_length=128)
    credential_profile_ref: str | None = Field(default=None, max_length=255)
    external_labels: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    created_by: str = Field(min_length=1, max_length=255)

    @field_validator("auth_header_name", "credential_profile_ref")
    @classmethod
    def strip_optional_auth_value(cls, value: str | None) -> str | None:
        return value.strip() or None if value is not None else None

    @model_validator(mode="after")
    def validate_auth_contract(self) -> "MetricBackendCreate":
        from .services.observability_auth import validate_backend_auth_contract

        validate_backend_auth_contract(
            auth_type=self.auth_type,
            auth_header_name=self.auth_header_name,
            credential_profile_ref=self.credential_profile_ref,
        )
        return self


class MetricBackendUpdate(APIModel):
    expected_revision: int = Field(ge=0)
    name: str = Field(min_length=1, max_length=255)
    provider: MetricProvider
    query_base_url: str = Field(min_length=1, max_length=2048)
    remote_write_url: str | None = Field(default=None, max_length=2048)
    auth_type: MetricBackendAuthType = "none"
    auth_header_name: str | None = Field(default=None, max_length=128)
    credential_profile_ref: str | None = Field(default=None, max_length=255)
    external_labels: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    actor: str = Field(min_length=1, max_length=255)

    @field_validator("auth_header_name", "credential_profile_ref")
    @classmethod
    def strip_optional_auth_value(cls, value: str | None) -> str | None:
        return value.strip() or None if value is not None else None

    @model_validator(mode="after")
    def validate_auth_contract(self) -> "MetricBackendUpdate":
        from .services.observability_auth import validate_backend_auth_contract

        validate_backend_auth_contract(
            auth_type=self.auth_type,
            auth_header_name=self.auth_header_name,
            credential_profile_ref=self.credential_profile_ref,
        )
        return self


class MetricBackendRead(APIModel):
    id: str
    name: str
    provider: str
    query_base_url: str
    remote_write_url: str | None
    auth_type: MetricBackendAuthType
    auth_header_name: str | None
    credential_profile_ref: str | None
    external_labels: dict[str, str]
    enabled: bool
    revision: int
    created_by: str
    last_checked_at: datetime | None
    last_health_status: str | None
    last_health_error: str | None
    created_at: datetime
    updated_at: datetime


class PrometheusInstantQuery(APIModel):
    query: str = Field(min_length=1, max_length=8192)
    time: datetime | None = None
    timeout_seconds: int = Field(default=15, ge=1, le=60)
    limit: int = Field(default=100, ge=1, le=1000)
    actor: str = Field(min_length=1, max_length=255)


class PrometheusRangeQuery(APIModel):
    query: str = Field(min_length=1, max_length=8192)
    start: datetime
    end: datetime
    step_seconds: int = Field(default=60, ge=1, le=3600)
    timeout_seconds: int = Field(default=15, ge=1, le=60)
    limit: int = Field(default=100, ge=1, le=1000)
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_range_budget(self) -> PrometheusRangeQuery:
        start = (
            self.start.replace(tzinfo=UTC)
            if self.start.tzinfo is None
            else self.start.astimezone(UTC)
        )
        end = (
            self.end.replace(tzinfo=UTC)
            if self.end.tzinfo is None
            else self.end.astimezone(UTC)
        )
        if end <= start:
            raise ValueError("end must be later than start")
        if end - start > timedelta(days=31):
            raise ValueError("query range must not exceed 31 days")
        points = (end - start).total_seconds() / self.step_seconds
        if points > 11_000:
            raise ValueError("query range must not exceed 11000 evaluation steps")
        return self


class PrometheusQueryResult(APIModel):
    backend_id: str
    mode: Literal["instant", "range"]
    result_type: str
    result: Any
    warnings: list[str] = Field(default_factory=list)
    infos: list[str] = Field(default_factory=list)
    queried_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class MetricBackendHealth(APIModel):
    backend_id: str
    status: Literal["healthy", "unhealthy"]
    checked_at: datetime
    error: str | None = None
