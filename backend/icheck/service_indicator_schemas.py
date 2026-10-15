from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .schemas import APIModel


ARTIFACT_INDICATOR_CONTRACT = "icheck.service-indicator-observation/v1"


ServiceIndicatorKind = Literal[
    "availability",
    "latency",
    "error_rate",
    "throughput",
    "saturation",
    "business",
    "custom",
]
ServiceIndicatorSourceType = Literal[
    "prometheus", "api", "collector", "business_system", "manual"
]
ServiceIndicatorBreachDirection = Literal["above", "below", "none"]
ServiceIndicatorThresholdStatus = Literal[
    "healthy", "warning", "critical", "informational"
]
ServiceIndicatorEffectiveStatus = Literal[
    "unknown", "stale", "healthy", "warning", "critical", "informational"
]
IndicatorReduction = Literal["single", "sum", "avg", "min", "max"]
IndicatorPollRunState = Literal[
    "pending", "processing", "retry", "succeeded", "dead_letter"
]


class ServiceIndicatorAPIModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class ThresholdContract(ServiceIndicatorAPIModel):
    breach_direction: ServiceIndicatorBreachDirection = "none"
    warning_threshold: float | None = None
    critical_threshold: float | None = None

    @field_validator("warning_threshold", "critical_threshold")
    @classmethod
    def finite_threshold(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("thresholds must be finite")
        return value

    @model_validator(mode="after")
    def coherent_thresholds(self):
        warning = self.warning_threshold
        critical = self.critical_threshold
        if self.breach_direction == "none":
            if warning is not None or critical is not None:
                raise ValueError("informational indicators cannot define thresholds")
            return self
        if warning is None and critical is None:
            raise ValueError("a thresholded indicator requires at least one threshold")
        if warning is not None and critical is not None:
            if self.breach_direction == "above" and critical <= warning:
                raise ValueError("an above critical threshold must exceed warning")
            if self.breach_direction == "below" and critical >= warning:
                raise ValueError("a below critical threshold must be below warning")
        return self


class ServiceIndicatorCreate(ThresholdContract):
    expected_service_revision: int = Field(ge=1)
    indicator_key: str = Field(
        min_length=2,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=10_000)
    kind: ServiceIndicatorKind
    unit: str = Field(min_length=1, max_length=64)
    source_type: ServiceIndicatorSourceType
    source_ref: str = Field(min_length=1, max_length=1024)
    freshness_seconds: int = Field(default=300, ge=10, le=2_592_000)
    actor: str = Field(min_length=1, max_length=255)


class ServiceIndicatorUpdate(ThresholdContract):
    expected_revision: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10_000)
    kind: ServiceIndicatorKind | None = None
    unit: str | None = Field(default=None, min_length=1, max_length=64)
    source_type: ServiceIndicatorSourceType | None = None
    source_ref: str | None = Field(default=None, min_length=1, max_length=1024)
    freshness_seconds: int | None = Field(default=None, ge=10, le=2_592_000)
    enabled: bool | None = None
    actor: str = Field(min_length=1, max_length=255)


class ServiceIndicatorObservationCreate(ServiceIndicatorAPIModel):
    source_observation_id: str = Field(min_length=1, max_length=255)
    value: float
    measurement_quality: Literal["measured", "estimated", "manual"] = "measured"
    dimensions: dict[str, str] = Field(default_factory=dict)
    evidence_ref: str | None = Field(default=None, max_length=2048)
    observed_at: datetime
    actor: str = Field(min_length=1, max_length=255)

    @field_validator("value")
    @classmethod
    def finite_value(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("value must be finite")
        return value

    @field_validator("dimensions")
    @classmethod
    def bounded_dimensions(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 32:
            raise ValueError("dimensions cannot contain more than 32 entries")
        if any(len(key) > 128 or len(item) > 512 for key, item in value.items()):
            raise ValueError("dimension key or value is too long")
        return value


class ServiceIndicatorObservationRead(ServiceIndicatorAPIModel):
    id: str
    definition_id: str
    source_observation_id: str
    value: float
    measurement_quality: Literal["measured", "estimated", "manual"]
    dimensions: dict[str, str]
    evidence_ref: str | None
    threshold_status: ServiceIndicatorThresholdStatus
    freshness_status: Literal["fresh", "stale"]
    effective_status: ServiceIndicatorEffectiveStatus
    observed_at: datetime
    expires_at: datetime
    ingested_at: datetime
    created_by: str


class ServiceIndicatorRead(ServiceIndicatorAPIModel):
    id: str
    service_id: str
    indicator_key: str
    name: str
    description: str
    kind: ServiceIndicatorKind
    unit: str
    source_type: ServiceIndicatorSourceType
    source_ref: str
    breach_direction: ServiceIndicatorBreachDirection
    warning_threshold: float | None
    critical_threshold: float | None
    freshness_seconds: int
    enabled: bool
    revision: int
    effective_status: ServiceIndicatorEffectiveStatus
    latest_observation: ServiceIndicatorObservationRead | None
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class ArtifactIndicatorEnvelope(ServiceIndicatorAPIModel):
    contract_version: Literal["icheck.service-indicator-observation/v1"]
    binding_key: str = Field(
        min_length=2,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    value: float
    measurement_quality: Literal["measured", "estimated"] = "measured"
    dimensions: dict[str, str] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def finite_envelope_value(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("value must be finite")
        return value

    @field_validator("dimensions")
    @classmethod
    def bounded_envelope_dimensions(
        cls, value: dict[str, str]
    ) -> dict[str, str]:
        if len(value) > 32:
            raise ValueError("dimensions cannot contain more than 32 entries")
        if any(len(key) > 128 or len(item) > 512 for key, item in value.items()):
            raise ValueError("dimension key or value is too long")
        return value


class ServiceIndicatorArtifactBindingCreate(ServiceIndicatorAPIModel):
    expected_indicator_revision: int = Field(ge=1)
    artifact_version_id: str = Field(min_length=1, max_length=36)
    producer_kind: Literal["collector", "workflow"]
    binding_key: str = Field(
        min_length=2,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    producer_tool_name: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    output_mapping: dict[str, str] = Field(default_factory=dict, max_length=3)
    actor: str = Field(min_length=1, max_length=255)

    @field_validator("output_mapping")
    @classmethod
    def valid_output_mapping(cls, value: dict[str, str]) -> dict[str, str]:
        if set(value) - {"value", "observed_at", "dimensions"}:
            raise ValueError("output mapping contains unsupported fields")
        for path in value.values():
            if (
                not path
                or len(path) > 512
                or any(not part or len(part) > 128 for part in path.split("."))
            ):
                raise ValueError("output mapping path is invalid")
        return value

    @model_validator(mode="after")
    def coherent_producer_contract(self):
        if self.producer_kind == "collector":
            if self.producer_tool_name or self.output_mapping:
                raise ValueError(
                    "collector bindings use the normalized envelope contract"
                )
        elif not self.producer_tool_name or "value" not in self.output_mapping:
            raise ValueError(
                "workflow bindings require a producer Tool and value mapping"
            )
        return self


class ServiceIndicatorArtifactBindingUpdate(ServiceIndicatorAPIModel):
    expected_revision: int = Field(ge=1)
    enabled: bool
    actor: str = Field(min_length=1, max_length=255)


class ServiceIndicatorArtifactBindingRead(ServiceIndicatorAPIModel):
    id: str
    definition_id: str
    artifact_version_id: str
    artifact_name: str
    artifact_version: int
    producer_kind: Literal["collector", "workflow"]
    binding_key: str
    producer_tool_name: str | None
    output_mapping: dict[str, str]
    enabled: bool
    revision: int
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class ServiceIndicatorArtifactPublicationRead(ServiceIndicatorAPIModel):
    id: str
    binding_id: str
    observation_id: str
    artifact_version_id: str
    binding_revision: int
    producer_kind: Literal["collector", "workflow"]
    collection_envelope_id: str | None
    investigation_id: str | None
    source_tool_call_id: str | None
    created_at: datetime


class PrometheusIndicatorBindingCreate(ServiceIndicatorAPIModel):
    expected_indicator_revision: int = Field(ge=1)
    metric_backend_id: str = Field(min_length=1, max_length=36)
    query: str = Field(min_length=1, max_length=8192)
    reduction: IndicatorReduction = "single"
    dimension_labels: list[str] = Field(default_factory=list, max_length=16)
    interval_seconds: int = Field(default=300, ge=60, le=86_400)
    timeout_seconds: int = Field(default=15, ge=1, le=60)
    actor: str = Field(min_length=1, max_length=255)

    @field_validator("dimension_labels")
    @classmethod
    def valid_dimension_labels(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(
            not item
            or len(item) > 128
            or re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", item) is None
            for item in normalized
        ):
            raise ValueError("dimension labels must be Prometheus label names")
        if len(set(normalized)) != len(normalized):
            raise ValueError("dimension labels must be unique")
        return normalized

    @model_validator(mode="after")
    def dimensions_require_single_reduction(self):
        if self.reduction != "single" and self.dimension_labels:
            raise ValueError(
                "dimension labels are only retained by single reduction"
            )
        return self


class PrometheusIndicatorBindingUpdate(ServiceIndicatorAPIModel):
    expected_revision: int = Field(ge=1)
    metric_backend_id: str | None = Field(default=None, min_length=1, max_length=36)
    query: str | None = Field(default=None, min_length=1, max_length=8192)
    reduction: IndicatorReduction | None = None
    dimension_labels: list[str] | None = Field(default=None, max_length=16)
    interval_seconds: int | None = Field(default=None, ge=60, le=86_400)
    timeout_seconds: int | None = Field(default=None, ge=1, le=60)
    enabled: bool | None = None
    actor: str = Field(min_length=1, max_length=255)

    @field_validator("dimension_labels")
    @classmethod
    def valid_dimension_labels(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value
        return PrometheusIndicatorBindingCreate.valid_dimension_labels(value)


class PrometheusIndicatorBindingRead(ServiceIndicatorAPIModel):
    id: str
    definition_id: str
    metric_backend_id: str
    metric_backend_name: str
    query: str
    query_sha256: str
    reduction: IndicatorReduction
    dimension_labels: list[str]
    interval_seconds: int
    timeout_seconds: int
    enabled: bool
    revision: int
    next_run_at: datetime
    last_scheduled_at: datetime | None
    last_started_at: datetime | None
    last_succeeded_at: datetime | None
    last_failed_at: datetime | None
    consecutive_failures: int
    last_error_type: str | None
    last_error_sha256: str | None
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class ServiceIndicatorPollRunRead(ServiceIndicatorAPIModel):
    id: str
    binding_id: str
    scheduled_for: datetime
    status: IndicatorPollRunState
    attempt_count: int
    max_attempts: int
    next_attempt_at: datetime
    worker_name: str | None
    lease_expires_at: datetime | None
    observation_id: str | None
    result_type: str | None
    series_count: int | None
    error_type: str | None
    error_sha256: str | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ServiceIndicatorPollAssignment(ServiceIndicatorAPIModel):
    run_id: str
    binding_id: str
    lease_token: str
    lease_expires_at: datetime
