from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator, model_validator

from .schemas import APIModel


class QualityModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    @field_validator("*", mode="after")
    @classmethod
    def utc_dates(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return value


class QualityPolicySettings(QualityModel):
    enabled: bool = True
    evidence_mode: Literal["execution_health", "remediation_outcome"] = "execution_health"
    window_minutes: int = Field(default=60, ge=5, le=10080)
    min_samples: int = Field(default=5, ge=1, le=2000)
    max_failure_ppm: int = Field(default=100000, ge=0, le=1000000)
    max_p95_ms: int = Field(default=30000, ge=1, le=3600000)
    max_sample_age_seconds: int = Field(default=900, ge=60, le=604800)
    evaluation_interval_seconds: int = Field(default=60, ge=60, le=86400)
    min_records_per_run: int = Field(default=0, ge=0, le=1000000)
    alert_on_degradation: bool = True

    @model_validator(mode="after")
    def coherent_window(self):
        if self.max_sample_age_seconds > self.window_minutes * 60:
            raise ValueError("Sample freshness cannot exceed the evidence window")
        if self.evidence_mode == "remediation_outcome" and self.min_samples > 200:
            raise ValueError("Remediation outcome evidence is bounded to 200 samples")
        return self


class QualityPolicyCreate(QualityPolicySettings):
    artifact_version_id: UUID
    expected_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=10, max_length=512)


class QualityPolicyUpdate(QualityPolicySettings):
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=512)


class QualityPolicyRead(QualityPolicySettings):
    id: str
    artifact_version_id: str
    content_hash: str
    revision: int
    last_assessment_id: str | None
    next_evaluation_at: datetime | None
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class QualityEvaluate(QualityModel):
    reason: str = Field(min_length=10, max_length=512)


class QualityAssessmentSummary(QualityModel):
    format_version: Literal["icheck.capability-quality/v1"] = "icheck.capability-quality/v1"
    evidence_scope: Literal["execution_health_not_correctness", "remediation_outcome_not_authority"] = "execution_health_not_correctness"
    authorizes_automation: Literal[False] = False
    id: str
    policy_id: str
    artifact_version_id: str
    policy_revision: int
    policy_sha256: str
    content_hash: str
    status: Literal["healthy", "degraded", "insufficient_data", "disabled"]
    reasons: list[str]
    sample_count: int
    failed_count: int
    failure_ppm: int | None
    p95_ms: int | None
    latest_sample_at: datetime | None
    scan_truncated: bool
    evidence_sha256: str
    assessment_sha256: str
    evaluated_at: datetime
    valid_until: datetime
    evaluated_by: str


class QualityAssessmentRead(QualityAssessmentSummary):
    policy_snapshot: dict[str, Any]
    evidence_manifest: list[dict[str, Any]]


class QualityPolicyStateRead(QualityModel):
    as_of: datetime
    policy: QualityPolicyRead
    latest_assessment: QualityAssessmentSummary | None
    current: bool
    state: Literal["healthy", "degraded", "insufficient_data", "disabled", "needs_evaluation", "expired"]
