from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, field_validator

from .schemas import APIModel


SITUATION_IMPACT_ASSESSMENT_CONTRACT = "icheck.situation-impact-assessment/v1"


class SituationAssessmentAPIModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class SituationImpactAssessmentProposal(SituationAssessmentAPIModel):
    contract: Literal["icheck.situation-impact-assessment/v1"]
    impact_level: Literal["unknown", "none", "low", "medium", "high", "critical"]
    summary: str = Field(min_length=1, max_length=4000)
    confidence: float = Field(ge=0, le=1)
    affected_node_ids: list[str] = Field(default_factory=list, max_length=100)
    supporting_evidence_ids: list[str] = Field(min_length=1, max_length=100)
    uncertainty: list[str] = Field(default_factory=list, max_length=50)

    @field_validator(
        "affected_node_ids",
        "supporting_evidence_ids",
        "uncertainty",
    )
    @classmethod
    def unique_values(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("values must be unique")
        return value


class SituationImpactAssessmentEvidenceRead(SituationAssessmentAPIModel):
    evidence_reference_id: str
    evidence_type: str
    evidence_id: str
    summary: str
    observed_at: datetime | None


class SituationServiceContextSnapshot(SituationAssessmentAPIModel):
    service_id: str
    service_key: str
    name: str
    owner_team: str
    criticality: Literal["tier_0", "tier_1", "tier_2", "tier_3"]
    business_impact: Literal["critical", "high", "moderate", "low"]
    business_impact_summary: str
    slo_target_percent: float | None
    recovery_time_objective_minutes: int | None
    recovery_point_objective_minutes: int | None
    catalog_revision: int = Field(ge=1)


class SituationServiceDependencySnapshot(SituationAssessmentAPIModel):
    dependency_id: str
    source_service_id: str
    source_service_key: str
    source_service_name: str
    target_service_id: str
    target_service_key: str
    target_service_name: str
    dependency_type: Literal[
        "synchronous", "asynchronous", "data", "shared_infrastructure"
    ]
    critical: bool
    evidence_note: str
    recorded_at: datetime


class SituationServiceIndicatorSnapshot(SituationAssessmentAPIModel):
    definition_id: str
    definition_revision: int = Field(ge=1)
    observation_id: str
    service_id: str
    indicator_key: str
    name: str
    kind: Literal[
        "availability",
        "latency",
        "error_rate",
        "throughput",
        "saturation",
        "business",
        "custom",
    ]
    unit: str
    value: float
    source_type: Literal[
        "prometheus", "api", "collector", "business_system", "manual"
    ]
    source_ref: str
    measurement_quality: Literal["measured", "estimated", "manual"]
    threshold_status: Literal["healthy", "warning", "critical", "informational"]
    freshness_status: Literal["fresh", "stale"]
    effective_status: Literal[
        "stale", "healthy", "warning", "critical", "informational"
    ]
    freshness_seconds: int = Field(ge=10, le=2_592_000)
    evidence_ref: str | None
    observed_at: datetime
    expires_at: datetime


class SituationImpactAssessmentRead(SituationAssessmentAPIModel):
    id: str
    situation_id: str
    investigation_id: str
    checkpoint_id: str
    contract_version: str
    status: Literal["proposed", "accepted", "rejected"]
    impact_level: Literal["unknown", "none", "low", "medium", "high", "critical"]
    summary: str
    confidence: float = Field(ge=0, le=1)
    affected_node_ids: list[str]
    uncertainty: list[str]
    service_context_snapshot: list[SituationServiceContextSnapshot]
    dependency_context_snapshot: list[SituationServiceDependencySnapshot]
    indicator_context_snapshot: list[SituationServiceIndicatorSnapshot]
    source_model_id: str
    created_by: str
    reviewed_by: str | None
    review_reason: str | None
    reviewed_at: datetime | None
    evidence: list[SituationImpactAssessmentEvidenceRead]
    created_at: datetime
    updated_at: datetime


class SituationImpactAssessmentReview(SituationAssessmentAPIModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=3, max_length=4000)
