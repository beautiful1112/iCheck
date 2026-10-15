"""Reviewed recovery predicates are separate from incident closure authority."""
from datetime import datetime
from typing import Literal

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from .source_qualification_schemas import QualificationModel, SourceQualificationCreate, SourceQualificationRevoke


class RecoverySourceBinding(QualificationModel):
    source_id: str = Field(min_length=36, max_length=36)
    qualification_review_id: str = Field(min_length=36, max_length=36)


class RecoveryReplacementBinding(QualificationModel):
    old_source_id: str = Field(min_length=36, max_length=36)
    retirement_id: str = Field(min_length=36, max_length=36)
    replacement_review_id: str = Field(min_length=36, max_length=36)


class SituationRecoveryPolicyCreate(QualificationModel):
    request_key: str = Field(min_length=8, max_length=128)
    name: str = Field(min_length=3, max_length=128)
    source_bindings: list[RecoverySourceBinding] = Field(min_length=1, max_length=64)
    proof_version: StrictInt = Field(default=1, ge=1, le=2)
    replacement_bindings: list[RecoveryReplacementBinding] = Field(default_factory=list, max_length=64)
    evidence_environment: Literal["controlled_fixture", "live_lab", "production"]
    min_quiet_samples: StrictInt = Field(default=2, ge=2, le=128)
    min_quiet_seconds: StrictInt = Field(default=60, ge=1, le=86400)
    max_sample_gap_seconds: StrictInt = Field(default=60, ge=1, le=86400)
    max_age_seconds: StrictInt = Field(default=120, ge=1, le=86400)
    validation_reference: str = Field(min_length=10, max_length=1024)
    reason: str = Field(min_length=10, max_length=512)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def aware(cls, value):
        return SourceQualificationCreate.timezone_required(value)

    @field_validator("request_key", "name", "validation_reference", "reason")
    @classmethod
    def text(cls, value):
        return SourceQualificationCreate.nonblank(value)

    @field_validator("source_bindings")
    @classmethod
    def unique_sorted(cls, values):
        if len({item.source_id for item in values}) != len(values):
            raise ValueError("Each exact source generation may be bound only once")
        return sorted(values, key=lambda item: item.source_id)

    @field_validator("replacement_bindings")
    @classmethod
    def replacements_sorted(cls, values):
        if len({item.old_source_id for item in values}) != len(values) or len({item.retirement_id for item in values}) != len(values):
            raise ValueError("Each historical source and permanent retirement may be bound only once")
        return sorted(values, key=lambda item: item.old_source_id)

    @model_validator(mode="after")
    def explicit_proof_version(self):
        if (self.proof_version == 2) != bool(self.replacement_bindings):
            raise ValueError("Replacement bindings require explicit recovery proof version 2; direct policies remain version 1")
        if {item.old_source_id for item in self.replacement_bindings} & {item.source_id for item in self.source_bindings}:
            raise ValueError("A historical source cannot also be a current source binding")
        return self


class SituationRecoveryPolicyReviewCreate(QualificationModel):
    independent_criteria_validated: Literal[True]
    acceptance_reference: str = Field(min_length=10, max_length=1024)
    reason: str = Field(min_length=10, max_length=512)

    @field_validator("independent_criteria_validated", mode="before")
    @classmethod
    def explicit(cls, value):
        if value is not True:
            raise ValueError("An explicit true independent criteria attestation is required")
        return value

    @field_validator("acceptance_reference", "reason")
    @classmethod
    def text(cls, value):
        return SourceQualificationCreate.nonblank(value)


class SituationRecoveryPolicyRequestRead(SituationRecoveryPolicyCreate):
    id: str
    author_principal_id: str
    author_subject: str
    created_at: datetime
    authorizes_incident_closure: Literal[False] = False

    @field_validator("expires_at")
    @classmethod
    def aware(cls, value):
        # SQLite's development driver strips the tzinfo stored by UTC-only
        # services. Normalize persisted output, never relax request validation.
        from .services.alert_conditions import as_utc
        return as_utc(value)

    @field_validator("created_at")
    @classmethod
    def created_utc(cls, value):
        return cls.aware(value)


class SituationRecoveryPolicyReviewRead(QualificationModel):
    id: str
    request_id: str
    reviewer_principal_id: str
    reviewer_subject: str
    acceptance_reference: str
    reason: str
    created_at: datetime
    authorizes_incident_closure: Literal[False] = False

    @field_validator("created_at")
    @classmethod
    def created_utc(cls, value):
        return SituationRecoveryPolicyRequestRead.aware(value)


class SituationRecoveryPolicyRevocationRead(QualificationModel):
    id: str
    review_id: str
    principal_id: str
    subject: str
    reason: str
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def created_utc(cls, value):
        return SituationRecoveryPolicyRequestRead.aware(value)


class SituationRecoveryPolicyDetail(QualificationModel):
    request: SituationRecoveryPolicyRequestRead
    review: SituationRecoveryPolicyReviewRead | None = None
    revocation: SituationRecoveryPolicyRevocationRead | None = None
    authorizes_incident_closure: Literal[False] = False


class SituationRecoveryEvidenceRead(QualificationModel):
    situation_id: str
    policy_review_id: str
    evaluated_at: datetime
    evidence_environment: str
    qualified_recovery: StrictBool
    production_qualified: StrictBool
    covers_situation: StrictBool
    member_count: int
    blockers: list[str]
    membership: list[dict]
    source_evidence: list[dict]
    valid_until: datetime | None = None
    verification_basis: Literal["peer_reviewed_source_recovery/v1", "peer_reviewed_source_recovery/v2"] = "peer_reviewed_source_recovery/v1"
    authorizes_incident_closure: Literal[False] = False
    closure_execution_available: Literal[False] = False
    physical_truth_automatically_verified: Literal[False] = False
    remediation_causality_proven: Literal[False] = False


SituationRecoveryPolicyRevoke = SourceQualificationRevoke
