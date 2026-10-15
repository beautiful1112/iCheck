"""Strict retained v2 references, not current authority or physical attestation."""
from datetime import datetime
from typing import Literal

from pydantic import Field, StrictInt, field_validator, model_validator

from .source_qualification_schemas import QualificationModel, SourceQualificationCreate
from .situation_recovery_schemas import SituationRecoveryEvidenceRead


class RecoveryMemberPin(QualificationModel):
    membership_id: str = Field(min_length=36, max_length=36)
    alert_id: str = Field(min_length=36, max_length=36)
    dedup_key: str
    event_type: str
    entity_type: str
    entity_id: str
    status: Literal["open", "acknowledged", "resolved"]
    first_seen: datetime
    last_seen: datetime
    occurrence_count: StrictInt = Field(ge=1)
    source_retirement_id: str | None = Field(min_length=36, max_length=36)

    @field_validator("first_seen", "last_seen")
    @classmethod
    def aware(cls, value):
        return SourceQualificationCreate.timezone_required(value)


class RecoveryActiveReference(QualificationModel):
    alert_id: str = Field(min_length=36, max_length=36)
    active_receipt_id: str = Field(min_length=36, max_length=36)
    active_source_id: str = Field(min_length=36, max_length=36)
    qualification_request_id: str = Field(min_length=36, max_length=36)
    qualification_review_id: str = Field(min_length=36, max_length=36)
    retirement_id: str | None = Field(min_length=36, max_length=36)
    replacement_request_id: str | None = Field(min_length=36, max_length=36)
    replacement_review_id: str | None = Field(min_length=36, max_length=36)

    @model_validator(mode="after")
    def complete_mapping(self):
        values = self.retirement_id, self.replacement_request_id, self.replacement_review_id
        if any(value is not None for value in values) != all(value is not None for value in values):
            raise ValueError("Historical replacement authority must be entirely present or absent")
        return self


class RecoverySourceReferences(QualificationModel):
    source_id: str = Field(min_length=36, max_length=36)
    qualification_review_id: str = Field(min_length=36, max_length=36)
    qualification_request_id: str = Field(min_length=36, max_length=36)
    condition_revision: StrictInt = Field(ge=1)
    current_alert_id: str | None = Field(min_length=36, max_length=36)
    quiet_receipt_id: str = Field(min_length=36, max_length=36)
    quiet_admission_id: str = Field(min_length=36, max_length=36)
    quiet_observed_at: datetime
    quiet_window_start: datetime
    quiet_after: datetime
    quiet_sample_receipt_ids: list[str] = Field(min_length=2, max_length=256)
    members: list[RecoveryActiveReference] = Field(min_length=1, max_length=512)

    @field_validator("quiet_observed_at", "quiet_window_start", "quiet_after")
    @classmethod
    def aware(cls, value):
        return SourceQualificationCreate.timezone_required(value)

    @model_validator(mode="after")
    def window(self):
        if (not self.quiet_after < self.quiet_window_start <= self.quiet_observed_at
            or len(set(self.quiet_sample_receipt_ids)) != len(self.quiet_sample_receipt_ids)
            or any(len(value) != 36 for value in self.quiet_sample_receipt_ids)
            or self.quiet_sample_receipt_ids[0] != self.quiet_receipt_id
            or len({item.alert_id for item in self.members}) != len(self.members)):
            raise ValueError("Retained replacement recovery window or members are malformed")
        return self


class ReplacementRecoveryProof(SituationRecoveryEvidenceRead):
    verification_basis: Literal["peer_reviewed_source_recovery/v2"]
    evidence_environment: Literal["controlled_fixture", "live_lab", "production"]
    qualified_recovery: Literal[True]
    covers_situation: Literal[True]
    blockers: list[str] = Field(max_length=0)
    member_count: StrictInt = Field(ge=1, le=512)
    membership: list[RecoveryMemberPin] = Field(min_length=1, max_length=512)
    source_evidence: list[RecoverySourceReferences] = Field(min_length=1, max_length=64)
    valid_until: datetime

    @field_validator("evaluated_at", "valid_until")
    @classmethod
    def aware(cls, value):
        return SourceQualificationCreate.timezone_required(value)

    @model_validator(mode="before")
    @classmethod
    def literal_flags(cls, value):
        for field, expected in (("qualified_recovery", True), ("covers_situation", True),
            ("authorizes_incident_closure", False), ("closure_execution_available", False),
            ("physical_truth_automatically_verified", False), ("remediation_causality_proven", False)):
            if not isinstance(value, dict) or value.get(field) is not expected:
                raise ValueError("Retained recovery requires literal, complete non-authorizing flags")
        return value

    @model_validator(mode="after")
    def complete(self):
        if (self.member_count != len(self.membership) or self.valid_until <= self.evaluated_at
            or self.production_qualified != (self.evidence_environment == "production")
            or len({member.alert_id for member in self.membership}) != self.member_count
            or len({item.source_id for item in self.source_evidence}) != len(self.source_evidence)):
            raise ValueError("Retained recovery identity, validity or source set is incomplete")
        return self
