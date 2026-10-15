"""Peer-reviewed generation identity; acceptance alone does not retire a source."""
from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from .source_qualification_schemas import (QualificationModel, SourceQualificationCreate,
    SourceQualificationReviewCreate, SourceQualificationRevoke)


class SourceReplacementProposalToolInput(QualificationModel):
    # Replacement binds two independently accepted generations, rather than
    # accepting a caller-supplied measurement or inventing a new Alert.
    evidence_environment: Literal["controlled_fixture", "live_lab", "production"]
    validation_reference: str = Field(min_length=10, max_length=1024)
    reason: str = Field(min_length=10, max_length=512)
    expires_at: datetime
    old_source_id: str = Field(min_length=36, max_length=36)
    new_source_id: str = Field(min_length=36, max_length=36)
    old_qualification_review_id: str = Field(min_length=36, max_length=36)
    new_qualification_review_id: str = Field(min_length=36, max_length=36)
    prior_retirement_id: str | None = Field(default=None, min_length=36, max_length=36)

    @field_validator("expires_at")
    @classmethod
    def timezone_required(cls, value):
        return SourceQualificationCreate.timezone_required(value)

    @field_validator("validation_reference", "reason")
    @classmethod
    def nonblank(cls, value):
        return SourceQualificationCreate.nonblank(value)

    @model_validator(mode="after")
    def different_generations(self):
        if self.old_source_id == self.new_source_id:
            raise ValueError("Replacement requires distinct source generations")
        return self


class SourceReplacementCreate(SourceReplacementProposalToolInput):
    request_key: str = Field(min_length=8, max_length=128)

    @field_validator("request_key")
    @classmethod
    def key_nonblank(cls, value):
        return SourceQualificationCreate.nonblank(value)


class SourceReplacementReviewCreate(SourceQualificationReviewCreate):
    pass


class SourceReplacementRevoke(SourceQualificationRevoke):
    pass


class SourceReplacementRequestRead(QualificationModel):
    id: str
    old_source_id: str
    new_source_id: str
    old_qualification_review_id: str
    new_qualification_review_id: str
    prior_retirement_id: str | None = None
    author_principal_id: str
    author_subject: str
    request_key: str
    evidence_environment: str
    validation_reference: str
    reason: str
    snapshot: dict
    expires_at: datetime
    created_at: datetime
    authorizes_source_retirement: Literal[False] = False
    authorizes_incident_closure: Literal[False] = False

    @field_validator("expires_at", "created_at")
    @classmethod
    def utc_read_clock(cls, value):
        # SQLite's UTC database adapter drops tzinfo on reload. The durable
        # timestamp must have one stable JSON spelling across commit/retry.
        return value.replace(tzinfo=value.tzinfo or UTC).astimezone(UTC)


class SourceReplacementReviewRead(QualificationModel):
    id: str
    request_id: str
    reviewer_principal_id: str
    reviewer_subject: str
    acceptance_reference: str
    reason: str
    created_at: datetime
    verification_basis: Literal["peer_reviewed_external_attestation"] = "peer_reviewed_external_attestation"
    physical_truth_automatically_verified: Literal[False] = False
    authorizes_incident_closure: Literal[False] = False


class SourceReplacementRevocationRead(QualificationModel):
    id: str
    review_id: str
    principal_id: str
    subject: str
    reason: str
    created_at: datetime


class SourceReplacementDetailRead(QualificationModel):
    request: SourceReplacementRequestRead
    review: SourceReplacementReviewRead | None
    revocation: SourceReplacementRevocationRead | None
    producer_cutover_performed: bool = False
    retirement_id: str | None = None
    authorizes_incident_closure: Literal[False] = False


class SourceReplacementApply(QualificationModel):
    execution_key: str = Field(min_length=8, max_length=128)
    reason: str = Field(min_length=10, max_length=512)

    @field_validator("execution_key", "reason")
    @classmethod
    def nonblank(cls, value):
        return SourceQualificationCreate.nonblank(value)


class SourceReplacementApplyToolInput(QualificationModel):
    request_id: str = Field(min_length=36, max_length=36)
    reason: str = Field(min_length=10, max_length=512)

    @field_validator("reason")
    @classmethod
    def nonblank(cls, value):
        return SourceQualificationCreate.nonblank(value)


class SourceReplacementReadToolInput(QualificationModel):
    request_id: str = Field(min_length=36, max_length=36)
    check_key: str | None = Field(default=None, min_length=8, max_length=128)

    @field_validator("check_key")
    @classmethod
    def nonblank(cls, value):
        return SourceQualificationCreate.nonblank(value) if value is not None else None


class SourceRetirementRead(QualificationModel):
    protocol: Literal["icheck.collector.source-retirement/v1"]
    id: str
    request_id: str
    review_id: str
    old_source_id: str
    new_source_id: str
    old_watermark_receipt_id: str
    new_receipt_id: str
    superseded_alert_id: str | None
    executor_principal_id: str
    executor_subject: str
    executor_snapshot: dict
    execution_key: str
    reason: str
    old_state_snapshot: dict
    new_state_snapshot: dict
    created_at: datetime
    verification_basis: Literal["peer_reviewed_external_attestation"] = "peer_reviewed_external_attestation"
    physical_truth_automatically_verified: Literal[False] = False
    authorizes_incident_closure: Literal[False] = False


class SourceReplacementSourceRead(QualificationModel):
    source_id: str
    deployment_id: str
    condition_key: str
    entity_type: str
    entity_id: str
    definition: dict
    logical_state: str
    observed_at: datetime | None
    retirement_id: str | None
    candidate_only: Literal[True] = True
    current_authority_validated: Literal[False] = False


class SourceReplacementQualificationRead(QualificationModel):
    source_id: str
    request_id: str
    review_id: str | None
    author_subject: str
    reviewer_subject: str | None
    evidence_environment: str
    expires_at: datetime
    revoked: bool


class SourceReplacementSummaryRead(QualificationModel):
    request_id: str
    old_source_id: str
    new_source_id: str
    review_id: str | None
    retirement_id: str | None
    prior_retirement_id: str | None
    author_subject: str
    reviewer_subject: str | None
    evidence_environment: str
    expires_at: datetime
    revoked: bool
    candidate_only: Literal[True] = True
    current_authority_validated: Literal[False] = False


class SourceReplacementWorkspaceRead(QualificationModel):
    old_source: SourceReplacementSourceRead
    new_source: SourceReplacementSourceRead | None
    candidates: list[SourceReplacementSourceRead]
    candidates_truncated: bool
    qualifications: list[SourceReplacementQualificationRead]
    qualifications_truncated: bool
    requests: list[SourceReplacementSummaryRead]
    requests_truncated: bool
    host_enabled: bool
    can_propose: bool
    can_review: bool
    can_revoke: bool
    can_apply: bool
    authorizes_source_retirement: Literal[False] = False
    current_authority_validated: Literal[False] = False
