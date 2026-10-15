"""Explicit human attestation; no request field can grant closure permission."""
from datetime import datetime
from typing import Literal

from pydantic import Field, StrictBool, field_validator

from .schemas import APIModel


class QualificationModel(APIModel):
    model_config = {**APIModel.model_config, "extra": "forbid"}


class SourceQualificationCreate(QualificationModel):
    baseline_receipt_id: str = Field(min_length=36, max_length=36)
    request_key: str = Field(min_length=8, max_length=128)
    evidence_environment: Literal["controlled_fixture", "live_lab", "production"]
    validation_reference: str = Field(min_length=10, max_length=1024)
    reason: str = Field(min_length=10, max_length=512)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Qualification expiry requires an explicit timezone")
        return value

    @field_validator("validation_reference", "reason", "request_key")
    @classmethod
    def nonblank(cls, value):
        if value != value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError("Qualification text must be trimmed and contain no control characters")
        return value


class SourceQualificationReviewCreate(QualificationModel):
    independent_semantics_validated: Literal[True]
    independent_identity_validated: Literal[True]
    independent_clock_validated: Literal[True]
    acceptance_reference: str = Field(min_length=10, max_length=1024)
    reason: str = Field(min_length=10, max_length=512)

    @field_validator("independent_semantics_validated", "independent_identity_validated", "independent_clock_validated", mode="before")
    @classmethod
    def exact_true(cls, value):
        if value is not True:
            raise ValueError("An explicit true human attestation is required")
        return value

    @field_validator("acceptance_reference", "reason")
    @classmethod
    def nonblank(cls, value):
        return SourceQualificationCreate.nonblank(value)


class SourceQualificationRevoke(QualificationModel):
    reason: str = Field(min_length=10, max_length=512)

    @field_validator("reason")
    @classmethod
    def nonblank(cls, value):
        return SourceQualificationCreate.nonblank(value)


class SourceQualificationRequestRead(QualificationModel):
    id: str
    source_id: str
    baseline_receipt_id: str
    author_principal_id: str
    author_subject: str
    request_key: str
    evidence_environment: str
    validation_reference: str
    reason: str
    snapshot: dict
    expires_at: datetime
    created_at: datetime
    authorizes_incident_closure: Literal[False] = False


class SourceQualificationReviewRead(QualificationModel):
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


class SourceQuietEvidenceRead(QualificationModel):
    source_id: str
    alert_id: str
    receipt_id: str | None = None
    qualification_review_id: str
    evaluated_at: datetime
    qualified_quiet: StrictBool
    production_qualified: StrictBool
    evidence_environment: str
    blockers: list[str]
    observed_at: datetime | None = None
    condition_revision: int | None = None
    qualification_expires_at: datetime
    verification_basis: Literal["peer_reviewed_external_attestation"] = "peer_reviewed_external_attestation"
    covers_situation: Literal[False] = False
    physical_truth_automatically_verified: Literal[False] = False
    authorizes_incident_closure: Literal[False] = False


class SourceQualificationRevocationRead(QualificationModel):
    id: str
    review_id: str
    principal_id: str
    subject: str
    reason: str
    created_at: datetime
    authorizes_incident_closure: Literal[False] = False


class SourceQualificationHistoryRead(QualificationModel):
    source_id: str
    requests: list[SourceQualificationRequestRead]
    reviews: list[SourceQualificationReviewRead]
    revocations: list[SourceQualificationRevocationRead]
    truncated: StrictBool
    authorizes_incident_closure: Literal[False] = False


class SourceReceiptRead(QualificationModel):
    id: str
    observed_at: datetime
    verdict: str
    disposition: str
    alert_id: str | None


class SourceDetailRead(QualificationModel):
    source_id: str
    condition_key: str
    entity_type: str
    entity_id: str
    context: dict
    logical_state: str
    observed_at: datetime | None
    latest_alert_id: str | None
    receipts: list[SourceReceiptRead]
    receipts_truncated: StrictBool
    independently_verified: Literal[False] = False
    authorizes_incident_closure: Literal[False] = False
