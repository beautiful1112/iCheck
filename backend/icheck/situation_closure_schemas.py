"""Typed, bounded control-plane closure commands. Lease secrets are never receipts."""
from datetime import datetime
from typing import Literal

from pydantic import Field, StrictInt, field_validator, model_validator

from .source_qualification_schemas import QualificationModel, SourceQualificationCreate


class SituationClosureGrantCreate(QualificationModel):
    request_key: str = Field(min_length=8, max_length=128)
    policy_review_id: str = Field(min_length=36, max_length=36)
    proof_basis: Literal["source_recovery", "verified_remediation"]
    proof_version: StrictInt = Field(default=1, ge=1, le=2)
    remediation_version_id: str | None = Field(default=None, min_length=36, max_length=36)
    independent_closure_authority_validated: Literal[True]
    acceptance_reference: str = Field(min_length=10, max_length=1024)
    reason: str = Field(min_length=10, max_length=512)
    max_lease_seconds: StrictInt = Field(default=30, ge=5, le=120)
    expires_at: datetime

    @field_validator("independent_closure_authority_validated", mode="before")
    @classmethod
    def explicit(cls, value):
        if value is not True:
            raise ValueError("Explicit independent closure authority attestation is required")
        return value

    @field_validator("request_key", "reason", "acceptance_reference")
    @classmethod
    def nonblank(cls, value):
        return SourceQualificationCreate.nonblank(value)

    @field_validator("expires_at")
    @classmethod
    def aware(cls, value):
        return SourceQualificationCreate.timezone_required(value)

    @model_validator(mode="after")
    def basis(self):
        if (self.proof_basis == "verified_remediation") != bool(self.remediation_version_id):
            raise ValueError("Only verified remediation must bind an exact published semantic Tool version")
        return self


class SituationClosureClaimCreate(QualificationModel):
    grant_id: str = Field(min_length=36, max_length=36)
    proof_version: StrictInt = Field(default=1, ge=1, le=2)
    request_key: str = Field(min_length=8, max_length=128)
    reason: str = Field(min_length=10, max_length=512)
    lease_seconds: StrictInt = Field(default=30, ge=5, le=120)
    expected_epoch: StrictInt = Field(default=0, ge=0)

    @field_validator("request_key", "reason")
    @classmethod
    def nonblank(cls, value):
        return SourceQualificationCreate.nonblank(value)


class SituationClosureFinalize(QualificationModel):
    attempt_id: str = Field(min_length=36, max_length=36)
    lease_token: str = Field(min_length=32, max_length=128, repr=False)


class SituationClosureReceiptRead(QualificationModel):
    id: str
    situation_id: str
    grant_id: str
    request_id: str
    attempt_id: str
    epoch: int
    event_id: str
    event_sequence: int
    committed_at: datetime
    proof: dict
    historical: Literal[True] = True
    grants_future_authority: Literal[False] = False
    remediation_causality_proven: Literal[False] = False
    physical_truth_automatically_verified: Literal[False] = False

    @field_validator("committed_at")
    @classmethod
    def utc(cls, value):
        from .services.alert_conditions import as_utc
        return as_utc(value)


class SituationClosureClaimRead(QualificationModel):
    request_id: str
    attempt_id: str | None = None
    epoch: int
    state: Literal["claimed", "released", "committed"]
    lease_expires_at: datetime | None = None
    lease_token: str | None = Field(default=None, repr=False)
    receipt: SituationClosureReceiptRead | None = None


class SituationClosureGrantRead(QualificationModel):
    id: str
    request_key: str
    policy_review_id: str
    proof_basis: str
    proof_version: StrictInt = Field(default=1, ge=1, le=2)
    remediation_version_id: str | None
    reviewer_principal_id: str
    reviewer_subject: str
    acceptance_reference: str
    reason: str
    max_lease_seconds: int
    expires_at: datetime
    created_at: datetime

    @field_validator("expires_at", "created_at")
    @classmethod
    def utc(cls, value):
        return SituationClosureReceiptRead.utc(value)


class SituationClosureToolInput(QualificationModel):
    situation_id: str = Field(min_length=36, max_length=36)
    grant_id: str = Field(min_length=36, max_length=36)
    proof_version: StrictInt = Field(default=1, ge=1, le=2)
    reason: str = Field(min_length=10, max_length=512)

    @field_validator("reason")
    @classmethod
    def nonblank(cls, value):
        return SourceQualificationCreate.nonblank(value)


class SituationRecoveryToolInput(QualificationModel):
    situation_id: str = Field(min_length=36, max_length=36)
    policy_review_id: str = Field(min_length=36, max_length=36)
    check_key: str | None = Field(default=None, min_length=8, max_length=128)


class SituationReplacementClosureToolInput(SituationClosureToolInput):
    # A new builtin avoids silently rewriting installed v1 registrations.
    proof_version: StrictInt = Field(ge=2, le=2)
