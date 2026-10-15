"""Internal recovery custody. Public projections never expose the Vault target."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .oauth_observation import OAuthCredentialObservation


class OAuthRecoveryTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    generation: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    vault_version: int = Field(strict=True, ge=1, le=2_147_483_646)
    issuer: str = Field(min_length=1, max_length=2048)
    client_id: str = Field(min_length=1, max_length=2048)
    resource: str = Field(min_length=1, max_length=2048)
    coordination_owner: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class OAuthContainmentProof(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    original_tool_call_id: str = Field(min_length=1, max_length=36)
    original_plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    verification_result_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    write_artifact_version_id: str = Field(min_length=1, max_length=36)
    write_artifact_activation_id: str = Field(min_length=1, max_length=36)
    verification_artifact_version_id: str = Field(min_length=1, max_length=36)
    verification_artifact_activation_id: str = Field(min_length=1, max_length=36)
    observed_at: datetime
    evidence_reference: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    family_reference: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    containment_reference: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")

    @model_validator(mode="after")
    def aware_observation(self):
        OAuthCredentialObservation.aware_timestamp(self.observed_at)
        return self


class OAuthRecoveryCustody(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: int = Field(default=1, strict=True, ge=1, le=1)
    recovery_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    intent_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    target: OAuthRecoveryTarget
    status: Literal["awaiting_evidence", "cleanup_pending", "complete"]
    initiated_by_principal_id: str = Field(min_length=1, max_length=36)
    initiated_by: str = Field(min_length=1, max_length=255)
    initiated_at: datetime
    connected_audit_id: str | None = Field(default=None, min_length=1, max_length=36)
    proposal_id: str | None = Field(default=None, min_length=1, max_length=36)
    verification_tool_call_id: str | None = Field(default=None, min_length=1, max_length=36)
    reviewed_by_principal_id: str | None = Field(default=None, min_length=1, max_length=36)
    reviewed_by: str | None = Field(default=None, min_length=1, max_length=255)
    reviewed_at: datetime | None = None
    cleanup_version: int | None = Field(default=None, strict=True, ge=2)
    fence_verified: bool = Field(default=False, strict=True)
    proof: OAuthContainmentProof | None = None
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def custody_state(self):
        for value in (self.initiated_at, self.reviewed_at, self.completed_at):
            if value is not None:
                OAuthCredentialObservation.aware_timestamp(value)
        proof = (self.proposal_id, self.verification_tool_call_id,
                 self.reviewed_by_principal_id, self.reviewed_by, self.reviewed_at,
                 self.cleanup_version, self.proof)
        if self.status == "awaiting_evidence":
            if self.fence_verified or any(value is not None for value in (*proof, self.completed_at)):
                raise ValueError("Unreviewed recovery cannot retain cleanup authority")
        else:
            if any(value is None for value in proof):
                raise ValueError("Reviewed recovery requires complete evidence custody")
            if self.reviewed_by_principal_id == self.initiated_by_principal_id:
                raise ValueError("Recovery requires an independent human reviewer")
            if self.cleanup_version != self.target.vault_version + 1:
                raise ValueError("Recovery cleanup must bind the exact fenced Vault version")
            if self.reviewed_at < self.initiated_at:
                raise ValueError("Recovery review predates its fence")
            if (self.status == "complete") != (self.completed_at is not None):
                raise ValueError("Only completed recovery may retain a completion time")
            if self.status == "complete" and not self.fence_verified:
                raise ValueError("Completed recovery requires a durably verified fence")
            if self.completed_at is not None and self.completed_at < self.reviewed_at:
                raise ValueError("Recovery completion predates review")
        return self
