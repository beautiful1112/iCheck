"""Pre-authorized, delayed and witnessed environment-promotion recovery."""
from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from .capability_promotion_schemas import CapabilityPromotionModel, EnvironmentStage
from .collector_schemas import ArtifactBundleSignature
from .transparency_witness_schemas import TransparencyGossipDocument

POLICY_FORMAT = "icheck.promotion-recovery-policy/v1"
SIGNED_POLICY_FORMAT = "icheck.promotion-recovery-policy.signed/v1"
CEREMONY_FORMAT = "icheck.promotion-key-recovery/v1"
SIGNED_CEREMONY_FORMAT = "icheck.promotion-key-recovery.signed/v1"


class RecoveryContext(CapabilityPromotionModel):
    source_id: str = Field(min_length=1, max_length=36)
    organization_id: str = Field(min_length=1, max_length=255)
    source_environment_id: str = Field(min_length=1, max_length=255)
    source_stage: EnvironmentStage
    target_environment_id: str = Field(min_length=1, max_length=255)
    target_stage: EnvironmentStage
    current_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    expires_at: datetime
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def timestamps(self):
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None or self.expires_at <= self.issued_at:
            raise ValueError("Recovery timestamps need offsets and a positive lifetime")
        return self


class PromotionRecoveryPolicyStatement(RecoveryContext):
    format_version: Literal["icheck.promotion-recovery-policy/v1"] = POLICY_FORMAT
    policy_version: int = Field(ge=1)
    trustee_fingerprints_sha256: list[str] = Field(min_length=2, max_length=8)
    witness_fingerprints_sha256: list[str] = Field(min_length=2, max_length=8)
    required_approvals: int = Field(ge=2, le=8)
    required_witnesses: int = Field(ge=2, le=8)
    delay_hours: int = Field(ge=1, le=72)
    max_evidence_age_hours: int = Field(ge=1, le=168)

    @model_validator(mode="after")
    def independent_sets(self):
        for values in (self.trustee_fingerprints_sha256, self.witness_fingerprints_sha256):
            if values != sorted(set(values)) or any(len(v) != 64 or any(c not in "0123456789abcdef" for c in v) for v in values):
                raise ValueError("Recovery fingerprints must be distinct, sorted SHA-256 values")
        if (self.required_approvals > len(self.trustee_fingerprints_sha256)
            or self.required_witnesses > len(self.witness_fingerprints_sha256)):
            raise ValueError("Recovery quorum exceeds its pre-authorized set")
        if (set(self.trustee_fingerprints_sha256) & set(self.witness_fingerprints_sha256)
            or self.current_key_fingerprint_sha256 in self.trustee_fingerprints_sha256 + self.witness_fingerprints_sha256):
            raise ValueError("Recovery authority, trustees and witnesses must use independent keys")
        return self


class SignedPromotionRecoveryPolicy(CapabilityPromotionModel):
    format_version: Literal["icheck.promotion-recovery-policy.signed/v1"] = SIGNED_POLICY_FORMAT
    statement: PromotionRecoveryPolicyStatement
    authority_signature: ArtifactBundleSignature


class PromotionRecoveryPolicyStatementCreate(CapabilityPromotionModel):
    trustee_trust_key_ids: list[str] = Field(min_length=2, max_length=8)
    witness_ids: list[str] = Field(min_length=2, max_length=8)
    required_approvals: int = Field(ge=2, le=8)
    required_witnesses: int = Field(ge=2, le=8)
    delay_hours: int = Field(default=24, ge=1, le=72)
    max_evidence_age_hours: int = Field(default=24, ge=1, le=168)
    validity_hours: int = Field(default=24, ge=1, le=24)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def unique_ids(self):
        for values in (self.trustee_trust_key_ids, self.witness_ids):
            if len(set(values)) != len(values) or any(not v or len(v) > 36 for v in values):
                raise ValueError("Recovery requires distinct local identities")
        if self.required_approvals > len(self.trustee_trust_key_ids) or self.required_witnesses > len(self.witness_ids):
            raise ValueError("Recovery quorum exceeds its configured set")
        return self


class PromotionRecoveryPolicyCreate(CapabilityPromotionModel):
    trustee_trust_key_ids: list[str] = Field(min_length=2, max_length=8)
    witness_ids: list[str] = Field(min_length=2, max_length=8)
    signed_policy: SignedPromotionRecoveryPolicy
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class PromotionKeyRecoveryStatement(RecoveryContext):
    format_version: Literal["icheck.promotion-key-recovery/v1"] = CEREMONY_FORMAT
    recovery_policy_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ceremony_id: str = Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    next_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    promotion_sequence: int = Field(ge=0)
    latest_statement_digest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    checkpoint_statement_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_head(self):
        if (self.promotion_sequence == 0) != (self.latest_statement_digest_sha256 is None):
            raise ValueError("Recovery accepted head is inconsistent")
        if self.current_key_fingerprint_sha256 == self.next_key_fingerprint_sha256:
            raise ValueError("Emergency recovery needs a different key")
        return self


class SignedPromotionKeyRecovery(CapabilityPromotionModel):
    format_version: Literal["icheck.promotion-key-recovery.signed/v1"] = SIGNED_CEREMONY_FORMAT
    statement: PromotionKeyRecoveryStatement
    next_signature: ArtifactBundleSignature
    trustee_signatures: list[ArtifactBundleSignature] = Field(min_length=2, max_length=8)


class PromotionKeyRecoveryStatementCreate(CapabilityPromotionModel):
    new_trust_key_id: str = Field(min_length=1, max_length=36)
    checkpoint_evidence: TransparencyGossipDocument
    validity_hours: int = Field(default=48, ge=2, le=168)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class PromotionKeyRecoveryProposalCreate(CapabilityPromotionModel):
    new_trust_key_id: str = Field(min_length=1, max_length=36)
    signed_recovery: SignedPromotionKeyRecovery
    checkpoint_evidence: TransparencyGossipDocument
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class PromotionKeyRecoveryAction(CapabilityPromotionModel):
    checkpoint_evidence: TransparencyGossipDocument | None = None
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class PromotionRecoveryPolicyRead(CapabilityPromotionModel):
    id: str
    source_id: str
    version: int
    trustee_key_ids: list[str]
    witness_ids: list[str]
    statement_digest_sha256: str
    signed_policy_snapshot: dict
    transparency_sequence: int
    reason: str
    accepted_by: str
    accepted_at: datetime


class PromotionKeyRecoveryRead(CapabilityPromotionModel):
    id: str
    source_id: str
    recovery_policy_id: str
    to_trust_key_id: str
    signed_recovery_snapshot: dict
    execute_after: datetime
    proposal_transparency_sequence: int
    status: Literal["pending", "executed", "cancelled"]
    reason: str
    proposed_by: str
    proposed_at: datetime


class PromotionRecoveryEventRead(CapabilityPromotionModel):
    id: str
    source_id: str
    recovery_policy_id: str
    ceremony_id: str | None
    event_type: str
    checkpoint_evidence_snapshot: dict | None
    verified_evidence: dict
    transparency_sequence: int
    reason: str
    actor: str
    occurred_at: datetime
