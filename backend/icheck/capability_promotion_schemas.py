from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, model_serializer, model_validator

from .collector_schemas import ArtifactBundleSignature
from .schemas import APIModel
from .transparency_witness_schemas import TransparencyGossipDocument


PROMOTION_ATTESTATION_FORMAT = "icheck.capability-promotion-attestation/v1"
SIGNED_PROMOTION_ATTESTATION_FORMAT = (
    "icheck.capability-promotion-attestation.signed/v1"
)
PROMOTION_KEY_ROTATION_FORMAT = "icheck.capability-promotion-key-rotation/v1"
SIGNED_PROMOTION_KEY_ROTATION_FORMAT = "icheck.capability-promotion-key-rotation.signed/v1"
EnvironmentStage = Literal["development", "test", "staging", "production"]
PublicationMode = Literal["disabled", "manual"]


class CapabilityPromotionModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class PromotionSourceWitnessPolicyUpdate(CapabilityPromotionModel):
    required_quorum: int = Field(ge=0, le=16)
    witness_ids: list[str] = Field(default_factory=list, max_length=16)
    max_attestation_age_hours: int = Field(default=168, ge=1, le=720)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_witness_policy(self):
        if len(set(self.witness_ids)) != len(self.witness_ids) or any(not value or len(value) > 36 for value in self.witness_ids):
            raise ValueError("Witness policy requires unique local witness IDs")
        if self.required_quorum > len(self.witness_ids):
            raise ValueError("Witness allowlist is smaller than required quorum")
        return self


class PromotionSourceWitnessPolicyRead(CapabilityPromotionModel):
    id: str | None = None
    required_quorum: int = 0
    witness_ids: list[str] = Field(default_factory=list)
    max_attestation_age_hours: int = 168
    updated_by: str | None = None
    updated_at: datetime | None = None


class PromotionSourceCheckpointBindingUpdate(CapabilityPromotionModel):
    log_id: str = Field(min_length=1, max_length=36)
    epoch: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class PromotionSourceCheckpointBindingRead(CapabilityPromotionModel):
    source_id: str
    log_id: str
    epoch: int
    reason: str
    updated_by: str
    updated_at: datetime


class PromotionSourceWitnessDecisionRead(CapabilityPromotionModel):
    id: str
    receipt_id: str
    checkpoint_statement_digest_sha256: str
    evidence_digest_sha256: str
    policy_snapshot: dict[str, object]
    witness_evidence: list[dict[str, str]]
    accepted_by: str
    accepted_at: datetime


class CapabilityPromotionPolicyUpdate(CapabilityPromotionModel):
    local_environment_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    local_stage: EnvironmentStage
    required_source_stage: EnvironmentStage
    max_attestation_age_hours: int = Field(ge=1, le=168)
    publication_mode: PublicationMode = "disabled"
    require_distinct_publisher: bool = True
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class CapabilityPromotionPolicyRead(CapabilityPromotionModel):
    id: str
    local_environment_id: str
    local_stage: EnvironmentStage
    required_source_stage: EnvironmentStage
    max_attestation_age_hours: int
    publication_mode: PublicationMode
    require_distinct_publisher: bool
    updated_by: str
    updated_at: datetime


class CapabilityPromotionSourceCreate(CapabilityPromotionModel):
    name: str = Field(min_length=1, max_length=255)
    organization_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    environment_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    source_stage: EnvironmentStage
    trust_key_id: str = Field(min_length=1, max_length=36)
    created_by: str = Field(min_length=1, max_length=255)


class CapabilityPromotionSourceStateCreate(CapabilityPromotionModel):
    enabled: bool
    checkpoint_evidence: TransparencyGossipDocument | None = None
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class CapabilityPromotionSourceRead(CapabilityPromotionModel):
    id: str
    name: str
    organization_id: str
    environment_id: str
    source_stage: EnvironmentStage
    trust_key_id: str
    key_fingerprint_sha256: str
    enabled: bool
    latest_sequence: int = Field(ge=0)
    latest_statement_digest_sha256: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class CapabilityPromotionKeyRotationStatementCreate(CapabilityPromotionModel):
    new_trust_key_id: str = Field(min_length=1, max_length=36)
    validity_hours: int = Field(ge=1, le=24, default=1)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class CapabilityPromotionKeyRotationStatement(CapabilityPromotionModel):
    format_version: Literal["icheck.capability-promotion-key-rotation/v1"] = PROMOTION_KEY_ROTATION_FORMAT
    organization_id: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    source_environment_id: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    source_stage: EnvironmentStage
    target_environment_id: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    target_stage: EnvironmentStage
    promotion_sequence: int = Field(ge=0)
    latest_statement_digest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    current_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    next_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    expires_at: datetime
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_rotation(self):
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Promotion key rotation timestamps require offsets")
        if self.expires_at <= self.issued_at:
            raise ValueError("Promotion key rotation expiry must follow issue time")
        if self.current_key_fingerprint_sha256 == self.next_key_fingerprint_sha256:
            raise ValueError("Promotion key rotation requires a different key")
        if (self.promotion_sequence == 0) != (self.latest_statement_digest_sha256 is None):
            raise ValueError("Promotion key rotation sequence and statement digest are inconsistent")
        return self


class SignedCapabilityPromotionKeyRotation(CapabilityPromotionModel):
    format_version: Literal["icheck.capability-promotion-key-rotation.signed/v1"] = SIGNED_PROMOTION_KEY_ROTATION_FORMAT
    statement: CapabilityPromotionKeyRotationStatement
    current_signature: ArtifactBundleSignature
    next_signature: ArtifactBundleSignature


class CapabilityPromotionKeyRotationCreate(CapabilityPromotionModel):
    new_trust_key_id: str = Field(min_length=1, max_length=36)
    signed_rotation: SignedCapabilityPromotionKeyRotation
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class CapabilityPromotionKeyRotationRead(CapabilityPromotionModel):
    id: str
    source_id: str
    from_trust_key_id: str
    to_trust_key_id: str
    from_key_fingerprint_sha256: str
    to_key_fingerprint_sha256: str
    promotion_sequence: int
    latest_statement_digest_sha256: str | None
    statement_digest_sha256: str
    current_signature_sha256: str
    next_signature_sha256: str
    issued_at: datetime
    expires_at: datetime
    reason: str
    rotated_by: str
    rotated_at: datetime


class CapabilityPromotionAttestation(CapabilityPromotionModel):
    format_version: Literal[
        "icheck.capability-promotion-attestation/v1"
    ] = PROMOTION_ATTESTATION_FORMAT
    organization_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    source_environment_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    source_stage: EnvironmentStage
    target_environment_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    target_stage: EnvironmentStage
    promotion_sequence: int = Field(ge=1)
    pack_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    pack_version: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    pack_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pack_signer_fingerprint_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    artifact_count: int = Field(ge=1, le=20)
    artifact_set_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_transparency_log_id: str = Field(min_length=1, max_length=36)
    source_transparency_epoch: int = Field(ge=1)
    source_transparency_sequence: int = Field(ge=1)
    source_transparency_head_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    validation_evidence_digest_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    issued_at: datetime
    expires_at: datetime
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_attestation(self) -> "CapabilityPromotionAttestation":
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Promotion attestation timestamps require offsets")
        if self.expires_at <= self.issued_at:
            raise ValueError("Promotion attestation expiry must follow issue time")
        if self.source_environment_id == self.target_environment_id:
            raise ValueError(
                "Promotion source and target environments must differ"
            )
        return self


class SignedCapabilityPromotionAttestation(CapabilityPromotionModel):
    format_version: Literal[
        "icheck.capability-promotion-attestation.signed/v1"
    ] = SIGNED_PROMOTION_ATTESTATION_FORMAT
    attestation: CapabilityPromotionAttestation
    signature: ArtifactBundleSignature
    source_checkpoint_evidence: TransparencyGossipDocument | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_envelope(self, handler):
        result = handler(self)
        if self.source_checkpoint_evidence is None:
            result.pop("source_checkpoint_evidence", None)
        return result


class CapabilityPromotionStatementCreate(CapabilityPromotionModel):
    installation_id: str = Field(min_length=1, max_length=36)
    organization_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    target_environment_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    target_stage: EnvironmentStage
    promotion_sequence: int = Field(ge=1)
    validation_evidence_digest_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    validity_hours: int = Field(default=24, ge=1, le=168)
    actor: str = Field(min_length=1, max_length=255)


class CapabilityPromotionPreviewCreate(CapabilityPromotionModel):
    signed_attestation: SignedCapabilityPromotionAttestation


class CapabilityPromotionAcceptCreate(CapabilityPromotionPreviewCreate):
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class CapabilityPromotionPreviewRead(CapabilityPromotionModel):
    source_id: str
    source_environment_id: str
    target_environment_id: str
    target_stage: EnvironmentStage
    promotion_sequence: int
    installation_id: str | None
    pack_name: str
    pack_version: str
    pack_digest_sha256: str
    artifact_count: int
    source_transparency_log_id: str
    source_transparency_epoch: int
    source_transparency_sequence: int
    source_transparency_head_sha256: str
    promotable: bool
    already_accepted: bool
    existing_receipt_id: str | None = None
    blockers: list[str] = Field(default_factory=list)
    source_witness_count: int = 0
    required_source_witness_quorum: int = 0


class CapabilityPromotionReceiptRead(CapabilityPromotionModel):
    id: str
    source_id: str
    installation_id: str
    organization_id: str
    source_environment_id: str
    source_stage: EnvironmentStage
    target_environment_id: str
    target_stage: EnvironmentStage
    promotion_sequence: int
    pack_name: str
    pack_version: str
    pack_digest_sha256: str
    pack_signer_fingerprint_sha256: str
    artifact_count: int
    artifact_set_digest_sha256: str
    source_transparency_log_id: str
    source_transparency_epoch: int
    source_transparency_sequence: int
    source_transparency_head_sha256: str
    validation_evidence_digest_sha256: str
    statement_digest_sha256: str
    trust_key_id: str
    key_fingerprint_sha256: str
    signature_sha256: str
    issued_at: datetime
    expires_at: datetime
    reason: str
    accepted_by: str
    accepted_at: datetime


class CapabilityPromotionPublicationAction(CapabilityPromotionModel):
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class CapabilityPromotionPublicationPreviewRead(CapabilityPromotionModel):
    receipt_id: str
    installation_id: str
    eligible: bool
    already_published: bool
    existing_publication_id: str | None = None
    artifact_version_ids: list[str] = Field(default_factory=list)
    candidate_artifact_version_ids: list[str] = Field(default_factory=list)
    already_published_version_ids: list[str] = Field(default_factory=list)
    reused_version_ids: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)


class CapabilityPromotionPublicationRead(CapabilityPromotionModel):
    id: str
    receipt_id: str
    installation_id: str
    publication_digest_sha256: str
    artifact_count: int
    newly_published_count: int
    artifact_version_ids: list[str]
    newly_published_version_ids: list[str]
    already_published_version_ids: list[str]
    reused_version_ids: list[str]
    policy_snapshot: dict[str, object]
    reason: str
    published_by: str
    published_at: datetime
