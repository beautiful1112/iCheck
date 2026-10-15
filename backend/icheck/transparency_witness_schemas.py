from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from .collector_schemas import ArtifactBundleSignature
from .schemas import APIModel


CHECKPOINT_STATEMENT_FORMAT = (
    "icheck.capability-transparency-checkpoint-statement/v1"
)
WITNESS_ATTESTATION_FORMAT = (
    "icheck.capability-transparency-witness-attestation/v1"
)
SIGNED_WITNESS_ATTESTATION_FORMAT = (
    "icheck.capability-transparency-witness-attestation.signed/v1"
)
GOSSIP_FORMAT = "icheck.capability-transparency-gossip/v1"


class TransparencyWitnessModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class TransparencyWitnessCreate(TransparencyWitnessModel):
    name: str = Field(min_length=1, max_length=255)
    witness_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    region: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    trust_key_id: str = Field(min_length=1, max_length=36)
    created_by: str = Field(min_length=1, max_length=255)


class TransparencyWitnessStateCreate(TransparencyWitnessModel):
    enabled: bool
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class TransparencyWitnessRead(TransparencyWitnessModel):
    id: str
    name: str
    witness_id: str
    region: str
    trust_key_id: str
    key_fingerprint_sha256: str
    enabled: bool
    created_by: str
    created_at: datetime
    updated_at: datetime


class TransparencyWitnessPolicyUpdate(TransparencyWitnessModel):
    required_quorum: int = Field(ge=1, le=16)
    max_attestation_age_hours: int = Field(ge=1, le=720)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class TransparencyWitnessPolicyRead(TransparencyWitnessModel):
    id: str
    required_quorum: int
    max_attestation_age_hours: int
    updated_by: str
    updated_at: datetime


class TransparencyCheckpointStatement(TransparencyWitnessModel):
    format_version: Literal[
        "icheck.capability-transparency-checkpoint-statement/v1"
    ] = CHECKPOINT_STATEMENT_FORMAT
    log_id: str = Field(min_length=1, max_length=36)
    epoch: int = Field(ge=1)
    sequence: int = Field(ge=1)
    head_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    expires_at: datetime
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_statement(self) -> "TransparencyCheckpointStatement":
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Checkpoint timestamps require offsets")
        if self.expires_at <= self.issued_at:
            raise ValueError("Checkpoint expiry must follow issue time")
        return self


class TransparencyCheckpointOfferCreate(TransparencyWitnessModel):
    validity_hours: int = Field(default=24, ge=1, le=168)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class TransparencyCheckpointOfferRead(TransparencyWitnessModel):
    id: str
    log_id: str
    epoch: int
    sequence: int
    head_digest_sha256: str
    statement_digest_sha256: str
    statement: TransparencyCheckpointStatement
    issued_at: datetime
    expires_at: datetime
    reason: str
    created_by: str
    created_at: datetime
    attestation_count: int
    required_quorum: int
    quorum_satisfied: bool


class TransparencyWitnessAttestation(TransparencyWitnessModel):
    format_version: Literal[
        "icheck.capability-transparency-witness-attestation/v1"
    ] = WITNESS_ATTESTATION_FORMAT
    witness_id: str = Field(min_length=1, max_length=255)
    checkpoint_statement_digest_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    log_id: str = Field(min_length=1, max_length=36)
    epoch: int = Field(ge=1)
    sequence: int = Field(ge=1)
    head_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    witnessed_at: datetime
    expires_at: datetime
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_attestation(self) -> "TransparencyWitnessAttestation":
        if self.witnessed_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Witness timestamps require offsets")
        if self.expires_at <= self.witnessed_at:
            raise ValueError("Witness expiry must follow witnessed_at")
        return self


class SignedTransparencyWitnessAttestation(TransparencyWitnessModel):
    format_version: Literal[
        "icheck.capability-transparency-witness-attestation.signed/v1"
    ] = SIGNED_WITNESS_ATTESTATION_FORMAT
    attestation: TransparencyWitnessAttestation
    signature: ArtifactBundleSignature


class TransparencyAttestationIngestCreate(TransparencyWitnessModel):
    signed_attestation: SignedTransparencyWitnessAttestation
    actor: str = Field(min_length=1, max_length=255)


class TransparencyWitnessAttestationRead(TransparencyWitnessModel):
    id: str
    checkpoint_offer_id: str
    witness_id: str
    external_witness_id: str
    trust_key_id: str
    key_fingerprint_sha256: str
    log_id: str
    epoch: int
    sequence: int
    head_digest_sha256: str
    checkpoint_statement_digest_sha256: str
    attestation_digest_sha256: str
    signature_sha256: str
    witnessed_at: datetime
    expires_at: datetime
    ingested_by: str
    ingested_at: datetime


class TransparencyGossipDocument(TransparencyWitnessModel):
    format_version: Literal[
        "icheck.capability-transparency-gossip/v1"
    ] = GOSSIP_FORMAT
    source_region: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    checkpoint: TransparencyCheckpointStatement
    attestations: list[SignedTransparencyWitnessAttestation] = Field(
        min_length=1,
        max_length=16,
    )


class TransparencyGossipIngestCreate(TransparencyWitnessModel):
    gossip: TransparencyGossipDocument
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class TransparencyGossipObservationRead(TransparencyWitnessModel):
    id: str
    source_region: str
    log_id: str
    epoch: int
    sequence: int
    head_digest_sha256: str
    checkpoint_statement_digest_sha256: str
    document_digest_sha256: str
    witness_count: int
    witness_evidence: list[dict[str, str]]
    initial_status: Literal["consistent", "behind", "ahead", "fork"]
    current_status: Literal["consistent", "behind", "ahead", "fork"]
    alert_id: str | None
    reason: str
    received_by: str
    received_at: datetime


class TransparencyForkAlertReconcileCreate(TransparencyWitnessModel):
    limit: int = Field(default=100, ge=1, le=500)
    actor: str = Field(min_length=1, max_length=255)


class TransparencyForkAlertReconcileRead(TransparencyWitnessModel):
    processed: int
    remaining: int
