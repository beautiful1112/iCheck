from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from .capability_promotion_schemas import (
    EnvironmentStage,
    SignedCapabilityPromotionAttestation,
)
from .schemas import APIModel
from .transparency_witness_schemas import TransparencyCheckpointStatement


EndpointKind = Literal[
    "transparency_witness",
    "promotion_target",
    "gossip_peer",
]
TransportTLSMode = Literal["server_auth", "mutual_tls"]
JobKind = Literal[
    "witness_checkpoint",
    "promotion_delivery",
    "gossip_delivery",
]
JobStatus = Literal[
    "pending",
    "processing",
    "retry",
    "succeeded",
    "dead_letter",
    "cancelled",
]


class EcosystemTransportModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class EcosystemTransportEndpointCreate(EcosystemTransportModel):
    name: str = Field(min_length=1, max_length=255)
    kind: EndpointKind
    url: str = Field(min_length=1, max_length=2048)
    credential_profile_ref: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    tls_mode: TransportTLSMode = "server_auth"
    tls_ca_certificate_ref: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    tls_client_certificate_ref: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    tls_client_private_key_ref: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    tls_client_private_key_password_ref: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    witness_id: str | None = Field(default=None, min_length=1, max_length=36)
    target_environment_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    target_stage: EnvironmentStage | None = None
    target_region_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    auto_dispatch: bool = False
    enabled: bool = True
    request_timeout_seconds: int = Field(default=10, ge=1, le=30)
    max_response_bytes: int = Field(
        default=1_000_000, ge=1024, le=5_000_000
    )
    created_by: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_binding(self) -> "EcosystemTransportEndpointCreate":
        if self.kind == "transparency_witness":
            if not self.witness_id:
                raise ValueError("Witness endpoints require witness_id")
            if (
                self.target_environment_id
                or self.target_stage
                or self.target_region_id
            ):
                raise ValueError("Witness endpoints cannot bind a promotion target")
        elif self.kind == "promotion_target":
            if self.witness_id:
                raise ValueError("Promotion endpoints cannot bind a witness")
            if self.target_region_id:
                raise ValueError("Promotion endpoints cannot bind a gossip region")
            if not self.target_environment_id or not self.target_stage:
                raise ValueError(
                    "Promotion endpoints require target environment and stage"
                )
            if self.auto_dispatch:
                raise ValueError(
                    "Promotion delivery requires an explicitly signed envelope"
                )
        else:
            if self.witness_id:
                raise ValueError("Gossip endpoints cannot bind a witness")
            if self.target_environment_id or self.target_stage:
                raise ValueError("Gossip endpoints cannot bind a promotion target")
            if not self.target_region_id:
                raise ValueError("Gossip endpoints require target_region_id")
        certificate = bool(self.tls_client_certificate_ref)
        private_key = bool(self.tls_client_private_key_ref)
        password = bool(self.tls_client_private_key_password_ref)
        if self.tls_mode == "mutual_tls":
            if not certificate or not private_key:
                raise ValueError(
                    "mutual_tls requires client certificate and private-key references"
                )
        elif certificate or private_key or password:
            raise ValueError(
                "Client certificate, private key, and password require mutual_tls"
            )
        if password and not private_key:
            raise ValueError(
                "Private-key password requires a private-key reference"
            )
        return self


class EcosystemTransportEndpointStateCreate(EcosystemTransportModel):
    enabled: bool
    auto_dispatch: bool | None = None
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class EcosystemTransportEndpointRead(EcosystemTransportModel):
    id: str
    name: str
    kind: EndpointKind
    url: str
    credential_profile_ref: str | None
    credential_configured: bool
    tls_mode: TransportTLSMode
    tls_ca_certificate_ref: str | None
    tls_client_certificate_ref: str | None
    tls_client_private_key_ref: str | None
    tls_client_private_key_password_ref: str | None
    custom_ca_configured: bool
    mutual_tls_configured: bool
    tls_revision: int
    witness_id: str | None
    target_environment_id: str | None
    target_stage: EnvironmentStage | None
    target_region_id: str | None
    auto_dispatch: bool
    enabled: bool
    request_timeout_seconds: int
    max_response_bytes: int
    created_by: str
    created_at: datetime
    updated_at: datetime


class EcosystemTransportTLSUpdate(EcosystemTransportModel):
    tls_mode: TransportTLSMode
    tls_ca_certificate_ref: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    tls_client_certificate_ref: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    tls_client_private_key_ref: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    tls_client_private_key_password_ref: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    expected_tls_revision: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_tls_binding(self) -> "EcosystemTransportTLSUpdate":
        certificate = bool(self.tls_client_certificate_ref)
        private_key = bool(self.tls_client_private_key_ref)
        password = bool(self.tls_client_private_key_password_ref)
        if self.tls_mode == "mutual_tls":
            if not certificate or not private_key:
                raise ValueError(
                    "mutual_tls requires client certificate and private-key references"
                )
        elif certificate or private_key or password:
            raise ValueError(
                "Client certificate, private key, and password require mutual_tls"
            )
        if password and not private_key:
            raise ValueError(
                "Private-key password requires a private-key reference"
            )
        return self


class EcosystemTransportWitnessDispatchCreate(EcosystemTransportModel):
    endpoint_ids: list[str] = Field(default_factory=list, max_length=16)
    max_attempts: int = Field(default=5, ge=1, le=20)
    actor: str = Field(min_length=1, max_length=255)


class EcosystemTransportGossipDispatchCreate(EcosystemTransportModel):
    endpoint_ids: list[str] = Field(default_factory=list, max_length=16)
    max_attempts: int = Field(default=5, ge=1, le=20)
    actor: str = Field(min_length=1, max_length=255)


class EcosystemTransportPromotionCreate(EcosystemTransportModel):
    endpoint_id: str = Field(min_length=1, max_length=36)
    signed_attestation: SignedCapabilityPromotionAttestation
    reason: str = Field(min_length=3, max_length=4000)
    max_attempts: int = Field(default=5, ge=1, le=20)
    actor: str = Field(min_length=1, max_length=255)


class EcosystemTransportJobAction(EcosystemTransportModel):
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class EcosystemTransportJobRead(EcosystemTransportModel):
    id: str
    endpoint_id: str
    endpoint_name: str
    kind: JobKind
    checkpoint_offer_id: str | None
    dedupe_key: str
    status: JobStatus
    attempt_count: int
    max_attempts: int
    next_attempt_at: datetime
    lease_worker_id: str | None
    lease_expires_at: datetime | None
    response_digest_sha256: str | None
    result_summary: dict[str, object]
    error_type: str | None
    error_sha256: str | None
    created_by: str
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class EcosystemTransportWorkerRead(EcosystemTransportModel):
    id: str
    name: str
    state: Literal["online", "draining", "offline"]
    last_heartbeat_at: datetime
    created_at: datetime
    updated_at: datetime


class EcosystemTransportHealthRead(EcosystemTransportModel):
    workers_total: int
    workers_online: int
    workers_stale: int
    pending: int
    processing: int
    retry: int
    succeeded: int
    dead_letter: int
    cancelled: int
    oldest_ready_age_seconds: float | None


class WitnessCheckpointSignRequest(EcosystemTransportModel):
    checkpoint: TransparencyCheckpointStatement
    idempotency_key: str = Field(min_length=1, max_length=128)
