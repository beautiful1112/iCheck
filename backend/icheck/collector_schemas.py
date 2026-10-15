from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .models import (
    ArtifactKind,
    ArtifactVersionStatus,
    CollectorDeploymentMode,
    CollectorMode,
    CollectorRunStatus,
    CollectorWorkerState,
    EnvelopeKind,
)
from .schemas import APIModel


class CollectorDefinitionInput(APIModel):
    adapter_type: str = Field(min_length=1, max_length=128)
    mode: CollectorMode = CollectorMode.POLL
    output_kinds: list[EnvelopeKind] = Field(min_length=1, max_length=4)
    credential_profile_ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )
    config_schema: dict[str, Any] = Field(default_factory=dict)
    target_schema: dict[str, Any] = Field(default_factory=dict)
    defaults: dict[str, Any] = Field(default_factory=dict)

    @field_validator("output_kinds")
    @classmethod
    def unique_output_kinds(
        cls, value: list[EnvelopeKind]
    ) -> list[EnvelopeKind]:
        return list(dict.fromkeys(value))


class CollectorDefinitionRead(CollectorDefinitionInput):
    id: str
    artifact_version_id: str
    created_at: datetime


class ArtifactVersionCreate(APIModel):
    definition: dict[str, Any] = Field(default_factory=dict)
    implementation: dict[str, Any] = Field(default_factory=dict)
    tests: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    created_by: str = Field(min_length=1, max_length=255)
    collector_definition: CollectorDefinitionInput | None = None


class ArtifactCreate(APIModel):
    name: str = Field(min_length=1, max_length=255)
    kind: ArtifactKind
    description: str = Field(default="", max_length=10000)
    owner: str = Field(min_length=1, max_length=255)
    labels: dict[str, Any] = Field(default_factory=dict)
    initial_version: ArtifactVersionCreate

    @model_validator(mode="after")
    def validate_kind_definition(self) -> ArtifactCreate:
        if self.kind == ArtifactKind.COLLECTOR:
            if self.initial_version.collector_definition is None:
                raise ValueError(
                    "collector artifacts require a collector_definition"
                )
        elif self.initial_version.collector_definition is not None:
            raise ValueError(
                "collector_definition is only valid for collector artifacts"
            )
        return self


class ArtifactVersionRead(APIModel):
    id: str
    artifact_id: str
    version: int
    status: ArtifactVersionStatus
    definition: dict[str, Any]
    implementation: dict[str, Any]
    tests: list[dict[str, Any]]
    validation_report: dict[str, Any]
    content_hash: str | None
    created_by: str
    created_at: datetime
    validated_at: datetime | None
    validated_by: str | None
    published_at: datetime | None
    published_by: str | None
    collector_definition: CollectorDefinitionRead | None = None


class ArtifactRead(APIModel):
    id: str
    name: str
    kind: ArtifactKind
    description: str
    owner: str
    labels: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    versions: list[ArtifactVersionRead] = Field(default_factory=list)


class ArtifactAction(APIModel):
    actor: str = Field(min_length=1, max_length=255)


class ArtifactBundleModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class ArtifactBundleIdentity(ArtifactBundleModel):
    name: str = Field(min_length=1, max_length=255)
    kind: ArtifactKind
    description: str = Field(default="", max_length=10000)
    labels: dict[str, Any] = Field(default_factory=dict)


class ArtifactBundleVersion(ArtifactBundleModel):
    definition: dict[str, Any] = Field(default_factory=dict)
    implementation: dict[str, Any] = Field(default_factory=dict)
    tests: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    collector_definition: CollectorDefinitionInput | None = None


class ArtifactBundleSource(ArtifactBundleModel):
    artifact_id: str = Field(min_length=1, max_length=128)
    version_id: str = Field(min_length=1, max_length=128)
    version: int = Field(ge=1)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ArtifactExportBundle(ArtifactBundleModel):
    format_version: Literal["icheck.artifact.bundle/v1"]
    artifact: ArtifactBundleIdentity
    version: ArtifactBundleVersion
    source: ArtifactBundleSource
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ArtifactImportCreate(ArtifactBundleModel):
    bundle: ArtifactExportBundle
    name_override: str | None = Field(default=None, min_length=1, max_length=255)
    created_by: str = Field(min_length=1, max_length=255)


class ArtifactBundleSignature(ArtifactBundleModel):
    algorithm: Literal["ed25519"]
    key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_base64: str = Field(min_length=80, max_length=128)


class ArtifactSignedBundle(ArtifactBundleModel):
    format_version: Literal["icheck.artifact.signed-bundle/v1"]
    bundle: ArtifactExportBundle
    signature: ArtifactBundleSignature


class ArtifactSignedImportCreate(ArtifactBundleModel):
    signed_bundle: ArtifactSignedBundle
    name_override: str | None = Field(default=None, min_length=1, max_length=255)
    created_by: str = Field(min_length=1, max_length=255)


class ArtifactTrustKeyCreate(ArtifactBundleModel):
    name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    public_key_pem: str = Field(min_length=64, max_length=4096)
    purposes: list[
        Literal[
            "artifact_bundle",
            "capability_pack",
            "capability_revocation",
            "remote_catalog",
            "transparency_witness",
            "trust_bundle",
            "environment_promotion",
            "trust_recovery",
            "snmp_exporter_attestation",
        ]
    ] = Field(
        default_factory=lambda: [
            "artifact_bundle",
            "capability_pack",
            "capability_revocation",
            "remote_catalog",
            "trust_bundle",
        ],
        min_length=1,
        max_length=9,
    )
    valid_from: datetime | None = None
    expires_at: datetime | None = None
    created_by: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_trust_key(self) -> "ArtifactTrustKeyCreate":
        if len(set(self.purposes)) != len(self.purposes):
            raise ValueError("Artifact trust-key purposes must be unique")
        if self.valid_from is not None and self.valid_from.tzinfo is None:
            raise ValueError("Artifact trust-key valid_from requires an offset")
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("Artifact trust-key expires_at requires an offset")
        if (
            self.valid_from is not None
            and self.expires_at is not None
            and self.expires_at <= self.valid_from
        ):
            raise ValueError("Artifact trust-key expiry must follow valid_from")
        return self


class ArtifactTrustKeyRead(ArtifactBundleModel):
    id: str
    name: str
    algorithm: str
    public_key_pem: str
    fingerprint_sha256: str
    enabled: bool
    purposes: list[str]
    trust_source: str
    trust_domain_id: str | None
    managed_bundle_sequence: int | None
    valid_from: datetime | None
    expires_at: datetime | None
    created_by: str
    created_at: datetime
    revoked_at: datetime | None
    revoked_by: str | None


class ArtifactTrustKeyAction(ArtifactBundleModel):
    actor: str = Field(min_length=1, max_length=255)


class ArtifactSignatureVerificationRead(ArtifactBundleModel):
    id: str
    artifact_version_id: str
    trust_key_id: str
    algorithm: str
    key_fingerprint_sha256: str
    bundle_digest_sha256: str
    signature_sha256: str
    verified_by: str
    verified_at: datetime


class ArtifactSemanticChange(ArtifactBundleModel):
    path: str = Field(min_length=1, max_length=2048)
    change_type: Literal["added", "removed", "changed"]
    before: Any = None
    after: Any = None


class ArtifactVersionDiffRead(ArtifactBundleModel):
    artifact_id: str
    from_version: int
    to_version: int
    from_content_hash: str | None
    to_content_hash: str | None
    change_count: int
    truncated: bool
    changes: list[ArtifactSemanticChange]


class ArtifactRestoreCreate(ArtifactBundleModel):
    source_version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class CollectorDeploymentCreate(APIModel):
    name: str = Field(min_length=1, max_length=255)
    artifact_version_id: str
    scope_device_id: str | None = Field(default=None, max_length=36)
    scope_device_identity_revision: int | None = Field(default=None, ge=1)
    target_classification: Literal["registered_device", "external_source"] | None = None
    external_source_reason: str | None = Field(default=None, min_length=10, max_length=1000)
    scope_site: str | None = Field(default=None, max_length=128)
    target: dict[str, Any] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    worker_selector: dict[str, str] = Field(default_factory=dict)
    execution_mode: CollectorDeploymentMode = CollectorDeploymentMode.SCHEDULED
    credential_profile_ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )
    schedule_seconds: int = Field(default=300, ge=5, le=86400)
    enabled: bool = True
    created_by: str = Field(min_length=1, max_length=255)
    next_run_at: datetime | None = None

    @model_validator(mode="after")
    def validate_execution_mode(self) -> CollectorDeploymentCreate:
        if self.execution_mode == CollectorDeploymentMode.SCHEDULED:
            if self.next_run_at is None:
                self.next_run_at = datetime.now(UTC)
        elif self.next_run_at is not None:
            raise ValueError(
                "on-demand deployments must be triggered explicitly"
            )
        return self


class CollectorDeploymentRead(APIModel):
    id: str
    name: str
    artifact_version_id: str
    scope_device_id: str | None
    scope_device_identity_revision: int | None
    target_classification: str | None
    external_source_reason: str | None
    scope_site: str | None
    target: dict[str, Any]
    configuration: dict[str, Any]
    worker_selector: dict[str, str]
    execution_mode: CollectorDeploymentMode
    credential_profile_ref: str | None
    schedule_seconds: int
    enabled: bool
    created_by: str
    next_run_at: datetime | None
    lease_worker_id: str | None
    lease_expires_at: datetime | None
    last_started_at: datetime | None
    last_finished_at: datetime | None
    created_at: datetime
    updated_at: datetime


class CollectorWorkerRegister(APIModel):
    name: str = Field(min_length=1, max_length=255)
    site: str | None = Field(default=None, max_length=128)
    capabilities: list[str] = Field(min_length=1, max_length=100)
    labels: dict[str, Any] = Field(default_factory=dict)

    @field_validator("capabilities")
    @classmethod
    def normalize_capabilities(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if not normalized:
            raise ValueError("at least one non-empty capability is required")
        return list(dict.fromkeys(normalized))


class CollectorWorkerHeartbeat(APIModel):
    state: CollectorWorkerState = CollectorWorkerState.ONLINE
    capabilities: list[str] | None = Field(default=None, max_length=100)
    labels: dict[str, Any] | None = None


class CollectorWorkerRead(APIModel):
    id: str
    name: str
    site: str | None
    capabilities: list[str]
    labels: dict[str, Any]
    state: CollectorWorkerState
    mtls_fingerprint_sha256: str | None
    mtls_not_after: datetime | None
    mtls_next_fingerprint_sha256: str | None
    mtls_next_not_before: datetime | None
    mtls_next_not_after: datetime | None
    mtls_revision: int
    last_heartbeat_at: datetime
    created_at: datetime
    updated_at: datetime


class CollectorWorkerRegistration(APIModel):
    worker: CollectorWorkerRead
    access_token: str


class CredentialProfileCreate(APIModel):
    name: str = Field(min_length=1, max_length=255)
    provider: str = Field(min_length=1, max_length=64)
    secret_ref: str = Field(min_length=1, max_length=1024)
    allowed_adapters: list[str] = Field(min_length=1, max_length=100)
    worker_selector: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    created_by: str = Field(min_length=1, max_length=255)

    @field_validator("allowed_adapters")
    @classmethod
    def normalize_allowed_adapters(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if not normalized:
            raise ValueError("at least one allowed adapter is required")
        return list(dict.fromkeys(normalized))


class CredentialProfileRotate(APIModel):
    expected_revision: int = Field(ge=0)
    secret_ref: str = Field(min_length=1, max_length=1024)
    reason: str = Field(min_length=1, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class CredentialProfileRead(APIModel):
    id: str
    name: str
    provider: str
    secret_ref: str
    allowed_adapters: list[str]
    worker_selector: dict[str, str]
    enabled: bool
    revision: int
    created_by: str
    created_at: datetime
    updated_at: datetime


class AuditEventRead(APIModel):
    id: str
    occurred_at: datetime
    event_type: str
    actor_type: str
    actor_id: str
    entity_type: str
    entity_id: str
    outcome: str
    details: dict[str, Any]


class CollectorLeaseClaim(APIModel):
    max_assignments: int = Field(default=1, ge=1, le=20)
    lease_seconds: int = Field(default=60, ge=15, le=3600)


class CollectorDeploymentTrigger(APIModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)


class CollectorAssignment(APIModel):
    run_id: str
    lease_token: str
    assignment_sha256: str = Field(min_length=64, max_length=64)
    lease_expires_at: datetime
    deployment_id: str
    deployment_name: str
    artifact_id: str
    artifact_name: str
    artifact_version_id: str
    artifact_version: int
    adapter_type: str
    mode: CollectorMode
    output_kinds: list[EnvelopeKind]
    target: dict[str, Any]
    configuration: dict[str, Any]
    definition: dict[str, Any]
    implementation: dict[str, Any]
    defaults: dict[str, Any]
    credential_profile_ref: str | None


class CollectorLeaseRenew(APIModel):
    lease_token: str = Field(min_length=20, max_length=512)
    lease_seconds: int = Field(default=60, ge=15, le=3600)


class CollectorRunAdmit(APIModel):
    lease_token: str = Field(min_length=20, max_length=512)
    assignment_sha256: str = Field(min_length=64, max_length=64)


class CredentialGrantRequest(APIModel):
    lease_token: str = Field(min_length=20, max_length=512)


class CredentialGrantRead(APIModel):
    profile_id: str
    profile_name: str
    provider: str
    secret_ref: str
    adapter_type: str
    deployment_id: str
    expires_at: datetime
    profile_revision: int


class CollectorRunComplete(APIModel):
    lease_token: str = Field(min_length=20, max_length=512)
    status: CollectorRunStatus
    error: str | None = Field(default=None, max_length=10000)
    stats: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_terminal_status(self) -> CollectorRunComplete:
        if self.status == CollectorRunStatus.RUNNING:
            raise ValueError("completion status must be terminal")
        if self.status == CollectorRunStatus.SUCCEEDED and self.error:
            raise ValueError("successful runs cannot include an error")
        return self


class CollectorRunRead(APIModel):
    id: str
    deployment_id: str
    artifact_version_id: str | None
    worker_id: str
    status: CollectorRunStatus
    execution_admitted_at: datetime | None
    started_at: datetime
    finished_at: datetime | None
    records_received: int
    error: str | None
    stats: dict[str, Any]


class CollectionEnvelopeInput(APIModel):
    kind: EnvelopeKind
    type: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=255)
    subject: str | None = Field(default=None, max_length=512)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, Any]
    idempotency_key: str | None = Field(default=None, max_length=512)


class CollectionEnvelopeBatch(APIModel):
    lease_token: str = Field(min_length=20, max_length=512)
    envelopes: list[CollectionEnvelopeInput] = Field(min_length=1, max_length=2000)


class EnvelopeIngestResult(APIModel):
    received: int
    accepted: int
    duplicates: int


class CollectorHealthSummary(APIModel):
    workers_total: int
    workers_online: int
    workers_stale: int
    deployments_total: int
    deployments_enabled: int
    deployments_leased: int
    deployments_due: int
    running_runs: int
    failed_runs_last_hour: int
