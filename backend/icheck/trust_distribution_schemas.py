from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from .collector_schemas import ArtifactBundleSignature
from .schemas import APIModel


ORGANIZATION_TRUST_BUNDLE_FORMAT = "icheck.organization-trust-bundle/v1"
SIGNED_ORGANIZATION_TRUST_BUNDLE_FORMAT = (
    "icheck.organization-trust-bundle.signed/v1"
)
ORGANIZATION_TRUST_ROOT_ROTATION_FORMAT = (
    "icheck.organization-trust-root-rotation/v1"
)
SIGNED_ORGANIZATION_TRUST_ROOT_ROTATION_FORMAT = (
    "icheck.organization-trust-root-rotation.signed/v1"
)
TRUST_KEY_PURPOSES = (
    "artifact_bundle",
    "capability_pack",
    "capability_revocation",
    "remote_catalog",
    "transparency_witness",
    "trust_bundle",
    "environment_promotion",
    "snmp_exporter_attestation",
)
TrustKeyPurpose = Literal[
    "artifact_bundle",
    "capability_pack",
    "capability_revocation",
    "remote_catalog",
    "transparency_witness",
    "trust_bundle",
    "environment_promotion",
    "snmp_exporter_attestation",
]


class TrustDistributionModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class OrganizationTrustDomainCreate(TrustDistributionModel):
    name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_. -]*$",
    )
    organization_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    authority_trust_key_id: str = Field(min_length=1, max_length=36)
    idempotency_key: str | None = Field(
        default=None,
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    allowed_purposes: list[TrustKeyPurpose] = Field(
        default_factory=lambda: list(TRUST_KEY_PURPOSES),
        min_length=1,
        max_length=len(TRUST_KEY_PURPOSES),
    )
    max_bundle_lifetime_days: int = Field(default=30, ge=1, le=366)
    max_key_lifetime_days: int = Field(default=730, ge=1, le=3650)
    created_by: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_policy(self) -> "OrganizationTrustDomainCreate":
        if len(set(self.allowed_purposes)) != len(self.allowed_purposes):
            raise ValueError("Trust-domain allowed purposes must be unique")
        return self


class OrganizationTrustDomainStateCreate(TrustDistributionModel):
    enabled: bool
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class OrganizationTrustDomainRead(TrustDistributionModel):
    id: str
    name: str
    organization_id: str
    authority_trust_key_id: str
    authority_key_fingerprint_sha256: str
    enabled: bool
    allowed_purposes: list[str]
    max_bundle_lifetime_days: int
    max_key_lifetime_days: int
    latest_sequence: int
    latest_bundle_digest_sha256: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class OrganizationTrustBundleKey(TrustDistributionModel):
    name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    public_key_pem: str = Field(min_length=64, max_length=4096)
    fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    purposes: list[TrustKeyPurpose] = Field(min_length=1, max_length=8)
    state: Literal["active", "revoked"]
    valid_from: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_key(self) -> "OrganizationTrustBundleKey":
        if len(set(self.purposes)) != len(self.purposes):
            raise ValueError("Trust-bundle key purposes must be unique")
        if self.valid_from.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Trust-bundle key timestamps require offsets")
        if self.expires_at <= self.valid_from:
            raise ValueError("Trust-bundle key expiry must follow valid_from")
        return self


class OrganizationTrustBundle(TrustDistributionModel):
    format_version: Literal[
        "icheck.organization-trust-bundle/v1"
    ] = ORGANIZATION_TRUST_BUNDLE_FORMAT
    organization_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    sequence: int = Field(ge=1)
    issued_at: datetime
    expires_at: datetime
    keys: list[OrganizationTrustBundleKey] = Field(
        min_length=1,
        max_length=256,
    )
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_bundle(self) -> "OrganizationTrustBundle":
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Trust-bundle timestamps require offsets")
        if self.expires_at <= self.issued_at:
            raise ValueError("Trust-bundle expiry must follow issue time")
        fingerprints = [item.fingerprint_sha256 for item in self.keys]
        if len(set(fingerprints)) != len(fingerprints):
            raise ValueError("Trust-bundle key fingerprints must be unique")
        names = [item.name for item in self.keys]
        if len(set(names)) != len(names):
            raise ValueError("Trust-bundle key names must be unique")
        return self


class SignedOrganizationTrustBundle(TrustDistributionModel):
    format_version: Literal[
        "icheck.organization-trust-bundle.signed/v1"
    ] = SIGNED_ORGANIZATION_TRUST_BUNDLE_FORMAT
    bundle: OrganizationTrustBundle
    signature: ArtifactBundleSignature


class OrganizationTrustBundlePreviewCreate(TrustDistributionModel):
    signed_bundle: SignedOrganizationTrustBundle


class OrganizationTrustBundleImportCreate(TrustDistributionModel):
    signed_bundle: SignedOrganizationTrustBundle
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class OrganizationTrustKeyPlan(TrustDistributionModel):
    name: str
    fingerprint_sha256: str
    purposes: list[str]
    requested_state: Literal["active", "revoked"]
    action: Literal["add", "update", "revoke", "tombstone", "unchanged"]
    blockers: list[str] = Field(default_factory=list)


class OrganizationTrustBundlePreviewRead(TrustDistributionModel):
    trust_domain_id: str
    organization_id: str
    sequence: int
    bundle_digest_sha256: str
    authority_key_fingerprint_sha256: str
    issued_at: datetime
    expires_at: datetime
    key_count: int
    active_key_count: int
    revoked_key_count: int
    installable: bool
    blockers: list[str] = Field(default_factory=list)
    keys: list[OrganizationTrustKeyPlan]


class OrganizationTrustBundleImportRead(TrustDistributionModel):
    id: str
    trust_domain_id: str
    sequence: int
    bundle_digest_sha256: str
    authority_key_fingerprint_sha256: str
    signature_sha256: str
    issued_at: datetime
    expires_at: datetime
    key_count: int
    active_key_count: int
    revoked_key_count: int
    reason: str
    imported_by: str
    imported_at: datetime


class OrganizationTrustRootRotationStatement(TrustDistributionModel):
    format_version: Literal[
        "icheck.organization-trust-root-rotation/v1"
    ] = ORGANIZATION_TRUST_ROOT_ROTATION_FORMAT
    organization_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    bundle_sequence: int = Field(ge=0)
    bundle_digest_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    current_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    next_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    expires_at: datetime
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_rotation(
        self,
    ) -> "OrganizationTrustRootRotationStatement":
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Trust-root rotation timestamps require offsets")
        if self.expires_at <= self.issued_at:
            raise ValueError("Trust-root rotation expiry must follow issue time")
        if self.current_key_fingerprint_sha256 == (
            self.next_key_fingerprint_sha256
        ):
            raise ValueError("Trust-root rotation requires a different key")
        if (self.bundle_sequence == 0) != (
            self.bundle_digest_sha256 is None
        ):
            raise ValueError(
                "Trust-root rotation sequence and bundle digest are inconsistent"
            )
        return self


class SignedOrganizationTrustRootRotation(TrustDistributionModel):
    format_version: Literal[
        "icheck.organization-trust-root-rotation.signed/v1"
    ] = SIGNED_ORGANIZATION_TRUST_ROOT_ROTATION_FORMAT
    statement: OrganizationTrustRootRotationStatement
    current_signature: ArtifactBundleSignature
    next_signature: ArtifactBundleSignature


class OrganizationTrustRootRotationCreate(TrustDistributionModel):
    new_authority_trust_key_id: str = Field(min_length=1, max_length=36)
    signed_rotation: SignedOrganizationTrustRootRotation
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class OrganizationTrustRootRotationRead(TrustDistributionModel):
    id: str
    trust_domain_id: str
    from_trust_key_id: str
    to_trust_key_id: str
    from_key_fingerprint_sha256: str
    to_key_fingerprint_sha256: str
    bundle_sequence: int
    bundle_digest_sha256: str | None
    statement_digest_sha256: str
    current_signature_sha256: str
    next_signature_sha256: str
    issued_at: datetime
    expires_at: datetime
    reason: str
    rotated_by: str
    rotated_at: datetime
