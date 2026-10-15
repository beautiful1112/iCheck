from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from .collector_schemas import ArtifactBundleSignature
from .schemas import APIModel


ORGANIZATION_TRUST_RECOVERY_POLICY_FORMAT = (
    "icheck.organization-trust-recovery-policy/v1"
)
SIGNED_ORGANIZATION_TRUST_RECOVERY_POLICY_FORMAT = (
    "icheck.organization-trust-recovery-policy.signed/v1"
)
ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT = (
    "icheck.organization-trust-root-reanchor/v1"
)
SIGNED_ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT = (
    "icheck.organization-trust-root-reanchor.signed/v1"
)
RECOVERY_SIGNING_REQUEST_FORMAT = "icheck.trust-recovery-signing-request/v1"
RECOVERY_SIGNING_RESPONSE_FORMAT = "icheck.trust-recovery-signing-response/v1"


class TrustRecoveryModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class OrganizationTrustRecoveryPolicyStatement(TrustRecoveryModel):
    format_version: Literal[
        "icheck.organization-trust-recovery-policy/v1"
    ] = ORGANIZATION_TRUST_RECOVERY_POLICY_FORMAT
    organization_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    trust_domain_id: str = Field(min_length=1, max_length=36)
    policy_version: int = Field(ge=1)
    bundle_sequence: int = Field(ge=0)
    bundle_digest_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    authority_key_fingerprint_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    trustee_key_fingerprints_sha256: list[str] = Field(
        min_length=2,
        max_length=8,
    )
    required_approvals: int = Field(ge=2, le=8)
    delay_hours: int = Field(ge=1, le=72)
    issued_at: datetime
    expires_at: datetime
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_policy(
        self,
    ) -> "OrganizationTrustRecoveryPolicyStatement":
        fingerprints = self.trustee_key_fingerprints_sha256
        if any(
            len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in fingerprints
        ):
            raise ValueError("Recovery trustee fingerprints must be SHA-256")
        if len(set(fingerprints)) != len(fingerprints):
            raise ValueError("Recovery trustee fingerprints must be unique")
        if fingerprints != sorted(fingerprints):
            raise ValueError("Recovery trustee fingerprints must be sorted")
        if self.required_approvals > len(fingerprints):
            raise ValueError("Recovery quorum exceeds the trustee count")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Recovery-policy timestamps require offsets")
        if self.expires_at <= self.issued_at:
            raise ValueError("Recovery-policy expiry must follow issue time")
        if (self.bundle_sequence == 0) != (
            self.bundle_digest_sha256 is None
        ):
            raise ValueError(
                "Recovery-policy bundle sequence and digest are inconsistent"
            )
        return self


class SignedOrganizationTrustRecoveryPolicy(TrustRecoveryModel):
    format_version: Literal[
        "icheck.organization-trust-recovery-policy.signed/v1"
    ] = SIGNED_ORGANIZATION_TRUST_RECOVERY_POLICY_FORMAT
    statement: OrganizationTrustRecoveryPolicyStatement
    authority_signature: ArtifactBundleSignature


class OrganizationTrustRecoveryPolicyStatementCreate(TrustRecoveryModel):
    trustee_trust_key_ids: list[str] = Field(min_length=2, max_length=8)
    required_approvals: int = Field(ge=2, le=8)
    delay_hours: int = Field(default=24, ge=1, le=72)
    validity_hours: int = Field(default=24, ge=1, le=24)
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_trustees(
        self,
    ) -> "OrganizationTrustRecoveryPolicyStatementCreate":
        if len(set(self.trustee_trust_key_ids)) != len(
            self.trustee_trust_key_ids
        ):
            raise ValueError("Recovery trustee keys must be unique")
        if self.required_approvals > len(self.trustee_trust_key_ids):
            raise ValueError("Recovery quorum exceeds the trustee count")
        return self


class OrganizationTrustRecoveryPolicyCreate(TrustRecoveryModel):
    trustee_trust_key_ids: list[str] = Field(min_length=2, max_length=8)
    signed_policy: SignedOrganizationTrustRecoveryPolicy
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_trustees(self) -> "OrganizationTrustRecoveryPolicyCreate":
        if len(set(self.trustee_trust_key_ids)) != len(
            self.trustee_trust_key_ids
        ):
            raise ValueError("Recovery trustee keys must be unique")
        return self


class OrganizationTrustRecoveryPolicyRead(TrustRecoveryModel):
    id: str
    trust_domain_id: str
    version: int
    active: bool
    authority_trust_key_id: str
    authority_key_fingerprint_sha256: str
    trustee_key_ids: list[str]
    trustee_key_fingerprints_sha256: list[str]
    required_approvals: int
    delay_hours: int
    bundle_sequence: int
    bundle_digest_sha256: str | None
    statement_digest_sha256: str
    authority_signature_sha256: str
    transparency_sequence: int
    reason: str
    created_by: str
    created_at: datetime
    superseded_at: datetime | None


class OrganizationTrustRootReanchorStatement(TrustRecoveryModel):
    format_version: Literal[
        "icheck.organization-trust-root-reanchor/v1"
    ] = ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT
    organization_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    trust_domain_id: str = Field(min_length=1, max_length=36)
    recovery_policy_version: int = Field(ge=1)
    recovery_policy_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ceremony_id: str = Field(
        min_length=36,
        max_length=36,
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    )
    bundle_sequence: int = Field(ge=0)
    bundle_digest_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    current_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    next_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    witness_log_id: str = Field(min_length=1, max_length=36)
    witness_epoch: int = Field(ge=1)
    witness_sequence: int = Field(ge=1)
    witness_head_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    expires_at: datetime
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_reanchor(
        self,
    ) -> "OrganizationTrustRootReanchorStatement":
        if self.current_key_fingerprint_sha256 == (
            self.next_key_fingerprint_sha256
        ):
            raise ValueError("Emergency re-anchor requires a different root")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Root re-anchor timestamps require offsets")
        if self.expires_at <= self.issued_at:
            raise ValueError("Root re-anchor expiry must follow issue time")
        if (self.bundle_sequence == 0) != (
            self.bundle_digest_sha256 is None
        ):
            raise ValueError(
                "Root re-anchor bundle sequence and digest are inconsistent"
            )
        return self


class SignedOrganizationTrustRootReanchor(TrustRecoveryModel):
    format_version: Literal[
        "icheck.organization-trust-root-reanchor.signed/v1"
    ] = SIGNED_ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT
    statement: OrganizationTrustRootReanchorStatement
    next_root_signature: ArtifactBundleSignature
    trustee_signatures: list[ArtifactBundleSignature] = Field(
        min_length=2,
        max_length=8,
    )


class OrganizationTrustRootReanchorStatementCreate(TrustRecoveryModel):
    new_authority_trust_key_id: str = Field(min_length=1, max_length=36)
    validity_hours: int = Field(default=48, ge=2, le=168)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class OrganizationTrustRootReanchorPreviewCreate(TrustRecoveryModel):
    new_authority_trust_key_id: str = Field(min_length=1, max_length=36)
    signed_reanchor: SignedOrganizationTrustRootReanchor


class OrganizationTrustRootReanchorProposalCreate(TrustRecoveryModel):
    new_authority_trust_key_id: str = Field(min_length=1, max_length=36)
    signed_reanchor: SignedOrganizationTrustRootReanchor
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class OrganizationTrustRootReanchorPreviewRead(TrustRecoveryModel):
    trust_domain_id: str
    recovery_policy_id: str
    recovery_policy_version: int
    ceremony_id: str
    from_key_fingerprint_sha256: str
    to_key_fingerprint_sha256: str
    witness_checkpoint_offer_id: str
    witness_sequence: int
    trustee_approval_count: int
    required_approvals: int
    execute_delay_hours: int
    eligible: bool
    blockers: list[str] = Field(default_factory=list)


class OrganizationTrustRootReanchorRead(TrustRecoveryModel):
    id: str
    trust_domain_id: str
    recovery_policy_id: str
    from_trust_key_id: str
    to_trust_key_id: str
    ceremony_id: str
    from_key_fingerprint_sha256: str
    to_key_fingerprint_sha256: str
    bundle_sequence: int
    bundle_digest_sha256: str | None
    witness_checkpoint_offer_id: str
    witness_log_id: str
    witness_epoch: int
    witness_sequence: int
    witness_head_digest_sha256: str
    statement_digest_sha256: str
    trustee_approval_count: int
    status: Literal["pending", "executed", "cancelled"]
    execute_after: datetime
    proposal_transparency_sequence: int | None
    execution_checkpoint_offer_id: str | None
    execution_transparency_sequence: int | None
    reason: str
    proposed_by: str
    proposed_at: datetime
    execution_reason: str | None
    executed_by: str | None
    executed_at: datetime | None
    cancelled_by: str | None
    cancelled_at: datetime | None
    issued_at: datetime
    expires_at: datetime


class OrganizationTrustRootReanchorAction(TrustRecoveryModel):
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class TrustRecoverySigningProviderCreate(TrustRecoveryModel):
    name: str = Field(min_length=1, max_length=255)
    provider_kind: Literal["hsm_gateway", "kms_gateway"]
    url: str = Field(min_length=1, max_length=2048)
    signing_key_ref: str = Field(min_length=1, max_length=1024)
    trust_key_id: str = Field(min_length=1, max_length=36)
    credential_profile_ref: str | None = Field(default=None, max_length=255)
    tls_mode: Literal["server_auth", "mutual_tls"] = "server_auth"
    tls_ca_certificate_ref: str | None = Field(default=None, max_length=255)
    tls_client_certificate_ref: str | None = Field(
        default=None,
        max_length=255,
    )
    tls_client_private_key_ref: str | None = Field(
        default=None,
        max_length=255,
    )
    tls_client_private_key_password_ref: str | None = Field(
        default=None,
        max_length=255,
    )
    request_timeout_seconds: int = Field(default=10, ge=1, le=30)
    max_response_bytes: int = Field(default=65536, ge=1024, le=65536)
    enabled: bool = True
    created_by: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_tls_binding(self) -> "TrustRecoverySigningProviderCreate":
        client_refs = (
            self.tls_client_certificate_ref,
            self.tls_client_private_key_ref,
            self.tls_client_private_key_password_ref,
        )
        if self.tls_mode == "server_auth" and any(client_refs):
            raise ValueError("server_auth cannot include a TLS client identity")
        if self.tls_mode == "mutual_tls" and (
            not self.tls_client_certificate_ref
            or not self.tls_client_private_key_ref
        ):
            raise ValueError("mutual_tls requires client certificate and key")
        return self


class TrustRecoverySigningProviderRead(TrustRecoveryModel):
    id: str
    name: str
    provider_kind: Literal["hsm_gateway", "kms_gateway"]
    url: str
    signing_key_ref: str
    trust_key_id: str
    key_fingerprint_sha256: str
    credential_profile_ref: str | None
    tls_mode: Literal["server_auth", "mutual_tls"]
    tls_ca_certificate_ref: str | None
    tls_client_certificate_ref: str | None
    tls_client_private_key_ref: str | None
    tls_client_private_key_password_ref: str | None
    tls_revision: int
    request_timeout_seconds: int
    max_response_bytes: int
    enabled: bool
    last_success_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class TrustRecoverySigningProviderStateCreate(TrustRecoveryModel):
    enabled: bool
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class TrustRecoverySigningProviderTLSUpdate(TrustRecoveryModel):
    expected_tls_revision: int = Field(ge=1)
    tls_mode: Literal["server_auth", "mutual_tls"]
    tls_ca_certificate_ref: str | None = Field(default=None, max_length=255)
    tls_client_certificate_ref: str | None = Field(
        default=None,
        max_length=255,
    )
    tls_client_private_key_ref: str | None = Field(
        default=None,
        max_length=255,
    )
    tls_client_private_key_password_ref: str | None = Field(
        default=None,
        max_length=255,
    )
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_tls_binding(
        self,
    ) -> "TrustRecoverySigningProviderTLSUpdate":
        client_refs = (
            self.tls_client_certificate_ref,
            self.tls_client_private_key_ref,
            self.tls_client_private_key_password_ref,
        )
        if self.tls_mode == "server_auth" and any(client_refs):
            raise ValueError("server_auth cannot include a TLS client identity")
        if self.tls_mode == "mutual_tls" and (
            not self.tls_client_certificate_ref
            or not self.tls_client_private_key_ref
        ):
            raise ValueError("mutual_tls requires client certificate and key")
        return self


class RecoverySigningGatewayRequest(TrustRecoveryModel):
    format_version: Literal[
        "icheck.trust-recovery-signing-request/v1"
    ] = RECOVERY_SIGNING_REQUEST_FORMAT
    request_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_id: str = Field(min_length=1, max_length=36)
    document_type: Literal["recovery_policy", "root_reanchor"]
    signed_format_version: str = Field(min_length=1, max_length=128)
    signing_key_ref: str = Field(min_length=1, max_length=1024)
    statement_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    message_base64: str = Field(min_length=4, max_length=4096)


class RecoverySigningGatewayResponse(TrustRecoveryModel):
    format_version: Literal[
        "icheck.trust-recovery-signing-response/v1"
    ] = RECOVERY_SIGNING_RESPONSE_FORMAT
    request_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: ArtifactBundleSignature


class TrustRecoveryPolicyProviderSignCreate(TrustRecoveryModel):
    provider_id: str = Field(min_length=1, max_length=36)
    statement: OrganizationTrustRecoveryPolicyStatement
    actor: str = Field(min_length=1, max_length=255)


class TrustRecoveryReanchorProviderSignCreate(TrustRecoveryModel):
    next_root_provider_id: str = Field(min_length=1, max_length=36)
    trustee_provider_ids: list[str] = Field(min_length=2, max_length=8)
    statement: OrganizationTrustRootReanchorStatement
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_providers(self) -> "TrustRecoveryReanchorProviderSignCreate":
        if len(set(self.trustee_provider_ids)) != len(
            self.trustee_provider_ids
        ):
            raise ValueError("Trustee signing providers must be unique")
        if self.next_root_provider_id in self.trustee_provider_ids:
            raise ValueError("Next-root and trustee providers must be distinct")
        return self


class TrustRecoverySigningEventRead(TrustRecoveryModel):
    id: str
    provider_id: str
    document_type: Literal["recovery_policy", "root_reanchor"]
    signed_format_version: str
    statement_digest_sha256: str
    request_digest_sha256: str
    trust_key_id: str
    key_fingerprint_sha256: str
    signature_sha256: str
    response_digest_sha256: str
    tls_evidence: dict[str, object]
    requested_by: str
    requested_at: datetime
