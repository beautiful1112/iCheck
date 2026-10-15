from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from pydantic import ValidationError
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..credentials import (
    CredentialProvider,
    CredentialUnavailable,
    resolve_server_secret,
)
from ..models import (
    ArtifactTrustKey,
    CredentialProfile,
    OrganizationTrustDomain,
    OrganizationTrustRecoveryPolicy,
    TrustRecoverySigningEvent,
    TrustRecoverySigningProvider,
    utcnow,
)
from ..trust_recovery_schemas import (
    RECOVERY_SIGNING_REQUEST_FORMAT,
    SIGNED_ORGANIZATION_TRUST_RECOVERY_POLICY_FORMAT,
    SIGNED_ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT,
    OrganizationTrustRecoveryPolicyStatement,
    OrganizationTrustRootReanchorStatement,
    RecoverySigningGatewayRequest,
    RecoverySigningGatewayResponse,
    SignedOrganizationTrustRecoveryPolicy,
    SignedOrganizationTrustRootReanchor,
    TrustRecoveryPolicyProviderSignCreate,
    TrustRecoveryReanchorProviderSignCreate,
    TrustRecoverySigningProviderCreate,
    TrustRecoverySigningProviderStateCreate,
    TrustRecoverySigningProviderTLSUpdate,
)
from .artifact_portability import (
    ensure_trust_key_usable,
    verify_trusted_digest_signature,
)
from .audit import record_audit_event
from .trust_namespace import assert_selected_trust_namespace
from .ecosystem_transport import (
    EcosystemTransportPermanentError,
    EcosystemTransportUnavailable,
    build_transport_tls_context,
)
from .transparency_witnessing import require_live_witnessed_checkpoint_offer


RECOVERY_SIGNING_ADAPTER = "trust_recovery_signing"
RECOVERY_CLOCK_SKEW = timedelta(minutes=5)
RECOVERY_POLICY_MAX_LIFETIME = timedelta(hours=24)
ROOT_REANCHOR_MAX_LIFETIME = timedelta(hours=168)


class RecoverySigningPermanentError(ValueError):
    """The configured binding or returned signature is invalid."""


class RecoverySigningUnavailable(RuntimeError):
    """The gateway or its server-side credential provider is unavailable."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for recovery signing",
            headers,
            fp,
        )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _host_allowed(hostname: str, allowed_hosts: list[str]) -> bool:
    host = hostname.rstrip(".").lower()
    for pattern in allowed_hosts:
        normalized = pattern.rstrip(".").lower()
        if normalized.startswith("*."):
            suffix = normalized[1:]
            if host.endswith(suffix) and host != normalized[2:]:
                return True
        elif host == normalized:
            return True
    return False


def validate_recovery_signing_url(
    url: str,
    *,
    allowed_hosts: list[str] | None = None,
) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Recovery signing providers must use HTTPS")
    if parsed.username or parsed.password:
        raise ValueError("Recovery signing URLs must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError(
            "Recovery signing URLs must not contain query or fragment data"
        )
    configured = (
        get_settings().recovery_signing_allowed_host_list
        if allowed_hosts is None
        else allowed_hosts
    )
    if not _host_allowed(parsed.hostname, configured):
        raise ValueError(
            "Recovery signing host is not in "
            "ICHECK_RECOVERY_SIGNING_ALLOWED_HOSTS"
        )
    return url


def _credential_profile(
    db: Session,
    reference: str,
) -> CredentialProfile | None:
    return db.scalar(
        select(CredentialProfile).where(
            or_(
                CredentialProfile.id == reference,
                CredentialProfile.name == reference,
            )
        )
    )


def _validate_credential_reference(
    db: Session,
    reference: str | None,
) -> None:
    if not reference:
        return
    profile = _credential_profile(db, reference)
    if profile is None:
        raise ValueError(f"Credential profile {reference!r} does not exist")
    if not profile.enabled:
        raise ValueError(f"Credential profile {reference!r} is disabled")
    if RECOVERY_SIGNING_ADAPTER not in profile.allowed_adapters:
        raise ValueError(
            f"Credential profile {reference!r} does not allow "
            f"{RECOVERY_SIGNING_ADAPTER!r}"
        )
    if profile.worker_selector:
        raise ValueError(
            "Recovery signing requires a server-side credential profile"
        )


def _validate_tls_references(
    db: Session,
    *,
    credential_profile_ref: str | None,
    ca_reference: str | None,
    certificate_reference: str | None,
    private_key_reference: str | None,
    password_reference: str | None,
) -> None:
    for reference in (
        credential_profile_ref,
        ca_reference,
        certificate_reference,
        private_key_reference,
        password_reference,
    ):
        _validate_credential_reference(db, reference)


def _usable_local_key(
    db: Session,
    key_id: str,
    *,
    expected_purpose: str | None = None,
) -> ArtifactTrustKey:
    key = db.get(ArtifactTrustKey, key_id)
    if key is None:
        raise ValueError("Recovery signing trust key does not exist")
    if key.trust_source != "local":
        raise ValueError("Recovery signing trust key must be pinned locally")
    purposes = set(key.purposes or [])
    if expected_purpose is None:
        candidates = purposes.intersection({"trust_bundle", "trust_recovery"})
        if not candidates:
            raise ValueError(
                "Recovery signing key requires trust_bundle or trust_recovery purpose"
            )
        expected_purpose = sorted(candidates)[0]
    ensure_trust_key_usable(
        db,
        key,
        expected_purpose=expected_purpose,
    )
    return key


def _validate_signing_key_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError("Signing key reference contains invalid characters")
    return value


def create_signing_provider(
    db: Session,
    payload: TrustRecoverySigningProviderCreate,
    *,
    actor: str,
    allowed_hosts: list[str] | None = None,
) -> TrustRecoverySigningProvider:
    validate_recovery_signing_url(payload.url, allowed_hosts=allowed_hosts)
    _validate_signing_key_ref(payload.signing_key_ref)
    key = _usable_local_key(db, payload.trust_key_id)
    _validate_tls_references(
        db,
        credential_profile_ref=payload.credential_profile_ref,
        ca_reference=payload.tls_ca_certificate_ref,
        certificate_reference=payload.tls_client_certificate_ref,
        private_key_reference=payload.tls_client_private_key_ref,
        password_reference=payload.tls_client_private_key_password_ref,
    )
    provider = TrustRecoverySigningProvider(
        name=payload.name,
        provider_kind=payload.provider_kind,
        url=payload.url,
        signing_key_ref=payload.signing_key_ref,
        trust_key_id=key.id,
        key_fingerprint_sha256=key.fingerprint_sha256,
        credential_profile_ref=payload.credential_profile_ref,
        tls_mode=payload.tls_mode,
        tls_ca_certificate_ref=payload.tls_ca_certificate_ref,
        tls_client_certificate_ref=payload.tls_client_certificate_ref,
        tls_client_private_key_ref=payload.tls_client_private_key_ref,
        tls_client_private_key_password_ref=(
            payload.tls_client_private_key_password_ref
        ),
        tls_revision=1,
        request_timeout_seconds=payload.request_timeout_seconds,
        max_response_bytes=payload.max_response_bytes,
        enabled=payload.enabled,
        created_by=actor,
    )
    db.add(provider)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="capability.trust_recovery_signer.registered",
            actor_type="user",
            actor_id=actor,
            entity_type="trust_recovery_signing_provider",
            entity_id=provider.id,
            details={
                "provider_kind": provider.provider_kind,
                "key_fingerprint_sha256": provider.key_fingerprint_sha256,
                "signing_key_ref_sha256": hashlib.sha256(
                    provider.signing_key_ref.encode("utf-8")
                ).hexdigest(),
                "tls_mode": provider.tls_mode,
                "tls_revision": provider.tls_revision,
                "has_application_credential": bool(
                    provider.credential_profile_ref
                ),
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Recovery signing provider name already exists") from exc
    db.refresh(provider)
    return provider


def list_signing_providers(
    db: Session,
    *,
    limit: int,
) -> list[TrustRecoverySigningProvider]:
    return list(
        db.scalars(
            select(TrustRecoverySigningProvider)
            .order_by(TrustRecoverySigningProvider.name)
            .limit(limit)
        ).all()
    )


def set_signing_provider_state(
    db: Session,
    provider_id: str,
    payload: TrustRecoverySigningProviderStateCreate,
    *,
    actor: str,
) -> TrustRecoverySigningProvider:
    provider = db.get(TrustRecoverySigningProvider, provider_id)
    if provider is None:
        raise LookupError("Recovery signing provider not found")
    if provider.enabled == payload.enabled:
        return provider
    if payload.enabled:
        validate_recovery_signing_url(provider.url)
        _usable_local_key(db, provider.trust_key_id)
        _validate_tls_references(
            db,
            credential_profile_ref=provider.credential_profile_ref,
            ca_reference=provider.tls_ca_certificate_ref,
            certificate_reference=provider.tls_client_certificate_ref,
            private_key_reference=provider.tls_client_private_key_ref,
            password_reference=(
                provider.tls_client_private_key_password_ref
            ),
        )
    provider.enabled = payload.enabled
    provider.updated_at = utcnow()
    record_audit_event(
        db,
        event_type=(
            "capability.trust_recovery_signer.enabled"
            if provider.enabled
            else "capability.trust_recovery_signer.disabled"
        ),
        actor_type="user",
        actor_id=actor,
        entity_type="trust_recovery_signing_provider",
        entity_id=provider.id,
        details={
            "key_fingerprint_sha256": provider.key_fingerprint_sha256,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    db.commit()
    db.refresh(provider)
    return provider


def update_signing_provider_tls(
    db: Session,
    provider_id: str,
    payload: TrustRecoverySigningProviderTLSUpdate,
    *,
    actor: str,
) -> TrustRecoverySigningProvider:
    provider = db.scalar(
        select(TrustRecoverySigningProvider)
        .where(TrustRecoverySigningProvider.id == provider_id)
        .with_for_update()
    )
    if provider is None:
        raise LookupError("Recovery signing provider not found")
    if provider.tls_revision != payload.expected_tls_revision:
        raise ValueError("Recovery signing TLS revision is stale")
    _validate_tls_references(
        db,
        credential_profile_ref=provider.credential_profile_ref,
        ca_reference=payload.tls_ca_certificate_ref,
        certificate_reference=payload.tls_client_certificate_ref,
        private_key_reference=payload.tls_client_private_key_ref,
        password_reference=payload.tls_client_private_key_password_ref,
    )
    provider.tls_mode = payload.tls_mode
    provider.tls_ca_certificate_ref = payload.tls_ca_certificate_ref
    provider.tls_client_certificate_ref = payload.tls_client_certificate_ref
    provider.tls_client_private_key_ref = (
        payload.tls_client_private_key_ref
    )
    provider.tls_client_private_key_password_ref = (
        payload.tls_client_private_key_password_ref
    )
    provider.tls_revision += 1
    provider.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="capability.trust_recovery_signer.tls_rotated",
        actor_type="user",
        actor_id=actor,
        entity_type="trust_recovery_signing_provider",
        entity_id=provider.id,
        details={
            "tls_mode": provider.tls_mode,
            "tls_revision": provider.tls_revision,
            "has_custom_ca": bool(provider.tls_ca_certificate_ref),
            "has_client_identity": bool(
                provider.tls_client_certificate_ref
            ),
            "has_private_key_password": bool(
                provider.tls_client_private_key_password_ref
            ),
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    db.commit()
    db.refresh(provider)
    return provider


def _authorization_header(
    db: Session,
    provider: TrustRecoverySigningProvider,
    *,
    credential_providers: Mapping[str, CredentialProvider] | None,
) -> str | None:
    if not provider.credential_profile_ref:
        return None
    profile = _credential_profile(db, provider.credential_profile_ref)
    if profile is None:
        raise RecoverySigningUnavailable(
            "Configured recovery signing credential is unavailable"
        )
    try:
        token = resolve_server_secret(
            profile,
            adapter_type=RECOVERY_SIGNING_ADAPTER,
            providers=credential_providers,
        )
    except CredentialUnavailable as exc:
        raise RecoverySigningUnavailable(str(exc)) from exc
    if "\r" in token or "\n" in token:
        raise RecoverySigningPermanentError(
            "Recovery signing credential contains invalid header characters"
        )
    return f"Bearer {token}"


def _post_gateway_request(
    provider: TrustRecoverySigningProvider,
    payload: RecoverySigningGatewayRequest,
    *,
    authorization: str | None,
    tls_context: Any,
    opener: Any | None,
) -> tuple[RecoverySigningGatewayResponse, str]:
    validate_recovery_signing_url(provider.url)
    encoded = _canonical_bytes(payload.model_dump(mode="json"))
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "iCheck-Recovery-Signing/1",
        "X-iCheck-Idempotency-Key": payload.request_digest_sha256,
    }
    if authorization:
        headers["Authorization"] = authorization
    request = Request(provider.url, data=encoded, headers=headers, method="POST")
    client = opener or build_opener(
        _NoRedirect(),
        HTTPSHandler(context=tls_context),
    ).open
    try:
        response = client(request, timeout=provider.request_timeout_seconds)
        with response:
            if response.headers.get_content_type() != "application/json":
                raise RecoverySigningPermanentError(
                    "Recovery signing response must use application/json"
                )
            raw = response.read(provider.max_response_bytes + 1)
    except HTTPError as exc:
        if exc.code in {408, 425, 429} or exc.code >= 500:
            raise RecoverySigningUnavailable(
                f"Recovery signing provider returned HTTP {exc.code}"
            ) from exc
        raise RecoverySigningPermanentError(
            f"Recovery signing provider rejected request with HTTP {exc.code}"
        ) from exc
    except (TimeoutError, URLError, OSError) as exc:
        raise RecoverySigningUnavailable(
            f"Recovery signing provider is unavailable: {type(exc).__name__}"
        ) from exc
    if len(raw) > provider.max_response_bytes:
        raise RecoverySigningPermanentError(
            "Recovery signing response exceeds the configured byte limit"
        )
    try:
        document = json.loads(raw)
        parsed = RecoverySigningGatewayResponse.model_validate(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise RecoverySigningPermanentError(
            "Recovery signing response is not a valid signed response"
        ) from exc
    return parsed, hashlib.sha256(raw).hexdigest()


def _request_material(
    provider: TrustRecoverySigningProvider,
    *,
    document_type: str,
    signed_format_version: str,
    statement_digest_sha256: str,
) -> dict[str, Any]:
    message = (
        f"{signed_format_version}\n{statement_digest_sha256}"
    ).encode("ascii")
    return {
        "format_version": RECOVERY_SIGNING_REQUEST_FORMAT,
        "provider_id": provider.id,
        "document_type": document_type,
        "signed_format_version": signed_format_version,
        "signing_key_ref": provider.signing_key_ref,
        "statement_digest_sha256": statement_digest_sha256,
        "message_base64": base64.b64encode(message).decode("ascii"),
    }


def _request_signature(
    db: Session,
    provider: TrustRecoverySigningProvider,
    *,
    document_type: str,
    signed_format_version: str,
    statement_digest_sha256: str,
    expected_purpose: str,
    actor: str,
    credential_providers: Mapping[str, CredentialProvider] | None = None,
    opener: Any | None = None,
) -> dict[str, Any]:
    if not provider.enabled:
        raise ValueError("Recovery signing provider is disabled")
    validate_recovery_signing_url(provider.url)
    key = _usable_local_key(
        db,
        provider.trust_key_id,
        expected_purpose=expected_purpose,
    )
    if key.fingerprint_sha256 != provider.key_fingerprint_sha256:
        raise ValueError("Recovery signing provider key binding has drifted")
    material = _request_material(
        provider,
        document_type=document_type,
        signed_format_version=signed_format_version,
        statement_digest_sha256=statement_digest_sha256,
    )
    request_digest = _digest(material)
    existing = db.scalar(
        select(TrustRecoverySigningEvent).where(
            TrustRecoverySigningEvent.request_digest_sha256 == request_digest
        )
    )
    if existing is not None:
        return existing.signature_snapshot
    request_payload = RecoverySigningGatewayRequest.model_validate(
        {**material, "request_digest_sha256": request_digest}
    )
    authorization = _authorization_header(
        db,
        provider,
        credential_providers=credential_providers,
    )
    try:
        tls_binding = build_transport_tls_context(
            db,
            provider,
            adapter_type=RECOVERY_SIGNING_ADAPTER,
            credential_providers=credential_providers,
        )
    except EcosystemTransportPermanentError as exc:
        raise RecoverySigningPermanentError(str(exc)) from exc
    except EcosystemTransportUnavailable as exc:
        raise RecoverySigningUnavailable(str(exc)) from exc
    response, response_digest = _post_gateway_request(
        provider,
        request_payload,
        authorization=authorization,
        tls_context=tls_binding.context,
        opener=opener,
    )
    if response.request_digest_sha256 != request_digest:
        raise RecoverySigningPermanentError(
            "Recovery signing response request digest does not match"
        )
    try:
        verification = verify_trusted_digest_signature(
            db,
            response.signature,
            expected_digest_sha256=statement_digest_sha256,
            signed_format_version=signed_format_version,
            expected_purpose=expected_purpose,
        )
    except ValueError as exc:
        raise RecoverySigningPermanentError(str(exc)) from exc
    if (
        verification["trust_key_id"] != provider.trust_key_id
        or verification["key_fingerprint_sha256"]
        != provider.key_fingerprint_sha256
    ):
        raise RecoverySigningPermanentError(
            "Recovery signing response is not from the pinned provider key"
        )
    event = TrustRecoverySigningEvent(
        provider_id=provider.id,
        document_type=document_type,
        signed_format_version=signed_format_version,
        statement_digest_sha256=statement_digest_sha256,
        request_digest_sha256=request_digest,
        trust_key_id=provider.trust_key_id,
        key_fingerprint_sha256=provider.key_fingerprint_sha256,
        signature_sha256=verification["signature_sha256"],
        signature_snapshot=response.signature.model_dump(mode="json"),
        response_digest_sha256=response_digest,
        tls_evidence=tls_binding.evidence,
        requested_by=actor,
    )
    db.add(event)
    provider.last_success_at = utcnow()
    provider.updated_at = utcnow()
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="capability.trust_recovery_signature.received",
            actor_type="user",
            actor_id=actor,
            entity_type="trust_recovery_signing_event",
            entity_id=event.id,
            details={
                "provider_id": provider.id,
                "provider_kind": provider.provider_kind,
                "document_type": document_type,
                "statement_digest_sha256": statement_digest_sha256,
                "request_digest_sha256": request_digest,
                "key_fingerprint_sha256": provider.key_fingerprint_sha256,
                "signature_sha256": verification["signature_sha256"],
                "response_digest_sha256": response_digest,
                "tls_evidence": tls_binding.evidence,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        existing = db.scalar(
            select(TrustRecoverySigningEvent).where(
                TrustRecoverySigningEvent.request_digest_sha256
                == request_digest
            )
        )
        if existing is not None:
            return existing.signature_snapshot
        raise RecoverySigningPermanentError(
            "Recovery signing event conflicts with existing evidence"
        ) from exc
    return event.signature_snapshot


def _validate_statement_digest(statement: Any, *, label: str) -> None:
    material = statement.model_dump(mode="json", exclude={"digest_sha256"})
    if _digest(material) != statement.digest_sha256:
        raise ValueError(f"{label} statement digest does not match")


def _active_policy(
    db: Session,
    domain_id: str,
) -> OrganizationTrustRecoveryPolicy | None:
    return db.scalar(
        select(OrganizationTrustRecoveryPolicy)
        .where(
            OrganizationTrustRecoveryPolicy.trust_domain_id == domain_id,
            OrganizationTrustRecoveryPolicy.active.is_(True),
        )
        .order_by(OrganizationTrustRecoveryPolicy.version.desc())
        .limit(1)
    )


def _validate_policy_statement_for_signing(
    db: Session,
    domain: OrganizationTrustDomain,
    statement: OrganizationTrustRecoveryPolicyStatement,
) -> None:
    assert_selected_trust_namespace(db, domain)
    _validate_statement_digest(statement, label="Recovery policy")
    if not domain.enabled:
        raise ValueError("Recovery policy can be signed only before containment")
    current = _active_policy(db, domain.id)
    expected_version = current.version + 1 if current is not None else 1
    if (
        statement.organization_id != domain.organization_id
        or statement.trust_domain_id != domain.id
        or statement.policy_version != expected_version
    ):
        raise ValueError("Recovery policy statement identity or version is stale")
    if (
        statement.bundle_sequence != domain.latest_sequence
        or statement.bundle_digest_sha256 != domain.latest_bundle_digest_sha256
        or statement.authority_key_fingerprint_sha256
        != domain.authority_key_fingerprint_sha256
    ):
        raise ValueError("Recovery policy statement trust head is stale")
    now = utcnow()
    issued_at = _as_utc(statement.issued_at)
    expires_at = _as_utc(statement.expires_at)
    if issued_at > now + RECOVERY_CLOCK_SKEW or expires_at <= now:
        raise ValueError("Recovery policy statement is not currently valid")
    if expires_at - issued_at > RECOVERY_POLICY_MAX_LIFETIME:
        raise ValueError("Recovery policy statement exceeds 24 hours")
    trustees = list(
        db.scalars(
            select(ArtifactTrustKey).where(
                ArtifactTrustKey.tenant_id == domain.tenant_id,
                ArtifactTrustKey.region_id == domain.region_id,
                ArtifactTrustKey.fingerprint_sha256.in_(
                    statement.trustee_key_fingerprints_sha256
                )
            )
        ).all()
    )
    if len(trustees) != len(statement.trustee_key_fingerprints_sha256):
        raise ValueError("Recovery policy trustee set is not pinned locally")
    for trustee in trustees:
        _usable_local_key(
            db,
            trustee.id,
            expected_purpose="trust_recovery",
        )


def sign_recovery_policy_with_provider(
    db: Session,
    domain_id: str,
    payload: TrustRecoveryPolicyProviderSignCreate,
    *,
    actor: str,
    credential_providers: Mapping[str, CredentialProvider] | None = None,
    opener: Any | None = None,
) -> SignedOrganizationTrustRecoveryPolicy:
    domain = db.get(OrganizationTrustDomain, domain_id)
    if domain is None:
        raise LookupError("Organization trust domain not found")
    assert_selected_trust_namespace(db, domain)
    _validate_policy_statement_for_signing(db, domain, payload.statement)
    provider = db.get(TrustRecoverySigningProvider, payload.provider_id)
    if provider is None:
        raise LookupError("Recovery signing provider not found")
    if (
        provider.trust_key_id != domain.authority_trust_key_id
        or provider.key_fingerprint_sha256
        != payload.statement.authority_key_fingerprint_sha256
    ):
        raise ValueError("Signing provider is not bound to the current root")
    signature = _request_signature(
        db,
        provider,
        document_type="recovery_policy",
        signed_format_version=(
            SIGNED_ORGANIZATION_TRUST_RECOVERY_POLICY_FORMAT
        ),
        statement_digest_sha256=payload.statement.digest_sha256,
        expected_purpose="trust_bundle",
        actor=actor,
        credential_providers=credential_providers,
        opener=opener,
    )
    return SignedOrganizationTrustRecoveryPolicy.model_validate(
        {
            "format_version": (
                SIGNED_ORGANIZATION_TRUST_RECOVERY_POLICY_FORMAT
            ),
            "statement": payload.statement.model_dump(mode="json"),
            "authority_signature": signature,
        }
    )


def _validate_reanchor_statement_for_signing(
    db: Session,
    domain: OrganizationTrustDomain,
    policy: OrganizationTrustRecoveryPolicy,
    statement: OrganizationTrustRootReanchorStatement,
) -> None:
    _validate_statement_digest(statement, label="Root re-anchor")
    if domain.enabled:
        raise ValueError("Disable the trust domain before signing a re-anchor")
    if (
        statement.organization_id != domain.organization_id
        or statement.trust_domain_id != domain.id
        or statement.recovery_policy_version != policy.version
        or statement.recovery_policy_digest_sha256
        != policy.statement_digest_sha256
    ):
        raise ValueError("Root re-anchor policy binding is stale")
    if (
        statement.bundle_sequence != domain.latest_sequence
        or statement.bundle_digest_sha256 != domain.latest_bundle_digest_sha256
        or statement.current_key_fingerprint_sha256
        != domain.authority_key_fingerprint_sha256
    ):
        raise ValueError("Root re-anchor trust head is stale")
    now = utcnow()
    issued_at = _as_utc(statement.issued_at)
    expires_at = _as_utc(statement.expires_at)
    if issued_at > now + RECOVERY_CLOCK_SKEW or expires_at <= now:
        raise ValueError("Root re-anchor statement is not currently valid")
    if expires_at - issued_at > ROOT_REANCHOR_MAX_LIFETIME:
        raise ValueError("Root re-anchor statement exceeds 168 hours")
    if expires_at <= now + timedelta(hours=policy.delay_hours):
        raise ValueError("Root re-anchor expires before its recovery delay")
    offer = require_live_witnessed_checkpoint_offer(
        db,
        log_id=statement.witness_log_id,
        epoch=statement.witness_epoch,
        sequence=statement.witness_sequence,
        head_digest_sha256=statement.witness_head_digest_sha256,
    )
    if offer.sequence < policy.transparency_sequence:
        raise ValueError("Recovery policy is not covered by the checkpoint")


def sign_root_reanchor_with_providers(
    db: Session,
    domain_id: str,
    payload: TrustRecoveryReanchorProviderSignCreate,
    *,
    actor: str,
    credential_providers: Mapping[str, CredentialProvider] | None = None,
    opener: Any | None = None,
) -> SignedOrganizationTrustRootReanchor:
    domain = db.get(OrganizationTrustDomain, domain_id)
    if domain is None:
        raise LookupError("Organization trust domain not found")
    assert_selected_trust_namespace(db, domain)
    policy = _active_policy(db, domain.id)
    if policy is None:
        raise ValueError("No active root-recovery policy is authorized")
    _validate_reanchor_statement_for_signing(
        db,
        domain,
        policy,
        payload.statement,
    )
    next_provider = db.get(
        TrustRecoverySigningProvider,
        payload.next_root_provider_id,
    )
    if next_provider is None:
        raise LookupError("Next-root signing provider not found")
    if next_provider.key_fingerprint_sha256 != (
        payload.statement.next_key_fingerprint_sha256
    ):
        raise ValueError("Next-root signing provider does not match the statement")
    trustee_providers: list[TrustRecoverySigningProvider] = []
    for provider_id in payload.trustee_provider_ids:
        provider = db.get(TrustRecoverySigningProvider, provider_id)
        if provider is None:
            raise LookupError("Recovery trustee signing provider not found")
        if provider.trust_key_id not in set(policy.trustee_key_ids):
            raise ValueError(
                "Recovery signing provider is not an authorized trustee"
            )
        trustee_providers.append(provider)
    if len(trustee_providers) < policy.required_approvals:
        raise ValueError("Recovery signing providers do not satisfy quorum")

    next_signature = _request_signature(
        db,
        next_provider,
        document_type="root_reanchor",
        signed_format_version=SIGNED_ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT,
        statement_digest_sha256=payload.statement.digest_sha256,
        expected_purpose="trust_bundle",
        actor=actor,
        credential_providers=credential_providers,
        opener=opener,
    )
    trustee_signatures: list[dict[str, Any]] = []
    for provider in trustee_providers:
        trustee_signatures.append(
            _request_signature(
                db,
                provider,
                document_type="root_reanchor",
                signed_format_version=(
                    SIGNED_ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT
                ),
                statement_digest_sha256=payload.statement.digest_sha256,
                expected_purpose="trust_recovery",
                actor=actor,
                credential_providers=credential_providers,
                opener=opener,
            )
        )
    trustee_signatures.sort(
        key=lambda item: item["key_fingerprint_sha256"]
    )
    record_audit_event(
        db,
        event_type="capability.trust_root_reanchor.signatures_assembled",
        actor_type="user",
        actor_id=actor,
        entity_type="organization_trust_domain",
        entity_id=domain.id,
        details={
            "ceremony_id": payload.statement.ceremony_id,
            "statement_digest_sha256": payload.statement.digest_sha256,
            "next_root_provider_id": next_provider.id,
            "trustee_provider_count": len(trustee_providers),
            "trustee_key_fingerprints_sha256": [
                item["key_fingerprint_sha256"]
                for item in trustee_signatures
            ],
        },
    )
    db.commit()
    return SignedOrganizationTrustRootReanchor.model_validate(
        {
            "format_version": (
                SIGNED_ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT
            ),
            "statement": payload.statement.model_dump(mode="json"),
            "next_root_signature": next_signature,
            "trustee_signatures": trustee_signatures,
        }
    )


def list_signing_events(
    db: Session,
    *,
    provider_id: str | None,
    limit: int,
) -> list[TrustRecoverySigningEvent]:
    query = select(TrustRecoverySigningEvent)
    if provider_id:
        query = query.where(
            TrustRecoverySigningEvent.provider_id == provider_id
        )
    return list(
        db.scalars(
            query.order_by(TrustRecoverySigningEvent.requested_at.desc()).limit(
                limit
            )
        ).all()
    )
