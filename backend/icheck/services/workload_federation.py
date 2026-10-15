from __future__ import annotations

import hashlib
import json
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..auth_schemas import WorkloadIdentityCreate, WorkloadIdentityUpdate
from ..config import Settings, get_settings
from ..database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, set_session_namespace
from ..models import (
    ControlPlanePrincipal,
    ControlPlaneRoleBinding,
    ControlPlaneWorkloadExchange,
    ControlPlaneWorkloadIdentity,
    utcnow,
)
from .audit import record_audit_event
from .control_plane_auth import (
    ControlPlaneAuthorizationError,
    PrincipalContext,
    issue_workload_access_token,
    principal_context,
)


MAX_DOCUMENT_BYTES = 1_048_576
MAX_SUBJECT_TOKEN_BYTES = 65_536
MAX_JWKS_KEYS = 128
ALLOWED_SIGNING_ALGORITHMS = {"RS256", "PS256", "ES256"}


class WorkloadFederationError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid_subject_token"):
        super().__init__(message)
        self.code = code


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class WorkloadOIDCMetadata:
    issuer: str
    jwks_uri: str
    signing_algorithms: frozenset[str]


@dataclass(frozen=True)
class WorkloadTokenResult:
    access_token: str
    expires_in: int


class WorkloadOIDCTransport:
    def __init__(self, timeout_seconds: int):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = build_opener(
            _NoRedirect(),
            HTTPSHandler(context=context),
        )
        self.timeout_seconds = timeout_seconds

    def get_json(self, url: str) -> dict[str, Any]:
        try:
            with self.opener.open(
                Request(
                    url,
                    method="GET",
                    headers={"Accept": "application/json"},
                ),
                timeout=self.timeout_seconds,
            ) as response:
                body = response.read(MAX_DOCUMENT_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise WorkloadFederationError(
                "Workload identity provider request failed",
                code="provider_unavailable",
            ) from exc
        if len(body) > MAX_DOCUMENT_BYTES:
            raise WorkloadFederationError(
                "Workload identity provider response is oversized",
                code="provider_unavailable",
            )
        try:
            document = json.loads(body)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise WorkloadFederationError(
                "Workload identity provider returned invalid JSON",
                code="provider_unavailable",
            ) from exc
        if not isinstance(document, dict):
            raise WorkloadFederationError(
                "Workload identity provider returned an invalid document",
                code="provider_unavailable",
            )
        return document


def workload_transport(settings: Settings) -> WorkloadOIDCTransport:
    return WorkloadOIDCTransport(
        settings.control_plane_workload_oidc_timeout_seconds
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_hash(document: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _validate_remote_url(url: str, settings: Settings) -> str:
    if len(url) > 4096:
        raise WorkloadFederationError(
            "Workload OIDC endpoint URL is oversized",
            code="provider_unavailable",
        )
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.hostname.lower()
        not in settings.control_plane_workload_oidc_allowed_host_list
    ):
        raise WorkloadFederationError(
            "Workload OIDC endpoint is not an allowlisted HTTPS URL",
            code="provider_unavailable",
        )
    return url


def discover_workload_provider(
    settings: Settings,
    transport: WorkloadOIDCTransport,
) -> WorkloadOIDCMetadata:
    issuer = (settings.control_plane_workload_oidc_issuer or "").rstrip("/")
    discovery_url = _validate_remote_url(
        issuer + "/.well-known/openid-configuration",
        settings,
    )
    document = transport.get_json(discovery_url)
    if document.get("issuer") != issuer:
        raise WorkloadFederationError(
            "Workload OIDC discovery issuer does not match configuration",
            code="provider_unavailable",
        )
    jwks_uri = document.get("jwks_uri")
    algorithms = document.get("id_token_signing_alg_values_supported")
    if not isinstance(jwks_uri, str):
        raise WorkloadFederationError(
            "Workload OIDC discovery has no JWKS endpoint",
            code="provider_unavailable",
        )
    if (
        not isinstance(algorithms, list)
        or not algorithms
        or not all(isinstance(item, str) for item in algorithms)
    ):
        raise WorkloadFederationError(
            "Workload OIDC discovery has no signing algorithms",
            code="provider_unavailable",
        )
    accepted = frozenset(algorithms) & ALLOWED_SIGNING_ALGORITHMS
    if not accepted:
        raise WorkloadFederationError(
            "Workload OIDC provider has no accepted signing algorithm",
            code="provider_unavailable",
        )
    return WorkloadOIDCMetadata(
        issuer=issuer,
        jwks_uri=_validate_remote_url(jwks_uri, settings),
        signing_algorithms=accepted,
    )


def _number_claim(
    claims: dict[str, Any],
    name: str,
    *,
    required: bool,
) -> int | None:
    value = claims.get(name)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise WorkloadFederationError(
            f"Workload subject token {name} claim is invalid"
        )
    return int(value)


def _validate_subject_token(
    token: str,
    *,
    settings: Settings,
    metadata: WorkloadOIDCMetadata,
    transport: WorkloadOIDCTransport,
) -> tuple[dict[str, Any], datetime]:
    if len(token.encode("utf-8")) > MAX_SUBJECT_TOKEN_BYTES:
        raise WorkloadFederationError("Workload subject token is oversized")
    jwks = transport.get_json(metadata.jwks_uri)
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_JWKS_KEYS:
        raise WorkloadFederationError(
            "Workload OIDC JWKS contains an invalid key set",
            code="provider_unavailable",
        )
    try:
        decoded = jwt.decode(
            token,
            KeySet.import_key_set(jwks),
            algorithms=metadata.signing_algorithms,
        )
    except (JoseError, ValueError, TypeError) as exc:
        raise WorkloadFederationError(
            "Workload subject token signature is invalid"
        ) from exc
    claims = decoded.claims
    if not isinstance(claims, dict):
        raise WorkloadFederationError("Workload subject token claims are invalid")
    if claims.get("iss") != metadata.issuer:
        raise WorkloadFederationError("Workload subject token issuer is invalid")
    subject = claims.get("sub")
    if (
        not isinstance(subject, str)
        or not 1 <= len(subject.encode("utf-8")) <= 1024
        or subject != subject.strip()
        or any(ord(character) < 0x20 for character in subject)
    ):
        raise WorkloadFederationError("Workload subject token subject is invalid")
    jti = claims.get("jti")
    if (
        not isinstance(jti, str)
        or not 1 <= len(jti.encode("utf-8")) <= 255
        or any(ord(character) < 0x20 for character in jti)
    ):
        raise WorkloadFederationError(
            "Workload subject token requires a bounded jti"
        )
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if (
        not isinstance(audiences, list)
        or not all(isinstance(item, str) for item in audiences)
        or (settings.control_plane_workload_oidc_audience or "") not in audiences
    ):
        raise WorkloadFederationError(
            "Workload subject token audience is invalid"
        )
    now = int(time.time())
    leeway = 30
    expires_at = _number_claim(claims, "exp", required=True)
    issued_at = _number_claim(claims, "iat", required=True)
    not_before = _number_claim(claims, "nbf", required=False)
    assert expires_at is not None
    assert issued_at is not None
    if expires_at <= now - leeway:
        raise WorkloadFederationError("Workload subject token has expired")
    if expires_at <= issued_at:
        raise WorkloadFederationError(
            "Workload subject token time window is invalid"
        )
    if issued_at > now + leeway:
        raise WorkloadFederationError(
            "Workload subject token was issued in the future"
        )
    if issued_at < now - 3600:
        raise WorkloadFederationError(
            "Workload subject token issue time is too old"
        )
    if expires_at > now + 3600:
        raise WorkloadFederationError(
            "Workload subject token expiry exceeds one hour"
        )
    if not_before is not None and not_before > now + leeway:
        raise WorkloadFederationError(
            "Workload subject token is not yet valid"
        )
    return claims, datetime.fromtimestamp(expires_at, UTC)


def _identity_for_claims(
    db: Session,
    settings: Settings,
    claims: dict[str, Any],
) -> ControlPlaneWorkloadIdentity | None:
    issuer = (settings.control_plane_workload_oidc_issuer or "").rstrip("/")
    audience = settings.control_plane_workload_oidc_audience or ""
    return db.scalar(
        select(ControlPlaneWorkloadIdentity)
        .options(
            selectinload(ControlPlaneWorkloadIdentity.principal)
            .selectinload(ControlPlanePrincipal.role_bindings)
            .selectinload(ControlPlaneRoleBinding.role)
        )
        .where(
            ControlPlaneWorkloadIdentity.issuer_sha256 == _sha256(issuer),
            ControlPlaneWorkloadIdentity.subject_sha256 == _sha256(claims["sub"]),
            ControlPlaneWorkloadIdentity.audience_sha256 == _sha256(audience),
        )
    )


def _record_denial(
    db: Session,
    settings: Settings,
    *,
    code: str,
    source_address: str | None,
    claims: dict[str, Any] | None = None,
    assertion_expires_at: datetime | None = None,
    identity: ControlPlaneWorkloadIdentity | None = None,
) -> str:
    jti_sha256 = (
        _sha256(claims["jti"])
        if claims is not None and isinstance(claims.get("jti"), str)
        else None
    )
    exchange = ControlPlaneWorkloadExchange(
        identity_id=identity.id if identity is not None else None,
        principal_id=identity.principal_id if identity is not None else None,
        assertion_jti_sha256=jti_sha256,
        issuer_sha256=_sha256(
            (settings.control_plane_workload_oidc_issuer or "").rstrip("/")
        ),
        subject_sha256=(
            _sha256(claims["sub"])
            if claims is not None and isinstance(claims.get("sub"), str)
            else None
        ),
        audience_sha256=_sha256(
            settings.control_plane_workload_oidc_audience or ""
        ),
        claims_sha256=_canonical_hash(claims) if claims is not None else None,
        source_address_sha256=(
            _sha256(source_address) if source_address else None
        ),
        assertion_expires_at=assertion_expires_at,
        outcome="denied",
        failure_code=code,
        tenant_id=identity.tenant_id if identity is not None else DEFAULT_TENANT_ID,
        region_id=identity.region_id if identity is not None else DEFAULT_REGION_ID,
    )
    db.add(exchange)
    try:
        db.commit()
        return code
    except IntegrityError:
        db.rollback()
        db.add(
            ControlPlaneWorkloadExchange(
                identity_id=identity.id if identity is not None else None,
                principal_id=(
                    identity.principal_id if identity is not None else None
                ),
                assertion_jti_sha256=None,
                issuer_sha256=_sha256(
                    (
                        settings.control_plane_workload_oidc_issuer
                        or ""
                    ).rstrip("/")
                ),
                subject_sha256=(
                    _sha256(claims["sub"])
                    if claims is not None
                    and isinstance(claims.get("sub"), str)
                    else None
                ),
                audience_sha256=_sha256(
                    settings.control_plane_workload_oidc_audience or ""
                ),
                claims_sha256=(
                    _canonical_hash(claims) if claims is not None else None
                ),
                source_address_sha256=(
                    _sha256(source_address) if source_address else None
                ),
                assertion_expires_at=assertion_expires_at,
                outcome="denied",
                failure_code="replayed_assertion",
                tenant_id=(
                    identity.tenant_id
                    if identity is not None
                    else DEFAULT_TENANT_ID
                ),
                region_id=(
                    identity.region_id
                    if identity is not None
                    else DEFAULT_REGION_ID
                ),
            )
        )
        db.commit()
        return "replayed_assertion"


def _deny(
    db: Session,
    settings: Settings,
    *,
    code: str,
    message: str,
    source_address: str | None,
    claims: dict[str, Any] | None = None,
    assertion_expires_at: datetime | None = None,
    identity: ControlPlaneWorkloadIdentity | None = None,
) -> None:
    effective_code = _record_denial(
        db,
        settings,
        code=code,
        source_address=source_address,
        claims=claims,
        assertion_expires_at=assertion_expires_at,
        identity=identity,
    )
    if effective_code == "replayed_assertion":
        message = "Workload subject token has already been exchanged"
    raise WorkloadFederationError(message, code=effective_code)


def exchange_workload_token(
    db: Session,
    subject_token: str,
    *,
    source_address: str | None,
    settings: Settings | None = None,
    transport: WorkloadOIDCTransport | None = None,
) -> WorkloadTokenResult:
    settings = settings or get_settings()
    if not settings.control_plane_workload_oidc_enabled:
        raise WorkloadFederationError(
            "Workload OIDC federation is disabled",
            code="disabled",
        )
    transport = transport or workload_transport(settings)
    try:
        metadata = discover_workload_provider(settings, transport)
        claims, assertion_expires_at = _validate_subject_token(
            subject_token,
            settings=settings,
            metadata=metadata,
            transport=transport,
        )
    except WorkloadFederationError as exc:
        _deny(
            db,
            settings,
            code=exc.code,
            message=str(exc),
            source_address=source_address,
        )

    identity = _identity_for_claims(db, settings, claims)
    issuer = (settings.control_plane_workload_oidc_issuer or "").rstrip("/")
    if (
        identity is None
        or identity.issuer != issuer
        or not identity.enabled
        or not identity.principal.enabled
        or identity.principal.principal_type != "service"
        or identity.tenant_id != identity.principal.tenant_id
        or identity.region_id != identity.principal.region_id
    ):
        _deny(
            db,
            settings,
            code="identity_not_enrolled",
            message="Workload identity is not enrolled or enabled",
            source_address=source_address,
            claims=claims,
            assertion_expires_at=assertion_expires_at,
            identity=identity,
        )

    set_session_namespace(
        db,
        identity.principal.tenant_id,
        identity.principal.region_id,
    )
    try:
        context = principal_context(
            identity.principal,
            db=db,
            auth_method="workload_federation",
        )
    except ControlPlaneAuthorizationError as exc:
        _deny(
            db,
            settings,
            code="identity_not_authorized",
            message=str(exc),
            source_address=source_address,
            claims=claims,
            assertion_expires_at=assertion_expires_at,
            identity=identity,
        )
    now = utcnow()
    issued_expires_at = min(
        _as_utc(assertion_expires_at),
        now
        + timedelta(
            minutes=min(
                settings.control_plane_workload_token_ttl_minutes,
                identity.max_token_ttl_minutes,
            )
        ),
    )
    token, raw_token = issue_workload_access_token(
        db,
        principal=identity.principal,
        workload_identity_id=identity.id,
        expires_at=issued_expires_at,
    )
    identity.last_exchange_at = now
    record_audit_event(
        db,
        event_type="auth.workload.token_exchanged",
        actor_type="service",
        actor_id=context.subject,
        entity_type="workload_identity",
        entity_id=identity.id,
        details={
            "principal_id": identity.principal_id,
            "issuer_sha256": identity.issuer_sha256,
            "subject_sha256": identity.subject_sha256,
            "audience_sha256": identity.audience_sha256,
            "claims_sha256": _canonical_hash(claims),
            "token_prefix": token.token_prefix,
            "expires_at": issued_expires_at.isoformat(),
        },
    )
    db.add(
        ControlPlaneWorkloadExchange(
            identity_id=identity.id,
            principal_id=identity.principal_id,
            assertion_jti_sha256=_sha256(claims["jti"]),
            issuer_sha256=identity.issuer_sha256,
            subject_sha256=identity.subject_sha256,
            audience_sha256=identity.audience_sha256,
            claims_sha256=_canonical_hash(claims),
            source_address_sha256=(
                _sha256(source_address) if source_address else None
            ),
            assertion_expires_at=assertion_expires_at,
            issued_token_id=token.id,
            issued_token_prefix=token.token_prefix,
            issued_token_expires_at=issued_expires_at,
            outcome="succeeded",
            failure_code=None,
            tenant_id=identity.tenant_id,
            region_id=identity.region_id,
        )
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        _deny(
            db,
            settings,
            code="replayed_assertion",
            message="Workload subject token has already been exchanged",
            source_address=source_address,
            claims=claims,
            assertion_expires_at=assertion_expires_at,
            identity=identity,
        )
    expires_in = max(
        1,
        int((_as_utc(issued_expires_at) - utcnow()).total_seconds()),
    )
    return WorkloadTokenResult(
        access_token=raw_token,
        expires_in=expires_in,
    )


def create_workload_identity(
    db: Session,
    principal: ControlPlanePrincipal,
    payload: WorkloadIdentityCreate,
    *,
    actor: PrincipalContext,
    settings: Settings | None = None,
) -> ControlPlaneWorkloadIdentity:
    settings = settings or get_settings()
    if not settings.control_plane_workload_oidc_enabled:
        raise ValueError("Workload OIDC federation is disabled")
    if principal.principal_type != "service":
        raise ValueError("Workload identities require a service Principal")
    issuer = (settings.control_plane_workload_oidc_issuer or "").rstrip("/")
    audience = settings.control_plane_workload_oidc_audience or ""
    identity = ControlPlaneWorkloadIdentity(
        principal=principal,
        issuer=issuer,
        issuer_sha256=_sha256(issuer),
        subject_sha256=_sha256(payload.subject),
        audience_sha256=_sha256(audience),
        enabled=True,
        max_token_ttl_minutes=(
            payload.max_token_ttl_minutes
            or settings.control_plane_workload_token_ttl_minutes
        ),
        tenant_id=principal.tenant_id,
        region_id=principal.region_id,
        created_by=actor.subject,
    )
    db.add(identity)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="auth.workload.identity_bound",
            actor_type=actor.principal_type,
            actor_id=actor.subject,
            entity_type="workload_identity",
            entity_id=identity.id,
            details={
                "principal_id": principal.id,
                "issuer_sha256": identity.issuer_sha256,
                "subject_sha256": identity.subject_sha256,
                "audience_sha256": identity.audience_sha256,
                "max_token_ttl_minutes": identity.max_token_ttl_minutes,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Workload identity or principal/issuer binding already exists"
        ) from exc
    db.refresh(identity)
    return identity


def update_workload_identity(
    db: Session,
    identity: ControlPlaneWorkloadIdentity,
    payload: WorkloadIdentityUpdate,
    *,
    actor: PrincipalContext,
) -> ControlPlaneWorkloadIdentity:
    identity.enabled = payload.enabled
    identity.max_token_ttl_minutes = payload.max_token_ttl_minutes
    record_audit_event(
        db,
        event_type="auth.workload.identity_updated",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="workload_identity",
        entity_id=identity.id,
        details={
            "principal_id": identity.principal_id,
            "enabled": identity.enabled,
            "max_token_ttl_minutes": identity.max_token_ttl_minutes,
            "reason_sha256": _sha256(payload.reason),
        },
    )
    db.commit()
    db.refresh(identity)
    return identity
