from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import ssl
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from cryptography.fernet import Fernet, InvalidToken
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..auth_schemas import OIDCIdentityCreate, OIDCIdentityUpdate
from ..config import Settings, get_settings
from ..database import set_session_namespace
from ..models import (
    ControlPlaneOIDCIdentity,
    ControlPlaneOIDCTransaction,
    ControlPlanePrincipal,
    ControlPlaneRoleBinding,
    utcnow,
)
from ..worker_auth import hash_token
from .audit import record_audit_event
from .control_plane_auth import (
    ControlPlaneAuthorizationError,
    PrincipalContext,
    create_browser_session,
    principal_context,
    revoke_federated_browser_sessions,
)


MAX_DOCUMENT_BYTES = 1_048_576
MAX_ID_TOKEN_BYTES = 65_536
MAX_JWKS_KEYS = 128
ALLOWED_ID_TOKEN_ALGORITHMS = {"RS256", "PS256", "ES256"}
OIDC_TRANSACTION_ADVISORY_LOCK = 4_808_711_311


class OIDCFederationError(ValueError):
    def __init__(self, message: str, *, code: str = "authentication_failed"):
        super().__init__(message)
        self.code = code


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class OIDCMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    signing_algorithms: frozenset[str]
    digest_sha256: str


@dataclass(frozen=True)
class OIDCLoginStart:
    authorization_url: str
    browser_token: str
    max_age_seconds: int


@dataclass(frozen=True)
class OIDCLoginResult:
    context: PrincipalContext
    session_token: str
    csrf_token: str
    return_to: str


def _canonical_hash(document: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _read_secret_file(path: str, *, label: str, maximum: int = 4096) -> str:
    try:
        metadata = os.stat(path)
        if not stat.S_ISREG(metadata.st_mode):
            raise OIDCFederationError(f"{label} must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise OIDCFederationError(
                f"{label} must not be accessible by group or others"
            )
        if metadata.st_size > maximum:
            raise OIDCFederationError(f"{label} is oversized")
        with open(path, encoding="utf-8") as handle:
            value = handle.read().strip()
    except OSError as exc:
        raise OIDCFederationError(f"Unable to read {label}") from exc
    if not value:
        raise OIDCFederationError(f"{label} is empty")
    return value


def _validate_remote_url(url: str, settings: Settings) -> str:
    if len(url) > 4096:
        raise OIDCFederationError("OIDC endpoint URL is oversized")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise OIDCFederationError("OIDC endpoints must be HTTPS URLs")
    if parsed.hostname.lower() not in settings.control_plane_oidc_allowed_host_list:
        raise OIDCFederationError("OIDC endpoint host is not allowlisted")
    return url


def _validate_browser_configuration(settings: Settings) -> None:
    for value, label, origin_only in (
        (
            settings.control_plane_oidc_redirect_uri or "",
            "OIDC redirect URI",
            False,
        ),
        (
            settings.control_plane_oidc_success_url or "",
            "OIDC success URL",
            True,
        ),
    ):
        parsed = urlsplit(value)
        secure = parsed.scheme == "https"
        loopback = parsed.scheme == "http" and parsed.hostname in {
            "127.0.0.1",
            "::1",
            "localhost",
        }
        if (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
            or not (secure or (loopback and settings.environment != "production"))
        ):
            raise OIDCFederationError(f"{label} is invalid")
        if origin_only and (parsed.path not in {"", "/"} or parsed.query):
            raise OIDCFederationError(
                "OIDC success URL must contain only an origin"
            )


def oidc_browser_location(
    settings: Settings,
    *,
    return_to: str | None = None,
    error_code: str | None = None,
) -> str:
    _validate_browser_configuration(settings)
    base = (settings.control_plane_oidc_success_url or "").rstrip("/")
    if error_code:
        return base + "/login?" + urlencode({"oidc_error": error_code})
    return base + _validate_return_to(return_to or "/")


def _validate_return_to(value: str) -> str:
    if len(value) > 2048:
        raise OIDCFederationError("OIDC return path is oversized")
    parsed = urlsplit(value)
    if (
        not value.startswith("/")
        or value.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
    ):
        raise OIDCFederationError("OIDC return path must be a local absolute path")
    return value


class OIDCTransport:
    def __init__(self, timeout_seconds: int):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = build_opener(
            _NoRedirect(),
            HTTPSHandler(context=context),
        )
        self.timeout_seconds = timeout_seconds

    def _json_response(self, request: Request) -> dict[str, Any]:
        try:
            with self.opener.open(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                body = response.read(MAX_DOCUMENT_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise OIDCFederationError("OIDC provider request failed") from exc
        if len(body) > MAX_DOCUMENT_BYTES:
            raise OIDCFederationError("OIDC provider response is oversized")
        try:
            document = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OIDCFederationError("OIDC provider returned invalid JSON") from exc
        if not isinstance(document, dict):
            raise OIDCFederationError("OIDC provider response must be an object")
        return document

    def get_json(self, url: str) -> dict[str, Any]:
        return self._json_response(
            Request(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "iCheck-oidc/0.1",
                },
                method="GET",
            )
        )

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        authorization: str,
    ) -> dict[str, Any]:
        return self._json_response(
            Request(
                url,
                data=urlencode(fields).encode("ascii"),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": authorization,
                    "User-Agent": "iCheck-oidc/0.1",
                },
                method="POST",
            )
        )


def oidc_transport(settings: Settings) -> OIDCTransport:
    return OIDCTransport(settings.control_plane_oidc_timeout_seconds)


def discover_oidc_provider(
    settings: Settings,
    transport: OIDCTransport,
) -> OIDCMetadata:
    issuer = (settings.control_plane_oidc_issuer or "").rstrip("/")
    if urlsplit(issuer).query:
        raise OIDCFederationError("OIDC issuer must not contain a query string")
    _validate_remote_url(issuer, settings)
    discovery_url = issuer + "/.well-known/openid-configuration"
    document = transport.get_json(discovery_url)
    if document.get("issuer") != issuer:
        raise OIDCFederationError("OIDC discovery issuer does not match configuration")
    endpoints: dict[str, str] = {}
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = document.get(key)
        if not isinstance(value, str):
            raise OIDCFederationError(f"OIDC discovery is missing {key}")
        endpoints[key] = _validate_remote_url(value, settings)
    response_types = document.get("response_types_supported")
    if isinstance(response_types, list) and "code" not in response_types:
        raise OIDCFederationError("OIDC provider does not support authorization code")
    challenge_methods = document.get("code_challenge_methods_supported")
    if isinstance(challenge_methods, list) and "S256" not in challenge_methods:
        raise OIDCFederationError("OIDC provider does not support PKCE S256")
    auth_methods = document.get("token_endpoint_auth_methods_supported")
    if isinstance(auth_methods, list) and "client_secret_basic" not in auth_methods:
        raise OIDCFederationError(
            "OIDC provider does not support client_secret_basic"
        )
    advertised_algorithms = document.get("id_token_signing_alg_values_supported")
    if not isinstance(advertised_algorithms, list):
        raise OIDCFederationError("OIDC discovery is missing signing algorithms")
    signing_algorithms = frozenset(
        value
        for value in advertised_algorithms
        if isinstance(value, str) and value in ALLOWED_ID_TOKEN_ALGORITHMS
    )
    if not signing_algorithms:
        raise OIDCFederationError("OIDC provider has no allowed signing algorithm")
    security_document = {
        "issuer": issuer,
        **endpoints,
        "signing_algorithms": sorted(signing_algorithms),
        "token_endpoint_auth_method": "client_secret_basic",
        "pkce": "S256",
    }
    return OIDCMetadata(
        issuer=issuer,
        authorization_endpoint=endpoints["authorization_endpoint"],
        token_endpoint=endpoints["token_endpoint"],
        jwks_uri=endpoints["jwks_uri"],
        signing_algorithms=signing_algorithms,
        digest_sha256=_canonical_hash(security_document),
    )


def _fernet(settings: Settings) -> Fernet:
    value = _read_secret_file(
        settings.control_plane_oidc_transaction_secret_file or "",
        label="OIDC transaction secret file",
        maximum=256,
    )
    try:
        return Fernet(value.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise OIDCFederationError(
            "OIDC transaction secret must be a Fernet key"
        ) from exc


def _enforce_transaction_capacity(db: Session, settings: Settings) -> None:
    """Prune transient rows and serialize the production capacity decision."""

    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": OIDC_TRANSACTION_ADVISORY_LOCK},
        )
    now = utcnow()
    db.execute(
        delete(ControlPlaneOIDCTransaction).where(
            ControlPlaneOIDCTransaction.expires_at <= now
        )
    )
    pending = db.scalar(
        select(func.count(ControlPlaneOIDCTransaction.id)).where(
            ControlPlaneOIDCTransaction.consumed_at.is_(None),
            ControlPlaneOIDCTransaction.expires_at > now,
        )
    )
    if int(pending or 0) >= settings.control_plane_oidc_max_pending_transactions:
        db.commit()
        raise OIDCFederationError(
            "OIDC login capacity is temporarily exhausted",
            code="capacity_exhausted",
        )


def begin_oidc_login(
    db: Session,
    return_to: str,
    *,
    settings: Settings | None = None,
    transport: OIDCTransport | None = None,
) -> OIDCLoginStart:
    settings = settings or get_settings()
    if not settings.control_plane_oidc_enabled:
        raise OIDCFederationError("OIDC federation is disabled", code="disabled")
    _validate_browser_configuration(settings)
    return_to = _validate_return_to(return_to)
    transport = transport or oidc_transport(settings)
    metadata = discover_oidc_provider(settings, transport)
    _enforce_transaction_capacity(db, settings)
    state = secrets.token_urlsafe(32)
    browser_token = f"ico_{secrets.token_urlsafe(32)}"
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(48)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    ttl_seconds = settings.control_plane_oidc_transaction_ttl_minutes * 60
    transaction = ControlPlaneOIDCTransaction(
        state_hash=hash_token(state),
        browser_token_hash=hash_token(browser_token),
        nonce_hash=hash_token(nonce),
        code_verifier_ciphertext=_fernet(settings).encrypt(
            code_verifier.encode("ascii")
        ).decode("ascii"),
        metadata_sha256=metadata.digest_sha256,
        return_to=return_to,
        expires_at=utcnow() + timedelta(seconds=ttl_seconds),
    )
    db.add(transaction)
    db.commit()
    query = urlencode(
        {
            "response_type": "code",
            "client_id": settings.control_plane_oidc_client_id or "",
            "redirect_uri": settings.control_plane_oidc_redirect_uri or "",
            "scope": " ".join(settings.control_plane_oidc_scope_list),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    separator = "&" if urlsplit(metadata.authorization_endpoint).query else "?"
    return OIDCLoginStart(
        authorization_url=metadata.authorization_endpoint + separator + query,
        browser_token=browser_token,
        max_age_seconds=ttl_seconds,
    )


def _record_transaction_failure(
    db: Session,
    transaction: ControlPlaneOIDCTransaction | None,
    *,
    code: str,
    detail: str,
) -> None:
    if transaction is None:
        return
    transaction.failure_code = code[:64]
    transaction.failure_sha256 = _sha256(detail)
    db.commit()


def _consume_transaction(
    db: Session,
    *,
    state: str,
    browser_token: str,
) -> ControlPlaneOIDCTransaction:
    transaction = db.scalar(
        select(ControlPlaneOIDCTransaction)
        .where(ControlPlaneOIDCTransaction.state_hash == hash_token(state))
        .with_for_update()
    )
    now = utcnow()
    if (
        transaction is None
        or not secrets.compare_digest(
            transaction.browser_token_hash,
            hash_token(browser_token),
        )
        or transaction.consumed_at is not None
        or _as_utc(transaction.expires_at) <= now
    ):
        raise OIDCFederationError(
            "OIDC login transaction is invalid or expired",
            code="invalid_transaction",
        )
    transaction.consumed_at = now
    db.commit()
    return transaction


def _client_authorization(settings: Settings) -> str:
    client_id = quote(settings.control_plane_oidc_client_id or "", safe="")
    secret = quote(
        _read_secret_file(
            settings.control_plane_oidc_client_secret_file or "",
            label="OIDC client secret file",
        ),
        safe="",
    )
    encoded = base64.b64encode(f"{client_id}:{secret}".encode("utf-8")).decode(
        "ascii"
    )
    return f"Basic {encoded}"


def _exchange_code(
    settings: Settings,
    metadata: OIDCMetadata,
    transport: OIDCTransport,
    *,
    code: str,
    code_verifier: str,
) -> str:
    if not 1 <= len(code) <= 8192:
        raise OIDCFederationError("OIDC authorization code is invalid")
    document = transport.post_form(
        metadata.token_endpoint,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.control_plane_oidc_redirect_uri or "",
            "code_verifier": code_verifier,
        },
        authorization=_client_authorization(settings),
    )
    if "error" in document:
        raise OIDCFederationError("OIDC token exchange was rejected")
    id_token = document.get("id_token")
    if not isinstance(id_token, str) or not 1 <= len(id_token) <= MAX_ID_TOKEN_BYTES:
        raise OIDCFederationError("OIDC token response has no bounded ID token")
    return id_token


def _number_claim(claims: dict[str, Any], name: str, *, required: bool) -> int | None:
    value = claims.get(name)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OIDCFederationError(f"OIDC ID token {name} claim is invalid")
    return int(value)


def _validate_id_token(
    settings: Settings,
    metadata: OIDCMetadata,
    transport: OIDCTransport,
    *,
    id_token: str,
    nonce_hash: str,
) -> dict[str, Any]:
    jwks = transport.get_json(metadata.jwks_uri)
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_JWKS_KEYS:
        raise OIDCFederationError("OIDC JWKS contains an invalid key set")
    try:
        token = jwt.decode(
            id_token,
            KeySet.import_key_set(jwks),
            algorithms=metadata.signing_algorithms,
        )
    except (JoseError, ValueError, TypeError) as exc:
        raise OIDCFederationError("OIDC ID token signature is invalid") from exc
    claims = token.claims
    if not isinstance(claims, dict):
        raise OIDCFederationError("OIDC ID token claims are invalid")
    now = int(time.time())
    leeway = 60
    if claims.get("iss") != metadata.issuer:
        raise OIDCFederationError("OIDC ID token issuer is invalid")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not 1 <= len(subject) <= 1024:
        raise OIDCFederationError("OIDC ID token subject is invalid")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if (
        not isinstance(audiences, list)
        or not all(isinstance(item, str) for item in audiences)
        or (settings.control_plane_oidc_client_id or "") not in audiences
    ):
        raise OIDCFederationError("OIDC ID token audience is invalid")
    if len(audiences) > 1 and claims.get("azp") != settings.control_plane_oidc_client_id:
        raise OIDCFederationError("OIDC ID token authorized party is invalid")
    if "azp" in claims and claims.get("azp") != settings.control_plane_oidc_client_id:
        raise OIDCFederationError("OIDC ID token authorized party is invalid")
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not secrets.compare_digest(
        hash_token(nonce),
        nonce_hash,
    ):
        raise OIDCFederationError("OIDC ID token nonce is invalid")
    expires_at = _number_claim(claims, "exp", required=True)
    issued_at = _number_claim(claims, "iat", required=True)
    not_before = _number_claim(claims, "nbf", required=False)
    assert expires_at is not None
    assert issued_at is not None
    if expires_at <= now - leeway:
        raise OIDCFederationError("OIDC ID token has expired")
    if expires_at <= issued_at:
        raise OIDCFederationError("OIDC ID token time window is invalid")
    if issued_at > now + leeway:
        raise OIDCFederationError("OIDC ID token was issued in the future")
    if issued_at < now - 86_400:
        raise OIDCFederationError("OIDC ID token issue time is too old")
    if expires_at > now + 86_400:
        raise OIDCFederationError("OIDC ID token expiry exceeds 24 hours")
    if not_before is not None and not_before > now + leeway:
        raise OIDCFederationError("OIDC ID token is not yet valid")
    return claims


def _identity_for_claims(
    db: Session,
    metadata: OIDCMetadata,
    claims: dict[str, Any],
) -> ControlPlaneOIDCIdentity:
    identity = db.scalar(
        select(ControlPlaneOIDCIdentity)
        .options(
            selectinload(ControlPlaneOIDCIdentity.principal)
            .selectinload(ControlPlanePrincipal.role_bindings)
            .selectinload(ControlPlaneRoleBinding.role)
        )
        .where(
            ControlPlaneOIDCIdentity.issuer_sha256 == _sha256(metadata.issuer),
            ControlPlaneOIDCIdentity.subject_sha256 == _sha256(claims["sub"]),
        )
        .with_for_update()
    )
    if (
        identity is None
        or identity.issuer != metadata.issuer
        or not identity.enabled
        or not identity.principal.enabled
        or identity.tenant_id != identity.principal.tenant_id
        or identity.region_id != identity.principal.region_id
    ):
        raise OIDCFederationError(
            "OIDC identity is not enrolled or enabled",
            code="identity_not_enrolled",
        )
    return identity


def finish_oidc_login(
    db: Session,
    *,
    state: str | None,
    browser_token: str | None,
    code: str | None,
    provider_error: str | None = None,
    settings: Settings | None = None,
    transport: OIDCTransport | None = None,
) -> OIDCLoginResult:
    settings = settings or get_settings()
    if not settings.control_plane_oidc_enabled:
        raise OIDCFederationError("OIDC federation is disabled", code="disabled")
    if not state or not browser_token:
        raise OIDCFederationError(
            "OIDC callback is missing transaction state",
            code="invalid_transaction",
        )
    transaction: ControlPlaneOIDCTransaction | None = None
    try:
        transaction = _consume_transaction(
            db,
            state=state,
            browser_token=browser_token,
        )
        if provider_error:
            raise OIDCFederationError(
                "OIDC provider denied authentication",
                code="provider_denied",
            )
        if not code:
            raise OIDCFederationError("OIDC callback has no authorization code")
        transport = transport or oidc_transport(settings)
        metadata = discover_oidc_provider(settings, transport)
        if not secrets.compare_digest(
            transaction.metadata_sha256,
            metadata.digest_sha256,
        ):
            raise OIDCFederationError("OIDC provider metadata changed during login")
        try:
            code_verifier = _fernet(settings).decrypt(
                transaction.code_verifier_ciphertext.encode("ascii"),
                ttl=settings.control_plane_oidc_transaction_ttl_minutes * 60,
            ).decode("ascii")
        except (InvalidToken, UnicodeError, ValueError) as exc:
            raise OIDCFederationError("OIDC PKCE verifier is unavailable") from exc
        id_token = _exchange_code(
            settings,
            metadata,
            transport,
            code=code,
            code_verifier=code_verifier,
        )
        claims = _validate_id_token(
            settings,
            metadata,
            transport,
            id_token=id_token,
            nonce_hash=transaction.nonce_hash,
        )
        identity = _identity_for_claims(db, metadata, claims)
        set_session_namespace(
            db,
            identity.principal.tenant_id,
            identity.principal.region_id,
        )
        context = principal_context(
            identity.principal,
            db=db,
            auth_method="oidc",
        )
        identity.last_login_at = utcnow()
        identity.last_claims_sha256 = _canonical_hash(claims)
        record_audit_event(
            db,
            event_type="auth.oidc.login_succeeded",
            actor_type="user",
            actor_id=context.subject,
            entity_type="oidc_identity",
            entity_id=identity.id,
            details={
                "principal_id": identity.principal_id,
                "issuer_sha256": identity.issuer_sha256,
                "subject_sha256": identity.subject_sha256,
                "claims_sha256": identity.last_claims_sha256,
            },
        )
        db.commit()
        session, session_token, csrf_token = create_browser_session(
            db,
            identity.principal,
            ttl_hours=settings.control_plane_browser_session_ttl_hours,
            actor=context,
            auth_source="oidc",
            federated_identity_id=identity.id,
        )
        _ = session
        return OIDCLoginResult(
            context=context,
            session_token=session_token,
            csrf_token=csrf_token,
            return_to=transaction.return_to,
        )
    except (OIDCFederationError, ControlPlaneAuthorizationError) as exc:
        error = (
            exc
            if isinstance(exc, OIDCFederationError)
            else OIDCFederationError(str(exc), code="identity_not_authorized")
        )
        _record_transaction_failure(
            db,
            transaction,
            code=error.code,
            detail=str(error),
        )
        raise error from exc


def create_oidc_identity(
    db: Session,
    principal: ControlPlanePrincipal,
    payload: OIDCIdentityCreate,
    *,
    actor: PrincipalContext,
    settings: Settings | None = None,
) -> ControlPlaneOIDCIdentity:
    settings = settings or get_settings()
    if not settings.control_plane_oidc_enabled:
        raise ValueError("OIDC federation is disabled")
    issuer = (settings.control_plane_oidc_issuer or "").rstrip("/")
    if urlsplit(issuer).query:
        raise ValueError("OIDC issuer must not contain a query string")
    identity = ControlPlaneOIDCIdentity(
        principal=principal,
        issuer=issuer,
        issuer_sha256=_sha256(issuer),
        subject_sha256=_sha256(payload.subject),
        enabled=True,
        tenant_id=principal.tenant_id,
        region_id=principal.region_id,
        created_by=actor.subject,
    )
    db.add(identity)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="auth.oidc.identity_bound",
            actor_type=actor.principal_type,
            actor_id=actor.subject,
            entity_type="oidc_identity",
            entity_id=identity.id,
            details={
                "principal_id": principal.id,
                "issuer_sha256": identity.issuer_sha256,
                "subject_sha256": identity.subject_sha256,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "OIDC identity or principal/provider binding already exists"
        ) from exc
    db.refresh(identity)
    return identity


def update_oidc_identity(
    db: Session,
    identity: ControlPlaneOIDCIdentity,
    payload: OIDCIdentityUpdate,
    *,
    actor: PrincipalContext,
) -> ControlPlaneOIDCIdentity:
    locked = db.scalar(
        select(ControlPlaneOIDCIdentity)
        .where(
            ControlPlaneOIDCIdentity.id == identity.id,
            ControlPlaneOIDCIdentity.tenant_id == actor.tenant_id,
        )
        .with_for_update()
    )
    if locked is None:
        raise LookupError("OIDC identity not found")
    locked.enabled = payload.enabled
    revoked_sessions = 0
    if not payload.enabled:
        revoked_sessions = revoke_federated_browser_sessions(
            db,
            auth_source="oidc",
            federated_identity_id=locked.id,
            reason=payload.reason,
            actor=actor,
        )
    record_audit_event(
        db,
        event_type="auth.oidc.identity_updated",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="oidc_identity",
        entity_id=locked.id,
        details={
            "principal_id": locked.principal_id,
            "enabled": locked.enabled,
            "revoked_sessions": revoked_sessions,
            "reason_sha256": _sha256(payload.reason),
        },
    )
    db.commit()
    db.refresh(locked)
    return locked
