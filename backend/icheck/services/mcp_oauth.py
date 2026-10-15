from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import ssl
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from cryptography.fernet import Fernet, InvalidToken
from pydantic import ValidationError
from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..credentials import (
    CredentialUnavailable,
    MCPOAuthVaultCredentialProvider,
    VaultRequestError,
    OAuthConsentStoreRejected,
    resolve_server_secret,
)
from .mcp_oauth_observations import locked_oauth_server
from ..database import set_session_namespace, require_locking_transaction
from ..oauth_observation import OAuthRevocationIntent
from ..models import (
    CredentialProfile,
    MCPOAuthScopeChallenge,
    MCPOAuthTransaction,
    MCPOAuthConsentAttempt,
    MCPServer,
    new_id,
    utcnow,
)
from ..worker_auth import hash_token
from ..oauth_consent import OAuthAuthorizationLocator, OAuthConsentSnapshot
from .control_plane_auth import PrincipalContext
from .mcp_consent_custody import (assert_consent_eligible, assert_no_open_consent,
    assert_live_authority, build_consent_snapshot, current_consent_snapshot, snapshot_authority)
from .audit import record_audit_event
from .mcp_scope_challenges import (
    reset_scope_challenge_after_oauth_failure,
    resolve_mcp_scope_challenges,
)


MAX_DOCUMENT_BYTES = 1_048_576
MCP_OAUTH_TRANSACTION_ADVISORY_LOCK = 4_808_711_312
CHALLENGE_PARAMETER = re.compile(
    r"(?i)(resource_metadata|scope)\s*=\s*\"((?:[^\"\\]|\\.)*)\""
)


class MCPOAuthError(ValueError):
    def __init__(self, message: str, *, code: str = "authorization_failed"):
        super().__init__(message)
        self.code = code


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _OAuthHTTPError(MCPOAuthError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        headers: Mapping[str, str] | None = None,
    ):
        super().__init__(message, code="provider_unavailable")
        self.status_code = status_code
        self.headers = dict(headers or {})


@dataclass(frozen=True)
class ProtectedResourceMetadata:
    resource: str
    authorization_servers: tuple[str, ...]
    scopes_supported: tuple[str, ...]
    metadata_url: str


@dataclass(frozen=True)
class AuthorizationServerMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: str | None
    token_endpoint_auth_methods: frozenset[str]
    authorization_response_iss_parameter_supported: bool


@dataclass(frozen=True)
class OAuthDiscovery:
    resource: ProtectedResourceMetadata
    authorization: AuthorizationServerMetadata
    requested_scopes: tuple[str, ...]
    digest_sha256: str


@dataclass(frozen=True)
class MCPOAuthStart:
    authorization_url: str
    browser_token: str
    max_age_seconds: int


@dataclass(frozen=True)
class MCPOAuthResult:
    server_id: str
    return_to: str


@dataclass(frozen=True)
class _CodeExchangeClient:
    oauth_client_id: str


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
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
            raise MCPOAuthError(f"{label} must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise MCPOAuthError(
                f"{label} must not be accessible by group or others"
            )
        if metadata.st_size > maximum:
            raise MCPOAuthError(f"{label} is oversized")
        with open(path, encoding="utf-8") as handle:
            value = handle.read().strip()
    except OSError as exc:
        raise MCPOAuthError(f"Unable to read {label}") from exc
    if not value:
        raise MCPOAuthError(f"{label} is empty")
    return value


def _fernet(settings: Settings) -> Fernet:
    value = _read_secret_file(
        settings.mcp_oauth_transaction_secret_file or "",
        label="MCP OAuth transaction secret file",
        maximum=256,
    )
    try:
        return Fernet(value.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise MCPOAuthError("MCP OAuth transaction secret must be a Fernet key") from exc


def _validate_return_to(value: str) -> str:
    if len(value) > 2048:
        raise MCPOAuthError("MCP OAuth return path is oversized")
    parsed = urlsplit(value)
    if (
        not value.startswith("/")
        or value.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
    ):
        raise MCPOAuthError("MCP OAuth return path must be a local absolute path")
    return value


def mcp_oauth_browser_location(
    settings: Settings,
    *,
    return_to: str = "/settings/mcp",
    server_id: str | None = None,
    error_code: str | None = None,
) -> str:
    if not settings.mcp_oauth_success_url:
        raise MCPOAuthError("MCP OAuth browser return is not configured")
    return_to = _validate_return_to(return_to)
    parsed = urlsplit(return_to)
    query = parsed.query
    additions: dict[str, str] = {}
    if server_id:
        additions["oauth_server"] = server_id
    if error_code:
        additions["oauth_error"] = error_code
    else:
        additions["oauth"] = "connected"
    suffix = urlencode(additions)
    query = f"{query}&{suffix}" if query else suffix
    path = urlunsplit(("", "", parsed.path, query, ""))
    return settings.mcp_oauth_success_url.rstrip("/") + path


def _host_allowed(host: str, allowed_hosts: list[str]) -> bool:
    normalized = host.rstrip(".").lower()
    return any(
        normalized == pattern.rstrip(".").lower()
        or (
            pattern.startswith("*.")
            and normalized.endswith(pattern[1:].rstrip(".").lower())
            and normalized != pattern[2:].rstrip(".").lower()
        )
        for pattern in allowed_hosts
    )


def _validate_remote_url(
    value: Any,
    settings: Settings,
    *,
    resource_host_allowed: bool = False,
) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        raise MCPOAuthError("MCP OAuth endpoint URL is invalid")
    parsed = urlsplit(value)
    host = (parsed.hostname or "").rstrip(".").lower()
    loopback = host in {"127.0.0.1", "::1", "localhost"}
    secure = parsed.scheme == "https" or (
        parsed.scheme == "http"
        and loopback
        and settings.environment.strip().lower() != "production"
    )
    allowed_hosts = list(settings.mcp_oauth_allowed_host_list)
    if resource_host_allowed:
        allowed_hosts.extend(settings.mcp_allowed_host_list)
    if (
        not host
        or parsed.username
        or parsed.password
        or parsed.fragment
        or not secure
        or not _host_allowed(host, allowed_hosts)
    ):
        raise MCPOAuthError("MCP OAuth endpoint host is not allowlisted")
    return value


def _validate_issuer(value: Any, settings: Settings) -> str:
    issuer = _validate_remote_url(value, settings)
    if urlsplit(issuer).query:
        raise MCPOAuthError("Authorization server issuer must not contain a query")
    return issuer


def _scope_values(value: Any, *, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    values = value.split() if isinstance(value, str) else value
    if (
        not isinstance(values, (list, tuple))
        or len(values) > 100
        or not all(isinstance(item, str) for item in values)
    ):
        raise MCPOAuthError(f"{label} is invalid")
    result: list[str] = []
    for scope in values:
        if (
            not 1 <= len(scope) <= 255
            or any(ord(character) < 0x21 or character in {'"', "\\"} for character in scope)
        ):
            raise MCPOAuthError(f"{label} is invalid")
        if scope not in result:
            result.append(scope)
    return tuple(result)


class MCPOAuthTransport:
    def __init__(
        self,
        timeout_seconds: int,
        *,
        opener: Any | None = None,
    ) -> None:
        if opener is None:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))
        self.opener = opener
        self.timeout_seconds = timeout_seconds

    def _json(self, request: Request) -> dict[str, Any]:
        try:
            with self.opener.open(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                body = response.read(MAX_DOCUMENT_BYTES + 1)
        except HTTPError as exc:
            raise _OAuthHTTPError(
                f"OAuth provider returned HTTP {exc.code}",
                status_code=exc.code,
                headers=dict(exc.headers or {}),
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise _OAuthHTTPError("OAuth provider request failed") from exc
        if len(body) > MAX_DOCUMENT_BYTES:
            raise MCPOAuthError("OAuth provider response exceeded 1 MiB")
        try:
            document = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MCPOAuthError("OAuth provider returned invalid JSON") from exc
        if not isinstance(document, dict):
            raise MCPOAuthError("OAuth provider response must be an object")
        return document

    def get_json(self, url: str) -> dict[str, Any]:
        return self._json(
            Request(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "iCheck-mcp-oauth/0.1",
                },
                method="GET",
            )
        )

    def challenge(self, endpoint: str) -> tuple[str | None, tuple[str, ...]]:
        request_id = secrets.token_hex(16)
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/list",
                "params": {},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        request = Request(
            endpoint,
            data=payload,
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2026-07-28",
                "User-Agent": "iCheck-mcp-oauth/0.1",
            },
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=self.timeout_seconds):
                return None, ()
        except HTTPError as exc:
            if exc.code != 401:
                raise _OAuthHTTPError(
                    f"MCP authorization probe returned HTTP {exc.code}",
                    status_code=exc.code,
                    headers=dict(exc.headers or {}),
                ) from exc
            challenge = (exc.headers or {}).get("WWW-Authenticate", "")
        except (URLError, TimeoutError, OSError) as exc:
            raise _OAuthHTTPError("MCP authorization probe failed") from exc
        if "bearer" not in challenge.lower():
            raise MCPOAuthError("MCP server did not return a Bearer challenge")
        parameters = {
            key.lower(): value.replace(r"\"", '"').replace(r"\\", "\\")
            for key, value in CHALLENGE_PARAMETER.findall(challenge)
        }
        return parameters.get("resource_metadata"), _scope_values(
            parameters.get("scope"),
            label="MCP OAuth challenge scope",
        )

    def post_form(
        self,
        url: str,
        fields: Mapping[str, str],
        *,
        authorization: str | None = None,
    ) -> dict[str, Any]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "iCheck-mcp-oauth/0.1",
        }
        if authorization:
            headers["Authorization"] = authorization
        return self._json(
            Request(
                url,
                data=urlencode(fields).encode("ascii"),
                headers=headers,
                method="POST",
            )
        )


def mcp_oauth_transport(settings: Settings) -> MCPOAuthTransport:
    return MCPOAuthTransport(settings.mcp_oauth_timeout_seconds)


def _resource_metadata_candidates(endpoint: str) -> list[str]:
    parsed = urlsplit(endpoint)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    result: list[str] = []
    path = parsed.path.strip("/")
    if path:
        result.append(f"{origin}/.well-known/oauth-protected-resource/{path}")
    result.append(f"{origin}/.well-known/oauth-protected-resource")
    return result


def _authorization_metadata_candidates(issuer: str) -> list[str]:
    parsed = urlsplit(issuer)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    path = parsed.path.strip("/")
    if path:
        return [
            f"{origin}/.well-known/oauth-authorization-server/{path}",
            f"{origin}/.well-known/openid-configuration/{path}",
            f"{issuer.rstrip('/')}/.well-known/openid-configuration",
        ]
    return [
        f"{origin}/.well-known/oauth-authorization-server",
        f"{origin}/.well-known/openid-configuration",
    ]


def _first_document(
    urls: list[str],
    transport: MCPOAuthTransport,
) -> tuple[str, dict[str, Any]]:
    for url in urls:
        try:
            return url, transport.get_json(url)
        except _OAuthHTTPError as exc:
            if exc.status_code == 404:
                continue
            raise
    raise MCPOAuthError("Required OAuth metadata document was not found")


def discover_mcp_oauth(
    server: MCPServer,
    *,
    settings: Settings | None = None,
    transport: MCPOAuthTransport | None = None,
    requested_scopes_override: list[str] | None = None,
    resource_metadata_url: str | None = None,
) -> OAuthDiscovery:
    settings = settings or get_settings()
    if not settings.mcp_oauth_configured:
        raise MCPOAuthError("MCP OAuth is not configured", code="not_configured")
    if server.auth_mode != "oauth_authorization_code":
        raise MCPOAuthError("MCP server does not use OAuth", code="not_configured")
    transport = transport or mcp_oauth_transport(settings)
    endpoint = server.endpoint_url
    metadata_url, challenged_scopes = transport.challenge(endpoint)
    if resource_metadata_url is not None:
        metadata_url = resource_metadata_url
    candidates: list[str]
    if metadata_url:
        candidates = [
            _validate_remote_url(
                metadata_url,
                settings,
                resource_host_allowed=True,
            )
        ]
    else:
        candidates = [
            _validate_remote_url(url, settings, resource_host_allowed=True)
            for url in _resource_metadata_candidates(endpoint)
        ]
    selected_metadata_url, document = _first_document(candidates, transport)
    if document.get("resource") != endpoint:
        raise MCPOAuthError("Protected resource metadata does not match MCP endpoint")
    authorization_servers = document.get("authorization_servers")
    if (
        not isinstance(authorization_servers, list)
        or not 1 <= len(authorization_servers) <= 10
        or not all(isinstance(value, str) for value in authorization_servers)
    ):
        raise MCPOAuthError("Protected resource metadata has no authorization server")
    authorization_servers = [
        _validate_issuer(value, settings) for value in authorization_servers
    ]
    if server.oauth_authorization_server:
        issuer = server.oauth_authorization_server
        if issuer not in authorization_servers:
            raise MCPOAuthError(
                "Configured authorization server is not advertised by the MCP resource"
            )
    elif len(authorization_servers) == 1:
        issuer = authorization_servers[0]
    else:
        raise MCPOAuthError(
            "MCP resource advertises multiple authorization servers; select one"
        )
    scopes_supported = _scope_values(
        document.get("scopes_supported"),
        label="Protected resource scopes_supported",
    )
    configured_scopes = tuple(server.oauth_requested_scopes or [])
    if requested_scopes_override is not None:
        override_scopes = _scope_values(
            requested_scopes_override,
            label="MCP OAuth step-up scope",
        )
        if configured_scopes and not set(override_scopes).issubset(
            configured_scopes
        ):
            raise MCPOAuthError(
                "MCP step-up scopes exceed the server's configured scope allowlist"
            )
        if scopes_supported and not set(override_scopes).issubset(
            scopes_supported
        ):
            raise MCPOAuthError(
                "MCP step-up scopes are not advertised by protected-resource metadata"
            )
        requested_scopes = list(override_scopes)
    elif challenged_scopes:
        if configured_scopes and not set(challenged_scopes).issubset(configured_scopes):
            raise MCPOAuthError(
                "MCP scope challenge exceeds the server's configured scope allowlist"
            )
        requested_scopes = list(challenged_scopes)
        if (
            "offline_access" in configured_scopes
            and "offline_access" in scopes_supported
            and "offline_access" not in requested_scopes
        ):
            requested_scopes.append("offline_access")
    else:
        requested_scopes = list(configured_scopes or scopes_supported)
    _, authorization_document = _first_document(
        [
            _validate_remote_url(url, settings)
            for url in _authorization_metadata_candidates(issuer)
        ],
        transport,
    )
    if authorization_document.get("issuer") != issuer:
        raise MCPOAuthError("Authorization metadata issuer does not match discovery")
    authorization_endpoint = _validate_remote_url(
        authorization_document.get("authorization_endpoint"),
        settings,
    )
    token_endpoint = _validate_remote_url(
        authorization_document.get("token_endpoint"),
        settings,
    )
    revocation_endpoint_value = authorization_document.get("revocation_endpoint")
    revocation_endpoint = (
        _validate_remote_url(revocation_endpoint_value, settings)
        if revocation_endpoint_value is not None
        else None
    )
    response_types = authorization_document.get("response_types_supported")
    if isinstance(response_types, list) and "code" not in response_types:
        raise MCPOAuthError("Authorization server does not support authorization code")
    challenge_methods = authorization_document.get("code_challenge_methods_supported")
    if not isinstance(challenge_methods, list) or "S256" not in challenge_methods:
        raise MCPOAuthError("Authorization server does not advertise PKCE S256")
    auth_methods_document = authorization_document.get(
        "token_endpoint_auth_methods_supported",
        ["client_secret_basic"],
    )
    if (
        not isinstance(auth_methods_document, list)
        or not all(isinstance(value, str) for value in auth_methods_document)
    ):
        raise MCPOAuthError("Authorization server token auth methods are invalid")
    expected_auth_method = (
        "client_secret_basic"
        if server.oauth_client_secret_profile_ref
        else "none"
    )
    if expected_auth_method not in auth_methods_document:
        raise MCPOAuthError(
            f"Authorization server does not support {expected_auth_method}"
        )
    resource = ProtectedResourceMetadata(
        resource=endpoint,
        authorization_servers=tuple(authorization_servers),
        scopes_supported=scopes_supported,
        metadata_url=selected_metadata_url,
    )
    authorization = AuthorizationServerMetadata(
        issuer=issuer,
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        revocation_endpoint=revocation_endpoint,
        token_endpoint_auth_methods=frozenset(auth_methods_document),
        authorization_response_iss_parameter_supported=(
            authorization_document.get(
                "authorization_response_iss_parameter_supported"
            )
            is True
        ),
    )
    digest_document = {
        "resource": resource.resource,
        "resource_metadata_url": resource.metadata_url,
        "authorization_servers": list(resource.authorization_servers),
        "issuer": authorization.issuer,
        "authorization_endpoint": authorization.authorization_endpoint,
        "token_endpoint": authorization.token_endpoint,
        "revocation_endpoint": authorization.revocation_endpoint,
        "token_endpoint_auth_methods": sorted(
            authorization.token_endpoint_auth_methods
        ),
        "authorization_response_iss_parameter_supported": (
            authorization.authorization_response_iss_parameter_supported
        ),
        "requested_scopes": requested_scopes,
        "pkce": "S256",
    }
    return OAuthDiscovery(
        resource=resource,
        authorization=authorization,
        requested_scopes=tuple(requested_scopes),
        digest_sha256=_canonical_hash(digest_document),
    )


def _enforce_transaction_capacity(db: Session, settings: Settings) -> None:
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": MCP_OAUTH_TRANSACTION_ADVISORY_LOCK},
        )
    now = utcnow()
    db.execute(
        delete(MCPOAuthTransaction).where(
            MCPOAuthTransaction.expires_at <= now
        )
    )
    pending = db.scalar(
        select(func.count(MCPOAuthTransaction.id)).where(
            MCPOAuthTransaction.consumed_at.is_(None),
            MCPOAuthTransaction.expires_at > now,
        )
    )
    if int(pending or 0) >= settings.mcp_oauth_max_pending_transactions:
        db.commit()
        raise MCPOAuthError(
            "MCP OAuth capacity is temporarily exhausted",
            code="capacity_exhausted",
        )


def begin_mcp_oauth(
    db: Session,
    server: MCPServer,
    *,
    actor: str,
    return_to: str,
    settings: Settings | None = None,
    transport: MCPOAuthTransport | None = None,
    scope_challenge_id: str | None = None,
    principal: PrincipalContext | None = None,
) -> MCPOAuthStart:
    require_locking_transaction(db, purpose="OAuth consent transactions")
    settings = settings or get_settings()
    return_to = _validate_return_to(return_to)
    server = locked_oauth_server(db, server.id)
    if server is None:
        raise MCPOAuthError("MCP OAuth server is unavailable")
    assert_consent_eligible(db, server)
    snapshot = build_consent_snapshot(db, server, actor=actor, principal=principal, settings=settings)
    authority = snapshot_authority(db, snapshot, settings)
    challenge: MCPOAuthScopeChallenge | None = None
    requested_scopes_override: list[str] | None = None
    resource_metadata_url: str | None = None
    if scope_challenge_id is not None:
        challenge = db.get(MCPOAuthScopeChallenge, scope_challenge_id)
        if (
            challenge is None
            or challenge.server_id != server.id
            or challenge.status != "pending"
            or challenge.approved_at is None
        ):
            raise MCPOAuthError(
                "MCP OAuth scope challenge is not approved and pending",
                code="scope_challenge_unavailable",
            )
        requested_scopes_override = list(challenge.requested_scopes or [])
        resource_metadata_url = challenge.resource_metadata_url
    discovery = discover_mcp_oauth(
        server,
        settings=settings,
        transport=transport,
        requested_scopes_override=requested_scopes_override,
        resource_metadata_url=resource_metadata_url,
    )
    if challenge is not None:
        challenge = db.scalar(
            select(MCPOAuthScopeChallenge)
            .where(MCPOAuthScopeChallenge.id == challenge.id)
            .with_for_update()
        )
        if (
            challenge is None
            or challenge.server_id != server.id
            or challenge.status != "pending"
            or challenge.approved_at is None
            or list(challenge.requested_scopes or [])
            != list(requested_scopes_override or [])
        ):
            raise MCPOAuthError(
                "MCP OAuth scope challenge changed; refresh and retry",
                code="scope_challenge_changed",
            )
    _enforce_transaction_capacity(db, settings)
    state = secrets.token_urlsafe(32)
    browser_token = f"icm_{secrets.token_urlsafe(32)}"
    code_verifier = secrets.token_urlsafe(48)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    transaction_id = new_id()
    state_hash = hash_token(state)
    snapshot = snapshot.model_copy(update={"authorization_locator": OAuthAuthorizationLocator(
        transaction_id=transaction_id, state_sha256=state_hash, pkce_s256=code_challenge)})
    ttl_seconds = settings.mcp_oauth_transaction_ttl_minutes * 60
    transaction = MCPOAuthTransaction(
        id=transaction_id,
        server_id=server.id,
        oauth_generation=server.oauth_generation,
        consent_snapshot=snapshot.model_dump(mode="json"),
        state_hash=state_hash,
        browser_token_hash=hash_token(browser_token),
        code_verifier_ciphertext=_fernet(settings).encrypt(
            code_verifier.encode("ascii")
        ).decode("ascii"),
        issuer=discovery.authorization.issuer,
        resource=discovery.resource.resource,
        metadata_sha256=discovery.digest_sha256,
        requested_scopes=list(discovery.requested_scopes),
        resource_metadata_url=discovery.resource.metadata_url,
        scope_challenge_id=challenge.id if challenge is not None else None,
        return_to=return_to,
        actor_id=snapshot.authority.subject,
        tenant_id=server.tenant_id,
        region_id=server.region_id,
        expires_at=utcnow() + timedelta(seconds=ttl_seconds),
    )
    db.add(transaction)
    if challenge is not None:
        challenge.status = "authorizing"
        challenge.revision += 1
        challenge.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="mcp.oauth.authorization_started",
        actor_type="user",
        actor_id=actor,
        entity_type="mcp_server",
        entity_id=server.id,
        details={
            "issuer": discovery.authorization.issuer,
            "resource": discovery.resource.resource,
            "scopes": list(discovery.requested_scopes),
            "metadata_sha256": discovery.digest_sha256,
            "scope_challenge_id": challenge.id if challenge is not None else None,
        },
    )
    assert_live_authority(db, authority)
    db.commit()
    fields = {
        "response_type": "code",
        "client_id": snapshot.client_id,
        "redirect_uri": settings.mcp_oauth_redirect_uri or "",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "resource": discovery.resource.resource,
    }
    if discovery.requested_scopes:
        fields["scope"] = " ".join(discovery.requested_scopes)
    separator = (
        "&"
        if urlsplit(discovery.authorization.authorization_endpoint).query
        else "?"
    )
    return MCPOAuthStart(
        authorization_url=(
            discovery.authorization.authorization_endpoint
            + separator
            + urlencode(fields)
        ),
        browser_token=browser_token,
        max_age_seconds=ttl_seconds,
    )


def _consume_transaction(
    db: Session,
    *,
    state: str,
    browser_token: str,
) -> MCPOAuthTransaction:
    transaction = db.scalar(
        select(MCPOAuthTransaction)
        .where(MCPOAuthTransaction.state_hash == hash_token(state))
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
        raise MCPOAuthError(
            "MCP OAuth transaction is invalid or expired",
            code="invalid_transaction",
        )
    transaction.consumed_at = now
    db.commit()
    set_session_namespace(db, transaction.tenant_id, transaction.region_id)
    return transaction


def _record_failure(
    db: Session,
    transaction: MCPOAuthTransaction | None,
    error: MCPOAuthError,
) -> None:
    if transaction is None:
        return
    reset_scope_challenge_after_oauth_failure(
        db,
        transaction.scope_challenge_id,
    )
    transaction.failure_code = error.code[:64]
    transaction.failure_sha256 = _sha256(str(error))
    record_audit_event(
        db,
        event_type="mcp.oauth.authorization_failed",
        actor_type="user",
        actor_id=transaction.actor_id,
        entity_type="mcp_server",
        entity_id=transaction.server_id,
        details={"error_code": error.code},
        outcome="failure",
    )
    db.commit()


def _profile(db: Session, reference: str) -> CredentialProfile | None:
    return db.scalar(
        select(CredentialProfile).where(
            or_(
                CredentialProfile.id == reference,
                CredentialProfile.name == reference,
            )
        ).with_for_update(read=True).execution_options(populate_existing=True)
    )


def _client_secret(db: Session, server: MCPServer) -> str | None:
    if not server.oauth_client_secret_profile_ref:
        return None
    profile = _profile(db, server.oauth_client_secret_profile_ref)
    if profile is None or not profile.enabled:
        raise MCPOAuthError("MCP OAuth client secret profile is unavailable")
    scoped = f"mcp_oauth_client:{server.name}"
    if scoped in profile.allowed_adapters:
        adapter = scoped
    elif "mcp_oauth_client" in profile.allowed_adapters:
        adapter = "mcp_oauth_client"
    else:
        raise MCPOAuthError("MCP OAuth client secret profile is not authorized")
    try:
        return resolve_server_secret(profile, adapter_type=adapter)
    except CredentialUnavailable as exc:
        raise MCPOAuthError("MCP OAuth client secret is unavailable") from exc


def _token_store(
    settings: Settings,
    *,
    vault_opener: Any | None = None,
    oauth_opener: Any | None = None,
) -> MCPOAuthVaultCredentialProvider:
    if not settings.server_secret_vault_address or not settings.server_secret_vault_token_file:
        raise MCPOAuthError("MCP OAuth Vault token storage is not configured")
    return MCPOAuthVaultCredentialProvider(
        address=settings.server_secret_vault_address,
        token_file=settings.server_secret_vault_token_file,
        namespace=settings.server_secret_vault_namespace,
        timeout_seconds=settings.server_secret_vault_timeout_seconds,
        opener=vault_opener,
        oauth_opener=oauth_opener,
        oauth_allowed_hosts=settings.mcp_oauth_allowed_host_list,
    )


def _token_profile(db: Session, server: MCPServer) -> CredentialProfile:
    if not server.credential_profile_ref:
        raise MCPOAuthError("MCP OAuth token profile is not configured")
    profile = _profile(db, server.credential_profile_ref)
    if (
        profile is None
        or not profile.enabled
        or profile.provider != "mcp_oauth_vault"
    ):
        raise MCPOAuthError("MCP OAuth token profile is unavailable")
    if "mcp" not in profile.allowed_adapters and (
        f"mcp:{server.name}" not in profile.allowed_adapters
    ):
        raise MCPOAuthError("MCP OAuth token profile is not authorized")
    return profile


def _client_authorization(client_id: str, client_secret: str) -> str:
    encoded = base64.b64encode(
        f"{quote(client_id, safe='')}:{quote(client_secret, safe='')}".encode(
            "utf-8"
        )
    ).decode("ascii")
    return f"Basic {encoded}"


def _exchange_code(
    server: MCPServer,
    discovery: OAuthDiscovery,
    settings: Settings,
    transport: MCPOAuthTransport,
    *,
    code: str,
    code_verifier: str,
    client_secret: str | None,
) -> dict[str, Any]:
    if not 1 <= len(code) <= 8192:
        raise MCPOAuthError("MCP OAuth authorization code is invalid")
    fields = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.mcp_oauth_redirect_uri or "",
        "code_verifier": code_verifier,
        "resource": discovery.resource.resource,
    }
    authorization = None
    if client_secret:
        authorization = _client_authorization(
            server.oauth_client_id or "",
            client_secret,
        )
    else:
        fields["client_id"] = server.oauth_client_id or ""
    redemption_started_at = utcnow()
    document = transport.post_form(
        discovery.authorization.token_endpoint,
        fields,
        authorization=authorization,
    )
    if "error" in document:
        raise MCPOAuthError("MCP OAuth token exchange was rejected")
    access_token = document.get("access_token")
    token_type = document.get("token_type")
    expires_in = document.get("expires_in")
    if (
        not isinstance(access_token, str)
        or not 1 <= len(access_token) <= 65_536
        or not isinstance(token_type, str)
        or token_type.lower() != "bearer"
        or isinstance(expires_in, bool)
        or not isinstance(expires_in, int)
        or not 1 <= expires_in <= 86_400
    ):
        raise MCPOAuthError("MCP OAuth token response is invalid")
    granted_scopes = _scope_values(
        document.get("scope", list(discovery.requested_scopes)),
        label="OAuth granted scope",
    )
    if discovery.requested_scopes and not set(granted_scopes).issubset(
        discovery.requested_scopes
    ):
        raise MCPOAuthError("OAuth token response returned unrequested scopes")
    refresh_token = document.get("refresh_token")
    if refresh_token is not None and (
        not isinstance(refresh_token, str)
        or not 1 <= len(refresh_token) <= 65_536
    ):
        raise MCPOAuthError("MCP OAuth refresh token is invalid")
    expires_at = redemption_started_at + timedelta(seconds=expires_in)
    if expires_at <= utcnow():
        raise MCPOAuthError("OAuth token response arrived after its lifetime; consent outcome remains fenced")
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_at": expires_at,
        "scope": granted_scopes,
        "refresh_token": refresh_token,
    }


def finish_mcp_oauth(
    db: Session,
    *,
    state: str | None,
    browser_token: str | None,
    code: str | None,
    issuer: str | None,
    provider_error: str | None = None,
    settings: Settings | None = None,
    transport: MCPOAuthTransport | None = None,
    token_store: MCPOAuthVaultCredentialProvider | None = None,
) -> MCPOAuthResult:
    require_locking_transaction(db, purpose="OAuth consent transactions")
    settings = settings or get_settings()
    if not state or not browser_token:
        raise MCPOAuthError(
            "MCP OAuth callback is missing transaction state",
            code="invalid_transaction",
        )
    transaction: MCPOAuthTransaction | None = None
    attempt_id: str | None = None
    bundle: dict[str, Any] | None = None
    known_unstored = False

    def retained_attempt():
        row = db.scalar(select(MCPOAuthConsentAttempt).where(MCPOAuthConsentAttempt.id == attempt_id)
            .with_for_update().execution_options(populate_existing=True))
        if row is None:
            raise MCPOAuthError("Admitted consent custody is unavailable", code="consent_recovery_required")
        return row

    try:
        transaction = _consume_transaction(
            db,
            state=state,
            browser_token=browser_token,
        )
        server = locked_oauth_server(db, transaction.server_id)
        if server is None or not server.enabled:
            raise MCPOAuthError("MCP OAuth server is unavailable")
        if server.oauth_status == "revocation_pending":
            raise MCPOAuthError("MCP OAuth cleanup must finish before reconnect", code="revocation_pending")
        if transaction.oauth_generation != server.oauth_generation:
            raise MCPOAuthError("MCP OAuth consent changed during authorization", code="consent_superseded")
        assert_consent_eligible(db, server)
        try:
            snapshot = OAuthConsentSnapshot.model_validate(transaction.consent_snapshot)
        except ValidationError as exc:
            raise MCPOAuthError("Consent has no valid original configuration/provenance snapshot", code="invalid_transaction") from exc
        profile = current_consent_snapshot(db, server, snapshot, settings)
        authority = snapshot_authority(db, snapshot, settings)
        transport = transport or mcp_oauth_transport(settings)
        discovery = discover_mcp_oauth(
            server,
            settings=settings,
            transport=transport,
            requested_scopes_override=list(transaction.requested_scopes),
            resource_metadata_url=transaction.resource_metadata_url,
        )
        if (
            not secrets.compare_digest(
                transaction.metadata_sha256,
                discovery.digest_sha256,
            )
            or transaction.issuer != discovery.authorization.issuer
            or transaction.resource != discovery.resource.resource
        ):
            raise MCPOAuthError("MCP OAuth metadata changed during authorization")
        if issuer is not None and issuer != transaction.issuer:
            raise MCPOAuthError(
                "MCP OAuth authorization response issuer is invalid",
                code="issuer_mismatch",
            )
        if (
            discovery.authorization.authorization_response_iss_parameter_supported
            and issuer is None
        ):
            raise MCPOAuthError(
                "MCP OAuth authorization response omitted its issuer",
                code="issuer_missing",
            )
        if provider_error:
            raise MCPOAuthError(
                "MCP OAuth provider denied authorization",
                code="provider_denied",
            )
        if not code:
            raise MCPOAuthError("MCP OAuth callback has no authorization code")
        try:
            code_verifier = _fernet(settings).decrypt(
                transaction.code_verifier_ciphertext.encode("ascii"),
                ttl=settings.mcp_oauth_transaction_ttl_minutes * 60,
            ).decode("ascii")
        except (InvalidToken, UnicodeError, ValueError) as exc:
            raise MCPOAuthError("MCP OAuth PKCE verifier is unavailable") from exc
        locator = OAuthAuthorizationLocator(transaction_id=transaction.id, state_sha256=transaction.state_hash,
            pkce_s256=base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii"))
        if snapshot.authorization_locator is not None and snapshot.authorization_locator != locator:
            raise MCPOAuthError("Consent protocol locator differs from the original transaction", code="invalid_transaction")
        # Authentic retained PKCE data can upgrade a pre-locator pending transaction,
        # but must never rewrite the immutable custody of an admitted attempt.
        snapshot = snapshot.model_copy(update={"authorization_locator": locator})
        client_secret = _client_secret(db, server)
        token_store = token_store or _token_store(settings)
        if (getattr(token_store, "address", None) != snapshot.vault_address.rstrip("/")
                or getattr(token_store, "namespace", None) != snapshot.vault_namespace):
            raise MCPOAuthError("Consent storage differs from the original Vault identity", code="consent_superseded")
        target = token_store.inspect_consent_target(snapshot.token_profile.secret_ref,
            expected_generation=snapshot.generation, require_present=server.oauth_status in {"connected", "expired"})
        if target.present and (target.issuer, target.client_id, target.resource) != (
                discovery.authorization.issuer, snapshot.client_id, discovery.resource.resource):
            raise MCPOAuthError("Existing consent target identity differs from this consent", code="consent_superseded")
        assert_live_authority(db, authority)
        if _as_utc(transaction.expires_at) <= utcnow():
            raise MCPOAuthError("Consent expired before code redemption", code="invalid_transaction")
        generation = secrets.token_hex(16)
        attempt = MCPOAuthConsentAttempt(server_id=server.id, transaction_id=transaction.id,
            tenant_id=server.tenant_id, region_id=server.region_id, generation=generation,
            previous_generation=snapshot.generation, status="redemption_admitted",
            issuer=discovery.authorization.issuer, client_id=snapshot.client_id, resource=discovery.resource.resource,
            snapshot=snapshot.model_dump(mode="json"), target=target.model_dump(mode="json"),
            target_version=target.vault_version, actor_id=snapshot.authority.subject)
        db.add(attempt); db.flush(); attempt_id = attempt.id
        server.oauth_status = "revocation_pending"
        server.updated_at = utcnow()
        record_audit_event(db, event_type="mcp.oauth.consent.redemption_admitted", actor_type="user",
            actor_id=snapshot.authority.subject, entity_type="mcp_server", entity_id=server.id,
            details={"attempt_id": attempt_id, "generation": generation,
                     "previous_generation": snapshot.generation, "target_version": target.vault_version})
        assert_live_authority(db, authority)
        db.commit()  # Durable unknown-outcome custody; no DB locks across grant I/O.
        token = _exchange_code(
            _CodeExchangeClient(snapshot.client_id),
            discovery,
            settings,
            transport,
            code=code,
            code_verifier=code_verifier,
            client_secret=client_secret,
        )
        bundle = {
            "access_token": token["access_token"],
            "token_type": "Bearer",
            "expires_at": token["expires_at"].isoformat(),
            "scope": " ".join(token["scope"]),
            "issuer": discovery.authorization.issuer,
            "resource": discovery.resource.resource,
            "token_endpoint": discovery.authorization.token_endpoint,
            "revocation_endpoint": discovery.authorization.revocation_endpoint,
            "client_id": snapshot.client_id,
            "metadata_sha256": discovery.digest_sha256,
            "icheck_oauth_authorization_locator": locator.model_dump(mode="json"),
        }
        if token["refresh_token"]:
            bundle["refresh_token"] = token["refresh_token"]
        if client_secret:
            bundle["client_secret"] = client_secret
        known_unstored = True
        server = locked_oauth_server(db, snapshot.server_id)
        attempt = retained_attempt()
        if (server is None or server.oauth_status != "revocation_pending"
                or attempt.status != "redemption_admitted" or attempt.family_recovery_id is not None):
            raise MCPOAuthError("Consent admission was superseded", code="consent_superseded")
        profile = current_consent_snapshot(db, server, snapshot, settings)
        authority = snapshot_authority(db, snapshot, settings)
        attempt.status = "storage_admitted"
        attempt.refresh_token_received = bool(token["refresh_token"])
        attempt.updated_at = utcnow()
        record_audit_event(db, event_type="mcp.oauth.consent.storage_admitted", actor_type="user",
            actor_id=snapshot.authority.subject, entity_type="mcp_server", entity_id=snapshot.server_id,
            details={"attempt_id": attempt_id, "generation": generation, "target_version": target.vault_version})
        assert_live_authority(db, authority)
        db.commit()
        known_unstored = False  # A publication request might now have committed.
        try:
            version = token_store.store_consent_bundle(snapshot.token_profile.secret_ref, bundle,
                generation=generation, target=target)
        except OAuthConsentStoreRejected:
            known_unstored = True  # Provider proves no publication request was sent.
            raise
        if type(version) is not int or version != target.vault_version + 1:
            raise CredentialUnavailable("OAuth credential storage returned an invalid version")
        server = locked_oauth_server(db, snapshot.server_id)
        attempt = retained_attempt()
        attempt.stored_version = version
        try:
            if (server is None or server.oauth_status != "revocation_pending" or attempt.status != "storage_admitted"
                    or attempt.family_recovery_id is not None):
                raise MCPOAuthError("Stored consent cannot be published to the superseded server", code="consent_superseded")
            current_consent_snapshot(db, server, snapshot, settings)
        except MCPOAuthError:
            attempt.status = "stored_unpublished"
            attempt.updated_at = utcnow()
            db.commit()  # Retain this OWNED storage receipt, even after containment.
            raise
        now = utcnow()
        if snapshot.generation is not None:
            previous = db.scalar(select(MCPOAuthConsentAttempt).where(
                MCPOAuthConsentAttempt.server_id == snapshot.server_id,
                MCPOAuthConsentAttempt.generation == snapshot.generation,
                MCPOAuthConsentAttempt.status == "connected").with_for_update())
            if previous is not None:
                previous.status = "superseded"  # NOT a claim of remote revocation.
                previous.updated_at = now
        attempt.status = "connected"
        attempt.updated_at = now
        server.oauth_generation = generation
        server.oauth_bundle_version = version
        server.oauth_credential_observation = None
        server.oauth_revocation_intent = None
        server.oauth_status = "connected"
        server.oauth_issuer = discovery.authorization.issuer
        server.oauth_resource = discovery.resource.resource
        server.oauth_granted_scopes = list(token["scope"])
        server.oauth_metadata_sha256 = discovery.digest_sha256
        server.oauth_access_token_sha256 = _sha256(token["access_token"])
        server.oauth_refresh_token_present = bool(token["refresh_token"])
        server.oauth_token_expires_at = token["expires_at"]
        server.oauth_connected_by = transaction.actor_id
        server.oauth_connected_at = now
        server.oauth_revoked_by = None
        server.oauth_revoked_at = None
        server.updated_at = now
        resolved_challenge_ids = resolve_mcp_scope_challenges(
            db,
            server=server,
            granted_scopes=token["scope"],
            actor=transaction.actor_id,
        )
        record_audit_event(
            db,
            event_type="mcp.oauth.connected",
            actor_type="user",
            actor_id=transaction.actor_id,
            entity_type="mcp_server",
            entity_id=server.id,
            details={
                "issuer": server.oauth_issuer,
                "resource": server.oauth_resource,
                "scopes": server.oauth_granted_scopes,
                "expires_at": token["expires_at"].isoformat(),
                "refresh_token_present": server.oauth_refresh_token_present,
                "metadata_sha256": server.oauth_metadata_sha256,
                "vault_profile_id": profile.id,
                "vault_profile_revision": profile.revision,
                "vault_ref_sha256": _sha256(profile.secret_ref),
                "vault_address": settings.server_secret_vault_address,
                "vault_namespace": settings.server_secret_vault_namespace,
                "generation": server.oauth_generation,
                "client_id": server.oauth_client_id,
                "connected_at": now.isoformat(),
                "scope_challenge_id": transaction.scope_challenge_id,
                "resolved_scope_challenge_ids": resolved_challenge_ids,
            },
        )
        db.commit()
        return MCPOAuthResult(
            server_id=server.id,
            return_to=transaction.return_to,
        )
    except (MCPOAuthError, CredentialUnavailable) as exc:
        db.rollback()
        if attempt_id is not None:
            retained = retained_attempt()
            if retained.status in {"redemption_admitted", "storage_admitted"}:
                retained.status = "compensation_pending" if known_unstored and bundle is not None else "outcome_unknown"
                retained.refresh_token_received = bool(bundle and bundle.get("refresh_token"))
                retained.failure_code = "consent_unstored" if known_unstored else "consent_outcome_unknown"
                retained.updated_at = utcnow()
                db.commit()
                if known_unstored and bundle is not None:
                    try:
                        token_store.compensate_unstored_consent(bundle)
                    except CredentialUnavailable:
                        pass  # Keep pending; never infer containment from failure.
                    else:
                        retained = retained_attempt()
                        retained.status = "compensation_acknowledged"
                        retained.updated_at = utcnow()
                        db.commit()  # Acknowledgement still requires independent family proof.
        error = (
            exc
            if isinstance(exc, MCPOAuthError)
            else MCPOAuthError("MCP OAuth credential storage is unavailable")
        )
        _record_failure(db, transaction, error)
        raise error from exc


def revoke_mcp_oauth(
    db: Session,
    server: MCPServer,
    *,
    actor: str,
    reason: str,
    settings: Settings | None = None,
    token_store: MCPOAuthVaultCredentialProvider | None = None,
) -> MCPServer:
    require_locking_transaction(db, purpose="OAuth cleanup transactions")
    if server.auth_mode != "oauth_authorization_code":
        raise MCPOAuthError("MCP server does not use OAuth")
    settings = settings or get_settings()
    server = locked_oauth_server(db, server.id)
    if server is None:
        raise MCPOAuthError("MCP OAuth server is unavailable")
    if server.auth_mode != "oauth_authorization_code":
        raise MCPOAuthError("MCP server no longer uses OAuth")
    assert_no_open_consent(db, server)
    if server.oauth_recovery_custody is not None:
        from ..oauth_recovery import OAuthRecoveryCustody
        try:
            recovery = OAuthRecoveryCustody.model_validate(server.oauth_recovery_custody)
        except ValidationError as exc:
            raise MCPOAuthError("OAuth recovery custody is invalid; administrative recovery is required", code="revocation_pending") from exc
        if recovery.status != "complete":
            raise MCPOAuthError("OAuth recovery must finish its independently reviewed cleanup", code="revocation_pending")
    generation = server.oauth_generation
    if server.oauth_status == "revocation_pending":
        try:
            intent = OAuthRevocationIntent.model_validate(server.oauth_revocation_intent)
        except ValidationError as exc:
            raise MCPOAuthError("Original OAuth cleanup target is unavailable; administrative recovery is required", code="revocation_pending") from exc
        if (intent.server_id != server.id or intent.tenant_id != server.tenant_id
            or intent.region_id != server.region_id or intent.generation != generation):
            raise MCPOAuthError("Original OAuth cleanup intent no longer matches this server", code="revocation_pending")
    else:
        profile = _token_profile(db, server)
        intent = OAuthRevocationIntent(intent_id=secrets.token_hex(16), server_id=server.id,
            tenant_id=server.tenant_id, region_id=server.region_id, generation=generation,
            profile_id=profile.id, profile_revision=profile.revision, secret_ref=profile.secret_ref,
            vault_address=settings.server_secret_vault_address, vault_namespace=settings.server_secret_vault_namespace)
        server.oauth_revocation_intent = intent.model_dump(mode="json")
    if (intent.vault_address != settings.server_secret_vault_address
        or intent.vault_namespace != settings.server_secret_vault_namespace):
        raise MCPOAuthError("Original OAuth Vault identity changed; cleanup remains pending", code="revocation_pending")
    server.oauth_status = "revocation_pending"
    server.updated_at = utcnow()
    db.commit()
    try:
        token_store = token_store or _token_store(settings)
        if hasattr(token_store, "revoke_bundle"):
            token_store.revoke_bundle(intent.secret_ref, expected_generation=generation)
        else:
            token_store.delete_bundle(intent.secret_ref)
    except VaultRequestError as exc:
        if exc.status_code != 404:
            record_audit_event(
                db,
                event_type="mcp.oauth.revocation_failed",
                actor_type="user",
                actor_id=actor,
                entity_type="mcp_server",
                entity_id=server.id,
                details={"reason": reason, "error_type": type(exc).__name__},
                outcome="failure",
            )
            db.commit()
            raise MCPOAuthError(
                "MCP OAuth execution is blocked, but Vault cleanup must be retried",
                code="revocation_pending",
            ) from exc
    except CredentialUnavailable as exc:
        record_audit_event(
            db,
            event_type="mcp.oauth.revocation_failed",
            actor_type="user",
            actor_id=actor,
            entity_type="mcp_server",
            entity_id=server.id,
            details={"reason": reason, "error_type": type(exc).__name__},
            outcome="failure",
        )
        db.commit()
        raise MCPOAuthError(
            "MCP OAuth execution is blocked, but Vault cleanup must be retried",
            code="revocation_pending",
        ) from exc
    server = locked_oauth_server(db, server.id)
    if (server is None or server.oauth_generation != generation or server.oauth_status != "revocation_pending"
        or server.oauth_revocation_intent != intent.model_dump(mode="json")):
        raise MCPOAuthError("MCP OAuth revocation was superseded", code="revocation_pending")
    now = utcnow()
    server.oauth_status = "revoked"
    generation_row = db.scalar(select(MCPOAuthConsentAttempt).where(
        MCPOAuthConsentAttempt.server_id == server.id, MCPOAuthConsentAttempt.generation == generation,
        MCPOAuthConsentAttempt.status == "connected").with_for_update())
    if generation_row is not None:
        generation_row.status = "revoked"
        generation_row.updated_at = now
    server.oauth_access_token_sha256 = None
    server.oauth_refresh_token_present = False
    server.oauth_token_expires_at = None
    server.oauth_credential_observation = None
    server.oauth_revocation_intent = None
    server.oauth_revoked_by = actor
    server.oauth_revoked_at = now
    server.updated_at = now
    record_audit_event(
        db,
        event_type="mcp.oauth.revoked",
        actor_type="user",
        actor_id=actor,
        entity_type="mcp_server",
        entity_id=server.id,
        details={"reason": reason, "vault_profile_id": intent.profile_id},
    )
    db.commit()
    db.refresh(server)
    return server
