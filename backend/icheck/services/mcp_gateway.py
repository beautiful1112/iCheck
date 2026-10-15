from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..agent_schemas import InvestigationEvidenceCreate
from ..config import get_settings
from ..credentials import (
    ProviderCredentialLease,
    CredentialBroker,
    CredentialContext,
    CredentialGrant,
    CredentialUnavailable,
    SecretRedactor,
    build_server_credential_providers,
    resolve_server_secret,
)
from ..mcp_schemas import (
    MCP_PROTOCOL_VERSION,
    MCPServerCreate,
    MCPServerHealth,
    MCPToolActivationCreate,
    MCPToolCircuitRecovery,
    MCPToolDeactivation,
    MCPToolRolloutAction,
)
from ..models import (
    AgentExecution,
    AgentExecutionStatus,
    AgentToolRegistration,
    AgentWorker,
    AlertSeverity,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    CredentialProfile,
    Investigation,
    MCPServer,
    MCPToolAttestation,
    MCPToolActivation,
    utcnow,
)
from ..schema_validation import validate_instance
from ..studio_schemas import GeneratedToolSpec
from .audit import record_audit_event
from .alerts import resolve_by_dedup_key, upsert_alert
from .mcp_scope_challenges import (
    MCPInsufficientScopeError,
    mcp_tool_has_open_scope_challenge,
    parse_insufficient_scope_challenge,
    record_mcp_scope_challenge,
)
from .tool_skills import _tool_spec_document, validate_tool_artifact_contract


MAX_LIST_RESPONSE_BYTES = 2_000_000
MAX_LIST_PAGES = 20
MAX_LISTED_TOOLS = 1_000
RESERVED_HEADERS = {
    "accept",
    "authorization",
    "connection",
    "content-length",
    "content-type",
    "host",
    "mcp-method",
    "mcp-name",
    "mcp-protocol-version",
    "transfer-encoding",
    "user-agent",
}


class MCPGatewayError(RuntimeError):
    pass


class MCPWriteOutcomeUnknown(MCPGatewayError):
    """A state-changing Tool request entered transport without a usable result."""


class MCPContractError(ValueError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for MCP servers",
            headers,
            fp,
        )


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def mcp_server_attestation_config_hash(
    server: MCPServer,
    profile: CredentialProfile | None,
) -> str:
    return _canonical_hash(
        {
            "server_id": server.id,
            "name": server.name,
            "endpoint_url": server.endpoint_url,
            "protocol_version": server.protocol_version,
            "enabled": server.enabled,
            "auth_mode": server.auth_mode,
            "credential_profile": (
                {
                    "id": profile.id,
                    "revision": profile.revision,
                    "provider": profile.provider,
                    "enabled": profile.enabled,
                    "allowed_adapters": sorted(profile.allowed_adapters or []),
                    "worker_selector": profile.worker_selector or {},
                }
                if profile is not None
                else None
            ),
            "oauth": (
                {
                    "status": server.oauth_status,
                    "generation": server.oauth_generation,
                    "issuer": server.oauth_issuer,
                    "resource": server.oauth_resource,
                    "granted_scopes": sorted(server.oauth_granted_scopes or []),
                    "metadata_sha256": server.oauth_metadata_sha256,
                }
                if server.auth_mode == "oauth_authorization_code"
                else None
            ),
        }
    )


def mcp_contract_hash(
    server: MCPServer,
    version: ArtifactVersion,
    spec: GeneratedToolSpec,
) -> str:
    return _canonical_hash(
        {
            "artifact_content_hash": version.content_hash,
            "server_id": server.id,
            "spec": _tool_spec_document(spec),
        }
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


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


def validate_mcp_endpoint(url: str, allowed_hosts: list[str]) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("endpoint_url must be an HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("endpoint_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("endpoint_url must not contain a query or fragment")
    loopback = parsed.hostname.rstrip(".").lower() in {
        "127.0.0.1",
        "::1",
        "localhost",
    }
    if parsed.scheme != "https" and not loopback:
        raise ValueError("non-loopback MCP endpoints require HTTPS")
    if not _host_allowed(parsed.hostname, allowed_hosts):
        raise ValueError(
            f"endpoint_url host {parsed.hostname!r} is not in the MCP allowlist"
        )
    return url.rstrip("/")


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


def _adapter_type(profile: CredentialProfile, server: MCPServer) -> str:
    scoped = f"mcp:{server.name}"
    if scoped in profile.allowed_adapters:
        return scoped
    if "mcp" in profile.allowed_adapters:
        return "mcp"
    raise CredentialUnavailable(
        f"Credential profile does not allow adapter {scoped!r} or 'mcp'"
    )


def _credential_headers(values: Mapping[str, str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    authorization = values.get("authorization")
    token = values.get("bearer_token") or values.get("token")
    api_key = values.get("api_key")
    username = values.get("username")
    password = values.get("password")
    if authorization:
        headers["Authorization"] = authorization
    elif token:
        headers["Authorization"] = f"Bearer {token}"
    elif username and password:
        encoded = base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
    if api_key:
        headers["X-API-Key"] = api_key
    for key, value in values.items():
        if not key.startswith("header."):
            continue
        header_name = key.removeprefix("header.").strip()
        if (
            not header_name
            or header_name.lower() in RESERVED_HEADERS
            or any(character in header_name for character in "\r\n:")
        ):
            raise CredentialUnavailable("Credential declares an unsafe HTTP header")
        headers[header_name] = value
    if any("\r" in value or "\n" in value for value in headers.values()):
        raise CredentialUnavailable("Credential contains an unsafe HTTP header value")
    return headers


class MCPHTTPClient:
    """Bounded client for the stateless MCP 2026-07-28 HTTP transport."""

    def __init__(
        self,
        endpoint_url: str,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
        credentials: Mapping[str, str] | None = None,
        opener: Any | None = None,
    ):
        self.endpoint_url = endpoint_url
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.credentials = dict(credentials or {})
        self.redactor = SecretRedactor()
        self.redactor.add_mapping(self.credentials)
        self.opener = opener or build_opener(_NoRedirect())
        self.request_dispatched = False

    def _parse_sse(self, body: bytes) -> dict[str, Any]:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MCPGatewayError("MCP server returned invalid UTF-8") from exc
        documents: list[dict[str, Any]] = []
        for event in text.replace("\r\n", "\n").split("\n\n"):
            data = "\n".join(
                line[5:].lstrip()
                for line in event.splitlines()
                if line.startswith("data:")
            )
            if not data:
                continue
            try:
                document = json.loads(data)
            except json.JSONDecodeError as exc:
                raise MCPGatewayError("MCP server returned invalid SSE JSON") from exc
            if isinstance(document, dict):
                documents.append(document)
        if len(documents) != 1:
            raise MCPGatewayError("MCP server returned an unsupported SSE sequence")
        return documents[0]

    def _request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        tool_name: str | None = None,
    ) -> dict[str, Any]:
        self.request_dispatched = False
        request_id = str(uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            "Mcp-Method": method,
            "User-Agent": "iCheck-mcp-gateway/0.1",
            **_credential_headers(self.credentials),
        }
        if tool_name:
            headers["Mcp-Name"] = tool_name
        request = Request(
            self.endpoint_url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            # Once transport is entered, a lost or invalid reply cannot prove
            # that a state-changing provider operation did not commit.
            self.request_dispatched = True
            with self.opener.open(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                body = response.read(self.max_response_bytes + 1)
                content_type = (
                    response.headers.get("Content-Type", "")
                    if getattr(response, "headers", None) is not None
                    else ""
                )
        except HTTPError as exc:
            scope_error = parse_insufficient_scope_challenge(
                exc.code,
                dict(exc.headers or {}),
            )
            if scope_error is not None:
                raise scope_error from exc
            raise MCPGatewayError(
                self.redactor.redact_text(
                    f"MCP server returned HTTP {exc.code}"
                )
            ) from exc
        except (OSError, URLError) as exc:
            raise MCPGatewayError(
                self.redactor.redact_text("MCP server request failed")
            ) from exc
        if len(body) > self.max_response_bytes:
            raise MCPGatewayError(
                f"MCP response exceeded {self.max_response_bytes} bytes"
            )
        try:
            if content_type.split(";", 1)[0].strip().lower() == "text/event-stream":
                document = self._parse_sse(body)
            else:
                document = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MCPGatewayError("MCP server returned invalid JSON") from exc
        if not isinstance(document, dict):
            raise MCPGatewayError("MCP server returned an invalid JSON-RPC envelope")
        if document.get("jsonrpc") != "2.0" or document.get("id") != request_id:
            raise MCPGatewayError("MCP server returned a mismatched JSON-RPC response")
        error = document.get("error")
        if error is not None:
            safe_error = self.redactor.redact_value(error)
            raise MCPGatewayError(f"MCP JSON-RPC error: {safe_error}")
        result = document.get("result")
        if not isinstance(result, dict):
            raise MCPGatewayError("MCP response is missing the result object")
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _page in range(MAX_LIST_PAGES):
            result = self._request(
                "tools/list",
                {"cursor": cursor} if cursor else {},
            )
            page = result.get("tools")
            if not isinstance(page, list):
                raise MCPGatewayError("MCP tools/list result is missing tools")
            if any(not isinstance(item, dict) for item in page):
                raise MCPGatewayError("MCP tools/list returned an invalid tool")
            tools.extend(page)
            if len(tools) > MAX_LISTED_TOOLS:
                raise MCPGatewayError(
                    f"MCP server advertises more than {MAX_LISTED_TOOLS} tools"
                )
            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                return tools
            if (
                not isinstance(next_cursor, str)
                or not next_cursor
                or next_cursor in seen_cursors
            ):
                raise MCPGatewayError("MCP tools/list returned an invalid cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise MCPGatewayError(
            f"MCP tools/list exceeded {MAX_LIST_PAGES} pages"
        )

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        result = self._request(
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments,
                "_meta": metadata,
            },
            tool_name=tool_name,
        )
        if result.get("isError") is True:
            safe_result = self.redactor.redact_value(result)
            raise MCPGatewayError(f"MCP tool reported an error: {safe_result}")
        if result.get("task") is not None:
            raise MCPGatewayError("Asynchronous MCP tasks are not enabled")
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            raise MCPGatewayError(
                "MCP tool must return an object in structuredContent"
            )
        safe = self.redactor.redact_value(structured)
        encoded = json.dumps(
            safe,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        if len(encoded) > self.max_response_bytes:
            raise MCPGatewayError(
                f"MCP structured result exceeded {self.max_response_bytes} bytes"
            )
        return safe


def _control_plane_credentials(
    db: Session,
    server: MCPServer,
) -> dict[str, str]:
    if not server.credential_profile_ref:
        if server.auth_mode == "oauth_authorization_code":
            raise CredentialUnavailable("MCP OAuth requires its configured token profile")
        return {}
    profile = _credential_profile(db, server.credential_profile_ref)
    if profile is None or not profile.enabled:
        raise CredentialUnavailable("MCP credential profile is unavailable")
    adapter_type = _adapter_type(profile, server)
    if server.auth_mode == "oauth_authorization_code":
        if server.oauth_status != "connected":
            raise CredentialUnavailable(
                f"MCP OAuth is {server.oauth_status}; connect it before use"
            )
        if profile.provider != "mcp_oauth_vault":
            raise CredentialUnavailable("MCP OAuth requires its Vault token provider")
        provider = build_server_credential_providers().get(profile.provider)
        if provider is None:
            raise CredentialUnavailable("MCP OAuth Vault provider is not configured")
        if not server.oauth_generation:
            raise CredentialUnavailable("MCP OAuth legacy consent must be reconnected")
        resolved = provider.resolve(profile.secret_ref, expected_generation=server.oauth_generation)
        values = resolved.values if isinstance(resolved, ProviderCredentialLease) else resolved
        token = values.get("bearer_token")
        if not isinstance(token, str) or not token:
            raise CredentialUnavailable("MCP OAuth provider returned no access token")
        if isinstance(resolved, ProviderCredentialLease) and resolved.oauth_observation is not None:
            from .mcp_oauth_observations import accept_oauth_observation
            if not accept_oauth_observation(
                db, server, resolved.oauth_observation, source="control_plane", assignment_id=server.id,
                expected_generation=server.oauth_generation, profile_id=profile.id, profile_revision=profile.revision,
            ):
                raise CredentialUnavailable("MCP OAuth consent changed during credential resolution")
            server.oauth_token_expires_at = resolved.expires_at
            server.oauth_bundle_version = resolved.oauth_observation.vault_version
        return {"bearer_token": token}
    return {"token": resolve_server_secret(profile, adapter_type=adapter_type)}


def _client_for_control_plane(
    db: Session,
    server: MCPServer,
    *,
    opener: Any | None = None,
) -> MCPHTTPClient:
    endpoint = validate_mcp_endpoint(
        server.endpoint_url,
        get_settings().mcp_allowed_host_list,
    )
    return MCPHTTPClient(
        endpoint,
        timeout_seconds=20,
        max_response_bytes=MAX_LIST_RESPONSE_BYTES,
        credentials=_control_plane_credentials(db, server),
        opener=opener,
    )


def create_mcp_server(
    db: Session,
    payload: MCPServerCreate,
    *,
    allowed_hosts: list[str],
) -> MCPServer:
    endpoint = validate_mcp_endpoint(payload.endpoint_url, allowed_hosts)
    if payload.credential_profile_ref:
        profile = _credential_profile(db, payload.credential_profile_ref)
        if profile is None or not profile.enabled:
            raise ValueError("Credential profile is unavailable")
        placeholder = MCPServer(name=payload.name)
        try:
            _adapter_type(profile, placeholder)
        except CredentialUnavailable as exc:
            raise ValueError(str(exc)) from exc
        if payload.auth_mode == "oauth_authorization_code" and (
            profile.provider != "mcp_oauth_vault"
        ):
            raise ValueError(
                "OAuth MCP servers require an mcp_oauth_vault credential profile"
            )
    if payload.oauth_client_secret_profile_ref:
        client_profile = _credential_profile(
            db,
            payload.oauth_client_secret_profile_ref,
        )
        if client_profile is None or not client_profile.enabled:
            raise ValueError("OAuth client secret profile is unavailable")
        scoped = f"mcp_oauth_client:{payload.name}"
        if not any(
            value in client_profile.allowed_adapters
            for value in ("mcp_oauth_client", scoped)
        ):
            raise ValueError("OAuth client secret profile is not authorized")
    server = MCPServer(
        **payload.model_dump(exclude={"endpoint_url"}),
        endpoint_url=endpoint,
        oauth_status=(
            "disconnected"
            if payload.auth_mode == "oauth_authorization_code"
            else "not_configured"
        ),
    )
    db.add(server)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="mcp.server.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="mcp_server",
            entity_id=server.id,
            details={
                "name": server.name,
                "endpoint_host": urlsplit(endpoint).hostname,
                "protocol_version": server.protocol_version,
                "credential_profile_configured": bool(
                    server.credential_profile_ref
                ),
                "auth_mode": server.auth_mode,
                "oauth_client_secret_configured": bool(
                    server.oauth_client_secret_profile_ref
                ),
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("MCP server name already exists") from exc
    db.refresh(server)
    return server


def check_mcp_server(
    db: Session,
    server: MCPServer,
    *,
    actor: str,
    opener: Any | None = None,
) -> MCPServerHealth:
    checked_at = utcnow()
    try:
        tools = _client_for_control_plane(db, server, opener=opener).list_tools()
        names = [item.get("name") for item in tools]
        if any(not isinstance(name, str) or not name for name in names):
            raise MCPGatewayError("MCP server advertised an invalid tool name")
        if len(names) != len(set(names)):
            raise MCPGatewayError("MCP server advertised duplicate tool names")
    except Exception as exc:
        server.last_checked_at = checked_at
        server.last_health_status = "unhealthy"
        server.last_health_error = str(exc)[:10_000]
        server.last_tool_count = None
        record_audit_event(
            db,
            event_type="mcp.server.checked",
            actor_type="user",
            actor_id=actor,
            entity_type="mcp_server",
            entity_id=server.id,
            details={"status": "unhealthy", "error_type": type(exc).__name__},
            outcome="failure",
        )
        db.commit()
        if isinstance(exc, (MCPGatewayError, CredentialUnavailable, ValueError)):
            raise MCPGatewayError(str(exc)) from exc
        raise MCPGatewayError("MCP server health check failed") from exc
    server.last_checked_at = checked_at
    server.last_health_status = "healthy"
    server.last_health_error = None
    server.last_tool_count = len(tools)
    record_audit_event(
        db,
        event_type="mcp.server.checked",
        actor_type="user",
        actor_id=actor,
        entity_type="mcp_server",
        entity_id=server.id,
        details={"status": "healthy", "tool_count": len(tools)},
    )
    db.commit()
    return MCPServerHealth(
        server_id=server.id,
        status="healthy",
        protocol_version=MCP_PROTOCOL_VERSION,
        checked_at=checked_at,
        tool_count=len(tools),
        tool_names=sorted(names),
    )


def _published_tool_version(db: Session, version_id: str) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == version_id)
        .options(selectinload(ArtifactVersion.artifact))
    )
    if version is None:
        raise LookupError("Artifact version not found")
    if version.artifact.kind != ArtifactKind.TOOL:
        raise MCPContractError("Only Tool Artifacts can be activated")
    if version.status != ArtifactVersionStatus.PUBLISHED:
        raise MCPContractError("Tool Artifact version must be published")
    validate_tool_artifact_contract(
        version.definition,
        version.implementation,
        version.tests,
    )
    return version


def _validated_activation_attestation(
    db: Session,
    server: MCPServer,
    version: ArtifactVersion,
    spec: GeneratedToolSpec,
    attestation_id: str,
) -> MCPToolAttestation:
    attestation = db.scalar(
        select(MCPToolAttestation)
        .where(MCPToolAttestation.id == attestation_id)
        .with_for_update()
    )
    if attestation is None:
        raise MCPContractError("MCP Tool attestation not found")
    now = utcnow()
    profile = (
        _credential_profile(db, server.credential_profile_ref)
        if server.credential_profile_ref
        else None
    )
    if (
        attestation.server_id != server.id
        or attestation.artifact_version_id != version.id
        or attestation.status != "passed"
        or attestation.expires_at is None
        or _as_utc(attestation.expires_at) <= now
        or attestation.consumed_at is not None
        or attestation.expected_artifact_content_hash != version.content_hash
        or attestation.expected_server_config_sha256
        != mcp_server_attestation_config_hash(server, profile)
        or attestation.expected_contract_sha256
        != mcp_contract_hash(server, version, spec)
        or attestation.expected_input_schema_sha256
        != _canonical_hash(spec.input_schema)
        or attestation.expected_output_schema_sha256
        != _canonical_hash(spec.output_schema)
        or attestation.remote_contract_sha256
        != _canonical_hash(
            {
                "name": spec.mcp_tool_name,
                "inputSchema": spec.input_schema,
                "outputSchema": spec.output_schema,
            }
        )
    ):
        raise MCPContractError(
            "A fresh, unconsumed Worker attestation for this exact contract is required"
        )
    return attestation


def _consume_attestation(
    attestation: MCPToolAttestation,
    activation: MCPToolActivation,
    *,
    consumed_at: datetime,
) -> None:
    attestation.status = "consumed"
    attestation.consumed_at = consumed_at
    attestation.consumed_by_activation_id = activation.id
    attestation.updated_at = consumed_at


def mcp_activation_allows_investigation(
    activation: MCPToolActivation,
    investigation_id: str,
) -> bool:
    if (
        activation.status != "active"
        or activation.rollout_state == "blocked"
        or activation.circuit_state != "closed"
    ):
        return False
    if activation.rollout_state == "full":
        return True
    bucket = int(
        hashlib.sha256(
            f"{activation.id}:{investigation_id}".encode("utf-8")
        ).hexdigest()[:8],
        16,
    ) % 100
    return bucket < activation.traffic_percent


def mcp_tool_available_for_investigation(
    db: Session,
    tool_id: str,
    investigation_id: str,
) -> bool:
    activation = db.scalar(
        select(MCPToolActivation).where(
            MCPToolActivation.tool_registration_id == tool_id,
            MCPToolActivation.status == "active",
        )
    )
    return bool(
        activation
        and mcp_activation_allows_investigation(activation, investigation_id)
        and not mcp_tool_has_open_scope_challenge(
            db,
            activation.server_id,
            activation.tool_name,
        )
    )


def _record_mcp_runtime_success(
    db: Session,
    activation_id: str,
) -> None:
    activation = db.scalar(
        select(MCPToolActivation)
        .where(MCPToolActivation.id == activation_id)
        .with_for_update()
    )
    if activation is None:
        return
    now = utcnow()
    activation.successful_calls += 1
    activation.consecutive_failures = 0
    activation.last_call_at = now
    activation.last_success_at = now
    activation.revision += 1
    activation.updated_at = now
    server = db.get(MCPServer, activation.server_id)
    if server is not None:
        server.last_checked_at = now
        server.last_health_status = "healthy"
        server.last_health_error = None
    db.flush()


def _record_mcp_runtime_failure(
    db: Session,
    activation_id: str,
    error: Exception,
) -> None:
    activation = db.scalar(
        select(MCPToolActivation)
        .where(MCPToolActivation.id == activation_id)
        .with_for_update()
    )
    if activation is None:
        return
    now = utcnow()
    failure_sha256 = hashlib.sha256(
        f"{type(error).__name__}:{error}".encode("utf-8")
    ).hexdigest()
    activation.failed_calls += 1
    activation.consecutive_failures += 1
    activation.last_call_at = now
    activation.last_failure_at = now
    activation.last_failure_sha256 = failure_sha256
    should_open = (
        activation.consecutive_failures
        >= activation.circuit_failure_threshold
        or (
            activation.rollout_state == "canary"
            and activation.failed_calls > activation.maximum_failed_calls
        )
    )
    opened_now = should_open and activation.circuit_state != "open"
    if should_open:
        activation.circuit_state = "open"
        activation.rollout_state = "blocked"
        activation.circuit_opened_at = now
        tool = db.get(AgentToolRegistration, activation.tool_registration_id)
        if tool is not None:
            tool.enabled = False
            tool.updated_at = now
    activation.revision += 1
    activation.updated_at = now
    server = db.get(MCPServer, activation.server_id)
    if server is not None:
        server.last_checked_at = now
        server.last_health_status = "unhealthy"
        server.last_health_error = f"runtime_failure_sha256:{failure_sha256}"
    if opened_now:
        alert = upsert_alert(
            db,
            dedup_key=f"mcp-circuit:{activation.id}",
            event_type="mcp.tool.circuit.open",
            severity=AlertSeverity.CRITICAL,
            title=f"MCP circuit opened for {activation.tool_name}",
            description=(
                "The governed MCP runtime disabled this Tool after its configured "
                "failure gate was reached. Fresh attestation is required."
            ),
            entity_type="mcp_tool_activation",
            entity_id=activation.id,
            details={
                "server_id": activation.server_id,
                "tool_name": activation.tool_name,
                "failed_calls": activation.failed_calls,
                "consecutive_failures": activation.consecutive_failures,
                "failure_sha256": failure_sha256,
            },
            observed_at=now,
        )
        record_audit_event(
            db,
            event_type="mcp.tool.circuit_opened",
            actor_type="system",
            actor_id="mcp.runtime",
            entity_type="mcp_tool_activation",
            entity_id=activation.id,
            details={
                "tool_name": activation.tool_name,
                "failed_calls": activation.failed_calls,
                "consecutive_failures": activation.consecutive_failures,
                "failure_sha256": failure_sha256,
                "alert_id": alert.id if alert else None,
            },
        )
    db.flush()


def activate_mcp_tool(
    db: Session,
    server: MCPServer,
    payload: MCPToolActivationCreate,
) -> MCPToolActivation:
    if not server.enabled:
        raise MCPContractError("MCP server is disabled")
    version = _published_tool_version(db, payload.artifact_version_id)
    spec = GeneratedToolSpec.model_validate(version.definition["spec"])
    if spec.mcp_server_name != server.name:
        raise MCPContractError(
            "Tool Artifact MCP server name does not match this server"
        )
    existing_version = db.scalar(
        select(MCPToolActivation).where(
            MCPToolActivation.artifact_version_id == version.id
        )
    )
    if existing_version is not None:
        if existing_version.status == "active":
            return existing_version
        raise MCPContractError(
            "This immutable Tool Artifact version was already deactivated; "
            "publish a new version before reactivation"
        )
    existing_active = db.scalar(
        select(MCPToolActivation).where(
            MCPToolActivation.tool_name == spec.tool_name,
            MCPToolActivation.status == "active",
        )
    )
    if existing_active is not None:
        raise MCPContractError(
            "An active MCP contract already owns this tool name; deactivate it first"
        )
    now = utcnow()
    attestation = _validated_activation_attestation(
        db,
        server,
        version,
        spec,
        payload.attestation_id,
    )

    tool = db.scalar(
        select(AgentToolRegistration).where(
            AgentToolRegistration.name == spec.tool_name
        )
    )
    if tool is not None and tool.transport != "mcp":
        raise MCPContractError("Tool name is reserved by an internal tool")
    values = {
        "description": spec.description,
        "transport": "mcp",
        "handler": f"{server.name}/{spec.mcp_tool_name}",
        "input_schema": spec.input_schema,
        "output_schema": spec.output_schema,
        "risk_level": spec.risk_level,
        "read_only": spec.read_only,
        "change_contract": (
            spec.change_contract.model_dump(mode="json")
            if spec.change_contract
            else None
        ),
        "required_permissions": spec.required_permissions,
        "timeout_seconds": spec.timeout_seconds,
        "max_result_bytes": spec.max_result_bytes,
        "enabled": True,
        "created_by": payload.actor,
    }
    if tool is None:
        tool = AgentToolRegistration(
            name=spec.tool_name,
            **values,
        )
        db.add(tool)
        db.flush()
        record_audit_event(
            db,
            event_type="agent.tool.registered",
            actor_type="user",
            actor_id=payload.actor,
            entity_type="agent_tool",
            entity_id=tool.id,
            details={
                "name": tool.name,
                "transport": tool.transport,
                "risk_level": tool.risk_level,
                "read_only": tool.read_only,
                "source": "mcp_activation",
            },
        )
    else:
        for key, value in values.items():
            setattr(tool, key, value)
        tool.updated_at = utcnow()
        db.flush()

    activation = MCPToolActivation(
        server_id=server.id,
        artifact_version_id=version.id,
        tool_registration_id=tool.id,
        status="active",
        tool_name=spec.tool_name,
        mcp_tool_name=spec.mcp_tool_name,
        contract_sha256=mcp_contract_hash(server, version, spec),
        input_schema_sha256=_canonical_hash(spec.input_schema),
        output_schema_sha256=_canonical_hash(spec.output_schema),
        rollout_state="canary",
        traffic_percent=payload.canary_percent,
        minimum_successful_calls=payload.minimum_successful_calls,
        maximum_failed_calls=payload.maximum_failed_calls,
        circuit_failure_threshold=payload.circuit_failure_threshold,
        circuit_state="closed",
        activated_by=payload.actor,
        activation_reason=payload.reason,
        attested_at=attestation.attested_at or now,
    )
    db.add(activation)
    db.flush()
    _consume_attestation(attestation, activation, consumed_at=now)
    record_audit_event(
        db,
        event_type="mcp.tool.activated",
        actor_type="user",
        actor_id=payload.actor,
        entity_type="mcp_tool_activation",
        entity_id=activation.id,
        details={
            "server_id": server.id,
            "artifact_version_id": version.id,
            "tool_registration_id": tool.id,
            "tool_name": spec.tool_name,
            "contract_sha256": activation.contract_sha256,
            "attestation_id": attestation.id,
            "attestor_worker_id": attestation.worker_id,
            "rollout_state": activation.rollout_state,
            "traffic_percent": activation.traffic_percent,
            "minimum_successful_calls": activation.minimum_successful_calls,
            "maximum_failed_calls": activation.maximum_failed_calls,
            "circuit_failure_threshold": activation.circuit_failure_threshold,
            "reason": payload.reason,
        },
    )
    db.commit()
    db.refresh(activation)
    return activation


def deactivate_mcp_tool(
    db: Session,
    activation: MCPToolActivation,
    payload: MCPToolDeactivation,
) -> MCPToolActivation:
    if activation.status != "active":
        raise MCPContractError("MCP tool activation is already inactive")
    tool = db.get(AgentToolRegistration, activation.tool_registration_id)
    if tool is None:
        raise RuntimeError("Activated MCP tool registration is missing")
    activation.status = "inactive"
    activation.deactivated_by = payload.actor
    activation.deactivation_reason = payload.reason
    now = utcnow()
    activation.deactivated_at = now
    activation.updated_at = now
    tool.enabled = False
    tool.updated_at = now
    resolve_by_dedup_key(
        db,
        f"mcp-circuit:{activation.id}",
        payload.actor,
        now,
    )
    record_audit_event(
        db,
        event_type="mcp.tool.deactivated",
        actor_type="user",
        actor_id=payload.actor,
        entity_type="mcp_tool_activation",
        entity_id=activation.id,
        details={
            "tool_registration_id": tool.id,
            "tool_name": activation.tool_name,
            "reason": payload.reason,
        },
    )
    db.commit()
    db.refresh(activation)
    return activation


def promote_mcp_tool(
    db: Session,
    activation: MCPToolActivation,
    payload: MCPToolRolloutAction,
) -> MCPToolActivation:
    locked = db.scalar(
        select(MCPToolActivation)
        .where(MCPToolActivation.id == activation.id)
        .with_for_update()
    )
    if locked is None:
        raise LookupError("MCP activation not found")
    if locked.revision != payload.expected_revision:
        raise MCPContractError("MCP activation revision changed; refresh and retry")
    if locked.status != "active" or locked.rollout_state != "canary":
        raise MCPContractError("Only an active MCP canary can be promoted")
    if locked.circuit_state != "closed":
        raise MCPContractError("An open MCP circuit cannot be promoted")
    if locked.successful_calls < locked.minimum_successful_calls:
        raise MCPContractError(
            "MCP canary has not reached its minimum successful call count"
        )
    if locked.failed_calls > locked.maximum_failed_calls:
        raise MCPContractError("MCP canary exceeded its failure budget")
    now = utcnow()
    locked.rollout_state = "full"
    locked.traffic_percent = 100
    locked.promoted_at = now
    locked.promoted_by = payload.actor
    locked.promotion_reason = payload.reason
    locked.revision += 1
    locked.updated_at = now
    record_audit_event(
        db,
        event_type="mcp.tool.promoted",
        actor_type="user",
        actor_id=payload.actor,
        entity_type="mcp_tool_activation",
        entity_id=locked.id,
        details={
            "tool_name": locked.tool_name,
            "successful_calls": locked.successful_calls,
            "failed_calls": locked.failed_calls,
            "reason": payload.reason,
        },
    )
    db.commit()
    db.refresh(locked)
    return locked


def recover_mcp_tool_circuit(
    db: Session,
    activation: MCPToolActivation,
    payload: MCPToolCircuitRecovery,
) -> MCPToolActivation:
    locked = db.scalar(
        select(MCPToolActivation)
        .where(MCPToolActivation.id == activation.id)
        .with_for_update()
    )
    if locked is None:
        raise LookupError("MCP activation not found")
    if locked.revision != payload.expected_revision:
        raise MCPContractError("MCP activation revision changed; refresh and retry")
    if (
        locked.status != "active"
        or locked.rollout_state != "blocked"
        or locked.circuit_state != "open"
    ):
        raise MCPContractError("Only a blocked MCP activation can be recovered")
    server = db.get(MCPServer, locked.server_id)
    if server is None or not server.enabled:
        raise MCPContractError("MCP server is unavailable")
    version = _published_tool_version(db, locked.artifact_version_id)
    spec = GeneratedToolSpec.model_validate(version.definition["spec"])
    if (
        locked.contract_sha256 != mcp_contract_hash(server, version, spec)
        or locked.input_schema_sha256 != _canonical_hash(spec.input_schema)
        or locked.output_schema_sha256 != _canonical_hash(spec.output_schema)
    ):
        raise MCPContractError("Blocked MCP activation contract has drifted")
    attestation = _validated_activation_attestation(
        db,
        server,
        version,
        spec,
        payload.attestation_id,
    )
    tool = db.get(AgentToolRegistration, locked.tool_registration_id)
    if tool is None:
        raise MCPContractError("Activated MCP Tool Registry entry is missing")
    now = utcnow()
    locked.rollout_state = "canary"
    locked.traffic_percent = payload.canary_percent
    locked.circuit_state = "closed"
    locked.successful_calls = 0
    locked.failed_calls = 0
    locked.consecutive_failures = 0
    locked.last_failure_sha256 = None
    locked.circuit_opened_at = None
    locked.revision += 1
    locked.updated_at = now
    tool.enabled = True
    tool.updated_at = now
    _consume_attestation(attestation, locked, consumed_at=now)
    resolve_by_dedup_key(
        db,
        f"mcp-circuit:{locked.id}",
        payload.actor,
        now,
    )
    record_audit_event(
        db,
        event_type="mcp.tool.circuit_recovered",
        actor_type="user",
        actor_id=payload.actor,
        entity_type="mcp_tool_activation",
        entity_id=locked.id,
        details={
            "tool_name": locked.tool_name,
            "attestation_id": attestation.id,
            "attestor_worker_id": attestation.worker_id,
            "traffic_percent": locked.traffic_percent,
            "reason": payload.reason,
        },
    )
    db.commit()
    db.refresh(locked)
    return locked


@dataclass
class MCPWorkerRuntime:
    worker: AgentWorker
    execution: AgentExecution
    credential_broker: CredentialBroker
    allowed_hosts: list[str]
    opener: Any | None = None

    def _credentials(
        self,
        db: Session,
        server: MCPServer,
        activation: MCPToolActivation,
    ) -> tuple[dict[str, str], Any | None]:
        if not server.credential_profile_ref:
            if server.auth_mode == "oauth_authorization_code":
                raise CredentialUnavailable("MCP OAuth requires its configured token profile")
            return {}, None
        if (
            server.auth_mode == "oauth_authorization_code"
            and server.oauth_status != "connected"
        ):
            raise CredentialUnavailable(
                f"MCP OAuth is {server.oauth_status}; connect it before execution"
            )
        if server.auth_mode == "oauth_authorization_code" and not server.oauth_generation:
            raise CredentialUnavailable("Legacy OAuth consent must be reconnected before worker handoff")
        profile = _credential_profile(db, server.credential_profile_ref)
        if profile is None or not profile.enabled:
            raise CredentialUnavailable("MCP credential profile is unavailable")
        adapter_type = _adapter_type(profile, server)
        worker_labels = dict(self.worker.labels or {})
        if any(
            worker_labels.get(key) != expected
            for key, expected in (profile.worker_selector or {}).items()
        ):
            raise CredentialUnavailable(
                "Agent worker does not match the credential profile scope"
            )
        db.refresh(self.execution)
        if (
            self.execution.status != AgentExecutionStatus.RUNNING
            or self.execution.worker_id != self.worker.id
            or self.execution.lease_expires_at is None
            or _as_utc(self.execution.lease_expires_at) <= utcnow()
        ):
            raise CredentialUnavailable("Agent execution lease is not active")
        grant = CredentialGrant(
            profile_id=profile.id,
            profile_name=profile.name,
            provider=profile.provider,
            secret_ref=profile.secret_ref,
            adapter_type=adapter_type,
            deployment_id=activation.id,
            expires_at=_as_utc(self.execution.lease_expires_at),
            profile_revision=profile.revision,
            oauth_generation=server.oauth_generation if server.auth_mode == "oauth_authorization_code" else None,
        )
        from ..credentials import OAuthCredentialUnavailable
        from .mcp_oauth_observations import accept_oauth_observation
        def observe(value):
            return accept_oauth_observation(db, server, value, source="agent", worker=self.worker,
                assignment_id=activation.id, expected_generation=grant.oauth_generation,
                profile_id=grant.profile_id, profile_revision=grant.profile_revision)
        try:
            resolved = self.credential_broker.resolve(grant, CredentialContext(
                worker_id=self.worker.id, deployment_id=activation.id, adapter_type=adapter_type,
            ))
        except OAuthCredentialUnavailable as exc:
            observe(exc.oauth_observation)
            raise
        if grant.oauth_generation and (
            resolved.oauth_observation is None or not observe(resolved.oauth_observation)
        ):
            resolved.close()
            raise CredentialUnavailable("MCP OAuth assignment no longer matches current credential custody")
        return dict(resolved.values), resolved

    def execute(
        self,
        db: Session,
        tool: AgentToolRegistration,
        arguments: dict[str, Any],
        *,
        investigation: Investigation,
        tool_call_id: str,
    ) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
        if "mcp" not in self.worker.capabilities:
            raise MCPGatewayError("Agent worker does not advertise MCP capability")
        activation = db.scalar(
            select(MCPToolActivation).where(
                MCPToolActivation.tool_registration_id == tool.id,
                MCPToolActivation.status == "active",
            )
        )
        if activation is None or not tool.enabled:
            raise MCPGatewayError("MCP tool has no active governed activation")
        if not mcp_activation_allows_investigation(
            activation,
            investigation.id,
        ):
            raise MCPGatewayError(
                "MCP tool is outside this investigation's canary cohort or its circuit is open"
            )
        if mcp_tool_has_open_scope_challenge(
            db,
            activation.server_id,
            activation.tool_name,
        ):
            raise MCPGatewayError(
                "MCP tool is waiting for operator-approved OAuth scope step-up"
            )
        server = db.get(MCPServer, activation.server_id)
        version = db.get(ArtifactVersion, activation.artifact_version_id)
        if server is None or not server.enabled:
            raise MCPGatewayError("MCP server is unavailable")
        if (
            server.auth_mode == "oauth_authorization_code"
            and server.oauth_status != "connected"
        ):
            raise MCPGatewayError(
                f"MCP OAuth is {server.oauth_status}; connect it before execution"
            )
        if server.protocol_version != MCP_PROTOCOL_VERSION:
            raise MCPGatewayError("MCP server protocol version is unsupported")
        if version is None or version.status != ArtifactVersionStatus.PUBLISHED:
            raise MCPGatewayError("Activated Tool Artifact is no longer published")
        if (
            activation.tool_name != tool.name
            or tool.transport != "mcp"
            or tool.handler
            != f"{server.name}/{activation.mcp_tool_name}"
            or activation.input_schema_sha256 != _canonical_hash(tool.input_schema)
            or activation.output_schema_sha256 != _canonical_hash(tool.output_schema)
        ):
            raise MCPGatewayError("Activated MCP Tool Registry contract has drifted")
        from .tool_provenance import assert_tool_execution_provenance

        assert_tool_execution_provenance(db, investigation, tool, arguments, activation, version)
        endpoint = validate_mcp_endpoint(server.endpoint_url, self.allowed_hosts)
        validate_instance(arguments, tool.input_schema, "MCP tool arguments")
        credentials: dict[str, str] = {}
        resolved = None
        client: MCPHTTPClient | None = None
        try:
            credentials, resolved = self._credentials(
                db,
                server,
                activation,
            )
            client = MCPHTTPClient(
                endpoint,
                timeout_seconds=tool.timeout_seconds,
                max_response_bytes=tool.max_result_bytes,
                credentials=credentials,
                opener=self.opener,
            )
            result = client.call_tool(
                activation.mcp_tool_name,
                arguments,
                metadata={
                    "icheck/investigationId": investigation.id,
                    "icheck/toolActivationId": activation.id,
                    "icheck/toolCallId": tool_call_id,
                },
            )
            validate_instance(result, tool.output_schema, "MCP tool result")
            _record_mcp_runtime_success(db, activation.id)
            result_hash = _canonical_hash(result)
            return result, [
                InvestigationEvidenceCreate(
                    evidence_type="mcp_tool_result",
                    evidence_id=f"{activation.id}:{result_hash}",
                    summary=(
                        f"MCP tool {tool.name!r} returned a schema-validated "
                        f"structured result with SHA-256 {result_hash}."
                    ),
                    observed_at=utcnow(),
                )
            ]
        except MCPInsufficientScopeError as exc:
            if client is not None and client.request_dispatched and not tool.read_only:
                error = MCPWriteOutcomeUnknown(
                    "MCP write outcome is unknown after transport; independent provider reconciliation is required"
                )
                _record_mcp_runtime_failure(db, activation.id, error)
                raise error from exc
            record_mcp_scope_challenge(
                db,
                server=server,
                activation=activation,
                investigation=investigation,
                error=exc,
            )
            raise MCPGatewayError(
                "MCP tool requires operator-approved OAuth scope step-up"
            ) from exc
        except Exception as exc:
            _record_mcp_runtime_failure(db, activation.id, exc)
            if client is not None and client.request_dispatched and not tool.read_only:
                raise MCPWriteOutcomeUnknown(
                    "MCP write outcome is unknown after transport; independent provider reconciliation is required"
                ) from exc
            redactor = SecretRedactor()
            redactor.add_mapping(credentials)
            if isinstance(exc, (MCPGatewayError, CredentialUnavailable, ValueError)):
                raise MCPGatewayError(
                    redactor.redact_text(str(exc))
                ) from exc
            raise MCPGatewayError("MCP tool execution failed") from exc
        finally:
            if resolved is not None:
                resolved.close()
