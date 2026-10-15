from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..mcp_schemas import MCPOAuthScopeChallengeApproval
from ..models import (
    Alert,
    AlertStatus,
    AlertSeverity,
    MCPOAuthScopeChallenge,
    MCPServer,
    MCPToolActivation,
    Investigation,
    utcnow,
)
from .audit import record_audit_event
from .alerts import resolve_alert, resolve_by_dedup_key, upsert_alert


_CHALLENGE_PARAMETER = re.compile(
    r'(?i)(error|error_description|resource_metadata|scope)\s*=\s*'
    r'"((?:[^"\\]|\\.)*)"'
)
_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]{1,255}$")
_ACTIVE_STATUSES = ("pending", "authorizing")


@dataclass(frozen=True)
class MCPInsufficientScopeError(RuntimeError):
    required_scopes: tuple[str, ...]
    resource_metadata_url: str | None = None

    def __str__(self) -> str:
        return "MCP authorization requires operator-approved additional scope"


def _unescape_challenge_value(value: str) -> str:
    return value.replace(r'\"', '"').replace("\\\\", "\\")


def normalize_scope_values(values: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for raw in values:
        value = str(raw).strip()
        if not _SCOPE_TOKEN.fullmatch(value):
            raise ValueError("MCP OAuth challenge contains an invalid scope")
        if value not in normalized:
            normalized.append(value)
    if not 1 <= len(normalized) <= 100:
        raise ValueError("MCP OAuth challenge must contain 1 to 100 scopes")
    return tuple(normalized)


def parse_insufficient_scope_challenge(
    status_code: int,
    headers: Mapping[str, str],
) -> MCPInsufficientScopeError | None:
    if status_code != 403:
        return None
    challenge = ""
    for key, value in headers.items():
        if key.lower() == "www-authenticate":
            challenge = str(value)
            break
    if not re.match(r"^\s*Bearer(?:\s|$)", challenge, flags=re.IGNORECASE):
        return None
    parameters = {
        key.lower(): _unescape_challenge_value(value)
        for key, value in _CHALLENGE_PARAMETER.findall(challenge)
    }
    if parameters.get("error") != "insufficient_scope":
        return None
    scope = parameters.get("scope", "")
    try:
        required_scopes = normalize_scope_values(scope.split())
    except ValueError:
        return None
    metadata_url = parameters.get("resource_metadata")
    if metadata_url is not None and not 1 <= len(metadata_url) <= 2048:
        return None
    return MCPInsufficientScopeError(
        required_scopes=required_scopes,
        resource_metadata_url=metadata_url,
    )


def mcp_tool_has_open_scope_challenge(
    db: Session,
    server_id: str,
    tool_name: str,
) -> bool:
    return (
        db.scalar(
            select(MCPOAuthScopeChallenge.id).where(
                MCPOAuthScopeChallenge.server_id == server_id,
                MCPOAuthScopeChallenge.tool_name == tool_name,
                MCPOAuthScopeChallenge.status.in_(_ACTIVE_STATUSES),
            )
        )
        is not None
    )


def record_mcp_scope_challenge(
    db: Session,
    *,
    server: MCPServer,
    activation: MCPToolActivation,
    investigation: Investigation,
    error: MCPInsufficientScopeError,
) -> MCPOAuthScopeChallenge:
    locked_server = db.scalar(
        select(MCPServer).where(MCPServer.id == server.id).with_for_update()
    )
    if (
        locked_server is None
        or locked_server.auth_mode != "oauth_authorization_code"
        or locked_server.oauth_status != "connected"
    ):
        raise ValueError("MCP scope step-up requires a connected OAuth server")
    challenged_scopes = normalize_scope_values(error.required_scopes)
    existing = db.scalar(
        select(MCPOAuthScopeChallenge)
        .where(
            MCPOAuthScopeChallenge.server_id == locked_server.id,
            MCPOAuthScopeChallenge.tool_name == activation.tool_name,
            MCPOAuthScopeChallenge.status.in_(_ACTIVE_STATUSES),
        )
        .with_for_update()
    )
    now = utcnow()
    if existing is None:
        challenge = MCPOAuthScopeChallenge(
            server_id=locked_server.id,
            activation_id=activation.id,
            investigation_id=investigation.id,
            tool_name=activation.tool_name,
            challenged_scopes=sorted(challenged_scopes),
            requested_scopes=sorted(
                set(locked_server.oauth_granted_scopes or [])
                | set(challenged_scopes)
            ),
            resource_metadata_url=error.resource_metadata_url,
            status="pending",
            tenant_id=locked_server.tenant_id,
            region_id=locked_server.region_id,
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(challenge)
        event_type = "mcp.oauth.scope_challenge.created"
    else:
        challenge = existing
        merged_scopes = sorted(
            set(challenge.challenged_scopes or []) | set(challenged_scopes)
        )
        changed = (
            merged_scopes != sorted(challenge.challenged_scopes or [])
            or (
                error.resource_metadata_url is not None
                and error.resource_metadata_url != challenge.resource_metadata_url
            )
        )
        challenge.activation_id = activation.id
        challenge.investigation_id = investigation.id
        challenge.challenged_scopes = merged_scopes
        challenge.requested_scopes = sorted(
            set(locked_server.oauth_granted_scopes or []) | set(merged_scopes)
        )
        if error.resource_metadata_url is not None:
            challenge.resource_metadata_url = error.resource_metadata_url
        challenge.occurrence_count += 1
        challenge.last_seen_at = now
        challenge.updated_at = now
        challenge.revision += 1
        if changed:
            challenge.status = "pending"
            challenge.approved_at = None
            challenge.approved_by = None
            challenge.approval_reason = None
            challenge.allowlist_expanded = False
        event_type = "mcp.oauth.scope_challenge.updated"
    db.flush()
    alert = upsert_alert(
        db,
        dedup_key=(
            f"mcp-oauth-scope:{locked_server.id}:{activation.tool_name}:{challenge.id}"
        ),
        event_type="mcp.oauth.scope.required",
        severity=AlertSeverity.WARNING,
        title=f"OAuth scope review required for {activation.tool_name}",
        description=(
            "The MCP server rejected a governed call with insufficient scope. "
            "The Tool is blocked until policy approval and fresh consent complete."
        ),
        entity_type="mcp_oauth_scope_challenge",
        entity_id=challenge.id,
        details={
            "server_id": locked_server.id,
            "activation_id": activation.id,
            "investigation_id": investigation.id,
            "tool_name": activation.tool_name,
            "challenged_scopes": challenge.challenged_scopes,
            "requested_scopes": challenge.requested_scopes,
            "occurrence_count": challenge.occurrence_count,
        },
        observed_at=now,
    )
    record_audit_event(
        db,
        event_type=event_type,
        actor_type="system",
        actor_id="mcp.runtime",
        entity_type="mcp_oauth_scope_challenge",
        entity_id=challenge.id,
        details={
            "server_id": locked_server.id,
            "activation_id": activation.id,
            "investigation_id": investigation.id,
            "tool_name": activation.tool_name,
            "challenged_scopes": challenge.challenged_scopes,
            "requested_scopes": challenge.requested_scopes,
            "occurrence_count": challenge.occurrence_count,
            "resource_metadata_present": bool(challenge.resource_metadata_url),
            "alert_id": alert.id if alert else None,
        },
    )
    db.flush()
    return challenge


def approve_mcp_scope_challenge(
    db: Session,
    challenge: MCPOAuthScopeChallenge,
    payload: MCPOAuthScopeChallengeApproval,
) -> MCPOAuthScopeChallenge:
    # Consent/runtime paths lock server then challenge; approval must use the
    # same order rather than waiting in the opposite direction.
    from .mcp_oauth_observations import locked_oauth_server
    server = locked_oauth_server(db, challenge.server_id)
    locked = db.scalar(
        select(MCPOAuthScopeChallenge)
        .where(MCPOAuthScopeChallenge.id == challenge.id)
        .with_for_update().execution_options(populate_existing=True)
    )
    if locked is None:
        raise LookupError("MCP OAuth scope challenge not found")
    if locked.revision != payload.expected_revision:
        raise ValueError("MCP OAuth scope challenge revision changed; refresh and retry")
    if locked.status != "pending":
        raise ValueError("Only a pending MCP OAuth scope challenge can be approved")
    if (
        server is None
        or locked.server_id != server.id
        or not server.enabled
        or server.auth_mode != "oauth_authorization_code"
        or server.oauth_status != "connected"
    ):
        raise ValueError("MCP OAuth server is not connected")
    required = set(locked.challenged_scopes or [])
    configured = set(server.oauth_requested_scopes or [])
    missing = required - configured
    if missing and not payload.allow_scope_expansion:
        raise ValueError(
            "MCP OAuth scope challenge exceeds the configured allowlist; "
            "explicit scope expansion approval is required"
        )
    if missing:
        server.oauth_requested_scopes = sorted(configured | required)
        server.updated_at = utcnow()
    now = utcnow()
    locked.requested_scopes = sorted(
        set(server.oauth_granted_scopes or []) | required
    )
    locked.approved_at = now
    locked.approved_by = payload.actor
    locked.approval_reason = payload.reason
    locked.allowlist_expanded = bool(missing)
    locked.revision += 1
    locked.updated_at = now
    record_audit_event(
        db,
        event_type="mcp.oauth.scope_challenge.approved",
        actor_type="user",
        actor_id=payload.actor,
        entity_type="mcp_oauth_scope_challenge",
        entity_id=locked.id,
        details={
            "server_id": server.id,
            "tool_name": locked.tool_name,
            "challenged_scopes": locked.challenged_scopes,
            "requested_scopes": locked.requested_scopes,
            "allowlist_expanded": locked.allowlist_expanded,
            "reason": payload.reason,
        },
    )
    db.commit()
    db.refresh(locked)
    return locked


def resolve_mcp_scope_challenges(
    db: Session,
    *,
    server: MCPServer,
    granted_scopes: Iterable[str],
    actor: str,
) -> list[str]:
    granted = set(granted_scopes)
    challenges = list(
        db.scalars(
            select(MCPOAuthScopeChallenge)
            .where(
                MCPOAuthScopeChallenge.server_id == server.id,
                MCPOAuthScopeChallenge.status.in_(_ACTIVE_STATUSES),
            )
            .with_for_update()
        ).all()
    )
    resolved_ids: list[str] = []
    now = utcnow()
    for challenge in challenges:
        if set(challenge.challenged_scopes or []).issubset(granted):
            challenge.status = "resolved"
            challenge.resolved_at = now
            challenge.resolved_by = actor
            resolved_ids.append(challenge.id)
            resolve_by_dedup_key(
                db,
                f"mcp-oauth-scope:{server.id}:{challenge.tool_name}:{challenge.id}",
                actor,
                now,
            )
            # Preserve pre-upgrade episodes without repinning a shared legacy
            # key to a different Challenge. This is an administrative consent
            # resolution, not independently observed quiet-source proof.
            legacy = db.scalar(select(Alert).where(
                Alert.dedup_key == f"mcp-oauth-scope:{server.id}:{challenge.tool_name}",
                Alert.entity_type == "mcp_oauth_scope_challenge", Alert.entity_id == challenge.id,
                Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]), Alert.source_retirement_id.is_(None)))
            if legacy is not None:
                resolve_alert(db, legacy, actor)
        elif challenge.status == "authorizing":
            challenge.status = "pending"
        else:
            continue
        challenge.revision += 1
        challenge.updated_at = now
    if resolved_ids:
        record_audit_event(
            db,
            event_type="mcp.oauth.scope_challenges.resolved",
            actor_type="user",
            actor_id=actor,
            entity_type="mcp_server",
            entity_id=server.id,
            details={
                "challenge_ids": resolved_ids,
                "granted_scopes": sorted(granted),
            },
        )
    db.flush()
    return resolved_ids


def reset_scope_challenge_after_oauth_failure(
    db: Session,
    challenge_id: str | None,
) -> None:
    if not challenge_id:
        return
    challenge = db.scalar(
        select(MCPOAuthScopeChallenge)
        .where(MCPOAuthScopeChallenge.id == challenge_id)
        .with_for_update()
    )
    if challenge is not None and challenge.status == "authorizing":
        challenge.status = "pending"
        challenge.revision += 1
        challenge.updated_at = utcnow()
        db.flush()
