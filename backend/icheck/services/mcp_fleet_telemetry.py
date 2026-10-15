from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session

from ..mcp_schemas import MCPFleetServerTelemetryRead, MCPFleetTelemetryRead
from ..models import (
    MCPOAuthScopeChallenge,
    MCPServer,
    MCPToolActivation,
    MCPToolAttestation,
    utcnow,
)


def _count(value: Any) -> int:
    return int(value or 0)


def _rate(successful: int, failed: int) -> float | None:
    total = successful + failed
    return round(successful * 100 / total, 2) if total else None


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _activation_aggregates(
    db: Session,
    server_ids: list[str] | None = None,
) -> dict[str, dict[str, int]]:
    query = select(
        MCPToolActivation.server_id,
        func.count(MCPToolActivation.id).label("active"),
        func.sum(
            case((MCPToolActivation.rollout_state == "canary", 1), else_=0)
        ).label("canary"),
        func.sum(
            case((MCPToolActivation.rollout_state == "full", 1), else_=0)
        ).label("full"),
        func.sum(
            case((MCPToolActivation.rollout_state == "blocked", 1), else_=0)
        ).label("blocked"),
        func.sum(
            case((MCPToolActivation.circuit_state == "open", 1), else_=0)
        ).label("open_circuits"),
        func.sum(MCPToolActivation.successful_calls).label("successful"),
        func.sum(MCPToolActivation.failed_calls).label("failed"),
    ).where(MCPToolActivation.status == "active")
    if server_ids is not None:
        if not server_ids:
            return {}
        query = query.where(MCPToolActivation.server_id.in_(server_ids))
    rows = db.execute(query.group_by(MCPToolActivation.server_id)).all()
    return {
        row.server_id: {
            "active": _count(row.active),
            "canary": _count(row.canary),
            "full": _count(row.full),
            "blocked": _count(row.blocked),
            "open_circuits": _count(row.open_circuits),
            "successful": _count(row.successful),
            "failed": _count(row.failed),
        }
        for row in rows
    }


def _scope_aggregates(
    db: Session,
    server_ids: list[str] | None = None,
) -> dict[str, dict[str, int]]:
    query = select(
        MCPOAuthScopeChallenge.server_id,
        func.sum(
            case((MCPOAuthScopeChallenge.status == "pending", 1), else_=0)
        ).label("pending"),
        func.sum(
            case((MCPOAuthScopeChallenge.status == "authorizing", 1), else_=0)
        ).label("authorizing"),
    ).where(MCPOAuthScopeChallenge.status.in_(("pending", "authorizing")))
    if server_ids is not None:
        if not server_ids:
            return {}
        query = query.where(MCPOAuthScopeChallenge.server_id.in_(server_ids))
    rows = db.execute(query.group_by(MCPOAuthScopeChallenge.server_id)).all()
    return {
        row.server_id: {
            "pending": _count(row.pending),
            "authorizing": _count(row.authorizing),
        }
        for row in rows
    }


def _attestation_aggregates(
    db: Session,
    now: datetime,
    server_ids: list[str] | None = None,
) -> dict[str, dict[str, int]]:
    query = select(
        MCPToolAttestation.server_id,
        func.sum(
            case(
                (MCPToolAttestation.status.in_(("pending", "processing")), 1),
                else_=0,
            )
        ).label("backlog"),
        func.sum(
            case((MCPToolAttestation.status == "dead_letter", 1), else_=0)
        ).label("dead_letter"),
        func.sum(
            case(
                (
                    and_(
                        MCPToolAttestation.status == "passed",
                        MCPToolAttestation.expires_at.is_not(None),
                        MCPToolAttestation.expires_at > now,
                    ),
                    1,
                ),
                else_=0,
            )
        ).label("fresh"),
    )
    if server_ids is not None:
        if not server_ids:
            return {}
        query = query.where(MCPToolAttestation.server_id.in_(server_ids))
    rows = db.execute(query.group_by(MCPToolAttestation.server_id)).all()
    return {
        row.server_id: {
            "backlog": _count(row.backlog),
            "dead_letter": _count(row.dead_letter),
            "fresh": _count(row.fresh),
        }
        for row in rows
    }


def mcp_fleet_telemetry(
    db: Session,
    *,
    stale_after_seconds: int = 900,
    server_limit: int = 200,
) -> MCPFleetTelemetryRead:
    now = utcnow()
    stale_cutoff = now - timedelta(seconds=stale_after_seconds)
    server_row = db.execute(
        select(
            func.count(MCPServer.id).label("total"),
            func.sum(case((MCPServer.enabled.is_(True), 1), else_=0)).label(
                "enabled"
            ),
            func.sum(case((MCPServer.enabled.is_(False), 1), else_=0)).label(
                "disabled"
            ),
            func.sum(
                case(
                    (
                        and_(
                            MCPServer.enabled.is_(True),
                            MCPServer.last_health_status == "healthy",
                            MCPServer.last_checked_at.is_not(None),
                            MCPServer.last_checked_at >= stale_cutoff,
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("healthy"),
            func.sum(
                case(
                    (
                        and_(
                            MCPServer.enabled.is_(True),
                            MCPServer.last_health_status == "unhealthy",
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("unhealthy"),
            func.sum(
                case(
                    (
                        and_(
                            MCPServer.enabled.is_(True),
                            MCPServer.last_health_status == "healthy",
                            MCPServer.last_checked_at.is_not(None),
                            MCPServer.last_checked_at < stale_cutoff,
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("stale"),
            func.sum(
                case(
                    (
                        and_(
                            MCPServer.enabled.is_(True),
                            or_(
                                MCPServer.last_health_status.is_(None),
                                MCPServer.last_checked_at.is_(None),
                            ),
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("unchecked"),
            func.sum(
                case(
                    (
                        and_(
                            MCPServer.enabled.is_(True),
                            MCPServer.auth_mode == "oauth_authorization_code",
                            MCPServer.oauth_status != "connected",
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("oauth_attention"),
        )
    ).one()
    activation_row = db.execute(
        select(
            func.count(MCPToolActivation.id).label("active"),
            func.sum(
                case((MCPToolActivation.rollout_state == "canary", 1), else_=0)
            ).label("canary"),
            func.sum(
                case((MCPToolActivation.rollout_state == "full", 1), else_=0)
            ).label("full"),
            func.sum(
                case((MCPToolActivation.rollout_state == "blocked", 1), else_=0)
            ).label("blocked"),
            func.sum(
                case((MCPToolActivation.circuit_state == "open", 1), else_=0)
            ).label("open_circuits"),
            func.sum(MCPToolActivation.successful_calls).label("successful"),
            func.sum(MCPToolActivation.failed_calls).label("failed"),
        ).where(MCPToolActivation.status == "active")
    ).one()
    scope_row = db.execute(
        select(
            func.sum(
                case((MCPOAuthScopeChallenge.status == "pending", 1), else_=0)
            ).label("pending"),
            func.sum(
                case((MCPOAuthScopeChallenge.status == "authorizing", 1), else_=0)
            ).label("authorizing"),
        ).where(MCPOAuthScopeChallenge.status.in_(("pending", "authorizing")))
    ).one()
    attestation_row = db.execute(
        select(
            func.sum(
                case(
                    (MCPToolAttestation.status.in_(("pending", "processing")), 1),
                    else_=0,
                )
            ).label("backlog"),
            func.sum(
                case((MCPToolAttestation.status == "dead_letter", 1), else_=0)
            ).label("dead_letter"),
            func.sum(
                case(
                    (
                        and_(
                            MCPToolAttestation.status == "passed",
                            MCPToolAttestation.expires_at.is_not(None),
                            MCPToolAttestation.expires_at > now,
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("fresh"),
        )
    ).one()

    servers = list(
        db.scalars(select(MCPServer).order_by(MCPServer.name).limit(server_limit)).all()
    )
    server_ids = [server.id for server in servers]
    activation_by_server = _activation_aggregates(db, server_ids)
    scope_by_server = _scope_aggregates(db, server_ids)
    attestation_by_server = _attestation_aggregates(db, now, server_ids)
    server_details: list[MCPFleetServerTelemetryRead] = []
    for server in servers:
        activation = activation_by_server.get(server.id, {})
        scope = scope_by_server.get(server.id, {})
        attestation = attestation_by_server.get(server.id, {})
        successful = _count(activation.get("successful"))
        failed = _count(activation.get("failed"))
        checked_at = _as_utc(server.last_checked_at)
        health_is_stale = bool(checked_at and checked_at < stale_cutoff)
        if not server.enabled:
            posture = "inactive"
        elif (
            _count(activation.get("open_circuits"))
            or server.last_health_status == "unhealthy"
            or _count(attestation.get("dead_letter"))
        ):
            posture = "critical"
        elif (
            health_is_stale
            or not server.last_health_status
            or not checked_at
            or (
                server.auth_mode == "oauth_authorization_code"
                and server.oauth_status != "connected"
            )
            or _count(scope.get("pending"))
            or _count(scope.get("authorizing"))
        ):
            posture = "degraded"
        else:
            posture = "healthy"
        server_details.append(
            MCPFleetServerTelemetryRead(
                server_id=server.id,
                server_name=server.name,
                enabled=server.enabled,
                posture=posture,
                health_status=server.last_health_status,
                health_is_stale=health_is_stale,
                oauth_status=server.oauth_status,
                active_activations=_count(activation.get("active")),
                canary_activations=_count(activation.get("canary")),
                full_activations=_count(activation.get("full")),
                blocked_activations=_count(activation.get("blocked")),
                open_circuits=_count(activation.get("open_circuits")),
                successful_calls=successful,
                failed_calls=failed,
                success_rate_percent=_rate(successful, failed),
                pending_scope_challenges=_count(scope.get("pending")),
                authorizing_scope_challenges=_count(scope.get("authorizing")),
                attestation_backlog=_count(attestation.get("backlog")),
                dead_letter_attestations=_count(attestation.get("dead_letter")),
                fresh_attestations=_count(attestation.get("fresh")),
                last_checked_at=server.last_checked_at,
            )
        )

    enabled = _count(server_row.enabled)
    unhealthy = _count(server_row.unhealthy)
    stale = _count(server_row.stale)
    unchecked = _count(server_row.unchecked)
    open_circuits = _count(activation_row.open_circuits)
    dead_letters = _count(attestation_row.dead_letter)
    pending_scopes = _count(scope_row.pending)
    authorizing_scopes = _count(scope_row.authorizing)
    oauth_attention = _count(server_row.oauth_attention)
    if enabled == 0:
        posture = "empty"
    elif open_circuits or unhealthy or dead_letters:
        posture = "critical"
    elif stale or unchecked or pending_scopes or authorizing_scopes or oauth_attention:
        posture = "degraded"
    else:
        posture = "healthy"
    successful = _count(activation_row.successful)
    failed = _count(activation_row.failed)
    return MCPFleetTelemetryRead(
        generated_at=now,
        stale_after_seconds=stale_after_seconds,
        posture=posture,
        server_count=_count(server_row.total),
        enabled_server_count=enabled,
        disabled_server_count=_count(server_row.disabled),
        healthy_server_count=_count(server_row.healthy),
        unhealthy_server_count=unhealthy,
        stale_server_count=stale,
        unchecked_server_count=unchecked,
        oauth_attention_server_count=oauth_attention,
        active_activation_count=_count(activation_row.active),
        canary_activation_count=_count(activation_row.canary),
        full_activation_count=_count(activation_row.full),
        blocked_activation_count=_count(activation_row.blocked),
        open_circuit_count=open_circuits,
        successful_calls=successful,
        failed_calls=failed,
        success_rate_percent=_rate(successful, failed),
        pending_scope_challenge_count=pending_scopes,
        authorizing_scope_challenge_count=authorizing_scopes,
        attestation_backlog_count=_count(attestation_row.backlog),
        dead_letter_attestation_count=dead_letters,
        fresh_attestation_count=_count(attestation_row.fresh),
        servers=server_details,
    )
