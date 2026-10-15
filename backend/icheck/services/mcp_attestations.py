from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from ..credentials import CredentialGrant, CredentialUnavailable
from ..mcp_schemas import (
    MCP_PROTOCOL_VERSION,
    MCPAttestationClaim,
    MCPAttestationCredentialGrant,
    MCPToolAttestationAssignment,
    MCPToolAttestationComplete,
    MCPToolAttestationCreate,
)
from ..models import (
    AgentWorker,
    AgentWorkerState,
    ArtifactVersion,
    CredentialProfile,
    MCPServer,
    MCPToolAttestation,
    utcnow,
)
from ..studio_schemas import GeneratedToolSpec
from .audit import record_audit_event
from .mcp_oauth_observations import accept_oauth_observation, locked_oauth_server
from .mcp_gateway import (
    MCPContractError,
    _adapter_type,
    _canonical_hash,
    _credential_profile,
    _published_tool_version,
    mcp_contract_hash,
    mcp_server_attestation_config_hash,
    validate_mcp_endpoint,
)


ATTESTATION_TTL = timedelta(minutes=15)
MAX_CLOCK_SKEW = timedelta(minutes=5)
RETRYABLE_FAILURES = {
    "credential_unavailable",
    "transport_error",
    "worker_error",
}


class MCPAttestationLeaseLost(RuntimeError):
    pass


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _clear_lease(attestation: MCPToolAttestation, *, clear_worker: bool) -> None:
    if clear_worker:
        attestation.worker_id = None
    attestation.lease_token_hash = None
    attestation.lease_expires_at = None


def _profile_for_server(
    db: Session,
    server: MCPServer,
) -> CredentialProfile | None:
    if not server.credential_profile_ref:
        return None
    profile = _credential_profile(db, server.credential_profile_ref)
    if profile is None or not profile.enabled:
        raise MCPContractError("MCP credential profile is unavailable")
    try:
        _adapter_type(profile, server)
    except CredentialUnavailable as exc:
        raise MCPContractError(str(exc)) from exc
    return profile


def request_mcp_tool_attestation(
    db: Session,
    server: MCPServer,
    payload: MCPToolAttestationCreate,
    *,
    allowed_hosts: list[str],
) -> MCPToolAttestation:
    if not server.enabled:
        raise MCPContractError("MCP server is disabled")
    validate_mcp_endpoint(server.endpoint_url, allowed_hosts)
    if (
        server.auth_mode == "oauth_authorization_code"
        and server.oauth_status != "connected"
    ):
        raise MCPContractError(
            f"MCP OAuth is {server.oauth_status}; connect it before attestation"
        )
    version = _published_tool_version(db, payload.artifact_version_id)
    if not version.content_hash:
        raise MCPContractError("Published Tool Artifact content hash is missing")
    spec = GeneratedToolSpec.model_validate(version.definition["spec"])
    if spec.mcp_server_name != server.name:
        raise MCPContractError(
            "Tool Artifact MCP server name does not match this server"
        )
    profile = _profile_for_server(db, server)
    server_hash = mcp_server_attestation_config_hash(server, profile)
    contract_hash = mcp_contract_hash(server, version, spec)
    input_hash = _canonical_hash(spec.input_schema)
    output_hash = _canonical_hash(spec.output_schema)
    now = utcnow()
    existing = db.scalar(
        select(MCPToolAttestation)
        .where(
            MCPToolAttestation.server_id == server.id,
            MCPToolAttestation.artifact_version_id == version.id,
            MCPToolAttestation.status.in_(["pending", "processing", "passed"]),
        )
        .order_by(MCPToolAttestation.created_at.desc())
    )
    if (
        existing is not None
        and existing.expected_server_config_sha256 == server_hash
        and existing.expected_contract_sha256 == contract_hash
        and (
            existing.status != "passed"
            or (
                existing.expires_at is not None
                and _as_utc(existing.expires_at) > now
            )
        )
    ):
        return existing
    attestation = MCPToolAttestation(
        server_id=server.id,
        artifact_version_id=version.id,
        status="pending",
        tool_name=spec.tool_name,
        mcp_tool_name=spec.mcp_tool_name,
        expected_server_config_sha256=server_hash,
        expected_artifact_content_hash=version.content_hash,
        expected_contract_sha256=contract_hash,
        expected_input_schema_sha256=input_hash,
        expected_output_schema_sha256=output_hash,
        credential_profile_id=profile.id if profile else None,
        credential_profile_revision=profile.revision if profile else None,
        requested_by=payload.actor,
        request_reason=payload.reason,
        next_attempt_at=now,
    )
    db.add(attestation)
    db.flush()
    record_audit_event(
        db,
        event_type="mcp.tool_attestation.queued",
        actor_type="user",
        actor_id=payload.actor,
        entity_type="mcp_tool_attestation",
        entity_id=attestation.id,
        details={
            "server_id": server.id,
            "artifact_version_id": version.id,
            "tool_name": spec.tool_name,
            "contract_sha256": contract_hash,
            "reason": payload.reason,
        },
    )
    db.commit()
    db.refresh(attestation)
    return attestation


def _snapshot_is_current(
    db: Session,
    attestation: MCPToolAttestation,
) -> tuple[MCPServer, ArtifactVersion, GeneratedToolSpec, CredentialProfile | None]:
    server = locked_oauth_server(db, attestation.server_id)
    if server is None or not server.enabled:
        raise MCPContractError("MCP attestation server is unavailable")
    version = _published_tool_version(db, attestation.artifact_version_id)
    if not version.content_hash:
        raise MCPContractError("Published Tool Artifact content hash is missing")
    spec = GeneratedToolSpec.model_validate(version.definition["spec"])
    profile = _profile_for_server(db, server)
    if (
        version.content_hash != attestation.expected_artifact_content_hash
        or mcp_contract_hash(server, version, spec)
        != attestation.expected_contract_sha256
        or mcp_server_attestation_config_hash(server, profile)
        != attestation.expected_server_config_sha256
        or _canonical_hash(spec.input_schema)
        != attestation.expected_input_schema_sha256
        or _canonical_hash(spec.output_schema)
        != attestation.expected_output_schema_sha256
        or spec.tool_name != attestation.tool_name
        or spec.mcp_tool_name != attestation.mcp_tool_name
    ):
        raise MCPContractError(
            "MCP server or Tool Artifact changed after attestation was queued"
        )
    if (
        attestation.credential_profile_id != (profile.id if profile else None)
        or attestation.credential_profile_revision
        != (profile.revision if profile else None)
    ):
        raise MCPContractError(
            "MCP credential profile changed after attestation was queued"
        )
    if (
        server.auth_mode == "oauth_authorization_code"
        and server.oauth_status != "connected"
    ):
        raise MCPContractError(
            f"MCP OAuth is {server.oauth_status}; attestation is blocked"
        )
    return server, version, spec, profile


def _profile_matches_worker(
    profile: CredentialProfile,
    worker: AgentWorker,
) -> bool:
    labels = dict(worker.labels or {})
    return all(
        labels.get(key) == expected
        for key, expected in (profile.worker_selector or {}).items()
    )


def _credential_grant(
    attestation: MCPToolAttestation,
    server: MCPServer,
    profile: CredentialProfile | None,
    *,
    expires_at: datetime,
) -> MCPAttestationCredentialGrant | None:
    if profile is None:
        return None
    if server.auth_mode == "oauth_authorization_code" and not server.oauth_generation:
        raise MCPContractError("Legacy OAuth consent must be reconnected before worker handoff")
    grant = CredentialGrant(
        profile_id=profile.id,
        profile_name=profile.name,
        provider=profile.provider,
        secret_ref=profile.secret_ref,
        adapter_type=_adapter_type(profile, server),
        deployment_id=attestation.id,
        expires_at=expires_at,
        profile_revision=profile.revision,
        oauth_generation=server.oauth_generation if server.auth_mode == "oauth_authorization_code" else None,
    )
    return MCPAttestationCredentialGrant.model_validate(grant.__dict__)


def claim_mcp_tool_attestations(
    db: Session,
    worker: AgentWorker,
    payload: MCPAttestationClaim,
    *,
    allowed_hosts: list[str],
) -> list[MCPToolAttestationAssignment]:
    if worker.state != AgentWorkerState.ONLINE:
        raise ValueError("Only online attestor workers can claim MCP attestations")
    if "mcp_attestation" not in worker.capabilities:
        raise ValueError("Worker does not advertise mcp_attestation capability")
    if (worker.labels or {}).get("role") != "mcp_attestor":
        raise ValueError("Worker is not bound to the MCP attestor role")
    now = utcnow()
    worker.last_heartbeat_at = now
    ready = and_(
        MCPToolAttestation.status == "pending",
        MCPToolAttestation.next_attempt_at <= now,
    )
    abandoned = and_(
        MCPToolAttestation.status == "processing",
        MCPToolAttestation.lease_expires_at.is_not(None),
        MCPToolAttestation.lease_expires_at <= now,
    )
    candidates = list(
        db.scalars(
            select(MCPToolAttestation)
            .where(or_(ready, abandoned))
            .order_by(
                MCPToolAttestation.next_attempt_at,
                MCPToolAttestation.created_at,
                MCPToolAttestation.id,
            )
            .with_for_update(skip_locked=True)
            .limit(payload.max_assignments * 4)
        ).all()
    )
    assignments: list[MCPToolAttestationAssignment] = []
    for attestation in candidates:
        if len(assignments) >= payload.max_assignments:
            break
        if (
            attestation.status == "processing"
            and attestation.attempt_count >= attestation.max_attempts
        ):
            attestation.status = "dead_letter"
            attestation.failure_code = "lease_expired"
            attestation.failure_sha256 = _canonical_hash(
                {"code": "lease_expired", "attempt": attestation.attempt_count}
            )
            _clear_lease(attestation, clear_worker=False)
            continue
        try:
            server, _version, spec, profile = _snapshot_is_current(
                db, attestation
            )
            endpoint = validate_mcp_endpoint(server.endpoint_url, allowed_hosts)
        except (MCPContractError, ValueError) as exc:
            attestation.status = "failed"
            attestation.failure_code = "snapshot_drift"
            attestation.failure_sha256 = hashlib.sha256(
                str(exc).encode("utf-8")
            ).hexdigest()
            _clear_lease(attestation, clear_worker=False)
            continue
        if profile is not None and not _profile_matches_worker(profile, worker):
            continue
        token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(seconds=payload.lease_seconds)
        attestation.status = "processing"
        attestation.worker_id = worker.id
        attestation.lease_token_hash = _token_hash(token)
        attestation.lease_expires_at = expires_at
        attestation.attempt_count += 1
        attestation.updated_at = now
        assignments.append(
            MCPToolAttestationAssignment(
                attestation_id=attestation.id,
                worker_id=worker.id,
                server_id=server.id,
                artifact_version_id=attestation.artifact_version_id,
                lease_token=token,
                lease_expires_at=expires_at,
                attempt=attestation.attempt_count,
                endpoint_url=endpoint,
                protocol_version=MCP_PROTOCOL_VERSION,
                mcp_tool_name=attestation.mcp_tool_name,
                expected_input_schema=spec.input_schema,
                expected_output_schema=spec.output_schema,
                expected_input_schema_sha256=(
                    attestation.expected_input_schema_sha256
                ),
                expected_output_schema_sha256=(
                    attestation.expected_output_schema_sha256
                ),
                credential_grant=_credential_grant(
                    attestation,
                    server,
                    profile,
                    expires_at=expires_at,
                ),
            )
        )
        record_audit_event(
            db,
            event_type="mcp.tool_attestation.claimed",
            actor_type="worker",
            actor_id=worker.id,
            entity_type="mcp_tool_attestation",
            entity_id=attestation.id,
            details={
                "attempt": attestation.attempt_count,
                "lease_expires_at": expires_at.isoformat(),
            },
        )
    db.commit()
    return assignments


def complete_mcp_tool_attestation(
    db: Session,
    attestation_id: str,
    worker: AgentWorker,
    payload: MCPToolAttestationComplete,
) -> MCPToolAttestation:
    attestation = db.scalar(
        select(MCPToolAttestation)
        .where(MCPToolAttestation.id == attestation_id)
        .with_for_update()
    )
    if attestation is None:
        raise LookupError("MCP Tool attestation not found")
    if attestation.status != "processing":
        raise MCPAttestationLeaseLost("MCP Tool attestation is not processing")
    if attestation.worker_id != worker.id:
        raise MCPAttestationLeaseLost(
            "MCP Tool attestation belongs to another worker"
        )
    if not attestation.lease_token_hash or not hmac.compare_digest(
        attestation.lease_token_hash,
        _token_hash(payload.lease_token),
    ):
        raise MCPAttestationLeaseLost("MCP Tool attestation lease token is invalid")
    now = utcnow()
    if (
        attestation.lease_expires_at is None
        or _as_utc(attestation.lease_expires_at) <= now
    ):
        raise MCPAttestationLeaseLost("MCP Tool attestation lease expired")
    checked_at = _as_utc(payload.checked_at)
    if checked_at > now + MAX_CLOCK_SKEW or checked_at < _as_utc(
        attestation.created_at
    ) - MAX_CLOCK_SKEW:
        raise ValueError("MCP Tool attestation timestamp is invalid")
    try:
        server, _version, spec, _profile = _snapshot_is_current(db, attestation)
    except MCPContractError as exc:
        attestation.status = "failed"
        attestation.failure_code = "snapshot_drift"
        attestation.failure_sha256 = hashlib.sha256(
            str(exc).encode("utf-8")
        ).hexdigest()
        _clear_lease(attestation, clear_worker=False)
        db.commit()
        db.refresh(attestation)
        return attestation
    if payload.oauth_observation is not None and _profile is not None:
        accept_oauth_observation(
            db, server, payload.oauth_observation, source="attestor", worker=worker,
            assignment_id=attestation.id, expected_generation=server.oauth_generation,
            profile_id=attestation.credential_profile_id,
            profile_revision=attestation.credential_profile_revision,
        )
    if payload.status == "passed":
        expected_remote_hash = _canonical_hash(
            {
                "name": attestation.mcp_tool_name,
                "inputSchema": spec.input_schema,
                "outputSchema": spec.output_schema,
            }
        )
        if (
            payload.protocol_version != MCP_PROTOCOL_VERSION
            or payload.input_schema_sha256
            != attestation.expected_input_schema_sha256
            or payload.output_schema_sha256
            != attestation.expected_output_schema_sha256
            or payload.remote_contract_sha256 != expected_remote_hash
        ):
            raise ValueError("MCP attestation evidence does not match the queued contract")
        attestation.status = "passed"
        attestation.advertised_tool_count = payload.advertised_tool_count
        attestation.catalog_sha256 = payload.catalog_sha256
        attestation.remote_contract_sha256 = payload.remote_contract_sha256
        attestation.failure_code = None
        attestation.failure_sha256 = None
        attestation.attested_at = checked_at
        attestation.expires_at = checked_at + ATTESTATION_TTL
        server.last_checked_at = checked_at
        server.last_health_status = "healthy"
        server.last_health_error = None
        server.last_tool_count = payload.advertised_tool_count
    else:
        retryable = bool(
            payload.retryable
            and payload.failure_code in RETRYABLE_FAILURES
            and attestation.attempt_count < attestation.max_attempts
        )
        attestation.status = "pending" if retryable else (
            "dead_letter"
            if payload.retryable
            and attestation.attempt_count >= attestation.max_attempts
            else "failed"
        )
        attestation.failure_code = payload.failure_code
        attestation.failure_sha256 = payload.failure_sha256
        attestation.next_attempt_at = now + timedelta(
            seconds=min(300, 5 * (2 ** attestation.attempt_count))
        )
        server.last_checked_at = checked_at
        server.last_health_status = "unhealthy"
        server.last_health_error = payload.failure_code
        server.last_tool_count = None
    _clear_lease(attestation, clear_worker=attestation.status == "pending")
    attestation.updated_at = now
    record_audit_event(
        db,
        event_type="mcp.tool_attestation.completed",
        actor_type="worker",
        actor_id=worker.id,
        entity_type="mcp_tool_attestation",
        entity_id=attestation.id,
        details={
            "status": attestation.status,
            "attempt": attestation.attempt_count,
            "failure_code": attestation.failure_code,
            "contract_sha256": attestation.expected_contract_sha256,
        },
        outcome="success" if attestation.status == "passed" else "failure",
    )
    db.commit()
    db.refresh(attestation)
    return attestation
