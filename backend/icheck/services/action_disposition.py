"""Append-only custody of an unresolved MCP write; never a send grant."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent_schemas import MCPWriteDispositionRefs
from ..database import require_locking_transaction
from ..models import MCPWriteDisposition, utcnow
from .action_reconciliation import (
    MCPWriteEvidenceSnapshot, make_mcp_write_evidence_manifest,
    mcp_write_reconciliation_packet,
)
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext


def _evidence_refs(db: Session, snapshot: MCPWriteEvidenceSnapshot) -> MCPWriteDispositionRefs:
    manifest = make_mcp_write_evidence_manifest(db, snapshot)
    return MCPWriteDispositionRefs(
        provider=[{
            "observation_id": row.observation_id,
            "lookup_result_hash": row.lookup_result_hash,
            "review_id": row.review_id,
            "review_decision": row.review_decision,
        } for row in manifest.provider_observations],
        independent=[{
            "observation_id": row.observation_id,
            "verification_result_hash": row.verification_result_hash,
            "review_id": row.review_id,
            "review_decision": row.review_decision,
        } for row in manifest.independent_observations],
    )


def _assert_separate_reviewer(snapshot: MCPWriteEvidenceSnapshot, actor: PrincipalContext) -> None:
    proposal = snapshot.proposal
    if (
        actor.principal_type != "user"
        or actor.principal_id is None
        or not actor.permits("changes.approve")
    ):
        raise PermissionError("Authenticated change approver is required")
    if actor.principal_id in {
        proposal.requested_by_principal_id, proposal.approved_by_principal_id,
    } or actor.subject in {proposal.requested_by, proposal.approved_by}:
        raise PermissionError("Disposition reviewer must be separate from the action requester and approver")
    for row in (*snapshot.provider_observations, *snapshot.independent_observations):
        if (
            row.recorded_by_principal_id == actor.principal_id
            or row.recorded_by == actor.subject
        ):
            raise PermissionError("Disposition reviewer participated in the evidence")
    for row in (*snapshot.provider_reviews, *snapshot.independent_reviews):
        if (
            row.reviewed_by_principal_id == actor.principal_id
            or row.reviewed_by == actor.subject
        ):
            raise PermissionError("Disposition reviewer participated in the evidence")


def record_unresolved_mcp_write_disposition(
    db: Session,
    snapshot: MCPWriteEvidenceSnapshot,
    request_id: str,
    reason: str,
    *,
    actor: PrincipalContext,
) -> MCPWriteDisposition:
    """Record unresolved custody under the complete read's PostgreSQL lock."""
    if db.get_bind().dialect.name != "postgresql" or not snapshot.native_locking:
        raise ValueError("Native PostgreSQL locking is required for MCP disposition")
    require_locking_transaction(db, purpose="MCP write disposition")
    _assert_separate_reviewer(snapshot, actor)
    reason = reason.strip()
    if not 10 <= len(reason) <= 1000:
        raise ValueError("Disposition reason must contain 10-1000 characters")
    assert_no_inline_secrets(reason, "MCP write disposition reason")
    packet = mcp_write_reconciliation_packet(db, snapshot.proposal)
    if packet.tool_call_id != snapshot.packet.tool_call_id:
        raise ValueError("Original MCP write changed during disposition")
    existing = db.scalar(select(MCPWriteDisposition).where(
        MCPWriteDisposition.request_id == request_id,
        MCPWriteDisposition.tenant_id == snapshot.proposal.tenant_id,
        MCPWriteDisposition.region_id == snapshot.proposal.region_id,
    ))
    if existing is not None:
        if (
            existing.proposal_id == snapshot.proposal.id
            and existing.original_tool_call_id == packet.tool_call_id
            and existing.reviewed_by_principal_id == actor.principal_id
            and existing.reviewed_by == actor.subject
            and existing.reason == reason
            and existing.decision == "unresolved"
        ):
            return existing
        raise ValueError("Disposition request ID is already bound to another decision")
    refs = _evidence_refs(db, snapshot)
    refs_document = refs.model_dump(mode="json")
    for prior in db.scalars(select(MCPWriteDisposition).where(
        MCPWriteDisposition.proposal_id == snapshot.proposal.id,
        MCPWriteDisposition.tenant_id == snapshot.proposal.tenant_id,
        MCPWriteDisposition.region_id == snapshot.proposal.region_id,
    )):
        if prior.evidence_refs == refs_document:
            raise ValueError("This complete evidence set already has an unresolved disposition")
    row = MCPWriteDisposition(
        request_id=request_id,
        proposal_id=snapshot.proposal.id,
        original_tool_call_id=packet.tool_call_id,
        decision="unresolved",
        plan_hash=snapshot.proposal.plan_hash,
        evidence_refs=refs_document,
        reviewed_by_principal_id=actor.principal_id,
        reviewed_by=actor.subject,
        reason=reason,
        recorded_at=utcnow(),
    )
    db.add(row)
    db.flush()
    record_audit_event(
        db,
        event_type="mcp.write.disposition.unresolved",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="mcp_write_disposition",
        entity_id=row.id,
        details={
            "proposal_id": row.proposal_id,
            "original_tool_call_id": row.original_tool_call_id,
            "provider_observation_count": len(refs.provider),
            "independent_observation_count": len(refs.independent),
            "original_outcome": "unknown",
            "automatic_retry_allowed": False,
            "delivery_verified": False,
        },
    )
    db.commit()
    db.refresh(row)
    return row


def list_mcp_write_dispositions(
    db: Session, proposal_id: str, *, limit: int = 1001,
) -> list[MCPWriteDisposition]:
    return list(db.scalars(
        select(MCPWriteDisposition)
        .where(MCPWriteDisposition.proposal_id == proposal_id)
        .order_by(MCPWriteDisposition.recorded_at, MCPWriteDisposition.id)
        .limit(limit)
    ).all())
