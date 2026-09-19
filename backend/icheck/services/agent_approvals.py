from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent_schemas import AgentActionDecision
from ..models import (
    AgentActionProposal,
    AgentExecution,
    AgentExecutionStatus,
    AgentToolRegistration,
    Investigation,
    InvestigationToolCall,
    utcnow,
)
from .agent_authorization import require_tool_permissions
from .agent_execution import append_execution_event
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext


class ActionRejected(RuntimeError):
    pass


class ActionOutcomeUnknown(RuntimeError):
    pass


def action_plan_hash(
    *,
    tool_id: str,
    arguments: dict[str, Any],
    purpose: str,
) -> str:
    encoded = json.dumps(
        {"tool_id": tool_id, "arguments": arguments, "purpose": purpose},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def propose_action(
    db: Session,
    investigation: Investigation,
    tool: AgentToolRegistration,
    *,
    iteration: int,
    arguments: dict[str, Any],
    purpose: str,
) -> AgentActionProposal:
    if tool.read_only or tool.risk_level != "change":
        raise ValueError("Only state-changing tools use governed action proposals")
    require_tool_permissions(investigation, tool)
    assert_no_inline_secrets(arguments, "action proposal arguments")
    plan_hash = action_plan_hash(
        tool_id=tool.id,
        arguments=arguments,
        purpose=purpose,
    )
    existing = db.scalar(
        select(AgentActionProposal).where(
            AgentActionProposal.investigation_id == investigation.id,
            AgentActionProposal.plan_hash == plan_hash,
        )
    )
    if existing is not None:
        return existing
    if investigation.status != "running":
        raise ValueError("Only running investigations can propose an action")

    proposal = AgentActionProposal(
        investigation_id=investigation.id,
        tool_id=tool.id,
        iteration=iteration,
        arguments=arguments,
        purpose=purpose,
        plan_hash=plan_hash,
        status="pending",
        requested_by_principal_id=investigation.requested_by_principal_id,
        requested_by=investigation.created_by,
    )
    db.add(proposal)
    investigation.status = "waiting_approval"
    investigation.updated_at = utcnow()
    db.flush()
    record_audit_event(
        db,
        event_type="investigation.action.proposed",
        actor_type="agent",
        actor_id="agent.langgraph",
        entity_type="agent_action_proposal",
        entity_id=proposal.id,
        details={
            "investigation_id": investigation.id,
            "tool_id": tool.id,
            "plan_hash": plan_hash,
            "iteration": iteration,
        },
    )
    db.commit()
    db.refresh(proposal)
    return proposal


def decide_action_proposal(
    db: Session,
    proposal: AgentActionProposal,
    payload: AgentActionDecision,
    *,
    actor: PrincipalContext,
) -> AgentActionProposal:
    if not actor.permits("changes.approve"):
        raise PermissionError("Required permission: changes.approve")
    if proposal.status != "pending":
        raise ValueError("Action proposal is no longer pending")
    if not secrets.compare_digest(proposal.plan_hash, payload.expected_plan_hash):
        raise ValueError("Action proposal plan hash changed or is stale")
    same_principal = (
        proposal.requested_by_principal_id is not None
        and actor.principal_id == proposal.requested_by_principal_id
    )
    if same_principal or actor.subject == proposal.requested_by:
        raise PermissionError("The action requester cannot approve their own action")

    investigation = db.get(Investigation, proposal.investigation_id)
    execution = db.scalar(
        select(AgentExecution).where(
            AgentExecution.investigation_id == proposal.investigation_id
        )
    )
    if investigation is None or execution is None:
        raise LookupError("Proposal investigation execution not found")
    if (
        investigation.status != "waiting_approval"
        or execution.status != AgentExecutionStatus.WAITING_APPROVAL
    ):
        raise ValueError("Investigation is not durably waiting for approval")

    now = utcnow()
    proposal.status = "approved" if payload.decision == "approve" else "rejected"
    proposal.approved_by_principal_id = actor.principal_id
    proposal.approved_by = actor.subject
    proposal.decision_reason = payload.reason
    proposal.decided_at = now
    investigation.status = "running"
    investigation.updated_at = now
    execution.status = AgentExecutionStatus.QUEUED
    execution.worker_id = None
    execution.lease_token_hash = None
    execution.lease_expires_at = None
    execution.finished_at = None
    execution.error = None
    execution.updated_at = now
    event = append_execution_event(
        db,
        execution,
        event_type="execution.approval_recorded",
        payload={
            "proposal_id": proposal.id,
            "decision": payload.decision,
            "plan_hash": proposal.plan_hash,
            "actor": actor.subject,
        },
    )
    record_audit_event(
        db,
        event_type=f"investigation.action.{proposal.status}",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="agent_action_proposal",
        entity_id=proposal.id,
        outcome="success" if payload.decision == "approve" else "denied",
        details={
            "investigation_id": investigation.id,
            "tool_id": proposal.tool_id,
            "plan_hash": proposal.plan_hash,
            "reason": payload.reason,
            "event_sequence": event.sequence,
        },
    )
    db.commit()
    db.refresh(proposal)
    return proposal


def approval_resume_value(
    db: Session,
    investigation_id: str,
) -> dict[str, str] | None:
    proposal = db.scalar(
        select(AgentActionProposal)
        .where(
            AgentActionProposal.investigation_id == investigation_id,
            AgentActionProposal.status.in_(["approved", "rejected", "executing"]),
        )
        .order_by(AgentActionProposal.decided_at.desc())
        .limit(1)
    )
    if proposal is None:
        return None
    return {"proposal_id": proposal.id, "plan_hash": proposal.plan_hash}


def validate_resumed_action(
    db: Session,
    proposal_id: str,
    *,
    investigation: Investigation,
    tool: AgentToolRegistration,
    arguments: dict[str, Any],
    purpose: str,
) -> AgentActionProposal:
    proposal = db.get(AgentActionProposal, proposal_id)
    expected = action_plan_hash(
        tool_id=tool.id,
        arguments=arguments,
        purpose=purpose,
    )
    if (
        proposal is None
        or proposal.investigation_id != investigation.id
        or proposal.tool_id != tool.id
        or not secrets.compare_digest(proposal.plan_hash, expected)
    ):
        raise ValueError("Approval does not match the exact proposed action")
    if proposal.status == "rejected":
        raise ActionRejected("A human approver rejected the proposed action")
    if proposal.status == "executing":
        raise ActionOutcomeUnknown(
            "Action outcome is unknown after worker interruption; automatic replay blocked"
        )
    if proposal.status != "approved":
        raise ValueError("Action proposal is not approved")
    proposal.status = "executing"
    proposal.execution_started_at = utcnow()
    db.commit()
    db.refresh(proposal)
    return proposal


def finish_action_proposal(
    db: Session,
    proposal: AgentActionProposal,
    *,
    call: InvestigationToolCall,
    error: str | None = None,
) -> AgentActionProposal:
    proposal.tool_call_id = call.id
    proposal.status = "failed" if error else "succeeded"
    proposal.result_hash = call.result_hash
    proposal.error = error
    proposal.execution_finished_at = utcnow()
    record_audit_event(
        db,
        event_type=f"investigation.action.{proposal.status}",
        actor_type="agent",
        actor_id="agent.runtime",
        entity_type="agent_action_proposal",
        entity_id=proposal.id,
        outcome="failure" if error else "success",
        details={
            "investigation_id": proposal.investigation_id,
            "tool_id": proposal.tool_id,
            "tool_call_id": call.id,
            "plan_hash": proposal.plan_hash,
            "result_hash": call.result_hash,
        },
    )
    db.commit()
    db.refresh(proposal)
    return proposal
