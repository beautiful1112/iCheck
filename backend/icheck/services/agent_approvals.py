from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent_schemas import AgentActionDecision
from ..config import get_settings
from ..models import (
    AgentActionProposal,
    AgentExecution,
    AgentExecutionStatus,
    AgentToolRegistration,
    GovernedChangePlan,
    Investigation,
    InvestigationToolCall,
    utcnow,
)
from .agent_authorization import require_tool_permissions
from .agent_execution import append_execution_event
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .change_governance import (
    create_change_plan,
    decide_change_plan,
    find_required_rollback_plan,
    mark_change_execution_finished,
    mark_change_execution_started,
)
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
    rollback_of_change_plan: GovernedChangePlan | None = None,
) -> AgentActionProposal:
    if tool.read_only or tool.risk_level != "change":
        raise ValueError("Only state-changing tools use governed action proposals")
    if tool.handler == "situations.close_reviewed":
        raise ValueError("Reviewed Situation closure uses its owned control-plane ledger, not a physical action proposal")
    require_tool_permissions(investigation, tool)
    assert_no_inline_secrets(arguments, "action proposal arguments")
    if rollback_of_change_plan is not None:
        matched = find_required_rollback_plan(
            db,
            investigation=investigation,
            tool=tool,
            arguments=arguments,
        )
        if matched is None or matched.id != rollback_of_change_plan.id:
            raise ValueError("Rollback proposal does not match the required plan")
    if (
        get_settings().require_governed_change_contracts
        and tool.change_contract is None
        and rollback_of_change_plan is None
    ):
        raise ValueError(
            "This deployment requires icheck.change-tool/v1 for every change Tool "
            "except an exact rollback frozen by an existing governed plan"
        )
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
        expected_rollback_id = (
            rollback_of_change_plan.id if rollback_of_change_plan else None
        )
        if existing.rollback_of_change_plan_id != expected_rollback_id:
            raise ValueError("Existing action proposal has different rollback context")
        return existing
    if rollback_of_change_plan is not None and rollback_of_change_plan.status != "rollback_required":
        raise ValueError("Rollback is already completed or awaiting restoration verification; do not repeat it")
    if investigation.status != "running":
        raise ValueError("Only running investigations can propose an action")

    from .situation_closure import guard_new_situation_action
    guard_new_situation_action(db, investigation)

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
        rollback_of_change_plan_id=(
            rollback_of_change_plan.id if rollback_of_change_plan else None
        ),
    )
    with db.begin_nested():
        db.add(proposal)
        db.flush()
        change_plan = create_change_plan(
            db,
            proposal=proposal,
            investigation=investigation,
            tool=tool,
        )
        from .action_targets import seal_action_targets
        seal_action_targets(db, proposal, investigation, change_plan)
        investigation.status = "waiting_approval"
        investigation.updated_at = utcnow()
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
            "change_plan_id": change_plan.id if change_plan else None,
            "change_plan_hash": change_plan.plan_hash if change_plan else None,
            "rollback_of_change_plan_id": (
                rollback_of_change_plan.id if rollback_of_change_plan else None
            ),
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
    change_plan = decide_change_plan(
        db,
        proposal,
        decision=payload.decision,
        expected_plan_hash=payload.expected_change_plan_hash,
        actor=actor.subject,
    )
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
    execution.completion_worker_id = None
    execution.completion_token_hash = None
    execution.completion_request_hash = None
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
            "change_plan_id": change_plan.id if change_plan else None,
            "change_plan_hash": (
                change_plan.approved_plan_hash if change_plan else None
            ),
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
            AgentActionProposal.status.in_(
                ["approved", "rejected", "executing", "succeeded", "failed"]
            ),
        )
        .order_by(AgentActionProposal.decided_at.desc())
        .limit(1)
    )
    if proposal is None:
        return None
    return {"proposal_id": proposal.id, "plan_hash": proposal.plan_hash}


def _exact_resumed_proposal(
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
    return proposal


def validate_resumed_action(
    db: Session,
    proposal_id: str,
    *,
    investigation: Investigation,
    tool: AgentToolRegistration,
    arguments: dict[str, Any],
    purpose: str,
) -> AgentActionProposal:
    proposal = _exact_resumed_proposal(
        db,
        proposal_id,
        investigation=investigation,
        tool=tool,
        arguments=arguments,
        purpose=purpose,
    )
    if proposal.status == "rejected":
        raise ActionRejected("A human approver rejected the proposed action")
    if proposal.status == "executing":
        raise ActionOutcomeUnknown(
            "Action outcome is unknown after worker interruption; automatic replay blocked"
        )
    if proposal.status != "approved":
        raise ValueError("Action proposal is not approved")
    from .preapproval_execution import validate_reviewed_execution
    validate_reviewed_execution(db, proposal)
    from .rollback_execution import validate_rollback_execution
    validate_rollback_execution(db, proposal)
    mark_change_execution_started(db, proposal)
    proposal.status = "executing"
    proposal.execution_started_at = utcnow()
    db.commit()
    db.refresh(proposal)
    return proposal


def prepare_resumed_action(
    db: Session,
    proposal_id: str,
    *,
    investigation: Investigation,
    tool: AgentToolRegistration,
    arguments: dict[str, Any],
    purpose: str,
    allow_running_call: bool = False,
    running_result_call_id: str | None = None,
) -> tuple[AgentActionProposal, InvestigationToolCall | None]:
    proposal = _exact_resumed_proposal(
        db,
        proposal_id,
        investigation=investigation,
        tool=tool,
        arguments=arguments,
        purpose=purpose,
    )
    if proposal.status == "rejected":
        raise ActionRejected("A human approver rejected the proposed action")
    if proposal.status == "approved":
        return (
            validate_resumed_action(
                db,
                proposal.id,
                investigation=investigation,
                tool=tool,
                arguments=arguments,
                purpose=purpose,
            ),
            None,
        )
    call = (
        db.get(InvestigationToolCall, proposal.tool_call_id)
        if proposal.tool_call_id is not None
        else db.scalar(
            select(InvestigationToolCall)
            .where(
                InvestigationToolCall.investigation_id == investigation.id,
                InvestigationToolCall.tool_id == tool.id,
                InvestigationToolCall.iteration == proposal.iteration,
            )
            .order_by(InvestigationToolCall.created_at.desc())
            .limit(1)
        )
    )
    if (
        call is None
        or call.arguments != arguments
        or (
            call.status not in {"succeeded", "failed"}
            and not (
                allow_running_call
                and proposal.status == "executing"
                and call.status == "running"
            )
        )
    ):
        raise ActionOutcomeUnknown(
            "Action outcome is unknown after worker interruption; automatic replay blocked"
        )
    if call.status == "running":
        from .preapproval_execution import authorization_for_proposal
        from .rollback_execution import rollback_authorization
        accepting_bound_result = (
            allow_running_call
            and proposal.status == "executing"
            and running_result_call_id == call.id
        )
        if not accepting_bound_result:
            reviewed = (
                authorization_for_proposal(db, proposal) is not None
                or rollback_authorization(db, proposal) is not None
            )
            raise ActionOutcomeUnknown(
                ("Reviewed action" if reviewed else "Action")
                + " outcome is unknown; replay requires independent reconciliation"
            )
        # A delegated result continuation is not a completed action yet. Keep
        # ownership executing until the bound result has been schema-validated
        # and persisted; never manufacture success from a running Tool call.
        return proposal, call
    if proposal.status == "executing":
        proposal = finish_action_proposal(
            db,
            proposal,
            call=call,
            error=(call.error or "Persisted action Tool call failed")
            if call.status == "failed"
            else None,
        )
    elif proposal.status not in {"succeeded", "failed"}:
        raise ValueError("Action proposal is not resumable")
    if proposal.tool_call_id != call.id:
        raise ValueError("Persisted action outcome does not match its proposal")
    return proposal, call


def finish_action_proposal(
    db: Session,
    proposal: AgentActionProposal,
    *,
    call: InvestigationToolCall,
    error: str | None = None,
) -> AgentActionProposal:
    if proposal.tool_call_id is not None and proposal.tool_call_id != call.id:
        raise ValueError("Action proposal is bound to a different Tool call")
    mark_change_execution_finished(db, proposal, failed=error is not None)
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
