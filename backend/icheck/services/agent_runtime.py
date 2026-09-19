from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..agent_schemas import (
    AgentToolCreate,
    InvestigationCheckpointCreate,
    InvestigationCreate,
    InvestigationEvidenceCreate,
    InvestigationState,
    InvestigationToolCallComplete,
    InvestigationToolCallCreate,
)
from ..models import (
    AIModelConfig,
    AIModelRoute,
    AgentActionProposal,
    AgentToolRegistration,
    Investigation,
    InvestigationCheckpoint,
    InvestigationEvidence,
    InvestigationToolCall,
    utcnow,
)
from ..schema_validation import validate_instance, validate_schema
from .audit import record_audit_event
from .agent_authorization import require_tool_permissions
from .agent_execution import enqueue_agent_execution
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext, development_principal


TERMINAL_INVESTIGATION_STATUSES = {
    "completed",
    "escalated",
    "failed",
    "cancelled",
}


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def create_agent_tool(
    db: Session,
    payload: AgentToolCreate,
) -> AgentToolRegistration:
    validate_schema(payload.input_schema, "tool input_schema")
    validate_schema(payload.output_schema, "tool output_schema")
    assert_no_inline_secrets(payload.input_schema, "input_schema")
    assert_no_inline_secrets(payload.output_schema, "output_schema")
    tool = AgentToolRegistration(**payload.model_dump())
    db.add(tool)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="agent.tool.registered",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="agent_tool",
            entity_id=tool.id,
            details={
                "name": tool.name,
                "transport": tool.transport,
                "risk_level": tool.risk_level,
                "read_only": tool.read_only,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Agent tool name already exists") from exc
    db.refresh(tool)
    return tool


def create_investigation(
    db: Session,
    payload: InvestigationCreate,
    *,
    actor: PrincipalContext | None = None,
) -> Investigation:
    assert_no_inline_secrets(payload.scope, "investigation.scope")
    route = db.scalar(
        select(AIModelRoute).where(AIModelRoute.purpose == payload.route_purpose)
    )
    if route is None:
        raise LookupError(f"AI model route {payload.route_purpose!r} not found")
    if not route.enabled:
        raise ValueError("AI model route is disabled")
    model = db.get(AIModelConfig, route.primary_model_id)
    if model is None or not model.enabled:
        raise ValueError("Primary AI model is unavailable")
    authorization = actor or development_principal()
    created_by = (
        payload.created_by
        if actor is None or authorization.auth_method == "disabled"
        else authorization.subject
    )
    investigation = Investigation(
        title=payload.title,
        objective=payload.objective,
        scope=payload.scope,
        status="pending",
        route_id=route.id,
        model_id=model.id,
        fallback_model_ids=list(route.fallback_model_ids),
        max_iterations=route.max_iterations,
        max_tool_calls=route.max_tool_calls,
        timeout_seconds=route.timeout_seconds,
        token_budget=route.token_budget,
        requested_by_principal_id=authorization.principal_id,
        permission_snapshot=sorted(authorization.permissions),
        authorization_scope=dict(authorization.authorization_scope),
        created_by=created_by,
    )
    db.add(investigation)
    db.flush()
    record_audit_event(
        db,
        event_type="investigation.created",
        actor_type="user",
        actor_id=created_by,
        entity_type="investigation",
        entity_id=investigation.id,
        details={
            "route_id": route.id,
            "model_id": model.id,
            "requested_by_principal_id": authorization.principal_id,
            "permission_snapshot": sorted(authorization.permissions),
            "authorization_scope": authorization.authorization_scope,
            "budgets": {
                "max_iterations": route.max_iterations,
                "max_tool_calls": route.max_tool_calls,
                "timeout_seconds": route.timeout_seconds,
                "token_budget": route.token_budget,
            },
        },
    )
    db.commit()
    db.refresh(investigation)
    return investigation


def _next_checkpoint_sequence(db: Session, investigation_id: str) -> int:
    current = db.scalar(
        select(func.max(InvestigationCheckpoint.sequence)).where(
            InvestigationCheckpoint.investigation_id == investigation_id
        )
    )
    return int(current or 0) + 1


def _persist_checkpoint(
    db: Session,
    investigation: Investigation,
    *,
    node: str,
    state: InvestigationState,
    actor: str,
) -> InvestigationCheckpoint:
    document = state.model_dump(mode="json")
    checkpoint = InvestigationCheckpoint(
        investigation_id=investigation.id,
        sequence=_next_checkpoint_sequence(db, investigation.id),
        node=node,
        state=document,
        state_hash=_canonical_hash(document),
        created_by=actor,
    )
    db.add(checkpoint)
    db.flush()
    return checkpoint


def start_investigation(
    db: Session,
    investigation: Investigation,
    *,
    actor: str,
) -> tuple[Investigation, InvestigationCheckpoint]:
    if investigation.status != "pending":
        raise ValueError("Only pending investigations can be started")
    now = utcnow()
    investigation.status = "running"
    investigation.started_at = now
    investigation.updated_at = now
    state = InvestigationState(
        investigation_id=investigation.id,
        objective=investigation.objective,
        scope=investigation.scope,
        status="running",
    )
    checkpoint = _persist_checkpoint(
        db,
        investigation,
        node="start",
        state=state,
        actor=actor,
    )
    execution = enqueue_agent_execution(
        db,
        investigation,
        actor=actor,
        commit=False,
    )
    record_audit_event(
        db,
        event_type="investigation.started",
        actor_type="user",
        actor_id=actor,
        entity_type="investigation",
        entity_id=investigation.id,
        details={
            "checkpoint_id": checkpoint.id,
            "execution_id": execution.id,
        },
    )
    db.commit()
    db.refresh(investigation)
    db.refresh(checkpoint)
    return investigation, checkpoint


def _escalate(
    db: Session,
    investigation: Investigation,
    reason: str,
) -> None:
    if investigation.status == "escalated":
        return
    investigation.status = "escalated"
    investigation.escalation_reason = reason
    investigation.finished_at = utcnow()
    investigation.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="investigation.escalated",
        actor_type="system",
        actor_id="agent.policy",
        entity_type="investigation",
        entity_id=investigation.id,
        details={"reason": reason},
    )


def _ensure_running_budget(
    db: Session,
    investigation: Investigation,
) -> None:
    if investigation.status != "running":
        raise ValueError("Investigation is not running")
    if investigation.started_at is None:
        raise ValueError("Investigation has no start time")
    deadline = _as_utc(investigation.started_at) + timedelta(
        seconds=investigation.timeout_seconds
    )
    if utcnow() > deadline:
        _escalate(db, investigation, "Wall-clock budget exhausted")
        db.commit()
        raise ValueError("Investigation wall-clock budget exhausted")
    if investigation.iterations_used >= investigation.max_iterations:
        _escalate(db, investigation, "Iteration budget exhausted")
        db.commit()
        raise ValueError("Investigation iteration budget exhausted")
    if investigation.tool_calls_used >= investigation.max_tool_calls:
        _escalate(db, investigation, "Tool-call budget exhausted")
        db.commit()
        raise ValueError("Investigation tool-call budget exhausted")
    if investigation.tokens_used >= investigation.token_budget:
        _escalate(db, investigation, "Token budget exhausted")
        db.commit()
        raise ValueError("Investigation token budget exhausted")


def append_investigation_checkpoint(
    db: Session,
    investigation: Investigation,
    payload: InvestigationCheckpointCreate,
) -> InvestigationCheckpoint:
    if investigation.status != "running":
        raise ValueError("Only running investigations accept checkpoints")
    if payload.state.investigation_id != investigation.id:
        raise ValueError("Checkpoint state belongs to another investigation")
    if payload.state.objective != investigation.objective:
        raise ValueError("Checkpoint objective is immutable")
    if payload.state.scope != investigation.scope:
        raise ValueError("Checkpoint scope is immutable")
    if payload.state.iteration < investigation.iterations_used:
        raise ValueError("Checkpoint iteration cannot move backwards")

    investigation.iterations_used = payload.state.iteration
    investigation.tokens_used += payload.token_usage
    budget_reason: str | None = None
    if investigation.iterations_used > investigation.max_iterations:
        budget_reason = "Iteration budget exhausted"
    elif investigation.tokens_used > investigation.token_budget:
        budget_reason = "Token budget exhausted"
    elif investigation.started_at and utcnow() > (
        _as_utc(investigation.started_at)
        + timedelta(seconds=investigation.timeout_seconds)
    ):
        budget_reason = "Wall-clock budget exhausted"
    if budget_reason:
        _escalate(db, investigation, budget_reason)
        payload.state.status = "escalated"
        payload.state.escalation_reason = budget_reason
    else:
        investigation.status = payload.state.status
        investigation.confidence = payload.state.confidence
        investigation.conclusion = payload.state.conclusion
        investigation.uncertainty = payload.state.uncertainty
        investigation.escalation_reason = payload.state.escalation_reason
        if payload.state.status in TERMINAL_INVESTIGATION_STATUSES:
            investigation.finished_at = utcnow()
    investigation.updated_at = utcnow()
    checkpoint = _persist_checkpoint(
        db,
        investigation,
        node=payload.node,
        state=payload.state,
        actor=payload.actor,
    )
    record_audit_event(
        db,
        event_type="investigation.checkpoint.saved",
        actor_type="agent",
        actor_id=payload.actor,
        entity_type="investigation",
        entity_id=investigation.id,
        details={
            "checkpoint_id": checkpoint.id,
            "sequence": checkpoint.sequence,
            "node": checkpoint.node,
            "state_hash": checkpoint.state_hash,
        },
    )
    db.commit()
    db.refresh(checkpoint)
    return checkpoint


def add_evidence_reference(
    db: Session,
    investigation: Investigation,
    payload: InvestigationEvidenceCreate,
) -> InvestigationEvidence:
    existing = db.scalar(
        select(InvestigationEvidence).where(
            InvestigationEvidence.investigation_id == investigation.id,
            InvestigationEvidence.evidence_type == payload.evidence_type,
            InvestigationEvidence.evidence_id == payload.evidence_id,
        )
    )
    if existing is not None:
        return existing
    evidence = InvestigationEvidence(
        investigation_id=investigation.id,
        **payload.model_dump(),
    )
    db.add(evidence)
    db.flush()
    record_audit_event(
        db,
        event_type="investigation.evidence.linked",
        actor_type="agent",
        actor_id="agent.runtime",
        entity_type="investigation",
        entity_id=investigation.id,
        details={
            "evidence_type": evidence.evidence_type,
            "evidence_id": evidence.evidence_id,
        },
    )
    db.commit()
    db.refresh(evidence)
    return evidence


def create_tool_call(
    db: Session,
    investigation: Investigation,
    payload: InvestigationToolCallCreate,
    *,
    approved_proposal: AgentActionProposal | None = None,
) -> InvestigationToolCall:
    _ensure_running_budget(db, investigation)
    if payload.iteration < 1 or payload.iteration > investigation.max_iterations:
        _escalate(db, investigation, "Iteration budget exhausted")
        db.commit()
        raise ValueError("Tool call exceeds the iteration budget")
    tool = db.get(AgentToolRegistration, payload.tool_id)
    if tool is None:
        raise LookupError("Agent tool not found")
    if not tool.enabled:
        raise ValueError("Agent tool is disabled")
    try:
        require_tool_permissions(investigation, tool)
    except PermissionError:
        record_audit_event(
            db,
            event_type="investigation.tool.permission_denied",
            actor_type="agent",
            actor_id="agent.runtime",
            entity_type="investigation",
            entity_id=investigation.id,
            outcome="denied",
            details={
                "tool_id": tool.id,
                "required_permissions": tool.required_permissions,
            },
        )
        db.commit()
        raise
    if not tool.read_only and approved_proposal is None:
        investigation.status = "waiting_approval"
        investigation.updated_at = utcnow()
        record_audit_event(
            db,
            event_type="investigation.tool.approval_required",
            actor_type="agent",
            actor_id="agent.runtime",
            entity_type="investigation",
            entity_id=investigation.id,
            details={"tool_id": tool.id, "risk_level": tool.risk_level},
        )
        db.commit()
        raise ValueError("State-changing tools require the governed action engine")
    if not tool.read_only and (
        approved_proposal is None
        or approved_proposal.status != "executing"
        or approved_proposal.investigation_id != investigation.id
        or approved_proposal.tool_id != tool.id
        or approved_proposal.arguments != payload.arguments
    ):
        raise ValueError("Approved action does not match this exact tool call")
    assert_no_inline_secrets(payload.arguments, "tool arguments")
    validate_instance(payload.arguments, tool.input_schema, "tool arguments")
    call_hash = _canonical_hash(
        {"tool_id": tool.id, "arguments": payload.arguments}
    )
    duplicate = db.scalar(
        select(InvestigationToolCall).where(
            InvestigationToolCall.investigation_id == investigation.id,
            InvestigationToolCall.call_hash == call_hash,
        )
    )
    if duplicate is not None:
        raise ValueError("Duplicate tool call blocked for this investigation")
    now = utcnow()
    call = InvestigationToolCall(
        investigation_id=investigation.id,
        tool_id=tool.id,
        iteration=payload.iteration,
        call_hash=call_hash,
        arguments=payload.arguments,
        status="running",
        started_at=now,
    )
    db.add(call)
    investigation.tool_calls_used += 1
    investigation.iterations_used = max(
        investigation.iterations_used,
        payload.iteration,
    )
    investigation.updated_at = now
    db.flush()
    record_audit_event(
        db,
        event_type="investigation.tool.started",
        actor_type="agent",
        actor_id="agent.runtime",
        entity_type="investigation_tool_call",
        entity_id=call.id,
        details={
            "investigation_id": investigation.id,
            "tool_id": tool.id,
            "call_hash": call_hash,
            "iteration": payload.iteration,
        },
    )
    db.commit()
    db.refresh(call)
    return call


def complete_tool_call(
    db: Session,
    call: InvestigationToolCall,
    payload: InvestigationToolCallComplete,
) -> InvestigationToolCall:
    if call.status != "running":
        raise ValueError("Tool call is no longer running")
    tool = db.get(AgentToolRegistration, call.tool_id)
    if tool is None:
        raise LookupError("Agent tool not found")
    result_hash: str | None = None
    if payload.status == "succeeded":
        assert_no_inline_secrets(payload.result, "tool result")
        validate_instance(payload.result, tool.output_schema, "tool result")
        encoded = json.dumps(
            payload.result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        if len(encoded) > tool.max_result_bytes:
            raise ValueError("Tool result exceeds max_result_bytes")
        result_hash = hashlib.sha256(encoded).hexdigest()
    now = utcnow()
    call.status = payload.status
    call.result = payload.result
    call.result_hash = result_hash
    call.error = payload.error
    call.finished_at = now
    record_audit_event(
        db,
        event_type="investigation.tool.completed",
        actor_type="agent",
        actor_id="agent.runtime",
        entity_type="investigation_tool_call",
        entity_id=call.id,
        outcome="success" if payload.status == "succeeded" else "failure",
        details={
            "investigation_id": call.investigation_id,
            "tool_id": tool.id,
            "status": payload.status,
            "result_hash": result_hash,
        },
    )
    db.commit()
    db.refresh(call)
    return call
