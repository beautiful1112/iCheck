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
    GovernedChangePlan,
    Investigation,
    InvestigationCheckpoint,
    InvestigationEvidence,
    InvestigationToolCall,
    ServiceReportInstance,
    utcnow,
)
from ..schema_validation import validate_instance, validate_schema
from .audit import record_audit_event
from .agent_authorization import require_tool_permissions
from .agent_execution import enqueue_agent_execution
from .agent_profiles import (
    agent_profile_snapshot,
    resolve_investigation_agent_profile,
)
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
    *,
    commit: bool = True,
) -> AgentToolRegistration:
    if payload.transport == "managed_mcp":
        raise ValueError("Managed MCP tools must be installed from reviewed Studio packages")
    from .agent_authorization import assert_reviewed_situation_tool_contract
    assert_reviewed_situation_tool_contract(payload)
    validate_schema(payload.input_schema, "tool input_schema")
    validate_schema(payload.output_schema, "tool output_schema")
    assert_no_inline_secrets(payload.input_schema, "input_schema")
    assert_no_inline_secrets(payload.output_schema, "output_schema")
    if payload.change_contract is not None:
        assert_no_inline_secrets(
            payload.change_contract.model_dump(mode="json"),
            "change_contract",
        )
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
        if commit:
            db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Agent tool name already exists") from exc
    if commit:
        db.refresh(tool)
    return tool


def create_investigation(
    db: Session,
    payload: InvestigationCreate,
    *,
    actor: PrincipalContext | None = None,
    commit: bool = True,
) -> Investigation:
    from .ai_catalog_mutex import catalog_lock
    catalog_lock(db)
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
    profile = resolve_investigation_agent_profile(
        db,
        reference=payload.agent_profile,
        route=route,
    )
    profile_snapshot = agent_profile_snapshot(profile) if profile else {}
    authorization = actor or development_principal()
    created_by = (
        payload.created_by
        if actor is None or authorization.auth_method == "disabled"
        else authorization.subject
    )
    situation = None
    if payload.situation_id is not None:
        from ..models import Situation

        situation = db.get(Situation, payload.situation_id)
        if situation is None:
            raise LookupError("Situation not found")
    investigation = Investigation(
        title=payload.title,
        objective=payload.objective,
        execution_mode=payload.execution_mode,
        scope=payload.scope,
        status="pending",
        route_id=route.id,
        model_id=model.id,
        fallback_model_ids=list(route.fallback_model_ids),
        agent_profile_id=profile.id if profile else None,
        agent_profile_snapshot=profile_snapshot,
        max_iterations=min(
            route.max_iterations,
            profile.max_iterations if profile else route.max_iterations,
        ),
        max_tool_calls=min(
            route.max_tool_calls,
            profile.max_tool_calls if profile else route.max_tool_calls,
        ),
        timeout_seconds=min(
            route.timeout_seconds,
            profile.timeout_seconds if profile else route.timeout_seconds,
        ),
        token_budget=min(
            route.token_budget,
            profile.token_budget if profile else route.token_budget,
        ),
        situation_id=payload.situation_id,
        requested_by_principal_id=authorization.principal_id,
        permission_snapshot=sorted(authorization.permissions),
        authorization_scope=dict(authorization.authorization_scope),
        created_by=created_by,
    )
    db.add(investigation)
    db.flush()
    if situation is not None:
        from .situations import record_situation_investigation

        record_situation_investigation(
            db,
            situation,
            investigation,
            actor=created_by,
        )
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
            "agent_profile_id": profile.id if profile else None,
            "agent_profile_revision": profile.revision if profile else None,
            "requested_by_principal_id": authorization.principal_id,
            "permission_snapshot": sorted(authorization.permissions),
            "authorization_scope": authorization.authorization_scope,
            "budgets": {
                "max_iterations": investigation.max_iterations,
                "max_tool_calls": investigation.max_tool_calls,
                "timeout_seconds": investigation.timeout_seconds,
                "token_budget": investigation.token_budget,
            },
        },
    )
    if commit:
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
    commit: bool = True,
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
    if commit:
        db.commit()
        db.refresh(investigation)
        db.refresh(checkpoint)
    else:
        db.flush()
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
    *,
    allow_waiting_approval: bool = False,
) -> None:
    if investigation.status != "running" and not (
        allow_waiting_approval and investigation.status == "waiting_approval"
    ):
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
    if payload.state.status == "completed":
        from .conversational_onboarding import explicit_input, retained_receipt
        enrollment = explicit_input(investigation.objective)
        if enrollment is not None and not investigation.workflow_snapshot and not investigation.skill_artifact_version_id:
            receipt = retained_receipt(db, investigation, enrollment)
            if receipt is None or payload.state.structured_output is None or payload.state.structured_output.get("device_ids") != receipt.device_ids:
                raise ValueError("Cannot mark enrollment completed without its durable device inventory receipt")
    if payload.state.iteration < investigation.iterations_used:
        raise ValueError("Checkpoint iteration cannot move backwards")
    from .situation_hypotheses import (
        sync_situation_hypotheses,
        validate_hypothesis_evidence,
    )
    from .situation_assessments import sync_situation_impact_assessment
    from .situation_reconciliation import (
        sync_situation_integration_remote_reference,
    )
    from .indicator_artifacts import sync_workflow_indicator_publications
    from .topology_proposals import sync_investigation_topology_proposal
    from .visualization_proposals import (
        sync_investigation_visualization_proposal,
    )
    from .report_delivery_receipts import sync_report_delivery_receipt
    from .workflow_execution_evidence import validate_workflow_execution_evidence

    validate_workflow_execution_evidence(db, investigation, payload)

    hypothesis_evidence = validate_hypothesis_evidence(
        db,
        investigation,
        payload.state,
    )

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
        investigation.structured_output = payload.state.structured_output
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
    sync_situation_hypotheses(
        db,
        investigation,
        checkpoint,
        payload.state,
        actor=payload.actor,
        evidence_by_id=hypothesis_evidence,
    )
    sync_situation_impact_assessment(
        db,
        investigation,
        checkpoint,
        payload.state,
        actor=payload.actor,
    )
    sync_investigation_topology_proposal(
        db,
        investigation,
        checkpoint,
        payload.state,
        actor=payload.actor,
    )
    sync_investigation_visualization_proposal(
        db,
        investigation,
        checkpoint,
        payload.state,
        actor=payload.actor,
    )
    sync_situation_integration_remote_reference(
        db,
        investigation,
        actor=payload.actor,
    )
    sync_report_delivery_receipt(
        db,
        investigation,
        checkpoint=checkpoint,
        actor=payload.actor,
    )
    sync_workflow_indicator_publications(db, investigation)
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
    report_instance = None
    if payload.evidence_type == "service_report_instance":
        report_instance = db.get(ServiceReportInstance, payload.evidence_id)
        if (
            report_instance is None
            or report_instance.tenant_id != investigation.tenant_id
            or report_instance.region_id != investigation.region_id
        ):
            raise LookupError("Saved report evidence is not available in this namespace")
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
        report_instance_id=report_instance.id if report_instance is not None else None,
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
    governed_change_plan: GovernedChangePlan | None = None,
    governed_stage: str | None = None,
    reviewed_situation_closure: bool = False,
    reviewed_source_replacement: bool = False,
    explicit_device_enrollment: bool = False,
) -> InvestigationToolCall:
    if (governed_change_plan is None) != (governed_stage is None):
        raise ValueError("Governed change plan and stage must be provided together")
    allow_waiting_approval = False
    if governed_change_plan is not None and governed_stage is not None:
        if governed_stage not in {"precheck", "dry_run", "postcheck", "rollback_check"}:
            raise ValueError("Unknown governed read-only stage")
        persisted_plan = db.get(GovernedChangePlan, governed_change_plan.id)
        if (
            persisted_plan is None
            or persisted_plan.investigation_id != investigation.id
            or persisted_plan.status not in (
                {"awaiting_rollback_check"} if governed_stage == "rollback_check"
                else {"awaiting_postcheck"} if governed_stage == "postcheck"
                else {"awaiting_evidence", "ready_for_approval"}
            )
        ):
            raise ValueError("Governed change plan is not awaiting approval evidence")
        proposal = db.get(AgentActionProposal, persisted_plan.action_proposal_id)
        stage_proposal = proposal
        if governed_stage == "rollback_check":
            from .change_verification import rollback_for_plan
            stage_proposal, _ = rollback_for_plan(db, persisted_plan, now=utcnow())
        if (
            proposal is None
            or proposal.status not in (
                {"succeeded", "failed"} if governed_stage == "rollback_check"
                else {"succeeded"} if governed_stage == "postcheck" else {"pending"})
            or proposal.investigation_id != investigation.id
            or stage_proposal is None or payload.iteration != stage_proposal.iteration
        ):
            raise ValueError("Governed change proposal is not pending for this call")
        from .change_governance import (
            assert_change_stage_tool_current,
            change_stage_arguments,
        )

        stage_snapshot = persisted_plan.tool_contract_snapshot.get(
            "steps", {}
        ).get(governed_stage)
        if not isinstance(stage_snapshot, dict):
            raise ValueError("Governed change stage is absent from the frozen plan")
        stage_tool = assert_change_stage_tool_current(
            db,
            persisted_plan,
            governed_stage,
        )
        if (
            not stage_tool.read_only
            or payload.tool_id != stage_tool.id
            or payload.arguments
            != change_stage_arguments(persisted_plan, governed_stage)
        ):
            raise ValueError("Tool call does not match the frozen change stage")
        from .change_verification import stage_not_before
        stage_not_before(db, persisted_plan, governed_stage, now=utcnow())
        allow_waiting_approval = governed_stage not in {"postcheck", "rollback_check"}
    _ensure_running_budget(
        db,
        investigation,
        allow_waiting_approval=allow_waiting_approval,
    )
    if payload.iteration < 1 or payload.iteration > investigation.max_iterations:
        _escalate(db, investigation, "Iteration budget exhausted")
        db.commit()
        raise ValueError("Tool call exceeds the iteration budget")
    tool = db.get(AgentToolRegistration, payload.tool_id)
    if tool is None:
        raise LookupError("Agent tool not found")
    if (tool.tenant_id, tool.region_id) != (investigation.tenant_id, investigation.region_id):
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
    if reviewed_situation_closure and reviewed_source_replacement:
        raise PermissionError("An owned Tool journal cannot mix control-plane protocols")
    if reviewed_source_replacement:
        from .agent_authorization import assert_source_replacement_tool_contract, OWNED_SOURCE_REPLACEMENT_HANDLERS
        assert_source_replacement_tool_contract(tool)
        if tool.handler not in OWNED_SOURCE_REPLACEMENT_HANDLERS or approved_proposal is not None or governed_change_plan is not None:
            raise PermissionError("Only the owned source replacement runtime may journal this control-plane call")
    if explicit_device_enrollment:
        from .conversational_onboarding import authorized_input, TOOL
        if tool.handler != TOOL or approved_proposal is not None or governed_change_plan is not None:
            raise PermissionError("Only the owned enrollment runtime may journal this call")
        authorized_input(investigation, payload.arguments, db=db)
    owned_control_plane = reviewed_situation_closure or reviewed_source_replacement or explicit_device_enrollment
    if reviewed_situation_closure:
        from .agent_authorization import assert_reviewed_situation_tool_contract
        assert_reviewed_situation_tool_contract(tool)
        if tool.handler != "situations.close_reviewed" or approved_proposal is not None or governed_change_plan is not None:
            raise PermissionError("Only the owned reviewed-closure runtime may journal this control-plane call")
    if not tool.read_only and approved_proposal is None and not owned_control_plane:
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
    if not tool.read_only and not owned_control_plane and (
        approved_proposal is None
        or approved_proposal.status != "executing"
        or approved_proposal.investigation_id != investigation.id
        or approved_proposal.tool_id != tool.id
        or approved_proposal.arguments != payload.arguments
    ):
        raise ValueError("Approved action does not match this exact tool call")
    if approved_proposal is not None and approved_proposal.tool_call_id is not None:
        raise ValueError("Approved action already has a bound Tool call")
    assert_no_inline_secrets(payload.arguments, "tool arguments")
    validate_instance(payload.arguments, tool.input_schema, "tool arguments")
    call_material = {"tool_id": tool.id, "arguments": payload.arguments}
    if governed_change_plan is not None:
        call_material.update(governed_change_plan_id=governed_change_plan.id, governed_stage=governed_stage)
    call_hash = _canonical_hash(call_material)
    duplicate = db.scalar(
        select(InvestigationToolCall).where(
            InvestigationToolCall.investigation_id == investigation.id,
            InvestigationToolCall.call_hash == call_hash,
        )
    )
    if duplicate is not None:
        raise ValueError("Duplicate tool call blocked for this investigation")
    now = utcnow()
    from .tool_provenance import tool_artifact_provenance

    call = InvestigationToolCall(
        investigation_id=investigation.id,
        tool_id=tool.id,
        iteration=payload.iteration,
        call_hash=call_hash,
        arguments=payload.arguments,
        status="running",
        started_at=now,
        governed_change_plan_id=governed_change_plan.id if governed_change_plan else None,
        governed_stage=governed_stage,
        **tool_artifact_provenance(db, tool),
    )
    db.add(call)
    investigation.tool_calls_used += 1
    investigation.iterations_used = max(
        investigation.iterations_used,
        payload.iteration,
    )
    investigation.updated_at = now
    db.flush()
    if approved_proposal is not None:
        # The exact external attempt must remain discoverable even if its
        # result never arrives. Terminal completion updates status, not identity.
        approved_proposal.tool_call_id = call.id
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
    *,
    evidence_ids: list[str] | None = None,
    owned_source_replacement: bool = False,
    owned_situation_closure: bool = False,
    owned_device_enrollment: bool = False,
) -> InvestigationToolCall:
    if call.status != "running":
        raise ValueError("Tool call is no longer running")
    tool = db.get(AgentToolRegistration, call.tool_id)
    if tool is None:
        raise LookupError("Agent tool not found")
    if tool.handler == "inventory.enroll_devices":
        if not owned_device_enrollment or owned_source_replacement or owned_situation_closure:
            raise PermissionError("Device enrollment Tool completion belongs to its owned runtime")
        from .conversational_onboarding import authorized_input, retained_receipt, enrollment_result
        investigation = db.get(Investigation, call.investigation_id)
        request = authorized_input(investigation, call.arguments, db=db)
        if payload.status == "succeeded":
            receipt = retained_receipt(db, investigation, request)
            if receipt is None:
                raise PermissionError("Enrollment success requires a committed device receipt")
            result = enrollment_result(db, investigation, request, receipt)
            if payload.result.get("device_ids") != result["device_ids"] or payload.result.get("contract") != result["contract"]:
                raise PermissionError("Enrollment result does not match its durable inventory receipt")
    elif owned_device_enrollment:
        raise PermissionError("Only the enrollment handler may use its owned completion")
    if owned_source_replacement and owned_situation_closure:
        raise PermissionError("A Tool completion cannot mix owned domain runtimes")
    from .situation_closure_runtime import owned_closure_request_id, assert_owned_closure_completion
    if owned_situation_closure:
        assert_owned_closure_completion(db, call, payload, evidence_ids)
    elif tool.handler == "situations.close_reviewed" or owned_closure_request_id(db, call) is not None:
        raise PermissionError("Situation closure Tool completion belongs to its owned runtime")
    from .agent_authorization import OWNED_SOURCE_REPLACEMENT_HANDLERS
    if not owned_source_replacement:
        from .source_replacement_runtime import replacement_call_records
        if tool.handler in OWNED_SOURCE_REPLACEMENT_HANDLERS or any(replacement_call_records(db, call)):
            raise PermissionError("Source replacement Tool completion belongs to its owned runtime")
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
    if evidence_ids is not None:
        from .tool_evidence_bindings import bind_tool_evidence
        # Terminal result, exact citation receipt and audit commit atomically.
        try:
            db.flush()
            bind_tool_evidence(db, call, evidence_ids)
        except Exception:
            db.rollback()
            db.refresh(call)
            raise
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
