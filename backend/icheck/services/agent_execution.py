from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.orm import Session

from ..database import require_locking_transaction
from ..agent_schemas import (
    AgentExecutionAssignment,
    AgentExecutionCancel,
    AgentExecutionClaim,
    AgentExecutionComplete,
    AgentExecutionProgress,
    AgentWorkerHeartbeat,
    AgentWorkerRegister,
)
from ..models import (
    AIModelConfig,
    AIProviderConfig,
    AgentActionProposal,
    AgentExecution,
    AgentExecutionEvent,
    AgentExecutionStatus,
    AgentWorker,
    AgentWorkerState,
    Investigation,
    InvestigationCheckpoint,
    InvestigationEvidence,
    utcnow,
)
from ..worker_auth import hash_token, issue_worker_token
from ..worker_mtls import WorkerPeerIdentity
from .audit import record_audit_event
from .worker_mtls import apply_registration_identity
from .collectors import assert_no_inline_secrets


TERMINAL_EXECUTION_STATUSES = {
    AgentExecutionStatus.SUCCEEDED,
    AgentExecutionStatus.FAILED,
    AgentExecutionStatus.CANCELLED,
}

TERMINAL_INVESTIGATION_TO_EXECUTION = {
    "completed": AgentExecutionStatus.SUCCEEDED,
    "escalated": AgentExecutionStatus.FAILED,
    "failed": AgentExecutionStatus.FAILED,
    "cancelled": AgentExecutionStatus.CANCELLED,
    "waiting_approval": AgentExecutionStatus.WAITING_APPROVAL,
}


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _next_event_sequence(db: Session, execution_id: str) -> int:
    current = db.scalar(
        select(func.max(AgentExecutionEvent.sequence)).where(
            AgentExecutionEvent.execution_id == execution_id
        )
    )
    return int(current or 0) + 1


def append_execution_event(
    db: Session,
    execution: AgentExecution,
    *,
    event_type: str,
    payload: dict[str, object] | None = None,
) -> AgentExecutionEvent:
    document = payload or {}
    assert_no_inline_secrets(document, "agent execution event")
    event = AgentExecutionEvent(
        execution_id=execution.id,
        sequence=_next_event_sequence(db, execution.id),
        event_type=event_type,
        payload=document,
    )
    db.add(event)
    db.flush()
    return event


def enqueue_agent_execution(
    db: Session,
    investigation: Investigation,
    *,
    actor: str,
    commit: bool = True,
) -> AgentExecution:
    if investigation.status != "running":
        raise ValueError("Only running investigations can be queued")
    existing = db.scalar(
        select(AgentExecution).where(
            AgentExecution.investigation_id == investigation.id
        )
    )
    if existing is not None:
        raise ValueError("Investigation execution already exists")
    execution = AgentExecution(
        investigation_id=investigation.id,
        status=AgentExecutionStatus.QUEUED,
    )
    db.add(execution)
    db.flush()
    event = append_execution_event(
        db,
        execution,
        event_type="execution.queued",
        payload={"actor": actor},
    )
    record_audit_event(
        db,
        event_type="agent.execution.queued",
        actor_type="user",
        actor_id=actor,
        entity_type="agent_execution",
        entity_id=execution.id,
        details={
            "investigation_id": investigation.id,
            "event_sequence": event.sequence,
        },
    )
    if commit:
        db.commit()
        db.refresh(execution)
    return execution


def register_agent_worker(
    db: Session,
    payload: AgentWorkerRegister,
    *,
    peer_identity: WorkerPeerIdentity | None = None,
    mtls_mode: Literal["disabled", "optional", "required"] = "disabled",
) -> tuple[AgentWorker, str]:
    assert_no_inline_secrets(payload.labels, "agent worker labels")
    require_locking_transaction(db, purpose="Agent Worker registration")
    worker = db.scalar(
        select(AgentWorker).where(AgentWorker.name == payload.name)
        .with_for_update().execution_options(populate_existing=True)
    )
    now = utcnow()
    access_token, access_token_hash = issue_worker_token()
    rotated = worker is not None
    if worker is None:
        worker = AgentWorker(
            **payload.model_dump(),
            auth_token_hash=access_token_hash,
            token_issued_at=now,
            state=AgentWorkerState.ONLINE,
            last_heartbeat_at=now,
        )
        db.add(worker)
        db.flush()
        apply_registration_identity(
            db,
            worker,
            peer_identity,
            kind="agent",
            mode=mtls_mode,
        )
    else:
        apply_registration_identity(
            db,
            worker,
            peer_identity,
            kind="agent",
            mode=mtls_mode,
        )
        worker.capabilities = payload.capabilities
        worker.labels = payload.labels
        worker.auth_token_hash = access_token_hash
        worker.token_issued_at = now
        if worker.state != AgentWorkerState.DRAINING:
            worker.state = AgentWorkerState.ONLINE
        worker.last_heartbeat_at = now
        worker.updated_at = now
    db.flush()
    record_audit_event(
        db,
        event_type="agent.worker.registered",
        actor_type="worker",
        actor_id=worker.name,
        entity_type="agent_worker",
        entity_id=worker.id,
        details={
            "token_rotated": rotated,
            "capabilities": worker.capabilities,
            "mtls_bound": worker.mtls_fingerprint_sha256 is not None,
            "mtls_revision": worker.mtls_revision,
        },
    )
    db.commit()
    db.refresh(worker)
    return worker, access_token


def heartbeat_agent_worker(
    db: Session,
    worker: AgentWorker,
    payload: AgentWorkerHeartbeat,
) -> AgentWorker:
    from .worker_registry import lock_worker_registry
    worker = lock_worker_registry(db, worker)
    requested_state = AgentWorkerState(payload.state)
    if not (
        worker.state == AgentWorkerState.DRAINING
        and requested_state == AgentWorkerState.ONLINE
    ):
        worker.state = requested_state
    if payload.capabilities is not None:
        normalized = [item.strip() for item in payload.capabilities if item.strip()]
        if not normalized:
            raise ValueError("at least one capability is required")
        worker.capabilities = list(dict.fromkeys(normalized))
    if payload.labels is not None:
        assert_no_inline_secrets(payload.labels, "agent worker labels")
        worker.labels = payload.labels
    worker.last_heartbeat_at = utcnow()
    worker.updated_at = utcnow()
    db.commit()
    db.refresh(worker)
    return worker


def _resume_required(db: Session, investigation: Investigation) -> bool:
    if any(
        (
            investigation.iterations_used,
            investigation.tool_calls_used,
            investigation.tokens_used,
        )
    ):
        return True
    proposals = db.scalar(
        select(func.count())
        .select_from(AgentActionProposal)
        .where(AgentActionProposal.investigation_id == investigation.id)
    )
    if int(proposals or 0) > 0:
        return True
    checkpoints = db.scalar(
        select(func.count())
        .select_from(InvestigationCheckpoint)
        .where(
            InvestigationCheckpoint.investigation_id == investigation.id
        )
    )
    return int(checkpoints or 0) > 1


def reconcile_agent_executions(
    db: Session,
    *,
    now: datetime | None = None,
) -> int:
    """Repair executions left behind between a terminal graph commit and ack."""

    reconciled = 0
    checked_at = now or utcnow()
    require_locking_transaction(db, purpose="Agent execution reconciliation")
    rows = list(
        db.execute(
            select(AgentExecution, Investigation)
            .join(
                Investigation,
                Investigation.id == AgentExecution.investigation_id,
            )
            .where(
                AgentExecution.status == AgentExecutionStatus.RUNNING,
                or_(
                    Investigation.status.in_(TERMINAL_INVESTIGATION_TO_EXECUTION),
                    and_(
                        AgentExecution.cancellation_requested_at.is_not(None),
                        AgentExecution.lease_expires_at.is_not(None),
                        AgentExecution.lease_expires_at < checked_at,
                    ),
                ),
            )
            .with_for_update(of=AgentExecution, skip_locked=True)
            .execution_options(populate_existing=True)
        ).all()
    )
    for execution, investigation in rows:
        target = TERMINAL_INVESTIGATION_TO_EXECUTION.get(investigation.status)
        reason = "terminal_investigation"
        if (
            execution.cancellation_requested_at is not None
            and (
                target is not None
                or (
                    execution.lease_expires_at is not None
                    and _as_utc(execution.lease_expires_at) < checked_at
                )
            )
        ):
            target = AgentExecutionStatus.CANCELLED
            reason = (
                "cancelled_after_terminal_commit"
                if investigation.status in TERMINAL_INVESTIGATION_TO_EXECUTION
                else "cancelled_after_lease_expiry"
            )
            investigation.status = "cancelled"
            investigation.finished_at = checked_at
            investigation.updated_at = checked_at
        if target is None:
            continue
        previous_worker_id = execution.worker_id
        execution.status = target
        execution.worker_id = None
        execution.lease_token_hash = None
        execution.lease_expires_at = None
        execution.finished_at = (
            None if target == AgentExecutionStatus.WAITING_APPROVAL else checked_at
        )
        execution.error = (
            "Investigation ended without a worker completion acknowledgement"
            if target == AgentExecutionStatus.FAILED
            else None
        )
        execution.updated_at = checked_at
        event = append_execution_event(
            db,
            execution,
            event_type="execution.reconciled",
            payload={
                "status": target.value,
                "reason": reason,
                "previous_worker_id": previous_worker_id,
            },
        )
        record_audit_event(
            db,
            event_type="agent.execution.reconciled",
            actor_type="system",
            actor_id="agent.scheduler",
            entity_type="agent_execution",
            entity_id=execution.id,
            outcome=(
                "success"
                if target == AgentExecutionStatus.SUCCEEDED
                else "failure"
            ),
            details={
                "investigation_id": investigation.id,
                "status": target.value,
                "reason": reason,
                "event_sequence": event.sequence,
            },
        )
        reconciled += 1
    return reconciled


def claim_agent_executions(
    db: Session,
    worker: AgentWorker,
    payload: AgentExecutionClaim,
) -> list[AgentExecutionAssignment]:
    from .worker_registry import lock_worker_registry
    worker = lock_worker_registry(db, worker)
    if worker.state != AgentWorkerState.ONLINE:
        raise ValueError("Only online agent workers can claim executions")
    now = utcnow()
    reconcile_agent_executions(db, now=now)
    lease_expires_at = now + timedelta(seconds=payload.lease_seconds)
    eligible = or_(
        AgentExecution.status == AgentExecutionStatus.QUEUED,
        and_(
            AgentExecution.status == AgentExecutionStatus.RUNNING,
            AgentExecution.lease_expires_at.is_not(None),
            AgentExecution.lease_expires_at < now,
        ),
    )
    candidates = list(
        db.execute(
            select(AgentExecution, Investigation)
            .join(
                Investigation,
                Investigation.id == AgentExecution.investigation_id,
            )
            .join(AIModelConfig, AIModelConfig.id == Investigation.model_id)
            .join(
                AIProviderConfig,
                AIProviderConfig.id == AIModelConfig.provider_id,
            )
            .where(
                eligible,
                AgentExecution.cancellation_requested_at.is_(None),
                Investigation.status == "running",
                AIProviderConfig.provider_type.in_(worker.capabilities),
            )
            .order_by(AgentExecution.created_at, AgentExecution.id)
            .limit(payload.max_assignments * 4)
        ).all()
    )

    assignments: list[AgentExecutionAssignment] = []
    alert_status_cache = {}
    for candidate, investigation in candidates:
        if len(assignments) >= payload.max_assignments:
            break
        from .alert_investigation_control import enforce_stop
        if enforce_stop(db, candidate, cache=alert_status_cache):
            continue
        previous_worker_id = candidate.worker_id
        token = secrets.token_urlsafe(32)
        token_hash = hash_token(token)
        attempt = candidate.attempt_count + 1
        claimed = db.execute(
            update(AgentExecution)
            .execution_options(synchronize_session=False)
            .where(
                AgentExecution.id == candidate.id,
                eligible,
                AgentExecution.cancellation_requested_at.is_(None),
            )
            .values(
                status=AgentExecutionStatus.RUNNING,
                worker_id=worker.id,
                lease_token_hash=token_hash,
                lease_expires_at=lease_expires_at,
                attempt_count=attempt,
                started_at=candidate.started_at or now,
                last_heartbeat_at=now,
                updated_at=now,
            )
        )
        if claimed.rowcount != 1:
            continue
        db.expire(candidate)
        event = append_execution_event(
            db,
            candidate,
            event_type=(
                "execution.reassigned"
                if previous_worker_id is not None
                else "execution.claimed"
            ),
            payload={
                "worker_id": worker.id,
                "previous_worker_id": previous_worker_id,
                "attempt": attempt,
            },
        )
        record_audit_event(
            db,
            event_type="agent.execution.claimed",
            actor_type="worker",
            actor_id=worker.id,
            entity_type="agent_execution",
            entity_id=candidate.id,
            details={
                "investigation_id": investigation.id,
                "attempt": attempt,
                "reassigned": previous_worker_id is not None,
                "event_sequence": event.sequence,
            },
        )
        assignments.append(
            AgentExecutionAssignment(
                execution_id=candidate.id,
                investigation_id=investigation.id,
                lease_token=token,
                lease_expires_at=lease_expires_at,
                attempt=attempt,
                resume_required=_resume_required(db, investigation),
            )
        )
    worker.last_heartbeat_at = now
    worker.updated_at = now
    db.commit()
    return assignments


def active_agent_execution(
    db: Session,
    execution_id: str,
    *,
    worker_id: str,
    lease_token: str,
    lock: bool = False,
) -> AgentExecution:
    if lock:
        require_locking_transaction(db, purpose="Agent execution mutations")
    execution = db.get(
        AgentExecution,
        execution_id,
        with_for_update=lock,
        populate_existing=lock,
    )
    if execution is None:
        raise LookupError("Agent execution not found")
    if execution.status != AgentExecutionStatus.RUNNING:
        raise ValueError("Agent execution is no longer running")
    if execution.worker_id != worker_id:
        raise ValueError("Agent execution belongs to another worker")
    if execution.lease_token_hash is None or not secrets.compare_digest(
        execution.lease_token_hash,
        hash_token(lease_token),
    ):
        raise ValueError("Invalid agent execution lease token")
    if (
        execution.lease_expires_at is None
        or _as_utc(execution.lease_expires_at) < utcnow()
    ):
        raise ValueError("Agent execution lease has expired")
    return execution


def renew_agent_execution_lease(
    db: Session,
    execution_id: str,
    *,
    worker: AgentWorker,
    lease_token: str,
    lease_seconds: int,
) -> AgentExecution:
    from .worker_registry import lock_worker_registry
    worker = lock_worker_registry(db, worker)
    execution = active_agent_execution(
        db,
        execution_id,
        worker_id=worker.id,
        lease_token=lease_token,
        lock=True,
    )
    from .alert_investigation_control import enforce_stop
    enforce_stop(db, execution)
    now = utcnow()
    execution.lease_expires_at = now + timedelta(seconds=lease_seconds)
    execution.last_heartbeat_at = now
    execution.updated_at = now
    worker.last_heartbeat_at = now
    worker.updated_at = now
    db.commit()
    db.refresh(execution)
    return execution


def record_agent_execution_progress(
    db: Session,
    execution_id: str,
    *,
    worker: AgentWorker,
    payload: AgentExecutionProgress,
) -> AgentExecutionEvent:
    execution = active_agent_execution(
        db,
        execution_id,
        worker_id=worker.id,
        lease_token=payload.lease_token,
        lock=True,
    )
    if execution.cancellation_requested_at is not None:
        raise ValueError("Agent execution cancellation was requested")
    investigation = db.get(
        Investigation,
        execution.investigation_id,
        with_for_update=True,
        populate_existing=True,
    )
    if investigation is None:
        raise LookupError("Investigation not found")
    replayed_checkpoint = False
    if payload.state is not None:
        from ..agent_schemas import (
            HypothesisState,
            InvestigationCheckpointCreate,
            InvestigationState,
        )
        from .agent_remote_runtime import _validate_graph_state
        from .agent_runtime import append_investigation_checkpoint

        graph_state = _validate_graph_state(
            payload.state,
            investigation,
            require_persisted_counters=False,
        )
        if (
            graph_state["current_node"] != payload.node
            or graph_state["status"] != payload.status
            or graph_state["iteration"] != payload.iteration
            or graph_state["tokens_used"] != payload.tokens_used
            or graph_state["tool_calls_used"] != payload.tool_calls_used
            or len(graph_state["evidence_ids"]) != payload.evidence_count
        ):
            raise ValueError("Agent progress state and counters diverged")
        if payload.node != "finalize" and investigation.status == "running":
            checkpoint_state = InvestigationState(
                investigation_id=graph_state["investigation_id"],
                objective=graph_state["objective"],
                scope=graph_state["scope"],
                status=graph_state["status"],
                iteration=graph_state["iteration"],
                plan=graph_state["plan"],
                hypotheses=[
                    HypothesisState.model_validate(item)
                    for item in graph_state["hypotheses"]
                ],
                evidence_ids=graph_state["evidence_ids"],
                tool_call_ids=graph_state["tool_call_ids"],
                workflow_tool_outcomes=(
                    [
                        {"call_id": item["call_id"], "status": item["status"]}
                        for item in graph_state["tool_results"]
                    ]
                    if payload.node == "tools" and investigation.workflow_snapshot
                    and graph_state["status"] == "running"
                    else []
                ),
                confidence=graph_state["confidence"],
                conclusion=graph_state["conclusion"],
                uncertainty=graph_state["uncertainty"],
                escalation_reason=graph_state["escalation_reason"],
                structured_output=graph_state["structured_output"],
            )
            previous = db.scalar(
                select(InvestigationCheckpoint)
                .where(InvestigationCheckpoint.investigation_id == investigation.id)
                .order_by(InvestigationCheckpoint.sequence.desc())
                .limit(1)
            )
            replayed_checkpoint = (
                previous is not None
                and previous.node == payload.node
                and previous.state == checkpoint_state.model_dump(mode="json")
            )
            if not replayed_checkpoint:
                append_investigation_checkpoint(
                    db,
                    investigation,
                    InvestigationCheckpointCreate(
                        node=payload.node,
                        state=checkpoint_state,
                        token_usage=(
                            graph_state["tokens_used"] - investigation.tokens_used
                        ),
                        actor=f"agent.worker.{worker.id}",
                    ),
                )
                db.refresh(investigation)
    evidence_count = db.scalar(
        select(func.count(InvestigationEvidence.id)).where(
            InvestigationEvidence.investigation_id == investigation.id
        )
    )
    expected = {
        "status": investigation.status,
        "iteration": investigation.iterations_used,
        "tokens_used": investigation.tokens_used,
        "tool_calls_used": investigation.tool_calls_used,
        "evidence_count": int(evidence_count or 0),
    }
    reported = payload.model_dump(exclude={"lease_token", "node", "state"})
    if reported != expected:
        raise ValueError(
            "Agent progress does not match persisted investigation state"
        )
    if replayed_checkpoint:
        reported["checkpoint_replayed"] = True
    event = append_execution_event(
        db,
        execution,
        event_type=f"graph.{payload.node}",
        payload=reported,
    )
    db.commit()
    db.refresh(event)
    return event


def cancel_agent_execution(
    db: Session,
    execution: AgentExecution,
    payload: AgentExecutionCancel,
    *,
    commit: bool = True,
    actor_type: str = "user",
) -> AgentExecution:
    require_locking_transaction(db, purpose="Agent execution cancellation")
    execution = db.get(
        AgentExecution,
        execution.id,
        with_for_update=True,
        populate_existing=True,
    )
    if execution is None:
        raise ValueError("Agent execution not found")
    if execution.status in TERMINAL_EXECUTION_STATUSES:
        if execution.status == AgentExecutionStatus.CANCELLED:
            return execution
        raise ValueError("Agent execution is already terminal")
    if execution.cancellation_requested_at is not None:
        return execution
    investigation = db.get(
        Investigation,
        execution.investigation_id,
        with_for_update=True,
        populate_existing=True,
    )
    if investigation is None:
        raise ValueError("Investigation not found")
    if investigation.status in {"completed", "failed", "escalated"}:
        raise ValueError("Investigation is already terminal")
    now = utcnow()
    execution.cancellation_requested_at = now
    execution.cancellation_requested_by = payload.actor
    execution.cancellation_reason = payload.reason
    immediate = execution.status in {
        AgentExecutionStatus.QUEUED,
        AgentExecutionStatus.WAITING_APPROVAL,
    }
    if immediate:
        execution.status = AgentExecutionStatus.CANCELLED
        execution.finished_at = now
        execution.worker_id = None
        execution.lease_token_hash = None
        execution.lease_expires_at = None
        if investigation.status not in {
            "completed",
            "failed",
            "escalated",
            "cancelled",
        }:
            investigation.status = "cancelled"
            investigation.finished_at = now
            investigation.updated_at = now
    execution.updated_at = now
    event = append_execution_event(
        db,
        execution,
        event_type=(
            "execution.cancelled"
            if immediate
            else "execution.cancellation_requested"
        ),
        payload={"actor": payload.actor, "reason": payload.reason},
    )
    record_audit_event(
        db,
        event_type="agent.execution.cancel_requested",
        actor_type=actor_type,
        actor_id=payload.actor,
        entity_type="agent_execution",
        entity_id=execution.id,
        details={
            "reason": payload.reason,
            "immediate": immediate,
            "event_sequence": event.sequence,
        },
    )
    if commit:
        db.commit()
        db.refresh(execution)
    else:
        db.flush()
    return execution


def complete_agent_execution(
    db: Session,
    execution_id: str,
    *,
    worker: AgentWorker,
    payload: AgentExecutionComplete,
) -> AgentExecution:
    require_locking_transaction(db, purpose="Agent execution completion")
    execution = db.get(
        AgentExecution,
        execution_id,
        with_for_update=True,
        populate_existing=True,
    )
    if execution is None:
        raise LookupError("Agent execution not found")
    request_hash = hashlib.sha256(
        json.dumps(
            {"status": payload.status, "error": payload.error},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    token_hash = hash_token(payload.lease_token)
    if execution.status != AgentExecutionStatus.RUNNING:
        if (
            execution.status
            in (TERMINAL_EXECUTION_STATUSES | {AgentExecutionStatus.WAITING_APPROVAL})
            and execution.completion_worker_id == worker.id
            and execution.completion_token_hash is not None
            and secrets.compare_digest(execution.completion_token_hash, token_hash)
            and execution.completion_request_hash is not None
            and secrets.compare_digest(execution.completion_request_hash, request_hash)
        ):
            return execution
        raise ValueError("Agent execution is no longer running")
    active_agent_execution(
        db,
        execution_id,
        worker_id=worker.id,
        lease_token=payload.lease_token,
    )
    investigation = db.get(
        Investigation,
        execution.investigation_id,
        with_for_update=True,
        populate_existing=True,
    )
    if investigation is None:
        raise LookupError("Investigation not found")
    now = utcnow()
    requested_status = AgentExecutionStatus(payload.status)
    target = (
        AgentExecutionStatus.CANCELLED
        if execution.cancellation_requested_at is not None
        else requested_status
    )
    if target == AgentExecutionStatus.SUCCEEDED:
        if investigation.status != "completed":
            raise ValueError("Succeeded execution requires a completed investigation")
    elif target == AgentExecutionStatus.WAITING_APPROVAL:
        if investigation.status != "waiting_approval":
            raise ValueError(
                "Waiting execution requires an investigation awaiting approval"
            )
    elif target == AgentExecutionStatus.CANCELLED:
        if execution.cancellation_requested_at is None:
            raise ValueError("Cancellation was not requested")
        investigation.status = "cancelled"
        investigation.finished_at = now
        investigation.updated_at = now
    elif target == AgentExecutionStatus.FAILED:
        if investigation.status == "running":
            investigation.status = "failed"
            investigation.escalation_reason = "Agent execution failed"
            investigation.finished_at = now
            investigation.updated_at = now

    execution.status = target
    execution.error = payload.error
    execution.completion_worker_id = worker.id
    execution.completion_token_hash = token_hash
    execution.completion_request_hash = request_hash
    execution.finished_at = (
        None if target == AgentExecutionStatus.WAITING_APPROVAL else now
    )
    execution.worker_id = None
    execution.lease_token_hash = None
    execution.lease_expires_at = None
    execution.updated_at = now
    event = append_execution_event(
        db,
        execution,
        event_type="execution.completed",
        payload={
            "status": target.value,
            "requested_status": requested_status.value,
            "attempt": execution.attempt_count,
            "has_error": payload.error is not None,
        },
    )
    record_audit_event(
        db,
        event_type="agent.execution.completed",
        actor_type="worker",
        actor_id=worker.id,
        entity_type="agent_execution",
        entity_id=execution.id,
        outcome=(
            "success" if target == AgentExecutionStatus.SUCCEEDED else "failure"
        ),
        details={
            "investigation_id": investigation.id,
            "status": target.value,
            "attempt": execution.attempt_count,
            "event_sequence": event.sequence,
        },
    )
    db.commit()
    db.refresh(execution)
    return execution
