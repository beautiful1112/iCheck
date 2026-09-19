from __future__ import annotations

import secrets
import time
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .agent_schemas import (
    AgentActionDecision,
    AgentActionProposalRead,
    AgentExecutionAssignment,
    AgentExecutionCancel,
    AgentExecutionClaim,
    AgentExecutionComplete,
    AgentExecutionEventRead,
    AgentExecutionLeaseRenew,
    AgentExecutionRead,
    AgentToolCreate,
    AgentToolRead,
    AgentWorkerHeartbeat,
    AgentWorkerRead,
    AgentWorkerRegister,
    AgentWorkerRegistration,
    InvestigationAction,
    InvestigationCheckpointCreate,
    InvestigationCheckpointRead,
    InvestigationCreate,
    InvestigationEvidenceCreate,
    InvestigationEvidenceRead,
    InvestigationRead,
    InvestigationStartResult,
    InvestigationToolCallComplete,
    InvestigationToolCallCreate,
    InvestigationToolCallRead,
)
from .auth import require_permissions
from .config import get_settings
from .database import SessionLocal, get_db
from .models import (
    AgentActionProposal,
    AgentExecution,
    AgentExecutionEvent,
    AgentExecutionStatus,
    AgentToolRegistration,
    AgentWorker,
    Investigation,
    InvestigationCheckpoint,
    InvestigationEvidence,
    InvestigationToolCall,
)
from .services.agent_execution import (
    cancel_agent_execution,
    claim_agent_executions,
    complete_agent_execution,
    heartbeat_agent_worker,
    register_agent_worker,
    renew_agent_execution_lease,
)
from .services.agent_approvals import decide_action_proposal
from .services.agent_runtime import (
    add_evidence_reference,
    append_investigation_checkpoint,
    complete_tool_call,
    create_agent_tool,
    create_investigation,
    create_tool_call,
    start_investigation,
)
from .worker_auth import (
    WorkerAuthenticationError,
    authenticate_agent_worker,
)
from .services.control_plane_auth import PrincipalContext


router = APIRouter(prefix="/api/v1/agent", tags=["agent-runtime"])
settings = get_settings()


def db_session():
    yield from get_db()


def _investigation(db: Session, investigation_id: str) -> Investigation:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return investigation


def _tool_call(db: Session, call_id: str) -> InvestigationToolCall:
    call = db.get(InvestigationToolCall, call_id)
    if call is None:
        raise HTTPException(status_code=404, detail="Investigation tool call not found")
    return call


def _agent_worker(db: Session, worker_id: str) -> AgentWorker:
    worker = db.get(AgentWorker, worker_id)
    if worker is None:
        raise HTTPException(status_code=404, detail="Agent worker not found")
    return worker


def _execution(db: Session, execution_id: str) -> AgentExecution:
    execution = db.get(AgentExecution, execution_id)
    if execution is None:
        raise HTTPException(status_code=404, detail="Agent execution not found")
    return execution


def _action_proposal(db: Session, proposal_id: str) -> AgentActionProposal:
    proposal = db.get(AgentActionProposal, proposal_id)
    if proposal is None:
        raise HTTPException(status_code=404, detail="Action proposal not found")
    return proposal


def _require_registration_token(token: str | None) -> None:
    configured = settings.agent_registration_token
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent worker registration is not configured",
        )
    if token is None or not secrets.compare_digest(configured, token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent worker registration token",
        )


def _authorize_agent_worker(
    worker: AgentWorker,
    authorization: str | None,
) -> None:
    try:
        authenticate_agent_worker(worker, authorization)
    except WorkerAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.post(
    "/tools",
    response_model=AgentToolRead,
    status_code=status.HTTP_201_CREATED,
)
def create_agent_tool_route(
    payload: AgentToolCreate,
    _: PrincipalContext = Depends(require_permissions("tools.admin")),
    db: Session = Depends(db_session),
) -> AgentToolRegistration:
    try:
        return create_agent_tool(db, payload)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/tools", response_model=list[AgentToolRead])
def list_agent_tools(
    enabled: bool | None = None,
    read_only: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("investigations.read")),
    db: Session = Depends(db_session),
) -> list[AgentToolRegistration]:
    query = select(AgentToolRegistration)
    if enabled is not None:
        query = query.where(AgentToolRegistration.enabled == enabled)
    if read_only is not None:
        query = query.where(AgentToolRegistration.read_only == read_only)
    return list(
        db.scalars(query.order_by(AgentToolRegistration.name).limit(limit)).all()
    )


@router.post(
    "/investigations",
    response_model=InvestigationRead,
    status_code=status.HTTP_201_CREATED,
)
def create_investigation_route(
    payload: InvestigationCreate,
    actor: PrincipalContext = Depends(require_permissions("investigations.create")),
    db: Session = Depends(db_session),
) -> Investigation:
    try:
        return create_investigation(db, payload, actor=actor)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/investigations", response_model=list[InvestigationRead])
def list_investigations(
    investigation_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("investigations.read")),
    db: Session = Depends(db_session),
) -> list[Investigation]:
    query = select(Investigation)
    if investigation_status:
        query = query.where(Investigation.status == investigation_status)
    return list(
        db.scalars(query.order_by(Investigation.created_at.desc()).limit(limit)).all()
    )


@router.get("/investigations/{investigation_id}", response_model=InvestigationRead)
def get_investigation_route(
    investigation_id: str,
    _: PrincipalContext = Depends(require_permissions("investigations.read")),
    db: Session = Depends(db_session),
) -> Investigation:
    return _investigation(db, investigation_id)


@router.post(
    "/investigations/{investigation_id}/start",
    response_model=InvestigationStartResult,
)
def start_investigation_route(
    investigation_id: str,
    payload: InvestigationAction,
    principal: PrincipalContext = Depends(
        require_permissions("investigations.create")
    ),
    db: Session = Depends(db_session),
) -> dict[str, object]:
    try:
        investigation, checkpoint = start_investigation(
            db,
            _investigation(db, investigation_id),
            actor=(
                payload.actor
                if principal.auth_method == "disabled"
                else principal.subject
            ),
        )
        return {"investigation": investigation, "checkpoint": checkpoint}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/investigations/{investigation_id}/execution",
    response_model=AgentExecutionRead,
)
def get_investigation_execution(
    investigation_id: str,
    db: Session = Depends(db_session),
) -> AgentExecution:
    _investigation(db, investigation_id)
    execution = db.scalar(
        select(AgentExecution).where(
            AgentExecution.investigation_id == investigation_id
        )
    )
    if execution is None:
        raise HTTPException(status_code=404, detail="Agent execution not found")
    return execution


@router.get("/action-proposals", response_model=list[AgentActionProposalRead])
def list_action_proposals(
    proposal_status: str | None = Query(default=None, alias="status"),
    investigation_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("investigations.read")),
    db: Session = Depends(db_session),
) -> list[AgentActionProposal]:
    query = select(AgentActionProposal)
    if proposal_status:
        query = query.where(AgentActionProposal.status == proposal_status)
    if investigation_id:
        query = query.where(
            AgentActionProposal.investigation_id == investigation_id
        )
    return list(
        db.scalars(
            query.order_by(AgentActionProposal.requested_at.desc()).limit(limit)
        ).all()
    )


@router.get(
    "/action-proposals/{proposal_id}",
    response_model=AgentActionProposalRead,
)
def get_action_proposal(
    proposal_id: str,
    _: PrincipalContext = Depends(require_permissions("investigations.read")),
    db: Session = Depends(db_session),
) -> AgentActionProposal:
    return _action_proposal(db, proposal_id)


@router.post(
    "/action-proposals/{proposal_id}/decision",
    response_model=AgentActionProposalRead,
)
def decide_action_proposal_route(
    proposal_id: str,
    payload: AgentActionDecision,
    actor: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> AgentActionProposal:
    try:
        return decide_action_proposal(
            db,
            _action_proposal(db, proposal_id),
            payload,
            actor=actor,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/workers/register",
    response_model=AgentWorkerRegistration,
)
def register_agent_worker_route(
    payload: AgentWorkerRegister,
    db: Session = Depends(db_session),
    x_icheck_registration_token: Annotated[
        str | None,
        Header(alias="X-iCheck-Registration-Token"),
    ] = None,
) -> AgentWorkerRegistration:
    _require_registration_token(x_icheck_registration_token)
    try:
        worker, access_token = register_agent_worker(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return AgentWorkerRegistration(
        worker=AgentWorkerRead.model_validate(worker),
        access_token=access_token,
    )


@router.get("/workers", response_model=list[AgentWorkerRead])
def list_agent_workers(
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(db_session),
) -> list[AgentWorker]:
    return list(
        db.scalars(
            select(AgentWorker).order_by(AgentWorker.name).limit(limit)
        ).all()
    )


@router.post(
    "/workers/{worker_id}/heartbeat",
    response_model=AgentWorkerRead,
)
def heartbeat_agent_worker_route(
    worker_id: str,
    payload: AgentWorkerHeartbeat,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentWorker:
    worker = _agent_worker(db, worker_id)
    _authorize_agent_worker(worker, authorization)
    try:
        return heartbeat_agent_worker(db, worker, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/workers/{worker_id}/executions/claim",
    response_model=list[AgentExecutionAssignment],
)
def claim_agent_executions_route(
    worker_id: str,
    payload: AgentExecutionClaim,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> list[AgentExecutionAssignment]:
    worker = _agent_worker(db, worker_id)
    _authorize_agent_worker(worker, authorization)
    try:
        return claim_agent_executions(db, worker, payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/executions/{execution_id}", response_model=AgentExecutionRead)
def get_agent_execution_route(
    execution_id: str,
    db: Session = Depends(db_session),
) -> AgentExecution:
    return _execution(db, execution_id)


@router.post(
    "/executions/{execution_id}/lease",
    response_model=AgentExecutionRead,
)
def renew_agent_execution_lease_route(
    execution_id: str,
    payload: AgentExecutionLeaseRenew,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentExecution:
    execution = _execution(db, execution_id)
    if execution.worker_id is None:
        raise HTTPException(status_code=409, detail="Execution has no worker")
    worker = _agent_worker(db, execution.worker_id)
    _authorize_agent_worker(worker, authorization)
    try:
        return renew_agent_execution_lease(
            db,
            execution_id,
            worker=worker,
            lease_token=payload.lease_token,
            lease_seconds=payload.lease_seconds,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/executions/{execution_id}/cancel",
    response_model=AgentExecutionRead,
)
def cancel_agent_execution_route(
    execution_id: str,
    payload: AgentExecutionCancel,
    db: Session = Depends(db_session),
) -> AgentExecution:
    try:
        return cancel_agent_execution(db, _execution(db, execution_id), payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/executions/{execution_id}/complete",
    response_model=AgentExecutionRead,
)
def complete_agent_execution_route(
    execution_id: str,
    payload: AgentExecutionComplete,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentExecution:
    execution = _execution(db, execution_id)
    if execution.worker_id is None:
        raise HTTPException(status_code=409, detail="Execution has no worker")
    worker = _agent_worker(db, execution.worker_id)
    _authorize_agent_worker(worker, authorization)
    try:
        return complete_agent_execution(
            db,
            execution_id,
            worker=worker,
            payload=payload,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/executions/{execution_id}/events",
    response_model=list[AgentExecutionEventRead],
)
def list_agent_execution_events(
    execution_id: str,
    after_sequence: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(db_session),
) -> list[AgentExecutionEvent]:
    _execution(db, execution_id)
    return list(
        db.scalars(
            select(AgentExecutionEvent)
            .where(
                AgentExecutionEvent.execution_id == execution_id,
                AgentExecutionEvent.sequence > after_sequence,
            )
            .order_by(AgentExecutionEvent.sequence)
            .limit(limit)
        ).all()
    )


@router.get("/executions/{execution_id}/events/stream")
def stream_agent_execution_events(
    execution_id: str,
    after_sequence: int = Query(default=0, ge=0),
    timeout_seconds: int = Query(default=25, ge=1, le=30),
    last_event_id: Annotated[
        str | None,
        Header(alias="Last-Event-ID"),
    ] = None,
) -> StreamingResponse:
    cursor = after_sequence
    if last_event_id:
        try:
            cursor = max(cursor, int(last_event_id))
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail="Last-Event-ID must be an integer sequence",
            ) from exc
    with SessionLocal() as db:
        _execution(db, execution_id)

    def event_stream():
        nonlocal cursor
        deadline = time.monotonic() + timeout_seconds
        last_keepalive = time.monotonic()
        while time.monotonic() < deadline:
            with SessionLocal() as db:
                events = list(
                    db.scalars(
                        select(AgentExecutionEvent)
                        .where(
                            AgentExecutionEvent.execution_id == execution_id,
                            AgentExecutionEvent.sequence > cursor,
                        )
                        .order_by(AgentExecutionEvent.sequence)
                        .limit(100)
                    ).all()
                )
                for event in events:
                    cursor = event.sequence
                    document = AgentExecutionEventRead.model_validate(event)
                    yield (
                        f"id: {event.sequence}\n"
                        f"event: {event.event_type}\n"
                        f"data: {document.model_dump_json()}\n\n"
                    )
                execution = db.get(AgentExecution, execution_id)
                if execution is None:
                    yield (
                        "event: stream.error\n"
                        "data: {\"detail\":\"execution_not_found\"}\n\n"
                    )
                    return
                if execution.status in {
                    AgentExecutionStatus.WAITING_APPROVAL,
                    AgentExecutionStatus.SUCCEEDED,
                    AgentExecutionStatus.FAILED,
                    AgentExecutionStatus.CANCELLED,
                }:
                    yield (
                        "event: stream.end\n"
                        f"data: {{\"status\":\"{execution.status.value}\","
                        f"\"last_sequence\":{cursor}}}\n\n"
                    )
                    return
            if time.monotonic() - last_keepalive >= 5:
                yield ": keepalive\n\n"
                last_keepalive = time.monotonic()
            time.sleep(0.25)
        yield (
            "event: stream.timeout\n"
            f"data: {{\"last_sequence\":{cursor}}}\n\n"
        )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post(
    "/investigations/{investigation_id}/checkpoints",
    response_model=InvestigationCheckpointRead,
    status_code=status.HTTP_201_CREATED,
)
def append_checkpoint_route(
    investigation_id: str,
    payload: InvestigationCheckpointCreate,
    db: Session = Depends(db_session),
) -> InvestigationCheckpoint:
    try:
        return append_investigation_checkpoint(
            db,
            _investigation(db, investigation_id),
            payload,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/investigations/{investigation_id}/checkpoints",
    response_model=list[InvestigationCheckpointRead],
)
def list_checkpoints(
    investigation_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(db_session),
) -> list[InvestigationCheckpoint]:
    _investigation(db, investigation_id)
    return list(
        db.scalars(
            select(InvestigationCheckpoint)
            .where(InvestigationCheckpoint.investigation_id == investigation_id)
            .order_by(InvestigationCheckpoint.sequence.desc())
            .limit(limit)
        ).all()
    )


@router.post(
    "/investigations/{investigation_id}/evidence",
    response_model=InvestigationEvidenceRead,
    status_code=status.HTTP_201_CREATED,
)
def add_evidence_route(
    investigation_id: str,
    payload: InvestigationEvidenceCreate,
    db: Session = Depends(db_session),
) -> InvestigationEvidence:
    return add_evidence_reference(
        db,
        _investigation(db, investigation_id),
        payload,
    )


@router.get(
    "/investigations/{investigation_id}/evidence",
    response_model=list[InvestigationEvidenceRead],
)
def list_evidence(
    investigation_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(db_session),
) -> list[InvestigationEvidence]:
    _investigation(db, investigation_id)
    return list(
        db.scalars(
            select(InvestigationEvidence)
            .where(InvestigationEvidence.investigation_id == investigation_id)
            .order_by(InvestigationEvidence.created_at.desc())
            .limit(limit)
        ).all()
    )


@router.post(
    "/investigations/{investigation_id}/tool-calls",
    response_model=InvestigationToolCallRead,
    status_code=status.HTTP_201_CREATED,
)
def create_tool_call_route(
    investigation_id: str,
    payload: InvestigationToolCallCreate,
    db: Session = Depends(db_session),
) -> InvestigationToolCall:
    try:
        return create_tool_call(
            db,
            _investigation(db, investigation_id),
            payload,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/investigations/{investigation_id}/tool-calls",
    response_model=list[InvestigationToolCallRead],
)
def list_tool_calls(
    investigation_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(db_session),
) -> list[InvestigationToolCall]:
    _investigation(db, investigation_id)
    return list(
        db.scalars(
            select(InvestigationToolCall)
            .where(InvestigationToolCall.investigation_id == investigation_id)
            .order_by(InvestigationToolCall.created_at.desc())
            .limit(limit)
        ).all()
    )


@router.post(
    "/tool-calls/{call_id}/complete",
    response_model=InvestigationToolCallRead,
)
def complete_tool_call_route(
    call_id: str,
    payload: InvestigationToolCallComplete,
    db: Session = Depends(db_session),
) -> InvestigationToolCall:
    try:
        return complete_tool_call(db, _tool_call(db, call_id), payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
