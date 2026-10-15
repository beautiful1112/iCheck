from __future__ import annotations

import secrets
import time
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .services.situation_closure_reads import investigation_receipts_visible
from .services.model_reasoner import ModelReasonerUnavailable

from .agent_schemas import (
    AgentActionDecision,
    AgentActionProposalRead,
    MCPWriteReconciliationPacket,
    MCPWriteReconciliationObservationCreate,
    MCPWriteReconciliationObservationRead,
    MCPWriteReconciliationReviewCreate,
    MCPWriteReconciliationReviewRead,
    MCPWriteReconciliationSummary,
    MCPWriteDispositionEvidenceSnapshot,
    MCPWriteDispositionCreate,
    MCPWriteDispositionRead,
    MCPDeclaredProviderLookupQualification,
    MCPIndependentVerificationQualification,
    MCPIndependentEvidenceSummary,
    MCPIndependentObservationCreate,
    MCPIndependentObservationRead,
    MCPIndependentReviewCreate,
    MCPIndependentReviewRead,
    AgentExecutionAssignment,
    AgentExecutionCancel,
    AgentExecutionClaim,
    AgentExecutionComplete,
    AgentExecutionEventRead,
    AgentExecutionLeaseRenew,
    AgentExecutionProgress,
    AgentExecutionRead,
    AgentRuntimeBootstrapRead,
    AgentRuntimeBootstrapRequest,
    AgentRuntimeCheckpointGet,
    AgentRuntimeCheckpointList,
    AgentRuntimeCheckpointPut,
    AgentRuntimeCheckpointPutRead,
    AgentRuntimeCheckpointTupleRead,
    AgentRuntimeCheckpointWrites,
    AgentRuntimeReasonRead,
    AgentRuntimeReasonRequest,
    AgentRuntimeToolRead,
    AgentRuntimeToolRequest,
    AgentToolCreate,
    AgentToolRead,
    AgentWorkerHeartbeat,
    AgentWorkerRead,
    AgentWorkerRegister,
    AgentWorkerRegistration,
    ChangeRiskPolicyRead,
    ChangeRiskPolicyUpdate,
    ChangePreapprovalCreate,
    ChangePreapprovalDecision,
    ChangePreapprovalPreview,
    ChangePreapprovalRead,
    ChangePreapprovalUpdate,
    ChangePreapprovalExecutionGrantCreate,
    ChangePreapprovalExecutionGrantRead,
    ChangePreapprovalExecutionGrantPage,
    ChangePreapprovalExecutionRequest,
    ChangePreapprovalAuthorizationRead,
    ChangePreapprovalQualificationRead,
    RollbackExecutionGrantCreate,
    RollbackExecutionGrantRead,
    RollbackExecutionGrantPage,
    RollbackQualificationRead,
    RollbackQualificationSettings,
    RollbackGrantRevocationCreate,
    RollbackAuthorizationCreate,
    RollbackAuthorizationRead,
    GovernedChangeEvidenceAttach,
    GovernedChangePlanRead,
    GovernedChangeWindowUpdate,
    InvestigationAction,
    InvestigationCheckpointCreate,
    InvestigationCheckpointRead,
    InvestigationCreate,
    InvestigationEvidenceCreate,
    InvestigationEvidenceRead,
    InvestigationPage,
    InvestigationRead,
    InvestigationStartResult,
    InvestigationToolCallComplete,
    InvestigationToolCallCreate,
    InvestigationToolCallRead,
)
from .auth import require_global_permissions, require_permissions
from .config import get_settings
from .database import SessionLocal, get_db, set_session_namespace
from .models import (
    AgentActionProposal,
    AgentExecution,
    AgentExecutionEvent,
    AgentExecutionStatus,
    AgentToolRegistration,
    AgentWorker,
    ChangeRiskPolicy,
    ChangePreapprovalPolicy,
    GovernedChangePlan,
    Investigation,
    InvestigationCheckpoint,
    InvestigationEvidence,
    InvestigationToolCall,
    MCPWriteIndependentObservation,
    MCPWriteReconciliationObservation,
    MCPWriteReconciliationReview,
)
from .services.agent_execution import (
    cancel_agent_execution,
    claim_agent_executions,
    complete_agent_execution,
    heartbeat_agent_worker,
    register_agent_worker,
    record_agent_execution_progress,
    renew_agent_execution_lease,
)
from .services.agent_remote_runtime import (
    checkpoint_get,
    checkpoint_list,
    checkpoint_put,
    checkpoint_writes,
    execute_runtime_reason,
    execute_runtime_tool,
    runtime_bootstrap,
)
from .services.agent_approvals import decide_action_proposal
from .services.action_disposition import (
    list_mcp_write_dispositions, record_unresolved_mcp_write_disposition,
)
from .services.action_reconciliation import (
    assess_mcp_write_evidence_contracts,
    list_independent_mcp_observations,
    list_independent_mcp_reviews,
    qualify_independent_mcp_verification,
    record_independent_mcp_observation,
    review_independent_mcp_observation,
    summarize_independent_mcp_evidence,
    list_mcp_write_lookup_observations,
    list_mcp_write_lookup_reviews,
    load_complete_mcp_write_evidence,
    make_mcp_write_evidence_manifest,
    mcp_write_reconciliation_packet,
    mcp_write_reconciliation_summary,
    qualify_declared_provider_lookup,
    record_mcp_write_lookup_observation,
    review_mcp_write_lookup_observation,
)
from .services.change_governance import (
    attach_change_evidence,
    get_change_plan,
    get_change_plan_for_proposal,
    update_change_window,
)
from .services.change_risk_policies import (
    get_change_risk_policy,
    list_change_risk_policies,
    update_change_risk_policy,
)
from .services.change_preapprovals import (
    create_preapproval,
    get_preapproval,
    list_preapprovals,
    preview_preapproval,
    review_preapproval,
    revise_preapproval,
    revoke_preapproval,
)
from .services.authorization_scope import (
    authorized_device_ids,
    namespace_clause,
    request_actor,
    require_requested_investigation_scope,
    require_situation_access,
    scope_contains,
    scope_contains_with_devices,
)
from .services.preapproval_execution import (
    authorize_reviewed_action, authorization_for_proposal,
    list_execution_grants, qualify_reviewed_execution,
    read_execution_qualification, require_policy_device_scope,
)
from .services.rollback_execution import (authorize_rollback, qualify_rollback, revoke_rollback,
    restoration_evidence, rollback_authorization)
from .models import ChangePreapprovalExecutionGrant, ChangeRollbackExecutionGrant, ChangeRollbackGrantRevocation
from .services.preapproval_execution import _row
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
from .worker_mtls import WorkerPeerIdentity, worker_peer_identity
from .worker_mtls_schemas import (
    WorkerMTLSLifecycleAction,
    WorkerMTLSRotationCreate,
    WorkerMTLSRotationRead,
    WorkerMTLSStateRead,
)
from .services.worker_mtls import (
    cancel_worker_mtls_rotation,
    revoke_worker_mtls_identity,
    stage_worker_mtls_rotation,
    verify_worker_peer,
)
from .services.control_plane_auth import PrincipalContext


router = APIRouter(prefix="/api/v1/agent", tags=["agent-runtime"])
WorkerPeer = Annotated[WorkerPeerIdentity | None, Depends(worker_peer_identity)]
settings = get_settings()


db_session = get_db


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


def _authorized_investigation(
    db: Session,
    investigation_id: str,
    principal: PrincipalContext,
) -> Investigation:
    investigation = _investigation(db, investigation_id)
    if (not scope_contains(db, principal, investigation.authorization_scope)
        or not investigation_receipts_visible(db, investigation, principal)):
        raise HTTPException(status_code=404, detail="Investigation not found")
    return investigation


def _authorized_execution(
    db: Session,
    execution_id: str,
    principal: PrincipalContext,
) -> AgentExecution:
    execution = _execution(db, execution_id)
    _authorized_investigation(db, execution.investigation_id, principal)
    return execution


@router.get("/investigations/{investigation_id}/diagnosis")
def get_ai_runtime_diagnosis(investigation_id: str, response: Response,
        principal: PrincipalContext = Depends(require_permissions("investigations.read")),
        db: Session = Depends(db_session)):
    from .services.ai_self_repair import diagnose
    response.headers["Cache-Control"] = "no-store"
    return diagnose(db, _authorized_investigation(db, investigation_id, principal))


@router.post("/investigations/{investigation_id}/repair-retry", response_model=InvestigationRead, status_code=201)
def retry_repaired_investigation(investigation_id: str, payload: InvestigationAction,
        principal: PrincipalContext = Depends(require_permissions("investigations.read", "investigations.create")),
        db: Session = Depends(db_session)):
    from .models import AIModelRoute, AIModelConfig
    from .ai_failure_diagnostics import batch_model
    previous = _authorized_investigation(db, investigation_id, principal)
    if previous.status not in {"escalated", "failed", "cancelled"} or previous.skill_snapshot or previous.workflow_snapshot:
        raise HTTPException(status_code=409, detail="Only a terminal autonomous investigation can use this explicit retry")
    route = db.get(AIModelRoute, previous.route_id)
    model = db.get(AIModelConfig, route.primary_model_id) if route else None
    if not route or not route.enabled or not model or not model.enabled or batch_model(model.model_name):
        raise HTTPException(status_code=409, detail="Repair the route with an enabled synchronous model before retrying")
    require_requested_investigation_scope(db, principal, previous.scope)
    if previous.situation_id:
        require_situation_access(db, principal, previous.situation_id)
    try:
        created = create_investigation(db, InvestigationCreate(title=previous.title, objective=previous.objective,
            execution_mode=previous.execution_mode,
            scope=previous.scope, situation_id=previous.situation_id, route_purpose=route.purpose,
            agent_profile=(previous.agent_profile_snapshot or {}).get("name"), created_by=principal.subject),
            actor=principal, commit=False)
        from .services.audit import record_audit_event
        record_audit_event(db, event_type="investigation.repair_retried", actor_type="user", actor_id=principal.subject,
            entity_type="investigation", entity_id=created.id,
            details={"previous_investigation_id": previous.id, "model_id": created.model_id})
        db.commit()
        start_investigation(db, created, actor=request_actor(principal, payload.actor))
        return created
    except (ValueError, LookupError) as exc:
        db.rollback(); raise HTTPException(status_code=409, detail=str(exc)) from None


def _authorized_proposal(
    db: Session,
    proposal_id: str,
    principal: PrincipalContext,
) -> AgentActionProposal:
    proposal = _action_proposal(db, proposal_id)
    _authorized_investigation(db, proposal.investigation_id, principal)
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
    db: Session,
    worker: AgentWorker,
    authorization: str | None,
    peer_identity: WorkerPeerIdentity | None,
) -> None:
    try:
        authenticate_agent_worker(worker, authorization)
        verify_worker_peer(
            db,
            worker,
            peer_identity,
            kind="agent",
            mode=get_settings().worker_mtls_mode,
        )
    except (WorkerAuthenticationError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _authorize_execution_worker(
    db: Session,
    execution_id: str,
    authorization: str | None,
    peer_identity: WorkerPeerIdentity | None,
) -> tuple[AgentExecution, AgentWorker]:
    execution = _execution(db, execution_id)
    if execution.worker_id is None:
        raise HTTPException(status_code=409, detail="Execution has no worker")
    worker = _agent_worker(db, execution.worker_id)
    _authorize_agent_worker(db, worker, authorization, peer_identity)
    return execution, worker


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
    if payload.transport == "mcp":
        raise HTTPException(
            status_code=422,
            detail=(
                "MCP tools must be registered by attesting and activating a "
                "published Tool Artifact through /api/v1/mcp"
            ),
        )
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
    require_requested_investigation_scope(db, actor, payload.scope)
    if payload.situation_id is not None:
        require_situation_access(db, actor, payload.situation_id)
    try:
        return create_investigation(db, payload, actor=actor)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/investigations", response_model=list[InvestigationRead])
def list_investigations(
    investigation_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=1000),
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> list[Investigation]:
    query = select(Investigation)
    if investigation_status:
        query = query.where(Investigation.status == investigation_status)
    rows = list(
        db.scalars(query.order_by(Investigation.created_at.desc())).all()
    )
    return [
        item
        for item in rows
        if scope_contains(db, principal, item.authorization_scope)
        and investigation_receipts_visible(db, item, principal)
    ][:limit]


@router.get("/investigations/page", response_model=InvestigationPage)
def page_investigations(
    investigation_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, min_length=1, max_length=36),
    principal: PrincipalContext = Depends(require_permissions("investigations.read")),
    db: Session = Depends(db_session),
    *,
    capability_task: Annotated[Literal["grafana-dashboard"] | None, Query()] = None,
    grafana_connection_id: Annotated[UUID | None, Query()] = None,
) -> InvestigationPage:
    allowed_statuses = {
        "pending", "running", "waiting_approval", "completed",
        "escalated", "failed", "cancelled",
    }
    if investigation_status is not None and investigation_status not in allowed_statuses:
        raise HTTPException(status_code=422, detail="Invalid investigation status")
    if grafana_connection_id and not capability_task:
        raise HTTPException(status_code=422, detail="Grafana history requires the dashboard task filter")
    filters = [namespace_clause(Investigation, principal)]
    if capability_task:
        filters.append(Investigation.scope["capability_task"].as_string() == capability_task)
    if grafana_connection_id:
        filters.append(Investigation.scope["grafana_connection_id"].as_string() == str(grafana_connection_id))
    allowed_devices = authorized_device_ids(db, principal)
    seek: Investigation | None = None
    if cursor is not None:
        try:
            if str(UUID(cursor)) != cursor:
                raise ValueError("Invalid cursor")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid investigation page cursor") from exc
        seek = db.scalar(select(Investigation).where(
            Investigation.id == cursor,
            *filters,
        ))
        if (
            seek is None
            or (investigation_status is not None and seek.status != investigation_status)
            or not scope_contains_with_devices(
                principal, seek.authorization_scope, allowed_devices,
            )
            or not investigation_receipts_visible(db, seek, principal)
        ):
            raise HTTPException(status_code=422, detail="Invalid investigation page cursor")

    base = select(Investigation).where(*filters)
    if investigation_status is not None:
        base = base.where(Investigation.status == investigation_status)
    visible: list[Investigation] = []
    batch_size = max(100, limit * 2)
    while len(visible) <= limit:
        query = base
        if seek is not None:
            query = query.where(or_(
                Investigation.created_at < seek.created_at,
                and_(
                    Investigation.created_at == seek.created_at,
                    Investigation.id < seek.id,
                ),
            ))
        rows = list(db.scalars(
            query.order_by(Investigation.created_at.desc(), Investigation.id.desc())
            .limit(batch_size)
        ).all())
        if not rows:
            break
        for row in rows:
            if scope_contains_with_devices(
                principal, row.authorization_scope, allowed_devices,
            ) and investigation_receipts_visible(db, row, principal):
                visible.append(row)
                if len(visible) > limit:
                    break
        if len(visible) > limit or len(rows) < batch_size:
            break
        seek = rows[-1]
    items = visible[:limit]
    return InvestigationPage(
        items=[InvestigationRead.model_validate(item) for item in items],
        next_cursor=items[-1].id if len(visible) > limit else None,
    )


@router.get("/investigations/{investigation_id}", response_model=InvestigationRead)
def get_investigation_route(
    investigation_id: str,
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> Investigation:
    return _authorized_investigation(db, investigation_id, principal)


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
            _authorized_investigation(db, investigation_id, principal),
            actor=request_actor(principal, payload.actor),
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
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> AgentExecution:
    _authorized_investigation(db, investigation_id, principal)
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
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> list[AgentActionProposal]:
    query = select(AgentActionProposal)
    if proposal_status:
        query = query.where(AgentActionProposal.status == proposal_status)
    if investigation_id:
        query = query.where(
            AgentActionProposal.investigation_id == investigation_id
        )
    rows = list(
        db.scalars(
            query.order_by(AgentActionProposal.requested_at.desc())
        ).all()
    )
    return [
        item
        for item in rows
        if scope_contains(
            db,
            principal,
            _investigation(db, item.investigation_id).authorization_scope,
        )
    ][:limit]


@router.get(
    "/action-proposals/{proposal_id}",
    response_model=AgentActionProposalRead,
)
def get_action_proposal(
    proposal_id: str,
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> AgentActionProposal:
    return _authorized_proposal(db, proposal_id, principal)


@router.get(
    "/action-proposals/{proposal_id}/reconciliation-packet",
    response_model=MCPWriteReconciliationPacket,
)
def get_action_reconciliation_packet(
    proposal_id: str,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> MCPWriteReconciliationPacket:
    try:
        return mcp_write_reconciliation_packet(
            db, _authorized_proposal(db, proposal_id, principal)
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/action-proposals/{proposal_id}/independent-verification/{verification_tool_call_id}",
    response_model=MCPIndependentVerificationQualification,
)
def get_action_independent_verification(
    proposal_id: str,
    verification_tool_call_id: str,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> MCPIndependentVerificationQualification:
    proposal = _authorized_proposal(db, proposal_id, principal)
    verification = db.get(InvestigationToolCall, verification_tool_call_id)
    if verification is None:
        raise HTTPException(status_code=404, detail="Verification Tool call not found")
    _authorized_investigation(db, verification.investigation_id, principal)
    try:
        return qualify_independent_mcp_verification(db, proposal, verification_tool_call_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/action-proposals/{proposal_id}/independent-observations",
    response_model=list[MCPIndependentObservationRead],
)
def list_action_independent_observations(
    proposal_id: str,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> list[MCPIndependentObservationRead]:
    _authorized_proposal(db, proposal_id, principal)
    rows = list_independent_mcp_observations(db, proposal_id, limit=1001)
    if len(rows) > 1000:
        raise HTTPException(status_code=409, detail="Independent evidence exceeds the bounded review")
    visible = []
    for row in rows:
        verification = db.get(InvestigationToolCall, row.verification_tool_call_id)
        if verification is None:
            continue
        try:
            _authorized_investigation(db, verification.investigation_id, principal)
        except HTTPException as exc:
            if exc.status_code != 404:
                raise
        else:
            visible.append(row)
    return visible


@router.post(
    "/action-proposals/{proposal_id}/independent-observations",
    response_model=MCPIndependentObservationRead,
    status_code=status.HTTP_201_CREATED,
)
def record_action_independent_observation(
    proposal_id: str,
    payload: MCPIndependentObservationCreate,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> MCPIndependentObservationRead:
    _authorized_proposal(db, proposal_id, principal)
    verification = db.get(InvestigationToolCall, payload.verification_tool_call_id)
    if verification is None:
        raise HTTPException(status_code=404, detail="Verification Tool call not found")
    _authorized_investigation(db, verification.investigation_id, principal)
    try:
        return record_independent_mcp_observation(
            db, proposal_id, payload.verification_tool_call_id, payload.reason,
            actor=principal,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/action-proposals/{proposal_id}/independent-reviews",
    response_model=list[MCPIndependentReviewRead],
)
def list_action_independent_reviews(
    proposal_id: str,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> list[MCPIndependentReviewRead]:
    _authorized_proposal(db, proposal_id, principal)
    visible_observations = {
        row.id for row in list_action_independent_observations(proposal_id, principal, db)
    }
    rows = list_independent_mcp_reviews(db, proposal_id, limit=1001)
    if len(rows) > 1000:
        raise HTTPException(status_code=409, detail="Independent reviews exceed the bounded review")
    return [row for row in rows if row.observation_id in visible_observations]


@router.get(
    "/action-proposals/{proposal_id}/independent-evidence-summary",
    response_model=MCPIndependentEvidenceSummary,
)
def get_action_independent_evidence_summary(
    proposal_id: str,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> MCPIndependentEvidenceSummary:
    # Reuse the exact per-verifier visibility checks of the evidence list.
    observations = list_action_independent_observations(proposal_id, principal, db)
    reviews = list_action_independent_reviews(proposal_id, principal, db)
    return summarize_independent_mcp_evidence(proposal_id, observations, reviews)


@router.post(
    "/action-proposals/{proposal_id}/independent-observations/{observation_id}/review",
    response_model=MCPIndependentReviewRead,
    status_code=status.HTTP_201_CREATED,
)
def review_action_independent_observation(
    proposal_id: str,
    observation_id: str,
    payload: MCPIndependentReviewCreate,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> MCPIndependentReviewRead:
    _authorized_proposal(db, proposal_id, principal)
    observation = db.get(MCPWriteIndependentObservation, observation_id)
    if observation is None or observation.proposal_id != proposal_id:
        raise HTTPException(status_code=404, detail="Independent observation not found")
    verification = db.get(InvestigationToolCall, observation.verification_tool_call_id)
    if verification is None:
        raise HTTPException(status_code=404, detail="Verification Tool call not found")
    _authorized_investigation(db, verification.investigation_id, principal)
    try:
        return review_independent_mcp_observation(
            db, proposal_id, observation_id, payload.decision, payload.reason,
            actor=principal,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/action-proposals/{proposal_id}/reconciliation-summary",
    response_model=MCPWriteReconciliationSummary,
)
def get_action_reconciliation_summary(
    proposal_id: str,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> MCPWriteReconciliationSummary:
    proposal = _authorized_proposal(db, proposal_id, principal)
    observations = _visible_provider_lookup_observations(db, proposal_id, principal)
    reviews = _visible_provider_lookup_reviews(db, proposal_id, principal, observations)
    try:
        return mcp_write_reconciliation_summary(
            db, proposal, observations, reviews
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _authorized_complete_mcp_snapshot(
    db: Session, proposal_id: str, principal: PrincipalContext,
):
    _authorized_proposal(db, proposal_id, principal)
    snapshot = load_complete_mcp_write_evidence(db, proposal_id)
    db.expire_all()
    _authorized_proposal(db, proposal_id, principal)
    for investigation_id in snapshot.evidence_investigation_ids:
        try:
            _authorized_investigation(db, investigation_id, principal)
        except HTTPException as exc:
            if exc.status_code == 404:
                raise HTTPException(
                    status_code=409,
                    detail="Complete MCP evidence set is not reviewable by this approver",
                ) from exc
            raise
    return snapshot


@router.get(
    "/action-proposals/{proposal_id}/disposition-evidence",
    response_model=MCPWriteDispositionEvidenceSnapshot,
)
def get_action_disposition_evidence(
    proposal_id: str,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> MCPWriteDispositionEvidenceSnapshot:
    try:
        snapshot = _authorized_complete_mcp_snapshot(db, proposal_id, principal)
        provider = mcp_write_reconciliation_summary(
            db, snapshot.proposal,
            list(snapshot.provider_observations), list(snapshot.provider_reviews),
        )
        independent = summarize_independent_mcp_evidence(
            proposal_id,
            list(snapshot.independent_observations), list(snapshot.independent_reviews),
        )
        contract_qualification = assess_mcp_write_evidence_contracts(db, snapshot)
        evidence_manifest = make_mcp_write_evidence_manifest(db, snapshot)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return MCPWriteDispositionEvidenceSnapshot(
        proposal_id=proposal_id,
        original_tool_call_id=snapshot.packet.tool_call_id,
        provider=provider,
        independent=independent,
        contract_qualification=contract_qualification,
        evidence_manifest=evidence_manifest,
        native_transactional_lock=snapshot.native_locking,
    )


@router.post(
    "/action-proposals/{proposal_id}/dispositions",
    response_model=MCPWriteDispositionRead,
    status_code=status.HTTP_201_CREATED,
)
def record_action_unresolved_disposition(
    proposal_id: str,
    payload: MCPWriteDispositionCreate,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> MCPWriteDispositionRead:
    if not get_settings().enable_mcp_write_disposition_custody:
        raise HTTPException(status_code=503, detail="MCP disposition custody is not enabled")
    try:
        snapshot = _authorized_complete_mcp_snapshot(db, proposal_id, principal)
        if not snapshot.native_locking:
            raise HTTPException(status_code=503, detail="Native PostgreSQL locking is required for MCP disposition")
        row = record_unresolved_mcp_write_disposition(
            db, snapshot, str(payload.request_id), payload.reason, actor=principal,
        )
        return MCPWriteDispositionRead.model_validate(row)
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/action-proposals/{proposal_id}/dispositions",
    response_model=list[MCPWriteDispositionRead],
)
def list_action_dispositions(
    proposal_id: str,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> list[MCPWriteDispositionRead]:
    try:
        _authorized_complete_mcp_snapshot(db, proposal_id, principal)
        rows = list_mcp_write_dispositions(db, proposal_id)
        if len(rows) > 1000:
            raise ValueError("MCP disposition history exceeds the bounded review")
        return [MCPWriteDispositionRead.model_validate(row) for row in rows]
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/action-proposals/{proposal_id}/reconciliation-observations/{observation_id}/declared-correlation",
    response_model=MCPDeclaredProviderLookupQualification,
)
def get_action_declared_provider_lookup(
    proposal_id: str,
    observation_id: str,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> MCPDeclaredProviderLookupQualification:
    proposal = _authorized_proposal(db, proposal_id, principal)
    observation = db.get(MCPWriteReconciliationObservation, observation_id)
    if observation is None or observation.proposal_id != proposal.id:
        raise HTTPException(status_code=404, detail="Lookup observation not found")
    lookup = db.get(InvestigationToolCall, observation.lookup_tool_call_id)
    if lookup is None:
        raise HTTPException(status_code=404, detail="Lookup Tool call not found")
    _authorized_investigation(db, lookup.investigation_id, principal)
    try:
        return qualify_declared_provider_lookup(db, proposal, observation_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _visible_provider_lookup_observations(
    db: Session, proposal_id: str, principal: PrincipalContext,
) -> list[MCPWriteReconciliationObservation]:
    _authorized_proposal(db, proposal_id, principal)
    rows = list_mcp_write_lookup_observations(db, proposal_id, limit=1001)
    if len(rows) > 1000:
        raise HTTPException(status_code=409, detail="Provider evidence exceeds the bounded review")
    visible = []
    for row in rows:
        lookup = db.get(InvestigationToolCall, row.lookup_tool_call_id)
        if lookup is None:
            continue
        try:
            _authorized_investigation(db, lookup.investigation_id, principal)
        except HTTPException as exc:
            if exc.status_code != 404:
                raise
        else:
            visible.append(row)
    return visible


@router.get(
    "/action-proposals/{proposal_id}/reconciliation-observations",
    response_model=list[MCPWriteReconciliationObservationRead],
)
def list_action_reconciliation_observations(
    proposal_id: str,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> list[MCPWriteReconciliationObservationRead]:
    return _visible_provider_lookup_observations(db, proposal_id, principal)


@router.post(
    "/action-proposals/{proposal_id}/reconciliation-observations",
    response_model=MCPWriteReconciliationObservationRead,
    status_code=status.HTTP_201_CREATED,
)
def record_action_reconciliation_observation(
    proposal_id: str,
    payload: MCPWriteReconciliationObservationCreate,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> MCPWriteReconciliationObservationRead:
    _authorized_proposal(db, proposal_id, principal)
    lookup = db.get(InvestigationToolCall, payload.lookup_tool_call_id)
    if lookup is None:
        raise HTTPException(status_code=404, detail="Lookup Tool call not found")
    _authorized_investigation(db, lookup.investigation_id, principal)
    try:
        return record_mcp_write_lookup_observation(
            db, proposal_id, payload.lookup_tool_call_id, payload.reason,
            actor=principal,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _visible_provider_lookup_reviews(
    db: Session, proposal_id: str, principal: PrincipalContext,
    observations: list[MCPWriteReconciliationObservation] | None = None,
) -> list[MCPWriteReconciliationReview]:
    visible_ids = {
        row.id for row in (
            observations if observations is not None
            else _visible_provider_lookup_observations(db, proposal_id, principal)
        )
    }
    rows = list_mcp_write_lookup_reviews(db, proposal_id, limit=1001)
    if len(rows) > 1000:
        raise HTTPException(status_code=409, detail="Provider reviews exceed the bounded review")
    return [row for row in rows if row.observation_id in visible_ids]


@router.get(
    "/action-proposals/{proposal_id}/reconciliation-reviews",
    response_model=list[MCPWriteReconciliationReviewRead],
)
def list_action_reconciliation_reviews(
    proposal_id: str,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> list[MCPWriteReconciliationReviewRead]:
    return _visible_provider_lookup_reviews(db, proposal_id, principal)


@router.post(
    "/action-proposals/{proposal_id}/reconciliation-observations/{observation_id}/review",
    response_model=MCPWriteReconciliationReviewRead,
    status_code=status.HTTP_201_CREATED,
)
def review_action_reconciliation_observation(
    proposal_id: str,
    observation_id: str,
    payload: MCPWriteReconciliationReviewCreate,
    principal: PrincipalContext = Depends(require_permissions("changes.approve")),
    db: Session = Depends(db_session),
) -> MCPWriteReconciliationReviewRead:
    _authorized_proposal(db, proposal_id, principal)
    observation = db.get(MCPWriteReconciliationObservation, observation_id)
    if observation is None or observation.proposal_id != proposal_id:
        raise HTTPException(status_code=404, detail="Lookup observation not found")
    lookup = db.get(InvestigationToolCall, observation.lookup_tool_call_id)
    if lookup is None:
        raise HTTPException(status_code=404, detail="Lookup Tool call not found")
    _authorized_investigation(db, lookup.investigation_id, principal)
    try:
        return review_mcp_write_lookup_observation(
            db, proposal_id, observation_id, payload.decision, payload.reason,
            actor=principal,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _authorized_change_plan(
    db: Session,
    proposal_id: str,
    principal: PrincipalContext,
    *,
    lock: bool = False,
) -> GovernedChangePlan:
    _authorized_proposal(db, proposal_id, principal)
    plan = get_change_plan_for_proposal(db, proposal_id, lock=lock)
    if plan is None:
        raise HTTPException(status_code=404, detail="Governed change plan not found")
    return plan


def _authorized_change_plan_by_id(
    db: Session,
    plan_id: str,
    principal: PrincipalContext,
) -> GovernedChangePlan:
    plan = get_change_plan(db, plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Governed change plan not found")
    _authorized_investigation(db, plan.investigation_id, principal)
    return plan


@router.get(
    "/change-risk-policies",
    response_model=list[ChangeRiskPolicyRead],
)
def list_governed_change_risk_policies(
    _: PrincipalContext = Depends(require_permissions("changes.policy.read")),
    db: Session = Depends(db_session),
) -> list[ChangeRiskPolicy]:
    return list_change_risk_policies(db)


@router.patch(
    "/change-risk-policies/{risk_class}",
    response_model=ChangeRiskPolicyRead,
)
def update_governed_change_risk_policy(
    risk_class: str,
    payload: ChangeRiskPolicyUpdate,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.manage")),
    db: Session = Depends(db_session),
) -> ChangeRiskPolicy:
    try:
        return update_change_risk_policy(
            db,
            get_change_risk_policy(db, risk_class, lock=True),
            payload,
            actor=actor.subject,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/change-preapprovals", response_model=list[ChangePreapprovalRead])
def list_reviewed_change_preapprovals(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=100),
    _: PrincipalContext = Depends(require_permissions("changes.policy.read")),
    db: Session = Depends(db_session),
) -> list[ChangePreapprovalPolicy]:
    return list_preapprovals(db, offset=offset, limit=limit)


@router.post("/change-preapprovals", response_model=ChangePreapprovalRead, status_code=201)
def create_reviewed_change_preapproval(
    payload: ChangePreapprovalCreate,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.manage")),
    db: Session = Depends(db_session),
) -> ChangePreapprovalPolicy:
    try:
        return create_preapproval(db, payload, actor=actor)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.patch("/change-preapprovals/{policy_id}", response_model=ChangePreapprovalRead)
def revise_reviewed_change_preapproval(
    policy_id: str,
    payload: ChangePreapprovalUpdate,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.manage")),
    db: Session = Depends(db_session),
) -> ChangePreapprovalPolicy:
    try:
        return revise_preapproval(db, get_preapproval(db, policy_id, lock=True), payload, actor=actor)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/change-preapprovals/{policy_id}/review", response_model=ChangePreapprovalRead)
def review_change_preapproval(
    policy_id: str,
    payload: ChangePreapprovalDecision,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.manage", "changes.approve")),
    db: Session = Depends(db_session),
) -> ChangePreapprovalPolicy:
    try:
        return review_preapproval(db, get_preapproval(db, policy_id, lock=True),
            expected_revision=payload.expected_revision, actor=actor, reason=payload.reason)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/change-preapprovals/{policy_id}/revoke", response_model=ChangePreapprovalRead)
def revoke_change_preapproval(
    policy_id: str,
    payload: ChangePreapprovalDecision,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.manage")),
    db: Session = Depends(db_session),
) -> ChangePreapprovalPolicy:
    try:
        return revoke_preapproval(db, get_preapproval(db, policy_id, lock=True),
            expected_revision=payload.expected_revision, actor=actor, reason=payload.reason)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/change-preapprovals/{policy_id}/change-plans/{plan_id}/preview", response_model=ChangePreapprovalPreview)
def preview_change_preapproval(
    policy_id: str,
    plan_id: str,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.read", "investigations.read")),
    db: Session = Depends(db_session),
) -> dict:
    try:
        policy = get_preapproval(db, policy_id)
        plan = _authorized_change_plan_by_id(db, plan_id, actor)
        return preview_preapproval(db, policy, plan)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/change-preapprovals/{policy_id}/execution-grants", response_model=ChangePreapprovalExecutionGrantPage)
def get_preapproval_execution_grants(
    policy_id: str,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.read")),
    db: Session = Depends(db_session),
) -> dict:
    try:
        require_policy_device_scope(db, get_preapproval(db, policy_id), actor)
        return {"items": list_execution_grants(db, policy_id),
            "execution_enabled": get_settings().enable_reviewed_change_execution}
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/change-preapprovals/{policy_id}/execution-qualification", response_model=ChangePreapprovalQualificationRead)
def get_execution_qualification(
    policy_id: str,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.read", "changes.approve")),
    db: Session = Depends(db_session),
):
    try:
        return read_execution_qualification(db, policy_id, actor=actor)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/change-preapprovals/{policy_id}/execution-grants", response_model=ChangePreapprovalExecutionGrantRead, status_code=201)
def create_preapproval_execution_grant(
    policy_id: str,
    payload: ChangePreapprovalExecutionGrantCreate,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.manage", "changes.approve")),
    db: Session = Depends(db_session),
):
    try:
        return qualify_reviewed_execution(db, policy_id, payload, actor=actor)
    except (LookupError, PermissionError, ValueError, IntegrityError) as exc:
        db.rollback()
        code = 404 if isinstance(exc, LookupError) else 403 if isinstance(exc, PermissionError) else 409
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.post("/change-preapprovals/{policy_id}/execution-grants/{grant_id}/change-plans/{plan_id}/authorize",
    response_model=ChangePreapprovalAuthorizationRead)
def authorize_preapproved_change_plan(
    policy_id: str, grant_id: str, plan_id: str,
    payload: ChangePreapprovalExecutionRequest,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.read", "changes.plan", "investigations.read")),
    db: Session = Depends(db_session),
):
    try:
        if grant_id not in {grant.id for grant in list_execution_grants(db, policy_id)}:
            raise LookupError("Execution grant not found for this policy")
        _authorized_change_plan_by_id(db, plan_id, actor)
        return authorize_reviewed_action(db, grant_id, plan_id, actor=actor,
            expected_plan_hash=payload.expected_plan_hash, expected_action_hash=payload.expected_action_hash)
    except (LookupError, PermissionError, ValueError, IntegrityError) as exc:
        db.rollback()
        code = 404 if isinstance(exc, LookupError) else 403 if isinstance(exc, PermissionError) else 409
        raise HTTPException(status_code=code, detail=str(exc)) from exc


def _rollback_primary_grant(db, policy_id, primary_grant_id, actor):
    policy = get_preapproval(db, policy_id)
    require_policy_device_scope(db, policy, actor)
    primary = _row(db, ChangePreapprovalExecutionGrant, primary_grant_id)
    if primary.policy_id != policy.id:
        raise LookupError("Primary execution grant not found for this policy")
    return primary


@router.get("/change-preapprovals/{policy_id}/execution-grants/{primary_grant_id}/rollback-qualification",
    response_model=RollbackQualificationRead)
def get_rollback_qualification(policy_id: str, primary_grant_id: str,
    min_samples: int = Query(default=5, ge=1, le=200),
    window_minutes: int = Query(default=1440, ge=1, le=1440),
    max_sample_age_seconds: int = Query(default=86400, ge=60, le=86400),
    max_start_delay_seconds: int = Query(default=300, ge=60, le=3600),
    actor: PrincipalContext = Depends(require_permissions("changes.policy.read", "changes.approve")),
    db: Session = Depends(db_session)):
    try:
        _rollback_primary_grant(db, policy_id, primary_grant_id, actor)
        evidence = restoration_evidence(db, primary_grant_id, RollbackQualificationSettings(
            min_samples=min_samples, window_minutes=window_minutes, max_sample_age_seconds=max_sample_age_seconds,
            max_start_delay_seconds=max_start_delay_seconds), actor=actor)
        return {key: evidence[key] for key in ("ready", "required_samples", "matching_samples", "evidence_sha256", "valid_until", "reason")}
    except (LookupError, PermissionError, ValueError) as exc:
        db.rollback()
        raise HTTPException(status_code=404 if isinstance(exc, LookupError) else 403 if isinstance(exc, PermissionError) else 409,
            detail=str(exc)) from exc


@router.get("/change-preapprovals/{policy_id}/execution-grants/{primary_grant_id}/rollback-grants",
    response_model=RollbackExecutionGrantPage)
def get_rollback_grants(policy_id: str, primary_grant_id: str,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.read")), db: Session = Depends(db_session)):
    try:
        _rollback_primary_grant(db, policy_id, primary_grant_id, actor)
        items = list(db.scalars(select(ChangeRollbackExecutionGrant).where(
            ChangeRollbackExecutionGrant.primary_grant_id == primary_grant_id,
            ChangeRollbackExecutionGrant.tenant_id == actor.tenant_id, ChangeRollbackExecutionGrant.region_id == actor.region_id)).all())
        revoked = list(db.scalars(select(ChangeRollbackGrantRevocation.grant_id).where(
            ChangeRollbackGrantRevocation.grant_id.in_([item.id for item in items]),
            ChangeRollbackGrantRevocation.tenant_id == actor.tenant_id, ChangeRollbackGrantRevocation.region_id == actor.region_id)).all())
        return {"items": items, "revoked_grant_ids": revoked, "execution_enabled": get_settings().enable_reviewed_rollback_execution}
    except (LookupError, PermissionError) as exc:
        db.rollback()
        raise HTTPException(status_code=404 if isinstance(exc, LookupError) else 403, detail=str(exc)) from exc


@router.post("/change-preapprovals/{policy_id}/execution-grants/{primary_grant_id}/rollback-grants",
    response_model=RollbackExecutionGrantRead, status_code=201)
def create_rollback_grant(policy_id: str, primary_grant_id: str, payload: RollbackExecutionGrantCreate,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.manage", "changes.approve")),
    db: Session = Depends(db_session)):
    try:
        _rollback_primary_grant(db, policy_id, primary_grant_id, actor)
        return qualify_rollback(db, primary_grant_id, payload, actor=actor)
    except (LookupError, PermissionError, ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(status_code=404 if isinstance(exc, LookupError) else 403 if isinstance(exc, PermissionError) else 409,
            detail=str(exc)) from exc


@router.post("/change-preapprovals/{policy_id}/execution-grants/{primary_grant_id}/rollback-grants/{grant_id}/revoke",
    status_code=204)
def revoke_rollback_grant(policy_id: str, primary_grant_id: str, grant_id: str, payload: RollbackGrantRevocationCreate,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.manage")), db: Session = Depends(db_session)):
    try:
        _rollback_primary_grant(db, policy_id, primary_grant_id, actor)
        if _row(db, ChangeRollbackExecutionGrant, grant_id).primary_grant_id != primary_grant_id:
            raise LookupError("Rollback grant not found for this primary grant")
        revoke_rollback(db, grant_id, actor=actor, reason=payload.reason)
        return Response(status_code=204)
    except (LookupError, PermissionError, ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(status_code=404 if isinstance(exc, LookupError) else 403 if isinstance(exc, PermissionError) else 409,
            detail=str(exc)) from exc


@router.post("/action-proposals/{proposal_id}/rollback-authorizations", response_model=RollbackAuthorizationRead)
def authorize_reviewed_rollback(proposal_id: str, payload: RollbackAuthorizationCreate,
    actor: PrincipalContext = Depends(require_permissions("changes.policy.read", "changes.plan", "investigations.read")),
    db: Session = Depends(db_session)):
    try:
        proposal = _row(db, AgentActionProposal, proposal_id)
        _authorized_change_plan_by_id(db, proposal.rollback_of_change_plan_id, actor)
        return authorize_rollback(db, str(payload.grant_id), proposal.id, actor=actor,
            expected_action_hash=payload.expected_action_hash)
    except (LookupError, PermissionError, ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(status_code=404 if isinstance(exc, LookupError) else 403 if isinstance(exc, PermissionError) else 409,
            detail=str(exc)) from exc


@router.get("/action-proposals/{proposal_id}/rollback-authorization", response_model=RollbackAuthorizationRead | None)
def read_rollback_authorization(proposal_id: str,
    actor: PrincipalContext = Depends(require_permissions("investigations.read")), db: Session = Depends(db_session)):
    try:
        proposal = _row(db, AgentActionProposal, proposal_id)
        _authorized_change_plan_by_id(db, proposal.rollback_of_change_plan_id, actor)
        return rollback_authorization(db, proposal)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/action-proposals/{proposal_id}/reviewed-authorization", response_model=ChangePreapprovalAuthorizationRead | None)
def get_reviewed_action_authorization(
    proposal_id: str,
    actor: PrincipalContext = Depends(require_permissions("investigations.read")),
    db: Session = Depends(db_session),
):
    plan = _authorized_change_plan(db, proposal_id, actor)
    return authorization_for_proposal(db, db.get(AgentActionProposal, plan.action_proposal_id))


@router.get(
    "/change-plans/{plan_id}",
    response_model=GovernedChangePlanRead,
)
def get_governed_change_plan_by_id(
    plan_id: str,
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> GovernedChangePlan:
    return _authorized_change_plan_by_id(db, plan_id, principal)


@router.get(
    "/action-proposals/{proposal_id}/change-plan",
    response_model=GovernedChangePlanRead,
)
def get_governed_change_plan(
    proposal_id: str,
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> GovernedChangePlan:
    return _authorized_change_plan(db, proposal_id, principal)


@router.patch(
    "/action-proposals/{proposal_id}/change-plan/window",
    response_model=GovernedChangePlanRead,
)
def update_governed_change_window(
    proposal_id: str,
    payload: GovernedChangeWindowUpdate,
    actor: PrincipalContext = Depends(require_permissions("changes.plan")),
    db: Session = Depends(db_session),
) -> GovernedChangePlan:
    try:
        return update_change_window(
            db,
            _authorized_change_plan(db, proposal_id, actor, lock=True),
            payload,
            actor=actor.subject,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/action-proposals/{proposal_id}/change-plan/evidence",
    response_model=GovernedChangePlanRead,
)
def attach_governed_change_evidence(
    proposal_id: str,
    payload: GovernedChangeEvidenceAttach,
    actor: PrincipalContext = Depends(require_permissions("changes.plan")),
    db: Session = Depends(db_session),
) -> GovernedChangePlan:
    try:
        return attach_change_evidence(
            db,
            _authorized_change_plan(db, proposal_id, actor, lock=True),
            payload,
            actor=actor.subject,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


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
            _authorized_proposal(db, proposal_id, actor),
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
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    x_icheck_registration_token: Annotated[
        str | None,
        Header(alias="X-iCheck-Registration-Token"),
    ] = None,
) -> AgentWorkerRegistration:
    _require_registration_token(x_icheck_registration_token)
    if "mcp_attestation" in payload.capabilities:
        raise HTTPException(
            status_code=422,
            detail=(
                "mcp_attestation is reserved for the dedicated "
                "/api/v1/mcp/attestors/register trust boundary"
            ),
        )
    try:
        worker, access_token = register_agent_worker(
            db,
            payload,
            peer_identity=peer_identity,
            mtls_mode=get_settings().worker_mtls_mode,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return AgentWorkerRegistration(
        worker=AgentWorkerRead.model_validate(worker),
        access_token=access_token,
    )


@router.get("/workers", response_model=list[AgentWorkerRead])
def list_agent_workers(
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_permissions("agent.workers.read")
    ),
    db: Session = Depends(db_session),
) -> list[AgentWorker]:
    return list(
        db.scalars(
            select(AgentWorker).order_by(AgentWorker.name).limit(limit)
        ).all()
    )


@router.post(
    "/workers/{worker_id}/mtls-rotation",
    response_model=WorkerMTLSRotationRead,
)
def stage_agent_worker_mtls_rotation_route(
    worker_id: str,
    payload: WorkerMTLSRotationCreate,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(db_session),
) -> WorkerMTLSRotationRead:
    try:
        return stage_worker_mtls_rotation(
            db,
            _agent_worker(db, worker_id),
            payload,
            kind="agent",
            actor=principal.subject,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/workers/{worker_id}/mtls-rotation/cancel",
    response_model=WorkerMTLSStateRead,
)
def cancel_agent_worker_mtls_rotation_route(
    worker_id: str,
    payload: WorkerMTLSLifecycleAction,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(db_session),
) -> WorkerMTLSStateRead:
    try:
        return cancel_worker_mtls_rotation(
            db,
            _agent_worker(db, worker_id),
            payload,
            kind="agent",
            actor=principal.subject,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/workers/{worker_id}/mtls-revoke",
    response_model=WorkerMTLSStateRead,
)
def revoke_agent_worker_mtls_identity_route(
    worker_id: str,
    payload: WorkerMTLSLifecycleAction,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(db_session),
) -> WorkerMTLSStateRead:
    try:
        return revoke_worker_mtls_identity(
            db,
            _agent_worker(db, worker_id),
            payload,
            kind="agent",
            actor=principal.subject,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/workers/{worker_id}/heartbeat",
    response_model=AgentWorkerRead,
)
def heartbeat_agent_worker_route(
    worker_id: str,
    payload: AgentWorkerHeartbeat,
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentWorker:
    worker = _agent_worker(db, worker_id)
    _authorize_agent_worker(db, worker, authorization, peer_identity)
    if payload.capabilities and "mcp_attestation" in payload.capabilities:
        raise HTTPException(
            status_code=422,
            detail="mcp_attestation capability cannot be added through heartbeat",
        )
    if (
        payload.labels
        and payload.labels.get("role") == "mcp_attestor"
        and (worker.labels or {}).get("role") != "mcp_attestor"
    ):
        raise HTTPException(
            status_code=422,
            detail="MCP attestor role cannot be added through heartbeat",
        )
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
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> list[AgentExecutionAssignment]:
    worker = _agent_worker(db, worker_id)
    _authorize_agent_worker(db, worker, authorization, peer_identity)
    try:
        return claim_agent_executions(db, worker, payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/executions/{execution_id}", response_model=AgentExecutionRead)
def get_agent_execution_route(
    execution_id: str,
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> AgentExecution:
    return _authorized_execution(db, execution_id, principal)


@router.post(
    "/executions/{execution_id}/lease",
    response_model=AgentExecutionRead,
)
def renew_agent_execution_lease_route(
    execution_id: str,
    payload: AgentExecutionLeaseRenew,
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentExecution:
    execution = _execution(db, execution_id)
    if execution.worker_id is None:
        raise HTTPException(status_code=409, detail="Execution has no worker")
    worker = _agent_worker(db, execution.worker_id)
    _authorize_agent_worker(db, worker, authorization, peer_identity)
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
    "/executions/{execution_id}/progress",
    response_model=AgentExecutionEventRead,
)
def record_agent_execution_progress_route(
    execution_id: str,
    payload: AgentExecutionProgress,
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentExecutionEvent:
    execution = _execution(db, execution_id)
    if execution.worker_id is None:
        raise HTTPException(status_code=409, detail="Execution has no worker")
    worker = _agent_worker(db, execution.worker_id)
    _authorize_agent_worker(db, worker, authorization, peer_identity)
    try:
        return record_agent_execution_progress(
            db,
            execution_id,
            worker=worker,
            payload=payload,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/executions/{execution_id}/runtime/bootstrap",
    response_model=AgentRuntimeBootstrapRead,
)
def bootstrap_agent_runtime_route(
    execution_id: str,
    payload: AgentRuntimeBootstrapRequest,
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentRuntimeBootstrapRead:
    _, worker = _authorize_execution_worker(
        db,
        execution_id,
        authorization,
        peer_identity,
    )
    try:
        return runtime_bootstrap(
            db,
            execution_id,
            worker=worker,
            lease_token=payload.lease_token,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/executions/{execution_id}/runtime/checkpoints/get",
    response_model=AgentRuntimeCheckpointTupleRead | None,
)
def get_agent_runtime_checkpoint_route(
    execution_id: str,
    payload: AgentRuntimeCheckpointGet,
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentRuntimeCheckpointTupleRead | None:
    _, worker = _authorize_execution_worker(
        db,
        execution_id,
        authorization,
        peer_identity,
    )
    try:
        return checkpoint_get(db, execution_id, worker=worker, payload=payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/executions/{execution_id}/runtime/checkpoints/list",
    response_model=list[AgentRuntimeCheckpointTupleRead],
)
def list_agent_runtime_checkpoints_route(
    execution_id: str,
    payload: AgentRuntimeCheckpointList,
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> list[AgentRuntimeCheckpointTupleRead]:
    _, worker = _authorize_execution_worker(
        db,
        execution_id,
        authorization,
        peer_identity,
    )
    try:
        return checkpoint_list(db, execution_id, worker=worker, payload=payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/executions/{execution_id}/runtime/checkpoints/put",
    response_model=AgentRuntimeCheckpointPutRead,
)
def put_agent_runtime_checkpoint_route(
    execution_id: str,
    payload: AgentRuntimeCheckpointPut,
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentRuntimeCheckpointPutRead:
    _, worker = _authorize_execution_worker(
        db,
        execution_id,
        authorization,
        peer_identity,
    )
    try:
        return checkpoint_put(db, execution_id, worker=worker, payload=payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/executions/{execution_id}/runtime/checkpoints/writes",
    status_code=status.HTTP_204_NO_CONTENT,
)
def put_agent_runtime_checkpoint_writes_route(
    execution_id: str,
    payload: AgentRuntimeCheckpointWrites,
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> Response:
    _, worker = _authorize_execution_worker(
        db,
        execution_id,
        authorization,
        peer_identity,
    )
    try:
        checkpoint_writes(db, execution_id, worker=worker, payload=payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/executions/{execution_id}/runtime/reason",
    response_model=AgentRuntimeReasonRead,
)
def execute_agent_runtime_reason_route(
    execution_id: str,
    payload: AgentRuntimeReasonRequest,
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentRuntimeReasonRead:
    _, worker = _authorize_execution_worker(
        db,
        execution_id,
        authorization,
        peer_identity,
    )
    try:
        return execute_runtime_reason(
            db,
            execution_id,
            worker=worker,
            payload=payload,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ModelReasonerUnavailable as exc:
        # A provider failure is a retained Agent outcome, not an opaque API 500.
        from .langgraph_runtime import GraphDecision
        from .ai_failure_diagnostics import diagnostic_text
        reason = diagnostic_text(exc.diagnostic) if exc.diagnostic else str(exc)[:3500]
        return AgentRuntimeReasonRead(protocol_version=payload.protocol_version,
            operation_id=payload.operation_id, decision=GraphDecision(action="escalate",
                escalation_reason=reason, token_usage=exc.token_usage).model_dump(mode="json"))


@router.post(
    "/executions/{execution_id}/runtime/tool",
    response_model=AgentRuntimeToolRead,
)
def execute_agent_runtime_tool_route(
    execution_id: str,
    payload: AgentRuntimeToolRequest,
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentRuntimeToolRead:
    _, worker = _authorize_execution_worker(
        db,
        execution_id,
        authorization,
        peer_identity,
    )
    try:
        return execute_runtime_tool(
            db,
            execution_id,
            worker=worker,
            payload=payload,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/executions/{execution_id}/cancel",
    response_model=AgentExecutionRead,
)
def cancel_agent_execution_route(
    execution_id: str,
    payload: AgentExecutionCancel,
    principal: PrincipalContext = Depends(
        require_permissions("investigations.cancel")
    ),
    db: Session = Depends(db_session),
) -> AgentExecution:
    trusted_payload = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return cancel_agent_execution(
            db,
            _authorized_execution(db, execution_id, principal),
            trusted_payload,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/executions/{execution_id}/complete",
    response_model=AgentExecutionRead,
)
def complete_agent_execution_route(
    execution_id: str,
    payload: AgentExecutionComplete,
    peer_identity: WorkerPeer,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> AgentExecution:
    execution = _execution(db, execution_id)
    worker_id = execution.worker_id or execution.completion_worker_id
    if worker_id is None:
        raise HTTPException(status_code=409, detail="Execution has no worker")
    worker = _agent_worker(db, worker_id)
    _authorize_agent_worker(db, worker, authorization, peer_identity)
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
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> list[AgentExecutionEvent]:
    _authorized_execution(db, execution_id, principal)
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
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
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
        set_session_namespace(db, principal.tenant_id, principal.region_id)
        _authorized_execution(db, execution_id, principal)

    def event_stream():
        nonlocal cursor
        deadline = time.monotonic() + timeout_seconds
        last_keepalive = time.monotonic()
        while time.monotonic() < deadline:
            with SessionLocal() as db:
                set_session_namespace(db, principal.tenant_id, principal.region_id)
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
    principal: PrincipalContext = Depends(
        require_permissions("agent.runtime.admin")
    ),
    db: Session = Depends(db_session),
) -> InvestigationCheckpoint:
    trusted_payload = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return append_investigation_checkpoint(
            db,
            _authorized_investigation(db, investigation_id, principal),
            trusted_payload,
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
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> list[InvestigationCheckpoint]:
    _authorized_investigation(db, investigation_id, principal)
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
    principal: PrincipalContext = Depends(
        require_permissions("agent.runtime.admin")
    ),
    db: Session = Depends(db_session),
) -> InvestigationEvidence:
    return add_evidence_reference(
        db,
        _authorized_investigation(db, investigation_id, principal),
        payload,
    )


@router.get(
    "/investigations/{investigation_id}/evidence",
    response_model=list[InvestigationEvidenceRead],
)
def list_evidence(
    investigation_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> list[InvestigationEvidence]:
    _authorized_investigation(db, investigation_id, principal)
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
    principal: PrincipalContext = Depends(
        require_permissions("agent.runtime.admin")
    ),
    db: Session = Depends(db_session),
) -> InvestigationToolCall:
    try:
        return create_tool_call(
            db,
            _authorized_investigation(db, investigation_id, principal),
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
    principal: PrincipalContext = Depends(
        require_permissions("investigations.read")
    ),
    db: Session = Depends(db_session),
) -> list[InvestigationToolCallRead]:
    _authorized_investigation(db, investigation_id, principal)
    rows = db.execute(select(InvestigationToolCall, AgentToolRegistration.name)
        .join(AgentToolRegistration, AgentToolRegistration.id == InvestigationToolCall.tool_id)
        .where(InvestigationToolCall.investigation_id == investigation_id)
        .order_by(InvestigationToolCall.created_at.desc()).limit(limit)).all()
    # Display metadata, not reconstructed execution provenance or new authority.
    return [InvestigationToolCallRead.model_validate(row).model_copy(update={"tool_name": name})
            for row, name in rows]


@router.post(
    "/tool-calls/{call_id}/complete",
    response_model=InvestigationToolCallRead,
)
def complete_tool_call_route(
    call_id: str,
    payload: InvestigationToolCallComplete,
    principal: PrincipalContext = Depends(
        require_permissions("agent.runtime.admin")
    ),
    db: Session = Depends(db_session),
) -> InvestigationToolCall:
    call = _tool_call(db, call_id)
    _authorized_investigation(db, call.investigation_id, principal)
    try:
        return complete_tool_call(db, call, payload)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
