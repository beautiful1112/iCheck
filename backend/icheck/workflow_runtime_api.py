from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .agent_schemas import InvestigationStartResult
from .auth import require_global_permissions, require_permissions
from .database import get_db
from .services.authorization_scope import (
    request_actor,
    require_requested_investigation_scope,
)
from .services.control_plane_auth import PrincipalContext
from .services.workflow_runtime import (
    create_situation_integration_binding,
    create_workflow_schedule_activation,
    create_workflow_trigger_activation,
    create_workflow_investigation,
    disable_situation_integration_binding,
    disable_workflow_schedule_activation,
    disable_workflow_trigger_activation,
    list_published_workflows,
    published_workflow_read,
    update_workflow_schedule_exclusions,
    workflow_version,
)
from .services.situation_reconciliation import (
    WebhookAuthenticationError,
    WebhookConflictError,
    reconcile_situation_webhook,
)
from .services.report_delivery_receipts import export_report_delivery_receipt, report_delivery_receipt_visible
from .models import (
    AgentActionProposal,
    AgentToolRegistration,
    Investigation,
    ReportDeliveryReceipt,
    SituationIntegrationBinding,
    SituationIntegrationEvent,
    SituationIntegrationInboundEvent,
    SituationIntegrationRemoteReference,
    WorkflowScheduleActivation,
    WorkflowScheduleEvent,
    WorkflowTriggerActivation,
    WorkflowTriggerEvent,
)
from .workflow_runtime_schemas import (
    PublishedWorkflowRead,
    ReportDeliveryReceiptRead,
    ReportDeliveryReceiptExport,
    SituationIntegrationBindingCreate,
    SituationIntegrationBindingRead,
    SituationIntegrationEventRead,
    SituationIntegrationInboundEventRead,
    SituationIntegrationRemoteReferenceRead,
    SituationIntegrationWebhookAck,
    WorkflowInvestigationCreate,
    WorkflowScheduleActivationCreate,
    WorkflowScheduleActivationRead,
    WorkflowScheduleEventRead,
    WorkflowScheduleExclusionsUpdate,
    WorkflowTriggerActivationAction,
    WorkflowTriggerActivationCreate,
    WorkflowTriggerActivationRead,
    WorkflowTriggerEventRead,
)


router = APIRouter(prefix="/api/v1/workflow-runtime", tags=["workflow-runtime"])
DBSession = Annotated[Session, Depends(get_db)]


@router.get("/workflows", response_model=list[PublishedWorkflowRead])
def list_published_workflows_route(
    db: DBSession,
    _: PrincipalContext = Depends(require_permissions("investigations.create")),
) -> list[PublishedWorkflowRead]:
    return [published_workflow_read(item) for item in list_published_workflows(db)]


@router.post(
    "/workflows/{version_id}/investigations",
    response_model=InvestigationStartResult,
)
def run_published_workflow_route(
    version_id: str,
    payload: WorkflowInvestigationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("investigations.create")
    ),
) -> dict[str, object]:
    require_requested_investigation_scope(db, principal, payload.scope)
    try:
        investigation, checkpoint = create_workflow_investigation(
            db,
            workflow_version(db, version_id),
            payload,
            principal=principal,
            actor=request_actor(principal, payload.actor),
        )
        return {"investigation": investigation, "checkpoint": checkpoint}
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/workflows/{version_id}/trigger-activation",
    response_model=WorkflowTriggerActivationRead,
    status_code=status.HTTP_201_CREATED,
)
def activate_workflow_trigger_route(
    version_id: str,
    payload: WorkflowTriggerActivationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> WorkflowTriggerActivation:
    try:
        return create_workflow_trigger_activation(
            db,
            workflow_version(db, version_id),
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/trigger-activations",
    response_model=list[WorkflowTriggerActivationRead],
)
def list_workflow_trigger_activations_route(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[WorkflowTriggerActivation]:
    return list(
        db.scalars(
            select(WorkflowTriggerActivation)
            .order_by(WorkflowTriggerActivation.created_at.desc())
            .limit(limit)
        ).all()
    )


@router.post(
    "/trigger-activations/{activation_id}/disable",
    response_model=WorkflowTriggerActivationRead,
)
def disable_workflow_trigger_route(
    activation_id: str,
    payload: WorkflowTriggerActivationAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> WorkflowTriggerActivation:
    activation = db.get(WorkflowTriggerActivation, activation_id)
    if activation is None:
        raise HTTPException(status_code=404, detail="Workflow trigger not found")
    return disable_workflow_trigger_activation(
        db,
        activation,
        actor=request_actor(principal, payload.actor),
    )


@router.get(
    "/trigger-events",
    response_model=list[WorkflowTriggerEventRead],
)
def list_workflow_trigger_events_route(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[WorkflowTriggerEvent]:
    return list(
        db.scalars(
            select(WorkflowTriggerEvent)
            .order_by(WorkflowTriggerEvent.created_at.desc())
            .limit(limit)
        ).all()
    )


@router.post(
    "/workflows/{version_id}/situation-integration",
    response_model=SituationIntegrationBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def create_situation_integration_route(
    version_id: str,
    payload: SituationIntegrationBindingCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> SituationIntegrationBinding:
    try:
        return create_situation_integration_binding(
            db,
            workflow_version(db, version_id),
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/situation-integrations",
    response_model=list[SituationIntegrationBindingRead],
)
def list_situation_integrations_route(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[SituationIntegrationBinding]:
    return list(
        db.scalars(
            select(SituationIntegrationBinding)
            .order_by(SituationIntegrationBinding.created_at.desc())
            .limit(limit)
        ).all()
    )


@router.post(
    "/situation-integrations/{binding_id}/disable",
    response_model=SituationIntegrationBindingRead,
)
def disable_situation_integration_route(
    binding_id: str,
    payload: WorkflowTriggerActivationAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> SituationIntegrationBinding:
    binding = db.get(SituationIntegrationBinding, binding_id)
    if binding is None:
        raise HTTPException(status_code=404, detail="Situation integration not found")
    return disable_situation_integration_binding(
        db,
        binding,
        actor=request_actor(principal, payload.actor),
    )


@router.get(
    "/situation-integration-events",
    response_model=list[SituationIntegrationEventRead],
)
def list_situation_integration_events_route(
    db: DBSession,
    binding_id: str | None = Query(default=None),
    situation_id: str | None = Query(default=None),
    event_status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[SituationIntegrationEvent]:
    query = select(SituationIntegrationEvent)
    if binding_id is not None:
        query = query.where(SituationIntegrationEvent.binding_id == binding_id)
    if situation_id is not None:
        query = query.where(SituationIntegrationEvent.situation_id == situation_id)
    if event_status is not None:
        if event_status not in {"pending", "processing", "succeeded", "failed"}:
            raise HTTPException(status_code=422, detail="Invalid integration status")
        query = query.where(SituationIntegrationEvent.status == event_status)
    return list(
        db.scalars(
            query.order_by(SituationIntegrationEvent.created_at.desc()).limit(limit)
        ).all()
    )


@router.get(
    "/situation-integration-references",
    response_model=list[SituationIntegrationRemoteReferenceRead],
)
def list_situation_integration_references_route(
    db: DBSession,
    binding_id: str | None = Query(default=None),
    situation_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[SituationIntegrationRemoteReference]:
    query = select(SituationIntegrationRemoteReference)
    if binding_id is not None:
        query = query.where(
            SituationIntegrationRemoteReference.binding_id == binding_id
        )
    if situation_id is not None:
        query = query.where(
            SituationIntegrationRemoteReference.situation_id == situation_id
        )
    return list(
        db.scalars(
            query.order_by(
                SituationIntegrationRemoteReference.updated_at.desc()
            ).limit(limit)
        ).all()
    )


@router.get(
    "/situation-integration-inbound-events",
    response_model=list[SituationIntegrationInboundEventRead],
)
def list_situation_integration_inbound_events_route(
    db: DBSession,
    binding_id: str | None = Query(default=None),
    reference_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[SituationIntegrationInboundEvent]:
    query = select(SituationIntegrationInboundEvent)
    if binding_id is not None:
        query = query.where(
            SituationIntegrationInboundEvent.binding_id == binding_id
        )
    if reference_id is not None:
        query = query.where(
            SituationIntegrationInboundEvent.reference_id == reference_id
        )
    return list(
        db.scalars(
            query.order_by(
                SituationIntegrationInboundEvent.received_at.desc()
            ).limit(limit)
        ).all()
    )


@router.post(
    "/situation-integrations/{binding_id}/webhook",
    response_model=SituationIntegrationWebhookAck,
)
async def reconcile_situation_integration_webhook_route(
    binding_id: str,
    request: Request,
    db: DBSession,
    x_icheck_timestamp: Annotated[
        str | None, Header(alias="X-Icheck-Timestamp")
    ] = None,
    x_icheck_event_id: Annotated[
        str | None, Header(alias="X-Icheck-Event-Id")
    ] = None,
    x_icheck_key_id: Annotated[
        str | None, Header(alias="X-Icheck-Key-Id")
    ] = None,
    x_icheck_signature: Annotated[
        str | None, Header(alias="X-Icheck-Signature")
    ] = None,
) -> SituationIntegrationWebhookAck:
    if not all(
        (
            x_icheck_timestamp,
            x_icheck_event_id,
            x_icheck_key_id,
            x_icheck_signature,
        )
    ):
        raise HTTPException(status_code=401, detail="Webhook signature is required")
    binding = db.get(SituationIntegrationBinding, binding_id)
    if binding is None:
        raise HTTPException(status_code=404, detail="Situation integration not found")
    try:
        return reconcile_situation_webhook(
            db,
            binding,
            raw_body=await request.body(),
            timestamp=x_icheck_timestamp,
            provider_event_id=x_icheck_event_id,
            key_id=x_icheck_key_id,
            signature=x_icheck_signature,
        )
    except WebhookAuthenticationError as exc:
        raise HTTPException(status_code=401, detail="Webhook authentication failed") from exc
    except WebhookConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/workflows/{version_id}/schedule-activation",
    response_model=WorkflowScheduleActivationRead,
    status_code=status.HTTP_201_CREATED,
)
def activate_workflow_schedule_route(
    version_id: str,
    payload: WorkflowScheduleActivationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> WorkflowScheduleActivation:
    try:
        return create_workflow_schedule_activation(
            db,
            workflow_version(db, version_id),
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/schedule-activations",
    response_model=list[WorkflowScheduleActivationRead],
)
def list_workflow_schedule_activations_route(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[WorkflowScheduleActivation]:
    return list(
        db.scalars(
            select(WorkflowScheduleActivation)
            .order_by(WorkflowScheduleActivation.created_at.desc())
            .limit(limit)
        ).all()
    )


@router.post(
    "/schedule-activations/{activation_id}/disable",
    response_model=WorkflowScheduleActivationRead,
)
def disable_workflow_schedule_route(
    activation_id: str,
    payload: WorkflowTriggerActivationAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> WorkflowScheduleActivation:
    activation = db.get(WorkflowScheduleActivation, activation_id)
    if activation is None:
        raise HTTPException(status_code=404, detail="Workflow schedule not found")
    return disable_workflow_schedule_activation(
        db,
        activation,
        actor=request_actor(principal, payload.actor),
    )


@router.post(
    "/schedule-activations/{activation_id}/exclusions",
    response_model=WorkflowScheduleActivationRead,
)
def update_workflow_schedule_exclusions_route(
    activation_id: str,
    payload: WorkflowScheduleExclusionsUpdate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> WorkflowScheduleActivation:
    try:
        return update_workflow_schedule_exclusions(
            db,
            activation_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/schedule-events",
    response_model=list[WorkflowScheduleEventRead],
)
def list_workflow_schedule_events_route(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[WorkflowScheduleEventRead]:
    rows = db.execute(
        select(
            WorkflowScheduleEvent,
            WorkflowScheduleActivation.report_artifact_version_id,
            WorkflowScheduleActivation.report_delivery_tool_name,
            Investigation.id,
            Investigation.status,
            ReportDeliveryReceipt.id,
            ReportDeliveryReceipt.verification_tool_call_id,
        )
        .join(
            WorkflowScheduleActivation,
            WorkflowScheduleActivation.id == WorkflowScheduleEvent.activation_id,
        )
        .outerjoin(
            Investigation,
            Investigation.workflow_schedule_event_id == WorkflowScheduleEvent.id,
        )
        .outerjoin(
            ReportDeliveryReceipt,
            ReportDeliveryReceipt.schedule_event_id == WorkflowScheduleEvent.id,
        )
        .order_by(WorkflowScheduleEvent.scheduled_for.desc())
        .limit(limit)
    ).all()
    investigation_ids = {row[3] for row in rows if row[3] is not None}
    attempts: dict[tuple[str, str], list[str | None]] = {}
    if investigation_ids:
        for investigation_id, tool_name, call_id in db.execute(
            select(
                AgentActionProposal.investigation_id,
                AgentToolRegistration.name,
                AgentActionProposal.tool_call_id,
            )
            .join(AgentToolRegistration, AgentToolRegistration.id == AgentActionProposal.tool_id)
            .where(
                AgentActionProposal.investigation_id.in_(investigation_ids),
                AgentActionProposal.execution_started_at.is_not(None),
            )
        ):
            attempts.setdefault((investigation_id, tool_name), []).append(call_id)
    result: list[WorkflowScheduleEventRead] = []
    for row in rows:
        (
            event, report_id, delivery_tool_name, investigation_id,
            investigation_status, receipt_id, verification_id,
        ) = row
        matched_attempts = attempts.get((investigation_id, delivery_tool_name), [])
        delivery_attempted = bool(matched_attempts)
        delivery_state = None
        if report_id is not None:
            if receipt_id is not None:
                delivery_state = "verified" if verification_id else "legacy_unverified"
            elif investigation_id is None:
                delivery_state = "not_dispatched"
            elif delivery_attempted:
                # A started external write may have reached the recipient even
                # when no verified receipt survived. Never suggest a resend.
                delivery_state = "reconciliation_required"
            elif investigation_status in {"completed", "failed", "escalated", "cancelled"}:
                delivery_state = "unverified"
            else:
                delivery_state = "pending"
        result.append(
            WorkflowScheduleEventRead.model_validate(event).model_copy(update={
                "investigation_id": investigation_id,
                "investigation_status": investigation_status,
                "report_delivery_tool_call_id": (
                    matched_attempts[0]
                    if delivery_state == "reconciliation_required" and len(matched_attempts) == 1
                    else None
                ),
                "report_delivery_state": delivery_state,
            })
        )
    return result


@router.get(
    "/report-delivery-receipts",
    response_model=list[ReportDeliveryReceiptRead],
)
def list_report_delivery_receipts_route(
    db: DBSession,
    response: Response,
    activation_id: str | None = Query(default=None),
    provider_key: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[ReportDeliveryReceipt]:
    query = select(ReportDeliveryReceipt)
    if activation_id is not None:
        query = query.where(
            ReportDeliveryReceipt.activation_id == activation_id
        )
    if provider_key is not None:
        query = query.where(ReportDeliveryReceipt.provider_key == provider_key)
    candidates = list(
        db.scalars(
            query.order_by(
                ReportDeliveryReceipt.delivered_at.desc(),
                ReportDeliveryReceipt.id.desc(),
            ).limit(limit)
        ).all()
    )
    response.headers["Cache-Control"] = "no-store"
    try:
        return [receipt for receipt in candidates if report_delivery_receipt_visible(db, receipt, principal)]
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="Report delivery receipt provenance is invalid") from exc


@router.get(
    "/report-delivery-receipts/{receipt_id}/export",
    response_model=ReportDeliveryReceiptExport,
    response_model_exclude_unset=True,
)
def export_report_delivery_receipt_route(
    receipt_id: str,
    db: DBSession,
    response: Response,
    principal: PrincipalContext = Depends(require_global_permissions("capabilities.read")),
) -> dict[str, object]:
    try:
        response.headers["Cache-Control"] = "no-store"
        return export_report_delivery_receipt(db, receipt_id, principal=principal)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="Report delivery receipt provenance is invalid") from exc
