from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import current_principal, require_global_permissions, require_permissions
from .ai_schemas import (
    AIAuthoringQuotaSnapshotRead,
    AIAuthoringQuotaReservationPage,
    AIAuthoringQuotaReservationRead,
    AIAuthoringQuotaUpdate,
    AIQuotaReconciliationCreate,
    AIQuotaReconciliationPage,
    AIQuotaReconciliationRead,
    AIQuotaReconciliationReview,
    AIQuotaOrphanCandidatePage,
    AIQuotaOrphanCandidateRead,
    AIQuotaOrphanCaseCreate,
    AIQuotaOrphanCasePage,
    AIQuotaOrphanCaseRead,
    AIQuotaOrphanCaseReview,
    AIQuotaSettlementConflictPage,
    AIQuotaSettlementConflictRead,
    AIQuotaSupplementCreate,
    AIQuotaSupplementPage,
    AIQuotaSupplementRead,
    AIQuotaSupplementReview,
    AgentProfileCreate,
    AgentProfileRead,
    AgentProfileUpdate,
    AIModelCreate,
    AIModelRead,
    AIModelRouteCreate,
    AIModelRouteRead,
    AIProviderCreate,
    AIProviderHealth,
    AIProviderRead,
    AIProviderUpdate,
    AIProviderRuntimeSettingsUpdate,
)
from .config import get_settings
from .database import get_db
from .models import AIModelConfig, AIModelRoute, AIProviderConfig, AgentProfile
from .services.agent_profiles import (
    create_agent_profile,
    get_agent_profile,
    list_agent_profiles,
    update_agent_profile,
)
from .services.ai_settings import (
    check_ai_provider,
    create_ai_model,
    create_ai_model_route as create_ai_model_route_service,
    create_ai_provider,
    get_ai_provider,
    update_ai_provider,
)
from .services.ai_authoring_quota import (
    AuthoringQuotaConflict,
    authoring_quota_snapshot,
    configure_authoring_quota,
    list_authoring_reservations,
    list_authoring_settlement_conflicts,
)
from .services.ai_quota_reconciliation import (
    list_quota_reconciliations,
    propose_quota_reconciliation,
    review_quota_reconciliation,
)
from .services.ai_quota_orphan_recovery import (
    list_orphan_candidates,
    list_orphan_cases,
    propose_orphan_closure,
    review_orphan_closure,
)
from .services.ai_quota_supplements import (
    list_supplement_candidates,
    list_supplement_cases,
    propose_supplement,
    review_supplement,
)
from .services.audit import record_audit_event
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext


router = APIRouter(prefix="/api/v1/ai", tags=["ai-settings"])
settings = get_settings()


db_session = get_db


@router.put("/providers/{provider_id}/runtime-settings", response_model=AIProviderRead)
def update_provider_runtime_settings(provider_id: str, payload: AIProviderRuntimeSettingsUpdate, response: Response,
        principal: PrincipalContext = Depends(require_permissions("ai.manage")), db: Session = Depends(db_session)):
    from .services.ai_settings import update_ai_provider_runtime_settings, AIProviderRuntimeConflict
    if get_settings().control_plane_auth_mode != "disabled" and principal.principal_type != "user":
        raise HTTPException(status_code=403, detail="A human AI administrator is required")
    response.headers["Cache-Control"] = "no-store"
    try:
        return update_ai_provider_runtime_settings(db, provider_id, payload, actor=principal.subject)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except AIProviderRuntimeConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


@router.get("/authoring-quota", response_model=AIAuthoringQuotaSnapshotRead)
def read_authoring_quota_route(
    actor: str | None = Query(default=None, max_length=255),
    principal: PrincipalContext = Depends(current_principal),
    db: Session = Depends(db_session),
) -> AIAuthoringQuotaSnapshotRead:
    if not (
        principal.permits("assets.activate")
        or principal.permits("investigations.create")
        or principal.permits("ai.manage")
        or (
            principal.permits("capabilities.manage")
            and principal.authorization_scope.get("all") is True
        )
    ):
        record_audit_event(
            db, event_type="auth.permission.denied", actor_type=principal.principal_type,
            actor_id=principal.subject, entity_type="api_route",
            entity_id="/api/v1/ai/authoring-quota", outcome="denied",
            details={"method": "GET", "required_permissions": [
                "assets.activate", "investigations.create", "ai.manage",
                "capabilities.manage",
            ]},
        )
        db.commit()
        raise HTTPException(status_code=403, detail="AI model-call permission is required")
    return AIAuthoringQuotaSnapshotRead.model_validate(
        authoring_quota_snapshot(db, actor=request_actor(principal, actor))
    )


@router.put("/authoring-quota", response_model=AIAuthoringQuotaSnapshotRead)
def configure_authoring_quota_route(
    payload: AIAuthoringQuotaUpdate,
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIAuthoringQuotaSnapshotRead:
    try:
        return AIAuthoringQuotaSnapshotRead.model_validate(configure_authoring_quota(
            db, actor=principal.subject, expected_revision=payload.expected_revision,
            daily_token_limit=payload.daily_token_limit,
            actor_daily_token_limit=payload.actor_daily_token_limit,
            reason=payload.reason,
        ))
    except AuthoringQuotaConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/authoring-quota/reservations",
    response_model=AIAuthoringQuotaReservationPage,
)
def list_authoring_quota_reservations_route(
    scope: Literal["mine", "namespace"] = "mine",
    state: Literal["attention", "pending", "uncertain", "all"] = "attention",
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=36),
    source_entity_id: str | None = Query(default=None, max_length=36),
    older_than_minutes: int | None = Query(default=None, ge=1, le=525_600),
    actor: str | None = Query(default=None, max_length=255),
    principal: PrincipalContext = Depends(current_principal),
    db: Session = Depends(db_session),
) -> AIAuthoringQuotaReservationPage:
    global_admin = (
        principal.permits("ai.manage")
        and principal.authorization_scope.get("all") is True
    )
    may_read_own = (
        principal.permits("assets.activate")
        or principal.permits("investigations.create")
        or principal.permits("ai.manage")
        or (
            principal.permits("capabilities.manage")
            and principal.authorization_scope.get("all") is True
        )
    )
    if (scope == "namespace" and not global_admin) or not may_read_own:
        record_audit_event(
            db, event_type="auth.permission.denied", actor_type=principal.principal_type,
            actor_id=principal.subject, entity_type="api_route",
            entity_id="/api/v1/ai/authoring-quota/reservations", outcome="denied",
            details={"method": "GET", "requested_scope": scope},
        )
        db.commit()
        raise HTTPException(status_code=403, detail="AI quota reservation access denied")
    try:
        rows, next_cursor = list_authoring_reservations(
            db, actor=None if scope == "namespace" else request_actor(principal, actor),
            state=state, limit=limit, cursor=cursor,
            source_entity_id=source_entity_id,
            older_than_minutes=older_than_minutes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AIAuthoringQuotaReservationPage(
        items=[AIAuthoringQuotaReservationRead.model_validate(row) for row in rows],
        next_cursor=next_cursor,
    )


@router.get(
    "/authoring-quota/settlement-conflicts",
    response_model=AIQuotaSettlementConflictPage,
)
def list_ai_quota_settlement_conflicts_route(
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=36),
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIQuotaSettlementConflictPage:
    if principal.principal_id is None or principal.principal_type != "user":
        raise HTTPException(status_code=403, detail="Authenticated global AI administration is required")
    try:
        rows, next_cursor = list_authoring_settlement_conflicts(
            db, limit=limit, cursor=cursor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AIQuotaSettlementConflictPage(
        items=[AIQuotaSettlementConflictRead(
            id=conflict.id,
            reservation_id=conflict.reservation_id,
            actor=receipt.actor,
            period_start=receipt.period_start,
            source_entity_type=receipt.source_entity_type,
            source_entity_id=receipt.source_entity_id,
            source_step=receipt.source_step,
            original_charged_tokens=conflict.settled_charged_tokens_snapshot,
            effective_charged_tokens=receipt.effective_charged_tokens,
            settled_known_tokens_snapshot=conflict.settled_known_tokens_snapshot,
            settled_external_charge_unknown_snapshot=conflict.settled_external_charge_unknown_snapshot,
            reported_known_tokens=conflict.reported_known_tokens,
            reported_external_charge_unknown=conflict.reported_external_charge_unknown,
            recorded_at=conflict.recorded_at,
        ) for conflict, receipt in rows],
        next_cursor=next_cursor,
    )


@router.get(
    "/authoring-quota/orphan-candidates",
    response_model=AIQuotaOrphanCandidatePage,
)
def list_ai_quota_orphan_candidates_route(
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=36),
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIQuotaOrphanCandidatePage:
    try:
        rows, next_cursor = list_orphan_candidates(
            db, limit=limit, cursor=cursor, actor=principal,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AIQuotaOrphanCandidatePage(
        items=[AIQuotaOrphanCandidateRead(
            reservation_id=receipt.id,
            actor=receipt.actor,
            period_start=receipt.period_start,
            reserved_tokens=receipt.reserved_tokens,
            created_at=receipt.created_at,
            source_entity_type=receipt.source_entity_type,
            source_entity_id=receipt.source_entity_id,
            source_step=receipt.source_step,
            eligible=eligible,
            eligibility_reason=explanation,
            source_status=evidence.status if evidence else None,
            source_terminal_at=evidence.terminal_at if evidence else None,
            audited_known_tokens=evidence.audited_known_tokens if evidence else None,
            audit_event_count=evidence.audit_event_count if evidence else None,
            audit_sha256=evidence.audit_sha256 if evidence else None,
        ) for receipt, eligible, explanation, evidence in rows],
        next_cursor=next_cursor,
    )


@router.post(
    "/authoring-quota/orphan-cases",
    response_model=AIQuotaOrphanCaseRead,
    status_code=status.HTTP_201_CREATED,
)
def propose_ai_quota_orphan_case_route(
    payload: AIQuotaOrphanCaseCreate,
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIQuotaOrphanCaseRead:
    try:
        return AIQuotaOrphanCaseRead.model_validate(propose_orphan_closure(
            db, reservation_id=payload.reservation_id,
            reason=payload.reason, actor=principal,
        ))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AuthoringQuotaConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/authoring-quota/orphan-cases",
    response_model=AIQuotaOrphanCasePage,
)
def list_ai_quota_orphan_cases_route(
    state: Literal["proposed", "closed", "rejected", "all"] = "proposed",
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=36),
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIQuotaOrphanCasePage:
    try:
        rows, next_cursor = list_orphan_cases(
            db, status=state, limit=limit, cursor=cursor, actor=principal,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AIQuotaOrphanCasePage(
        items=[AIQuotaOrphanCaseRead.model_validate(row) for row in rows],
        next_cursor=next_cursor,
    )


@router.post(
    "/authoring-quota/orphan-cases/{case_id}/review",
    response_model=AIQuotaOrphanCaseRead,
)
def review_ai_quota_orphan_case_route(
    case_id: str,
    payload: AIQuotaOrphanCaseReview,
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIQuotaOrphanCaseRead:
    try:
        return AIQuotaOrphanCaseRead.model_validate(review_orphan_closure(
            db, case_id=case_id, decision=payload.decision,
            reason=payload.reason, actor=principal,
        ))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AuthoringQuotaConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/authoring-quota/supplement-candidates",
    response_model=AIAuthoringQuotaReservationPage,
)
def list_ai_quota_supplement_candidates_route(
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=36),
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIAuthoringQuotaReservationPage:
    try:
        rows, next_cursor = list_supplement_candidates(
            db, limit=limit, cursor=cursor, actor=principal,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AIAuthoringQuotaReservationPage(
        items=[AIAuthoringQuotaReservationRead.model_validate(row) for row in rows],
        next_cursor=next_cursor,
    )


@router.post(
    "/authoring-quota/supplements",
    response_model=AIQuotaSupplementRead,
    status_code=status.HTTP_201_CREATED,
)
def propose_ai_quota_supplement_route(
    payload: AIQuotaSupplementCreate,
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIQuotaSupplementRead:
    try:
        return AIQuotaSupplementRead.model_validate(propose_supplement(
            db, reservation_id=payload.reservation_id,
            confirmed_total_tokens=payload.confirmed_total_tokens,
            evidence_sha256=payload.evidence_sha256,
            evidence_reference=payload.evidence_reference,
            reason=payload.reason, actor=principal,
        ))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AuthoringQuotaConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/authoring-quota/supplements",
    response_model=AIQuotaSupplementPage,
)
def list_ai_quota_supplements_route(
    state: Literal["proposed", "applied", "rejected", "all"] = "proposed",
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=36),
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIQuotaSupplementPage:
    try:
        rows, next_cursor = list_supplement_cases(
            db, status=state, limit=limit, cursor=cursor, actor=principal,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AIQuotaSupplementPage(
        items=[AIQuotaSupplementRead.model_validate(row) for row in rows],
        next_cursor=next_cursor,
    )


@router.post(
    "/authoring-quota/supplements/{case_id}/review",
    response_model=AIQuotaSupplementRead,
)
def review_ai_quota_supplement_route(
    case_id: str,
    payload: AIQuotaSupplementReview,
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIQuotaSupplementRead:
    try:
        return AIQuotaSupplementRead.model_validate(review_supplement(
            db, case_id=case_id, decision=payload.decision,
            reason=payload.reason, actor=principal,
        ))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AuthoringQuotaConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/authoring-quota/reconciliations",
    response_model=AIQuotaReconciliationRead,
    status_code=status.HTTP_201_CREATED,
)
def propose_ai_quota_reconciliation_route(
    payload: AIQuotaReconciliationCreate,
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIQuotaReconciliationRead:
    try:
        return AIQuotaReconciliationRead.model_validate(propose_quota_reconciliation(
            db, reservation_id=payload.reservation_id,
            confirmed_total_tokens=payload.confirmed_total_tokens,
            evidence_sha256=payload.evidence_sha256,
            evidence_reference=payload.evidence_reference,
            reason=payload.reason, actor=principal,
        ))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AuthoringQuotaConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/authoring-quota/reconciliations",
    response_model=AIQuotaReconciliationPage,
)
def list_ai_quota_reconciliations_route(
    state: Literal["proposed", "applied", "rejected", "all"] = "proposed",
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=36),
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIQuotaReconciliationPage:
    try:
        rows, next_cursor = list_quota_reconciliations(
            db, status=state, limit=limit, cursor=cursor, actor=principal,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AIQuotaReconciliationPage(
        items=[AIQuotaReconciliationRead.model_validate(row) for row in rows],
        next_cursor=next_cursor,
    )


@router.post(
    "/authoring-quota/reconciliations/{case_id}/review",
    response_model=AIQuotaReconciliationRead,
)
def review_ai_quota_reconciliation_route(
    case_id: str,
    payload: AIQuotaReconciliationReview,
    principal: PrincipalContext = Depends(require_global_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIQuotaReconciliationRead:
    try:
        return AIQuotaReconciliationRead.model_validate(review_quota_reconciliation(
            db, case_id=case_id, decision=payload.decision,
            reason=payload.reason, actor=principal,
        ))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AuthoringQuotaConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/providers",
    response_model=AIProviderRead,
    status_code=status.HTTP_201_CREATED,
)
def create_ai_provider_route(
    payload: AIProviderCreate,
    principal: PrincipalContext = Depends(require_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIProviderConfig:
    trusted_payload = payload.model_copy(
        update={"created_by": request_actor(principal, payload.created_by)}
    )
    try:
        return create_ai_provider(
            db,
            trusted_payload,
            allowed_hosts=settings.ai_allowed_host_list,
        )
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/providers", response_model=list[AIProviderRead])
def list_ai_providers(
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("ai.read")),
    db: Session = Depends(db_session),
) -> list[AIProviderConfig]:
    query = select(AIProviderConfig)
    if enabled is not None:
        query = query.where(AIProviderConfig.enabled == enabled)
    return list(
        db.scalars(query.order_by(AIProviderConfig.name).limit(limit)).all()
    )


@router.put("/providers/{provider_id}", response_model=AIProviderRead)
def update_ai_provider_route(
    provider_id: str,
    payload: AIProviderUpdate,
    principal: PrincipalContext = Depends(require_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIProviderConfig:
    trusted_payload = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return update_ai_provider(
            db,
            get_ai_provider(db, provider_id),
            trusted_payload,
            allowed_hosts=settings.ai_allowed_host_list,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.post(
    "/providers/{provider_id}/health",
    response_model=AIProviderHealth,
)
def check_ai_provider_route(
    provider_id: str,
    actor: str = Query(min_length=1, max_length=255),
    principal: PrincipalContext = Depends(require_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIProviderHealth:
    try:
        return check_ai_provider(
            db,
            get_ai_provider(db, provider_id),
            actor=request_actor(principal, actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/models",
    response_model=AIModelRead,
    status_code=status.HTTP_201_CREATED,
)
def create_ai_model_config_route(
    payload: AIModelCreate,
    principal: PrincipalContext = Depends(require_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIModelConfig:
    trusted_payload = payload.model_copy(
        update={"created_by": request_actor(principal, payload.created_by)}
    )
    try:
        return create_ai_model(db, trusted_payload)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/models", response_model=list[AIModelRead])
def list_ai_models(
    provider_id: str | None = None,
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("ai.read")),
    db: Session = Depends(db_session),
) -> list[AIModelConfig]:
    query = select(AIModelConfig)
    if provider_id:
        query = query.where(AIModelConfig.provider_id == provider_id)
    if enabled is not None:
        query = query.where(AIModelConfig.enabled == enabled)
    return list(
        db.scalars(query.order_by(AIModelConfig.display_name).limit(limit)).all()
    )


@router.post(
    "/routes",
    response_model=AIModelRouteRead,
    status_code=status.HTTP_201_CREATED,
)
def create_model_route_route(
    payload: AIModelRouteCreate,
    principal: PrincipalContext = Depends(require_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AIModelRoute:
    trusted_payload = payload.model_copy(
        update={"created_by": request_actor(principal, payload.created_by)}
    )
    try:
        return create_ai_model_route_service(db, trusted_payload)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/routes", response_model=list[AIModelRouteRead])
def list_model_routes(
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("ai.read")),
    db: Session = Depends(db_session),
) -> list[AIModelRoute]:
    query = select(AIModelRoute)
    if enabled is not None:
        query = query.where(AIModelRoute.enabled == enabled)
    return list(
        db.scalars(query.order_by(AIModelRoute.purpose).limit(limit)).all()
    )


@router.post(
    "/agent-profiles",
    response_model=AgentProfileRead,
    status_code=status.HTTP_201_CREATED,
)
def create_agent_profile_route(
    payload: AgentProfileCreate,
    principal: PrincipalContext = Depends(require_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AgentProfile:
    actor = request_actor(principal, payload.created_by)
    try:
        return create_agent_profile(db, payload, actor=actor)
    except ValueError as exc:
        db.rollback()
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/agent-profiles", response_model=list[AgentProfileRead])
def list_agent_profiles_route(
    enabled: bool | None = None,
    _: PrincipalContext = Depends(require_permissions("ai.profiles.read")),
    db: Session = Depends(db_session),
) -> list[AgentProfile]:
    profiles = list_agent_profiles(db)
    if enabled is not None:
        profiles = [item for item in profiles if item.enabled is enabled]
    return profiles


@router.put(
    "/agent-profiles/{profile_id}",
    response_model=AgentProfileRead,
)
def update_agent_profile_route(
    profile_id: str,
    payload: AgentProfileUpdate,
    principal: PrincipalContext = Depends(require_permissions("ai.manage")),
    db: Session = Depends(db_session),
) -> AgentProfile:
    actor = request_actor(principal, payload.actor)
    try:
        return update_agent_profile(
            db,
            get_agent_profile(db, profile_id, lock=True),
            payload,
            actor=actor,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        code = 409 if "stale" in str(exc) or "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc
