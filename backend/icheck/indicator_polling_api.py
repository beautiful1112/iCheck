from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .auth import require_permissions
from .database import get_db
from .service_indicator_schemas import (
    PrometheusIndicatorBindingCreate,
    PrometheusIndicatorBindingRead,
    PrometheusIndicatorBindingUpdate,
    ServiceIndicatorPollRunRead,
)
from .services.authorization_scope import (
    request_actor,
    require_service_access,
    require_service_manage_access,
)
from .services.control_plane_auth import PrincipalContext
from .services.indicator_polling import (
    binding_to_read,
    create_prometheus_binding,
    enqueue_poll_now,
    get_prometheus_binding,
    list_poll_runs,
    poll_run_to_read,
    update_prometheus_binding,
)
from .services.service_indicators import get_indicator


router = APIRouter(prefix="/api/v1/services", tags=["service-indicator-polling"])
DBSession = Annotated[Session, Depends(get_db)]


@router.get(
    "/{service_id}/indicators/{indicator_id}/prometheus-binding",
    response_model=PrometheusIndicatorBindingRead,
)
def get_indicator_prometheus_binding(
    service_id: str,
    indicator_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> PrometheusIndicatorBindingRead:
    service = require_service_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
        return binding_to_read(get_prometheus_binding(db, definition.id))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/{service_id}/indicators/{indicator_id}/prometheus-binding",
    response_model=PrometheusIndicatorBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def add_indicator_prometheus_binding(
    service_id: str,
    indicator_id: str,
    payload: PrometheusIndicatorBindingCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> PrometheusIndicatorBindingRead:
    service = require_service_manage_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
        binding = create_prometheus_binding(
            db,
            service,
            definition,
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return binding_to_read(binding)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.patch(
    "/{service_id}/indicators/{indicator_id}/prometheus-binding",
    response_model=PrometheusIndicatorBindingRead,
)
def edit_indicator_prometheus_binding(
    service_id: str,
    indicator_id: str,
    payload: PrometheusIndicatorBindingUpdate,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> PrometheusIndicatorBindingRead:
    service = require_service_manage_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
        binding = get_prometheus_binding(db, definition.id)
        binding = update_prometheus_binding(
            db,
            service,
            definition,
            binding,
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return binding_to_read(binding)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/{service_id}/indicators/{indicator_id}/prometheus-binding/poll-runs",
    response_model=ServiceIndicatorPollRunRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def enqueue_indicator_poll(
    service_id: str,
    indicator_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> ServiceIndicatorPollRunRead:
    service = require_service_manage_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
        run = enqueue_poll_now(
            db,
            get_prometheus_binding(db, definition.id),
            actor=request_actor(principal),
        )
        return poll_run_to_read(run)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/{service_id}/indicators/{indicator_id}/prometheus-binding/poll-runs",
    response_model=list[ServiceIndicatorPollRunRead],
)
def get_indicator_poll_runs(
    service_id: str,
    indicator_id: str,
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> list[ServiceIndicatorPollRunRead]:
    service = require_service_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
        binding = get_prometheus_binding(db, definition.id)
        return list_poll_runs(db, binding, limit=limit)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
