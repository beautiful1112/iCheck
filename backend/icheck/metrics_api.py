from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import require_permissions
from .config import get_settings
from .database import get_db
from .metric_schemas import (
    MetricBackendCreate,
    MetricBackendHealth,
    MetricBackendRead,
    MetricBackendUpdate,
    PrometheusInstantQuery,
    PrometheusQueryResult,
    PrometheusRangeQuery,
)
from .models import MetricBackend
from .services.metrics import (
    MetricBackendUnavailable,
    MetricQueryError,
    check_metric_backend,
    create_metric_backend,
    get_metric_backend,
    query_instant,
    query_range,
    update_metric_backend,
)
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext


router = APIRouter(prefix="/api/v1/metrics", tags=["metrics"])
settings = get_settings()


db_session = get_db


@router.post(
    "/backends",
    response_model=MetricBackendRead,
    status_code=status.HTTP_201_CREATED,
)
def create_metric_backend_route(
    payload: MetricBackendCreate,
    principal: PrincipalContext = Depends(
        require_permissions("metrics.manage")
    ),
    db: Session = Depends(db_session),
) -> MetricBackend:
    trusted_payload = payload.model_copy(
        update={"created_by": request_actor(principal, payload.created_by)}
    )
    try:
        return create_metric_backend(
            db,
            trusted_payload,
            allowed_hosts=settings.metrics_allowed_host_list,
        )
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/backends", response_model=list[MetricBackendRead])
def list_metric_backends(
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("metrics.read")),
    db: Session = Depends(db_session),
) -> list[MetricBackend]:
    query = select(MetricBackend)
    if enabled is not None:
        query = query.where(MetricBackend.enabled == enabled)
    return list(
        db.scalars(query.order_by(MetricBackend.name).limit(limit)).all()
    )


@router.put("/backends/{backend_id}", response_model=MetricBackendRead)
def update_metric_backend_route(
    backend_id: str,
    payload: MetricBackendUpdate,
    principal: PrincipalContext = Depends(
        require_permissions("metrics.manage")
    ),
    db: Session = Depends(db_session),
) -> MetricBackend:
    trusted_payload = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return update_metric_backend(
            db,
            get_metric_backend(db, backend_id),
            trusted_payload,
            allowed_hosts=settings.metrics_allowed_host_list,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        message = str(exc)
        code = 409 if "conflict" in message or "already exists" in message else 422
        raise HTTPException(status_code=code, detail=message) from exc


@router.post(
    "/backends/{backend_id}/query",
    response_model=PrometheusQueryResult,
)
def query_metric_backend_instant(
    backend_id: str,
    payload: PrometheusInstantQuery,
    principal: PrincipalContext = Depends(require_permissions("metrics.read")),
    db: Session = Depends(db_session),
) -> PrometheusQueryResult:
    try:
        return query_instant(
            db, get_metric_backend(db, backend_id),
            payload.model_copy(update={"actor": request_actor(principal, payload.actor)}),
            principal=principal,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except MetricQueryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except MetricBackendUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/backends/{backend_id}/query-range",
    response_model=PrometheusQueryResult,
)
def query_metric_backend_range(
    backend_id: str,
    payload: PrometheusRangeQuery,
    principal: PrincipalContext = Depends(require_permissions("metrics.read")),
    db: Session = Depends(db_session),
) -> PrometheusQueryResult:
    try:
        return query_range(
            db, get_metric_backend(db, backend_id),
            payload.model_copy(update={"actor": request_actor(principal, payload.actor)}),
            principal=principal,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except MetricQueryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except MetricBackendUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/backends/{backend_id}/health",
    response_model=MetricBackendHealth,
)
def check_metric_backend_route(
    backend_id: str,
    actor: str = Query(min_length=1, max_length=255),
    principal: PrincipalContext = Depends(
        require_permissions("metrics.manage")
    ),
    db: Session = Depends(db_session),
) -> MetricBackendHealth:
    try:
        return check_metric_backend(
            db,
            get_metric_backend(db, backend_id),
            actor=request_actor(principal, actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
