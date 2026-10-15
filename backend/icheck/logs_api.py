from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import require_permissions
from .config import get_settings
from .database import get_db
from .log_schemas import (
    DeviceLogQueryRange,
    LogBackendCreate,
    LogBackendHealth,
    LogBackendRead,
    LogBackendUpdate,
    LogQueryRange,
    LogQueryResult,
)
from .models import Device, LogBackend
from .services.authorization_scope import (
    device_scope_clause,
    has_global_scope,
    request_actor,
)
from .services.control_plane_auth import PrincipalContext
from .services.logs import (
    LogBackendUnavailable,
    LogQueryError,
    assert_device_log_result,
    build_device_log_query,
    check_log_backend,
    create_log_backend,
    get_log_backend,
    query_logs,
    update_log_backend,
)


router = APIRouter(prefix="/api/v1/logs", tags=["logs"])
settings = get_settings()


@router.post(
    "/backends",
    response_model=LogBackendRead,
    status_code=status.HTTP_201_CREATED,
)
def create_log_backend_route(
    payload: LogBackendCreate,
    principal: PrincipalContext = Depends(require_permissions("logs.manage")),
    db: Session = Depends(get_db),
) -> LogBackend:
    trusted_payload = payload.model_copy(
        update={"created_by": request_actor(principal, payload.created_by)}
    )
    try:
        return create_log_backend(
            db,
            trusted_payload,
            allowed_hosts=settings.logs_allowed_host_list,
        )
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/backends", response_model=list[LogBackendRead])
def list_log_backends(
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("logs.read")),
    db: Session = Depends(get_db),
) -> list[LogBackend]:
    query = select(LogBackend)
    if enabled is not None:
        query = query.where(LogBackend.enabled == enabled)
    return list(db.scalars(query.order_by(LogBackend.name).limit(limit)).all())


@router.put("/backends/{backend_id}", response_model=LogBackendRead)
def update_log_backend_route(
    backend_id: str,
    payload: LogBackendUpdate,
    principal: PrincipalContext = Depends(require_permissions("logs.manage")),
    db: Session = Depends(get_db),
) -> LogBackend:
    trusted_payload = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return update_log_backend(
            db,
            get_log_backend(db, backend_id),
            trusted_payload,
            allowed_hosts=settings.logs_allowed_host_list,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        message = str(exc)
        code = 409 if "conflict" in message or "already exists" in message else 422
        raise HTTPException(status_code=code, detail=message) from exc


@router.post(
    "/backends/{backend_id}/query-range",
    response_model=LogQueryResult,
)
def query_log_backend_range(
    backend_id: str,
    payload: LogQueryRange,
    principal: PrincipalContext = Depends(require_permissions("logs.read")),
    db: Session = Depends(get_db),
) -> LogQueryResult:
    if not has_global_scope(principal):
        raise HTTPException(
            status_code=403,
            detail="Scoped LogQL requires the device log query endpoint",
        )
    try:
        return query_logs(db, get_log_backend(db, backend_id), payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except LogQueryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except LogBackendUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/backends/{backend_id}/devices/{device_id}/query-range",
    response_model=LogQueryResult,
)
def query_device_log_backend_range(
    backend_id: str,
    device_id: str,
    payload: DeviceLogQueryRange,
    principal: PrincipalContext = Depends(
        require_permissions("assets.read", "logs.read")
    ),
    db: Session = Depends(get_db),
) -> LogQueryResult:
    device = db.scalar(
        select(Device).where(
            Device.id == device_id,
            device_scope_clause(principal),
        )
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    try:
        backend = get_log_backend(db, backend_id)
        query, matcher = build_device_log_query(
            backend,
            device_name=device.name,
            management_ip=device.management_ip,
        )
        result = query_logs(
            db,
            backend,
            LogQueryRange(
                query=query,
                start=payload.start,
                end=payload.end,
                direction=payload.direction,
                limit=payload.limit,
                timeout_seconds=payload.timeout_seconds,
                actor=request_actor(principal, payload.actor),
            ),
        )
        assert_device_log_result(backend, result, matcher)
        return result
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except LogQueryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except LogBackendUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/backends/{backend_id}/health",
    response_model=LogBackendHealth,
)
def check_log_backend_route(
    backend_id: str,
    actor: str = Query(min_length=1, max_length=255),
    principal: PrincipalContext = Depends(require_permissions("logs.manage")),
    db: Session = Depends(get_db),
) -> LogBackendHealth:
    try:
        return check_log_backend(
            db,
            get_log_backend(db, backend_id),
            actor=request_actor(principal, actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
