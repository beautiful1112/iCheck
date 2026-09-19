from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from .database import get_db
from .device_schemas import (
    DeviceConnectionPreflightRead,
    DeviceOnboardCreate,
    DeviceOnboardRead,
    DevicePreflightAssignment,
    DevicePreflightClaim,
    DevicePreflightComplete,
    DeviceVerificationRetry,
)
from .models import (
    CollectorWorker,
    Device,
    DeviceConnection,
    DeviceConnectionPreflight,
)
from .services.devices import (
    claim_device_preflights,
    complete_device_preflight,
    get_onboarded_device,
    onboard_device,
    retry_device_connection,
)
from .worker_auth import WorkerAuthenticationError, authenticate_worker


router = APIRouter(prefix="/api/v1/assets", tags=["assets"])
worker_router = APIRouter(prefix="/api/v1", tags=["device-preflight"])


def db_session():
    yield from get_db()


def _worker(db: Session, worker_id: str) -> CollectorWorker:
    worker = db.get(CollectorWorker, worker_id)
    if worker is None:
        raise HTTPException(status_code=404, detail="Collector worker not found")
    return worker


def _authorize_worker(
    worker: CollectorWorker,
    authorization: str | None,
) -> None:
    try:
        authenticate_worker(worker, authorization)
    except WorkerAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.post(
    "/devices",
    response_model=DeviceOnboardRead,
    status_code=status.HTTP_201_CREATED,
)
def onboard_device_route(
    payload: DeviceOnboardCreate,
    db: Session = Depends(db_session),
) -> Device:
    try:
        return onboard_device(db, payload)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/devices", response_model=list[DeviceOnboardRead])
def list_onboarded_devices(
    search: str | None = Query(default=None, max_length=255),
    kind: str | None = Query(default=None, max_length=64),
    site: str | None = Query(default=None, max_length=128),
    onboarding_status: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(db_session),
) -> list[Device]:
    query = select(Device).options(
        selectinload(Device.connections).selectinload(
            DeviceConnection.activation
        )
    )
    if search:
        value = f"%{search.strip()}%"
        query = query.where(
            or_(
                Device.name.ilike(value),
                Device.management_ip.ilike(value),
                Device.vendor.ilike(value),
                Device.model.ilike(value),
            )
        )
    if kind:
        query = query.where(Device.kind == kind)
    if site:
        query = query.where(Device.site == site)
    if onboarding_status:
        query = query.where(Device.onboarding_status == onboarding_status)
    return list(db.scalars(query.order_by(Device.name).limit(limit)).all())


@router.get("/devices/{device_id}", response_model=DeviceOnboardRead)
def get_onboarded_device_route(
    device_id: str,
    db: Session = Depends(db_session),
) -> Device:
    try:
        return get_onboarded_device(db, device_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/devices/{device_id}/connections/{connection_id}/preflights",
    response_model=list[DeviceConnectionPreflightRead],
)
def list_device_connection_preflights(
    device_id: str,
    connection_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(db_session),
) -> list[DeviceConnectionPreflight]:
    connection = db.scalar(
        select(DeviceConnection.id).where(
            DeviceConnection.id == connection_id,
            DeviceConnection.device_id == device_id,
        )
    )
    if connection is None:
        raise HTTPException(status_code=404, detail="Device connection not found")
    return list(
        db.scalars(
            select(DeviceConnectionPreflight)
            .where(DeviceConnectionPreflight.connection_id == connection_id)
            .order_by(DeviceConnectionPreflight.started_at.desc())
            .limit(limit)
        ).all()
    )


@router.post(
    "/devices/{device_id}/connections/{connection_id}/verification/retry",
    response_model=DeviceOnboardRead,
)
def retry_device_connection_route(
    device_id: str,
    connection_id: str,
    payload: DeviceVerificationRetry,
    db: Session = Depends(db_session),
) -> Device:
    try:
        return retry_device_connection(
            db,
            device_id,
            connection_id,
            actor=payload.actor,
            reason=payload.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@worker_router.post(
    "/collector-workers/{worker_id}/device-preflights/claim",
    response_model=list[DevicePreflightAssignment],
)
def claim_device_preflights_route(
    worker_id: str,
    payload: DevicePreflightClaim,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> list[DevicePreflightAssignment]:
    worker = _worker(db, worker_id)
    _authorize_worker(worker, authorization)
    try:
        return claim_device_preflights(db, worker, payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@worker_router.post(
    "/collector-workers/{worker_id}/device-preflights/{preflight_id}/complete",
    response_model=DeviceConnectionPreflightRead,
)
def complete_device_preflight_route(
    worker_id: str,
    preflight_id: str,
    payload: DevicePreflightComplete,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
):
    worker = _worker(db, worker_id)
    _authorize_worker(worker, authorization)
    try:
        return complete_device_preflight(db, worker, preflight_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
