from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from .database import get_db
from .models import (
    Alert,
    AlertRule,
    AlertSeverity,
    AlertStatus,
    Device,
    Endpoint,
    WirelessClientSession,
)
from .schemas import (
    AlertAction,
    AlertEvent,
    AlertRead,
    AlertRuleCreate,
    AlertRuleRead,
    DashboardSummary,
    DeviceCreate,
    DeviceRead,
    EndpointRead,
    IngestResult,
    NetworkObservationBatch,
    WirelessSnapshot,
)
from .services.alerts import acknowledge_alert, resolve_alert, upsert_alert
from .services.inventory import (
    endpoint_query,
    endpoint_to_dict,
    ingest_network_observations,
    ingest_wireless_snapshot,
)


router = APIRouter(prefix="/api/v1")
DBSession = Annotated[Session, Depends(get_db)]


@router.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "icheck-api"}


@router.post(
    "/devices",
    response_model=DeviceRead,
    status_code=status.HTTP_201_CREATED,
    tags=["inventory"],
)
def create_device(payload: DeviceCreate, db: DBSession) -> Device:
    device = Device(**payload.model_dump())
    db.add(device)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Device name or management IP already exists") from exc
    db.refresh(device)
    return device


@router.get("/devices", response_model=list[DeviceRead], tags=["inventory"])
def list_devices(
    db: DBSession,
    kind: str | None = None,
    site: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[Device]:
    query = select(Device)
    if kind:
        query = query.where(Device.kind == kind)
    if site:
        query = query.where(Device.site == site)
    return list(db.scalars(query.order_by(Device.name).limit(limit)).all())


@router.post(
    "/inventory/network-observations",
    response_model=IngestResult,
    tags=["inventory"],
)
def ingest_network(payload: NetworkObservationBatch, db: DBSession) -> IngestResult:
    collector_ids = {
        item.collector_device_id
        for item in payload.observations
        if item.collector_device_id is not None
    }
    if collector_ids:
        existing = set(
            db.scalars(select(Device.id).where(Device.id.in_(collector_ids))).all()
        )
        missing = sorted(collector_ids - existing)
        if missing:
            raise HTTPException(
                status_code=422,
                detail={"message": "Unknown collector device IDs", "ids": missing},
            )
    return ingest_network_observations(db, payload)


@router.post(
    "/inventory/wireless-snapshots",
    response_model=IngestResult,
    tags=["inventory"],
)
def ingest_wireless(payload: WirelessSnapshot, db: DBSession) -> IngestResult:
    try:
        return ingest_wireless_snapshot(db, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/endpoints", response_model=list[EndpointRead], tags=["inventory"])
def list_endpoints(
    db: DBSession,
    search: str | None = Query(default=None, max_length=255),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, object]]:
    endpoints = db.scalars(endpoint_query(search).limit(limit)).all()
    return [endpoint_to_dict(endpoint) for endpoint in endpoints]


@router.get("/endpoints/{endpoint_id}", response_model=EndpointRead, tags=["inventory"])
def get_endpoint(endpoint_id: str, db: DBSession) -> dict[str, object]:
    endpoint = db.scalar(
        select(Endpoint)
        .where(Endpoint.id == endpoint_id)
        .options(
            selectinload(Endpoint.ip_observations),
            selectinload(Endpoint.attachments),
            selectinload(Endpoint.wireless_sessions),
        )
    )
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return endpoint_to_dict(endpoint)


@router.post(
    "/alert-rules",
    response_model=AlertRuleRead,
    status_code=status.HTTP_201_CREATED,
    tags=["alerts"],
)
def create_alert_rule(payload: AlertRuleCreate, db: DBSession) -> AlertRule:
    rule = AlertRule(**payload.model_dump())
    db.add(rule)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Alert rule name already exists") from exc
    db.refresh(rule)
    return rule


@router.get("/alert-rules", response_model=list[AlertRuleRead], tags=["alerts"])
def list_alert_rules(db: DBSession) -> list[AlertRule]:
    return list(db.scalars(select(AlertRule).order_by(AlertRule.name)).all())


@router.post(
    "/alerts/events",
    response_model=AlertRead,
    status_code=status.HTTP_201_CREATED,
    tags=["alerts"],
)
def emit_alert_event(payload: AlertEvent, db: DBSession) -> Alert:
    alert = upsert_alert(
        db,
        dedup_key=payload.dedup_key
        or f"manual:{payload.event_type}:{payload.entity_type}:{payload.entity_id}",
        event_type=payload.event_type,
        severity=payload.severity,
        title=payload.title,
        description=payload.description,
        entity_type=payload.entity_type,
        entity_id=payload.entity_id,
        details=payload.details,
        observed_at=payload.observed_at,
    )
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/alerts", response_model=list[AlertRead], tags=["alerts"])
def list_alerts(
    db: DBSession,
    alert_status: AlertStatus | None = Query(default=None, alias="status"),
    severity: AlertSeverity | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[Alert]:
    query = select(Alert)
    if alert_status:
        query = query.where(Alert.status == alert_status)
    if severity:
        query = query.where(Alert.severity == severity)
    return list(db.scalars(query.order_by(Alert.last_seen.desc()).limit(limit)).all())


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertRead, tags=["alerts"])
def acknowledge(alert_id: str, payload: AlertAction, db: DBSession) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    try:
        acknowledge_alert(db, alert, payload.actor)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/alerts/{alert_id}/resolve", response_model=AlertRead, tags=["alerts"])
def resolve(alert_id: str, payload: AlertAction, db: DBSession) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    resolve_alert(db, alert, payload.actor)
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/dashboard/summary", response_model=DashboardSummary, tags=["operations"])
def dashboard_summary(db: DBSession) -> DashboardSummary:
    devices = db.scalar(select(func.count()).select_from(Device)) or 0
    endpoints = db.scalar(select(func.count()).select_from(Endpoint)) or 0
    wireless = (
        db.scalar(
            select(func.count())
            .select_from(WirelessClientSession)
            .where(WirelessClientSession.active.is_(True))
        )
        or 0
    )
    open_alerts = (
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.status != AlertStatus.RESOLVED)
        )
        or 0
    )
    critical = (
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.status != AlertStatus.RESOLVED,
                Alert.severity == AlertSeverity.CRITICAL,
            )
        )
        or 0
    )
    recent_alerts = list(db.scalars(select(Alert).order_by(Alert.last_seen.desc()).limit(6)).all())
    recent_endpoints = db.scalars(endpoint_query().limit(6)).all()
    return DashboardSummary(
        devices=devices,
        endpoints=endpoints,
        active_wireless_clients=wireless,
        open_alerts=open_alerts,
        critical_alerts=critical,
        recent_alerts=recent_alerts,
        recent_endpoints=[endpoint_to_dict(endpoint) for endpoint in recent_endpoints],
    )

