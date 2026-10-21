from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from .auth import require_global_permissions, require_permissions
from .database import get_db
from .models import (
    Alert,
    AlertRule,
    AlertSeverity,
    AlertStatus,
    Device,
    Endpoint,
    Situation,
    SituationStatus,
    WirelessClientSession,
)
from .schemas import (
    AlertAction,
    AlertEvent,
    AlertRead,
    AlertRuleCreate,
    AlertRuleRead,
    DashboardSummary,
    OperatorSummary,
    DeviceCreate,
    DeviceRead,
    EndpointRead,
    IngestResult,
    NetworkObservationBatch,
    WirelessSnapshot,
)
from .services.alerts import acknowledge_alert, resolve_alert, upsert_alert
from .network_binding_schemas import NetworkObservationBatchV2
from .services.authorization_scope import (
    alert_scope_clause,
    authorized_device_ids,
    authorized_device_ids_query,
    device_scope_clause,
    endpoint_scope_clause,
    has_global_scope,
    request_actor,
    require_alert_access,
    require_device_access,
    require_endpoint_access,
    require_site_access,
    situation_scope_clause,
)
from .services.control_plane_auth import PrincipalContext
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
def create_device(
    payload: DeviceCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("assets.write")),
) -> Device:
    require_site_access(principal, payload.site)
    values = payload.model_dump()
    values["created_by"] = request_actor(principal, payload.created_by)
    device = Device(**values)
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
    principal: PrincipalContext = Depends(require_permissions("assets.read")),
) -> list[Device]:
    query = select(Device).where(device_scope_clause(principal))
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
def ingest_network(
    payload: NetworkObservationBatch,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("inventory.ingest")
    ),
) -> IngestResult:
    return _ingest_network_payload(payload, db, principal)


@router.post("/inventory/network-observations/v2", response_model=IngestResult, tags=["inventory"])
def ingest_network_v2(
    payload: NetworkObservationBatchV2,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("inventory.ingest")),
) -> IngestResult:
    return _ingest_network_payload(payload, db, principal)


def _ingest_network_payload(payload: NetworkObservationBatch | NetworkObservationBatchV2,
                            db: Session, principal: PrincipalContext) -> IngestResult:
    collector_ids = {
        item.collector_device_id
        for item in payload.observations
        if item.collector_device_id is not None
    }
    if collector_ids:
        for device_id in collector_ids:
            require_device_access(db, principal, device_id)
        existing = set(
            db.scalars(select(Device.id).where(Device.id.in_(collector_ids))).all()
        )
        missing = sorted(collector_ids - existing)
        if missing:
            raise HTTPException(
                status_code=422,
                detail={"message": "Unknown collector device IDs", "ids": missing},
            )
    elif not has_global_scope(principal):
        raise HTTPException(
            status_code=403,
            detail="Scoped ingestion requires a collector device",
        )
    try:
        return ingest_network_observations(db, payload, principal=principal)
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/inventory/wireless-snapshots",
    response_model=IngestResult,
    tags=["inventory"],
)
def ingest_wireless(
    payload: WirelessSnapshot,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("inventory.ingest")
    ),
) -> IngestResult:
    require_device_access(db, principal, payload.controller_id)
    try:
        return ingest_wireless_snapshot(db, payload, principal=principal)
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/endpoints", response_model=list[EndpointRead], tags=["inventory"])
def list_endpoints(
    db: DBSession,
    search: str | None = Query(default=None, max_length=255),
    limit: int = Query(default=100, ge=1, le=1000),
    principal: PrincipalContext = Depends(require_permissions("endpoints.read")),
) -> list[dict[str, object]]:
    endpoints = db.scalars(
        endpoint_query(search).where(endpoint_scope_clause(principal)).limit(limit)
    ).all()
    allowed_ids = authorized_device_ids(db, principal)
    return [
        endpoint_to_dict(endpoint, allowed_device_ids=allowed_ids)
        for endpoint in endpoints
    ]


@router.get("/endpoints/{endpoint_id}", response_model=EndpointRead, tags=["inventory"])
def get_endpoint(
    endpoint_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("endpoints.read")),
) -> dict[str, object]:
    require_endpoint_access(db, principal, endpoint_id)
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
    return endpoint_to_dict(
        endpoint,
        allowed_device_ids=authorized_device_ids(db, principal),
    )


@router.post(
    "/alert-rules",
    response_model=AlertRuleRead,
    status_code=status.HTTP_201_CREATED,
    tags=["alerts"],
)
def create_alert_rule(
    payload: AlertRuleCreate,
    db: DBSession,
    _: PrincipalContext = Depends(require_global_permissions("alerts.admin")),
) -> AlertRule:
    if payload.event_type=="metric.prometheus":
        raise HTTPException(400,"Use the reviewed Prometheus metric-rule API; inventory rules do not evaluate metrics")
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
def list_alert_rules(
    db: DBSession,
    _: PrincipalContext = Depends(require_permissions("alerts.read")),
) -> list[AlertRule]:
    return list(db.scalars(select(AlertRule).where(AlertRule.event_type!="metric.prometheus").order_by(AlertRule.name)).all())


@router.post(
    "/alerts/events",
    response_model=AlertRead,
    status_code=status.HTTP_201_CREATED,
    tags=["alerts"],
)
def emit_alert_event(
    payload: AlertEvent,
    db: DBSession,
    response: Response,
    principal: PrincipalContext = Depends(require_permissions("alerts.emit")),
) -> Alert:
    if payload.event_type=="metric.prometheus" or (payload.dedup_key or "").startswith("metric:"):
        raise HTTPException(403,"Metric episodes require the provisioned Alertmanager receiver")
    if (
        not has_global_scope(principal)
        and payload.entity_type in {"device", "collector_device"}
    ):
        require_device_access(db, principal, payload.entity_id)
    elif (
        not has_global_scope(principal)
        and payload.entity_type in {"endpoint", "terminal"}
    ):
        require_endpoint_access(db, principal, payload.entity_id)
    elif not has_global_scope(principal):
        raise HTTPException(
            status_code=403,
            detail="Scoped alert emitters require a device or endpoint entity",
        )
    try:
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
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if alert is None:
        raise HTTPException(status_code=409, detail="Stale Alert observation has no Alert episode")
    response.headers["X-Icheck-Alert-Observation"] = getattr(alert, "_observation_disposition", "accepted")
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/alerts", response_model=list[AlertRead], tags=["alerts"])
def list_alerts(
    db: DBSession,
    alert_id: str | None = Query(default=None, min_length=1, max_length=36),
    alert_status: AlertStatus | None = Query(default=None, alias="status"),
    severity: AlertSeverity | None = None,
    device_id: str | None = Query(default=None, min_length=1, max_length=36),
    include_superseded: bool = False,
    limit: int = Query(default=100, ge=1, le=1000),
    principal: PrincipalContext = Depends(require_permissions("alerts.read")),
) -> list[Alert]:
    query = select(Alert).where(alert_scope_clause(principal))
    if alert_id:
        query = query.where(Alert.id == alert_id)
    if device_id:
        query = query.where(Alert.entity_type == "device", Alert.entity_id == device_id)
    if not include_superseded:
        query = query.where(Alert.source_retirement_id.is_(None))
    if alert_status:
        query = query.where(Alert.status == alert_status)
    if severity:
        query = query.where(Alert.severity == severity)
    return list(db.scalars(query.order_by(Alert.last_seen.desc()).limit(limit)).all())


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertRead, tags=["alerts"])
def acknowledge(
    alert_id: str,
    payload: AlertAction,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("alerts.manage")),
) -> Alert:
    alert = require_alert_access(db, principal, alert_id)
    try:
        acknowledge_alert(db, alert, request_actor(principal, payload.actor), principal=principal)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/alerts/{alert_id}/resolve", response_model=AlertRead, tags=["alerts"])
def resolve(
    alert_id: str,
    payload: AlertAction,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("alerts.manage")),
) -> Alert:
    alert = require_alert_access(db, principal, alert_id)
    try:
        resolve_alert(db, alert, request_actor(principal, payload.actor), principal=principal)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/operator/summary", response_model=OperatorSummary, tags=["operations"])
def operator_summary(db: DBSession, principal: PrincipalContext = Depends(
        require_permissions("operations.read", "assets.read", "endpoints.read", "alerts.read"))) -> OperatorSummary:
    active = (Alert.status != AlertStatus.RESOLVED, Alert.source_retirement_id.is_(None), alert_scope_clause(principal))
    return OperatorSummary(
        devices=db.scalar(select(func.count()).select_from(Device).where(device_scope_clause(principal))) or 0,
        endpoints=db.scalar(select(func.count()).select_from(Endpoint).where(endpoint_scope_clause(principal))) or 0,
        active_wireless_clients=db.scalar(select(func.count()).select_from(WirelessClientSession).where(
            WirelessClientSession.active.is_(True), WirelessClientSession.controller_id.in_(authorized_device_ids_query(principal)))) or 0,
        open_alerts=db.scalar(select(func.count()).select_from(Alert).where(*active)) or 0,
        critical_alerts=db.scalar(select(func.count()).select_from(Alert).where(*active, Alert.severity == AlertSeverity.CRITICAL)) or 0,
        recent_alerts=list(db.scalars(select(Alert).where(*active).order_by(Alert.last_seen.desc(), Alert.id).limit(6)).all()),
    )


@router.get("/dashboard/summary", response_model=DashboardSummary, tags=["operations"])
def dashboard_summary(
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions(
            "operations.read",
            "assets.read",
            "endpoints.read",
            "alerts.read",
        )
    ),
) -> DashboardSummary:
    devices = (
        db.scalar(
            select(func.count())
            .select_from(Device)
            .where(device_scope_clause(principal))
        )
        or 0
    )
    endpoints = (
        db.scalar(
            select(func.count())
            .select_from(Endpoint)
            .where(endpoint_scope_clause(principal))
        )
        or 0
    )
    wireless = (
        db.scalar(
            select(func.count())
            .select_from(WirelessClientSession)
            .where(
                WirelessClientSession.active.is_(True),
                WirelessClientSession.controller_id.in_(
                    authorized_device_ids_query(principal)
                ),
            )
        )
        or 0
    )
    open_alerts = (
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.status != AlertStatus.RESOLVED,
                Alert.source_retirement_id.is_(None),
                alert_scope_clause(principal),
            )
        )
        or 0
    )
    critical = (
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.status != AlertStatus.RESOLVED,
                Alert.source_retirement_id.is_(None),
                Alert.severity == AlertSeverity.CRITICAL,
                alert_scope_clause(principal),
            )
        )
        or 0
    )
    open_situations = (
        db.scalar(
            select(func.count())
            .select_from(Situation)
            .where(
                Situation.status != SituationStatus.RESOLVED.value,
                situation_scope_clause(principal),
            )
        )
        or 0
    )
    critical_situations = (
        db.scalar(
            select(func.count())
            .select_from(Situation)
            .where(
                Situation.status != SituationStatus.RESOLVED.value,
                Situation.severity == AlertSeverity.CRITICAL,
                situation_scope_clause(principal),
            )
        )
        or 0
    )
    recent_situations = list(
        db.scalars(
            select(Situation)
            .where(
                Situation.status != SituationStatus.RESOLVED.value,
                situation_scope_clause(principal),
            )
            .order_by(
                Situation.priority_score.desc(),
                Situation.last_seen.desc(),
            )
            .limit(6)
        ).all()
    )
    recent_alerts = list(
        db.scalars(
            select(Alert)
            .where(alert_scope_clause(principal))
            .order_by(Alert.last_seen.desc())
            .limit(6)
        ).all()
    )
    recent_endpoints = db.scalars(
        endpoint_query().where(endpoint_scope_clause(principal)).limit(6)
    ).all()
    allowed_ids = authorized_device_ids(db, principal)
    return DashboardSummary(
        devices=devices,
        endpoints=endpoints,
        active_wireless_clients=wireless,
        open_alerts=open_alerts,
        critical_alerts=critical,
        open_situations=open_situations,
        critical_situations=critical_situations,
        recent_situations=recent_situations,
        recent_alerts=recent_alerts,
        recent_endpoints=[
            endpoint_to_dict(endpoint, allowed_device_ids=allowed_ids)
            for endpoint in recent_endpoints
        ],
    )
