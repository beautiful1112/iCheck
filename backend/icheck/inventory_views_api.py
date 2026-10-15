"""Bounded, read-only views of collected inventory; never inferred health."""
from datetime import datetime
import math
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import require_permissions
from .database import get_db
from .models import (
    CollectionEnvelope, CollectorDeployment, CollectorRun, CollectorRunStatus,
    Device, Endpoint, EndpointAttachment, IPAddressObservation, WirelessClientSession,
)
from .schemas import APIModel
from .services.authorization_scope import (
    authorized_device_ids_query, device_scope_clause, has_global_scope,
    namespace_clause, require_endpoint_access,
)
from .services.control_plane_auth import PrincipalContext

router = APIRouter(prefix="/api/v1", tags=["inventory"])
DBSession = Annotated[Session, Depends(get_db)]


class InterfaceObservationRead(APIModel):
    device_id: str
    device_name: str
    if_index: str
    name: str | None
    description: str | None
    alias: str | None
    observed_at: datetime
    metrics: dict[str, float]
    evidence_ids: dict[str, str]
    metric_observed_at: dict[str, datetime]


class InterfaceObservationPage(APIModel):
    items: list[InterfaceObservationRead]
    samples_examined: int
    truncated: bool
    boundary: str = "Collected observations, not a complete or independently verified interface snapshot"


INTERFACE_METRICS = {
    "ifName", "ifDescr", "ifAlias", "ifOperStatus", "ifAdminStatus",
    "ifSpeed", "ifHighSpeed", "ifHCInOctets_total", "ifHCOutOctets_total",
    "ifInOctets_total", "ifOutOctets_total", "ifInErrors_total", "ifOutErrors_total",
}


@router.get("/assets/interfaces", response_model=InterfaceObservationPage)
def list_interfaces(
    db: DBSession,
    device_id: str | None = Query(default=None, min_length=1, max_length=36),
    limit: int = Query(default=200, ge=1, le=1000),
    sample_limit: int = Query(default=10000, ge=1, le=20000),
    principal: PrincipalContext = Depends(require_permissions("assets.read")),
) -> dict[str, Any]:
    query = (
        select(CollectionEnvelope, Device.id, Device.name)
        .join(CollectorRun, CollectionEnvelope.run_id == CollectorRun.id)
        .join(CollectorDeployment, CollectorRun.deployment_id == CollectorDeployment.id)
        .join(Device, CollectorDeployment.scope_device_id == Device.id)
        .where(
            device_scope_clause(principal),
            namespace_clause(CollectionEnvelope, principal),
            namespace_clause(CollectorRun, principal),
            namespace_clause(CollectorDeployment, principal),
            CollectionEnvelope.type == "metric.sample",
            CollectionEnvelope.payload["metric"].as_string().in_(INTERFACE_METRICS),
            CollectorRun.status == CollectorRunStatus.SUCCEEDED,
        )
        .order_by(CollectionEnvelope.observed_at.desc(), CollectionEnvelope.id)
        .limit(sample_limit + 1)
    )
    if device_id:
        query = query.where(Device.id == device_id)
    rows = db.execute(query).all()
    interfaces: dict[tuple[str, str], dict[str, Any]] = {}
    for envelope, identity, name in rows[:sample_limit]:
        payload = envelope.payload
        if not isinstance(payload, dict):
            continue
        labels = payload.get("labels")
        metric = payload.get("metric")
        if not isinstance(labels, dict) or not isinstance(metric, str) or metric not in INTERFACE_METRICS:
            continue
        index = labels.get("ifIndex")
        value = payload.get("value")
        if (not isinstance(index, str) or not index.isascii() or not index.isdecimal()
                or len(index) > 10 or not 1 <= int(index) <= 2147483647
                or isinstance(value, bool) or not isinstance(value, (int, float))):
            continue
        try:
            numeric_value = float(value)
        except (ValueError, OverflowError):
            continue
        if not math.isfinite(numeric_value):
            continue
        key = (identity, index)
        if key not in interfaces:
            interfaces[key] = {
                "device_id": identity, "device_name": name, "if_index": index,
                "name": None, "description": None, "alias": None,
                "observed_at": envelope.observed_at, "metrics": {}, "evidence_ids": {},
                "metric_observed_at": {},
            }
        item = interfaces[key]
        # Newest observation wins independently for each metric/label. Arbitrary
        # payloads, credentials, raw vendor data and non-interface labels stay private.
        for field, label in (("name", "ifName"), ("description", "ifDescr"), ("alias", "ifAlias")):
            text = labels.get(label)
            if item[field] is None and isinstance(text, str) and 0 < len(text) <= 255:
                item[field] = text
        if metric not in item["metrics"]:
            item["metrics"][metric] = numeric_value
            item["evidence_ids"][metric] = envelope.id
            item["metric_observed_at"][metric] = envelope.observed_at
    items = list(interfaces.values())
    return {"items": items[:limit], "samples_examined": min(len(rows), sample_limit),
            "truncated": len(rows) > sample_limit or len(items) > limit}


class EndpointHistoryRead(APIModel):
    id: str
    mac_address: str
    ip_history: list[dict[str, Any]]
    wired_history: list[dict[str, Any]]
    wireless_history: list[dict[str, Any]]
    truncated: list[str]


@router.get("/endpoints/{endpoint_id}/history", response_model=EndpointHistoryRead)
def endpoint_history(
    endpoint_id: str,
    db: DBSession,
    limit: int = Query(default=50, ge=1, le=500),
    principal: PrincipalContext = Depends(require_permissions("endpoints.read")),
) -> dict[str, Any]:
    require_endpoint_access(db, principal, endpoint_id)
    endpoint = db.get(Endpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    result: dict[str, Any] = {"id": endpoint.id, "mac_address": endpoint.mac_address, "truncated": []}
    for key, model, source_column, fields in (
        ("ip_history", IPAddressObservation, IPAddressObservation.collector_device_id,
         ("ip_address", "source", "collector_device_id", "vlan_id")),
        ("wired_history", EndpointAttachment, EndpointAttachment.collector_device_id,
         ("source", "collector_device_id", "interface_name", "vlan_id")),
        ("wireless_history", WirelessClientSession, WirelessClientSession.controller_id,
         ("controller_id", "ip_address", "access_point", "ssid", "band", "channel", "vlan_id",
          "rssi", "snr", "connected_at", "disconnected_at")),
    ):
        query = select(model).where(model.endpoint_id == endpoint_id, namespace_clause(model, principal))
        if not has_global_scope(principal):
            query = query.where(source_column.in_(authorized_device_ids_query(principal)))
        rows = db.scalars(query.order_by(model.last_seen.desc(), model.id).limit(limit + 1)).all()
        if len(rows) > limit:
            result["truncated"].append(key)
        result[key] = [
            {field: getattr(getattr(row, field), "value", getattr(row, field))
             for field in ("id", "active", "first_seen", "last_seen", *fields)}
            for row in rows[:limit]
        ]
    return result
