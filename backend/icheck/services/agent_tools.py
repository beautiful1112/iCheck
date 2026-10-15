from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from langgraph.errors import GraphInterrupt
from langgraph.types import interrupt
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from ..agent_schemas import (
    GovernedChangeEvidenceAttach,
    InvestigationEvidenceCreate,
    InvestigationToolCallComplete,
    InvestigationToolCallCreate,
)
from ..langgraph_runtime import (
    GraphToolExecutionFailure,
    GraphToolOutcomeUnknown,
    GraphToolRequest,
    GraphToolResult,
    GrafanaPreviewCompletion,
    InvestigationGraphState,
)
from ..log_schemas import LogQueryRange
from ..models import (
    Alert,
    AlertSeverity,
    AlertStatus,
    AgentToolRegistration,
    ArtifactVersion,
    ArtifactVersionStatus,
    CollectorDefinition,
    CollectorDeployment,
    CollectorDeploymentMode,
    CollectorRun,
    CollectorRunStatus,
    Device,
    DeviceConnection,
    Endpoint,
    EndpointAttachment,
    GovernedChangePlan,
    IPAddressObservation,
    Investigation,
    InvestigationEvidence,
    InvestigationToolCall,
    KnowledgeEntity,
    KnowledgeRelationship,
    MetricBackend,
    Situation,
    ServiceReportInstance,
    WirelessClientSession,
    WorkerScalingApplicationEvent,
    WorkerScalingDecision,
    WorkerScalingPolicy,
)
from ..metric_schemas import PrometheusInstantQuery, PrometheusRangeQuery
from ..schemas import normalize_ip, normalize_mac
from ..situation_impact_schemas import SituationImpactRead
from .agent_runtime import (
    add_evidence_reference,
    complete_tool_call,
    create_tool_call,
)
from .authorization_scope import (
    alert_scope_clause,
    authorized_device_ids,
    collector_deployment_scope_clause,
    device_scope_clause,
    endpoint_scope_clause,
    has_global_scope,
    knowledge_entity_scope_clause,
    knowledge_relationship_scope_clause,
    namespace_clause,
    situation_scope_clause,
)
from .control_plane_auth import PrincipalContext, development_principal
from .collectors import trigger_deployment, _assignment_hash, _deployment_device_identity_current
from .metrics import get_metric_backend, query_instant, query_range
from .logs import (
    assert_device_log_result,
    build_device_log_query,
    get_log_backend,
    query_logs,
)
from .situation_impact import situation_impact_graph
from .report_instances import (
    list_visible_report_instances, visible_report_instance, verified_instance_snapshot,
)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _get_device(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    device = db.scalar(
        select(Device)
        .where(
            Device.id == arguments["device_id"],
            device_scope_clause(principal),
        )
        .options(
            selectinload(Device.connections).selectinload(
                DeviceConnection.activations
            )
        )
    )
    if device is None:
        raise LookupError("Device not found")
    connection_results: list[dict[str, Any]] = []
    for connection in device.connections[:32]:
        active = [
            item for item in connection.activations if item.status == "active"
        ][:8]
        runtime_priority = {
            "drifted": 6,
            "stale": 5,
            "degraded": 4,
            "on_demand_failed": 3,
            "awaiting_first_run": 2,
            "on_demand_ready": 1,
            "healthy": 0,
        }
        primary = (
            max(
                active,
                key=lambda item: runtime_priority.get(item.runtime_status, 2),
            )
            if active
            else None
        )
        health_reason = primary.health_reason if primary else None
        if primary is not None and len(active) > 1:
            health_reason = (
                f"{len(active)} active capabilities. "
                f"Most significant state: {primary.health_reason or primary.runtime_status}."
            )
        connection_results.append(
            {
                "id": connection.id,
                "protocol": connection.protocol,
                "verification_status": connection.verification_status,
                "activation_status": primary.status if primary else None,
                "runtime_status": primary.runtime_status if primary else None,
                "health_reason": health_reason,
            }
        )
    result = {
        "id": device.id,
        "name": device.name,
        "kind": device.kind,
        "management_ip": device.management_ip,
        "site": device.site,
        "onboarding_status": device.onboarding_status,
        "connections": connection_results,
    }
    registration = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == "inventory.get_device"))
    if registration is not None and "discovered_name" in registration.output_schema.get("properties", {}):
        result["discovered_name"] = device.discovered_name
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="device",
            evidence_id=device.id,
            summary=(
                f"Device {device.name} is {device.onboarding_status} with "
                f"{len(device.connections)} monitoring connection(s)."
            ),
            observed_at=device.updated_at,
        )
    ]


def _list_open_alerts(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    limit = int(arguments.get("limit", 20))
    query = select(Alert).where(
        Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
        Alert.source_retirement_id.is_(None),
        alert_scope_clause(principal),
    )
    severity = arguments.get("severity")
    if severity:
        query = query.where(Alert.severity == AlertSeverity(severity))
    alerts = list(
        db.scalars(
            query.order_by(Alert.last_seen.desc(), Alert.id).limit(limit)
        ).all()
    )
    result = {
        "alerts": [
            {
                "id": alert.id,
                "severity": alert.severity.value,
                "status": alert.status.value,
                "title": alert.title,
                "entity_type": alert.entity_type,
                "entity_id": alert.entity_id,
                "last_seen": alert.last_seen.isoformat(),
                "occurrence_count": alert.occurrence_count,
            }
            for alert in alerts
        ]
    }
    evidence = [
        InvestigationEvidenceCreate(
            evidence_type="alert",
            evidence_id=alert.id,
            summary=(
                f"{alert.severity.value} alert {alert.title!r} is "
                f"{alert.status.value}."
            ),
            observed_at=alert.last_seen,
        )
        for alert in alerts
    ]
    return result, evidence


def _endpoint_from_selector(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> Endpoint:
    selectors = [
        key
        for key in ("endpoint_id", "mac_address", "ip_address")
        if arguments.get(key)
    ]
    if len(selectors) != 1:
        raise ValueError(
            "Exactly one of endpoint_id, mac_address, or ip_address is required"
        )
    selector = selectors[0]
    if selector == "endpoint_id":
        endpoint = db.scalar(
            select(Endpoint).where(
                Endpoint.id == arguments[selector],
                endpoint_scope_clause(principal),
            )
        )
    elif selector == "mac_address":
        endpoint = db.scalar(
            select(Endpoint).where(
                Endpoint.mac_address == normalize_mac(arguments[selector]),
                endpoint_scope_clause(principal),
            )
        )
    else:
        address = normalize_ip(arguments[selector])
        endpoint_ids = list(
            db.scalars(
                select(Endpoint.id)
                .join(IPAddressObservation)
                .where(IPAddressObservation.ip_address == address)
                .where(endpoint_scope_clause(principal))
                .distinct()
                .limit(2)
            ).all()
        )
        if len(endpoint_ids) > 1:
            raise ValueError(
                "IP address matches multiple historical endpoints; use a MAC "
                "address or endpoint ID"
            )
        endpoint = db.get(Endpoint, endpoint_ids[0]) if endpoint_ids else None
    if endpoint is None:
        raise LookupError("Endpoint not found")
    return endpoint


def _get_endpoint_history(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    endpoint = _endpoint_from_selector(db, arguments, principal)
    limit = int(arguments.get("limit", 50))
    allowed_ids = authorized_device_ids(db, principal)
    ip_scope = (
        []
        if allowed_ids is None
        else [IPAddressObservation.collector_device_id.in_(allowed_ids)]
    )
    wired_scope = (
        []
        if allowed_ids is None
        else [EndpointAttachment.collector_device_id.in_(allowed_ids)]
    )
    wireless_scope = (
        []
        if allowed_ids is None
        else [WirelessClientSession.controller_id.in_(allowed_ids)]
    )
    ip_history = list(
        db.scalars(
            select(IPAddressObservation)
            .where(
                IPAddressObservation.endpoint_id == endpoint.id,
                *ip_scope,
            )
            .order_by(
                IPAddressObservation.active.desc(),
                IPAddressObservation.last_seen.desc(),
                IPAddressObservation.id,
            )
            .limit(limit + 1)
        ).all()
    )
    wired_history = list(
        db.scalars(
            select(EndpointAttachment)
            .where(
                EndpointAttachment.endpoint_id == endpoint.id,
                *wired_scope,
            )
            .order_by(
                EndpointAttachment.active.desc(),
                EndpointAttachment.last_seen.desc(),
                EndpointAttachment.id,
            )
            .limit(limit + 1)
        ).all()
    )
    wireless_history = list(
        db.scalars(
            select(WirelessClientSession)
            .where(
                WirelessClientSession.endpoint_id == endpoint.id,
                *wireless_scope,
            )
            .order_by(
                WirelessClientSession.active.desc(),
                WirelessClientSession.last_seen.desc(),
                WirelessClientSession.id,
            )
            .limit(limit + 1)
        ).all()
    )
    truncated = [label for label, rows in (("IP", ip_history), ("wired", wired_history), ("wireless", wireless_history))
        if len(rows) > limit]
    ip_history, wired_history, wireless_history = ip_history[:limit], wired_history[:limit], wireless_history[:limit]
    result = {
        "id": endpoint.id,
        "mac_address": endpoint.mac_address,
        "hostname": endpoint.hostname,
        "vendor": endpoint.vendor,
        "first_seen": endpoint.first_seen.isoformat(),
        "last_seen": endpoint.last_seen.isoformat(),
        "ip_history": [
            {
                "address": item.ip_address,
                "source": item.source.value,
                "collector_device_id": item.collector_device_id,
                "vlan_id": item.vlan_id,
                "active": item.active,
                "first_seen": item.first_seen.isoformat(),
                "last_seen": item.last_seen.isoformat(),
            }
            for item in ip_history
        ],
        "wired_history": [
            {
                "source": item.source.value,
                "collector_device_id": item.collector_device_id,
                "interface_name": item.interface_name,
                "vlan_id": item.vlan_id,
                "active": item.active,
                "first_seen": item.first_seen.isoformat(),
                "last_seen": item.last_seen.isoformat(),
            }
            for item in wired_history
        ],
        "wireless_history": [
            {
                "controller_id": item.controller_id,
                "ip_address": item.ip_address,
                "access_point": item.access_point,
                "ssid": item.ssid,
                "band": item.band,
                "channel": item.channel,
                "vlan_id": item.vlan_id,
                "rssi": item.rssi,
                "snr": item.snr,
                "active": item.active,
                "connected_at": (
                    item.connected_at.isoformat() if item.connected_at else None
                ),
                "disconnected_at": (
                    item.disconnected_at.isoformat()
                    if item.disconnected_at
                    else None
                ),
                "first_seen": item.first_seen.isoformat(),
                "last_seen": item.last_seen.isoformat(),
            }
            for item in wireless_history
        ],
    }
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="endpoint",
            evidence_id=endpoint.id,
            summary=(
                f"Endpoint {endpoint.mac_address} has {len(ip_history)} IP, "
                f"{len(wired_history)} wired, and {len(wireless_history)} "
                "wireless history record(s) in this bounded result. "
                + ("Additional authorized history was truncated: " + ", ".join(truncated) + ". " if truncated else "")
                + "Logical history is not an independently verified complete current source snapshot."
            ),
            observed_at=endpoint.last_seen,
        )
    ]


def _wireless_controller_from_id(
    db: Session,
    controller_id: Any,
    principal: PrincipalContext,
) -> Device:
    if not isinstance(controller_id, str) or not controller_id:
        raise ValueError("Wireless controller ID is required")
    controller = db.scalar(
        select(Device).where(
            Device.id == controller_id,
            Device.kind == "wireless_controller",
            device_scope_clause(principal),
        )
    )
    if controller is None:
        raise LookupError("Wireless controller not found")
    return controller


def _bounded_wireless_integer(
    arguments: dict[str, Any],
    key: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    value = arguments.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Wireless {key} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(
            f"Wireless {key} must be between {minimum} and {maximum}"
        )
    return value


def _optional_wireless_text(
    arguments: dict[str, Any],
    key: str,
) -> str | None:
    value = arguments.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 255:
        raise ValueError(f"Wireless {key} filter is invalid")
    return value


def _list_wireless_controller_clients(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    controller = _wireless_controller_from_id(
        db,
        arguments.get("controller_id"),
        principal,
    )
    access_point = _optional_wireless_text(arguments, "access_point")
    ssid = _optional_wireless_text(arguments, "ssid")
    rssi_at_most = arguments.get("rssi_at_most")
    if rssi_at_most is not None:
        rssi_at_most = _bounded_wireless_integer(
            arguments,
            "rssi_at_most",
            default=0,
            minimum=-150,
            maximum=0,
        )
    snr_at_most = arguments.get("snr_at_most")
    if snr_at_most is not None:
        snr_at_most = _bounded_wireless_integer(
            arguments,
            "snr_at_most",
            default=100,
            minimum=-50,
            maximum=100,
        )
    active_only = arguments.get("active_only", True)
    if not isinstance(active_only, bool):
        raise ValueError("Wireless active_only must be a boolean")
    max_age_minutes = _bounded_wireless_integer(
        arguments,
        "max_age_minutes",
        default=60,
        minimum=1,
        maximum=10_080,
    )
    limit = _bounded_wireless_integer(
        arguments,
        "limit",
        default=50,
        minimum=1,
        maximum=100,
    )
    cutoff = datetime.now(UTC) - timedelta(minutes=max_age_minutes)
    query = (
        select(WirelessClientSession)
        .join(
            Endpoint,
            WirelessClientSession.endpoint_id == Endpoint.id,
        )
        .where(
            WirelessClientSession.controller_id == controller.id,
            WirelessClientSession.last_seen >= cutoff,
            namespace_clause(WirelessClientSession, principal),
        )
        .options(selectinload(WirelessClientSession.endpoint))
    )
    if active_only:
        query = query.where(WirelessClientSession.active.is_(True))
    if access_point is not None:
        query = query.where(WirelessClientSession.access_point == access_point)
    if ssid is not None:
        query = query.where(WirelessClientSession.ssid == ssid)
    if rssi_at_most is not None:
        query = query.where(
            WirelessClientSession.rssi.is_not(None),
            WirelessClientSession.rssi <= rssi_at_most,
        )
    if snr_at_most is not None:
        query = query.where(
            WirelessClientSession.snr.is_not(None),
            WirelessClientSession.snr <= snr_at_most,
        )
    matches = list(
        db.scalars(
            query.order_by(
                WirelessClientSession.active.desc(),
                WirelessClientSession.last_seen.desc(),
                WirelessClientSession.id,
            ).limit(limit + 1)
        ).all()
    )
    truncated = len(matches) > limit
    sessions = matches[:limit]
    filters = {
        "access_point": access_point,
        "ssid": ssid,
        "rssi_at_most": rssi_at_most,
        "snr_at_most": snr_at_most,
        "active_only": active_only,
        "max_age_minutes": max_age_minutes,
    }
    evidence_observed_at = max(
        [
            _as_utc(controller.updated_at),
            *(_as_utc(session.last_seen) for session in sessions),
        ]
    )
    result = {
        "controller": {
            "id": controller.id,
            "name": controller.name,
            "site": controller.site,
        },
        "filters": filters,
        "clients": [
            {
                "session_id": session.id,
                "endpoint_id": session.endpoint_id,
                "mac_address": session.endpoint.mac_address,
                "hostname": session.endpoint.hostname,
                "vendor": session.endpoint.vendor,
                "ip_address": session.ip_address,
                "access_point": session.access_point,
                "ssid": session.ssid,
                "bssid": session.bssid,
                "radio": session.radio,
                "band": session.band,
                "channel": session.channel,
                "vlan_id": session.vlan_id,
                "rssi": session.rssi,
                "snr": session.snr,
                "active": session.active,
                "connected_at": (
                    _as_utc(session.connected_at).isoformat()
                    if session.connected_at
                    else None
                ),
                "last_seen": _as_utc(session.last_seen).isoformat(),
            }
            for session in sessions
        ],
        "truncated": truncated,
        "observed_at": evidence_observed_at.isoformat(),
    }
    request_hash = hashlib.sha256(
        json.dumps(
            {
                "controller_id": controller.id,
                **filters,
                "limit": limit,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    qualifier = "active " if active_only else ""
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="wireless_controller_clients",
            evidence_id=f"{controller.id}:{request_hash}",
            summary=(
                f"Wireless controller {controller.name!r} returned "
                f"{len(sessions)} bounded {qualifier}client session(s); "
                f"request SHA-256 is {request_hash}."
            ),
            observed_at=evidence_observed_at,
        )
    ]


def _list_metric_backends(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    if not principal.permits("metrics.read"):
        raise PermissionError("Metric backend discovery requires metrics.read")
    limit = int(arguments.get("limit", 20))
    if not 1 <= limit <= 100:
        raise ValueError("Metric backend discovery limit must be between 1 and 100")
    # Select public identity only: never load endpoint URLs, credentials, labels
    # or diagnostic bodies into the model's discovery result.
    query = select(MetricBackend.id, MetricBackend.name, MetricBackend.provider).where(
        namespace_clause(MetricBackend, principal), MetricBackend.enabled.is_(True)
    )
    if arguments.get("name"):
        query = query.where(MetricBackend.name == arguments["name"])
    rows = db.execute(query.order_by(MetricBackend.name, MetricBackend.id).limit(limit + 1)).all()
    truncated = len(rows) > limit
    return {
        "backends": [{"backend_id": row.id, "name": row.name, "provider": row.provider} for row in rows[:limit]],
        "truncated": truncated,
        "next_action": (
            "No enabled metric backend matched. Report the missing configuration; do not invent an ID."
            if not rows else
            "Use a returned backend_id for metric queries, not a name or Grafana datasource UID. "
            "Discovery does not prove health or a mapping to a Grafana connection. "
            "Ask if the intended backend is ambiguous."
            + (" The list is truncated; filter by exact name or increase limit up to 100." if truncated else "")
        ),
    }, []


def _query_instant_metrics(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    backend = get_metric_backend(db, arguments["backend_id"])
    query = arguments["query"]
    result = query_instant(
        db,
        backend,
        PrometheusInstantQuery(
            query=query,
            time=arguments.get("time"),
            timeout_seconds=int(arguments.get("timeout_seconds", 10)),
            limit=int(arguments.get("limit", 100)),
            actor="agent.runtime",
        ),
        actor_type="agent",
        principal=principal,
    )
    query_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()
    series_count = len(result.result) if isinstance(result.result, list) else 1
    return result.model_dump(mode="json"), [
        InvestigationEvidenceCreate(
            evidence_type="metric_query",
            evidence_id=f"{backend.id}:{query_hash}",
            summary=(
                f"Instant metric query against {backend.name!r} returned "
                f"{series_count} {result.result_type} result item(s); query "
                f"SHA-256 is {query_hash}."
            ),
            observed_at=result.queried_at,
        )
    ]


def _query_range_metrics(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    backend = get_metric_backend(db, arguments["backend_id"])
    query = arguments["query"]
    payload = PrometheusRangeQuery(
        query=query,
        start=arguments["start"],
        end=arguments["end"],
        step_seconds=int(arguments.get("step_seconds", 60)),
        timeout_seconds=int(arguments.get("timeout_seconds", 10)),
        limit=int(arguments.get("limit", 100)),
        actor="agent.runtime",
    )
    start = _as_utc(payload.start)
    end = _as_utc(payload.end)
    duration = end - start
    if duration > timedelta(days=7):
        raise ValueError("Agent metric query range must not exceed seven days")
    evaluation_steps = duration.total_seconds() / payload.step_seconds
    if evaluation_steps > 2_000:
        raise ValueError(
            "Agent metric query range must not exceed 2000 evaluation steps"
        )
    result = query_range(db, backend, payload, actor_type="agent", principal=principal)
    request_hash = hashlib.sha256(
        json.dumps(
            {
                "backend_id": backend.id,
                "query": query,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "step_seconds": payload.step_seconds,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    series_count = len(result.result) if isinstance(result.result, list) else 1
    return result.model_dump(mode="json"), [
        InvestigationEvidenceCreate(
            evidence_type="metric_range_query",
            evidence_id=f"{backend.id}:{request_hash}",
            summary=(
                f"Range metric query against {backend.name!r} returned "
                f"{series_count} {result.result_type} result item(s) from "
                f"{start.isoformat()} through {end.isoformat()}; request "
                f"SHA-256 is {request_hash}."
            ),
            observed_at=result.queried_at,
        )
    ]


_DEVICE_METRIC_PREFIXES = (
    "windows_",
    "wmi_",
    "node_",
    "if",
    "sys",
    "snmp_",
    "probe_",
)
_DEVICE_METRIC_LABELS = {
    "icheck_tenant_id",
    "icheck_region_id",
    "icheck_device_id",
    "icheck_connection_id",
    "icheck_enrollment_id",
    "icheck_enrollment_revision",
    "icheck_protocol",
    "__name__",
    "instance",
    "job",
    "device",
    "hostname",
    "core",
    "cpu",
    "mode",
    "interface",
    "ifIndex",
    "ifName",
    "volume",
    "service",
    "state",
    "status",
    "collector",
    "quantile",
}


def _get_device_range_metrics(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    device = db.scalar(
        select(Device).where(
            Device.id == arguments["device_id"],
            device_scope_clause(principal),
        )
    )
    if device is None:
        raise LookupError("Device not found")
    metric = arguments["metric"]
    if metric != "up" and not metric.startswith(_DEVICE_METRIC_PREFIXES):
        raise ValueError("Metric is not in the device exporter namespace allowlist")

    expected_labels = {
        "icheck_tenant_id": principal.tenant_id,
        "icheck_region_id": principal.region_id,
        "icheck_device_id": device.id,
    }
    selector = ",".join(
        f"{key}={json.dumps(value)}" for key, value in expected_labels.items()
    )
    query = f"{metric}{{{selector}}}"
    payload = PrometheusRangeQuery(
        query=query,
        start=arguments["start"],
        end=arguments["end"],
        step_seconds=int(arguments.get("step_seconds", 60)),
        timeout_seconds=int(arguments.get("timeout_seconds", 10)),
        limit=int(arguments.get("limit", 20)),
        actor="agent.runtime",
    )
    start = _as_utc(payload.start)
    end = _as_utc(payload.end)
    duration = end - start
    if duration > timedelta(days=7):
        raise ValueError("Agent device metric range must not exceed seven days")
    if duration.total_seconds() / payload.step_seconds > 2_000:
        raise ValueError(
            "Agent device metric range must not exceed 2000 evaluation steps"
        )
    backend = get_metric_backend(db, arguments["backend_id"])
    response = query_range(db, backend, payload, actor_type="agent", principal=principal)
    if response.result_type != "matrix" or not isinstance(response.result, list):
        raise ValueError("Device metric backend must return a matrix result")
    if len(response.result) > payload.limit:
        raise ValueError("Device metric backend exceeded the requested series limit")

    sanitized_series: list[dict[str, Any]] = []
    for series in response.result:
        if not isinstance(series, dict):
            raise ValueError("Device metric series is invalid")
        labels = series.get("metric")
        values = series.get("values")
        if not isinstance(labels, dict) or not isinstance(values, list):
            raise ValueError("Device metric series is missing labels or values")
        if any(labels.get(key) != value for key, value in expected_labels.items()):
            raise PermissionError(
                "Metric backend returned a series outside the device selector"
            )
        if labels.get("__name__") != metric:
            raise PermissionError(
                "Metric backend returned a different metric than requested"
            )
        if len(values) > 2_001:
            raise ValueError("Device metric series exceeded its point limit")
        normalized_values: list[list[Any]] = []
        for sample in values:
            if (
                not isinstance(sample, list)
                or len(sample) != 2
                or isinstance(sample[0], bool)
                or not isinstance(sample[0], (int, float))
                or not isinstance(sample[1], str)
                or len(sample[1]) > 64
            ):
                raise ValueError("Device metric sample is invalid")
            normalized_values.append([sample[0], sample[1]])
        safe_labels: dict[str, str] = {}
        for key, value in labels.items():
            if key not in _DEVICE_METRIC_LABELS:
                continue
            if not isinstance(value, str) or len(value) > 512:
                raise ValueError("Device metric label is invalid")
            safe_labels[key] = value
        sanitized_series.append(
            {"metric": safe_labels, "values": normalized_values}
        )

    request_hash = hashlib.sha256(
        json.dumps(
            {
                "backend_id": backend.id,
                "device_id": device.id,
                "metric": metric,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "step_seconds": payload.step_seconds,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    result = {
        "backend_id": backend.id,
        "device_id": device.id,
        "metric": metric,
        "mode": "range",
        "result_type": "matrix",
        "result": sanitized_series,
        "warnings": response.warnings,
        "infos": response.infos,
        "queried_at": response.queried_at.isoformat(),
    }
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="device_metric_range",
            evidence_id=f"{device.id}:{request_hash}",
            summary=(
                f"Device {device.name!r} metric {metric!r} returned "
                f"{len(sanitized_series)} bounded series from "
                f"{start.isoformat()} through {end.isoformat()}; request "
                f"SHA-256 is {request_hash}."
            ),
            observed_at=response.queried_at,
        )
    ]


def _log_query_payload(arguments: dict[str, Any], *, limit: int) -> LogQueryRange:
    payload = LogQueryRange(
        query=arguments["query"],
        start=arguments["start"],
        end=arguments["end"],
        direction=arguments.get("direction", "backward"),
        limit=int(arguments.get("limit", limit)),
        timeout_seconds=int(arguments.get("timeout_seconds", 10)),
        actor="agent.runtime",
    )
    if _as_utc(payload.end) - _as_utc(payload.start) > timedelta(days=1):
        raise ValueError("Agent log query range must not exceed 24 hours")
    return payload


def _log_request_hash(
    *,
    backend_id: str,
    query: str,
    payload: LogQueryRange,
    device_id: str | None = None,
) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "backend_id": backend_id,
                "device_id": device_id,
                "query": query,
                "start": _as_utc(payload.start).isoformat(),
                "end": _as_utc(payload.end).isoformat(),
                "direction": payload.direction,
                "limit": payload.limit,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _query_log_range(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    if not has_global_scope(principal):
        raise PermissionError(
            "Scoped LogQL requires a scope-enforcing logs gateway"
        )
    payload = _log_query_payload(arguments, limit=500)
    backend = get_log_backend(db, arguments["backend_id"])
    response = query_logs(db, backend, payload, actor_type="agent")
    result = response.model_dump(mode="json")
    request_hash = _log_request_hash(
        backend_id=backend.id,
        query=payload.query,
        payload=payload,
    )
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="log_range_query",
            evidence_id=f"{backend.id}:{request_hash}",
            summary=(
                f"Log backend {backend.name!r} returned "
                f"{len(response.entries)} bounded redacted entries; complete "
                f"request SHA-256 is {request_hash}."
            ),
            observed_at=response.queried_at,
        )
    ]


def _get_device_log_range(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    device = db.scalar(
        select(Device).where(
            Device.id == arguments["device_id"],
            device_scope_clause(principal),
        )
    )
    if device is None:
        raise LookupError("Device not found")
    backend = get_log_backend(db, arguments["backend_id"])
    query, instance_matcher = build_device_log_query(
        backend,
        device_name=device.name,
        management_ip=device.management_ip,
    )
    payload = _log_query_payload(
        {**arguments, "query": query},
        limit=200,
    )
    if payload.limit > 500:
        raise ValueError("Agent device log query limit must not exceed 500")
    response = query_logs(db, backend, payload, actor_type="agent")
    assert_device_log_result(backend, response, instance_matcher)
    result = response.model_dump(mode="json")
    result["device_id"] = device.id
    request_hash = _log_request_hash(
        backend_id=backend.id,
        query=query,
        payload=payload,
        device_id=device.id,
    )
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="device_log_range",
            evidence_id=f"{device.id}:{request_hash}",
            summary=(
                f"Device {device.name!r} has {len(response.entries)} bounded "
                f"redacted log entries; complete request SHA-256 is "
                f"{request_hash}."
            ),
            observed_at=response.queried_at,
        )
    ]


_WINDOWS_DIAGNOSTIC_FIELDS = {
    "operating_system": {
        "Caption",
        "Version",
        "BuildNumber",
        "LastBootUpTime",
        "TotalVisibleMemorySize",
        "FreePhysicalMemory",
    },
    "computer_system": {
        "Name",
        "Domain",
        "Manufacturer",
        "Model",
        "TotalPhysicalMemory",
        "NumberOfLogicalProcessors",
    },
    "logical_disks": {
        "DeviceID",
        "VolumeName",
        "FileSystem",
        "Size",
        "FreeSpace",
    },
    "network_adapters": {
        "Description",
        "MACAddress",
        "IPAddress",
        "IPSubnet",
        "DefaultIPGateway",
        "DNSServerSearchOrder",
    },
}


def _windows_diagnostic_operations(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("Windows diagnostic operations are required")
    if len(value) > len(_WINDOWS_DIAGNOSTIC_FIELDS):
        raise ValueError("Windows diagnostic operation list is oversized")
    operations: list[str] = []
    for item in value:
        if item not in _WINDOWS_DIAGNOSTIC_FIELDS:
            raise ValueError("Windows diagnostic operation is unsupported")
        if item in operations:
            raise ValueError("Windows diagnostic operations must be unique")
        operations.append(item)
    return operations


def _request_windows_diagnostics(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    device = db.scalar(
        select(Device).where(
            Device.id == arguments["device_id"],
            device_scope_clause(principal),
        )
    )
    if device is None:
        raise LookupError("Device not found")
    requested_operations = _windows_diagnostic_operations(
        arguments.get("operations")
    )
    reason = arguments.get("reason")
    if not isinstance(reason, str) or not 3 <= len(reason) <= 1_000:
        raise ValueError("Windows diagnostic reason is invalid")

    query = (
        select(CollectorDeployment, CollectorDefinition)
        .join(
            ArtifactVersion,
            CollectorDeployment.artifact_version_id == ArtifactVersion.id,
        )
        .join(
            CollectorDefinition,
            CollectorDefinition.artifact_version_id == ArtifactVersion.id,
        )
        .where(
            CollectorDeployment.scope_device_id == device.id,
            CollectorDeployment.execution_mode
            == CollectorDeploymentMode.ON_DEMAND,
            CollectorDeployment.enabled.is_(True),
            collector_deployment_scope_clause(principal),
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
            CollectorDefinition.adapter_type == "psrp_cim",
        )
    )
    deployment_id = arguments.get("deployment_id")
    if deployment_id:
        query = query.where(CollectorDeployment.id == deployment_id)
    candidates: list[tuple[CollectorDeployment, list[str]]] = []
    for deployment, definition in db.execute(
        query.order_by(CollectorDeployment.id).limit(21)
    ).all():
        if not _deployment_device_identity_current(db, deployment):
            continue
        configuration = {**definition.defaults, **deployment.configuration}
        try:
            configured_operations = _windows_diagnostic_operations(
                configuration.get("operations")
            )
        except ValueError:
            continue
        if set(configured_operations) == set(requested_operations):
            candidates.append((deployment, configured_operations))
    if not candidates:
        raise LookupError(
            "No enabled published Windows diagnostic deployment matches the "
            "device and exact operation set"
        )
    if len(candidates) > 1:
        raise ValueError(
            "Windows diagnostic deployment is ambiguous; provide deployment_id"
        )

    deployment, configured_operations = candidates[0]
    now = datetime.now(UTC)
    if deployment.next_run_at is not None:
        requested_at = _as_utc(deployment.next_run_at)
        if (
            deployment.lease_expires_at is not None
            and _as_utc(deployment.lease_expires_at) >= now
        ):
            queue_status = "running"
            if deployment.last_started_at is not None:
                requested_at = _as_utc(deployment.last_started_at)
        else:
            queue_status = "already_queued"
    else:
        deployment = trigger_deployment(
            db,
            deployment.id,
            actor="agent.runtime",
            actor_type="agent",
            reason=reason,
        )
        if deployment.next_run_at is None:
            raise RuntimeError("Windows diagnostic request was not queued")
        requested_at = _as_utc(deployment.next_run_at)
        queue_status = "queued"

    result = {
        "device_id": device.id,
        "deployment_id": deployment.id,
        "operations": configured_operations,
        "queue_status": queue_status,
        "requested_at": requested_at.isoformat(),
    }
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="windows_diagnostic_request",
            evidence_id=f"{deployment.id}:{requested_at.isoformat()}",
            summary=(
                f"Governed Windows diagnostic deployment {deployment.id} is "
                f"{queue_status} for device {device.name!r} with the exact "
                f"operation set {', '.join(configured_operations)}."
            ),
            observed_at=requested_at,
        )
    ]


def _windows_diagnostic_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("Windows diagnostic field has an unsupported value")
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Windows diagnostic field must be finite")
        return value
    if isinstance(value, str):
        if len(value) > 2_000:
            raise ValueError("Windows diagnostic string is oversized")
        return value
    if isinstance(value, list) and len(value) <= 32:
        if all(isinstance(item, str) and len(item) <= 512 for item in value):
            return list(value)
    raise ValueError("Windows diagnostic field has an unsupported value")


def _get_latest_windows_diagnostics(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    device = db.scalar(
        select(Device).where(
            Device.id == arguments["device_id"],
            device_scope_clause(principal),
        )
    )
    if device is None:
        raise LookupError("Device not found")
    explicit_operations = arguments.get("operations")
    requested_operations = set(_windows_diagnostic_operations(explicit_operations)
        if explicit_operations is not None else _WINDOWS_DIAGNOSTIC_FIELDS)
    max_age_minutes = int(arguments.get("max_age_minutes", 60))
    if not 1 <= max_age_minutes <= 10_080:
        raise ValueError("Windows diagnostic max age is invalid")
    limit = int(arguments.get("limit", 50))
    if not 1 <= limit <= 100:
        raise ValueError("Windows diagnostic record limit is invalid")
    if explicit_operations is not None and limit < len(requested_operations):
        raise ValueError("Record limit must cover every requested diagnostic operation")
    now = datetime.now(UTC)
    cutoff = now - timedelta(minutes=max_age_minutes)
    not_before = arguments.get("not_before")
    if not_before is not None:
        try:
            if not isinstance(not_before, str) or len(not_before) > 64:
                raise ValueError()
            requested_at = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
            if requested_at.tzinfo is None or requested_at > now + timedelta(seconds=5):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError("Diagnostic not_before must be an aware request timestamp, not in the future") from None
        cutoff = max(cutoff, requested_at.astimezone(UTC))
    deployment_id = arguments.get("deployment_id")
    runs = list(
        db.scalars(
            select(CollectorRun)
            .join(
                CollectorDeployment,
                CollectorRun.deployment_id == CollectorDeployment.id,
            )
            .join(
                ArtifactVersion,
                CollectorRun.artifact_version_id == ArtifactVersion.id,
            )
            .join(
                CollectorDefinition,
                CollectorDefinition.artifact_version_id == ArtifactVersion.id,
            )
            .where(
                CollectorDeployment.scope_device_id == device.id,
                CollectorDeployment.execution_mode
                == CollectorDeploymentMode.ON_DEMAND,
                collector_deployment_scope_clause(principal),
                namespace_clause(CollectorRun, principal),
                CollectorDeployment.enabled.is_(True),
                ArtifactVersion.status.in_([ArtifactVersionStatus.PUBLISHED, ArtifactVersionStatus.DEPRECATED]),
                or_(CollectorDeployment.id == deployment_id, deployment_id is None),
                CollectorDefinition.adapter_type == "psrp_cim",
                CollectorRun.status == CollectorRunStatus.SUCCEEDED,
                CollectorRun.finished_at.is_not(None),
                CollectorRun.finished_at >= cutoff,
            )
            .options(selectinload(CollectorRun.envelopes))
            .order_by(CollectorRun.finished_at.desc(), CollectorRun.id.desc())
            .limit(20)
        )
        .unique()
        .all()
    )
    selected_run: CollectorRun | None = None
    records: list[dict[str, Any]] = []
    truncated = False
    for run in runs:
        deployment = run.deployment
        # A completed run is historical after its target/template changes.
        # Keep the records, but never present them as this device's fresh check.
        if (not run.assignment_sha256 or run.assignment_sha256 != _assignment_hash(deployment)
                or not _deployment_device_identity_current(db, deployment)
                or run.artifact_version_id != deployment.artifact_version_id
                or _as_utc(run.started_at) > _as_utc(run.finished_at)
                or _as_utc(run.finished_at) > now + timedelta(seconds=5)):
            continue
        try:
            configuration = {**deployment.artifact_version.collector_definition.defaults, **deployment.configuration}
            configured = set(_windows_diagnostic_operations(configuration.get("operations")))
        except ValueError:
            continue
        candidate_records: list[dict[str, Any]] = []
        for envelope in sorted(
            run.envelopes,
            key=lambda item: (item.observed_at, item.id),
        ):
            if not envelope.type.startswith("windows.cim."):
                continue
            operation = envelope.type.removeprefix("windows.cim.")
            if operation not in requested_operations or operation not in configured:
                continue
            observed = _as_utc(envelope.observed_at)
            if (observed < cutoff or observed < _as_utc(run.started_at) - timedelta(seconds=5)
                    or observed > min(now, _as_utc(run.finished_at)) + timedelta(seconds=5)):
                continue
            payload = envelope.payload
            if (
                not isinstance(payload, dict)
                or payload.get("operation") != operation
                or not isinstance(payload.get("data"), dict)
            ):
                raise ValueError("Windows diagnostic evidence is malformed")
            if payload.get("target") != deployment.target.get("host") or envelope.subject != deployment.target.get("host"):
                continue
            allowed_fields = _WINDOWS_DIAGNOSTIC_FIELDS[operation]
            fields = {
                key: _windows_diagnostic_value(value)
                for key, value in payload["data"].items()
                if key in allowed_fields
            }
            if not fields:
                raise ValueError(
                    "Windows diagnostic evidence has no allowlisted fields"
                )
            candidate_records.append(
                {
                    "operation": operation,
                    "observed_at": _as_utc(envelope.observed_at).isoformat(),
                    "fields": fields,
                }
            )
        available = {record["operation"] for record in candidate_records}
        if candidate_records and (explicit_operations is None or requested_operations <= available):
            if explicit_operations is not None:
                # Truncation may remove extra rows, never a requested operation.
                first = {next(index for index, record in enumerate(candidate_records) if record["operation"] == operation)
                    for operation in requested_operations}
                candidate_records = [record for index, record in enumerate(candidate_records) if index in first] + [
                    record for index, record in enumerate(candidate_records) if index not in first]
            selected_run = run
            truncated = len(candidate_records) > limit
            records = candidate_records[:limit]
            break
    if selected_run is None or selected_run.finished_at is None:
        raise LookupError("No fresh successful Windows diagnostic evidence found")
    db.refresh(selected_run.deployment)
    if (not selected_run.deployment.enabled
            or selected_run.assignment_sha256 != _assignment_hash(selected_run.deployment)
            or not _deployment_device_identity_current(db, selected_run.deployment)
            or db.scalar(select(Device.id).where(Device.id == device.id, device_scope_clause(principal))) is None):
        raise LookupError("Windows diagnostic target changed while reading evidence")
    finished_at = _as_utc(selected_run.finished_at)
    result = {
        "device_id": device.id,
        "run_id": selected_run.id,
        "deployment_id": selected_run.deployment_id,
        "status": "succeeded",
        "started_at": _as_utc(selected_run.started_at).isoformat(),
        "finished_at": finished_at.isoformat(),
        "records": records,
        "truncated": truncated,
    }
    operation_names = sorted({item["operation"] for item in records})
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="windows_diagnostic_run",
            evidence_id=selected_run.id,
            summary=(
                f"Windows device {device.name!r} has {len(records)} fresh "
                f"governed diagnostic record(s) for "
                f"{', '.join(operation_names)} from run {selected_run.id}."
            ),
            observed_at=min(datetime.fromisoformat(record["observed_at"]) for record in records),
        )
    ]


def _knowledge_entity_from_selector(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> KnowledgeEntity:
    entity_id = arguments.get("entity_id")
    entity_type = arguments.get("entity_type")
    external_key = arguments.get("external_key")
    if entity_id and not entity_type and not external_key:
        entity = db.scalar(
            select(KnowledgeEntity).where(
                KnowledgeEntity.id == entity_id,
                knowledge_entity_scope_clause(principal),
            )
        )
    elif not entity_id and entity_type and external_key:
        matches = list(
            db.scalars(
                select(KnowledgeEntity)
                .where(
                    KnowledgeEntity.entity_type == entity_type,
                    KnowledgeEntity.external_key == external_key,
                    knowledge_entity_scope_clause(principal),
                )
                .order_by(KnowledgeEntity.id)
                .limit(2)
            ).all()
        )
        if len(matches) > 1:
            raise ValueError(
                "Knowledge selector is ambiguous; use the durable entity_id"
            )
        entity = matches[0] if matches else None
    else:
        raise ValueError(
            "Provide entity_id or the entity_type and external_key pair"
        )
    if entity is None:
        raise LookupError("Knowledge entity not found")
    return entity


def _knowledge_node(entity: KnowledgeEntity) -> dict[str, Any]:
    return {
        "id": entity.id,
        "entity_type": entity.entity_type,
        "external_key": entity.external_key,
        "display_name": entity.display_name,
        "status": entity.status,
        "active": entity.active,
        "site": entity.scope_site,
        "last_seen": entity.last_seen.isoformat(),
    }


def _query_knowledge_graph(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    root = _knowledge_entity_from_selector(db, arguments, principal)
    limit = int(arguments.get("limit", 25))
    direction = arguments.get("direction", "both")
    if direction == "outgoing":
        direction_clause = KnowledgeRelationship.source_entity_id == root.id
    elif direction == "incoming":
        direction_clause = KnowledgeRelationship.target_entity_id == root.id
    else:
        direction_clause = or_(
            KnowledgeRelationship.source_entity_id == root.id,
            KnowledgeRelationship.target_entity_id == root.id,
        )
    query = select(KnowledgeRelationship).where(
        direction_clause,
        knowledge_relationship_scope_clause(principal),
    )
    if arguments.get("active_only", True):
        query = query.where(KnowledgeRelationship.active.is_(True))
    relationship_types = arguments.get("relationship_types") or []
    if relationship_types:
        query = query.where(
            KnowledgeRelationship.relationship_type.in_(relationship_types)
        )
    found = list(
        db.scalars(
            query.order_by(
                KnowledgeRelationship.last_seen.desc(),
                KnowledgeRelationship.id,
            ).limit(limit + 1)
        ).all()
    )
    truncated = len(found) > limit
    relationships = found[:limit]
    neighbor_ids: list[str] = []
    for relationship in relationships:
        for entity_id in (
            relationship.source_entity_id,
            relationship.target_entity_id,
        ):
            if entity_id != root.id and entity_id not in neighbor_ids:
                neighbor_ids.append(entity_id)
    neighbors_by_id = {
        entity.id: entity
        for entity in db.scalars(
            select(KnowledgeEntity).where(
                KnowledgeEntity.id.in_(neighbor_ids),
                knowledge_entity_scope_clause(principal),
            )
        ).all()
    }
    visible_ids = {root.id, *neighbors_by_id}
    relationships = [
        item
        for item in relationships
        if item.source_entity_id in visible_ids
        and item.target_entity_id in visible_ids
    ]
    result = {
        "root": _knowledge_node(root),
        "neighbors": [
            _knowledge_node(neighbors_by_id[entity_id])
            for entity_id in neighbor_ids
            if entity_id in neighbors_by_id
        ],
        "relationships": [
            _knowledge_relationship_document(item) for item in relationships
        ],
        "truncated": truncated,
    }
    observed_at = max(
        [_as_utc(root.last_seen), *(_as_utc(item.last_seen) for item in relationships)]
    )
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="knowledge_graph",
            evidence_id=root.id,
            summary=(
                f"Knowledge entity {root.display_name!r} has "
                f"{len(result['neighbors'])} neighbor(s) and "
                f"{len(relationships)} relationship(s) in this bounded result."
            ),
            observed_at=observed_at,
        )
    ]


def _knowledge_relationship_document(
    relationship: KnowledgeRelationship,
) -> dict[str, Any]:
    return {
        "id": relationship.id,
        "relationship_type": relationship.relationship_type,
        "source_entity_id": relationship.source_entity_id,
        "target_entity_id": relationship.target_entity_id,
        "directed": relationship.directed,
        "active": relationship.active,
        "last_seen": relationship.last_seen.isoformat(),
    }


def _find_knowledge_paths(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    source = _knowledge_entity_from_selector(
        db,
        {"entity_id": arguments["source_entity_id"]},
        principal,
    )
    target = _knowledge_entity_from_selector(
        db,
        {"entity_id": arguments["target_entity_id"]},
        principal,
    )
    if source.id == target.id:
        raise ValueError("Knowledge path endpoints must be different")
    max_depth = int(arguments.get("max_depth", 3))
    max_paths = int(arguments.get("max_paths", 10))
    if not 1 <= max_depth <= 4 or not 1 <= max_paths <= 20:
        raise ValueError("Knowledge path bounds are invalid")
    direction = arguments.get("direction", "both")
    if direction not in {"outgoing", "both"}:
        raise ValueError("Knowledge path direction is invalid")
    relationship_types = list(arguments.get("relationship_types") or [])
    if len(relationship_types) > 20:
        raise ValueError("Knowledge path relationship filter is oversized")
    active_only = bool(arguments.get("active_only", True))
    node_cache: dict[str, KnowledgeEntity] = {
        source.id: source,
        target.id: target,
    }
    path_states: list[tuple[list[str], list[KnowledgeRelationship]]] = [
        ([source.id], [])
    ]
    found: list[tuple[list[str], list[KnowledgeRelationship]]] = []
    truncated = False

    for _ in range(max_depth):
        frontier = {nodes[-1] for nodes, _edges in path_states}
        if not frontier:
            break
        relationship_query = select(KnowledgeRelationship).where(
            or_(
                KnowledgeRelationship.source_entity_id.in_(frontier),
                KnowledgeRelationship.target_entity_id.in_(frontier),
            ),
            knowledge_relationship_scope_clause(principal),
        )
        if active_only:
            relationship_query = relationship_query.where(
                KnowledgeRelationship.active.is_(True)
            )
        if relationship_types:
            relationship_query = relationship_query.where(
                KnowledgeRelationship.relationship_type.in_(relationship_types)
            )
        level_relationships = list(
            db.scalars(
                relationship_query.order_by(
                    KnowledgeRelationship.last_seen.desc(),
                    KnowledgeRelationship.id,
                ).limit(501)
            ).all()
        )
        if len(level_relationships) > 500:
            truncated = True
            level_relationships = level_relationships[:500]
        candidate_node_ids = {
            entity_id
            for relationship in level_relationships
            for entity_id in (
                relationship.source_entity_id,
                relationship.target_entity_id,
            )
            if entity_id not in node_cache
        }
        if candidate_node_ids:
            node_cache.update(
                {
                    entity.id: entity
                    for entity in db.scalars(
                        select(KnowledgeEntity).where(
                            KnowledgeEntity.id.in_(candidate_node_ids),
                            knowledge_entity_scope_clause(principal),
                        )
                    ).all()
                }
            )
        adjacency: dict[str, list[tuple[KnowledgeRelationship, str]]] = {
            item: [] for item in frontier
        }
        for relationship in level_relationships:
            source_id = relationship.source_entity_id
            target_id = relationship.target_entity_id
            if source_id in frontier and target_id in node_cache:
                adjacency[source_id].append((relationship, target_id))
            if (
                target_id in frontier
                and source_id in node_cache
                and (direction == "both" or not relationship.directed)
            ):
                adjacency[target_id].append((relationship, source_id))

        next_states: list[tuple[list[str], list[KnowledgeRelationship]]] = []
        for node_ids, edges in path_states:
            for relationship, next_id in adjacency.get(node_ids[-1], []):
                if next_id in node_ids:
                    continue
                candidate = (node_ids + [next_id], edges + [relationship])
                if next_id == target.id:
                    found.append(candidate)
                    if len(found) >= max_paths:
                        truncated = True
                        break
                else:
                    next_states.append(candidate)
            if len(found) >= max_paths:
                break
        if found:
            break
        if len(next_states) > 2_000:
            truncated = True
            next_states = next_states[:2_000]
        path_states = next_states

    path_documents = [
        {
            "nodes": [_knowledge_node(node_cache[node_id]) for node_id in node_ids],
            "relationships": [
                _knowledge_relationship_document(relationship)
                for relationship in relationships
            ],
        }
        for node_ids, relationships in found[:max_paths]
    ]
    observed_values = [
        _as_utc(source.last_seen),
        _as_utc(target.last_seen),
        *(
            _as_utc(relationship.last_seen)
            for _node_ids, relationships in found
            for relationship in relationships
        ),
    ]
    request_hash = hashlib.sha256(
        json.dumps(
            {
                "source_entity_id": source.id,
                "target_entity_id": target.id,
                "relationship_types": relationship_types,
                "direction": direction,
                "max_depth": max_depth,
                "max_paths": max_paths,
                "active_only": active_only,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    result = {
        "source": _knowledge_node(source),
        "target": _knowledge_node(target),
        "paths": path_documents,
        "truncated": truncated,
    }
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="knowledge_path",
            evidence_id=f"{source.id}:{target.id}:{request_hash}",
            summary=(
                f"Knowledge path search from {source.display_name!r} to "
                f"{target.display_name!r} found {len(path_documents)} bounded "
                "shortest path(s); paths are topology evidence, not a causal claim."
            ),
            observed_at=max(observed_values),
        )
    ]


def _situation_from_id(
    db: Session,
    situation_id: str,
    principal: PrincipalContext,
) -> Situation:
    situation = db.scalar(
        select(Situation).where(
            Situation.id == situation_id,
            situation_scope_clause(principal),
        )
    )
    if situation is None:
        raise LookupError("Situation not found")
    return situation


def _get_situation_impact(
    db: Session,
    arguments: dict[str, Any],
    principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    situation = _situation_from_id(db, arguments["situation_id"], principal)
    result = SituationImpactRead.model_validate(
        situation_impact_graph(db, situation, principal)
    ).model_dump(mode="json")
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="situation_impact",
            evidence_id=situation.id,
            summary=(
                f"Situation impact context contains {len(result['nodes'])} "
                f"node(s), {len(result['edges'])} edge(s), and "
                f"{len(result['paths'])} bounded path(s); it does not claim "
                "root cause."
            ),
            observed_at=situation.last_seen,
        )
    ]


def _get_capability_quality(
    db: Session, arguments: dict[str, Any], principal: PrincipalContext,
    *, evidence_mode: str = "execution_health",
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    from .capability_quality import EVIDENCE_SCOPES, _namespace, list_policies, policy_state

    if not principal.permits("capabilities.read") or principal.authorization_scope.get("all") is not True:
        raise PermissionError("Capability execution quality requires namespace-wide read permission")
    if _namespace(db) != (principal.tenant_id, principal.region_id):
        raise PermissionError("Capability execution quality namespace does not match")
    items = []
    evidence = []
    for policy in list_policies(db, limit=arguments.get("limit", 10), offset=arguments.get("offset", 0), artifact_version_id=arguments.get("artifact_version_id"), evidence_mode=evidence_mode):
        state = policy_state(db, policy)
        assessment = state.latest_assessment if state.current else None
        document = None
        if assessment is not None:
            document = {key: getattr(assessment, key) for key in ("id", "sample_count", "failed_count", "p95_ms", "reasons", "assessment_sha256")}
            document.update(evaluated_at=assessment.evaluated_at.isoformat(), valid_until=assessment.valid_until.isoformat())
            evidence.append(InvestigationEvidenceCreate(evidence_type="capability_quality_assessment", evidence_id=assessment.id,
                summary=f"Artifact version {policy.artifact_version_id}: {evidence_mode} {state.state}, {assessment.sample_count} samples, {assessment.failed_count} failed. Assessment SHA256 {assessment.assessment_sha256}. Evidence scope {assessment.evidence_scope}; no automation authority.",
                observed_at=assessment.evaluated_at))
        items.append({"policy_id": policy.id, "artifact_version_id": policy.artifact_version_id, "policy_revision": policy.revision,
            "state": state.state, "current": state.current, "assessment": document})
    return {"authorizes_automation": False, "evidence_scope": EVIDENCE_SCOPES[evidence_mode], "items": items}, evidence


def _get_remediation_quality(db: Session, arguments: dict[str, Any], principal: PrincipalContext):
    return _get_capability_quality(db, arguments, principal, evidence_mode="remediation_outcome")


def _get_worker_scaling(
    db: Session,
    arguments: dict[str, Any],
    _principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    limit = int(arguments.get("limit", 20))
    query = select(WorkerScalingPolicy)
    if arguments.get("pool"):
        query = query.where(WorkerScalingPolicy.pool == arguments["pool"])
    policies = list(
        db.scalars(
            query.order_by(WorkerScalingPolicy.pool, WorkerScalingPolicy.name).limit(
                limit
            )
        ).all()
    )
    recommendations: list[dict[str, Any]] = []
    evidence: list[InvestigationEvidenceCreate] = []
    for policy in policies:
        decision = db.scalar(
            select(WorkerScalingDecision)
            .where(WorkerScalingDecision.policy_id == policy.id)
            .order_by(WorkerScalingDecision.observed_at.desc())
            .limit(1)
        )
        document = None
        if decision is not None:
            application = db.scalar(
                select(WorkerScalingApplicationEvent)
                .where(
                    WorkerScalingApplicationEvent.decision_id == decision.id
                )
                .order_by(
                    WorkerScalingApplicationEvent.created_at.desc(),
                    WorkerScalingApplicationEvent.id.desc(),
                )
                .limit(1)
            )
            reason_codes = list(decision.reasons or [])
            if application is not None:
                reason_codes.extend(
                    [
                        f"capacity_provider_{application.status}",
                        (
                            "capacity_provider_observed_replicas_"
                            f"{application.observed_replicas}"
                        ),
                        f"capacity_provider_detail_{application.detail_code}",
                    ]
                )
            document = {
                "id": decision.id,
                "queue_depth": decision.queue_depth,
                "oldest_queue_age_seconds": decision.oldest_queue_age_seconds,
                "current_replicas": decision.current_replicas,
                "ready_replicas": decision.ready_replicas,
                "busy_replicas": decision.busy_replicas,
                "stale_replicas": decision.stale_replicas,
                "desired_replicas": decision.desired_replicas,
                "direction": decision.direction,
                "reasons": reason_codes,
                "observed_at": decision.observed_at.isoformat(),
            }
            evidence.append(
                InvestigationEvidenceCreate(
                    evidence_type="worker_scaling_decision",
                    evidence_id=decision.id,
                    summary=(
                        f"{policy.pool.value} pool {policy.name!r} recommends "
                        f"{decision.desired_replicas} replica(s) from "
                        f"{decision.current_replicas} with queue depth "
                        f"{decision.queue_depth}."
                    ),
                    observed_at=decision.observed_at,
                )
            )
            if application is not None:
                evidence.append(
                    InvestigationEvidenceCreate(
                        evidence_type="worker_scaling_application",
                        evidence_id=application.id,
                        summary=(
                            f"Capacity provider {application.provider_subject!r} "
                            f"reported {application.status} with "
                            f"{application.observed_replicas} observed replica(s) "
                            f"for decision {decision.id}."
                        ),
                        observed_at=application.created_at,
                    )
                )
        recommendations.append(
            {
                "policy_id": policy.id,
                "policy_name": policy.name,
                "pool": policy.pool.value,
                "enabled": policy.enabled,
                "decision": document,
            }
        )
    return {"recommendations": recommendations}, evidence


_REPORT_STATUSES = {"healthy", "warning", "critical", "unknown"}
_REPORT_KINDS = {
    "availability", "latency", "error_rate", "throughput", "saturation",
    "business", "custom",
}


def _safe_report_status(value: str) -> str:
    return value if value in _REPORT_STATUSES else "unknown"


def _saved_report_item(instance: ServiceReportInstance, snapshot) -> dict[str, Any]:
    return {
        "instance_id": instance.id,
        "artifact_id": instance.artifact_id,
        "artifact_version_id": instance.artifact_version_id,
        "artifact_version": snapshot.version,
        "generated_at": _as_utc(snapshot.generated_at).isoformat(),
        "snapshot_sha256": instance.content_sha256,
        "artifact_content_hash": snapshot.content_hash,
        "overall_status": _safe_report_status(snapshot.overall_status),
        "section_count": snapshot.section_count,
        "sample_count": snapshot.sample_count,
        "drifted_section_count": snapshot.drifted_section_count,
    }


def _saved_report_evidence(instance: ServiceReportInstance, snapshot) -> InvestigationEvidenceCreate:
    return InvestigationEvidenceCreate(
        evidence_type="service_report_instance", evidence_id=instance.id,
        summary=(
            f"Saved Report instance {instance.id} for Artifact {instance.artifact_id}, "
            f"generated {_as_utc(snapshot.generated_at).isoformat()}, status "
            f"{_safe_report_status(snapshot.overall_status)}, snapshot SHA256 "
            f"{instance.content_sha256}. This is historical evidence, not a "
            "current health measurement."
        ),
        observed_at=instance.generated_at,
    )


def _list_saved_reports(
    db: Session, arguments: dict[str, Any], principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    instances, next_id = list_visible_report_instances(
        db, principal, limit=arguments.get("limit", 10), after_id=arguments.get("after_id"),
    )
    snapshots = [verified_instance_snapshot(db, instance, principal) for instance in instances]
    return {
        "format_version": "icheck.agent-saved-reports/v1",
        "evidence_basis": "saved_snapshot",
        "items": [
            _saved_report_item(instance, snapshot)
            for instance, snapshot in zip(instances, snapshots, strict=True)
        ],
        "next_after_id": next_id,
    }, [
        _saved_report_evidence(instance, snapshot)
        for instance, snapshot in zip(instances, snapshots, strict=True)
    ]


def _get_saved_report(
    db: Session, arguments: dict[str, Any], principal: PrincipalContext,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    instance = visible_report_instance(db, arguments["instance_id"], principal)
    snapshot = verified_instance_snapshot(db, instance, principal)
    sections = []
    for section in snapshot.sections:
        unit = section.unit
        if unit is not None and not re.fullmatch(r"[A-Za-z0-9%][A-Za-z0-9%/._-]{0,31}", unit):
            unit = None
        drift = section.drift_code
        if drift is not None and not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", drift):
            drift = "other"
        sections.append({
            "section_key": section.section_key,
            "service_key": section.service_key,
            "indicator_key": section.indicator_key,
            "kind": section.kind if section.kind in _REPORT_KINDS else None,
            "unit": unit,
            "state": section.state,
            "drift_code": drift,
            "current_status": _safe_report_status(section.current_status),
            "current_value": section.current_value,
            "sample_count": section.sample_count,
            "minimum": section.minimum,
            "maximum": section.maximum,
            "average": section.average,
            "first_observed_at": (
                _as_utc(section.first_observed_at).isoformat()
                if section.first_observed_at else None
            ),
            "last_observed_at": (
                _as_utc(section.last_observed_at).isoformat()
                if section.last_observed_at else None
            ),
            "trend": section.trend,
            "breach_direction": (
                section.breach_direction
                if section.breach_direction in {"above", "below", "none"} else None
            ),
            "warning_threshold": section.warning_threshold,
            "critical_threshold": section.critical_threshold,
            "samples_truncated": section.samples_truncated,
        })
    return {
        "format_version": "icheck.agent-saved-report/v1",
        "evidence_basis": "saved_snapshot",
        **_saved_report_item(instance, snapshot),
        "published_at": _as_utc(snapshot.published_at).isoformat(),
        "lookback_minutes": snapshot.lookback_minutes,
        "sections": sections,
    }, [_saved_report_evidence(instance, snapshot)]


def _get_retained_report_proofs(db, arguments, principal):
    from ..report_schemas import RetainedProofReportRender
    instance = visible_report_instance(db, arguments["instance_id"], principal)
    snapshot = verified_instance_snapshot(db, instance, principal)
    if not isinstance(snapshot, RetainedProofReportRender):
        raise LookupError("Retained proof report is unavailable")
    relations = ("old_source_id", "new_source_id", "old_qualification_review_id", "new_qualification_review_id",
        "prior_retirement_id", "request_id", "review_id", "old_watermark_receipt_id", "new_receipt_id",
        "superseded_alert_id", "situation_id", "grant_id", "attempt_id", "event_id")
    references = []
    for proof in snapshot.retained_proofs:
        recorded = proof.recorded.model_dump(mode="json")
        references.append({"section_key": proof.section_key, "reference_kind": proof.reference_kind,
            "reference_id": str(proof.reference_id), "recorded_at": recorded.get("created_at", recorded.get("committed_at")),
            "relations": [{"role": role, "id": recorded[role]} for role in relations if recorded.get(role) is not None]})
    return {"format_version": "icheck.agent-retained-report-proofs/v1", "instance_id": instance.id,
        "historical": True, "grants_future_authority": False, "remediation_causality_proven": False,
        "physical_truth_automatically_verified": False, "references": references}, [_saved_report_evidence(instance, snapshot)]


def _assert_replayed_saved_report_result(
    db: Session, handler: str, result: Any, principal: PrincipalContext,
) -> None:
    if not isinstance(result, dict):
        raise PermissionError("Saved report Tool result is invalid")
    if handler in {"reports.get_saved", "reports.get_retained_proofs"}:
        instance_id = result.get("instance_id")
        if not isinstance(instance_id, str):
            raise PermissionError("Saved report Tool result has no instance ID")
        reader = _get_retained_report_proofs if handler == "reports.get_retained_proofs" else _get_saved_report
        current, _ = reader(db, {"instance_id": instance_id}, principal)
        if current != result:
            raise PermissionError("Saved report Tool result no longer matches its source")
    elif handler == "reports.list_saved":
        items = result.get("items")
        if not isinstance(items, list) or len(items) > 10:
            raise PermissionError("Saved report Tool list result is invalid")
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("instance_id"), str):
                raise PermissionError("Saved report Tool list item is invalid")
            instance = visible_report_instance(db, item["instance_id"], principal)
            snapshot = verified_instance_snapshot(db, instance, principal)
            if item != _saved_report_item(instance, snapshot):
                raise PermissionError("Saved report Tool list item no longer matches its source")


def _get_situation_recovery(db, arguments, principal):
    from ..situation_closure_schemas import SituationRecoveryToolInput
    from .situation_recovery import situation_recovery_evidence
    payload = SituationRecoveryToolInput.model_validate(arguments)
    report = situation_recovery_evidence(db, payload.situation_id, payload.policy_review_id, principal)
    return report.model_dump(mode="json"), [InvestigationEvidenceCreate(
        evidence_type="situation_recovery", evidence_id=f"{report.situation_id}:{report.policy_review_id}:{payload.check_key or 'initial'}",
        summary="Fresh exact-source whole-Situation recovery check; does not authorize closure or prove repair causality.",
        observed_at=report.evaluated_at)]


def _runtime_owned_closure_only(*_args):
    raise PermissionError("Reviewed closure must use its durable runtime-owned control-plane journal")


def _runtime_owned_replacement_only(*_args):
    raise PermissionError("Source replacement writes require their durable runtime-owned control-plane journal")


def _get_source_replacement(db, arguments, principal):
    from ..source_replacement_schemas import SourceReplacementReadToolInput
    from .source_replacements import source_replacement_detail
    payload = SourceReplacementReadToolInput.model_validate(arguments)
    detail = source_replacement_detail(db, payload.request_id, principal)
    return detail.model_dump(mode="json"), [InvestigationEvidenceCreate(
        evidence_type="source_replacement_request", evidence_id=detail.request.id,
        summary="Retained peer-reviewed source mapping; record metadata is not current cutover or closure authority.",
        observed_at=detail.request.created_at)]


def _assert_replayed_recovery_result(db, arguments, result, investigation):
    from .agent_authorization import investigation_principal
    from .collector_conditions import canonical
    current, _ = _get_situation_recovery(db, arguments, investigation_principal(investigation))
    # Retain the immutable Tool receipt; never update it to look freshly
    # observed. A distinct check_key permits another bounded Agent loop call.
    old = dict(result); fresh = dict(current)
    old.pop("evaluated_at", None); fresh.pop("evaluated_at", None)
    if canonical(old) != canonical(fresh):
        raise ValueError("Recorded recovery proof changed or expired; request a fresh check_key")


def _preview_device_activation(db, arguments, principal):
    from .authorization_scope import require_device_access
    from .activation import preview_activation
    from ..models import DeviceActivationPolicy
    require_device_access(db, principal, arguments["device_id"])
    policy = db.scalar(select(DeviceActivationPolicy).where(DeviceActivationPolicy.name == arguments["policy_name"],
        DeviceActivationPolicy.status == ArtifactVersionStatus.PUBLISHED).order_by(DeviceActivationPolicy.version.desc()))
    if policy is None:
        raise LookupError("Published activation policy not found")
    plan = preview_activation(db, arguments["device_id"], arguments["connection_id"], policy.id)
    return {"contract": "icheck.device-activation-preview/v1", "device_id": arguments["device_id"],
            "connection_id": arguments["connection_id"], "plan": plan.model_dump(mode="json")}, []


from .device_onboarding import find_for_ai, list_for_ai, preview_for_ai
from .ai_self_repair import diagnose_for_ai

INTERNAL_HANDLERS = {
    "inventory.enroll_devices": lambda *args: (_ for _ in ()).throw(PermissionError("Enrollment is runtime-owned")),
    "platform.diagnose_ai_runtime": diagnose_for_ai,
    "inventory.find_devices": find_for_ai,
    "credentials.list_device_profiles": list_for_ai,
    "inventory.preview_onboarding": preview_for_ai,
    "inventory.preview_activation": _preview_device_activation,
    "collector_sources.get_replacement": _get_source_replacement,
    "collector_sources.propose_replacement": _runtime_owned_replacement_only,
    "collector_sources.apply_reviewed_replacement": _runtime_owned_replacement_only,
    "situations.get_recovery_evidence": _get_situation_recovery,
    "situations.close_reviewed": _runtime_owned_closure_only,
    "reports.list_saved": _list_saved_reports,
    "reports.get_saved": _get_saved_report,
    "reports.get_retained_proofs": _get_retained_report_proofs,
    "inventory.get_device": _get_device,
    "alerts.list_open": _list_open_alerts,
    "inventory.get_endpoint_history": _get_endpoint_history,
    "wireless.list_controller_clients": _list_wireless_controller_clients,
    "metrics.backends.list": _list_metric_backends,
    "metrics.query_instant": _query_instant_metrics,
    "metrics.query_range": _query_range_metrics,
    "metrics.get_device_range": _get_device_range_metrics,
    "logs.query_range": _query_log_range,
    "logs.get_device_range": _get_device_log_range,
    "windows.request_diagnostics": _request_windows_diagnostics,
    "windows.get_latest_diagnostics": _get_latest_windows_diagnostics,
    "knowledge.query_graph": _query_knowledge_graph,
    "knowledge.find_paths": _find_knowledge_paths,
    "situations.get_impact": _get_situation_impact,
    "capacity.get_worker_scaling": _get_worker_scaling,
    "quality.get_execution_health": _get_capability_quality,
    "quality.get_remediation_outcomes": _get_remediation_quality,
}

SCOPED_INTERNAL_HANDLERS = {
    "platform.diagnose_ai_runtime",
    "inventory.find_devices",
    "credentials.list_device_profiles",
    "inventory.preview_onboarding",
    "inventory.preview_activation",
    "collector_sources.get_replacement",
    "situations.get_recovery_evidence",
    "reports.list_saved",
    "reports.get_saved",
    "reports.get_retained_proofs",
    "inventory.get_device",
    "alerts.list_open",
    "inventory.get_endpoint_history",
    "wireless.list_controller_clients",
    "metrics.backends.list",
    "metrics.query_instant",
    "metrics.query_range",
    "metrics.get_device_range",
    "logs.query_range",
    "logs.get_device_range",
    "windows.request_diagnostics",
    "windows.get_latest_diagnostics",
    "knowledge.query_graph",
    "knowledge.find_paths",
    "situations.get_impact",
    "capacity.get_worker_scaling",
    "quality.get_execution_health",
    "quality.get_remediation_outcomes",
}

# Native and MCP integrations use the same registry. Grafana tools never apply
# remote changes; their durable proposals are confirmed by a human GUI endpoint.
from ..grafana_tools import GRAFANA_TOOLS
from .grafana import tools_for_ai as grafana_tools_for_ai
for _grafana_tool in GRAFANA_TOOLS:
    _name = _grafana_tool["name"]
    INTERNAL_HANDLERS[_name] = lambda db, arguments, principal, name=_name: grafana_tools_for_ai(name, db, arguments, principal)
    SCOPED_INTERNAL_HANDLERS.add(_name)

from ..metric_alert_tools import METRIC_ALERT_TOOLS
from ..research_tools import RESEARCH_TOOLS
from .research import tools_for_ai as research_tools_for_ai
for _research_tool in RESEARCH_TOOLS:
    _name = _research_tool["name"]
    INTERNAL_HANDLERS[_name] = lambda db, arguments, principal, name=_name: research_tools_for_ai(name, db, arguments, principal)
    SCOPED_INTERNAL_HANDLERS.add(_name)

from .metric_alerts import tools_for_ai as metric_alert_tools_for_ai
for _metric_alert_tool in METRIC_ALERT_TOOLS:
    _name=_metric_alert_tool["name"]
    INTERNAL_HANDLERS[_name]=lambda db,arguments,principal,name=_name:metric_alert_tools_for_ai(name,db,arguments,principal)
    SCOPED_INTERNAL_HANDLERS.add(_name)


from ..autonomy_tools import AUTONOMY_TOOLS
def _investigation_context_required(*_args):
    raise PermissionError("Investigation assistance requires executor-owned context")


for _autonomy_tool in AUTONOMY_TOOLS:
    # These handlers need executor-owned investigation context, never an ID
    # supplied by the model. Dispatch is below, after the ordinary tool gates.
    INTERNAL_HANDLERS[_autonomy_tool["name"]] = _investigation_context_required


def execute_internal_tool(
    db: Session,
    tool: AgentToolRegistration,
    arguments: dict[str, Any],
    *,
    investigation: Investigation | None = None,
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    if tool.transport != "internal":
        raise RuntimeError("MCP tool execution requires the future MCP gateway")
    if tool.handler in {item["name"] for item in AUTONOMY_TOOLS}:
        if investigation is None or tool.name != tool.handler or not tool.read_only or tool.change_contract is not None:
            raise PermissionError("Investigation assistance requires its native executor-owned context")
        from ..autonomy_schemas import CapabilityDiscovery, CapabilityNeed
        from .investigation_assistance import discover, save_request
        if tool.handler == "investigation.discover_capabilities":
            return discover(db, investigation, CapabilityDiscovery.model_validate(arguments)), []
        return save_request(db, investigation, CapabilityNeed.model_validate(arguments)).model_dump(mode="json"), []
    handler = INTERNAL_HANDLERS.get(tool.handler)
    if handler is None:
        raise RuntimeError(f"Internal tool handler {tool.handler!r} is unavailable")
    if investigation is None:
        principal = development_principal()
    else:
        from .agent_authorization import investigation_principal

        principal = investigation_principal(investigation)
    if tool.handler in SCOPED_INTERNAL_HANDLERS:
        return handler(db, arguments, principal)
    return handler(db, arguments)


def _grafana_preview_completion(investigation, tool, result):
    """Mark only a trusted native preview, outside reusable Workflow/Skill runs.

    Called by the executor after its permission/dispatch gates and successful
    persisted call. Remote tool result bodies cannot populate this envelope.
    """
    if ((investigation.scope or {}).get("capability_task") != "grafana-dashboard"
            or investigation.workflow_snapshot or investigation.skill_artifact_version_id
            or tool.name not in {"grafana.dashboard.preview", "grafana.dashboard.restore.preview"}
            or tool.transport != "internal" or tool.handler != tool.name or not tool.read_only):
        return None
    from ..grafana_schemas import GrafanaChangeRead
    try:
        proposal = GrafanaChangeRead.model_validate(result)
        receipt = GrafanaPreviewCompletion(change_id=proposal.id)
    except (ValueError, TypeError):
        return None
    if (proposal.status != "proposed" or proposal.resource_kind != "dashboard"
            or proposal.review_url != f"/dashboards?change={receipt.change_id}"):
        return None
    return receipt


class DatabaseToolExecutor:
    def __init__(
        self,
        db: Session,
        investigation: Investigation,
        *,
        mcp_runtime: Any | None = None,
        resume_interrupted_calls: bool = False,
        running_result_call_id: str | None = None,
    ):
        self.db = db
        self.investigation = investigation
        self.mcp_runtime = mcp_runtime
        self.resume_interrupted_calls = resume_interrupted_calls
        self.recover_plain_checkpoint = False
        self.running_result_call_id = running_result_call_id

    def _execute(
        self,
        tool: AgentToolRegistration,
        arguments: dict[str, Any],
        *,
        tool_call_id: str,
    ) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
        if tool.transport == "internal":
            return execute_internal_tool(
                self.db,
                tool,
                arguments,
                investigation=self.investigation,
            )
        if tool.transport == "managed_mcp":
            from .managed_extensions import execute
            return execute(self.db, tool, arguments, self.investigation, tool_call_id)
        if tool.transport == "mcp" and self.mcp_runtime is not None:
            result, evidence = self.mcp_runtime.execute(
                self.db,
                tool,
                arguments,
                investigation=self.investigation,
                tool_call_id=tool_call_id,
            )
            from .report_delivery_receipts import assert_report_attachment_tool_outcome

            assert_report_attachment_tool_outcome(self.db, self.investigation, tool, result)
            return result, evidence
        raise ValueError(
            f"Agent tool {tool.name!r} is not executable by this worker"
        )

    def _assert_runtime_allowed(
        self,
        tool: AgentToolRegistration,
        arguments: dict[str, Any],
        state: InvestigationGraphState,
        *,
        contract_dependency: bool = False,
    ) -> None:
        if not contract_dependency:
            from .tool_skills import assert_skill_tool_allowed
            from .workflow_runtime import assert_workflow_tool_allowed

            assert_skill_tool_allowed(self.db, self.investigation, tool)
            assert_workflow_tool_allowed(
                self.db,
                self.investigation,
                tool,
                state["plan"],
            )
        if not tool.enabled:
            raise ValueError(f"Agent tool {tool.name!r} is disabled")
        if tool.transport == "internal" and tool.handler not in INTERNAL_HANDLERS:
            raise ValueError(
                f"Agent tool {tool.name!r} is not executable by this worker"
            )
        if tool.transport not in {"internal", "mcp", "managed_mcp"}:
            raise ValueError(
                f"Agent tool {tool.name!r} uses an unsupported transport"
            )
        if tool.transport == "mcp" and self.mcp_runtime is None:
            raise ValueError(
                f"Agent tool {tool.name!r} requires an MCP-enabled worker"
            )
        if tool.transport == "mcp":
            from .mcp_gateway import mcp_tool_available_for_investigation

            if not mcp_tool_available_for_investigation(
                self.db,
                tool.id,
                self.investigation.id,
            ):
                raise ValueError(
                    f"Agent tool {tool.name!r} is outside this investigation's "
                    "canary cohort or its circuit is open"
                )
        from .agent_authorization import require_tool_permissions

        require_tool_permissions(self.investigation, tool)
        if tool.transport == "managed_mcp":
            from .managed_extensions import available
            if not available(self.db, tool, self.investigation):
                raise PermissionError("Managed MCP installation is unavailable in this investigation's scope")
        from .workflow_runtime import assert_scheduled_report_delivery_allowed

        assert_scheduled_report_delivery_allowed(self.db, self.investigation, tool, arguments)
        self._assert_object_scope(tool, arguments)

    def _assert_object_scope(
        self,
        tool: AgentToolRegistration,
        arguments: dict[str, Any],
    ) -> None:
        from .agent_authorization import investigation_principal

        principal = investigation_principal(self.investigation)
        from .agent_authorization import SOURCE_REPLACEMENT_HANDLERS
        if tool.handler in SOURCE_REPLACEMENT_HANDLERS:
            from .source_replacement_runtime import replacement_tool_scope
            replacement_tool_scope(self.db, self.investigation, tool.handler, arguments)
        if tool.handler in {
            "inventory.get_device",
            "inventory.preview_activation",
            "logs.get_device_range",
            "metrics.get_device_range",
            "windows.request_diagnostics",
            "windows.get_latest_diagnostics",
        }:
            device = self.db.scalar(
                select(Device.id).where(
                    Device.id == arguments.get("device_id"),
                    device_scope_clause(principal),
                )
            )
            if device is None:
                raise PermissionError(
                    "Investigation scope does not authorize this device"
                )
        elif tool.handler == "inventory.get_endpoint_history":
            _endpoint_from_selector(self.db, arguments, principal)
        elif tool.handler == "wireless.list_controller_clients":
            _wireless_controller_from_id(
                self.db,
                arguments.get("controller_id"),
                principal,
            )
        elif tool.handler == "knowledge.query_graph":
            _knowledge_entity_from_selector(self.db, arguments, principal)
        elif tool.handler == "knowledge.find_paths":
            _knowledge_entity_from_selector(
                self.db,
                {"entity_id": arguments.get("source_entity_id")},
                principal,
            )
            _knowledge_entity_from_selector(
                self.db,
                {"entity_id": arguments.get("target_entity_id")},
                principal,
            )
        elif tool.handler in {"situations.get_impact", "situations.get_recovery_evidence", "situations.close_reviewed"}:
            requested_id = arguments.get("situation_id")
            if tool.handler == "situations.close_reviewed" and self.investigation.situation_id != requested_id:
                raise PermissionError("Reviewed closure requires an exact Situation-bound investigation")
            if (
                self.investigation.situation_id is not None
                and requested_id != self.investigation.situation_id
            ):
                raise PermissionError(
                    "Investigation is bound to a different Situation"
                )
            _situation_from_id(self.db, requested_id, principal)
        elif tool.handler in {"reports.get_saved", "reports.get_retained_proofs"}:
            visible_report_instance(self.db, arguments.get("instance_id"), principal)
        elif tool.handler == "reports.list_saved" and arguments.get("after_id"):
            visible_report_instance(self.db, arguments["after_id"], principal)
        elif tool.handler == "logs.query_range" and not has_global_scope(principal):
            raise PermissionError(
                "Scoped LogQL requires a scope-enforcing logs gateway"
            )

    @staticmethod
    def _stage_evidence(plan: GovernedChangePlan, stage: str):
        matches = [item for item in plan.evidence if item.stage == stage]
        return max(matches, key=lambda item: (item.created_at, item.id), default=None)

    def _existing_stage_call(
        self,
        tool: AgentToolRegistration,
        arguments: dict[str, Any],
        plan: GovernedChangePlan | None = None,
        stage: str | None = None,
    ) -> InvestigationToolCall | None:
        calls = self.db.scalars(
            select(InvestigationToolCall)
            .where(
                InvestigationToolCall.investigation_id == self.investigation.id,
                InvestigationToolCall.tool_id == tool.id,
                InvestigationToolCall.governed_change_plan_id == (plan.id if plan else None),
                InvestigationToolCall.governed_stage == stage,
            )
            .order_by(InvestigationToolCall.created_at.desc())
            .limit(100)
        ).all()
        return next((call for call in calls if call.arguments == arguments), None)

    def _attach_stage_evidence(
        self,
        plan: GovernedChangePlan,
        stage: str,
        call: InvestigationToolCall,
    ) -> tuple[GovernedChangePlan, bool]:
        from .change_governance import attach_change_evidence

        plan = attach_change_evidence(
            self.db,
            plan,
            GovernedChangeEvidenceAttach(
                expected_revision=plan.revision,
                expected_plan_hash=plan.plan_hash,
                stage=stage,
                tool_call_id=call.id,
                reason=f"Automatically executed governed {stage} stage.",
            ),
            actor="agent.runtime",
        )
        evidence = self._stage_evidence(plan, stage)
        if evidence is None:
            raise RuntimeError("Governed stage evidence was not persisted")
        return plan, evidence.passed

    def _run_governed_stage(
        self,
        plan: GovernedChangePlan,
        stage: str,
        state: InvestigationGraphState,
    ) -> tuple[GovernedChangePlan, str | None, list[str], bool | None]:
        from .change_governance import (
            assert_change_stage_tool_current,
            change_stage_arguments,
        )

        existing_evidence = self._stage_evidence(plan, stage)
        if existing_evidence is not None:
            from .change_verification import scoped_row, validate_stage_call
            from .change_governance import _hash_document
            call = scoped_row(self.db, InvestigationToolCall, existing_evidence.tool_call_id, plan)
            if call is None:
                raise ValueError("Governed recovery evidence has no bound call")
            passed, _ = validate_stage_call(self.db, plan, stage, call)
            if (passed is not existing_evidence.passed
                or existing_evidence.tool_id != call.tool_id
                or existing_evidence.arguments_hash != _hash_document(call.arguments)
                or existing_evidence.result_hash != call.result_hash):
                raise ValueError("Governed recovery evidence has drifted")
            self._consume_recorded_mcp_call(call)
            return plan, existing_evidence.tool_call_id, self._recorded_evidence_ids(call), existing_evidence.passed
        snapshot = plan.tool_contract_snapshot.get("steps", {}).get(stage)
        if not isinstance(snapshot, dict) or not isinstance(
            snapshot.get("tool_id"), str
        ):
            raise ValueError(f"Governed change plan has no frozen {stage} Tool")
        tool = assert_change_stage_tool_current(self.db, plan, stage)
        if not tool.read_only:
            raise ValueError(f"Governed {stage} Tool is unsafe")
        arguments = change_stage_arguments(plan, stage)
        self._assert_runtime_allowed(
            tool,
            arguments,
            state,
            contract_dependency=True,
        )
        call = self._existing_stage_call(tool, arguments, plan, stage)
        if call is not None:
            if call.status == "succeeded":
                self._consume_recorded_mcp_call(call)
                plan, passed = self._attach_stage_evidence(plan, stage, call)
                return plan, call.id, self._recorded_evidence_ids(call), passed
            if (
                call.status != "running"
                or not self.resume_interrupted_calls
            ):
                return plan, call.id, [], None
        else:
            call = create_tool_call(
                self.db,
                self.investigation,
                InvestigationToolCallCreate(
                    tool_id=tool.id,
                    iteration=state["iteration"],
                    arguments=arguments,
                ),
                governed_change_plan=plan,
                governed_stage=stage,
            )
        try:
            result, evidence_payloads = self._execute(tool, arguments, tool_call_id=call.id)
            evidence_ids = [
                add_evidence_reference(
                    self.db,
                    self.investigation,
                    evidence_payload,
                ).id
                for evidence_payload in evidence_payloads
            ]
            call = complete_tool_call(
                self.db,
                call,
                InvestigationToolCallComplete(status="succeeded", result=result),
                evidence_ids=evidence_ids,
            )
        except GraphInterrupt:
            raise
        except Exception as exc:
            if call.status == "running":
                complete_tool_call(
                    self.db,
                    call,
                    InvestigationToolCallComplete(
                        status="failed",
                        error=str(exc)[:10_000],
                    ),
                )
            return plan, call.id, [], None
        plan, passed = self._attach_stage_evidence(plan, stage, call)
        return plan, call.id, evidence_ids, passed

    def _consume_recorded_mcp_call(self, call: InvestigationToolCall) -> None:
        consumer = getattr(self.mcp_runtime, "consume_recorded_call", None)
        tool = self.db.get(AgentToolRegistration, call.tool_id)
        if tool is not None and tool.transport == "mcp" and consumer is not None:
            consumer(call)

    def _recorded_evidence_ids(self, call: InvestigationToolCall) -> list[str]:
        from .tool_evidence_bindings import recorded_tool_evidence_ids
        recorded = recorded_tool_evidence_ids(self.db, call)
        if recorded is not None:
            return recorded
        # Compatibility is limited to provable old MCP activation/result
        # references; unbound internal calls never acquire guessed citations.
        if call.artifact_activation_id is None or call.result_hash is None:
            return []
        # Recover only an existing reference bound to this exact immutable
        # activation/result identity, never every reference in the investigation
        # or a fabricated citation inferred from a mutable current registry.
        return list(self.db.scalars(select(InvestigationEvidence.id).where(
            InvestigationEvidence.investigation_id == call.investigation_id,
            InvestigationEvidence.evidence_type == "mcp_tool_result",
            InvestigationEvidence.evidence_id == f"{call.artifact_activation_id}:{call.result_hash}",
        ).limit(2)))

    @staticmethod
    def _governance_result(plan: GovernedChangePlan) -> dict[str, Any]:
        from .change_governance import change_stage_arguments

        result: dict[str, Any] = {
            "contract": "icheck.graph-governance-result/v1",
            "change_plan_id": plan.id,
            "change_plan_hash": plan.plan_hash,
            "status": plan.status,
        }
        if plan.status == "rollback_required":
            rollback = plan.tool_contract_snapshot.get("rollback", {})
            result["rollback"] = {
                "tool_name": rollback.get("tool_name"),
                "arguments": change_stage_arguments(plan, "rollback"),
                "requires_new_approval": True,
            }
        return result

    def _execute_reviewed_closure(self, tool, request, state):
        from .situation_closure import close_from_agent_call
        # Always match the persisted journal, even outside generic physical
        # replay mode. A completed receipt is historical, never another write.
        call = self._existing_stage_call(tool, request.arguments)
        if call is None:
            call = create_tool_call(self.db, self.investigation, InvestigationToolCallCreate(
                tool_id=tool.id, iteration=state["iteration"], arguments=request.arguments),
                reviewed_situation_closure=True)
        if call.status == "failed":
            return GraphToolResult(call_id=call.id, tool_name=tool.name, arguments=request.arguments,
                status="failed", error=call.error or "Closure Tool journal failed")
        if call.status not in {"running", "succeeded"}:
            raise ValueError("Closure Tool journal status is invalid")
        try:
            receipt = close_from_agent_call(self.db, self.investigation, call, request.arguments)
        except Exception:
            self.db.rollback()
            # Keep the journal resumable. In particular, a durable receipt or
            # live claim must not be replaced by a fabricated terminal error.
            raise
        result = receipt.model_dump(mode="json")
        if call.status == "succeeded":
            if call.result != result:
                raise ValueError("Closure Tool terminal journal differs from its durable receipt")
            evidence_ids = self._recorded_evidence_ids(call)
        else:
            evidence = add_evidence_reference(self.db, self.investigation, InvestigationEvidenceCreate(
                evidence_type="situation_closure_receipt", evidence_id=receipt.id,
                summary="Historical independently reviewed closure receipt; no future action authority or repair causality.",
                observed_at=receipt.committed_at))
            evidence_ids = [evidence.id]
            complete_tool_call(self.db, call, InvestigationToolCallComplete(status="succeeded", result=result),
                evidence_ids=evidence_ids, owned_situation_closure=True)
        return GraphToolResult(call_id=call.id, tool_name=tool.name, arguments=request.arguments,
            status="succeeded", result=result, evidence_ids=evidence_ids)

    def _execute_owned_source_replacement(self, tool, request, state):
        from .agent_runtime import _canonical_hash
        from .source_replacement_runtime import replacement_from_agent_call
        call = self.db.scalar(select(InvestigationToolCall).where(
            InvestigationToolCall.investigation_id == self.investigation.id,
            InvestigationToolCall.call_hash == _canonical_hash({"tool_id": tool.id, "arguments": request.arguments})))
        if call is None:
            call = create_tool_call(self.db, self.investigation, InvestigationToolCallCreate(
                tool_id=tool.id, iteration=state["iteration"], arguments=request.arguments),
                reviewed_source_replacement=True)
        if call.status == "failed":
            return GraphToolResult(call_id=call.id, tool_name=tool.name, arguments=request.arguments,
                status="failed", error=call.error or "Replacement Tool journal failed")
        try:
            record = replacement_from_agent_call(self.db, self.investigation, call, request.arguments)
            result = record.model_dump(mode="json")
            if call.status == "succeeded":
                if call.result != result:
                    raise ValueError("Replacement Tool journal differs from its immutable domain receipt")
                evidence_ids = self._recorded_evidence_ids(call)
            else:
                applying = tool.handler == "collector_sources.apply_reviewed_replacement"
                evidence = add_evidence_reference(self.db, self.investigation, InvestigationEvidenceCreate(
                    evidence_type="source_retirement_receipt" if applying else "source_replacement_request",
                    evidence_id=record.id, observed_at=record.created_at,
                    summary="Retained source cutover receipt; no physical operation or incident closure." if applying
                        else "Exact source equivalence proposal; independent human acceptance still required."))
                evidence_ids = [evidence.id]
                complete_tool_call(self.db, call, InvestigationToolCallComplete(status="succeeded", result=result),
                    evidence_ids=evidence_ids, owned_source_replacement=True)
        except Exception:
            self.db.rollback()
            # A durable mapping/cutover may already exist. Never fabricate a
            # failed journal or issue another key after an uncertain response.
            raise
        return GraphToolResult(call_id=call.id, tool_name=tool.name, arguments=request.arguments,
            status="succeeded", result=result, evidence_ids=evidence_ids)

    def _execute_explicit_enrollment(self, tool, request, state):
        from .conversational_onboarding import authorized_input, enroll
        authorized_input(self.investigation, request.arguments, db=self.db)
        snapshot = self.investigation.agent_profile_snapshot or {}
        if snapshot.get("tool_policy") == "allowlist" and tool.name not in snapshot.get("allowed_tool_names", []):
            raise PermissionError("AgentProfile does not permit device enrollment")
        call = self._existing_stage_call(tool, request.arguments)
        if call is None:
            call = create_tool_call(self.db, self.investigation,
                InvestigationToolCallCreate(tool_id=tool.id, iteration=state['iteration'], arguments=request.arguments),
                explicit_device_enrollment=True)
        if call.status == 'succeeded':
            return GraphToolResult(call_id=call.id, tool_name=tool.name, arguments=request.arguments,
                status='succeeded', result=call.result)
        if call.status == 'failed':
            return GraphToolResult(call_id=call.id, tool_name=tool.name, arguments=request.arguments,
                status='failed', error=call.error)
        try:
            result = enroll(self.db, self.investigation, request.arguments)
            complete_tool_call(self.db, call, InvestigationToolCallComplete(status='succeeded', result=result),
                owned_device_enrollment=True)
            return GraphToolResult(call_id=call.id, tool_name=tool.name, arguments=request.arguments,
                status='succeeded', result=result)
        except Exception as exc:
            self.db.rollback()
            self.db.refresh(call)
            complete_tool_call(self.db, call, InvestigationToolCallComplete(status='failed', error=str(exc)[:2000]),
                owned_device_enrollment=True)
            return GraphToolResult(call_id=call.id, tool_name=tool.name, arguments=request.arguments,
                status='failed', error=call.error)

    def __call__(
        self,
        request: GraphToolRequest,
        state: InvestigationGraphState,
    ) -> GraphToolResult:
        tool = self.db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == request.tool_name
            )
        )
        if tool is None:
            raise LookupError(f"Agent tool {request.tool_name!r} not found")
        self._assert_runtime_allowed(tool, request.arguments, state)
        if tool.handler == "inventory.enroll_devices":
            return self._execute_explicit_enrollment(tool, request, state)
        from .agent_authorization import OWNED_SOURCE_REPLACEMENT_HANDLERS
        if tool.handler in OWNED_SOURCE_REPLACEMENT_HANDLERS:
            return self._execute_owned_source_replacement(tool, request, state)
        if tool.handler == "situations.close_reviewed":
            return self._execute_reviewed_closure(tool, request, state)
        if not tool.read_only:
            from .agent_approvals import (
                finish_action_proposal,
                prepare_resumed_action,
                propose_action,
            )
            from .mcp_gateway import MCPWriteOutcomeUnknown
            from .change_governance import (
                attach_rollback_action_result,
                find_required_rollback_plan,
                get_change_plan,
                get_change_plan_for_proposal,
            )

            rollback_of_change_plan = find_required_rollback_plan(
                self.db,
                investigation=self.investigation,
                tool=tool,
                arguments=request.arguments,
            )
            proposal = propose_action(
                self.db,
                self.investigation,
                tool,
                iteration=state["iteration"],
                arguments=request.arguments,
                purpose=request.purpose,
                rollback_of_change_plan=rollback_of_change_plan,
            )
            change_plan = get_change_plan_for_proposal(self.db, proposal.id)
            auxiliary_call_ids: list[str] = []
            governance_evidence_ids: list[str] = []
            governance_error: str | None = None
            if change_plan is not None:
                try:
                    for stage in ("precheck", "dry_run"):
                        (
                            change_plan,
                            stage_call_id,
                            stage_evidence_ids,
                            passed,
                        ) = self._run_governed_stage(change_plan, stage, state)
                        if (
                            stage_call_id is not None
                            and stage_call_id not in auxiliary_call_ids
                        ):
                            auxiliary_call_ids.append(stage_call_id)
                        for evidence_id in stage_evidence_ids:
                            if evidence_id not in governance_evidence_ids:
                                governance_evidence_ids.append(evidence_id)
                        if passed is not True:
                            break
                except GraphInterrupt:
                    raise
                except Exception as exc:
                    governance_error = f"{type(exc).__name__}: {exc}"[:4000]
            from .agent_authorization import investigation_principal
            from .preapproval_execution import try_inline_reviewed_authorization
            resume_value = (
                try_inline_reviewed_authorization(
                    self.db, change_plan, actor=investigation_principal(self.investigation),
                ) if change_plan is not None else None
            )
            if resume_value is None and rollback_of_change_plan is not None:
                from .rollback_execution import try_inline_rollback
                resume_value = try_inline_rollback(self.db, proposal,
                    actor=investigation_principal(self.investigation))
            if (resume_value is None and self.recover_plain_checkpoint
                and proposal.status in {"approved", "rejected", "executing", "succeeded", "failed"}):
                # Only a control-plane operation with no pending dynamic
                # interrupt may consume its exact recorded human decision.
                # prepare_resumed_action still denies every unbound running
                # write and revalidates approved starts/terminal recovery.
                resume_value = {"proposal_id": proposal.id, "plan_hash": proposal.plan_hash}
            if resume_value is None:
                resume_value = interrupt(
                    {
                        "kind": "action_approval",
                        "proposal_id": proposal.id,
                        "investigation_id": self.investigation.id,
                        "tool_name": tool.name,
                        "purpose": proposal.purpose,
                        "arguments": proposal.arguments,
                        "plan_hash": proposal.plan_hash,
                        "change_plan_id": change_plan.id if change_plan is not None else None,
                        "change_plan_hash": change_plan.plan_hash if change_plan is not None else None,
                        "change_plan_status": change_plan.status if change_plan is not None else None,
                        "governance_error": governance_error,
                        "rollback_of_change_plan_id": (
                            rollback_of_change_plan.id if rollback_of_change_plan is not None else None
                        ),
                    }
                )
            if not isinstance(resume_value, dict) or not isinstance(
                resume_value.get("proposal_id"), str
            ):
                raise ValueError("Approval resume payload is invalid")
            from .agent_approvals import ActionRejected
            try:
                proposal, recovered_call = prepare_resumed_action(
                    self.db,
                    resume_value["proposal_id"],
                    investigation=self.investigation,
                    tool=tool,
                    arguments=request.arguments,
                    purpose=request.purpose,
                    allow_running_call=self.resume_interrupted_calls,
                    running_result_call_id=self.running_result_call_id,
                )
            except ActionRejected as exc:
                # Account for actual completed prerequisites, not a fabricated
                # action call/result. The action has not started.
                raise GraphToolExecutionFailure(tool_call_ids=auxiliary_call_ids,
                    evidence_ids=governance_evidence_ids) from exc
            action_evidence_ids: list[str] = []
            if recovered_call is None or recovered_call.status == "running":
                call = recovered_call
                if call is None:
                    call = create_tool_call(
                        self.db,
                        self.investigation,
                        InvestigationToolCallCreate(
                            tool_id=tool.id,
                            iteration=state["iteration"],
                            arguments=request.arguments,
                        ),
                        approved_proposal=proposal,
                    )
                try:
                    result, evidence_payloads = self._execute(
                        tool,
                        request.arguments,
                        tool_call_id=call.id,
                    )
                    action_evidence_ids = [
                        add_evidence_reference(
                            self.db,
                            self.investigation,
                            evidence_payload,
                        ).id
                        for evidence_payload in evidence_payloads
                    ]
                    call = complete_tool_call(
                        self.db,
                        call,
                        InvestigationToolCallComplete(
                            status="succeeded",
                            result=result,
                        ),
                        evidence_ids=action_evidence_ids,
                    )
                except GraphInterrupt:
                    raise
                except MCPWriteOutcomeUnknown as exc:
                    # The provider may have committed this write. Preserve
                    # the running call and executing proposal; never route an
                    # ambiguous send through a normal failure/rollback edge.
                    self.db.commit()
                    raise GraphToolOutcomeUnknown(
                        tool_call_ids=[*auxiliary_call_ids, call.id],
                        evidence_ids=governance_evidence_ids,
                    ) from exc
                except Exception as exc:
                    if call.status == "running":
                        complete_tool_call(
                            self.db,
                            call,
                            InvestigationToolCallComplete(
                                status="failed",
                                error=str(exc)[:10_000],
                            ),
                        )
                    finish_action_proposal(
                        self.db,
                        proposal,
                        call=call,
                        error=str(exc)[:10_000],
                    )
                    parent_plan = (
                        get_change_plan(
                            self.db,
                            proposal.rollback_of_change_plan_id,
                        )
                        if proposal.rollback_of_change_plan_id is not None
                        else get_change_plan_for_proposal(self.db, proposal.id)
                    )
                    return GraphToolResult(
                        call_id=call.id,
                        tool_name=tool.name,
                        arguments=request.arguments,
                        status="failed",
                        error=str(exc)[:10_000],
                        evidence_ids=governance_evidence_ids,
                        auxiliary_call_ids=auxiliary_call_ids,
                        governance=(
                            self._governance_result(parent_plan)
                            if parent_plan is not None
                            else None
                        ),
                    )
                finish_action_proposal(self.db, proposal, call=call)
            else:
                call = recovered_call
                result = call.result
                self._consume_recorded_mcp_call(call)
                action_evidence_ids = self._recorded_evidence_ids(call)
            if call.status == "failed" or proposal.status == "failed":
                parent_plan = (
                    get_change_plan(
                        self.db,
                        proposal.rollback_of_change_plan_id,
                    )
                    if proposal.rollback_of_change_plan_id is not None
                    else get_change_plan_for_proposal(self.db, proposal.id)
                )
                return GraphToolResult(
                    call_id=call.id,
                    tool_name=tool.name,
                    arguments=request.arguments,
                    status="failed",
                    error=(call.error or proposal.error or "Action Tool failed")[
                        :10_000
                    ],
                    evidence_ids=governance_evidence_ids,
                    auxiliary_call_ids=auxiliary_call_ids,
                    governance=(
                        self._governance_result(parent_plan)
                        if parent_plan is not None
                        else None
                    ),
                )
            postcheck_passed: bool | None = True
            postcheck_error: str | None = None
            change_plan = get_change_plan_for_proposal(self.db, proposal.id)
            if change_plan is not None:
                try:
                    (
                        change_plan,
                        postcheck_call_id,
                        postcheck_evidence_ids,
                        postcheck_passed,
                    ) = self._run_governed_stage(change_plan, "postcheck", state)
                    if (
                        postcheck_call_id is not None
                        and postcheck_call_id not in auxiliary_call_ids
                    ):
                        auxiliary_call_ids.append(postcheck_call_id)
                    for evidence_id in postcheck_evidence_ids:
                        if evidence_id not in governance_evidence_ids:
                            governance_evidence_ids.append(evidence_id)
                    if postcheck_passed is not True:
                        postcheck_error = (
                            "Governed post-check failed or did not produce "
                            "verifiable evidence"
                        )
                except GraphInterrupt:
                    raise
                except Exception as exc:
                    postcheck_passed = None
                    postcheck_error = (
                        f"Governed post-check orchestration failed: "
                        f"{type(exc).__name__}: {exc}"
                    )[:10_000]
            governance_plan = change_plan
            if (
                proposal.rollback_of_change_plan_id is not None
                and postcheck_passed is True
            ):
                try:
                    governance_plan = attach_rollback_action_result(
                        self.db,
                        proposal,
                        call,
                    )
                    if governance_plan is None:
                        raise RuntimeError("Rollback parent plan was not resolved")
                    rollback_evidence = self._stage_evidence(
                        governance_plan,
                        "rollback",
                    )
                    if rollback_evidence is None or not rollback_evidence.passed:
                        postcheck_passed = False
                        postcheck_error = (
                            "Rollback Tool completed but its declared outcome failed"
                        )
                    elif "rollback_check" in governance_plan.tool_contract_snapshot.get("steps", {}):
                        governance_plan, check_id, check_evidence_ids, postcheck_passed = self._run_governed_stage(
                            governance_plan, "rollback_check", state)
                        if check_id is not None and check_id not in auxiliary_call_ids:
                            auxiliary_call_ids.append(check_id)
                        for evidence_id in check_evidence_ids:
                            if evidence_id not in governance_evidence_ids:
                                governance_evidence_ids.append(evidence_id)
                        if postcheck_passed is not True:
                            postcheck_error = "Rollback restoration check failed or has no verifiable evidence"
                except GraphInterrupt:
                    raise
                except Exception as exc:
                    postcheck_passed = None
                    postcheck_error = (
                        f"Rollback evidence binding failed: "
                        f"{type(exc).__name__}: {exc}"
                    )[:10_000]
                    governance_plan = get_change_plan(
                        self.db,
                        proposal.rollback_of_change_plan_id,
                    )
            return GraphToolResult(
                call_id=call.id,
                tool_name=tool.name,
                arguments=request.arguments,
                status=("succeeded" if postcheck_passed is True else "failed"),
                result=result,
                error=postcheck_error,
                evidence_ids=[
                    *governance_evidence_ids,
                    *(
                        item
                        for item in action_evidence_ids
                        if item not in governance_evidence_ids
                    ),
                ],
                auxiliary_call_ids=auxiliary_call_ids,
                governance=(
                    self._governance_result(governance_plan)
                    if governance_plan is not None
                    else None
                ),
            )
        call = (
            self._existing_stage_call(tool, request.arguments)
            if self.resume_interrupted_calls
            else None
        )
        if call is None:
            call = create_tool_call(
                self.db,
                self.investigation,
                InvestigationToolCallCreate(
                    tool_id=tool.id,
                    iteration=state["iteration"],
                    arguments=request.arguments,
                ),
            )
        elif call.status == "succeeded":
            if tool.handler == "collector_sources.get_replacement":
                from .agent_authorization import investigation_principal
                from .source_replacement_runtime import assert_retained_replacement_result
                assert_retained_replacement_result(self.db, call.result, investigation_principal(self.investigation),
                    expected_request_id=request.arguments.get("request_id"))
            if tool.handler == "situations.get_recovery_evidence":
                _assert_replayed_recovery_result(self.db, request.arguments, call.result, self.investigation)
            if tool.handler in {"reports.list_saved", "reports.get_saved", "reports.get_retained_proofs"}:
                from .agent_authorization import investigation_principal

                _assert_replayed_saved_report_result(
                    self.db, tool.handler, call.result,
                    investigation_principal(self.investigation),
                )
            return GraphToolResult(
                call_id=call.id,
                tool_name=tool.name,
                arguments=request.arguments,
                status="succeeded",
                result=call.result,
                evidence_ids=self._recorded_evidence_ids(call),
                task_completion=_grafana_preview_completion(self.investigation, tool, call.result),
            )
        elif call.status == "failed":
            return GraphToolResult(
                call_id=call.id,
                tool_name=tool.name,
                arguments=request.arguments,
                status="failed",
                error=call.error or "Persisted Tool call failed",
            )
        elif call.status != "running":
            raise ValueError("Persisted Tool call has an invalid status")
        try:
            result, evidence_payloads = self._execute(tool, request.arguments, tool_call_id=call.id)
            evidence_ids = [
                add_evidence_reference(
                    self.db,
                    self.investigation,
                    evidence_payload,
                ).id
                for evidence_payload in evidence_payloads
            ]
            complete_tool_call(
                self.db,
                call,
                InvestigationToolCallComplete(
                    status="succeeded",
                    result=result,
                ),
                evidence_ids=evidence_ids,
            )
            return GraphToolResult(
                call_id=call.id,
                tool_name=tool.name,
                arguments=request.arguments,
                status="succeeded",
                result=result,
                evidence_ids=evidence_ids,
                task_completion=_grafana_preview_completion(self.investigation, tool, result),
            )
        except GraphInterrupt:
            raise
        except Exception as exc:
            complete_tool_call(
                self.db,
                call,
                InvestigationToolCallComplete(
                    status="failed",
                    error=str(exc)[:10_000],
                ),
            )
            return GraphToolResult(
                call_id=call.id,
                tool_name=tool.name,
                arguments=request.arguments,
                status="failed",
                error=str(exc)[:10_000],
            )
