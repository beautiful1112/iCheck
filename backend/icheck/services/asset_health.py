"""Read-only, scoped inventory categories and current monitoring evidence.

Successful protocol enrollment is NOT current health. Only fresh samples from a
currently authorized monitoring enrollment can establish collection availability.
"""
from collections import defaultdict
from datetime import UTC, datetime
import json
import math
import re

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from ..metric_schemas import PrometheusInstantQuery
from ..models import Device, DeviceConnection, DeviceConnectionActivation, CollectorDeployment, MetricBackend, utcnow
from .authorization_scope import device_scope_clause, namespace_clause
from .metrics import MetricBackendUnavailable, MetricQueryError, query_instant
from .monitoring import _rows, _target
from .runtime_health import _runtime_evaluation

CATEGORIES = {
    "wired": ("switch", "router", "load_balancer"),
    "wireless": ("wireless_controller", "wireless_access_point"),
    "firewalls": ("firewall",),
    "servers": ("physical_server", "linux_server", "windows_server"),
    "storage": ("storage",),
}


def category_clause(category):
    if category == "other":
        return Device.kind.not_in([kind for kinds in CATEGORIES.values() for kind in kinds])
    return Device.kind.in_(CATEGORIES[category])


def asset_summary(db, principal):
    counts = {category: 0 for category in (*CATEGORIES, "other")}
    rows = db.execute(select(Device.kind, func.count(Device.id)).where(device_scope_clause(principal)).group_by(Device.kind))
    for kind, count in rows:
        category = next((key for key, kinds in CATEGORIES.items() if kind in kinds), "other")
        counts[category] += count
    return {"total": sum(counts.values()), "categories": counts, "scope": "Authorized registered inventory; counts are not live health"}


def _binding(target):
    return (target.device_id, target.connection_id, target.enrollment_id, str(target.enrollment_revision))


def _health_expression(pattern):
    filters = 'job="icheck_continuous",icheck_device_id=~' + json.dumps(pattern)
    legacy = 'up{' + filters + ',icheck_protocol!="https_api"}'
    transport = 'up{' + filters + ',icheck_protocol="https_api"}'
    request = 'icheck_http_request_success{' + filters + ',icheck_protocol="https_api"}'
    match = 'on(icheck_tenant_id,icheck_region_id,icheck_device_id,icheck_connection_id,icheck_enrollment_id,icheck_enrollment_revision)'
    healthy_transport, failed_transport = f'({transport} == 1)', f'({transport} == 0)'
    # A gateway parse/TLS/network failure is up=0 with no request-success sample.
    # Do not keep showing the previous request=1. Timestamp raw series separately:
    # timestamp(calculated expression) would report evaluation time, not freshness.
    values = f'({legacy} or ({request} and {match} {healthy_transport}) or {failed_transport})'
    stamps = f'(timestamp({legacy}) or (timestamp({request}) and {match} {healthy_transport}) or (timestamp({transport}) and {match} {failed_transport}))'
    return f'label_replace({values}, "icheck_health_field", "up", "__name__", ".*") or label_replace({stamps}, "icheck_health_field", "observed_at", "__name__", ".*")'


def _samples(document, targets, principal, now):
    expected = {_binding(target): target for target in targets}
    values = defaultdict(lambda: defaultdict(set))
    if not isinstance(document, list) or len(document) > 1000:
        raise ValueError("Invalid bounded health result")
    for sample in document:
        if not isinstance(sample, dict) or not isinstance(sample.get("metric"), dict):
            continue
        labels = sample["metric"]
        if labels.get("icheck_tenant_id") != principal.tenant_id or labels.get("icheck_region_id") != principal.region_id:
            continue
        key = tuple(labels.get(field) for field in ("icheck_device_id", "icheck_connection_id", "icheck_enrollment_id", "icheck_enrollment_revision"))
        if key not in expected:
            continue
        field = labels.get("icheck_health_field")
        if field not in {"up", "observed_at"}:
            continue
        value = sample.get("value")
        if not isinstance(value, list) or len(value) != 2:
            continue
        try:
            numeric = float(value[1])
        except (ValueError, TypeError, OverflowError):
            continue
        if not math.isfinite(numeric) or (field == "up" and numeric not in {0, 1}):
            continue
        values[key][field].add(numeric)
    result = defaultdict(list)
    for key, target in expected.items():
        fields = values[key]
        item = {"connection_id": target.connection_id, "protocol": target.protocol, "state": "unknown",
            "observed_at": None, "sample_age_seconds": None, "freshness_limit_seconds": max(60, 3 * target.schedule_seconds + target.timeout_seconds),
            "reason": "No unambiguous current-enrollment sample",
            "source": "Prometheus HTTP request success" if target.protocol == "https_api" else "Prometheus up"}
        if len(fields["up"]) == 1 and len(fields["observed_at"]) == 1:
            stamp = next(iter(fields["observed_at"]))
            age = now.timestamp() - stamp
            if 0 < stamp and age >= -5:
                try:
                    observed = datetime.fromtimestamp(stamp, UTC)
                except (OverflowError, ValueError, OSError):
                    observed = None
                if observed is not None:
                    item.update(observed_at=observed, sample_age_seconds=max(0, round(age, 1)))
                    if age > item["freshness_limit_seconds"]:
                        item.update(state="stale", reason="Last collection sample is older than its freshness limit")
                    elif next(iter(fields["up"])) == 1:
                        item.update(state="up", reason="Fresh collection succeeded; this is not a claim that every interface is up")
                    else:
                        item.update(state="poll_failed", reason="Fresh collection attempt failed; a device outage is not established")
        result[target.device_id].append(item)
    return result


def device_health(db, principal, device_ids, *, backend_id=None):
    now = utcnow()
    devices = list(db.scalars(select(Device).where(device_scope_clause(principal), Device.id.in_(device_ids))
        .options(selectinload(Device.connections))).all())
    targets = [target for row in _rows(db, principal, device_ids=[device.id for device in devices])
        if (target := _target(row, issued=now)) is not None]
    error = None
    observations = {}
    backend = None
    if targets:
        if not principal.permits("metrics.read"):
            error = "metrics_read_required"
        else:
            query = select(MetricBackend).where(namespace_clause(MetricBackend, principal), MetricBackend.enabled.is_(True))
            if backend_id: query = query.where(MetricBackend.id == backend_id)
            backends = list(db.scalars(query.order_by(MetricBackend.id).limit(2)).all())
            if len(backends) != 1:
                error = "metrics_backend_selection_required" if backends else "metrics_backend_unavailable"
            else:
                backend = backends[0]
                pattern = "|".join(re.escape(identity) for identity in sorted({target.device_id for target in targets}))
                expression = _health_expression(pattern)
                try:
                    reply = query_instant(db, backend, PrometheusInstantQuery(query=expression, timeout_seconds=3,
                        limit=1000, actor=principal.subject), principal=principal)
                    if reply.result_type != "vector": raise ValueError("Non-vector health result")
                    observations = _samples(reply.result, targets, principal, now)
                    # A monitoring withdrawal/identity/credential edit during I/O
                    # must not turn historical series into current device health.
                    current = {_binding(target) for row in _rows(db, principal, device_ids=[device.id for device in devices])
                        if (target := _target(row, issued=utcnow())) is not None}
                    for target in targets:
                        if _binding(target) not in current:
                            observations.pop(target.device_id, None)
                            error = "monitoring_authority_changed"
                except (MetricBackendUnavailable, MetricQueryError, ValueError):
                    error = "metrics_health_query_unavailable"
    # Other plugin collectors report scheduled runtime evidence through SQL,
    # with the same approved deployment fingerprint and device identity fences.
    collector_observations = defaultdict(list)
    collector_rows = db.execute(select(DeviceConnectionActivation, CollectorDeployment, DeviceConnection, Device)
        .select_from(DeviceConnectionActivation)
        .join(CollectorDeployment, DeviceConnectionActivation.deployment_id == CollectorDeployment.id)
        .join(DeviceConnection, DeviceConnectionActivation.connection_id == DeviceConnection.id)
        .join(Device, DeviceConnection.device_id == Device.id)
        .where(device_scope_clause(principal), Device.id.in_([device.id for device in devices]), DeviceConnection.enabled.is_(True),
            DeviceConnectionActivation.status == "active", namespace_clause(DeviceConnectionActivation, principal),
            namespace_clause(CollectorDeployment, principal)).limit(401)).all()
    for activation, deployment, connection, device in collector_rows[:400]:
        if deployment.execution_mode.value != "scheduled":
            continue  # On-demand readiness is not current continuous health.
        state = "unknown"
        reason = "Collection deployment no longer matches the device identity"
        if deployment.scope_device_id == device.id and deployment.scope_device_identity_revision == device.identity_revision:
            runtime, reason = _runtime_evaluation(activation, deployment, now=now)
            state = {"healthy":"up", "degraded":"poll_failed", "stale":"stale"}.get(runtime, "unknown")
        observed = activation.last_success_at
        if observed is not None and observed.tzinfo is None: observed = observed.replace(tzinfo=UTC)
        age = (now - observed).total_seconds() if observed else None
        if age is not None and age < -5:
            state, reason = "unknown", "Collector evidence is future-dated"
        collector_observations[device.id].append({"connection_id": connection.id, "protocol": connection.protocol,
            "state": state, "observed_at": observed, "sample_age_seconds": max(0, round(age, 1)) if age is not None else None,
            "freshness_limit_seconds": max(300, 3 * deployment.schedule_seconds), "reason": reason,
            "source": "Approved scheduled Collector runtime"})
    if len(collector_rows) > 400:
        collector_observations.clear()
        error = error or "collector_health_scope_exceeded"
    items = []
    target_ids = {target.device_id for target in targets}
    for device in devices:
        connections = observations.get(device.id, []) + collector_observations.get(device.id, [])
        states = {connection["state"] for connection in connections}
        if not device.enabled:
            state, reason = "disabled", "Device is disabled"
        elif error == "collector_health_scope_exceeded":
            state, reason = "unknown", error
        elif device.id in target_ids or connections:
            if (error and device.id in target_ids) or not connections:
                state, reason = "unknown", error or "No current collection evidence"
            elif states == {"up"}:
                state, reason = "up", "Current authorized collection is succeeding"
            elif states == {"poll_failed"}:
                state, reason = "poll_failed", "Collection is failing; this does not establish a powered-off device"
            elif states == {"stale"}:
                state, reason = "stale", "Collection evidence is stale"
            elif states == {"unknown"}:
                state, reason = "unknown", "No unambiguous current-enrollment evidence"
            else:
                state, reason = "degraded", "Connections have mixed collection states"
        elif any(connection.verification_status in {"pending", "running"} for connection in device.connections):
            state, reason = "pending", "Waiting for protocol verification and monitoring setup"
        else:
            state, reason = "not_monitored", "No current authorized continuous enrollment; verified transport alone is not live health"
        items.append({"device_id": device.id, "state": state, "reason": reason, "connections": connections,
            "checked_at": now, "backend_id": backend.id if backend else None})
    return {"items": items, "checked_at": now, "diagnostic": error,
        "boundary": "Live collection availability, not overall hardware health or all-interface status"}
