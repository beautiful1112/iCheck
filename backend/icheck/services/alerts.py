from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, AlertRule, AlertSeverity, AlertStatus, utcnow
from .alert_conditions import (as_utc, latest_alert, lock_condition, observation_disposition,
    observe_unknown_condition, pin_identity, record_observation)
from .collector_condition_authority import assert_collector_condition_writer

if TYPE_CHECKING:
    from .control_plane_auth import PrincipalContext


DEFAULT_RULES = (
    {
        "name": "Weak wireless signal",
        "event_type": "wireless.rssi.low",
        "severity": AlertSeverity.WARNING,
        "conditions": {"threshold": -75},
        "cooldown_seconds": 300,
        "enabled": True,
    },
    {
        "name": "Endpoint IP changed",
        "event_type": "endpoint.ip.changed",
        "severity": AlertSeverity.WARNING,
        "conditions": {},
        "cooldown_seconds": 300,
        "enabled": True,
    },
    {
        "name": "New endpoint discovered",
        "event_type": "endpoint.new",
        "severity": AlertSeverity.INFO,
        "conditions": {},
        "cooldown_seconds": 300,
        "enabled": False,
    },
)


def ensure_default_rules(db: Session, *, commit: bool = True) -> None:
    existing = set(db.scalars(select(AlertRule.name)).all())
    for rule in DEFAULT_RULES:
        if rule["name"] not in existing:
            db.add(AlertRule(**rule))
    if commit:
        db.commit()


def rule_matches(rule: AlertRule, details: dict[str, Any]) -> bool | None:
    if rule.event_type=="metric.prometheus": return None  # Evaluated only by Prometheus.
    if rule.event_type == "wireless.rssi.low":
        rssi = details.get("rssi")
        threshold = rule.conditions.get("threshold", -75)
        if (isinstance(rssi, bool) or not isinstance(rssi, (int, float))
            or not -150 <= rssi <= 0 or isinstance(threshold, bool)
            or not isinstance(threshold, (int, float)) or not -150 <= threshold <= 0):
            return None
        return rssi < threshold
    return True


def upsert_alert(
    db: Session,
    *,
    dedup_key: str,
    event_type: str,
    severity: AlertSeverity,
    title: str,
    description: str,
    entity_type: str,
    entity_id: str,
    details: dict[str, Any],
    observed_at: datetime,
    rule_id: str | None = None,
) -> Alert | None:
    if (event_type=="metric.prometheus" or dedup_key.startswith("metric:")) and not db.info.get("native_metric_alert_writer"):
        raise ValueError("Metric episodes require the provisioned Alertmanager receiver")
    assert_collector_condition_writer(db, dedup_key)
    state = lock_condition(db, dedup_key)
    values = (event_type, entity_type, entity_id, rule_id)
    if state.event_type is not None:
        pin_identity(state, values)
    disposition = observation_disposition(state, observed_at, active=True)
    prior = latest_alert(db, state)
    if disposition in {"stale", "duplicate"}:
        row = prior
        if row is not None:
            row._observation_disposition = disposition
        return row
    alert = db.scalar(
        select(Alert).where(
            Alert.tenant_id == state.tenant_id,
            Alert.region_id == state.region_id,
            Alert.dedup_key == dedup_key,
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
        )
        .with_for_update().execution_options(populate_existing=True)
    )
    if alert:
        if as_utc(alert.last_seen) > as_utc(observed_at):
            raise ValueError("Alert source timestamp has drifted beyond its condition watermark")
        alert.last_seen = as_utc(observed_at)
        alert.occurrence_count += 1
        alert.title = title
        alert.description = description
        alert.details = details
        if alert.severity != severity:
            alert.severity = severity
        pin_identity(state, values)
        record_observation(state, observed_at, active=True, disposition=disposition, alert=alert)
        alert._observation_disposition = disposition
        db.flush()
        from .situations import correlate_alert

        correlate_alert(db, alert)
        return alert

    alert = Alert(
        rule_id=rule_id,
        dedup_key=dedup_key,
        event_type=event_type,
        severity=severity,
        title=title,
        description=description,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details,
        first_seen=as_utc(observed_at),
        last_seen=as_utc(observed_at),
    )
    db.add(alert)
    db.flush()
    pin_identity(state, values)
    record_observation(state, observed_at, active=True, disposition=disposition, alert=alert)
    alert._observation_disposition = disposition
    db.flush()
    from .workflow_runtime import enqueue_alert_trigger_events

    enqueue_alert_trigger_events(db, alert)
    from .situations import correlate_alert

    correlate_alert(db, alert)
    return alert


def emit_for_rules(
    db: Session,
    *,
    event_type: str,
    entity_type: str,
    entity_id: str,
    title: str,
    description: str,
    details: dict[str, Any],
    observed_at: datetime,
    dedup_suffix: str = "",
) -> list[Alert]:
    if event_type=="metric.prometheus": return []
    rules = db.scalars(
        select(AlertRule).where(
            AlertRule.event_type == event_type,
            AlertRule.enabled.is_(True),
        )
    ).all()
    alerts: list[Alert] = []
    for rule in rules:
        dedup_key = f"{rule.id}:{entity_id}:{dedup_suffix}".rstrip(":")
        matched = rule_matches(rule, details)
        source_identity = (event_type, entity_type, entity_id, rule.id)
        if matched is True:
            alert = upsert_alert(
                db,
                rule_id=rule.id,
                dedup_key=dedup_key,
                event_type=event_type,
                severity=rule.severity,
                title=title,
                description=description,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
                observed_at=observed_at,
            )
            if alert is not None:
                alerts.append(alert)
        elif matched is False:
            resolve_by_dedup_key(db, dedup_key, "iCheck rule engine", observed_at, source_identity=source_identity)
        else:
            observe_unknown_condition(db, dedup_key, observed_at, source_identity=source_identity)
    return alerts


def resolve_by_dedup_key(
    db: Session, dedup_key: str, actor: str, resolved_at: datetime | None = None,
    *, source_identity: tuple | None = None, source_quiet_verified: bool = True,
) -> Alert | None:
    if dedup_key.startswith("metric:") and not db.info.get("native_metric_alert_writer"):
        raise ValueError("Metric clearance is reported by Prometheus/Alertmanager, not a second evaluator")
    assert_collector_condition_writer(db, dedup_key)
    state = lock_condition(db, dedup_key)
    observed_at = as_utc(resolved_at or utcnow())
    disposition = observation_disposition(state, observed_at, active=False if source_quiet_verified else None)
    prior = latest_alert(db, state)
    if source_identity is not None:
        if state.event_type is not None:
            pin_identity(state, source_identity)
    if disposition in {"stale", "duplicate"}:
        return prior
    alert = db.scalar(
        select(Alert).where(
            Alert.tenant_id == state.tenant_id,
            Alert.region_id == state.region_id,
            Alert.dedup_key == dedup_key,
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
        )
        .with_for_update().execution_options(populate_existing=True)
    )
    if alert and as_utc(alert.last_seen) > observed_at:
        raise ValueError("Alert source timestamp has drifted beyond its condition watermark")
    if source_identity is not None:
        # Bind an absent quiet source together with its revision/observation.
        # Binding before a SELECT can autoflush an incomplete guarded update.
        pin_identity(state, source_identity)
    # Same-time contradiction never selects the quiet verdict. Preserve an
    # active episode and a conflict watermark until a strictly newer sample.
    record_observation(state, observed_at, active=False if source_quiet_verified else None, disposition=disposition, alert=alert)
    if alert and disposition == "accepted":
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = observed_at
        alert.resolved_by = actor
        from .situations import correlate_alert

        correlate_alert(db, alert, actor=actor)
    db.flush()
    return alert


def _lock_alert_lifecycle(db: Session, alert: Alert, *, principal=None) -> Alert:
    if db.is_modified(alert, include_collections=False):
        raise ValueError("Persist pending Alert edits before lifecycle mutations")
    state = lock_condition(db, alert.dedup_key)
    with db.no_autoflush:
        current = db.scalar(select(Alert).where(Alert.id == alert.id,
            Alert.tenant_id == alert.tenant_id, Alert.region_id == alert.region_id,
            Alert.dedup_key == state.dedup_key).with_for_update().execution_options(populate_existing=True))
    if current is None:
        raise ValueError("Alert is unavailable in this namespace")
    if current.source_retirement_id:
        raise ValueError("Superseded Alert history cannot be acknowledged or measured resolved")
    if principal is not None:
        from .authorization_scope import require_alert_access
        require_alert_access(db, principal, current.id)
    return current


def acknowledge_alert(db: Session, alert: Alert, actor: str, *, principal: PrincipalContext | None = None) -> Alert:
    alert = _lock_alert_lifecycle(db, alert, principal=principal)
    if alert.status == AlertStatus.RESOLVED:
        raise ValueError("A resolved alert cannot be acknowledged")
    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_at = utcnow()
    alert.acknowledged_by = actor
    from .situations import correlate_alert

    correlate_alert(db, alert, actor=actor)
    return alert


def resolve_alert(db: Session, alert: Alert, actor: str, *, principal: PrincipalContext | None = None) -> Alert:
    if alert.event_type=="metric.prometheus":
        raise ValueError("Prometheus/Alertmanager reports metric-condition clearance; acknowledgement does not resolve the source")
    alert = _lock_alert_lifecycle(db, alert, principal=principal)
    if alert.status != AlertStatus.RESOLVED:
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = utcnow()
        alert.resolved_by = actor
        from .situations import correlate_alert

        correlate_alert(db, alert, actor=actor)
        from .alert_investigation_control import stop_for_alerts
        stop_for_alerts(db, [alert.id], reason="Automatic investigation stopped: triggering alert was closed by the user")
    return alert
