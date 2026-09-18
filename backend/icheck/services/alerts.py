from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, AlertRule, AlertSeverity, AlertStatus, utcnow


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


def ensure_default_rules(db: Session) -> None:
    existing = set(db.scalars(select(AlertRule.name)).all())
    for rule in DEFAULT_RULES:
        if rule["name"] not in existing:
            db.add(AlertRule(**rule))
    db.commit()


def rule_matches(rule: AlertRule, details: dict[str, Any]) -> bool:
    if rule.event_type == "wireless.rssi.low":
        rssi = details.get("rssi")
        threshold = rule.conditions.get("threshold", -75)
        return rssi is not None and rssi < threshold
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
) -> Alert:
    alert = db.scalar(
        select(Alert).where(
            Alert.dedup_key == dedup_key,
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
        )
    )
    if alert:
        alert.last_seen = observed_at
        alert.occurrence_count += 1
        alert.title = title
        alert.description = description
        alert.details = details
        if alert.severity != severity:
            alert.severity = severity
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
        first_seen=observed_at,
        last_seen=observed_at,
    )
    db.add(alert)
    db.flush()
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
    rules = db.scalars(
        select(AlertRule).where(
            AlertRule.event_type == event_type,
            AlertRule.enabled.is_(True),
        )
    ).all()
    alerts: list[Alert] = []
    for rule in rules:
        dedup_key = f"{rule.id}:{entity_id}:{dedup_suffix}".rstrip(":")
        if rule_matches(rule, details):
            alerts.append(
                upsert_alert(
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
            )
        else:
            resolve_by_dedup_key(db, dedup_key, "iCheck rule engine", observed_at)
    return alerts


def resolve_by_dedup_key(
    db: Session, dedup_key: str, actor: str, resolved_at: datetime | None = None
) -> Alert | None:
    alert = db.scalar(
        select(Alert).where(
            Alert.dedup_key == dedup_key,
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
        )
    )
    if alert:
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = resolved_at or utcnow()
        alert.resolved_by = actor
    return alert


def acknowledge_alert(db: Session, alert: Alert, actor: str) -> Alert:
    if alert.status == AlertStatus.RESOLVED:
        raise ValueError("A resolved alert cannot be acknowledged")
    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_at = utcnow()
    alert.acknowledged_by = actor
    return alert


def resolve_alert(db: Session, alert: Alert, actor: str) -> Alert:
    if alert.status != AlertStatus.RESOLVED:
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = utcnow()
        alert.resolved_by = actor
    return alert

