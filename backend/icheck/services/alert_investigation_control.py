"""Control-plane stop boundary for automatically dispatched investigations.

The DB-only dispatcher may enqueue work; this gate runs before a worker can
start spending or checking devices. Native Alertmanager supplies silence
matching (including external/regex silences), not a second matcher engine.
"""
from sqlalchemy import select

from ..agent_schemas import AgentExecutionCancel
from ..alertmanager_runtime import AlertmanagerUnavailable
from ..models import (AgentExecution, AgentExecutionStatus, Alert, AlertInvestigationEvent,
                      AlertRule, AlertStatus, Investigation, MetricRuleChange)


def automatic_alert(db, investigation):
    event = db.scalar(select(AlertInvestigationEvent).where(
        AlertInvestigationEvent.investigation_id == investigation.id,
        AlertInvestigationEvent.tenant_id == investigation.tenant_id,
        AlertInvestigationEvent.region_id == investigation.region_id,
        AlertInvestigationEvent.status == "dispatched"))
    if event is None:
        return False, None
    alert = db.scalar(select(Alert).where(Alert.id == event.alert_id,
        Alert.tenant_id == investigation.tenant_id, Alert.region_id == investigation.region_id)
        .execution_options(populate_existing=True))
    return True, alert


def native_stop_reason(db, alert, *, cache=None):
    from . import alertmanager
    # The retained, applied rule is the trusted identity; descriptions and
    # arbitrary labels from the notification are not a matching authority.
    revision = (alert.details or {}).get("metric_rule_revision")
    if type(revision) is not int or revision < 1:
        return "Automatic investigation stopped: metric alert identity is unavailable"
    rule = db.scalar(select(AlertRule).where(AlertRule.id == alert.rule_id,
        AlertRule.tenant_id == alert.tenant_id, AlertRule.region_id == alert.region_id))
    if rule is None or not rule.enabled or rule.conditions.get("revision") != revision:
        return "Automatic investigation stopped: metric rule disabled or superseded"
    version = db.scalar(select(MetricRuleChange).where(
        MetricRuleChange.rule_id == rule.id, MetricRuleChange.expected_revision == revision - 1,
        MetricRuleChange.status == "applied", MetricRuleChange.tenant_id == alert.tenant_id,
        MetricRuleChange.region_id == alert.region_id))
    if version is None:
        return "Automatic investigation stopped: applied metric rule is unavailable"
    expected = {"alertname": version.compiled_rule["alert"], **version.compiled_rule["labels"]}
    identity = {"icheck_tenant_id": alert.tenant_id, "icheck_region_id": alert.region_id,
                "icheck_metric_rule_id": rule.id, "icheck_metric_rule_revision": str(revision)}
    if any(expected.get(key) != value for key, value in identity.items()):
        return "Automatic investigation stopped: metric alert identity is unavailable"
    # Cache only within one claim batch, never across runtime boundaries.
    cache = {} if cache is None else cache
    key = (alert.tenant_id, alert.region_id)
    try:
        if key not in cache:
            from types import SimpleNamespace
            actor = SimpleNamespace(tenant_id=alert.tenant_id, region_id=alert.region_id)
            cache[key] = alertmanager.CLIENT(actor).api("/api/v2/alerts")
        rows = cache[key]
        if not isinstance(rows, list) or len(rows) > 5000:
            raise ValueError("Unbounded native status")
        matches = [row for row in rows if isinstance(row, dict) and isinstance(row.get("labels"), dict)
                   and all(row["labels"].get(key) == value for key, value in expected.items())]
        if not matches:
            return "Automatic investigation stopped: triggering alert is no longer observable in Alertmanager"
        for row in matches:
            status = row.get("status", {})
            silences = status.get("silencedBy")
            if not isinstance(silences, list) or status.get("state") not in {"active", "suppressed", "unprocessed"}:
                raise ValueError("Unknown native status")
            if silences:
                return "Automatic investigation stopped: triggering alert is silenced in Alertmanager"
            if status["state"] == "unprocessed":
                raise ValueError("Silence matching has not completed")
        # Inhibition alone is not an explicit user silence/closure.
        return None
    except (AlertmanagerUnavailable, PermissionError, ValueError, KeyError, TypeError, AttributeError):
        cache[key] = None
        return "Automatic investigation stopped: Alertmanager silence status could not be verified"


def stop_reason(db, investigation, *, cache=None):
    automatic, alert = automatic_alert(db, investigation)
    if not automatic:
        return None  # Manual conversations/follow-ups are a separate user request.
    if alert is None:
        return "Automatic investigation stopped: triggering alert is unavailable"
    if alert.status == AlertStatus.RESOLVED:
        return "Automatic investigation stopped: triggering alert was closed or resolved"
    if alert.event_type == "metric.prometheus":
        return native_stop_reason(db, alert, cache=cache)
    return None  # Acknowledgement alone is not closure.


def enforce_stop(db, execution, *, reason=None, cache=None):
    """Persist a cancellation in the caller's transaction; no implicit commit."""
    from .agent_execution import cancel_agent_execution, TERMINAL_EXECUTION_STATUSES
    if execution.status in TERMINAL_EXECUTION_STATUSES or execution.cancellation_requested_at is not None:
        return False
    investigation = db.get(Investigation, execution.investigation_id)
    if investigation is None or investigation.status not in {"pending", "running", "waiting_approval"}:
        return False
    reason = reason or stop_reason(db, investigation, cache=cache)
    if not reason:
        return False
    execution = db.get(AgentExecution, execution.id, with_for_update=True, populate_existing=True)
    if execution.status in TERMINAL_EXECUTION_STATUSES or execution.cancellation_requested_at is not None:
        return False
    investigation = db.get(Investigation, execution.investigation_id, with_for_update=True, populate_existing=True)
    if investigation.status not in {"pending", "running", "waiting_approval"}:
        return False
    cancel_agent_execution(db, execution, AgentExecutionCancel(actor="system.alert-investigation", reason=reason),
                           commit=False, actor_type="system")
    return True


def stop_for_alerts(db, alert_ids, *, reason):
    """Immediate stop for a user-confirmed local close/silence, before commit."""
    rows = db.scalars(select(AgentExecution).join(AlertInvestigationEvent,
        AlertInvestigationEvent.investigation_id == AgentExecution.investigation_id).where(
            AlertInvestigationEvent.alert_id.in_(alert_ids), AlertInvestigationEvent.status == "dispatched",
            AlertInvestigationEvent.tenant_id == AgentExecution.tenant_id,
            AlertInvestigationEvent.region_id == AgentExecution.region_id,
            AgentExecution.status.in_([AgentExecutionStatus.QUEUED, AgentExecutionStatus.RUNNING,
                                      AgentExecutionStatus.WAITING_APPROVAL]))
        .order_by(AgentExecution.id).with_for_update(of=AgentExecution).execution_options(populate_existing=True))
    for execution in rows:
        enforce_stop(db, execution, reason=reason)


def stop_for_silence(db, actor, silence):
    from .alertmanager import exact_matchers, stamp
    from ..models import utcnow
    matchers = exact_matchers(silence)
    if (matchers.get("icheck_tenant_id") != actor.tenant_id
            or matchers.get("icheck_region_id") != actor.region_id
            or not stamp(silence["startsAt"]) <= utcnow() < stamp(silence["endsAt"])):
        return
    # Only iCheck's exact-rule silence writes use this immediate shortcut.
    # Other native silences are checked through Alertmanager at execution time.
    if set(matchers) != {"icheck_tenant_id", "icheck_region_id", "icheck_metric_rule_id", "icheck_metric_rule_revision"}:
        return
    alerts = db.scalars(select(Alert).where(Alert.tenant_id == actor.tenant_id, Alert.region_id == actor.region_id,
        Alert.event_type == "metric.prometheus", Alert.rule_id == matchers["icheck_metric_rule_id"]))
    ids = [row.id for row in alerts if str((row.details or {}).get("metric_rule_revision")) == matchers["icheck_metric_rule_revision"]]
    if ids:
        stop_for_alerts(db, ids, reason="Automatic investigation stopped: triggering alert was silenced by the user")
