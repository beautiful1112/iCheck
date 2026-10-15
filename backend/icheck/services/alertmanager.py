"""Alertmanager management reuses native evaluation and the existing audit log."""
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5, NAMESPACE_URL

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
import yaml
from ..alertmanager_runtime import NativeAlertmanager, AlertmanagerUnavailable, configuration_summary, notification_counters, name
from ..config import get_settings
from ..metric_rule_runtime import digest, RuleRuntimeConflict
from ..models import AlertRule, AuditEvent, MetricRuleChange, utcnow
from . import metric_alerts
from .audit import record_audit_event
from .authorization_scope import namespace_clause

CLIENT = NativeAlertmanager
REQUEST = "alertmanager.silence.requested"
COMPLETE = "alertmanager.silence.confirmed"


def stamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp requires timezone")
    return parsed.astimezone(UTC)


def scope(actor):
    return {"icheck_tenant_id": actor.tenant_id, "icheck_region_id": actor.region_id}


def exact_matchers(item):
    rows = item.get("matchers", [])
    if not isinstance(rows, list) or len(rows) > 32:
        return {}
    result = {}
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("name"), str) or not isinstance(row.get("value"), str)
                or row.get("isRegex") or row.get("isEqual", True) is not True or row.get("name") in result):
            return {}
        result[row.get("name")] = row.get("value")
    return result


def silence_scope(item, actor):
    matchers = exact_matchers(item)
    return all(matchers.get(key) == value for key, value in scope(actor).items())


def fingerprint(item):
    return digest({key: item.get(key) for key in ("id", "matchers", "startsAt", "endsAt", "createdBy", "comment", "updatedAt")})


def scoped_rule(db, actor, identifier, *, lock=False):
    return metric_alerts.rule_row(db, identifier, actor, lock=lock)


def request_row(db, actor, identifier, *, lock=False):
    query = select(AuditEvent).where(AuditEvent.id == identifier, AuditEvent.event_type == REQUEST,
        namespace_clause(AuditEvent, actor)).execution_options(populate_existing=True)
    row = db.scalar(query.with_for_update() if lock else query)
    if row is None:
        raise LookupError("Silence request not found")
    return row


def completion(db, actor, row):
    return db.scalar(select(AuditEvent).where(AuditEvent.id == str(uuid5(NAMESPACE_URL, "icheck-silence-complete:" + row.id)),
        AuditEvent.event_type == COMPLETE, namespace_clause(AuditEvent, actor)))


def request_view(db, actor, row):
    result = completion(db, actor, row)
    return {"id": row.id, "action": row.details["action"], "created_at": row.occurred_at.isoformat(),
        "status": "confirmed" if result else "unconfirmed", "rule_id": row.details.get("rule_id"),
        "silence_id": result.details["silence_id"] if result else row.details.get("silence_id"),
        "reason": row.details.get("reason", ""), "warning": "An unconfirmed request is never automatically resent; inspect its outcome."}


def finish(db, actor, row, silence):
    if completion(db, actor, row) is None:
        if row.details["action"] == "create":
            from .alert_investigation_control import stop_for_silence
            stop_for_silence(db, actor, silence)
        event = record_audit_event(db, event_type=COMPLETE, actor_type="user", actor_id=actor.subject,
            entity_type="alertmanager_silence_request", entity_id=row.id,
            details={"silence_id": silence["id"], "action": row.details["action"], "rule_id": row.details.get("rule_id")})
        event.id = str(uuid5(NAMESPACE_URL, "icheck-silence-complete:" + row.id))
        db.commit()
    return request_view(db, actor, row)


def locate_created(client, row):
    desired = row.details["native_request"]
    matches = []
    for item in client.api("/api/v2/silences"):
        if (item.get("comment") == desired["comment"] and item.get("createdBy") == desired["createdBy"]
                and exact_matchers(item) == exact_matchers(desired)
                # Alertmanager advances a past start to its actual admission time.
                # Never accept a start before the approved window or a longer end.
                and stamp(desired["startsAt"]) <= stamp(item["startsAt"]) < stamp(desired["endsAt"])
                and stamp(item["endsAt"]) == stamp(desired["endsAt"])):
            matches.append(item)
    return matches[0] if len(matches) == 1 else None


def inspect(db, actor, identifier):
    metric_alerts.current_authority(db, actor)
    client = CLIENT(actor)
    row = request_row(db, actor, identifier, lock=True)
    if completion(db, actor, row):
        return request_view(db, actor, row)
    if row.details["runtime"] != client.base:
        raise RuleRuntimeConflict("Native Alertmanager binding changed; restore the reviewed binding before inspecting this request")
    try:
        if row.details["action"] == "create":
            observed = locate_created(client, row)
        else:
            observed = client.api("/api/v2/silence/" + str(UUID(row.details["silence_id"])))
            identity = {key: observed.get(key) for key in ("id", "matchers", "createdBy", "comment")}
            if (not silence_scope(observed, actor) or digest(identity) != row.details["reviewed_identity"]
                    or stamp(observed["endsAt"]) > utcnow()):
                observed = None
        if observed:
            return finish(db, actor, row, observed)
    except (AlertmanagerUnavailable, ValueError, KeyError, TypeError, AttributeError):
        pass
    return request_view(db, actor, row)


def admit(db, actor, request_key, incoming, prepare):
    """A deterministic audit ID admits at most one native write for a request."""
    identifier = str(uuid5(NAMESPACE_URL, f"icheck-silence:{actor.tenant_id}:{actor.region_id}:{request_key}"))
    row = db.scalar(select(AuditEvent).where(AuditEvent.id == identifier, namespace_clause(AuditEvent, actor)))
    if row:
        if row.event_type != REQUEST or row.details["input_hash"] != digest(incoming):
            raise RuleRuntimeConflict("Request key already belongs to a different silence action")
        return row, False
    details = {**prepare(identifier), "input_hash": digest(incoming)}
    row = record_audit_event(db, event_type=REQUEST, actor_type="user", actor_id=actor.subject,
        entity_type="alertmanager_silence_request", entity_id=identifier, details=details, outcome="pending")
    row.id = identifier
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        row = request_row(db, actor, identifier)
        if row.details["input_hash"] != digest(incoming):
            raise RuleRuntimeConflict("Request key already belongs to a different silence action") from None
        return row, False
    return row, True


def create(db, actor, payload):
    metric_alerts.current_authority(db, actor)
    client = CLIENT(actor)
    def prepare(identifier):
        rule = scoped_rule(db, actor, str(payload.rule_id))
        if not rule.enabled or rule.conditions.get("revision") != payload.expected_revision:
            raise RuleRuntimeConflict("Rule changed or is disabled; review its current revision")
        now = utcnow().replace(microsecond=0)
        values = {**scope(actor), "icheck_metric_rule_id": rule.id, "icheck_metric_rule_revision": str(payload.expected_revision)}
        native = {"matchers": [{"name": key, "value": value, "isRegex": False, "isEqual": True} for key, value in values.items()],
            "startsAt": now.isoformat(), "endsAt": (now + timedelta(minutes=payload.duration_minutes)).isoformat(),
            "createdBy": actor.subject, "comment": f"{payload.reason} [icheck:{identifier}]"}
        return {"action": "create", "rule_id": rule.id, "reason": payload.reason,
            "native_request": native, "runtime": client.base}
    row, fresh = admit(db, actor, payload.request_key, payload.model_dump(mode="json"), prepare)
    if not fresh:
        return inspect(db, actor, row.id)
    row = request_row(db, actor, row.id, lock=True)
    authority = metric_alerts.current_authority(db, actor)
    rule = scoped_rule(db, actor, str(payload.rule_id), lock=True)
    if not rule.enabled or rule.conditions.get("revision") != payload.expected_revision:
        raise RuleRuntimeConflict("Rule changed before silence admission; no write was made")
    if stamp(row.details["native_request"]["endsAt"]) <= utcnow():
        raise RuleRuntimeConflict("Reviewed silence window elapsed before admission; no write was made")
    if authority:
        authority.assert_live(db)
    try:
        client.api("/api/v2/silences", "POST", row.details["native_request"])
        observed = locate_created(client, row)
        if observed:
            return finish(db, actor, row, observed)
    except (AlertmanagerUnavailable, ValueError, KeyError, TypeError, AttributeError):
        pass
    return request_view(db, actor, row)


def expire(db, actor, identifier, payload):
    metric_alerts.current_authority(db, actor)
    client = CLIENT(actor)
    def prepare(_):
        item = client.api("/api/v2/silence/" + identifier)
        if not silence_scope(item, actor) or fingerprint(item) != payload.expected_fingerprint:
            raise RuleRuntimeConflict("Silence changed or is outside this workspace; refresh before ending it")
        matchers = exact_matchers(item)
        rule = scoped_rule(db, actor, matchers.get("icheck_metric_rule_id"))
        if stamp(item["endsAt"]) <= utcnow():
            raise RuleRuntimeConflict("Silence has already ended")
        return {"action": "expire", "rule_id": rule.id, "silence_id": identifier, "runtime": client.base,
            "reviewed_identity": digest({key: item.get(key) for key in ("id", "matchers", "createdBy", "comment")})}
    row, fresh = admit(db, actor, payload.request_key, {**payload.model_dump(mode="json"), "silence_id": identifier}, prepare)
    if not fresh:
        return inspect(db, actor, row.id)
    row = request_row(db, actor, row.id, lock=True)
    item = client.api("/api/v2/silence/" + identifier)
    if not silence_scope(item, actor) or fingerprint(item) != payload.expected_fingerprint:
        raise RuleRuntimeConflict("Silence changed before admission; no write was made")
    authority = metric_alerts.current_authority(db, actor)
    if authority:
        authority.assert_live(db)
    try:
        client.api("/api/v2/silence/" + identifier, "DELETE")
    except AlertmanagerUnavailable:
        pass
    return inspect(db, actor, row.id)


def overview(db, actor):
    metric_alerts.guard(actor)
    rows = list(db.scalars(select(AlertRule).where(AlertRule.event_type == metric_alerts.EVENT, namespace_clause(AlertRule, actor)).order_by(AlertRule.name).limit(101)))
    rules = {row.id: row for row in rows[:100]}
    result = {"checked_at": utcnow().isoformat(), "ready": False, "provisioned": bool(get_settings().metric_alertmanager_url),
        "receiver_identity_configured": bool(get_settings().metric_alert_webhook_subject),
        "version": None, "diagnostics": [], "receivers": [], "routes": [], "alerts": [], "silences": [], "counters": [],
        "rules": [{"id": row.id, "name": row.name, "revision": row.conditions.get("revision", 0), "enabled": row.enabled} for row in rules.values()],
        "rules_truncated": len(rows) > 100, "delivery_history": [], "requests": []}
    receipts = db.scalars(select(AuditEvent).where(namespace_clause(AuditEvent, actor),
        AuditEvent.event_type == "metric_rule.notification.received").order_by(AuditEvent.occurred_at.desc(), AuditEvent.id).limit(100))
    result["delivery_history"] = [{"id": row.id, "received_at": row.occurred_at.isoformat(), "receiver": name(row.entity_id),
        "alert_count": row.details.get("alert_count", 0), "episodes": row.details.get("episodes", [])} for row in receipts]
    result["requests"] = [request_view(db, actor, row) for row in db.scalars(select(AuditEvent).where(
        namespace_clause(AuditEvent, actor), AuditEvent.event_type == REQUEST).order_by(AuditEvent.occurred_at.desc()).limit(50))]
    try:
        client = CLIENT(actor)
    except AlertmanagerUnavailable as error:
        result["diagnostics"].append(str(error)); return result
    try:
        client.api("/-/ready"); result["ready"] = True
        status = client.api("/api/v2/status")
        result["version"] = name(status.get("versionInfo", {}).get("version"))
        result.update(configuration_summary(status["config"]["original"]))
    except (AlertmanagerUnavailable, ValueError, KeyError, TypeError, AttributeError, yaml.YAMLError):
        result["diagnostics"].append("Readiness or sanitized routing configuration is unavailable")
    try:
        active = client.api("/api/v2/alerts")
        versions = {(row.rule_id, str(row.expected_revision + 1)): row for row in db.scalars(select(MetricRuleChange).where(
            namespace_clause(MetricRuleChange, actor), MetricRuleChange.status == "applied", MetricRuleChange.rule_id.in_(rules)).order_by(MetricRuleChange.applied_at.desc()).limit(1000))}
        result["alerts_truncated"] = len(active) > 500
        for item in active[:500]:
            labels = item.get("labels", {})
            version = versions.get((labels.get("icheck_metric_rule_id"), labels.get("icheck_metric_rule_revision")))
            if version is None or any(labels.get(key) != value for key, value in {"alertname": version.compiled_rule["alert"], **version.compiled_rule["labels"]}.items()):
                continue
            result["alerts"].append({"rule_id": version.rule_id, "revision": version.expected_revision + 1,
                "name": version.definition["name"], "severity": version.definition["severity"], "device_id": version.target_snapshot["device_id"],
                "status": item["status"]["state"] if item["status"]["state"] in {"active", "suppressed", "unprocessed"} else "unknown",
                "silenced_count": len(item["status"].get("silencedBy", [])), "inhibited_count": len(item["status"].get("inhibitedBy", [])),
                "starts_at": stamp(item["startsAt"]).isoformat(), "receivers": [name(row.get("name")) for row in item.get("receivers", [])],
                "dashboard_url": version.compiled_rule["annotations"].get("dashboard_url"), "investigation_url": version.compiled_rule["annotations"].get("investigation_url")})
    except (AlertmanagerUnavailable, ValueError, KeyError, TypeError, AttributeError):
        result["diagnostics"].append("Active Alertmanager notifications are unavailable")
    try:
        silences = client.api("/api/v2/silences")
        result["silences_truncated"] = len(silences) > 500
        for item in silences[:500]:
            matchers = exact_matchers(item)
            rule = rules.get(matchers.get("icheck_metric_rule_id"))
            if not rule or not silence_scope(item, actor):
                continue
            result["silences"].append({"id": str(UUID(item["id"])), "rule_id": rule.id, "rule_name": rule.name,
                "revision": int(matchers["icheck_metric_rule_revision"]), "starts_at": stamp(item["startsAt"]).isoformat(),
                "ends_at": stamp(item["endsAt"]).isoformat(), "state": item["status"]["state"] if item["status"]["state"] in {"active", "pending", "expired"} else "unknown",
                "fingerprint": fingerprint(item)})
    except (AlertmanagerUnavailable, ValueError, KeyError, TypeError, AttributeError):
        result["diagnostics"].append("Scoped silence status is unavailable")
    try:
        result["counters"] = notification_counters(client.api("/metrics"))
    except (AlertmanagerUnavailable, ValueError, TypeError):
        result["diagnostics"].append("Notification attempt counters are unavailable")
    return result
