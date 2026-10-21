"""External source events, native alert projection and automatic-investigation stops.

Source reads are fixed, bounded and read-only. A source event has one durable
native episode: local closure is never undone by the next source poll.
"""
from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import func, select

from ..database import require_locking_transaction, validate_session_namespace
from ..integration_custody import IntegrationCustodyUnavailable
from ..models import (Alert, AlertSeverity, AlertStatus, Device,
    MonitoringIntegrationConnection as Connection, MonitoringIntegrationAlertFeed as Feed,
    MonitoringIntegrationEvent as Event, MonitoringIntegrationResource as Resource,
    MonitoringIntegrationBinding as Binding, new_id, utcnow)
from ..monitoring_connectors.contracts import AlertObservation
from ..monitoring_connectors.zabbix import ConnectorError
from . import monitoring_integrations as integrations
from .authorization_scope import namespace_clause
from .integration_scheduling import aware

TYPE = "external.zabbix"
TYPES = {"external.zabbix", "external.solarwinds_orion", "external.rest_webhook"}


def severity(provider, value):
    number = int(value)
    if provider == "solarwinds_orion":
        return AlertSeverity.CRITICAL if number in {2, 3} else AlertSeverity.WARNING if number == 1 else AlertSeverity.INFO
    return AlertSeverity.CRITICAL if number >= 4 else AlertSeverity.WARNING if number >= 2 else AlertSeverity.INFO


def guard(db, actor, *, manage=False):
    integrations.guard(db, actor, manage=manage)
    required = ("alerts.read", "alerts.manage") if manage else ("alerts.read",)
    if not actor.permits(*required):
        raise PermissionError("External alert configuration requires alert permissions")


def read_feed(db, identifier, actor):
    guard(db, actor)
    row = integrations.connection(db, identifier, actor)
    feed = db.scalar(select(Feed).where(Feed.connection_id == row.id, namespace_clause(Feed, actor)))
    result = {"connection_id": row.id, "connection_revision": row.revision, "revision": 0, "enabled": False,
              "interval_seconds": 60, "phase": "not_started", "failures": 0,
              "last_error": None, "last_attempt_at": None, "last_success_at": None, "next_run_at": None}
    if feed:
        for key in result:
            value = getattr(feed, key)
            result[key] = aware(value) if key.endswith("_at") else value
    return result


def notify(db, identifier, payload, actor):
    """Authenticated hint only. Payloads cannot import events or start AI directly."""
    integrations.guard(db, actor)
    if not actor.permits("metrics.manage", "alerts.manage"):
        raise PermissionError("Webhook rechecks require integration and alert management permissions")
    row = integrations.connection(db, identifier, actor, lock=True)
    integrations._revision(row, payload.expected_revision)
    feed = db.scalar(select(Feed).where(Feed.connection_id == row.id, namespace_clause(Feed, actor))
                     .with_for_update().execution_options(populate_existing=True))
    if not row.enabled or not feed or not feed.enabled or feed.connection_revision != row.revision:
        raise integrations.IntegrationConflict("Enable this connection and its alert feed first")
    # Debounce at the configured polling cadence. Notifications never bypass the
    # source budget or make a permanently failing source retry in a hot loop.
    now = utcnow()
    earliest = aware(feed.last_attempt_at) + timedelta(seconds=feed.interval_seconds) if feed.last_attempt_at else now
    due = max(now, earliest)
    if feed.next_run_at is None or aware(feed.next_run_at) > due:
        feed.next_run_at = due
    integrations.audit(db, row, actor, "webhook_recheck", {"revision": row.revision})
    db.commit()
    return {"accepted": True, "source_recheck_required": True, "next_run_at": aware(feed.next_run_at)}


def update_feed(db, identifier, payload, actor):
    guard(db, actor, manage=True)
    row = integrations.connection(db, identifier, actor, lock=True)
    integrations._revision(row, payload.expected_revision)
    feed = db.scalar(select(Feed).where(Feed.connection_id == row.id, namespace_clause(Feed, actor))
                     .with_for_update().execution_options(populate_existing=True))
    if (feed.revision if feed else 0) != payload.expected_feed_revision:
        raise integrations.IntegrationConflict("Alert feed changed; refresh before continuing")
    if payload.enabled and (not row.enabled or not row.group_ids):
        raise integrations.IntegrationConflict("Enable the scoped connection first")
    if feed is None:
        feed = Feed(connection_id=row.id, tenant_id=row.tenant_id, region_id=row.region_id,
                    revision=0, connection_revision=row.revision, started_at=utcnow())
        db.add(feed)
    if feed.connection_revision != row.revision:
        feed.cursor, feed.bootstrap_ids, feed.phase, feed.started_at = "0", None, "bootstrap", utcnow()
    feed.revision += 1
    feed.connection_revision, feed.enabled = row.revision, payload.enabled
    feed.interval_seconds, feed.updated_by = payload.interval_seconds, actor.subject
    feed.next_run_at = utcnow() if payload.enabled else None
    feed.failures, feed.last_error = 0, None
    if not payload.enabled:
        stop_connection(db, row, "External alert feed paused")
    integrations.audit(db, row, actor, "alert_feed_updated", {"revision": feed.revision, "enabled": feed.enabled,
        "interval_seconds": feed.interval_seconds})
    db.commit()
    return read_feed(db, identifier, actor)


def _ns(model, row):
    return (model.tenant_id == row.tenant_id) & (model.region_id == row.region_id)


def event_for_alert(db, alert):
    return db.scalar(select(Event).where(Event.alert_id == alert.id, _ns(Event, alert))
                     .execution_options(populate_existing=True))


def mapped_asset(db, connection, observation):
    if len(observation.resources) != 1:
        return None
    observed = observation.resources[0]
    result = db.execute(select(Resource, Binding, Device).join(Binding, Binding.resource_id == Resource.id)
        .join(Device, Device.id == Binding.device_id).where(
            Resource.connection_id == connection.id, Resource.remote_id == observed.ref.remote_id,
            Binding.connection_id == connection.id,
            _ns(Resource, connection), _ns(Binding, connection), _ns(Device, connection))
        .execution_options(populate_existing=True)).first()
    if result is None:
        return None
    resource, binding, device = result
    # This event read just rechecked host membership at the source. A concurrent
    # inventory scan is not itself an identity change or a reason to stop AI.
    if (not connection.enabled or binding.connection_revision != connection.revision
        or resource.connection_revision != connection.revision or resource.name != binding.source_name
        or not device.enabled or device.identity_revision != binding.device_identity_revision
        or observed.name != binding.source_name or not observed.monitoring_enabled):
        return None
    return resource, binding, device


def stopped(db, event, reason):
    if event.stopped_at is None:
        event.stopped_at, event.stop_reason = utcnow(), reason
    if event.alert_id:
        from .alert_investigation_control import stop_for_alerts
        stop_for_alerts(db, [event.alert_id], reason="Automatic investigation stopped: " + reason)


def stop_connection(db, row, reason):
    # Only admitted episodes need immediate cancellation. Other rows are fenced
    # by connection/feed checks at admission and every execution boundary.
    from ..models import AlertInvestigationEvent, AgentExecution, AgentExecutionStatus
    events = db.scalars(select(Event).join(AlertInvestigationEvent, AlertInvestigationEvent.alert_id == Event.alert_id)
        .join(AgentExecution, AgentExecution.investigation_id == AlertInvestigationEvent.investigation_id).where(
            Event.connection_id == row.id, _ns(Event, row), _ns(AlertInvestigationEvent, row), _ns(AgentExecution, row),
            AlertInvestigationEvent.status == "dispatched",
            AgentExecution.status.in_([AgentExecutionStatus.QUEUED, AgentExecutionStatus.RUNNING, AgentExecutionStatus.WAITING_APPROVAL]))
        .order_by(Event.id).limit(1000)).unique().all()
    for event in events:
        stopped(db, event, reason)


def stop_reason(db, alert, *, live=False, cache=None):
    """DB-only admission; source revalidation before claim/model/tool/lease."""
    event = event_for_alert(db, alert)
    if event is None:
        return "External event identity is unavailable"
    if alert.status == AlertStatus.RESOLVED:
        return "External alert was closed or resolved"
    if event.stopped_at:
        return event.stop_reason or "External alert episode stopped"
    connection = db.scalar(select(Connection).where(Connection.id == event.connection_id, _ns(Connection, event))
                           .execution_options(populate_existing=True))
    feed = db.scalar(select(Feed).where(Feed.connection_id == event.connection_id, _ns(Feed, event))
                     .execution_options(populate_existing=True))
    if (not connection or not feed or not connection.enabled or not feed.enabled
        or feed.connection_revision != connection.revision or event.connection_revision != connection.revision):
        return "External alert connection, scope or feed changed"
    if not event.available or (not live and utcnow() - aware(event.checked_at) > timedelta(seconds=feed.interval_seconds * 2 + 30)):
        return "External alert status is unavailable or stale"
    observation = AlertObservation.model_validate(event.observation)
    if observation.investigation_stop_required:
        return "External alert is suppressed or resolved"
    mapped = mapped_asset(db, connection, observation)
    if (not mapped or mapped[0].id != event.resource_id or mapped[1].revision != event.binding_revision
        or alert.entity_id != mapped[2].id or alert.entity_type != "device"):
        return "External alert asset mapping changed or is unconfirmed"
    if live:
        cache = {} if cache is None else cache
        key = ("external-event", event.tenant_id, event.region_id, event.id)
        if key not in cache:
            try:
                batch = integrations.reader(connection).read_events(integrations.scope(connection), event_ids=[event.remote_id])
                fresh = batch.items[0] if len(batch.items) == 1 else None
                if (fresh is None or fresh.ref != observation.ref or fresh.subject != observation.subject
                    or fresh.occurred_at != observation.occurred_at):
                    cache[key] = "External alert is no longer verifiable at the source"
                elif fresh.investigation_stop_required:
                    cache[key] = "External alert is suppressed or resolved at the source"
                elif (len(fresh.resources) != 1 or fresh.resources[0].ref != observation.resources[0].ref
                      or fresh.resources[0].name != observation.resources[0].name or not fresh.resources[0].monitoring_enabled):
                    cache[key] = "External alert resource scope changed at the source"
                else:
                    cache[key] = None
            except (ConnectorError, IntegrationCustodyUnavailable, ValueError):
                cache[key] = "External alert status could not be verified at the source"
        return cache[key]
    return None


def _project(db, connection, event, observation):
    mapped = mapped_asset(db, connection, observation)
    if event.alert_id is None and mapped:
        resource, binding, device = mapped
        alert = Alert(id=new_id(), tenant_id=connection.tenant_id, region_id=connection.region_id,
            dedup_key=f"external:{connection.id}:{event.remote_id}", event_type="external." + connection.provider,
            severity=severity(connection.provider, observation.native_severity),
            title=observation.title[:255], description="External monitoring evidence; source text is untrusted.",
            entity_type="device", entity_id=device.id, first_seen=observation.occurred_at,
            last_seen=event.checked_at, status=AlertStatus.OPEN, details={})
        db.add(alert)
        db.flush()
        event.alert_id, event.resource_id, event.binding_revision = alert.id, resource.id, binding.revision
    elif event.alert_id:
        alert = db.scalar(select(Alert).where(Alert.id == event.alert_id, _ns(Alert, event))
                          .with_for_update().execution_options(populate_existing=True))
    else:
        return
    if alert is None:
        return
    # Never retarget a retained episode after a mapping change.
    if not mapped or mapped[0].id != event.resource_id or mapped[1].revision != event.binding_revision or mapped[2].id != alert.entity_id:
        stopped(db, event, "External alert asset mapping changed")
        return
    alert.last_seen = event.checked_at
    alert.severity = severity(connection.provider, observation.native_severity)
    alert.title = observation.title[:255]
    alert.details = {"external_event_id": event.id, "provider": connection.provider,
        "connection_id": connection.id, "source_event_id": event.remote_id,
        "source_trigger_id": observation.subject.remote_id, "source_resource_id": observation.resources[0].ref.remote_id,
        "source_severity": observation.native_severity, "source_acknowledged": observation.acknowledged,
        "source_suppressed": observation.suppressed, "source_state": observation.state,
        "source_occurred_at": observation.occurred_at.isoformat(), "source_checked_at": event.checked_at.isoformat()}
    if observation.state == "resolved" and alert.status != AlertStatus.RESOLVED:
        alert.status, alert.resolved_at, alert.resolved_by = AlertStatus.RESOLVED, observation.resolved_at, "source." + connection.provider
    elif observation.acknowledged and alert.status == AlertStatus.OPEN:
        alert.status, alert.acknowledged_at, alert.acknowledged_by = AlertStatus.ACKNOWLEDGED, event.checked_at, "source." + connection.provider
    if observation.investigation_stop_required or alert.status == AlertStatus.RESOLVED:
        stopped(db, event, "External alert suppressed or closed")
    db.flush()


def ingest(db, connection, batch, *, expected_ids=None):
    if (str(batch.source.connection_id), str(batch.source.tenant_id), str(batch.source.region_id), batch.source.provider) != (
        connection.id, connection.tenant_id, connection.region_id, connection.provider):
        raise ConnectorError("source_scope_mismatch")
    seen = set()
    for observation in batch.items:
        if observation.occurred_at > utcnow() + timedelta(minutes=5):
            raise ConnectorError("invalid_source_response")
        remote = observation.ref.remote_id
        seen.add(remote)
        event = db.scalar(select(Event).where(Event.connection_id == connection.id, Event.remote_id == remote, _ns(Event, connection)))
        if event is None:
            event = Event(id=new_id(), tenant_id=connection.tenant_id, region_id=connection.region_id,
                connection_id=connection.id, remote_id=remote, connection_revision=connection.revision,
                available=True, observation=observation.model_dump(mode="json"), source_resolved=False, checked_at=batch.fetched_at)
            db.add(event)
        else:
            previous = AlertObservation.model_validate(event.observation)
            if (observation.subject != previous.subject or observation.occurred_at != previous.occurred_at
                or (event.source_resolved and observation.state != "resolved")):
                event.available, event.checked_at = False, batch.fetched_at
                stopped(db, event, "External event identity or recovery contradicted")
                continue
        event.connection_revision, event.available, event.checked_at = connection.revision, True, batch.fetched_at
        event.observation = observation.model_dump(mode="json")
        event.source_resolved = observation.state == "resolved"
        if observation.investigation_stop_required:
            stopped(db, event, "External alert suppressed or closed")
        _project(db, connection, event, observation)
    if expected_ids:
        missing = set(expected_ids) - seen
        for event in db.scalars(select(Event).where(Event.connection_id == connection.id, _ns(Event, connection), Event.remote_id.in_(missing))):
            event.available, event.checked_at = False, batch.fetched_at
            stopped(db, event, "External event no longer visible; recovery unconfirmed")
    db.flush()


def _poll_locked(db, connection, feed):
    now = utcnow()
    feed.last_attempt_at = now
    reader, scope = integrations.reader(connection), integrations.scope(connection)
    with db.begin_nested():
        if feed.phase == "bootstrap" and feed.bootstrap_ids is None:
            feed.bootstrap_ids = reader.active_event_manifest(scope)
        elif feed.phase == "bootstrap" and feed.bootstrap_ids:
            ids = feed.bootstrap_ids[:100]
            ingest(db, connection, reader.read_events(scope, event_ids=ids), expected_ids=ids)
            feed.bootstrap_ids = feed.bootstrap_ids[100:]
        elif feed.phase == "reconcile":
            rows = db.scalars(select(Event).where(Event.connection_id == connection.id, _ns(Event, connection),
                Event.source_resolved.is_(False)).order_by(Event.checked_at, Event.id).limit(100)).all()
            ids = [event.remote_id for event in rows]
            if ids:
                ingest(db, connection, reader.read_events(scope, event_ids=ids), expected_ids=ids)
            feed.phase = "new"
        else:
            batch = reader.read_events(scope, after=feed.cursor, since=aware(feed.started_at))
            ingest(db, connection, batch)
            if batch.items:
                feed.cursor = str(max(int(item.ref.remote_id) for item in batch.items))
            feed.phase = "reconcile"
        if feed.phase == "bootstrap" and feed.bootstrap_ids == []:
            feed.phase = "new"
    feed.last_success_at, feed.failures, feed.last_error = utcnow(), 0, None
    # New-event and retained-event pages alternate so arrivals cannot starve recovery.
    feed.next_run_at = utcnow() if feed.phase in {"bootstrap", "reconcile"} else utcnow() + timedelta(seconds=feed.interval_seconds)


def poll_once(db):
    tenant, region = validate_session_namespace(db)
    actor = SimpleNamespace(tenant_id=tenant, region_id=region, principal_type="worker", subject="integration-alert-worker")
    require_locking_transaction(db, purpose="External alert feed")
    connection = db.scalar(select(Connection).join(Feed, Feed.connection_id == Connection.id).where(
        _ns(Connection, actor), _ns(Feed, actor), Connection.enabled.is_(True), Feed.enabled.is_(True),
        Feed.connection_revision == Connection.revision, Feed.next_run_at <= utcnow())
        .order_by(Feed.next_run_at, Connection.id).limit(1).with_for_update(skip_locked=True, of=Connection)
        .execution_options(populate_existing=True))
    if connection is None:
        db.rollback()
        return False
    feed = db.scalar(select(Feed).where(Feed.connection_id == connection.id, _ns(Feed, actor))
                     .with_for_update().execution_options(populate_existing=True))
    if not feed.enabled or feed.connection_revision != connection.revision or aware(feed.next_run_at) > utcnow():
        db.rollback()
        return False
    try:
        _poll_locked(db, connection, feed)
    except (ConnectorError, IntegrationCustodyUnavailable) as error:
        feed.failures += 1
        feed.last_error = integrations.safe_error(error)
        feed.next_run_at = utcnow() + timedelta(seconds=feed.interval_seconds)
        stop_connection(db, connection, "External alert feed could not verify source status")
    integrations.audit(db, connection, actor, "alert_feed_polled", {"phase": feed.phase, "error_code": feed.last_error})
    db.commit()
    return True


def listing(db, identifier, actor, *, offset=0, limit=50):
    guard(db, actor)
    connection = integrations.connection(db, identifier, actor)
    query = select(Event).where(Event.connection_id == connection.id, _ns(Event, connection))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    items = []
    for event in db.scalars(query.order_by(Event.checked_at.desc(), Event.id).offset(offset).limit(limit)):
        observation = AlertObservation.model_validate(event.observation)
        native = db.scalar(select(Alert).where(Alert.id == event.alert_id, _ns(Alert, event))) if event.alert_id else None
        locally_closed = native is not None and native.status == AlertStatus.RESOLVED
        mapped = mapped_asset(db, connection, observation)
        current = mapped and (not event.alert_id or (mapped[0].id == event.resource_id
            and mapped[1].revision == event.binding_revision and native and mapped[2].id == native.entity_id))
        items.append({"id": event.id, "source_event_id": event.remote_id, "title": observation.title,
            "source_state": observation.state, "suppressed": observation.suppressed, "acknowledged": observation.acknowledged,
            "native_severity": observation.native_severity, "available": event.available, "checked_at": aware(event.checked_at),
            "occurred_at": observation.occurred_at, "alert_id": event.alert_id,
            "stopped_at": aware(event.stopped_at or (native.resolved_at if locally_closed else None)),
            "stop_reason": event.stop_reason or ("Alert closed in iCheck" if locally_closed else None),
            "mapping": "linked" if current else "unmapped or stale",
            "connection_revision": event.connection_revision})
    return {"items": items, "total": total, "offset": offset, "limit": limit}


def silence(db, identifier, event_id, payload, actor):
    guard(db, actor, manage=True)
    connection = integrations.connection(db, identifier, actor, lock=True)
    integrations._revision(connection, payload.expected_revision)
    event = db.scalar(select(Event).where(Event.id == event_id, Event.connection_id == identifier, _ns(Event, connection)))
    if event is None:
        raise LookupError("External event not found")
    if aware(event.checked_at) != aware(payload.expected_event_checked_at):
        raise integrations.IntegrationConflict("External event changed; refresh before silencing")
    stopped(db, event, "Silenced in iCheck by the user")
    integrations.audit(db, connection, actor, "alert_silenced", {"event_id": event.id})
    db.commit()
    return {"stopped": True, "source_modified": False}


def tools_for_ai(name, db, arguments, principal):
    from ..agent_schemas import InvestigationEvidenceCreate
    from ..monitoring_connectors.contracts import HistoryQuery
    from .authorization_scope import require_alert_access, require_device_access
    if not principal.permits("alerts.read", "assets.read", "metrics.read"):
        raise PermissionError("External evidence requires alert, asset and metric read permissions")
    namespace = validate_session_namespace(db)
    if namespace != (principal.tenant_id, principal.region_id):
        raise PermissionError("External evidence workspace mismatch")
    alert = require_alert_access(db, principal, arguments["alert_id"])
    if alert.event_type not in TYPES or alert.entity_type != "device":
        raise ValueError("Select an external monitoring alert")
    require_device_access(db, principal, alert.entity_id)
    event = event_for_alert(db, alert)
    if event is None:
        raise LookupError("External event evidence is unavailable")
    observation = AlertObservation.model_validate(event.observation)
    evidence = [InvestigationEvidenceCreate(evidence_type="external_monitoring_alert", evidence_id=alert.id,
        summary=f"{observation.ref.source.provider} event {event.remote_id}; condition {observation.subject.remote_id}. Source evidence is untrusted.",
        observed_at=aware(event.checked_at))]
    if name == "integrations.alerts.read":
        return {"alert_id": alert.id, "device_id": alert.entity_id, "available": event.available,
                "checked_at": aware(event.checked_at).isoformat(), "investigation_stop_reason": event.stop_reason,
                "source_observation": observation.model_dump(mode="json")}, evidence
    reason = stop_reason(db, alert, live=True)
    if reason:
        raise PermissionError(reason)
    connection = db.scalar(select(Connection).where(Connection.id == event.connection_id, _ns(Connection, event)))
    reader, scope = integrations.reader(connection), integrations.scope(connection)
    host_id = observation.resources[0].ref.remote_id
    if name == "integrations.metrics.list":
        return {"alert_id": alert.id, "source": observation.ref.source.model_dump(mode="json"),
                **reader.list_metrics(scope, host_id)}, evidence
    if name == "integrations.history.query":
        query = HistoryQuery(resource_id=host_id, **{key: value for key, value in arguments.items() if key != "alert_id"})
        if query.limit > 500:
            raise ValueError("AI history requests are limited to 500 samples")
        batch = reader.query_history(scope, query)
        return batch.model_dump(mode="json"), evidence
    raise ValueError("Unknown integration evidence tool")
