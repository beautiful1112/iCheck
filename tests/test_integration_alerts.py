"""Synthetic Zabbix events only: no network, provider spend or device access."""
from copy import deepcopy
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from icheck.auth import current_principal
from icheck.database import SessionLocal as RawSession, set_session_namespace
from icheck.main import app
from icheck.models import (Alert, AlertStatus, AgentExecution, AgentExecutionStatus, Investigation,
    InvestigationEvidence, AlertInvestigationPolicy, MonitoringIntegrationAlertFeed as Feed,
    MonitoringIntegrationEvent as Event, MonitoringIntegrationConnection as Connection,
    MonitoringIntegrationBinding as Binding, Device, utcnow)
from icheck.monitoring_connectors.zabbix import ConnectorError
from icheck.services import integration_alerts as service, monitoring_integrations as integrations
from icheck.services import alert_investigation as dispatch
from icheck.services.alerts import resolve_alert
from icheck.services.control_plane_auth import development_principal
from test_integration_bindings import inventory, asset, plan, body
from test_integration_discovery_sync import source
from test_monitoring_integrations import protected_configuration, BASE, TOKEN
from test_agent_runtime import configure_investigation_route
from test_alert_investigation_stop import claim
from test_investigation_autonomy import enable


@contextmanager
def SessionLocal():
    actor = development_principal()
    with RawSession() as db:
        set_session_namespace(db, actor.tenant_id, actor.region_id)
        yield db


@pytest.fixture
def events(source, monkeypatch):
    original = source.request
    source.events = [{"eventid": "200", "objectid": "300", "source": "0", "object": "0", "value": "1",
        "name": "Interface unavailable", "severity": "4", "clock": str(int(utcnow().timestamp())),
        "acknowledged": "0", "suppressed": "0", "r_eventid": "0", "hosts": [{"hostid": "100"}]}]
    source.recoveries = []
    source.fail_events = False
    source.item_host = "100"

    def request(self, payload, **bounds):
        method, params = payload["method"], payload["params"]
        if method not in {"event.get", "problem.get", "item.get", "history.get"}:
            return original(self, payload, **bounds)
        source.calls.append(payload)
        if source.fail_events:
            raise ConnectorError("source_timeout")
        if method == "problem.get":
            assert "recent" not in params and params["groupids"] == ["1", "2"]
            rows = [{"eventid": row["eventid"]} for row in source.events if row["r_eventid"] == "0"]
        elif method == "event.get":
            assert params["source"] == params["object"] == 0
            if "groupids" in params:
                assert params["groupids"] == ["1", "2"] and params["value"] == 1
                rows = source.events
            else:
                rows = source.recoveries
            rows = [row for row in rows if ("eventids" not in params or row["eventid"] in params["eventids"])
                and int(row["eventid"]) >= int(params.get("eventid_from", 0))
                and int(row["clock"]) >= params.get("time_from", 0)]
        elif method == "item.get":
            rows = [{"itemid": "400", "hostid": source.item_host, "name": "Interface traffic", "value_type": "3", "units": "bps"}]
        else:
            rows = [{"itemid": "400", "clock": str(params["time_from"] + 1), "ns": "0", "value": "42"}]
        return {"jsonrpc": "2.0", "id": payload["id"], "result": deepcopy(rows[:params["limit"]])}

    monkeypatch.setattr(source, "request", request)
    return source


def setup(client, events, *, link=True, existing=None):
    row, path = existing or inventory(client, events, 2)
    if link:
        asset("Device 100")
        assert client.put(path + "/asset-mapping", json=body(plan(client, path))).status_code == 200
    response = client.put(path + "/alert-feed", json={
        "expected_revision": row["revision"], "expected_feed_revision": 0, "enabled": True, "confirm": True})
    assert response.status_code == 200, response.text
    poll()  # bounded current problem manifest
    poll()  # explicit event observations
    return row, path


def poll(*, phase=None):
    with SessionLocal() as db:
        for feed in db.scalars(select(Feed)):
            feed.next_run_at = utcnow() - timedelta(seconds=1)
            if phase:
                feed.phase = phase
        db.commit()
        return service.poll_once(db)


@pytest.fixture
def automatic(client, events):
    configure_investigation_route(client)
    enable(client)
    with SessionLocal() as db:
        db.scalar(select(AlertInvestigationPolicy)).enabled_at -= timedelta(seconds=2)
        db.commit()
    row, path = setup(client, events)
    with SessionLocal() as db:
        assert dispatch.dispatch_alert_investigations(db) == 1
        execution = db.scalar(select(AgentExecution))
        assert execution is not None
        return row, path, db.scalar(select(Alert)).id, execution.investigation_id, execution.id


def test_opt_in_idempotent_projection_local_gets_and_source_provenance(client, events):
    row, path = inventory(client, events, 1)
    calls = len(events.calls)
    feed = client.get(path + "/alert-feed")
    assert feed.status_code == 200 and not feed.json()["enabled"] and feed.json()["revision"] == 0
    assert client.get(path + "/external-alerts").json()["total"] == 0
    assert len(events.calls) == calls
    assert not poll()
    _, path = setup(client, events, existing=(row, path))
    poll(phase="reconcile")
    view = client.get(path + "/external-alerts").json()
    assert view["total"] == 1 and view["items"][0]["mapping"] == "linked"
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Alert)) == 1
        alert = db.scalar(select(Alert))
        assert alert.details["source_event_id"] == "200" and alert.details["source_trigger_id"] == "300"
        assert alert.event_type == "external.zabbix" and alert.severity.value == "critical"
        assert db.scalar(select(func.count()).select_from(Investigation)) == 0
    assert TOKEN not in str(view)


@pytest.mark.parametrize("condition", ["unmapped", "multiple_hosts", "missing_host", "disabled_host"])
def test_only_one_reviewed_current_asset_can_project(client, events, condition):
    if condition == "multiple_hosts":
        events.events[0]["hosts"].append({"hostid": "101"})
    if condition == "missing_host":
        events.missing = {"100"}
    row, path = setup(client, events, link=condition not in {"unmapped", "missing_host"})
    if condition == "disabled_host":
        # Identity change after initial projection fences admission.
        with SessionLocal() as db:
            db.scalar(select(Device)).enabled = False
            db.commit()
            assert service.stop_reason(db, db.scalar(select(Alert)))
        return
    assert client.get(path + "/external-alerts").json()["items"][0]["alert_id"] is None
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Alert)) == 0


def test_dispatch_has_source_evidence_and_does_not_call_a_model(client, automatic):
    with SessionLocal() as db:
        assert db.get(Investigation, automatic[3]).execution_mode == "diagnose"
        assert db.get(Investigation, automatic[3]).tokens_used == 0
        assert db.scalar(select(InvestigationEvidence)).evidence_type == "external_monitoring_alert"
        assert dispatch.dispatch_alert_investigations(db) == 0


@pytest.mark.parametrize("change", ["suppressed", "resolved", "missing", "unavailable", "mapping", "identity", "feed", "connection"])
def test_live_gate_stops_before_worker_claim_without_waiting_for_poll(client, events, automatic, change):
    if change == "suppressed":
        events.events[0]["suppressed"] = "1"
    elif change == "resolved":
        recover(events)
    elif change == "missing":
        events.events = []
    elif change == "unavailable":
        events.fail_events = True
    else:
        with SessionLocal() as db:
            if change == "mapping": db.scalar(select(Binding)).revision += 1
            if change == "identity": db.scalar(select(Device)).identity_revision += 1
            if change == "feed": db.scalar(select(Feed)).enabled = False
            if change == "connection": db.scalar(select(Connection)).revision += 1
            db.commit()
    assert claim(client)[1] == []
    with SessionLocal() as db:
        assert db.get(AgentExecution, automatic[4]).status == AgentExecutionStatus.CANCELLED
        assert db.get(Alert, automatic[2]).status == AlertStatus.OPEN


def recover(events):
    events.events[0]["r_eventid"] = "201"
    events.recoveries = [{"eventid": "201", "objectid": "300", "source": "0", "object": "0", "value": "0",
        "clock": str(int(events.events[0]["clock"]) + 1)}]


@pytest.mark.parametrize("change", ["suppressed", "resolved", "missing", "unavailable"])
def test_poll_cancels_and_never_confuses_missing_or_silence_with_recovery(client, events, automatic, change):
    if change == "suppressed": events.events[0]["suppressed"] = "1"
    if change == "resolved": recover(events)
    if change == "missing": events.events = []
    if change == "unavailable": events.fail_events = True
    poll(phase="reconcile")
    with SessionLocal() as db:
        assert db.get(AgentExecution, automatic[4]).status == AgentExecutionStatus.CANCELLED
        assert (db.get(Alert, automatic[2]).status == AlertStatus.RESOLVED) == (change == "resolved")
        if change == "unavailable":
            assert db.scalar(select(Feed)).last_error == "source_timeout"
        else:
            assert db.scalar(select(Event)).stopped_at


def test_acknowledgement_is_not_a_stop(client, events, automatic):
    events.events[0]["acknowledged"] = "1"
    poll(phase="reconcile")
    with SessionLocal() as db:
        assert db.get(Alert, automatic[2]).status == AlertStatus.ACKNOWLEDGED
    assert len(claim(client)[1]) == 1


@pytest.mark.parametrize("boundary", ["lease", "reason", "tool"])
def test_silence_blocks_next_running_boundary(client, events, automatic, boundary):
    headers, assignments = claim(client)
    base = f"/api/v1/agent/executions/{automatic[4]}"
    payload = {"protocol_version": "icheck.agent-runtime/v1", "lease_token": assignments[0]["lease_token"]}
    bootstrap = client.post(base + "/runtime/bootstrap", headers=headers, json=payload)
    assert bootstrap.status_code == 200, bootstrap.text
    events.events[0]["suppressed"] = "1"
    if boundary == "lease":
        response = client.post(base + "/lease", headers=headers, json={"lease_token": payload["lease_token"], "lease_seconds": 60})
        assert response.status_code == 200 and response.json()["cancellation_requested_at"]
    else:
        request = {**payload, "operation_id": "0" * 64, "state": bootstrap.json()["initial_state"]}
        if boundary == "tool":
            request["request"] = {"tool_name": "inventory.devices.list", "arguments": {}, "rationale": "Inspect inventory"}
        response = client.post(base + "/runtime/" + boundary, headers=headers, json=request)
        assert response.status_code == 409, response.text
    events.events[0]["suppressed"] = "0"
    assert claim(client)[1] == []


def test_user_silence_and_close_are_durable_without_source_writes(client, events, automatic):
    view = client.get(automatic[1] + "/external-alerts").json()["items"][0]
    calls = len(events.calls)
    payload = {"expected_revision": automatic[0]["revision"], "expected_event_checked_at": view["checked_at"], "confirm": True}
    result = client.post(automatic[1] + f"/external-alerts/{view['id']}/silence", json=payload)
    assert result.status_code == 200 and result.json()["source_modified"] is False
    assert len(events.calls) == calls
    with SessionLocal() as db:
        assert db.get(AgentExecution, automatic[4]).status == AgentExecutionStatus.CANCELLED
    assert client.post(f"/api/v1/alerts/{automatic[2]}/resolve", json={"actor": "fixture"}).status_code == 200
    assert client.get(f"/api/v1/alerts?alert_id={automatic[2]}").json()[0]["status"] == "resolved"
    poll(phase="reconcile")
    with SessionLocal() as db:
        assert db.get(Alert, automatic[2]).status == AlertStatus.RESOLVED
        assert db.scalar(select(func.count()).select_from(Alert)) == 1
        assert service.stop_reason(db, db.get(Alert, automatic[2]), live=True)


def test_close_and_source_ingest_roll_back_together(client, events, automatic):
    with SessionLocal() as db:
        resolve_alert(db, db.get(Alert, automatic[2]), "fixture")
        db.rollback()
        assert db.get(AgentExecution, automatic[4]).status == AgentExecutionStatus.QUEUED
        events.events[0]["suppressed"] = "1"
        connection = db.get(Connection, automatic[0]["id"])
        service.ingest(db, connection, integrations.reader(connection).read_events(integrations.scope(connection), event_ids=["200"]))
        db.rollback()
        assert db.scalar(select(Event)).stopped_at is None
        assert db.get(AgentExecution, automatic[4]).status == AgentExecutionStatus.QUEUED


def test_feed_revisions_human_permissions_and_connection_changes(client, events, automatic):
    row, path = automatic[:2]
    payload = {"expected_revision": row["revision"], "expected_feed_revision": 0, "enabled": False, "confirm": True}
    assert client.put(path + "/alert-feed", json=payload).status_code == 409
    actor = replace(development_principal(), principal_type="service")
    app.dependency_overrides[current_principal] = lambda: actor
    try:
        assert client.put(path + "/alert-feed", json={**payload, "expected_feed_revision": 1}).status_code == 403
    finally:
        app.dependency_overrides.pop(current_principal, None)
    assert client.put(path, json={"expected_revision": row["revision"], "enabled": False}).status_code == 200
    assert not client.get(path + "/alert-feed").json()["enabled"]
    with SessionLocal() as db:
        assert db.get(AgentExecution, automatic[4]).status == AgentExecutionStatus.CANCELLED


def test_ai_tools_are_asset_scoped_and_return_bounded_source_history(client, events, automatic):
    actor = development_principal()
    with SessionLocal() as db:
        arguments = {"alert_id": automatic[2]}
        result, evidence = service.tools_for_ai("integrations.alerts.read", db, arguments, actor)
        assert result["source_observation"]["ref"]["remote_id"] == "200" and evidence
        result, _ = service.tools_for_ai("integrations.metrics.list", db, arguments, actor)
        assert result["items"][0]["metric_id"] == "400"
        result, _ = service.tools_for_ai("integrations.history.query", db, {**arguments, "metric_id": "400", "value_type": "uint",
            "start": (utcnow() - timedelta(minutes=5)).isoformat(), "end": utcnow().isoformat(), "limit": 10}, actor)
        assert result["items"][0]["value"] == 42
        events.item_host = "999"
        with pytest.raises(ConnectorError, match="metric_scope_or_type_mismatch"):
            service.tools_for_ai("integrations.metrics.list", db, arguments, actor)


def test_forward_paging_and_explicit_recovery_are_bounded(client, events):
    row, _ = setup(client, events)
    with SessionLocal() as db:
        connection = db.get(Connection, row["id"])
        reader, scope = integrations.reader(connection), integrations.scope(connection)
        events.events = [{**events.events[0], "eventid": str(n)} for n in range(200, 301)]
        first = reader.read_events(scope, after="0", since=utcnow() - timedelta(minutes=1))
        assert len(first.items) == 100 and first.truncated
        second = reader.read_events(scope, after="299", since=utcnow() - timedelta(minutes=1))
        assert len(second.items) == 1 and not second.truncated
        recover(events)
        events.recoveries[0]["objectid"] = "999"
        with pytest.raises(ConnectorError, match="invalid_recovery_evidence"):
            reader.read_events(scope, event_ids=["200"])


def test_missing_status_stops_waiting_approval_and_remains_stopped_after_reappearance(client, events, automatic):
    with SessionLocal() as db:
        db.get(AgentExecution, automatic[4]).status = AgentExecutionStatus.WAITING_APPROVAL
        db.get(Investigation, automatic[3]).status = "waiting_approval"
        db.commit()
    old = events.events
    events.events = []
    poll(phase="reconcile")
    events.events = old
    poll(phase="reconcile")
    with SessionLocal() as db:
        assert db.get(AgentExecution, automatic[4]).status == AgentExecutionStatus.CANCELLED
        assert db.scalar(select(Event)).available
        assert db.scalar(select(Event)).stopped_at
        assert dispatch.dispatch_alert_investigations(db) == 0


def test_source_severity_updates_and_asset_remap_never_retargets_old_episode(client, events, automatic):
    events.events[0]["severity"] = "2"
    poll(phase="reconcile")
    with SessionLocal() as db:
        assert db.get(Alert, automatic[2]).severity.value == "warning"
        old_device = db.get(Alert, automatic[2]).entity_id
        other = Device(name="Other", kind="network")
        db.add(other); db.flush()
        binding = db.scalar(select(Binding))
        binding.device_id = other.id
        binding.revision += 1
        db.commit()
    poll(phase="reconcile")
    with SessionLocal() as db:
        assert db.get(Alert, automatic[2]).entity_id == old_device
        assert db.get(AgentExecution, automatic[4]).status == AgentExecutionStatus.CANCELLED


def test_source_old_events_do_not_backfill_policy_and_empty_pages_do_not_close(client, events):
    events.events[0]["clock"] = str(int((utcnow() - timedelta(days=5)).timestamp()))
    configure_investigation_route(client)
    enable(client)
    setup(client, events)
    poll(phase="new")
    with SessionLocal() as db:
        assert dispatch.dispatch_alert_investigations(db) == 0
        assert db.scalar(select(Alert)).status == AlertStatus.OPEN
    recover(events)
    poll(phase="reconcile")
    with SessionLocal() as db:
        assert db.scalar(select(Alert)).status == AlertStatus.RESOLVED


def test_external_episodes_do_not_share_a_silence_boundary(client, events, automatic):
    events.events.append({**events.events[0], "eventid": "202"})
    poll(phase="new")
    with SessionLocal() as db:
        assert dispatch.dispatch_alert_investigations(db) == 1
        assert db.scalar(select(func.count()).select_from(Investigation)) == 2


def test_evidence_tools_enforce_current_asset_scope(client, events, automatic):
    from fastapi import HTTPException
    actor = replace(development_principal(), authorization_scope={"device_ids": ["different"]})
    with SessionLocal() as db, pytest.raises(HTTPException) as error:
        service.tools_for_ai("integrations.alerts.read", db, {"alert_id": automatic[2]}, actor)
    assert error.value.status_code == 404


def test_alert_worker_has_no_enable_binding_or_enqueue_authority():
    from icheck.worker_database_roles import PROFILES, COLUMN_GRANTS
    role = PROFILES["integration-alert-worker"]
    columns = COLUMN_GRANTS["integration-alert-worker"]
    assert role["agent_executions"] == ("SELECT",)
    assert role["investigations"] == ("SELECT",)
    assert "monitoring_integration_bindings" not in columns
    assert "enabled" not in columns["monitoring_integration_alert_feeds"]["UPDATE"]
    assert columns["monitoring_integration_connections"]["UPDATE"] == ("updated_at",)


def test_local_close_is_visible_and_stops_ai_before_another_poll(client, events, automatic):
    calls = len(events.calls)
    assert client.post(f"/api/v1/alerts/{automatic[2]}/resolve", json={"actor": "fixture"}).status_code == 200
    row = client.get(automatic[1] + "/external-alerts").json()["items"][0]
    assert row["source_state"] == "open" and row["stopped_at"]
    assert row["stop_reason"] == "Alert closed in iCheck"
    assert len(events.calls) == calls
    with SessionLocal() as db:
        assert db.get(AgentExecution, automatic[4]).status == AgentExecutionStatus.CANCELLED


def test_same_remote_event_in_two_connections_keeps_distinct_episodes(client, events, automatic):
    from test_monitoring_integrations import create
    from test_integration_discovery_sync import start, step
    with SessionLocal() as db:
        db.get(Feed, automatic[0]["id"]).enabled = False
        db.commit()
    response = create(client, name="Second Zabbix")
    assert response.status_code == 201
    row = response.json()
    path = f"{BASE}/{row['id']}"
    row = client.put(path, json={"expected_revision": 1, "enabled": True}).json()
    run = start(client, row)
    while run["can_resume"]:
        run = step(client, row, run)
    assert client.put(path + "/asset-mapping", json=body(plan(client, path))).status_code == 200
    setup(client, events, link=False, existing=(row, path))
    with SessionLocal() as db:
        records = db.scalars(select(Event)).all()
        assert len(records) == 2 and {item.remote_id for item in records} == {"200"}
        assert len({item.alert_id for item in records}) == 2
