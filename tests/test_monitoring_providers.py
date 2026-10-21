"""Full saved-provider and alert projection paths with injected source transport."""
import base64
from copy import deepcopy
from datetime import timedelta

import pytest
from sqlalchemy import select

from icheck.config import get_settings
from icheck.database import SessionLocal
from icheck.integration_custody import decrypt_token
from icheck import integration_custody
from icheck.models import (MonitoringIntegrationConnection, MonitoringIntegrationAlertFeed, Alert, utcnow,
    AlertInvestigationPolicy, AgentExecution, AgentExecutionStatus)
from icheck.services import monitoring_integrations as service
from icheck.services import alert_investigation as dispatch
from test_orion_bridge_connectors import Orion, Bridge
from test_integration_alerts import poll
from test_integration_bindings import asset, plan, body
from test_agent_runtime import configure_investigation_route
from test_alert_investigation_stop import claim
from test_investigation_autonomy import enable

BASE = "/api/v1/integrations/connections"
PASSWORD = "synthetic-orion-password"


@pytest.fixture
def vendor(monkeypatch):
    fake = Orion()
    fake.responses["events"][0]["occurred"] = utcnow().isoformat()
    monkeypatch.setenv("ICHECK_MONITORING_INTEGRATION_ALLOWED_ORIGINS", "https://orion.example.test:17774,https://bridge.example.test")
    get_settings.cache_clear()
    monkeypatch.setattr(integration_custody, "key", lambda: b"k" * 32)
    monkeypatch.setattr(service, "ORION_TRANSPORT", lambda *a, **kw: fake)
    yield fake
    get_settings.cache_clear()


def saved(client):
    response = client.post(BASE, json={"name": "Orion", "provider": "solarwinds_orion",
        "api_url": "https://orion.example.test:17774", "username": "readonly", "password": PASSWORD, "group_ids": ["2"]})
    assert response.status_code == 201, response.text
    return response.json(), BASE + "/" + response.json()["id"]


def test_native_orion_create_test_rotation_keeps_secrets_write_only(client, vendor):
    row, path = saved(client)
    assert not vendor.calls and not row["enabled"]
    assert PASSWORD not in str(row) and "readonly" not in str(row)
    with SessionLocal() as db:
        stored = db.get(MonitoringIntegrationConnection, row["id"])
        assert PASSWORD.encode() not in stored.encrypted_token
        assert base64.b64decode(decrypt_token(stored)).decode() == "readonly:" + PASSWORD
    test = client.post(path + "/test", json={"expected_revision": 1, "confirm": True})
    assert test.status_code == 200 and test.json()["status"] == "succeeded", test.text
    assert client.put(path, json={"expected_revision": 1, "enabled": False, "password": "alone"}).status_code == 422
    assert client.put(path, json={"expected_revision": 1, "enabled": False, "token": "synthetic-replacement-token"}).status_code == 422
    rotated = client.put(path, json={"expected_revision": 1, "enabled": False, "username": "other", "password": "replacement"})
    assert rotated.status_code == 200 and rotated.json()["last_test_status"] is None


def enable_mapped_feed(client, row, path):
    row = client.put(path, json={"expected_revision": 1, "enabled": True}).json()
    confirm = {"expected_revision": row["revision"], "confirm": True}
    started = client.post(path + "/syncs", json=confirm)
    assert started.status_code == 200, started.text
    step = client.post(path + "/syncs/" + started.json()["id"] + "/step", json={**confirm, "expected_cursor": 0})
    assert step.status_code == 200 and step.json()["status"] == "completed", step.text
    asset("Router")
    mapped = client.put(path + "/asset-mapping", json=body(plan(client, path)))
    assert mapped.status_code == 200, mapped.text
    feed = client.put(path + "/alert-feed", json={**confirm, "expected_feed_revision": 0, "enabled": True})
    assert feed.status_code == 200, feed.text
    poll(); poll()
    return row, path, confirm


def test_orion_inventory_mapping_feed_and_source_closure(client, vendor):
    row, path, confirm = enable_mapped_feed(client, *saved(client))
    with SessionLocal() as db:
        alert = db.scalar(select(Alert))
        assert alert.event_type == "external.solarwinds_orion" and alert.severity.value == "critical"
    assert client.post(path + "/notify", json=confirm).status_code == 202
    with SessionLocal() as db:
        feed = db.get(MonitoringIntegrationAlertFeed, row["id"])
        assert feed.next_run_at is not None
    event = vendor.responses["events"][0]
    vendor.responses["recoveries"] = [{"id": 101, "episode": 200, "subject": 300,
        "occurred": event["occurred"], "event_type": 8}]
    event["active_id"] = None
    poll(phase="reconcile")
    view = client.get(path + "/external-alerts").json()
    assert view["items"][0]["source_state"] == "resolved", view
    with SessionLocal() as db:
        assert db.scalar(select(Alert)).resolved_by == "source.solarwinds_orion"


def test_bridge_create_is_disabled_notify_does_not_enable_or_query(client, vendor):
    response = client.post(BASE, json={"name": "Bridge", "provider": "rest_webhook", "api_url": "https://bridge.example.test/read",
        "token": "synthetic-bridge-token", "group_ids": ["2"]})
    assert response.status_code == 201 and not response.json()["enabled"], response.text
    path = BASE + "/" + response.json()["id"]
    assert client.post(path + "/notify", json={"expected_revision": 1, "confirm": True}).status_code == 409
    assert not vendor.calls


@pytest.mark.parametrize("provider", ["solarwinds_orion", "rest_webhook"])
@pytest.mark.parametrize("stop", ["source_silence", "source_close", "local_silence", "local_close"])
def test_new_provider_alerts_stop_running_investigation_and_never_restart(client, vendor, monkeypatch, provider, stop):
    configure_investigation_route(client)
    enable(client)
    with SessionLocal() as db:
        db.scalar(select(AlertInvestigationPolicy)).enabled_at -= timedelta(seconds=2)
        db.commit()
    bridge = Bridge()
    bridge.rows["events"][0]["occurred_at"] = utcnow().isoformat()
    if provider == "solarwinds_orion":
        row, path = saved(client)
    else:
        monkeypatch.setattr(service, "BRIDGE_TRANSPORT", lambda *a, **kw: bridge)
        response = client.post(BASE, json={"name": "Bridge", "provider": provider, "api_url": "https://bridge.example.test/read",
            "token": "synthetic-bridge-token", "group_ids": ["2"]})
        assert response.status_code == 201, response.text
        row, path = response.json(), BASE + "/" + response.json()["id"]
    row, path, confirm = enable_mapped_feed(client, row, path)
    with SessionLocal() as db:
        assert dispatch.dispatch_alert_investigations(db) == 1
        execution_id = db.scalar(select(AgentExecution.id))
        alert_id = db.scalar(select(Alert.id))
    headers, assignments = claim(client)
    assert len(assignments) == 1
    base = "/api/v1/agent/executions/" + execution_id
    payload = {"protocol_version": "icheck.agent-runtime/v1", "lease_token": assignments[0]["lease_token"]}
    bootstrap = client.post(base + "/runtime/bootstrap", headers=headers, json=payload)
    assert bootstrap.status_code == 200, bootstrap.text
    if stop == "local_close":
        assert client.post("/api/v1/alerts/" + alert_id + "/resolve", json={"actor": "fixture"}).status_code == 200
    elif stop == "local_silence":
        event = client.get(path + "/external-alerts").json()["items"][0]
        response = client.post(path + "/external-alerts/" + event["id"] + "/silence",
            json={**confirm, "expected_event_checked_at": event["checked_at"]})
        assert response.status_code == 200, response.text
    elif stop == "source_silence":
        vendor.responses["suppression"][0]["SuppressionMode"] = 2
        bridge.rows["events"][0]["suppressed"] = True
    else:
        event = vendor.responses["events"][0]
        event["active_id"] = None
        vendor.responses["recoveries"] = [{"id": 101, "episode": 200, "subject": 300,
            "occurred": event["occurred"], "event_type": 8}]
        bridge.rows["events"][0].update(state="resolved", recovery_id="101", resolved_at=utcnow().isoformat())
    response = client.post(base + "/runtime/reason", headers=headers,
        json={**payload, "operation_id": "0" * 64, "state": bootstrap.json()["initial_state"]})
    assert response.status_code == 409, response.text
    with SessionLocal() as db:
        execution = db.get(AgentExecution, execution_id)
        assert execution.cancellation_requested_at
    completed = client.post(base + "/complete", headers=headers,
        json={"lease_token": payload["lease_token"], "status": "failed", "error": "fixture observed cancellation"})
    assert completed.status_code == 200 and completed.json()["status"] == "cancelled"
    vendor.responses["suppression"][0]["SuppressionMode"] = 0
    bridge.rows["events"][0]["suppressed"] = False
    with SessionLocal() as db:
        assert dispatch.dispatch_alert_investigations(db) == 0
        assert db.get(AgentExecution, execution_id).status == AgentExecutionStatus.CANCELLED
