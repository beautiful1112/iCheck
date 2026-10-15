"""Focused native management checks; no live monitoring targets or model calls."""
from copy import deepcopy
from dataclasses import replace
import json
from uuid import uuid4

import pytest
from sqlalchemy import select
from icheck.auth import current_principal
from icheck.config import get_settings
from icheck.database import SessionLocal, DEFAULT_TENANT_ID, DEFAULT_REGION_ID
from icheck.main import app
from icheck.models import AlertRule, AuditEvent, MetricRuleChange, ControlPlanePrincipal, utcnow
from icheck.alertmanager_runtime import NativeAlertmanager, AlertmanagerUnavailable, configuration_summary, notification_counters
from icheck.services import alertmanager as service
from icheck.services.control_plane_auth import development_principal
from test_preview_alert_workspace import administrator


class FakeAlertmanager:
    base = "http://127.0.0.1:9093"
    def __init__(self):
        self.silences = []; self.alerts = []; self.calls = []; self.lose = False; self.unavailable = False
    def api(self, path, method="GET", body=None):
        self.calls.append((path, method, deepcopy(body)))
        if self.unavailable: raise AlertmanagerUnavailable("Native fixture unavailable")
        if path == "/-/ready": return "OK"
        if path == "/metrics": return 'alertmanager_notifications_total{integration="webhook"} 4\nalertmanager_notifications_failed_total{integration="webhook"} 1\n'
        if path == "/api/v2/status":
            return {"versionInfo": {"version": "0.34.1"}, "config": {"original": """
route:
  receiver: icheck-inbox
  group_by: [icheck_metric_rule_id]
  group_wait: 5s
  routes:
    - receiver: icheck-inbox
      matchers: ['severity="critical"', 'token="do-not-expose"']
receivers:
  - name: icheck-inbox
    webhook_configs:
      - url: https://private.invalid/?token=do-not-expose
        send_resolved: true
        http_config:
          authorization:
            credentials: do-not-expose
"""}}
        if path == "/api/v2/alerts": return deepcopy(self.alerts)
        if path == "/api/v2/silences":
            if method == "GET": return deepcopy(self.silences)
            row = {**deepcopy(body), "startsAt": utcnow().isoformat(), "id": str(uuid4()), "updatedAt": utcnow().isoformat(), "status": {"state": "active"}}
            self.silences.append(row)
            if self.lose: raise AlertmanagerUnavailable("Synthetic response loss")
            return {"silenceID": row["id"]}
        row = next(row for row in self.silences if path.endswith(row["id"]))
        if method == "DELETE":
            row["endsAt"] = utcnow().isoformat(); row["status"] = {"state": "expired"}
            if self.lose: raise AlertmanagerUnavailable("Synthetic response loss")
            return None
        return deepcopy(row)


@pytest.fixture
def managed(client, administrator, monkeypatch):
    client.headers.update(administrator)
    for key, value in {"METRIC_ALERTMANAGER_URL": "http://127.0.0.1:9093", "METRIC_RULE_BACKEND_ID": str(uuid4()),
        "METRIC_RULE_TENANT_ID": DEFAULT_TENANT_ID, "METRIC_RULE_REGION_ID": DEFAULT_REGION_ID,
        "METRIC_ALERT_WEBHOOK_SUBJECT": "fixture.alertmanager"}.items(): monkeypatch.setenv("ICHECK_" + key, value)
    get_settings.cache_clear()
    rule_id, device_id = str(uuid4()), str(uuid4())
    labels = {"icheck_tenant_id": DEFAULT_TENANT_ID, "icheck_region_id": DEFAULT_REGION_ID,
        "icheck_metric_rule_id": rule_id, "icheck_metric_rule_revision": "1"}
    compiled = {"alert": "fixture_alert", "labels": labels, "annotations": {"dashboard_url": "/grafana/d/fixture", "investigation_url": "/?brief=Inspect"}}
    with SessionLocal() as db:
        db.add(AlertRule(id=rule_id, name="Fixture threshold", event_type="metric.prometheus", severity="warning", enabled=True,
            conditions={"revision": 1, "compiled_rule": compiled})); db.flush()
        db.add(MetricRuleChange(rule_id=rule_id, expected_revision=0, definition={"name": "Fixture threshold", "severity": "warning"},
            target_snapshot={"device_id": device_id}, backend_revision=1, compiled_rule=compiled, catalog_before={}, catalog_after={},
            runtime_before_hash="a" * 64, runtime_binding={}, plan_hash="b" * 64, status="applied", created_by="fixture", applied_at=utcnow()))
        db.add(AuditEvent(event_type="metric_rule.notification.received", actor_type="service", actor_id="fixture", entity_type="alertmanager_receiver",
            entity_id="icheck-inbox", details={"alert_count": 1, "episodes": []})); db.commit()
    fake = FakeAlertmanager()
    fake.alerts = [{"labels": {"alertname": "fixture_alert", **labels}, "annotations": {"summary": "untrusted", "url": "do-not-expose"},
        "startsAt": utcnow().isoformat(), "status": {"state": "suppressed", "silencedBy": [str(uuid4())], "inhibitedBy": []},
        "receivers": [{"name": "icheck-inbox"}]}]
    def runtime(actor):
        NativeAlertmanager(actor)  # Real endpoint/namespace guard, mocked wire only.
        return fake
    monkeypatch.setattr(service, "CLIENT", runtime)
    yield fake, {"request_key": str(uuid4()), "confirm": True, "rule_id": rule_id, "expected_revision": 1,
        "duration_minutes": 30, "reason": "Approved maintenance window"}
    app.dependency_overrides.pop(current_principal, None)
    get_settings.cache_clear()


def overview(client):
    response = client.get("/api/v1/alertmanager/overview")
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def test_readiness_routing_delivery_history_and_safe_alert_projection(client, managed):
    fake, payload = managed
    fake.alerts.append({**deepcopy(fake.alerts[0]), "labels": {"icheck_tenant_id": "another-tenant"}})
    body = overview(client)
    assert body["ready"] and body["version"] == "0.34.1"
    assert len(body["alerts"]) == 1 and body["alerts"][0]["name"] == "Fixture threshold"
    assert body["alerts"][0]["silenced_count"] == 1
    assert len(body["routes"]) == 2 and len(body["receivers"]) == 1
    assert "do-not-expose" not in json.dumps(body) and "private.invalid" not in json.dumps(body)
    assert body["delivery_history"][0]["alert_count"] == 1
    assert body["counters"] == [{"integration": "webhook", "attempts": 4.0, "failures": 1.0}]
    fake.unavailable = True
    body = overview(client)
    assert not body["ready"] and body["diagnostics"] and len(body["delivery_history"]) == 1


def test_reviewed_create_replay_conflict_and_expire(client, managed):
    fake, payload = managed
    created = client.post("/api/v1/alertmanager/silences", json=payload)
    assert created.status_code == 200, created.text
    assert created.json()["status"] == "confirmed"
    assert len(fake.silences) == 1
    assert service.exact_matchers(fake.silences[0]) == {"icheck_tenant_id": DEFAULT_TENANT_ID, "icheck_region_id": DEFAULT_REGION_ID,
        "icheck_metric_rule_id": payload["rule_id"], "icheck_metric_rule_revision": "1"}
    assert client.post("/api/v1/alertmanager/silences", json=payload).json() == created.json()
    assert len(fake.silences) == 1
    assert client.post("/api/v1/alertmanager/silences", json={**payload, "duration_minutes": 60}).status_code == 409
    view = overview(client)["silences"][0]
    end = {"request_key": str(uuid4()), "confirm": True, "expected_fingerprint": view["fingerprint"]}
    expired = client.post(f"/api/v1/alertmanager/silences/{view['id']}/expire", json=end)
    assert expired.status_code == 200 and expired.json()["status"] == "confirmed", expired.text
    assert client.post(f"/api/v1/alertmanager/silences/{view['id']}/expire", json=end).json() == expired.json()
    assert sum(method == "DELETE" for _, method, _ in fake.calls) == 1
    assert overview(client)["silences"][0]["state"] == "expired"
    with SessionLocal() as db:
        rows = db.scalars(select(AuditEvent).where(AuditEvent.event_type.in_([service.REQUEST, service.COMPLETE]))).all()
        assert len(rows) == 4


def test_response_loss_inspects_without_repeating_native_mutation(client, managed):
    fake, payload = managed; fake.lose = True
    lost = client.post("/api/v1/alertmanager/silences", json=payload)
    assert lost.status_code == 200 and lost.json()["status"] == "unconfirmed", lost.text
    recovered = client.post("/api/v1/alertmanager/requests/" + lost.json()["id"] + "/inspect")
    assert recovered.status_code == 200 and recovered.json()["status"] == "confirmed", recovered.text
    assert len(fake.silences) == 1
    assert sum(method == "POST" for _, method, _ in fake.calls) == 1


def test_unknown_outcome_without_remote_match_stays_unknown(client, managed):
    fake, payload = managed; fake.lose = True
    lost = client.post("/api/v1/alertmanager/silences", json=payload).json()
    fake.silences.clear()
    assert client.post("/api/v1/alertmanager/silences", json=payload).json()["status"] == "unconfirmed"
    assert sum(method == "POST" for _, method, _ in fake.calls) == 1
    assert lost["status"] == "unconfirmed"


@pytest.mark.parametrize("fault", ["stale_rule", "no_confirmation", "too_long", "extra_matcher", "cross_namespace", "scoped_actor"])
def test_unreviewed_silence_never_reaches_native_write(client, managed, fault):
    fake, payload = managed
    if fault == "stale_rule": payload["expected_revision"] = 2
    elif fault == "no_confirmation": payload["confirm"] = False
    elif fault == "too_long": payload["duration_minutes"] = 1441
    elif fault == "extra_matcher": payload["matchers"] = [{"name": "alertname", "value": ".*", "isRegex": True}]
    else:
        actor = development_principal()
        if fault == "cross_namespace": actor = replace(actor, tenant_id="another-tenant")
        else: actor = replace(actor, authorization_scope={"device_ids": [str(uuid4())]})
        app.dependency_overrides[current_principal] = lambda: actor
    response = client.post("/api/v1/alertmanager/silences", json=payload)
    assert response.status_code in {403, 409, 422}, response.text
    assert not fake.silences


def test_current_disabled_human_cannot_silence_with_stale_identity(client, managed):
    fake, payload = managed
    with SessionLocal() as db:
        db.scalar(select(ControlPlanePrincipal).where(ControlPlanePrincipal.principal_type == "user")).enabled = False
        db.commit()
    assert client.post("/api/v1/alertmanager/silences", json=payload).status_code in {401, 403}
    assert not fake.silences


def test_native_address_and_yaml_aliases_fail_closed(monkeypatch):
    actor = development_principal()
    monkeypatch.setenv("ICHECK_METRIC_RULE_BACKEND_ID", "fixture")
    monkeypatch.setenv("ICHECK_METRIC_RULE_TENANT_ID", actor.tenant_id)
    monkeypatch.setenv("ICHECK_METRIC_RULE_REGION_ID", actor.region_id)
    for value in ("http://localhost:9093", "https://127.0.0.1:9093", "http://127.0.0.1:9093/?secret=x", "http://198.18.0.1:9093", "http://user:pass@127.0.0.1:9093"):
        monkeypatch.setenv("ICHECK_METRIC_ALERTMANAGER_URL", value); get_settings.cache_clear()
        with pytest.raises(AlertmanagerUnavailable): NativeAlertmanager(actor)
    with pytest.raises(ValueError): configuration_summary("route: &loop {routes: [*loop]}")
    with pytest.raises(ValueError): notification_counters("alertmanager_notifications_total NaN\n")
    get_settings.cache_clear()


def test_uncertain_request_cannot_be_confirmed_against_changed_runtime(client, managed):
    fake, payload = managed; fake.lose = True
    lost = client.post("/api/v1/alertmanager/silences", json=payload).json()
    fake.base = "http://127.0.0.1:19093"
    assert client.post("/api/v1/alertmanager/requests/" + lost["id"] + "/inspect").status_code == 409
    assert sum(method == "POST" for _, method, _ in fake.calls) == 1


def test_changed_silence_and_other_workspace_cannot_be_expired(client, managed):
    fake, payload = managed
    assert client.post("/api/v1/alertmanager/silences", json=payload).json()["status"] == "confirmed"
    view = overview(client)["silences"][0]
    body = {"request_key": str(uuid4()), "confirm": True, "expected_fingerprint": view["fingerprint"]}
    fake.silences[0]["comment"] = "A different maintenance window"
    assert client.post(f"/api/v1/alertmanager/silences/{view['id']}/expire", json=body).status_code == 409
    fake.silences[0]["matchers"][0]["value"] = "another-tenant"
    body["expected_fingerprint"] = service.fingerprint(fake.silences[0])
    assert client.post(f"/api/v1/alertmanager/silences/{view['id']}/expire", json=body).status_code == 409
    assert not overview(client)["silences"]
    assert not any(method == "DELETE" for _, method, _ in fake.calls)


def test_private_native_silence_protocol(client, managed, monkeypatch, tmp_path):
    """Real native API on a disposable loopback server; no alerts or receivers."""
    import os
    from pathlib import Path
    import socket
    import subprocess
    import time
    binary = os.environ.get("ICHECK_METRIC_ALERT_TEST_ALERTMANAGER_BINARY")
    if not binary:
        pytest.skip("Explicit native binary required for isolated silence protocol qualification")
    assert Path(binary).is_file()
    with socket.socket() as handle:
        handle.bind(("127.0.0.1", 0)); port = handle.getsockname()[1]
    config = tmp_path / "alertmanager.json"
    config.write_text(json.dumps({"route": {"receiver": "no-delivery"}, "receivers": [{"name": "no-delivery"}]}))
    monkeypatch.setenv("ICHECK_METRIC_ALERTMANAGER_URL", f"http://127.0.0.1:{port}")
    get_settings.cache_clear()
    monkeypatch.setattr(service, "CLIENT", NativeAlertmanager)
    process = subprocess.Popen([binary, "--config.file=" + str(config), "--storage.path=" + str(tmp_path / "storage"),
        f"--web.listen-address=127.0.0.1:{port}", "--cluster.listen-address="], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        runtime = NativeAlertmanager(development_principal())
        for _ in range(60):
            assert process.poll() is None
            try:
                runtime.api("/-/ready"); break
            except AlertmanagerUnavailable: time.sleep(.1)
        else: pytest.fail("Isolated Alertmanager did not become ready")
        _, payload = managed
        created = client.post("/api/v1/alertmanager/silences", json=payload)
        assert created.status_code == 200 and created.json()["status"] == "confirmed", created.text
        assert client.post("/api/v1/alertmanager/silences", json=payload).json() == created.json()
        assert len(runtime.api("/api/v2/silences")) == 1
        observed = overview(client)
        assert observed["ready"] and not observed["diagnostics"] and not observed["alerts"]
        silence = observed["silences"][0]
        assert silence["state"] == "active"
        expired = client.post(f"/api/v1/alertmanager/silences/{silence['id']}/expire", json={
            "request_key": str(uuid4()), "confirm": True, "expected_fingerprint": silence["fingerprint"]})
        assert expired.status_code == 200 and expired.json()["status"] == "confirmed", expired.text
        assert overview(client)["silences"][0]["state"] == "expired"
    finally:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
