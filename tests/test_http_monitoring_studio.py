"""Same immutable template from conversation proposal to test/enable/evidence."""
import json
from types import SimpleNamespace
from uuid import uuid4
import pytest
from sqlalchemy import select
from icheck.database import SessionLocal
from icheck.models import Device, DeviceConnection, ArtifactVersion, CollectorDeployment, MetricBackend, utcnow
from icheck.services import monitoring_templates
from test_capability_studio import configure_authoring_route, FakeStructuredOpener
from test_device_preflights import register_worker
from dataclasses import replace
from icheck.auth import current_principal
from icheck.main import app
from icheck.services.control_plane_auth import development_principal


@pytest.fixture(autouse=True)
def human_operator():
    app.dependency_overrides[current_principal] = lambda: replace(development_principal(), principal_type="user", subject="test.admin", auth_method="bearer")
    yield
    app.dependency_overrides.pop(current_principal, None)

SPEC = {"artifact_name": "http-queue", "description": "Collect actual queue depth through the approved HTTP adapter.",
    "metrics": [{"name": "vendor_queue_depth", "type": "gauge", "value_pointer": "/queue/depth"}]}


def draft(client, monkeypatch, *, sample=True, documents=None):
    configure_authoring_route(client)
    opener = FakeStructuredOpener(documents or [SPEC])
    monkeypatch.setattr("icheck.services.structured_model.build_opener", lambda *_: opener)
    payload = {"title": "HTTP queue", "brief": "Monitor the API queue depth every minute through Prometheus.",
        "target_url": "http://198.18.1.10:8080/status", "http_monitoring": {"mode": "api", "schedule_seconds": 60},
        "created_by": "lab.admin"}
    if sample: payload["sample_document"] = {"queue": {"depth": 7}}
    created = client.post("/api/v1/capability-studio/sessions", json=payload)
    assert created.status_code == 201, created.text
    path = "/api/v1/capability-studio/sessions/" + created.json()["id"]
    key = str(uuid4())
    generated = client.post(path + "/generate", json={"actor": "lab.admin", "request_key": key})
    assert generated.status_code == 200, generated.text
    return generated.json(), path, opener, key


def target(client, path, doc):
    response = client.post("/api/v1/assets/devices", json={"name": "API test target", "kind": "other", "management_ip": "198.18.1.10",
        "site": "LAB", "created_by": "lab.admin", "connections": [{"protocol": "https_api"}]})
    assert response.status_code == 201
    device = response.json(); connection = device["connections"][0]
    payload = {"artifact_version_id": doc["artifact_version_id"], "device_id": device["id"], "connection_id": connection["id"],
        "expected_device_revision": device["revision"], "actor": "lab.admin", "reason": "Test this exact template on the selected API."}
    queued = client.post(path + "/monitoring/test", json=payload)
    assert queued.status_code == 200, queued.text
    return queued.json(), payload


def complete(client, state, payload, *, executor=None):
    from icheck.http_metrics import HTTPMonitorSpec, render_result, HTTPResult
    worker, headers = register_worker(client, name="http-studio-worker", site="LAB", capabilities=["http_json"])
    claim = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim", headers=headers, json={"max_assignments": 1, "lease_seconds": 60}).json()[0]
    if executor:
        proof, _ = executor(claim)
    else:
        request = HTTPMonitorSpec.model_validate(claim["configuration"]["http_monitor"])
        _, proof = render_result(request, HTTPResult(b'{"queue":{"depth":7}}', 200, .01, content_type="application/json"))
        proof.update(check="http_metric_query", target_host=claim["target_host"], target_port=claim["port"])
    response = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/{claim['preflight_id']}/complete", headers=headers,
        json={"lease_token": claim["lease_token"], "status": "verified", "evidence": proof})
    assert response.status_code == 200, response.text


def get_state(client, path, payload, **changes):
    return client.get(path + "/monitoring/state", params={key: payload[key] for key in ("artifact_version_id", "device_id", "connection_id")} | changes)


def enable_payload(state, payload):
    return {**payload, "expected_device_revision": state["device_revision"], "preview_hash": state["monitoring"]["preview_hash"],
        "expected_revision": state["monitoring"]["enrollment"]["revision"] if state["monitoring"]["enrollment"] else 0,
        "gateway_profile": "lab-http", "schedule_seconds": 60, "timeout_seconds": 10}


def test_target_search_reaches_beyond_first_page_without_probing(client, monkeypatch):
    doc, path, _, _ = draft(client, monkeypatch)
    with SessionLocal() as db:
        for index in range(105):
            device = Device(name=f"target-{index:03}", kind="other", management_ip=f"198.18.2.{index+1}", site="LAB")
            db.add(device); db.flush()
            db.add(DeviceConnection(device_id=device.id, protocol="https_api", adapter_type="http_json",
                created_by="test", configuration={"private": "must-not-leak"}))
        for index, (name, protocol, enabled, connection_enabled) in enumerate([
            ("target-special%_", "https_api", True, True), ("target-specialXX", "https_api", True, True),
            ("target-disabled", "https_api", False, True), ("target-disabled-connection", "https_api", True, False),
            ("target-wrong-protocol", "snmp", True, True),
        ]):
            device = Device(name=name, kind="other", management_ip=f"198.18.3.{index+1}", site="LAB", enabled=enabled)
            db.add(device); db.flush()
            db.add(DeviceConnection(device_id=device.id, protocol=protocol, adapter_type="http_json",
                created_by="test", enabled=connection_enabled))
        db.commit()
    first = client.get(path + "/monitoring/targets").json()
    assert len(first["targets"]) == 100 and first["has_more"] is True
    assert not any(row["name"] == "target-104" for row in first["targets"])
    for term in ("TARGET-104", "198.18.2.105", "  target-104  "):
        response = client.get(path + "/monitoring/targets", params={"search": term})
        assert response.status_code == 200, response.text
        assert [row["name"] for row in response.json()["targets"]] == ["target-104"]
        assert response.json()["has_more"] is False
        assert "must-not-leak" not in response.text
    literal = client.get(path + "/monitoring/targets", params={"search": "%_"}).json()
    assert [row["name"] for row in literal["targets"]] == ["target-special%_"]
    for term in ("disabled", "wrong-protocol", "missing"):
        assert client.get(path + "/monitoring/targets", params={"search": term}).json()["targets"] == []
    assert client.get(path + "/monitoring/targets", params={"search": "x" * 201}).status_code == 422
    with SessionLocal() as db:
        assert all(row.verification_status == "pending" for row in db.scalars(select(DeviceConnection)))
        scoped = replace(development_principal(), authorization_scope={"sites": ["OTHER"]})
        assert monitoring_templates.target_choices(db, scoped, doc["id"], "target-104")["targets"] == []


def test_http_conversation_creates_same_declarative_artifact_and_replays_model_request(client, monkeypatch):
    doc, path, opener, key = draft(client, monkeypatch)
    assert doc["status"] == "validated" and len(opener.requests) == 1
    replay = client.post(path + "/generate", json={"actor": "lab.admin", "request_key": key})
    assert replay.status_code == 200 and replay.json()["artifact_version_id"] == doc["artifact_version_id"] and len(opener.requests) == 1
    with SessionLocal() as db:
        v = db.get(ArtifactVersion, doc["artifact_version_id"])
        assert v.implementation == {"runtime": "prometheus_gateway_v1", "adapter": "http_metrics"}
        assert v.definition["http_monitor"]["metrics"][0]["value_pointer"] == "/queue/depth"
        assert not v.validation_report["live_target_tested"] and not v.validation_report["continuous_collection_enabled"]
        assert db.scalars(select(CollectorDeployment)).all() == []
    assert client.get("/api/v1/monitoring/targets").json()["targets"] == []


def test_no_sample_is_schema_only_and_cannot_claim_fixture_or_live_success(client, monkeypatch):
    doc, path, opener, key = draft(client, monkeypatch, sample=False)
    report = doc["messages"][-1]["structured_content"]["validation_report"]
    assert report["validation_level"] == "schema" and report["fixture_count"] == 0 and not report["live_target_tested"]
    assert "untested" in doc["messages"][-1]["content"]


def test_selected_target_test_then_single_enable_publishes_and_enrolls_exact_version(client, monkeypatch):
    doc, path, opener, key = draft(client, monkeypatch)
    state, payload = target(client, path, doc)
    assert state["stage"] == "testing" and not state["fresh_samples_verified"]
    assert client.post(path + "/monitoring/enable", json=enable_payload(state, payload)).status_code == 409
    complete(client, state, payload)
    state = get_state(client, path, payload).json()
    assert state["stage"] == "tested_not_enabled"
    enabled = client.post(path + "/monitoring/enable", json=enable_payload(state, payload))
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["stage"] == "enabled_awaiting_fresh_samples" and not enabled.json()["fresh_samples_verified"]
    assert client.get(path).json()["status"] == "published"
    assert client.get("/api/v1/monitoring/targets").json()["targets"][0]["http_monitor"]["metrics"][0]["name"] == "vendor_queue_depth"


def test_invalid_enable_cannot_partially_publish_or_allow_legacy_sql_metric_deployment(client, monkeypatch):
    doc, path, opener, key = draft(client, monkeypatch)
    state, payload = target(client, path, doc); complete(client, state, payload)
    state = get_state(client, path, payload).json()
    bad = client.post(path + "/monitoring/enable", json={**enable_payload(state, payload), "modules": ["if_mib"]})
    assert bad.status_code == 422
    assert client.get(path).json()["status"] == "validated"
    with SessionLocal() as db: assert db.get(ArtifactVersion, doc["artifact_version_id"]).status.value == "validated"
    legacy = client.post("/api/v1/collector-deployments", json={"artifact_version_id": doc["artifact_version_id"],
        "name": "must-not-create-sql-metrics", "target": {"device_id": payload["device_id"], "connection_id": payload["connection_id"]}, "created_by": "lab.admin"})
    assert legacy.status_code == 422 and "SQL" in legacy.text


def test_conversational_revision_changes_immutable_version_and_invalidates_old_test_binding(client, monkeypatch):
    revised = {**SPEC, "artifact_name": "model-must-not-rename", "description": "Revised metric name.",
        "metrics": [{"name": "vendor_queue_depth_new", "type": "gauge", "value_pointer": "/queue/depth"}]}
    doc, path, opener, key = draft(client, monkeypatch, documents=[SPEC, revised])
    state, payload = target(client, path, doc); complete(client, state, payload)
    new = client.post(path + "/messages", json={"actor": "lab.admin", "content": "Rename the queue measurement but keep the same numeric pointer.", "request_key": str(uuid4())})
    assert new.status_code == 200, new.text
    assert new.json()["artifact_version_id"] != doc["artifact_version_id"]
    state = get_state(client, path, {**payload, "artifact_version_id": new.json()["artifact_version_id"]}).json()
    assert state["stage"] == "select_and_test_target" and not state["bound_to_template"]
    with SessionLocal() as db:
        first = db.get(ArtifactVersion, doc["artifact_version_id"]); second = db.get(ArtifactVersion, new.json()["artifact_version_id"])
        assert first.definition["http_monitor"]["metrics"][0]["name"] == "vendor_queue_depth"
        assert second.artifact.name == "http-queue"


def test_stale_target_revision_and_credential_literals_rejected_without_echo(client, monkeypatch):
    doc, path, opener, key = draft(client, monkeypatch)
    state, payload = target(client, path, doc)
    assert client.post(path + "/monitoring/test", json=payload).status_code == 409
    bad = client.post("/api/v1/capability-studio/sessions", json={"title": "HTTP", "brief": "Monitor the selected API endpoint.",
        "target_url": "https://user:private-password@198.18.1.10/status", "http_monitoring": {"mode": "probe"}, "created_by": "lab.admin"})
    assert bad.status_code == 422 and "private-password" not in bad.text
    query_secret = client.post("/api/v1/capability-studio/sessions", json={"title": "HTTP", "brief": "Monitor the selected API endpoint.",
        "target_url": "https://198.18.1.10/status?api_key=private-token-value", "http_monitoring": {"mode": "probe"}, "created_by": "lab.admin"})
    assert query_secret.status_code == 422 and "private-token-value" not in query_secret.text


def collecting(client, monkeypatch):
    doc, path, opener, key = draft(client, monkeypatch)
    state, payload = target(client, path, doc); complete(client, state, payload)
    state = get_state(client, path, payload).json()
    response = client.post(path + "/monitoring/enable", json=enable_payload(state, payload))
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        db.add(MetricBackend(name="template-prometheus", provider="prometheus", query_base_url="https://prometheus.example.test",
            external_labels={}, enabled=True, created_by="test.admin")); db.commit()
    return doc, path, payload, response.json()


def fresh_reader(monkeypatch, payload, state, *, fault=None, before_result=None):
    names = ["vendor_queue_depth", "icheck_http_request_success", "icheck_http_status_code", "icheck_http_request_duration_seconds"]
    stamp = utcnow().timestamp()
    from icheck.database import DEFAULT_TENANT_ID, DEFAULT_REGION_ID
    labels = {"job": "icheck_continuous", "icheck_device_id": payload["device_id"], "icheck_connection_id": payload["connection_id"],
        "icheck_enrollment_id": state["monitoring"]["enrollment"]["id"], "icheck_enrollment_revision": "1",
        "icheck_tenant_id": DEFAULT_TENANT_ID, "icheck_region_id": DEFAULT_REGION_ID}
    def query(db, backend, request, **kwargs):
        if before_result: before_result()
        if request.query.startswith("count by"):
            selected = names[:-1] if fault == "missing" else names
            result = [{"metric": {"__name__": name}, "value": [stamp, "1"]} for name in selected]
        elif request.query.startswith("label_replace"):
            result = [{"metric": {"icheck_metric_name": name}, "value": [stamp, str(stamp - 1000 if fault == "stale" else stamp)]} for name in names]
        else:
            result = [{"metric": {**labels, "icheck_region_id": "foreign" if fault == "foreign" else DEFAULT_REGION_ID},
                "value": [stamp, "0" if fault == "request_failed" else "1"]}]
        return SimpleNamespace(result_type="vector", result=result)
    monkeypatch.setattr("icheck.services.metrics.query_instant", query)


@pytest.mark.parametrize("fault", [None, "missing", "stale", "request_failed", "foreign"])
def test_template_verifies_each_actual_metric_and_freshness_not_exporter_up(client, monkeypatch, fault):
    doc, path, payload, state = collecting(client, monkeypatch)
    fresh_reader(monkeypatch, payload, state, fault=fault)
    response = get_state(client, path, payload, verify_samples="true")
    assert response.status_code == 200, response.text
    assert response.json()["fresh_samples_verified"] is (fault is None)
    assert response.json()["stage"] == ("collecting" if fault is None else "enabled_awaiting_fresh_samples")
    if fault in {None, "stale"}:
        overview = client.get(f"/api/v1/assets/devices/{payload['device_id']}/connections/{payload['connection_id']}/monitoring/measurements")
        assert overview.status_code == 200, overview.text
        assert overview.json()["fresh_samples_verified"] is (fault is None)
        assert overview.json()["metric_evidence"] == response.json()["metric_evidence"]
        assert "template" not in overview.json() and "target_test" not in overview.json()


def test_native_template_unavailable_during_query_discards_evidence_and_targets(client, monkeypatch):
    doc, path, payload, state = collecting(client, monkeypatch)
    changed = False
    def change():
        nonlocal changed
        if changed: return
        changed = True
        with SessionLocal() as db:
            db.get(ArtifactVersion, doc["artifact_version_id"]).status = "draft"; db.commit()
    fresh_reader(monkeypatch, payload, state, before_result=change)
    response = get_state(client, path, payload, verify_samples="true")
    assert response.status_code == 200 and not response.json()["fresh_samples_verified"]
    assert client.get("/api/v1/monitoring/targets").json()["targets"] == []


def test_fresh_template_proposes_one_native_dashboard_and_retains_real_saved_url(client, monkeypatch, tmp_path):
    from icheck.config import get_settings
    from icheck.services import grafana
    from test_grafana_plugin import FakeGrafana
    doc, path, payload, state = collecting(client, monkeypatch)
    fresh_reader(monkeypatch, payload, state)
    key = tmp_path / "grafana.key"; key.write_bytes(b"g" * 32); key.chmod(0o400)
    monkeypatch.setenv("ICHECK_GRAFANA_SECRET_KEY_FILE", str(key)); get_settings.cache_clear()
    fake = FakeGrafana(); fake.metrics = lambda _: ["vendor_queue_depth", "icheck_http_request_success", "icheck_http_request_duration_seconds"]
    monkeypatch.setattr(grafana, "CLIENT", fake)
    try:
        connection = client.post("/api/v1/grafana/connections", json={"name": "template-grafana", "public_url": "https://icheck.test/grafana/",
            "token": "fixture-only-grafana-token", "shared_dataset_acknowledged": True}).json()
        params = {key: payload[key] for key in ("artifact_version_id", "device_id", "connection_id")} | {"grafana_connection_id": connection["id"]}
        proposed = client.post(path + "/monitoring/dashboard-proposal", params=params)
        assert proposed.status_code == 200, proposed.text
        assert fake.writes == [] and proposed.json()["status"] == "proposed"
        repeat = client.post(path + "/monitoring/dashboard-proposal", params=params)
        assert repeat.json()["id"] == proposed.json()["id"]
        before = get_state(client, path, payload).json()
        assert before["grafana_dashboard_url"] is None and before["monitoring"]["currently_authorized"]
        confirmed = client.post(f"/api/v1/grafana/changes/{proposed.json()['id']}/confirm", json={"confirm": True, "expected_plan_hash": proposed.json()["plan_hash"]})
        assert confirmed.status_code == 200, confirmed.text
        after = get_state(client, path, payload).json()
        assert after["grafana_dashboard_url"].startswith("https://icheck.test/grafana/d/icheck-http-")
        assert after["monitoring"]["currently_authorized"] and len(fake.writes) == 1
        assert "fixture-only-grafana-token" not in json.dumps(after)
    finally: get_settings.cache_clear()


def test_http_template_restores_prior_definition_as_new_version_without_source_edits(client, monkeypatch):
    revised = {**SPEC, "metrics": [{"name": "vendor_queue_new", "type": "gauge", "value_pointer": "/queue/depth"}]}
    doc, path, opener, key = draft(client, monkeypatch, documents=[SPEC, revised])
    assert client.post(path + "/publish", json={"actor": "lab.admin", "expected_artifact_version_id": doc["artifact_version_id"]}).status_code == 200
    new = client.post(path + "/messages", json={"actor": "lab.admin", "content": "Use the new queue metric name.", "request_key": str(uuid4())}).json()
    assert client.post(path + "/publish", json={"actor": "lab.admin", "expected_artifact_version_id": new["artifact_version_id"]}).status_code == 200
    restored = client.post(f"/api/v1/artifacts/{doc['artifact_id']}/restore-candidates", json={"source_version": 1, "reason": "Restore the earlier numeric mapping.", "actor": "lab.admin"})
    assert restored.status_code == 201, restored.text
    assert restored.json()["version"] == 3 and restored.json()["definition"]["http_monitor"]["metrics"][0]["name"] == "vendor_queue_depth"
