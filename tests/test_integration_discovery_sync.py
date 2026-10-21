"""Synthetic group discovery and durable inventory synchronization; no network."""
from dataclasses import replace
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from icheck.auth import current_principal
from icheck.database import SessionLocal, set_session_namespace, DEFAULT_TENANT_ID, DEFAULT_REGION_ID
from icheck.integration_schemas import SyncStep
from icheck.main import app
from icheck.models import (MonitoringIntegrationResource as Resource, MonitoringIntegrationSync as Sync,
                           Device, DeviceMonitoringEnrollment, AuditEvent)
from icheck.monitoring_connectors.zabbix import ConnectorError
from icheck.services import monitoring_integrations as service
from icheck.services.control_plane_auth import development_principal
from test_monitoring_integrations import protected_configuration, saved, create, BASE, TOKEN


@pytest.fixture
def source(monkeypatch, protected_configuration):
    class Fake:
        hosts = [str(n) for n in range(100, 601)]
        groups = [{"groupid": "1", "name": "Network"}, {"groupid": "2", "name": "Linux"}]
        calls = []
        missing = set()
        failing = False
        outside_scope = False
        wrong_id = False

        def __init__(self, endpoint, token, *, budget_seconds):
            assert token == TOKEN

        def request(self, payload, **bounds):
            Fake.calls.append(payload)
            assert bounds["max_response_bytes"] == 2_000_000
            if self.failing:
                raise ConnectorError("source_timeout")
            method, params = payload["method"], payload["params"]
            if method == "apiinfo.version":
                result = "7.4.2"
            elif method == "hostgroup.get":
                result = [g for g in self.groups if params.get("search", {}).get("name", "") in g["name"]][:params["limit"]]
            elif params["output"] == ["hostid"]:
                assert "hostid_from" not in params and params["groupids"]
                result = [{"hostid": i} for i in self.hosts[:params["limit"]]]
            else:
                ids = params.get("hostids", self.hosts[:params["limit"]])
                result = [{"hostid": "999999" if self.wrong_id else i, "host": "fixture", "name": "Device " + i,
                    "status": "0", "hostgroups": [{"groupid": "99" if self.outside_scope else "1"}]}
                    for i in ids if i not in self.missing]
            return {"jsonrpc": "2.0", "id": payload["id"], "result": result}
    monkeypatch.setattr(service, "TRANSPORT", Fake)
    return Fake


def enabled(client):
    row = saved(client)
    result = client.put(BASE + "/" + row["id"], json={"expected_revision": 1, "enabled": True})
    assert result.status_code == 200, result.text
    return result.json()


def start(client, row):
    response = client.post(f"{BASE}/{row['id']}/syncs", json={"expected_revision": row["revision"], "confirm": True})
    assert response.status_code == 200, response.text
    return response.json()


def step(client, row, run):
    response = client.post(f"{BASE}/{row['id']}/syncs/{run['id']}/step", json={
        "expected_revision": row["revision"], "expected_cursor": run["cursor"], "confirm": True})
    assert response.status_code == 200, response.text
    return response.json()


def test_setup_without_group_scope_never_means_query_all(client, source):
    row = create(client, group_ids=[]).json()
    path = BASE + "/" + row["id"]
    consent = {"expected_revision": 1, "confirm": True}
    assert client.post(path + "/preview", json=consent).status_code == 422
    assert client.post(path + "/test", json=consent).status_code == 422
    assert client.put(path, json={"expected_revision": 1, "enabled": True}).status_code == 422
    assert source.calls == []
    result = client.post(path + "/groups", json={**consent, "search": "Net"})
    assert result.json() == {"items": [{"id": "1", "name": "Network"}], "truncated": False}
    assert [c["method"] for c in source.calls] == ["apiinfo.version", "hostgroup.get"]
    assert client.get(path).json()["group_ids"] == []


def test_preview_is_scoped_bounded_and_non_mutating(client, source):
    row = saved(client)
    response = client.post(f"{BASE}/{row['id']}/preview", json={"expected_revision": 1, "confirm": True})
    assert response.status_code == 200, response.text
    assert len(response.json()["items"]) == 20 and response.json()["truncated"]
    with SessionLocal() as db:
        for model in (Resource, Sync, Device, DeviceMonitoringEnrollment):
            assert db.scalar(select(func.count()).select_from(model)) == 0


def test_sync_resumes_across_requests_and_never_enrolls_native_polling(client, source):
    row = enabled(client)
    run = start(client, row)
    assert run["total"] == 501 and run["cursor"] == 0 and run["can_resume"]
    assert "host_ids" not in run
    calls = len(source.calls)
    assert start(client, row)["id"] == run["id"] and len(source.calls) == calls
    first = step(client, row, run)
    assert first["cursor"] == first["observed"] == 250
    history = client.get(f"{BASE}/{row['id']}/syncs").json()
    assert history[0] == first
    second = step(client, row, history[0])
    final = step(client, row, second)
    assert final["status"] == "completed" and final["cursor"] == final["observed"] == 501 and not final["can_resume"]
    result = client.get(f"{BASE}/{row['id']}/resources?limit=100&offset=500").json()
    assert result["total"] == 501 and len(result["items"]) == 1 and result["items"][0]["health"] == "unknown"
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Device)) == 0
        assert db.scalar(select(func.count()).select_from(DeviceMonitoringEnrollment)) == 0
        assert db.scalar(select(func.count()).select_from(Resource)) == 501


def test_repeated_cursor_and_revision_cannot_advance_twice(client, source):
    row = enabled(client)
    run = start(client, row)
    step(client, row, run)
    calls = len(source.calls)
    path = f"{BASE}/{row['id']}/syncs/{run['id']}/step"
    assert client.post(path, json={"expected_revision": 2, "expected_cursor": 0, "confirm": True}).status_code == 409
    assert client.post(path, json={"expected_revision": 1, "expected_cursor": 250, "confirm": True}).status_code == 409
    assert len(source.calls) == calls


def test_failed_page_preserves_cursor_and_can_retry(client, source):
    row = enabled(client)
    first = step(client, row, start(client, row))
    source.failing = True
    failed = step(client, row, first)
    assert failed["status"] == "failed" and failed["cursor"] == failed["observed"] == 250 and failed["can_resume"]
    assert client.get(f"{BASE}/{row['id']}/resources").json()["total"] == 250
    source.failing = False
    assert step(client, row, failed)["cursor"] == 500


def test_missing_or_empty_source_results_never_delete_inventory(client, source):
    source.hosts = ["100", "101"]
    row = enabled(client)
    first = step(client, row, start(client, row))
    source.missing = {"101"}
    second = step(client, row, start(client, row))
    assert second["observed"] == 1 and second["total"] == 2 and second["status"] == "completed"
    rows = client.get(f"{BASE}/{row['id']}/resources").json()["items"]
    assert {item["remote_id"]: item["last_run_id"] for item in rows} == {"100": second["id"], "101": first["id"]}
    source.hosts = []
    empty = start(client, row)
    assert empty["status"] == "completed" and empty["total"] == 0
    assert client.get(f"{BASE}/{row['id']}/resources").json()["total"] == 2


@pytest.mark.parametrize("change", [{"enabled": False}, {"enabled": True, "group_ids": ["2"]}])
def test_reconfiguration_supersedes_progress_and_hides_old_scope(client, source, change):
    row = enabled(client)
    run = step(client, row, start(client, row))
    path = f"{BASE}/{row['id']}"
    assert client.put(path, json={"expected_revision": 2, **change}).status_code == 200
    assert client.get(path + "/syncs").json()[0]["status"] == "superseded"
    assert client.get(path + "/resources").json()["total"] == 0
    assert client.post(path + f"/syncs/{run['id']}/step", json={"expected_revision": 3, "expected_cursor": 250, "confirm": True}).status_code == 409
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 250


@pytest.mark.parametrize("flag", ["outside_scope", "wrong_id"])
def test_scope_mismatch_is_not_partially_imported(client, source, flag):
    row = enabled(client)
    run = start(client, row)
    setattr(source, flag, True)
    failed = step(client, row, run)
    assert failed["status"] == "failed" and failed["cursor"] == 0
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 0


def test_large_scope_is_explicitly_rejected_not_silently_truncated(client, source):
    source.hosts = [str(i) for i in range(1, 10002)]
    row = enabled(client)
    failed = start(client, row)
    assert failed["status"] == "failed" and failed["error_code"] == "source_scope_too_large"
    assert not failed["can_resume"]


def test_resource_identity_is_per_connection_and_upsert_is_idempotent(client, source):
    source.hosts = ["100"]
    first = enabled(client)
    second = create(client, name="Second source").json()
    second = client.put(f"{BASE}/{second['id']}", json={"expected_revision": 1, "enabled": True}).json()
    for row in (first, first, second):
        step(client, row, start(client, row))
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 2


def test_failed_commit_does_not_advance_cursor_or_save_partial_batch(client, source, monkeypatch):
    source.hosts = ["100"]
    row = enabled(client)
    run = start(client, row)
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        def fail():
            db.flush()
            raise RuntimeError("simulated interruption")
        monkeypatch.setattr(db, "commit", fail)
        with pytest.raises(RuntimeError, match="simulated"):
            service.sync_step(db, row["id"], run["id"], SyncStep(expected_revision=2, expected_cursor=0, confirm=True), development_principal())
        db.rollback()
    assert client.get(f"{BASE}/{row['id']}/syncs").json()[0]["cursor"] == 0
    assert client.get(f"{BASE}/{row['id']}/resources").json()["total"] == 0


@pytest.mark.parametrize("scope", [{"sites": ["LAB"]}, {"all": True}])
def test_readers_cannot_trigger_source_calls(client, source, scope):
    row = enabled(client)
    principal = replace(development_principal(), permissions=frozenset({"metrics.read"}), authorization_scope=scope)
    app.dependency_overrides[current_principal] = lambda: principal
    for suffix in ("groups", "preview", "syncs"):
        assert client.post(f"{BASE}/{row['id']}/{suffix}", json={"expected_revision": 2, "confirm": True}).status_code == 403
    assert client.get(f"{BASE}/{row['id']}/resources").status_code == (200 if scope.get("all") else 403)
    assert source.calls == []


def test_foreign_run_id_and_disabled_connection_fail_before_source_contact(client, source):
    row = saved(client)
    assert client.post(f"{BASE}/{row['id']}/syncs", json={"expected_revision": 1, "confirm": True}).status_code == 409
    row = client.put(f"{BASE}/{row['id']}", json={"expected_revision": 1, "enabled": True}).json()
    assert client.post(f"{BASE}/{row['id']}/syncs/{uuid4()}/step", json={"expected_revision": 2, "expected_cursor": 0, "confirm": True}).status_code == 404
    assert source.calls == []
