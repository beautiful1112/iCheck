"""Saved integration configuration is not polling or device enrollment."""
from dataclasses import replace
import json
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from icheck.auth import current_principal
from icheck.config import get_settings
from icheck.database import SessionLocal, set_session_namespace
from icheck import integration_custody as custody
from icheck.main import app
from icheck.models import (AuditEvent, Device, MonitoringIntegrationConnection as Connection,
                           Region, Tenant)
from icheck.monitoring_connectors.zabbix import ConnectorError
from icheck.services import monitoring_integrations as service
from icheck.services.control_plane_auth import development_principal

BASE = "/api/v1/integrations/connections"
TOKEN = "fixture-only-zabbix-token"


@pytest.fixture(autouse=True)
def protected_configuration(monkeypatch):
    monkeypatch.setenv("ICHECK_MONITORING_INTEGRATION_ALLOWED_ORIGINS", "https://zabbix.example.test")
    get_settings.cache_clear()
    monkeypatch.setattr(custody, "key", lambda: b"k" * 32)
    monkeypatch.setattr(service, "TRANSPORT", lambda *a, **k: pytest.fail("Unexpected connection test"))
    yield
    app.dependency_overrides.pop(current_principal, None)
    get_settings.cache_clear()


def create(client, **updates):
    return client.post(BASE, json={"name": "Branch Zabbix", "api_url": "https://zabbix.example.test/zabbix",
                                  "group_ids": ["2", "1", "2"], "token": TOKEN, **updates})


def saved(client):
    response = create(client)
    assert response.status_code == 201, response.text
    return response.json()


def test_saved_disabled_encrypted_and_reads_are_redacted(client):
    row = saved(client)
    assert not row["enabled"] and row["revision"] == 1 and row["token_configured"]
    assert row["synchronization"] == "manual_and_scheduled" and row["last_test_status"] is None
    assert row["group_ids"] == ["1", "2"]
    assert row["api_url"] == "https://zabbix.example.test/zabbix/api_jsonrpc.php"
    for path in (BASE, BASE + "/" + row["id"]):
        response = client.get(path)
        assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
        assert TOKEN not in response.text and "encrypted_token" not in response.text
    with SessionLocal() as db:
        stored = db.get(Connection, row["id"])
        assert TOKEN.encode() not in stored.encrypted_token and custody.decrypt_token(stored) == TOKEN
        assert db.scalar(select(func.count()).select_from(Device)) == 0
        audits = db.scalars(select(AuditEvent).where(AuditEvent.entity_id == row["id"])).all()
        assert len(audits) == 1 and TOKEN not in json.dumps(audits[0].details)


def test_updates_are_revision_guarded_and_not_polling(client):
    row = saved(client)
    path = BASE + "/" + row["id"]
    body = {"expected_revision": 1, "enabled": True, "name": "Updated", "group_ids": ["3"]}
    response = client.put(path, json=body)
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["revision"] == 2 and updated["enabled"] and updated["group_ids"] == ["3"]
    assert updated["last_test_status"] is None
    assert client.put(path, json=body).status_code == 409
    assert client.post(path + "/test", json={"expected_revision": 1, "confirm": True}).status_code == 409
    assert client.put(path, json={"expected_revision": 2, "enabled": False,
                                  "api_url": "https://other.example.test"}).status_code == 422
    assert client.get(path).json()["revision"] == 2


def test_custody_rotation_and_binding(client):
    row = saved(client)
    path = BASE + "/" + row["id"]
    with SessionLocal() as db:
        old = db.get(Connection, row["id"]).encrypted_token
    rotated = "replacement-fixture-only-token"
    assert client.put(path, json={"expected_revision": 1, "enabled": False, "token": rotated}).status_code == 200
    with SessionLocal() as db:
        stored = db.get(Connection, row["id"])
        assert stored.encrypted_token != old and custody.decrypt_token(stored) == rotated
        for field, value in (("id", str(uuid4())), ("tenant_id", str(uuid4())), ("region_id", str(uuid4())),
                             ("provider", "other"), ("api_url", "https://other.example.test/api_jsonrpc.php")):
            original = getattr(stored, field)
            setattr(stored, field, value)
            with pytest.raises(custody.IntegrationCustodyUnavailable):
                custody.decrypt_token(stored)
            setattr(stored, field, original)


def test_disable_and_read_work_even_when_key_or_allowlist_unavailable(client, monkeypatch):
    row = saved(client)
    path = BASE + "/" + row["id"]
    def unavailable():
        raise custody.IntegrationCustodyUnavailable("Protected integration key storage is unavailable")
    monkeypatch.setattr(custody, "key", unavailable)
    monkeypatch.setenv("ICHECK_MONITORING_INTEGRATION_ALLOWED_ORIGINS", "")
    get_settings.cache_clear()
    assert client.put(path, json={"expected_revision": 1, "enabled": False}).status_code == 200
    assert client.get(path).status_code == 200
    assert client.post(path + "/test", json={"expected_revision": 2, "confirm": True}).status_code == 503


def test_connection_names_unique_only_within_namespace_and_pagination(client):
    row = saved(client)
    assert create(client).status_code == 409
    assert create(client, name="Another source").status_code == 201
    pages = [client.get(BASE, params={"limit": 1, "offset": index}).json() for index in range(3)]
    assert [len(page) for page in pages] == [1, 1, 0]
    assert pages[0][0]["id"] != pages[1][0]["id"]
    assert row["id"] in {page[0]["id"] for page in pages[:2]}
    assert client.get(BASE, params={"limit": 101}).status_code == 422


@pytest.mark.parametrize("overrides", [
    {"token": "short"}, {"token": "a\r\nAuthorization: secret"}, {"token": "invalid space " * 2},
    {"name": TOKEN}, {"name": "bad\nname"}, {"api_url": "https://other.example.test"},
    {"api_url": f"https://zabbix.example.test/{TOKEN}"}, {"password": TOKEN},
    {"group_ids": ["0"]}, {"group_ids": ["18446744073709551616"]},
    {"group_ids": [2]}, {"enabled": True}, {"provider": "solarwinds_orion"},
])
def test_invalid_configuration_and_secrets_never_echo(client, overrides):
    response = create(client, **overrides)
    assert response.status_code == 422
    assert TOKEN not in response.text and "Authorization: secret" not in response.text
    assert response.headers["Cache-Control"] == "no-store"
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Connection)) == 0


@pytest.mark.parametrize("principal", [
    replace(development_principal(), permissions=frozenset()),
    replace(development_principal(), permissions=frozenset({"metrics.manage"})),
    replace(development_principal(), authorization_scope={"sites": ["LAB"]}),
    replace(development_principal(), principal_type="service", auth_method="bearer"),
])
def test_connection_mutations_require_global_human_authority(client, principal):
    row = saved(client)
    app.dependency_overrides[current_principal] = lambda: principal
    assert create(client, name="Other source").status_code == 403
    assert client.put(BASE + "/" + row["id"], json={"expected_revision": 1, "enabled": True}).status_code == 403
    assert client.post(BASE + "/" + row["id"] + "/test", json={"expected_revision": 1, "confirm": True}).status_code == 403
    if principal.principal_type != "service":
        assert client.get(BASE).status_code == 403


def test_read_only_principal_can_inspect_but_not_change_or_test(client):
    row = saved(client)
    principal = replace(development_principal(), permissions=frozenset({"metrics.read"}))
    app.dependency_overrides[current_principal] = lambda: principal
    path = BASE + "/" + row["id"]
    assert client.get(BASE).status_code == 200
    assert client.get(path).status_code == 200
    assert create(client, name="Read only").status_code == 403
    assert client.put(path, json={"expected_revision": 1, "enabled": True}).status_code == 403
    assert client.post(path + "/test", json={"expected_revision": 1, "confirm": True}).status_code == 403


def test_connections_require_authentication(client, monkeypatch):
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    assert client.get(BASE).status_code == 401
    assert create(client).status_code == 401


def test_connection_identity_cannot_cross_workspaces(client):
    own = saved(client)
    principal = development_principal()
    tenant, region, foreign_id = str(uuid4()), str(uuid4()), str(uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant, tenant_id=tenant, region_id=region, slug="foreign", name="Foreign",
                      default_region_id=region, created_by="fixture"))
        db.add(Region(id=region, tenant_id=tenant, region_id=region, code="foreign", name="Foreign", created_by="fixture"))
        db.add(Connection(id=foreign_id, tenant_id=tenant, region_id=region, name=own["name"], provider="zabbix",
                          api_url=own["api_url"], group_ids=["1"], encrypted_token=b"not-a-real-token", created_by="fixture"))
        db.commit()
        set_session_namespace(db, tenant, region)
        other = replace(principal, tenant_id=tenant, region_id=region)
        assert [row.id for row in service.listing(db, other)] == [foreign_id]
        with pytest.raises(LookupError):
            service.connection(db, own["id"], other)
        with pytest.raises(PermissionError):
            service.listing(db, principal)
    assert client.get(BASE + "/" + foreign_id).status_code == 404
    assert client.put(BASE + "/" + foreign_id, json={"expected_revision": 1, "enabled": True}).status_code == 404
    assert client.post(BASE + "/" + foreign_id + "/test", json={"expected_revision": 1, "confirm": True}).status_code == 404
    assert [row["id"] for row in client.get(BASE).json()] == [own["id"]]


@pytest.mark.parametrize("mode", ["success", "empty", "truncated", "rejected", "secret_error"])
def test_explicit_bounded_test_records_evidence_without_starting_monitoring(client, monkeypatch, mode):
    row = saved(client)
    calls = []
    class Fake:
        def __init__(self, endpoint, token, *, budget_seconds):
            assert endpoint == row["api_url"] and token == TOKEN and budget_seconds == 30

        def request(self, payload, *, timeout_seconds, max_response_bytes):
            calls.append(payload)
            assert timeout_seconds == 10 and max_response_bytes == 2_000_000
            if mode in {"rejected", "secret_error"}:
                raise ConnectorError("source_tls_failed" if mode == "rejected" else TOKEN)
            if payload["method"] == "apiinfo.version":
                result = "7.4.2"
            else:
                assert payload["method"] == "host.get"
                assert payload["params"]["groupids"] == ["1", "2"] and payload["params"]["limit"] == 21
                count = {"success": 1, "empty": 0, "truncated": 21}[mode]
                result = [{"hostid": str(100 + index), "name": "Fixture", "host": "fixture", "status": "0",
                           "hostgroups": [{"groupid": "1"}]} for index in range(count)]
            return {"jsonrpc": "2.0", "id": payload["id"], "result": result}
    monkeypatch.setattr(service, "TRANSPORT", Fake)
    path = BASE + "/" + row["id"]
    for confirm in (None, False, "true", 1):
        assert client.post(path + "/test", json={"expected_revision": 1, "confirm": confirm}).status_code == 422
    assert calls == []
    response = client.post(path + "/test", json={"expected_revision": 1, "confirm": True})
    assert response.status_code == 200, response.text
    result = response.json()
    assert TOKEN not in response.text
    assert "no resource enrollment" in result["meaning"]
    failed = mode in {"rejected", "secret_error"}
    assert result["status"] == ("failed" if failed else "succeeded")
    if not failed:
        assert result["resource_count"] == {"empty": 0, "success": 1, "truncated": 20}[mode]
        assert result["truncated"] == (mode == "truncated")
    else:
        assert result["error_code"] == ("source_tls_failed" if mode == "rejected" else "source_unavailable")
    read = client.get(path).json()
    assert not read["enabled"] and read["revision"] == 1 and read["last_test_revision"] == 1
    assert read["last_test_status"] == result["status"]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Device)) == 0
        audits = db.scalars(select(AuditEvent).where(AuditEvent.entity_id == row["id"])).all()
        assert len(audits) == 2 and TOKEN not in json.dumps([audit.details for audit in audits])
    updated = client.put(path, json={"expected_revision": 1, "enabled": False, "group_ids": ["5"]}).json()
    assert updated["last_test_at"] is None and updated["last_test_status"] is None


def test_missing_key_cannot_save_plaintext(client, monkeypatch):
    def unavailable():
        raise custody.IntegrationCustodyUnavailable("Protected integration key storage is unavailable")
    monkeypatch.setattr(custody, "key", unavailable)
    assert create(client).status_code == 503
    assert client.get(BASE).json() == []


def test_rotation_cannot_reflect_the_previous_token_in_metadata(client):
    row = saved(client)
    response = client.put(BASE + "/" + row["id"], json={"expected_revision": 1, "enabled": False,
                          "token": "replacement-fixture-only", "name": TOKEN})
    assert response.status_code == 422 and TOKEN not in response.text
    assert client.get(BASE + "/" + row["id"]).json()["revision"] == 1
