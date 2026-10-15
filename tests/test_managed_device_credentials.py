import json
import os
from contextlib import contextmanager
import pytest
from sqlalchemy import select
from icheck.config import get_settings
from icheck.database import SessionLocal, set_session_namespace
from icheck.models import ManagedDeviceCredential, CredentialProfile, AuditEvent, Device
from icheck.services.device_credentials import resolve, DeviceCredentialUnavailable
from test_password_login import required_auth, bootstrap, login
from test_device_preflights import register_worker
from test_monitoring_gateway import gateway

COMMUNITY = "synthetic-community-for-tests-only"

@pytest.fixture
def device_key(tmp_path, monkeypatch):
    path = tmp_path / "device.key"; path.write_bytes(os.urandom(32)); path.chmod(0o400)
    monkeypatch.setenv("ICHECK_DEVICE_MANAGED_SECRET_KEY_FILE", str(path)); get_settings.cache_clear()
    yield path
    get_settings.cache_clear()

@contextmanager
def db_session():
    with SessionLocal() as db:
        set_session_namespace(db, "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002")
        yield db

def credential(client, **fields):
    response = client.post("/api/v1/device-credentials", json={"name": "lab-snmp-ro", "site": "LAB", "kind": "snmp_v2c", "community": COMMUNITY, **fields})
    assert response.status_code == 201, response.text
    assert COMMUNITY not in response.text and response.headers["cache-control"] == "no-store"
    return response.json()

def plan_input(profile):
    return {"site": "LAB", "protocol": "snmp", "credential_profile_ref": profile["name"],
        "devices": [{"name": "lab-switch-1", "management_ip": "198.18.0.10", "kind": "switch"},
                    {"name": "lab-router-2", "management_ip": "198.18.0.11", "kind": "router"}]}

@pytest.mark.parametrize("kind,values", [
    ("snmp_v2c", {"community": COMMUNITY}), ("https_token", {"token": "synthetic-http-token"}),
    ("http_basic", {"username": "monitor", "password": "synthetic-api-password"}),
    ("windows_password", {"username": "DOMAIN\\monitor", "password": "synthetic-windows-password"}),
    ("ssh_password", {"username": "monitor", "password": "synthetic-ssh-password"}),
])
def test_all_protocol_credentials_are_encrypted_write_only(client, device_key, kind, values):
    response = client.post("/api/v1/device-credentials", json={"name": "credential", "site": "LAB", "kind": kind, **values})
    assert response.status_code == 201, response.text
    p = response.json()
    with db_session() as db:
        row = db.scalar(select(ManagedDeviceCredential))
        assert all(v.encode() not in row.encrypted_secret for v in values.values())
        assert resolve(db, db.get(CredentialProfile, p["id"])) == values
        assert all(v not in json.dumps(a.details) for a in db.scalars(select(AuditEvent)) for v in values.values())
    assert all(v not in client.get("/api/v1/device-credentials").text for v in values.values())

def test_ssh_key_is_validated_and_encrypted(client, device_key):
    import asyncssh
    value = asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode()
    response = client.post("/api/v1/device-credentials", json={"name": "ssh-key", "site": "LAB", "kind": "ssh_key", "username": "monitor", "private_key": value})
    assert response.status_code == 201, response.text
    assert value not in response.text
    with db_session() as db:
        assert resolve(db, db.get(CredentialProfile, response.json()["id"]))["private_key"] == value

def test_rotation_revocation_and_stale_revision(client, device_key):
    p = credential(client)
    body = {"name": p["name"], "site": "LAB", "kind": "snmp_v2c", "community": "synthetic-new-community",
            "expected_revision": 1, "reason": "Rotate test credential"}
    assert client.put(f"/api/v1/device-credentials/{p['id']}", json=body).status_code == 200
    assert client.put(f"/api/v1/device-credentials/{p['id']}", json=body).status_code == 409
    assert client.post(f"/api/v1/device-credentials/{p['id']}/revoke", json={"expected_revision": 2, "reason": "Revoke"}).status_code == 200
    with db_session() as db:
        with pytest.raises(DeviceCredentialUnavailable): resolve(db, db.get(CredentialProfile, p["id"]))
    body["expected_revision"] = 3
    assert client.put(f"/api/v1/device-credentials/{p['id']}", json=body).status_code == 200

@pytest.mark.parametrize("extra", [{"token": COMMUNITY}, {"unknown": COMMUNITY}, {"community": "bad\ncommunity"}, {"kind": "ssh_key", "private_key": COMMUNITY}])
def test_invalid_secrets_are_not_echoed(client, device_key, extra):
    response = client.post("/api/v1/device-credentials", json={"name": "test", "site": "LAB", "kind": "snmp_v2c", "community": COMMUNITY, **extra})
    assert response.status_code == 422
    assert COMMUNITY not in response.text and all("input" not in error for error in response.json()["detail"])

def test_missing_or_unsafe_key_fails_closed(client, device_key):
    device_key.chmod(0o644)
    assert client.post("/api/v1/device-credentials", json={"name": "test", "site": "LAB", "kind": "snmp_v2c", "community": COMMUNITY}).status_code == 503
    assert client.get("/api/v1/credential-profiles").json() == []

def test_ai_preview_no_writes_and_human_approval_atomic_replay(client, device_key):
    p = credential(client); body = plan_input(p)
    response = client.post("/api/v1/assets/onboarding/preview", json=body)
    assert response.status_code == 200, response.text
    plan = response.json()
    assert COMMUNITY not in response.text
    assert client.get("/api/v1/assets/devices").json() == []
    approval = {**plan["input"], "preview_hash": plan["preview_hash"], "reason": "Approve lab devices"}
    saved = client.post("/api/v1/assets/onboarding/approve", json=approval)
    assert saved.status_code == 200, saved.text
    assert len(saved.json()["device_ids"]) == 2
    assert client.post("/api/v1/assets/onboarding/approve", json=approval).json()["replayed"] is True
    devices = client.get("/api/v1/assets/devices").json()
    assert len(devices) == 2
    assert all(d["connections"][0]["credential_profile_ref"] == p["id"] and d["connections"][0]["verification_status"] == "pending" for d in devices)

def test_plan_change_credential_rotation_duplicate_and_site_guards(client, device_key):
    p = credential(client); body = plan_input(p)
    plan = client.post("/api/v1/assets/onboarding/preview", json=body).json()
    changed = {**plan["input"], "preview_hash": plan["preview_hash"], "reason": "Approve", "port": 1161}
    assert client.post("/api/v1/assets/onboarding/approve", json=changed).status_code == 409
    assert client.post("/api/v1/assets/onboarding/preview", json={**body, "site": "OTHER"}).status_code == 422
    assert client.post("/api/v1/assets/onboarding/preview", json={**body, "devices": [body["devices"][0]] * 2}).status_code == 422
    client.post(f"/api/v1/device-credentials/{p['id']}/revoke", json={"expected_revision": 1, "reason": "Revoke"})
    assert client.post("/api/v1/assets/onboarding/approve", json={**plan["input"], "preview_hash": plan["preview_hash"], "reason": "Approve"}).status_code == 409
    assert client.get("/api/v1/assets/devices").json() == []

def test_only_leased_scoped_worker_can_resolve_preflight(client, device_key):
    p = credential(client); body = plan_input(p)
    plan = client.post("/api/v1/assets/onboarding/preview", json=body).json()
    client.post("/api/v1/assets/onboarding/approve", json={**plan["input"], "preview_hash": plan["preview_hash"], "reason": "Lab"})
    worker, headers = register_worker(client, name="collector", site="LAB", capabilities=["snmp_exporter"])
    claim = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim", headers=headers, json={"max_assignments": 1, "lease_seconds": 60}).json()[0]
    assert claim["credential_provider"] == "managed_device"
    path = f"/api/v1/collector-workers/{worker['id']}/device-preflights/{claim['preflight_id']}/managed-credential"
    assert client.post(path, headers=headers, json={"lease_token": "incorrect-token-long-enough"}).status_code == 409
    good = client.post(path, headers=headers, json={"lease_token": claim["lease_token"]})
    assert good.status_code == 200, good.text
    assert good.json()["values"] == {"community": COMMUNITY}
    assert good.headers["cache-control"] == "no-store"
    client.post(f"/api/v1/device-credentials/{p['id']}/revoke", json={"expected_revision": 1, "reason": "Revoke"})
    assert client.post(path, headers=headers, json={"lease_token": claim["lease_token"]}).status_code == 409

def test_credentials_and_onboarding_require_login_and_csrf(client, device_key, required_auth):
    assert client.get("/api/v1/device-credentials").status_code == 401
    bootstrap(client); logged = login(client); assert logged.status_code == 201
    response = client.post("/api/v1/device-credentials", json={"name": "test", "site": "LAB", "kind": "snmp_v2c", "community": COMMUNITY})
    assert response.status_code == 403


def test_ai_tools_find_profiles_prepare_only_and_find_approved_devices(client, device_key):
    from icheck.builtin_agent_tools import ensure_builtin_agent_tools
    from icheck.services.agent_tools import execute_internal_tool
    from icheck.services.control_plane_auth import development_principal
    p = credential(client)
    principal = development_principal()
    with db_session() as db:
        tools = {tool.name: tool for tool in ensure_builtin_agent_tools(db)}
        profiles, _ = execute_internal_tool(db, tools["credentials.list_device_profiles"], {"site": "LAB"})
        assert profiles["profiles"][0]["name"] == p["name"]
        assert "secret_ref" not in json.dumps(profiles) and COMMUNITY not in json.dumps(profiles)
        plan, _ = execute_internal_tool(db, tools["inventory.preview_onboarding"], plan_input(p))
        assert db.scalars(select(Device)).all() == []
    response = client.post("/api/v1/assets/onboarding/approve", json={**plan["input"], "preview_hash": plan["preview_hash"], "reason": "Approve tool preview"})
    assert response.status_code == 200, response.text
    with db_session() as db:
        result, evidence = execute_internal_tool(db, tools["inventory.find_devices"],
            {"site": "LAB", "management_ips": ["198.18.0.10", "198.18.0.12"]})
        assert result["devices"][0]["connections"][0]["verification_status"] == "pending"
        assert result["missing_addresses"] == ["198.18.0.12"] and evidence


def test_managed_continuous_gateway_uses_enrollment_credential_not_shared_auth(client, device_key, gateway, monkeypatch):
    from dataclasses import replace
    from contextlib import contextmanager
    from fastapi import Depends
    from icheck.auth import current_principal
    from icheck.main import app
    from icheck.database import get_db
    from icheck.models import DeviceConnection, utcnow
    from icheck.services.control_plane_auth import development_principal
    from test_monitoring_enrollments import seeded, approve
    from icheck.monitoring_gateway import GatewayError
    p = credential(client)
    device, connection, _, path = seeded(client)
    with db_session() as db:
        c = db.get(DeviceConnection, connection["id"]); c.credential_profile_ref = p["id"]; db.commit()
    enrolled = approve(client, path).json()
    secret_path = f"/api/v1/monitoring/enrollments/{enrolled['id']}/managed-credential"
    assert client.get(secret_path).status_code == 403
    subject, config, opener = gateway
    assert subject.discovery() == []  # Root custody opt-in is independent of GUI approval.
    config.profiles["lab-readonly"].allow_managed_snmp_credentials = True
    monkeypatch.setenv("ICHECK_MANAGED_MONITORING_GATEWAY_SUBJECT", "test-gateway"); get_settings.cache_clear()
    def gateway_principal(db=Depends(get_db)):
        principal = replace(development_principal(), subject="test-gateway", principal_type="service")
        set_session_namespace(db, principal.tenant_id, principal.region_id)
        return principal
    app.dependency_overrides[current_principal] = gateway_principal
    @contextmanager
    def isolated_exporter(values, **kwargs):
        assert values == {"community": COMMUNITY}
        yield "http://127.0.0.1:19919"
    monkeypatch.setattr("icheck.managed_snmp.exporter", isolated_exporter)
    try:
        secret = client.get(secret_path)
        assert secret.status_code == 200, secret.text
        assert secret.headers["cache-control"] == "no-store"
        assert subject.discovery()
        body = subject.scrape(enrolled["id"])
        assert COMMUNITY.encode() not in body
        from urllib.parse import urlsplit, parse_qs
        wire = [r for r in opener.requests if urlsplit(r.full_url).hostname == "127.0.0.1"]
        assert wire and parse_qs(urlsplit(wire[-1].full_url).query)["auth"] == ["managed"]
        assert all(COMMUNITY not in r.full_url for r in opener.requests)
    finally:
        app.dependency_overrides.pop(current_principal, None); get_settings.cache_clear()
