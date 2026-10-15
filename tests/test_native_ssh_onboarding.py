"""Register native tool targets without enabling Collector SSH or probing devices."""
from dataclasses import replace

import pytest
from sqlalchemy import select
from icheck.auth import current_principal
from icheck.database import SessionLocal
from icheck.main import app
from icheck.models import DeviceConnection, DeviceConnectionPreflight
from icheck.services.control_plane_auth import development_principal
from test_managed_device_credentials import device_key
from test_device_preflights import register_worker


@pytest.fixture
def native_credential(client, device_key, monkeypatch):
    response = client.post("/api/v1/device-credentials", json={"name": "native-ssh", "kind": "ssh_password", "site": "LAB",
        "username": "fixture", "password": "synthetic-password"})
    assert response.status_code == 201, response.text
    monkeypatch.setattr("icheck.extension_host.NativeExtensionProcess.call",
        lambda *_a, **_kw: pytest.fail("Saving inventory must not call a native tool"))
    return response.json()["id"]


def create(client, credential, *, native=True, site="LAB"):
    body = {"name": "native-target", "management_ip": "198.18.4.1", "kind": "switch", "site": site, "created_by": "fixture",
        "connections": [{"protocol": "ssh", "credential_profile_ref": credential, "configuration": {"verification_mode": "studio"}}]
        if native else [{"protocol": "snmp", "enabled": False}]}
    result = client.post("/api/v1/assets/devices", json=body)
    assert result.status_code == 201, result.text
    return result.json()


@pytest.mark.parametrize("existing", [False, True])
def test_optional_site_reuses_saved_credential_scope_without_moving_device(client, native_credential, existing):
    device = create(client, native_credential, native=not existing, site=None)
    old_connections = device["connections"] if existing else []
    if existing:
        response = client.post(f"/api/v1/assets/devices/{device['id']}/native-ssh", json={
            "expected_revision": device["revision"], "credential_profile_ref": native_credential})
        assert response.status_code == 201, response.text
        device = response.json()
        assert next(row for row in device["connections"] if row["protocol"] == "snmp") == old_connections[0]
    assert device["site"] is None
    ssh = next(row for row in device["connections"] if row["protocol"] == "ssh")
    assert ssh["worker_selector"] == {"site": "LAB"}
    assert ssh["credential_profile_ref"] == native_credential
    assert ssh["verification_status"] == "not_requested" and ssh["next_verification_at"] is None


def test_new_native_target_is_registered_not_verified_or_queued(client, native_credential):
    device = create(client, native_credential)
    connection = device["connections"][0]
    assert device["onboarding_status"] == "registered"
    assert connection["enabled"] and connection["verification_status"] == "not_requested"
    assert connection["next_verification_at"] is None and connection["last_verified_at"] is None
    assert connection["last_verification_evidence"] == {}
    worker, headers = register_worker(client, name="ssh-worker", site="LAB", capabilities=["ssh"])
    claim = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim", headers=headers,
        json={"max_assignments": 2, "lease_seconds": 60})
    assert claim.status_code == 200 and claim.json() == [], claim.text
    retry = client.post(f"/api/v1/assets/devices/{device['id']}/connections/{connection['id']}/verification/retry",
        json={"actor": "fixture", "reason": "Explicit legacy retry is not the native tool test"})
    assert retry.status_code == 409 and "Studio" in retry.text
    overview = client.get("/api/v1/monitoring/overview").json()
    assert overview["total"] == 1
    assert all(check["protocol"] != "ssh" for check in overview["items"][0]["checks"])
    assert overview["items"][0]["state"] == "not_monitored" and overview["items"][0]["checks"] == []


def test_existing_device_registration_preserves_other_connections_and_rejects_replacement(client, native_credential):
    before = create(client, native_credential, native=False)
    url = f"/api/v1/assets/devices/{before['id']}/native-ssh"
    body = {"expected_revision": before["revision"], "port": 2222, "credential_profile_ref": native_credential}
    response = client.post(url, json=body)
    assert response.status_code == 201, response.text
    after = response.json()
    assert after["revision"] == before["revision"] + 1
    assert next(row for row in after["connections"] if row["protocol"] == "snmp") == before["connections"][0]
    ssh = next(row for row in after["connections"] if row["protocol"] == "ssh")
    assert ssh["port"] == 2222 and ssh["verification_status"] == "not_requested"
    assert client.post(url, json=body).status_code == 409
    assert client.post(url, json={**body, "expected_revision": after["revision"]}).status_code == 409
    with SessionLocal() as db:
        assert len(db.scalars(select(DeviceConnection).where(DeviceConnection.device_id == after["id"])).all()) == 2
        assert db.scalar(select(DeviceConnectionPreflight)) is None


def test_reenable_and_identity_correction_do_not_queue_native_ssh(client, native_credential):
    device = create(client, native_credential)
    connection = device["connections"][0]
    url = f"/api/v1/assets/devices/{device['id']}"
    for enabled in (False, True):
        response = client.patch(url + f"/connections/{connection['id']}/enabled", json={"expected_revision": device["revision"],
            "enabled": enabled, "actor": "fixture", "reason": "Change the on-demand binding availability"})
        assert response.status_code == 200, response.text
        device = response.json()
    assert device["connections"][0]["verification_status"] == "not_requested"
    correction = {"name": device["name"], "management_ip": "198.18.4.2", "site": "LAB", "expected_revision": device["revision"],
        "credential_profile_refs": {}}
    preview = client.post(url + "/identity-correction/preview", json=correction)
    assert preview.status_code == 200, preview.text
    corrected = client.post(url + "/identity-correction/commit", json={**correction, "preview_hash": preview.json()["preview_hash"],
        "reason": "Correct the selected test address", "actor": "fixture"})
    assert corrected.status_code == 200, corrected.text
    assert corrected.json()["connections"][0]["verification_status"] == "not_requested"
    assert corrected.json()["connections"][0]["next_verification_at"] is None


@pytest.mark.parametrize("fault", ["missing", "wrong_site", "disabled", "legacy_provider", "other_protocol", "unknown_mode"])
def test_native_registration_requires_a_supported_credential_and_mode(client, native_credential, fault):
    body = {"name": "invalid-native", "management_ip": "198.18.4.3", "kind": "switch", "site": "LAB", "created_by": "fixture",
        "connections": [{"protocol": "ssh", "credential_profile_ref": native_credential, "configuration": {"verification_mode": "studio"}}]}
    if fault == "missing": body["connections"][0]["credential_profile_ref"] = None
    elif fault == "wrong_site": body["site"] = "OTHER"
    elif fault == "disabled":
        assert client.post(f"/api/v1/device-credentials/{native_credential}/revoke", json={"expected_revision": 1, "reason": "Fixture revocation"}).status_code == 200
    elif fault == "legacy_provider":
        credential = client.post("/api/v1/credential-profiles", json={"name": "external-ssh", "provider": "vault", "secret_ref": "fixture/ref",
            "allowed_adapters": ["ssh"], "worker_selector": {"site": "LAB"}, "created_by": "fixture"}).json()
        body["connections"][0]["credential_profile_ref"] = credential["id"]
    elif fault == "other_protocol": body["connections"][0]["protocol"] = "snmp"
    else: body["connections"][0]["configuration"]["verification_mode"] = "skip"
    assert client.post("/api/v1/assets/devices", json=body).status_code == 422


def test_registration_cannot_cross_device_scope(client, native_credential):
    device = create(client, native_credential, native=False)
    app.dependency_overrides[current_principal] = lambda: replace(development_principal(), authorization_scope={"sites": ["OTHER"]})
    try:
        result = client.post(f"/api/v1/assets/devices/{device['id']}/native-ssh", json={"expected_revision": device["revision"],
            "credential_profile_ref": native_credential})
        assert result.status_code == 404
    finally:
        app.dependency_overrides.pop(current_principal, None)
