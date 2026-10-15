"""First-use identity confirmation reuses saved credentials; no live lab traffic."""
from dataclasses import replace
from uuid import uuid4

import paramiko
import pytest

from icheck.auth import current_principal
from icheck.database import SessionLocal
from icheck.main import app
from icheck.models import Device, DeviceConnection, CredentialProfile
from icheck.services import ssh_host_identity as identity
from icheck.services import managed_extensions as runtime
from icheck.services.control_plane_auth import development_principal
from test_managed_extensions import setup, install
from test_mcp_extensions import SPEC
from test_extension_host import ssh_simulator


def url(setup):
    return f"/api/v1/capability-studio/extensions/targets/{setup['connection']}/identity"


def confirmation(observed, **changes):
    return {"binding_hash": observed["binding_hash"], "host_public_key": observed["host_public_key"], **changes}


def test_first_use_is_explicit_and_saved_identity_reuses_credentials_for_both_tools(client, setup, monkeypatch):
    calls = []
    def discover(host, port, profile):
        assert profile == "modern"
        calls.append((host, port))
        return setup["host_key"]
    monkeypatch.setattr(identity, "read_public_key", discover)
    # Physical site is optional; the connection and secret keep LAB scope.
    with SessionLocal() as db:
        db.get(Device, setup["device"]).site = None; db.commit()
    state = client.get(url(setup)).json()
    assert state["state"] == "unconfirmed" and calls == []
    original_resolve = runtime.resolve_credential
    monkeypatch.setattr(runtime, "resolve_credential", lambda *_a: pytest.fail("Fingerprint discovery must not resolve a password"))
    observed = client.post(url(setup) + "/probe").json()
    assert observed["state"] == "first_use" and len(calls) == 1
    assert observed["fingerprint"] == identity.fingerprint(setup["host_key"])
    assert client.get(url(setup)).json()["state"] == "unconfirmed"
    response = client.post(url(setup) + "/confirm", json=confirmation(observed))
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "confirmed"
    assert len(calls) == 1 and setup["calls"] == []
    monkeypatch.setattr(runtime, "resolve_credential", original_resolve)
    version = setup["version"](1)
    tests = []
    for tool in SPEC["tools"]:
        # Web client no longer supplies a manually pasted key.
        result = client.post("/api/v1/capability-studio/extensions/tests", json={"request_key": str(uuid4()),
            "artifact_version_id": version, "connection_id": setup["connection"], "tool_name": tool["name"]})
        assert result.status_code == 200 and result.json()["status"] == "succeeded", result.text
        tests.append(result.json()["id"])
    installed = install(client, version, tests)
    assert installed.status_code == 200 and len(installed.json()["tool_ids"]) == 2
    assert client.get(url(setup)).json()["state"] == "confirmed" and len(calls) == 1
    with SessionLocal() as db:
        assert db.get(Device, setup["device"]).site is None
        connection = db.get(DeviceConnection, setup["connection"])
        assert connection.worker_selector == {"site": "LAB"}
        assert connection.configuration[identity.CONFIG_KEY]["host_public_key"] == setup["host_key"]
    for search in ["198.18.0.1", "SIMULATED"]:
        found = client.get("/api/v1/capability-studio/extensions/targets", params={"search": search}).json()
        assert len(found) == 1 and found[0]["credential_name"] == "extension-ssh"


def test_changed_key_requires_replacement_confirmation_and_invalidates_old_bindings(client, setup, monkeypatch):
    monkeypatch.setattr(identity, "read_public_key", lambda *_a: setup["host_key"])
    first = client.post(url(setup) + "/probe").json()
    assert client.post(url(setup) + "/confirm", json=confirmation(first)).status_code == 200
    with SessionLocal() as db:
        old_binding = runtime._binding(db, development_principal(), setup["connection"])
    key = paramiko.RSAKey.generate(2048)
    changed = key.get_name() + " " + key.get_base64()
    monkeypatch.setattr(identity, "read_public_key", lambda *_a: changed)
    observed = client.post(url(setup) + "/probe").json()
    assert observed["state"] == "changed" and observed["saved_fingerprint"] == first["fingerprint"]
    assert client.get(url(setup)).json()["host_public_key"] == setup["host_key"]
    assert client.post(url(setup) + "/confirm", json=confirmation(observed)).status_code == 409
    assert client.post(url(setup) + "/confirm", json=confirmation(observed, accept_changed=True)).status_code == 200
    with SessionLocal() as db:
        with pytest.raises(runtime.ExtensionReviewConflict):
            runtime._assert_binding(db, development_principal(), old_binding)
        with pytest.raises(runtime.ExtensionReviewConflict):
            runtime._binding(db, development_principal(), setup["connection"], setup["host_key"])
    assert client.post(url(setup) + "/confirm", json=confirmation(observed, accept_changed=True)).status_code == 409


@pytest.mark.parametrize("change", ["address", "port", "credential", "disabled", "scope"])
def test_stale_identity_review_cannot_confirm_new_target_or_credential(client, setup, monkeypatch, change):
    monkeypatch.setattr(identity, "read_public_key", lambda *_a: setup["host_key"])
    observed = client.post(url(setup) + "/probe").json()
    with SessionLocal() as db:
        if change == "address": db.get(Device, setup["device"]).management_ip = "198.18.0.2"
        elif change == "port": db.get(DeviceConnection, setup["connection"]).port = 2222
        elif change == "credential": db.get(CredentialProfile, setup["credential"]).revision += 1
        elif change == "disabled": db.get(CredentialProfile, setup["credential"]).enabled = False
        else: db.get(DeviceConnection, setup["connection"]).worker_selector = {"site": "OTHER"}
        db.commit()
    assert client.post(url(setup) + "/confirm", json=confirmation(observed)).status_code == 409
    with SessionLocal() as db:
        assert identity.CONFIG_KEY not in db.get(DeviceConnection, setup["connection"]).configuration


def test_saved_key_is_invalid_after_target_identity_change(client, setup, monkeypatch):
    monkeypatch.setattr(identity, "read_public_key", lambda *_a: setup["host_key"])
    observed = client.post(url(setup) + "/probe").json()
    client.post(url(setup) + "/confirm", json=confirmation(observed))
    with SessionLocal() as db:
        db.get(Device, setup["device"]).identity_revision += 1; db.commit()
    assert client.get(url(setup)).json()["state"] == "target_changed"
    with SessionLocal() as db, pytest.raises(runtime.ExtensionReviewConflict):
        runtime._binding(db, development_principal(), setup["connection"], setup["host_key"])


def test_discovery_errors_are_safe_and_never_save_trust(client, setup, monkeypatch):
    def fail(*_a): raise RuntimeError("sensitive-device-output")
    monkeypatch.setattr(identity, "read_public_key", fail)
    result = client.post(url(setup) + "/probe")
    assert result.status_code == 409 and "sensitive-device-output" not in result.text
    assert "no login" in result.text
    assert client.get(url(setup)).json()["state"] == "unconfirmed"


def test_real_key_exchange_does_not_authenticate_or_open_a_channel(tmp_path, monkeypatch):
    def unexpected(*_a, **_kw): pytest.fail("Identity discovery must not authenticate or open a channel")
    monkeypatch.setattr(paramiko.Transport, "auth_password", unexpected)
    monkeypatch.setattr(paramiko.Transport, "auth_publickey", unexpected)
    monkeypatch.setattr(paramiko.Transport, "auth_none", unexpected)
    monkeypatch.setattr(paramiko.Transport, "open_session", unexpected)
    with ssh_simulator(tmp_path) as (port, hosts, commands):
        key = identity.read_public_key("127.0.0.1", port)
        assert key == " ".join(hosts.read_text().split()[1:])
        assert commands == []


def test_target_changed_during_discovery_discards_observation(client, setup, monkeypatch):
    def discover(*_a):
        with SessionLocal() as db:
            db.get(Device, setup["device"]).management_ip = "198.18.0.2"; db.commit()
        return setup["host_key"]
    monkeypatch.setattr(identity, "read_public_key", discover)
    result = client.post(url(setup) + "/probe")
    assert result.status_code == 409 and "changed during discovery" in result.text


def test_matching_saved_key_read_and_confirmation_do_not_invalidate_installation(client, setup, monkeypatch):
    monkeypatch.setattr(identity, "read_public_key", lambda *_a: setup["host_key"])
    observed = client.post(url(setup) + "/probe").json()
    confirmed = client.post(url(setup) + "/confirm", json=confirmation(observed)).json()
    again = client.post(url(setup) + "/probe").json()
    assert again["state"] == "matches" and again["binding_hash"] == confirmed["binding_hash"]
    assert client.post(url(setup) + "/confirm", json=confirmation(again)).json()["binding_hash"] == confirmed["binding_hash"]


@pytest.mark.parametrize("fault", ["scope", "disabled", "loopback", "remote_worker"])
def test_discovery_cannot_bypass_existing_target_controls(client, setup, monkeypatch, fault):
    monkeypatch.setattr(identity, "read_public_key", lambda *_a: pytest.fail("Unauthorized discovery"))
    if fault == "scope":
        app.dependency_overrides[current_principal] = lambda: replace(development_principal(), authorization_scope={"sites": ["OTHER"]})
    else:
        with SessionLocal() as db:
            if fault == "disabled": db.get(Device, setup["device"]).enabled = False
            elif fault == "loopback": db.get(Device, setup["device"]).management_ip = "127.0.0.1"
            else: db.get(DeviceConnection, setup["connection"]).worker_selector = {"site": "LAB", "worker": "remote"}
            db.commit()
    try:
        assert client.post(url(setup) + "/probe").status_code in {403, 404, 409}
    finally:
        app.dependency_overrides.pop(current_principal, None)
