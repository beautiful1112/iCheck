"""Device-scoped legacy opt-in and real SSH wire tests, without lab traffic."""
from dataclasses import replace
import socket

import paramiko
import pytest
from sqlalchemy import select

from icheck.auth import current_principal
from icheck.database import SessionLocal
from icheck.device_schemas import DeviceConnectionInput
from icheck.extension_host import NativeExtensionProcess, ExtensionHostError
from icheck.main import app
from icheck.models import Device, DeviceConnection, AuditEvent
from icheck.services import managed_extensions as runtime, ssh_host_identity as identity
from icheck.services.control_plane_auth import development_principal
from icheck.services.devices import _connection_values
from icheck.ssh_compatibility import MODERN, LEGACY, CONFIG_KEY, transport_factory
from test_extension_host import ssh_simulator, target, package
from test_managed_extensions import setup, _run_tests, install
from test_mcp_extensions import DEVICE, RECEIPT
from test_ssh_host_identity import url, confirmation


def change(client, setup, profile=LEGACY, **changes):
    state = client.get(url(setup)).json()
    return client.post(url(setup) + "/compatibility", json={"profile": profile,
        "binding_hash": state["binding_hash"], "accept_legacy_risk": profile == LEGACY, **changes})


def test_profile_requires_explicit_review_is_audited_and_does_not_connect(client, setup, monkeypatch):
    monkeypatch.setattr(identity, "read_public_key", lambda *_: pytest.fail("Saving a profile cannot contact a target"))
    assert client.get(url(setup)).json()["ssh_profile"] == MODERN
    assert change(client, setup, accept_legacy_risk=False).status_code == 409
    assert change(client, setup, profile="anything").status_code == 422
    saved = change(client, setup)
    assert saved.status_code == 200 and saved.json()["ssh_profile"] == LEGACY
    assert saved.json()["state"] == "unconfirmed"
    # Repeated confirmation is idempotent, not a new revision or audit.
    assert change(client, setup).json()["binding_hash"] == saved.json()["binding_hash"]
    with SessionLocal() as db:
        record = db.get(DeviceConnection, setup["connection"]).configuration[CONFIG_KEY]
        assert record["device_id"] == setup["device"] and record["host"] == "198.18.0.1"
        assert record["port"] == 22 and record["profile"] == LEGACY
        events = list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == "device.ssh_compatibility.changed")))
        assert len(events) == 1 and events[0].details["accepted_legacy_risk"] is True
    assert change(client, setup, MODERN).json()["ssh_profile"] == MODERN


def test_profile_reaches_discovery_and_target_resolver_and_invalidates_old_tests(client, setup, monkeypatch):
    version = setup["version"](1)
    tests = _run_tests(client, setup, version)
    original = client.get(url(setup)).json()
    assert change(client, setup).status_code == 200
    assert install(client, version, tests).status_code == 409
    assert change(client, setup, MODERN, binding_hash=original["binding_hash"]).status_code == 409
    observed_profiles = []
    def discover(host, port, profile):
        observed_profiles.append(profile); return setup["host_key"]
    monkeypatch.setattr(identity, "read_public_key", discover)
    observed = client.post(url(setup) + "/probe").json()
    assert observed_profiles == [LEGACY]
    assert client.post(url(setup) + "/confirm", json=confirmation(observed)).status_code == 200
    with SessionLocal() as db:
        binding = runtime._binding(db, development_principal(), setup["connection"])
        _, _, spec = runtime._version(db, development_principal(), version)
        with runtime._target_resolver(db, development_principal(), binding, revalidate=lambda: None) as resolve:
            assert resolve(spec, spec.tools[0], setup["device"]).ssh_profile == LEGACY
    # One installation still owns both tools. Profile change invalidates active authority too.
    fresh_tests = _run_tests(client, setup, version)
    current = client.get(url(setup)).json()
    rows = client.get("/api/v1/capability-studio/extensions/tests", params={"artifact_version_id": version}).json()
    assert all(row["binding_hash"] == current["binding_hash"] for row in rows if row["id"] in fresh_tests)
    assert install(client, version, fresh_tests).status_code == 200
    assert change(client, setup, MODERN).status_code == 200
    with SessionLocal() as db, pytest.raises(runtime.ExtensionReviewConflict):
        runtime._assert_binding(db, development_principal(), binding)


def test_profile_change_during_discovery_discards_observed_key(client, setup, monkeypatch):
    def discover(*_args):
        assert change(client, setup).status_code == 200
        return setup["host_key"]
    monkeypatch.setattr(identity, "read_public_key", discover)
    result = client.post(url(setup) + "/probe")
    assert result.status_code == 409 and "changed during discovery" in result.text
    assert client.get(url(setup)).json()["state"] == "unconfirmed"


def test_algorithm_mismatch_has_safe_actionable_error(client, setup, monkeypatch):
    def incompatible(*_args):
        raise paramiko.ssh_exception.IncompatiblePeer("private remote diagnostic")
    monkeypatch.setattr(identity, "read_public_key", incompatible)
    result = client.post(url(setup) + "/probe")
    assert result.status_code == 409 and "compatibility profile" in result.text
    assert "private remote" not in result.text and "no login" in result.text


@pytest.mark.parametrize("changed", ["host", "port", "identity"])
def test_legacy_exception_cannot_follow_a_changed_device_target(client, setup, monkeypatch, changed):
    assert change(client, setup).status_code == 200
    with SessionLocal() as db:
        device = db.get(Device, setup["device"])
        if changed == "host": device.management_ip = "198.18.0.2"
        elif changed == "identity": device.identity_revision += 1
        else: db.get(DeviceConnection, setup["connection"]).port = 2222
        db.commit()
    monkeypatch.setattr(identity, "read_public_key", lambda *_: pytest.fail("Stale exception must not connect"))
    assert client.get(url(setup)).json()["ssh_profile_current"] is False
    assert client.post(url(setup) + "/probe").status_code == 409
    with SessionLocal() as db, pytest.raises(runtime.ExtensionReviewConflict):
        runtime._binding(db, development_principal(), setup["connection"], setup["host_key"])
    assert change(client, setup).json()["ssh_profile_current"] is True


def test_generic_device_configuration_cannot_inject_profile(client, setup):
    with SessionLocal() as db, pytest.raises(ValueError, match="reviewed device profile"):
        _connection_values(db, DeviceConnectionInput(protocol="ssh", configuration={CONFIG_KEY: {"profile": LEGACY}}),
            site="LAB", actor="fixture")


@pytest.mark.parametrize("actor", [replace(development_principal(), permissions=frozenset({"assets.read"})),
    replace(development_principal(), principal_type="service"),
    replace(development_principal(), authorization_scope={"sites": ["OTHER"]})])
def test_profile_cannot_be_selected_by_unauthorized_identity(client, setup, actor):
    state = client.get(url(setup)).json()
    app.dependency_overrides[current_principal] = lambda: actor
    try:
        result = client.post(url(setup) + "/compatibility", json={"profile": LEGACY,
            "binding_hash": state["binding_hash"], "accept_legacy_risk": True})
        assert result.status_code in {403, 404}
    finally:
        app.dependency_overrides.pop(current_principal, None)


def test_transport_policy_is_local_and_legacy_prefers_modern_algorithms():
    baseline = (paramiko.Transport._preferred_kex, dict(paramiko.Transport._kex_info), dict(paramiko.RSAKey.HASHES))
    for profile in (LEGACY, MODERN, LEGACY, MODERN):
        left, right = socket.socketpair()
        transport = transport_factory(profile)(left)
        try:
            options = transport.get_security_options()
            assert ("diffie-hellman-group14-sha1" in options.kex) == (profile == LEGACY)
            assert ("ssh-rsa" in options.key_types) == (profile == LEGACY)
            assert options.kex[0] != "diffie-hellman-group14-sha1"
            assert not any("group1-" in name for name in options.kex)
            assert not any("md5" in name for name in options.digests)
            assert "3des-cbc" not in options.ciphers and "ssh-dss" not in options.key_types
            if profile == LEGACY: assert not any("-etm" in name for name in options.digests)
        finally:
            transport.close(); right.close()
    assert baseline == (paramiko.Transport._preferred_kex, dict(paramiko.Transport._kex_info), dict(paramiko.RSAKey.HASHES))
    with pytest.raises(ValueError): transport_factory("auto")


def test_legacy_discovery_is_key_exchange_only_and_modern_never_falls_back(tmp_path):
    authenticated = []
    with ssh_simulator(tmp_path, legacy=True, authentication=authenticated) as (port, hosts, commands):
        with pytest.raises(paramiko.ssh_exception.IncompatiblePeer): identity.read_public_key("127.0.0.1", port)
        assert identity.read_public_key("127.0.0.1", port, LEGACY) == " ".join(hosts.read_text().split()[1:])
    assert authenticated == [] and commands == []


@pytest.mark.parametrize("tool", ["get_interface_status", "backup_configuration"])
def test_real_native_mcp_tools_use_legacy_profile_over_ssh(package, tmp_path, tool):
    with ssh_simulator(tmp_path, legacy=True) as (port, hosts, commands):
        result = NativeExtensionProcess(timeout_seconds=30).call(package, tool, {"device_id": DEVICE},
            resolve=lambda spec, item, device: replace(target(port, hosts, spec, item, device), ssh_profile=LEGACY),
            store_backup=lambda *_: RECEIPT)
    assert result == (RECEIPT if tool == "backup_configuration" else {"interfaces": [{"name": "Gi0/1", "state": "connected"}]})
    assert ("show running-config" if tool == "backup_configuration" else "show interfaces status") in commands


def test_legacy_wrong_host_key_is_rejected_before_password_or_commands(package, tmp_path):
    authenticated = []
    with ssh_simulator(tmp_path, legacy=True, authentication=authenticated) as (port, hosts, commands):
        wrong = paramiko.RSAKey.generate(2048)
        hosts.write_text(f"[127.0.0.1]:{port} ssh-rsa {wrong.get_base64()}\n")
        with pytest.raises(ExtensionHostError):
            NativeExtensionProcess(timeout_seconds=20).call(package, "get_interface_status", {"device_id": DEVICE},
                resolve=lambda spec, tool, device: replace(target(port, hosts, spec, tool, device), ssh_profile=LEGACY), store_backup=None)
    assert authenticated == [] and commands == []
