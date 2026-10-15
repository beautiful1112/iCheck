from datetime import timedelta
import json

import pytest
from sqlalchemy import select

from icheck.database import SessionLocal
from icheck.models import CredentialProfile, Device, DeviceConnection, DeviceMonitoringEnrollment, utcnow
from icheck.services import monitoring
from icheck.services.control_plane_auth import PrincipalContext
from test_device_onboarding import create_network_credential


def seeded(client, *, protocol="snmp", credential=False):
    profile = create_network_credential(client) if credential else None
    response = client.post("/api/v1/assets/devices", json={
        "name": "monitored-lab", "kind": "switch" if protocol == "snmp" else "windows_server",
        "management_ip": "198.18.1.10", "site": "LAB", "created_by": "lab.admin",
        "connections": [{"protocol": protocol, "credential_profile_ref": profile["id"] if profile else None}],
    })
    assert response.status_code == 201, response.text
    device = response.json()
    connection = device["connections"][0]
    with SessionLocal() as owner:
        row = owner.get(DeviceConnection, connection["id"])
        row.verification_status = "verified"
        row.last_verified_at = utcnow()
        row.last_verification_evidence = {"authentication_tested": False}
        owner.commit()
    path = f"/api/v1/assets/devices/{device['id']}/connections/{connection['id']}/monitoring"
    return device, connection, profile, path


def approve(client, path, *, protocol="snmp", revision=0, **changes):
    preview = client.get(path)
    assert preview.status_code == 200, preview.text
    payload = {"expected_revision": revision, "preview_hash": preview.json()["preview_hash"],
        "gateway_profile": "lab-readonly", "modules": ["if_mib"] if protocol == "snmp" else [],
        "collectors": [] if protocol == "snmp" else ["cpu", "memory"],
        "actor": "lab.admin", "reason": "Continuously monitor the verified lab connection.", **changes}
    return client.post(path + "/approve", json=payload)


@pytest.mark.parametrize("protocol", ["snmp", "windows_exporter"])
def test_explicit_approval_revision_withdrawal_and_no_implicit_preflight_enrollment(client, protocol):
    device, connection, profile, path = seeded(client, protocol=protocol)
    assert client.get("/api/v1/monitoring/targets").json()["targets"] == []
    preview = client.get(path).json()
    assert preview["eligible"] and not preview["currently_authorized"] and preview["warnings"]
    response = approve(client, path, protocol=protocol)
    assert response.status_code == 200, response.text
    enrollment = response.json()
    snapshot = client.get("/api/v1/monitoring/targets").json()
    assert len(snapshot["targets"]) == 1
    target = snapshot["targets"][0]
    assert target["host"] == device["management_ip"] and target["enrollment_id"] == enrollment["id"]
    assert target["connection_id"] == connection["id"] and target["protocol"] == protocol
    assert "configuration" not in target and "secret_ref" not in target
    assert client.get(f"/api/v1/monitoring/enrollments/{enrollment['id']}/target").status_code == 200
    assert approve(client, path, protocol=protocol).status_code == 409
    renewed = approve(client, path, protocol=protocol, revision=1)
    assert renewed.status_code == 200 and renewed.json()["revision"] == 2
    withdrawal = client.post(path + "/withdraw", json={"expected_revision": 2,
        "actor": "lab.admin", "reason": "Withdraw monitoring for the lab maintenance window."})
    assert withdrawal.status_code == 200 and withdrawal.json()["revision"] == 3
    assert client.get("/api/v1/monitoring/targets").json()["targets"] == []
    assert client.get(f"/api/v1/monitoring/enrollments/{enrollment['id']}/target").status_code == 404
    assert not client.get(path).json()["currently_authorized"]


@pytest.mark.parametrize("change", ["device_disabled", "connection_disabled", "identity", "port", "configuration",
    "verification", "future_verification", "credential_disabled", "credential_ref", "credential_scope", "expiry"])
def test_current_changes_and_revocations_withdraw_without_publisher_state(client, change):
    device, connection, profile, path = seeded(client, credential=True)
    enrollment = approve(client, path).json()
    with SessionLocal() as owner:
        d = owner.get(Device, device["id"])
        c = owner.get(DeviceConnection, connection["id"])
        p = owner.get(CredentialProfile, profile["id"])
        if change == "device_disabled": d.enabled = False
        elif change == "connection_disabled": c.enabled = False
        elif change == "identity": d.identity_revision += 1
        elif change == "port": c.port = 1161
        elif change == "configuration": c.configuration = {"modules": ["new_module"]}
        elif change == "verification": c.verification_status = "failed"
        elif change == "future_verification": c.last_verified_at = utcnow() + timedelta(hours=1)
        elif change == "credential_disabled": p.enabled = False
        elif change == "credential_ref": p.secret_ref = "kv/lab/rotated-readonly"
        elif change == "credential_scope": p.worker_selector = {"site": "OTHER"}
        else:
            row = owner.get(DeviceMonitoringEnrollment, enrollment["id"])
            row.approved_until = utcnow() - timedelta(seconds=1)
            row.revision += 1
        owner.commit()
    assert client.get("/api/v1/monitoring/targets").json()["targets"] == []
    assert client.get(f"/api/v1/monitoring/enrollments/{enrollment['id']}/target").status_code == 404


def test_changed_preview_cannot_approve_or_launder_current_configuration(client):
    device, connection, _, path = seeded(client)
    preview = client.get(path).json()
    with SessionLocal() as owner:
        owner.get(DeviceConnection, connection["id"]).configuration = {"modules": ["changed"]}
        owner.commit()
    response = client.post(path + "/approve", json={"expected_revision": 0,
        "preview_hash": preview["preview_hash"], "gateway_profile": "lab-readonly", "modules": ["if_mib"],
        "actor": "lab.admin", "reason": "Approve this exact current connection."})
    assert response.status_code == 409, response.text
    assert client.get("/api/v1/monitoring/targets").json()["targets"] == []


@pytest.mark.parametrize("changes", [
    {"timeout_seconds": 30, "schedule_seconds": 30}, {"modules": ["if_mib", "if_mib"]},
    {"gateway_profile": "https://attacker.invalid"}, {"validity_hours": 721},
    {"modules": []}, {"collectors": ["cpu"]}, {"raw_token": "must-never-enter-storage"},
])
def test_approval_rejects_invalid_or_secret_bearing_contract(client, changes):
    _, _, _, path = seeded(client)
    response = approve(client, path, **changes)
    assert response.status_code == 422, response.text


def test_required_initial_verification_and_complete_snapshot_bound(client, monkeypatch):
    _, connection, _, path = seeded(client)
    with SessionLocal() as owner:
        owner.get(DeviceConnection, connection["id"]).verification_status = "pending"
        owner.commit()
    assert approve(client, path).status_code == 422
    with SessionLocal() as owner:
        owner.get(DeviceConnection, connection["id"]).verification_status = "verified"
        owner.commit()
    assert approve(client, path).status_code == 200
    monkeypatch.setattr(monitoring, "SNAPSHOT_LIMIT", 0)
    response = client.get("/api/v1/monitoring/targets")
    assert response.status_code == 422 and "complete" in response.text


def test_scope_filtered_join_and_secret_free_output(client):
    device, connection, _, path = seeded(client, credential=True)
    assert approve(client, path).status_code == 200
    from icheck.database import DEFAULT_TENANT_ID, DEFAULT_REGION_ID
    principal = PrincipalContext(principal_id="test", subject="read.monitor", role_names=("monitor",), auth_method="bearer",
        principal_type="service", permissions=frozenset({"assets.read"}),
        authorization_scope={"sites": ["OTHER"]}, tenant_id=DEFAULT_TENANT_ID, region_id=DEFAULT_REGION_ID)
    with SessionLocal() as db:
        assert monitoring.monitoring_snapshot(db, principal).targets == []
        with pytest.raises(LookupError): monitoring.monitoring_preview(db, principal, device["id"], connection["id"])
    response = client.get("/api/v1/monitoring/targets")
    assert "kv/lab/network-readonly" not in response.text and "secret_ref" not in response.text
    assert "kv/lab/network-readonly" not in json.dumps(client.get("/api/v1/audit-events").json())


def test_renewal_retains_each_public_approval_contract_without_private_configuration(client):
    device, _, _, path = seeded(client, credential=True)
    assert approve(client, path, schedule_seconds=60).status_code == 200
    assert approve(client, path, revision=1, schedule_seconds=120, modules=["system"]).status_code == 200
    events = client.get("/api/v1/audit-events", params={"event_type": "device.monitoring.approved"}).json()
    contracts = sorted((event["details"] for event in events), key=lambda item: item["revision"])
    assert [item["revision"] for item in contracts] == [1, 2]
    assert [item["schedule_seconds"] for item in contracts] == [60, 120]
    assert [item["modules"] for item in contracts] == [["if_mib"], ["system"]]
    assert all(item["approved_until"] and item["device_identity_revision"] == device["identity_revision"]
               for item in contracts)
    assert "kv/lab/network-readonly" not in json.dumps(events)
    assert "credential_fingerprint" not in json.dumps(events)
