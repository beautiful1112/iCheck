from datetime import timedelta

import pytest
from fastapi import HTTPException

from icheck.database import SessionLocal
from icheck.device_api import preview_device_identity_correction_route
from icheck.device_schemas import DeviceIdentityCorrectionInput
from icheck.models import DeviceConnection, DeviceConnectionPreflight, utcnow
from icheck.services.control_plane_auth import PrincipalContext


def _device(client, name="correction-switch-01", ip="198.18.10.1"):
    response = client.post("/api/v1/assets/devices", json={
        "name": name, "kind": "switch", "management_ip": ip,
        "site": "LAB", "connections": [{"protocol": "icmp"}],
        "created_by": "correction.test",
    })
    assert response.status_code == 201, response.text
    return response.json()


def _worker(client, site="LAB"):
    response = client.post(
        "/api/v1/collector-workers/register",
        headers={"X-iCheck-Registration-Token": "test-registration-token"},
        json={"name": f"correction-{site.lower()}-worker", "site": site,
              "capabilities": ["icmp"], "labels": {}},
    )
    assert response.status_code == 200, response.text
    item = response.json()
    return item["worker"], {"Authorization": f"Bearer {item['access_token']}"}


def _request(device, *, name="correction-router-01", ip="198.18.20.1", site="BRANCH"):
    return {
        "expected_revision": device["revision"],
        "name": name,
        "management_ip": ip,
        "site": site,
        "credential_profile_refs": {},
    }


def _preview(client, device, request):
    return client.post(
        f"/api/v1/assets/devices/{device['id']}/identity-correction/preview",
        json=request,
    )


def _commit(client, device, request, preview):
    return client.post(
        f"/api/v1/assets/devices/{device['id']}/identity-correction/commit",
        json={
            **request, "preview_hash": preview["preview_hash"],
            "actor": "correction.test", "reason": "Correct lab address and placement",
        },
    )


def test_identity_correction_requires_preview_and_resets_target(client):
    device = _device(client)
    request = _request(device)
    preview_response = _preview(client, device, request)
    assert preview_response.status_code == 200, preview_response.text
    preview = preview_response.json()
    assert preview["can_commit"] is True
    assert preview["blockers"] == []
    assert preview["connections"][0]["proposed_worker_selector"] == {
        "site": "BRANCH"
    }

    committed = _commit(client, device, request, preview)
    assert committed.status_code == 200, committed.text
    updated = committed.json()
    assert updated["revision"] == 2
    assert (updated["name"], updated["management_ip"], updated["site"]) == (
        "correction-router-01", "198.18.20.1", "BRANCH"
    )
    assert updated["connections"][0]["verification_status"] == "pending"
    assert updated["connections"][0]["worker_selector"] == {"site": "BRANCH"}
    assert updated["onboarding_status"] == "pending_verification"
    assert _commit(client, device, request, preview).status_code == 409

    audit = client.get(
        "/api/v1/audit-events", params={"event_type": "device.identity.corrected"}
    ).json()
    assert len(audit) == 1
    assert audit[0]["details"]["revision_before"] == 1
    assert audit[0]["details"]["revision_after"] == 2


def test_identity_correction_blocks_active_preflight_and_rejects_late_result(client):
    device = _device(client)
    worker, headers = _worker(client)
    claimed = client.post(
        f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim",
        headers=headers, json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claimed.status_code == 200, claimed.text
    assignment = claimed.json()[0]
    request = _request(device)
    blocked = _preview(client, device, request).json()
    assert blocked["can_commit"] is False
    assert any("preflight lease" in item for item in blocked["blockers"])
    assert _commit(client, device, request, blocked).status_code == 409

    with SessionLocal() as db:
        connection = db.get(DeviceConnection, device["connections"][0]["id"])
        preflight = db.get(DeviceConnectionPreflight, assignment["preflight_id"])
        connection.verification_lease_expires_at = utcnow() - timedelta(minutes=1)
        preflight.lease_expires_at = utcnow() - timedelta(minutes=1)
        preflight.target_host = None  # Simulate history created before the snapshot migration.
        preflight.site_snapshot = None
        db.commit()
    preview = _preview(client, device, request).json()
    assert preview["can_commit"] is True
    result = _commit(client, device, request, preview)
    assert result.status_code == 200, result.text
    late = client.post(
        f"/api/v1/collector-workers/{worker['id']}/device-preflights/"
        f"{assignment['preflight_id']}/complete",
        headers=headers,
        json={"lease_token": assignment["lease_token"], "status": "verified"},
    )
    assert late.status_code == 409
    history = client.get(
        f"/api/v1/assets/devices/{device['id']}/connections/"
        f"{device['connections'][0]['id']}/preflights"
    ).json()
    assert history[0]["status"] == "expired"
    assert history[0]["target_host"] == "198.18.10.1"
    assert history[0]["site_snapshot"] == "LAB"

    branch_worker, branch_headers = _worker(client, site="BRANCH")
    new_claim = client.post(
        f"/api/v1/collector-workers/{branch_worker['id']}/device-preflights/claim",
        headers=branch_headers, json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert new_claim.status_code == 200, new_claim.text
    assert new_claim.json()[0]["target_host"] == "198.18.20.1"
    history = client.get(
        f"/api/v1/assets/devices/{device['id']}/connections/"
        f"{device['connections'][0]['id']}/preflights"
    ).json()
    assert history[0]["target_host"] == "198.18.20.1"
    assert history[0]["site_snapshot"] == "BRANCH"


def test_site_correction_requires_compatible_new_credential_binding(client):
    for site in ("LAB", "BRANCH"):
        created = client.post("/api/v1/credential-profiles", json={
            "name": f"{site.lower()}-snmp-profile",
            "provider": "vault",
            "secret_ref": f"kv/{site.lower()}/snmp-readonly",
            "allowed_adapters": ["snmp_exporter"],
            "worker_selector": {"site": site},
            "created_by": "correction.test",
        })
        assert created.status_code == 201, created.text
    created = client.post("/api/v1/assets/devices", json={
        "name": "credential-move-switch", "kind": "switch",
        "management_ip": "198.18.30.1", "site": "LAB",
        "connections": [{
            "protocol": "snmp", "credential_profile_ref": "lab-snmp-profile",
        }],
        "created_by": "correction.test",
    })
    assert created.status_code == 201, created.text
    device = created.json()
    request = _request(
        device, name="credential-move-switch", ip="198.18.30.2", site="BRANCH"
    )
    blocked = _preview(client, device, request)
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["can_commit"] is False
    assert any("credential profile" in item for item in blocked.json()["blockers"])

    request["credential_profile_refs"] = {
        device["connections"][0]["id"]: "branch-snmp-profile"
    }
    preview = _preview(client, device, request).json()
    assert preview["can_commit"] is True
    result = _commit(client, device, request, preview)
    assert result.status_code == 200, result.text
    assert result.json()["connections"][0]["credential_profile_ref"] == (
        "branch-snmp-profile"
    )
    assert result.json()["connections"][0]["worker_selector"]["site"] == "BRANCH"


def test_identity_correction_preview_requires_both_source_and_destination_site_scope(client):
    device = _device(client)
    payload = DeviceIdentityCorrectionInput.model_validate(_request(device))

    def principal(sites):
        return PrincipalContext(
            principal_id="site-operator",
            subject="site-operator@example.test",
            principal_type="user",
            permissions=frozenset({"assets.write"}),
            role_names=(), authorization_scope={"sites": sites},
            auth_method="token",
        )

    with SessionLocal() as db:
        with pytest.raises(HTTPException) as destination_denied:
            preview_device_identity_correction_route(
                device["id"], payload, principal(["LAB"]), db
            )
        assert destination_denied.value.status_code == 403
        with pytest.raises(HTTPException) as source_denied:
            preview_device_identity_correction_route(
                device["id"], payload, principal(["BRANCH"]), db
            )
        assert source_denied.value.status_code == 404
        allowed = preview_device_identity_correction_route(
            device["id"], payload, principal(["LAB", "BRANCH"]), db
        )
        assert allowed.can_commit is True
