import json

import pytest
from fastapi import HTTPException

from icheck.database import SessionLocal
from icheck.device_api import update_device_metadata_route
from icheck.device_schemas import DeviceMetadataUpdate
from icheck.services.control_plane_auth import PrincipalContext


def create_network_credential(client, *, site="LAB"):
    response = client.post(
        "/api/v1/credential-profiles",
        json={
            "name": "lab-network-readonly",
            "provider": "vault",
            "secret_ref": "kv/lab/network-readonly",
            "allowed_adapters": ["snmp_exporter", "http_json", "ssh"],
            "worker_selector": {"site": site},
            "created_by": "lab.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def device_payload():
    return {
        "name": "lab-fw-01",
        "kind": "firewall",
        "management_ip": "10.10.0.1",
        "vendor": "Example Networks",
        "model": "Virtual Firewall",
        "site": "LAB",
        "labels": {"environment": "lab", "role": "edge"},
        "connections": [
            {
                "protocol": "snmp",
                "credential_profile_ref": "lab-network-readonly",
                "configuration": {
                    "modules": ["if_mib", "system"],
                    "auth_module": "lab_v3",
                },
            },
            {
                "protocol": "https_api",
                "credential_profile_ref": "lab-network-readonly",
            },
            {"protocol": "icmp"},
        ],
        "created_by": "lab.admin",
    }


def test_device_onboarding_persists_monitoring_intents_and_audit(client):
    create_network_credential(client)
    response = client.post("/api/v1/assets/devices", json=device_payload())
    assert response.status_code == 201, response.text
    device = response.json()
    assert device["name"] == "lab-fw-01"
    assert device["management_ip"] == "10.10.0.1"
    assert device["onboarding_status"] == "pending_verification"
    assert device["labels"] == {"environment": "lab", "role": "edge"}

    connections = {item["protocol"]: item for item in device["connections"]}
    assert set(connections) == {"snmp", "https_api", "icmp"}
    assert connections["snmp"]["adapter_type"] == "snmp_exporter"
    assert connections["snmp"]["port"] == 161
    assert connections["https_api"]["port"] == 443
    assert connections["icmp"]["port"] is None
    assert all(
        item["worker_selector"] == {"site": "LAB"}
        for item in connections.values()
    )
    assert all(
        item["verification_status"] == "pending"
        for item in connections.values()
    )

    listed = client.get(
        "/api/v1/assets/devices",
        params={"search": "10.10.0.1", "site": "LAB"},
    )
    assert listed.status_code == 200, listed.text
    assert [item["id"] for item in listed.json()] == [device["id"]]
    detail = client.get(f"/api/v1/assets/devices/{device['id']}")
    assert detail.status_code == 200
    assert len(detail.json()["connections"]) == 3

    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "device.onboarded"},
    ).json()
    assert len(audits) == 1
    assert audits[0]["details"]["protocols"] == [
        "snmp",
        "https_api",
        "icmp",
    ]
    assert audits[0]["details"]["credential_profile_count"] == 2
    assert "kv/lab/network-readonly" not in json.dumps(audits)


def test_device_onboarding_rejects_inline_secrets_and_scope_mismatch(client):
    create_network_credential(client, site="BRANCH")
    mismatched = client.post("/api/v1/assets/devices", json=device_payload())
    assert mismatched.status_code == 422
    assert "worker_selector" in mismatched.text

    payload = device_payload()
    payload["connections"] = [
        {
            "protocol": "snmp",
            "configuration": {"community": "must-not-be-stored"},
        }
    ]
    inline_secret = client.post("/api/v1/assets/devices", json=payload)
    assert inline_secret.status_code == 422
    assert "inline secret" in inline_secret.text


def test_device_onboarding_rejects_duplicate_protocols_and_addresses(client):
    duplicate_protocol = device_payload()
    duplicate_protocol["connections"] = [
        {"protocol": "icmp"},
        {"protocol": "icmp"},
    ]
    response = client.post("/api/v1/assets/devices", json=duplicate_protocol)
    assert response.status_code == 422
    assert "only once" in response.text

    first = device_payload()
    first["connections"] = [{"protocol": "icmp"}]
    assert client.post("/api/v1/assets/devices", json=first).status_code == 201
    second = {
        **first,
        "name": "lab-router-01",
    }
    duplicate_address = client.post("/api/v1/assets/devices", json=second)
    assert duplicate_address.status_code == 409
    assert "management IP" in duplicate_address.text


def test_device_metadata_edit_is_revisioned_audited_and_keeps_verification(client):
    create_network_credential(client)
    created = client.post("/api/v1/assets/devices", json=device_payload()).json()
    assert created["revision"] == 1
    path = f"/api/v1/assets/devices/{created['id']}/metadata"
    payload = {
        "expected_revision": created["revision"],
        "kind": "router",
        "vendor": "Updated Vendor",
        "model": None,
        "labels": {"environment": "lab", "role": "core"},
        "actor": "lab.admin",
    }
    response = client.patch(path, json=payload)
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["revision"] == 2
    assert updated["kind"] == "router"
    assert updated["vendor"] == "Updated Vendor"
    assert updated["model"] is None
    assert updated["labels"] == {"environment": "lab", "role": "core"}
    assert updated["name"] == created["name"]
    assert updated["management_ip"] == created["management_ip"]
    assert updated["site"] == created["site"]
    assert [item["verification_status"] for item in updated["connections"]] == [
        item["verification_status"] for item in created["connections"]
    ]

    stale = client.patch(path, json=payload)
    assert stale.status_code == 409
    assert "refresh" in stale.text
    immutable = client.patch(
        path, json={**payload, "expected_revision": 2, "management_ip": "10.10.0.9"}
    )
    assert immutable.status_code == 422
    assert client.get(f"/api/v1/assets/devices/{created['id']}").json()["revision"] == 2

    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "device.metadata.updated"},
    ).json()
    assert len(audits) == 1
    assert audits[0]["details"]["revision_before"] == 1
    assert audits[0]["details"]["revision_after"] == 2
    assert audits[0]["details"]["changed_fields"] == [
        "kind", "labels", "model", "vendor"
    ]
    assert audits[0]["details"]["kind_before"] == "firewall"
    assert audits[0]["details"]["kind_after"] == "router"


def test_device_metadata_edit_validates_labels_and_does_not_revise_noop(client):
    create_network_credential(client)
    created = client.post("/api/v1/assets/devices", json=device_payload()).json()
    path = f"/api/v1/assets/devices/{created['id']}/metadata"
    same = {
        "expected_revision": created["revision"],
        "kind": created["kind"],
        "vendor": created["vendor"],
        "model": created["model"],
        "labels": created["labels"],
        "actor": "lab.admin",
    }
    no_op = client.patch(path, json=same)
    assert no_op.status_code == 200, no_op.text
    assert no_op.json()["revision"] == 1
    invalid = client.patch(path, json={**same, "labels": {"": "bad"}})
    assert invalid.status_code == 422
    assert client.get(f"/api/v1/assets/devices/{created['id']}").json()["revision"] == 1


def test_device_metadata_edit_rechecks_site_scope_and_uses_trusted_actor(client):
    create_network_credential(client)
    created = client.post("/api/v1/assets/devices", json=device_payload()).json()
    payload = DeviceMetadataUpdate(
        expected_revision=1, kind="router", vendor="Scoped Vendor",
        model=None, labels={}, actor="spoofed.actor",
    )

    def principal(site: str) -> PrincipalContext:
        return PrincipalContext(
            principal_id="scoped-operator",
            subject="scoped-operator@example.test",
            principal_type="user",
            permissions=frozenset({"assets.write"}),
            role_names=(), authorization_scope={"sites": [site]},
            auth_method="token",
        )

    with SessionLocal() as db:
        with pytest.raises(HTTPException) as denied:
            update_device_metadata_route(created["id"], payload, principal("OTHER"), db)
        assert denied.value.status_code == 404
        assert update_device_metadata_route(
            created["id"], payload, principal("LAB"), db
        ).revision == 2

    audit = client.get(
        "/api/v1/audit-events",
        params={"event_type": "device.metadata.updated"},
    ).json()[0]
    assert audit["actor_id"] == "scoped-operator@example.test"
