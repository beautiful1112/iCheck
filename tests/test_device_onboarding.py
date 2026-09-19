import json


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
