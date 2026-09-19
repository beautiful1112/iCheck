import json


REGISTRATION_HEADERS = {
    "X-iCheck-Registration-Token": "test-registration-token"
}


def register_worker(client, *, name, site, capabilities):
    response = client.post(
        "/api/v1/collector-workers/register",
        headers=REGISTRATION_HEADERS,
        json={
            "name": name,
            "site": site,
            "capabilities": capabilities,
            "labels": {"environment": "lab"},
        },
    )
    assert response.status_code == 200, response.text
    registration = response.json()
    return registration["worker"], {
        "Authorization": f"Bearer {registration['access_token']}"
    }


def onboard_device(client, *, protocol="icmp", credential_profile_ref=None):
    connection = {"protocol": protocol}
    if credential_profile_ref:
        connection["credential_profile_ref"] = credential_profile_ref
    response = client.post(
        "/api/v1/assets/devices",
        json={
            "name": f"lab-{protocol}-01",
            "kind": "switch" if protocol != "ssh" else "linux_server",
            "management_ip": "10.20.0.10" if protocol != "ssh" else "10.20.0.20",
            "site": "LAB",
            "labels": {"environment": "lab"},
            "connections": [connection],
            "created_by": "lab.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_worker_claims_scoped_preflight_and_reports_verified_evidence(client):
    device = onboard_device(client)
    wrong_worker, wrong_headers = register_worker(
        client,
        name="branch-icmp-worker",
        site="BRANCH",
        capabilities=["icmp"],
    )
    wrong_claim = client.post(
        f"/api/v1/collector-workers/{wrong_worker['id']}/device-preflights/claim",
        headers=wrong_headers,
        json={"max_assignments": 5, "lease_seconds": 60},
    )
    assert wrong_claim.status_code == 200
    assert wrong_claim.json() == []

    worker, worker_headers = register_worker(
        client,
        name="lab-icmp-worker",
        site="LAB",
        capabilities=["icmp"],
    )
    unauthorized = client.post(
        f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim",
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert unauthorized.status_code == 401

    claimed = client.post(
        f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim",
        headers=worker_headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claimed.status_code == 200, claimed.text
    assignments = claimed.json()
    assert len(assignments) == 1
    assignment = assignments[0]
    assert assignment["device_id"] == device["id"]
    assert assignment["target_host"] == "10.20.0.10"
    assert assignment["adapter_type"] == "icmp"
    assert assignment["port"] is None
    assert assignment["credential_profile_ref"] is None

    duplicate_claim = client.post(
        f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim",
        headers=worker_headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert duplicate_claim.status_code == 200
    assert duplicate_claim.json() == []

    detail = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    assert detail["onboarding_status"] == "verifying"
    assert detail["connections"][0]["verification_status"] == "running"

    invalid_lease = client.post(
        (
            f"/api/v1/collector-workers/{worker['id']}/device-preflights/"
            f"{assignment['preflight_id']}/complete"
        ),
        headers=worker_headers,
        json={
            "lease_token": "x" * 32,
            "status": "verified",
            "evidence": {"echo_replies": 3},
        },
    )
    assert invalid_lease.status_code == 409

    completed = client.post(
        (
            f"/api/v1/collector-workers/{worker['id']}/device-preflights/"
            f"{assignment['preflight_id']}/complete"
        ),
        headers=worker_headers,
        json={
            "lease_token": assignment["lease_token"],
            "status": "verified",
            "latency_ms": 8,
            "evidence": {"echo_replies": 3, "packet_loss_percent": 0},
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "verified"

    verified = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    assert verified["onboarding_status"] == "verified"
    connection = verified["connections"][0]
    assert connection["verification_status"] == "verified"
    assert connection["verification_worker_id"] is None
    assert connection["last_verification_evidence"]["echo_replies"] == 3
    assert connection["last_verification_worker_id"] == worker["id"]
    history = client.get(
        (
            f"/api/v1/assets/devices/{device['id']}/connections/"
            f"{connection['id']}/preflights"
        ),
        params={"limit": 1},
    )
    assert history.status_code == 200
    assert history.json()[0]["evidence"]["echo_replies"] == 3
    assert assignment["lease_token"] not in json.dumps(verified)

    audits = client.get("/api/v1/audit-events").json()
    event_types = {item["event_type"] for item in audits}
    assert "device.connection.preflight.claimed" in event_types
    assert "device.connection.preflight.completed" in event_types
    assert assignment["lease_token"] not in json.dumps(audits)


def test_failed_preflight_requires_explicit_retry_and_rejects_secret_evidence(client):
    credential = client.post(
        "/api/v1/credential-profiles",
        json={
            "name": "lab-ssh-readonly",
            "provider": "vault",
            "secret_ref": "kv/lab/ssh-readonly",
            "allowed_adapters": ["ssh"],
            "worker_selector": {"site": "LAB"},
            "created_by": "lab.admin",
        },
    )
    assert credential.status_code == 201
    device = onboard_device(
        client,
        protocol="ssh",
        credential_profile_ref="lab-ssh-readonly",
    )
    worker, headers = register_worker(
        client,
        name="lab-ssh-worker",
        site="LAB",
        capabilities=["ssh"],
    )

    claim_url = (
        f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim"
    )
    first = client.post(
        claim_url,
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    ).json()[0]
    complete_url = (
        f"/api/v1/collector-workers/{worker['id']}/device-preflights/"
        f"{first['preflight_id']}/complete"
    )
    failed = client.post(
        complete_url,
        headers=headers,
        json={
            "lease_token": first["lease_token"],
            "status": "failed",
            "latency_ms": 1000,
            "error": "TCP connection timed out",
            "evidence": {"tcp_connect": False},
        },
    )
    assert failed.status_code == 200, failed.text

    failed_device = client.get(
        f"/api/v1/assets/devices/{device['id']}"
    ).json()
    connection = failed_device["connections"][0]
    assert failed_device["onboarding_status"] == "verification_failed"
    assert connection["last_verification_error"] == "TCP connection timed out"
    assert client.post(
        claim_url,
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    ).json() == []

    retry = client.post(
        (
            f"/api/v1/assets/devices/{device['id']}/connections/"
            f"{connection['id']}/verification/retry"
        ),
        json={"actor": "lab.admin", "reason": "Firewall rule corrected"},
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["onboarding_status"] == "pending_verification"

    second = client.post(
        claim_url,
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    ).json()[0]
    second_complete_url = (
        f"/api/v1/collector-workers/{worker['id']}/device-preflights/"
        f"{second['preflight_id']}/complete"
    )
    leaked = client.post(
        second_complete_url,
        headers=headers,
        json={
            "lease_token": second["lease_token"],
            "status": "verified",
            "evidence": {"password": "must-not-be-persisted"},
        },
    )
    assert leaked.status_code == 409
    assert "inline secret" in leaked.text

    succeeded = client.post(
        second_complete_url,
        headers=headers,
        json={
            "lease_token": second["lease_token"],
            "status": "verified",
            "latency_ms": 14,
            "evidence": {"tcp_connect": True, "protocol_banner": "SSH-2.0"},
        },
    )
    assert succeeded.status_code == 200, succeeded.text

    verified = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    assert verified["onboarding_status"] == "verified"
    verified_connection = verified["connections"][0]
    assert verified_connection["last_verification_evidence"]["tcp_connect"] is True
    history = client.get(
        (
            f"/api/v1/assets/devices/{device['id']}/connections/"
            f"{verified_connection['id']}/preflights"
        ),
        params={"limit": 20},
    ).json()
    assert [item["status"] for item in history] == ["verified", "failed"]
    assert "kv/lab/ssh-readonly" not in json.dumps(history)

    retry_audit = client.get(
        "/api/v1/audit-events",
        params={"event_type": "device.connection.preflight.retried"},
    ).json()
    assert retry_audit[0]["details"]["reason"] == "Firewall rule corrected"
