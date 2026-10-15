import json
from dataclasses import replace

from sqlalchemy import select, update
from sqlalchemy.sql.dml import Update

from icheck.database import SessionLocal
from icheck.device_schemas import DevicePreflightClaim
from icheck.models import CollectorWorker, Device, DeviceConnection, DeviceConnectionPreflight
from icheck.services.devices import claim_device_preflights
from icheck.auth import current_principal
from icheck.main import app
from icheck.services.control_plane_auth import development_principal


REGISTRATION_HEADERS = {
    "X-iCheck-Registration-Token": "test-registration-token"
}


def test_disable_optional_connection_expires_old_lease_and_retains_history(client):
    response = client.post("/api/v1/assets/devices", json={"name":"optional-check-fixture","kind":"switch",
        "management_ip":"198.18.1.10","site":"LAB","created_by":"fixture",
        "connections":[{"protocol":"snmp"},{"protocol":"icmp"}]})
    assert response.status_code == 201, response.text
    device = response.json()
    snmp = next(row for row in device["connections"] if row["protocol"]=="snmp")
    ping = next(row for row in device["connections"] if row["protocol"]=="icmp")
    with SessionLocal() as db:
        db.get(DeviceConnection,snmp["id"]).verification_status="verified"
        db.commit()
    worker, headers = register_worker(client,name="optional-check-worker",site="LAB",capabilities=["icmp"])
    claim = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim",headers=headers,
        json={"max_assignments":1,"lease_seconds":60}).json()[0]
    path = f"/api/v1/assets/devices/{device['id']}/connections/{ping['id']}/enabled"
    result = client.patch(path,json={"expected_revision":device["revision"],"enabled":False,"actor":"fixture",
        "reason":"Disable the optional unavailable ping check."})
    assert result.status_code==200, result.text
    assert result.json()["onboarding_status"]=="verified"
    disabled = next(row for row in result.json()["connections"] if row["id"]==ping["id"])
    assert not disabled["enabled"] and disabled["verification_status"]=="disabled"
    assert len(result.json()["connections"])==2
    history = client.get(path.removesuffix("/enabled")+"/preflights").json()
    assert len(history)==1 and history[0]["status"]=="expired"
    late = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/{claim['preflight_id']}/complete",
        headers=headers,json={"lease_token":claim["lease_token"],"status":"verified","evidence":{"reachable":True}})
    assert late.status_code==409


def test_connection_reenable_does_not_restore_monitoring_and_requires_current_revision(client):
    from test_monitoring_enrollments import seeded, approve
    device, connection, _, monitoring_path = seeded(client)
    approved = approve(client,monitoring_path)
    assert approved.status_code==200, approved.text
    path=monitoring_path.removesuffix("/monitoring")+"/enabled"
    payload={"expected_revision":device["revision"],"enabled":False,"actor":"fixture","reason":"Disable this fixture monitoring connection."}
    result=client.patch(path,json=payload)
    assert result.status_code==200, result.text
    assert not client.get(monitoring_path).json()["enrollment"]["enabled"]
    assert client.get("/api/v1/monitoring/targets").json()["targets"]==[]
    assert client.patch(path,json={**payload,"enabled":True}).status_code==409
    enabled=client.patch(path,json={**payload,"expected_revision":result.json()["revision"],"enabled":True})
    assert enabled.status_code==200, enabled.text
    assert enabled.json()["connections"][0]["verification_status"]=="pending"
    assert enabled.json()["onboarding_status"]=="pending_verification"
    assert not client.get(monitoring_path).json()["enrollment"]["enabled"]
    assert client.get("/api/v1/monitoring/targets").json()["targets"]==[]


def test_connection_state_permission_scope_and_strict_boolean(client):
    device=onboard_device(client)
    connection=device["connections"][0]
    path=f"/api/v1/assets/devices/{device['id']}/connections/{connection['id']}/enabled"
    payload={"expected_revision":device["revision"],"enabled":False,"actor":"fixture","reason":"Disable this optional fixture connection."}
    assert client.patch(path,json={**payload,"enabled":"false"}).status_code==422
    try:
        app.dependency_overrides[current_principal]=lambda:replace(development_principal(),permissions=frozenset({"assets.read"}))
        assert client.patch(path,json=payload).status_code==403
        app.dependency_overrides[current_principal]=lambda:replace(development_principal(),authorization_scope={"sites":["OTHER"]})
        assert client.patch(path,json=payload).status_code in {403,404}
    finally:
        app.dependency_overrides.pop(current_principal,None)
    with SessionLocal() as db: assert db.get(DeviceConnection,connection["id"]).enabled


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


def test_claim_releases_connection_when_device_revision_changes_before_assignment(
    client, monkeypatch,
):
    device = onboard_device(client)
    worker, _ = register_worker(
        client, name="lab-revision-guard-worker", site="LAB", capabilities=["icmp"]
    )
    connection_id = device["connections"][0]["id"]
    with SessionLocal() as db:
        registered_worker = db.get(CollectorWorker, worker["id"])
        original_execute = db.execute
        injected = False

        def execute_with_revision_change(statement, *args, **kwargs):
            nonlocal injected
            result = original_execute(statement, *args, **kwargs)
            if (
                not injected
                and isinstance(statement, Update)
                and statement.table.name == "device_connections"
            ):
                injected = True
                original_execute(
                    update(Device)
                    .execution_options(synchronize_session=False)
                    .where(Device.id == device["id"])
                    .values(revision=Device.revision + 1)
                )
            return result

        monkeypatch.setattr(db, "execute", execute_with_revision_change)
        assignments = claim_device_preflights(
            db, registered_worker, DevicePreflightClaim(max_assignments=1)
        )
    assert injected
    assert assignments == []
    with SessionLocal() as db:
        connection = db.get(DeviceConnection, connection_id)
        assert connection.verification_status == "pending"
        assert connection.verification_lease_token_hash is None
        assert db.scalars(select(DeviceConnectionPreflight).where(
            DeviceConnectionPreflight.connection_id == connection_id
        )).all() == []


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
