import json

from icheck.builtin_artifacts import (
    snmp_exporter_artifact_payload,
    windows_exporter_artifact_payload,
)
from icheck.database import SessionLocal
from icheck.models import CollectorDeployment, utcnow


REGISTRATION_HEADERS = {
    "X-iCheck-Registration-Token": "test-registration-token"
}


def publish_artifact(client, payload):
    created = client.post("/api/v1/artifacts", json=payload)
    assert created.status_code == 201, created.text
    version = created.json()["versions"][0]
    validated = client.post(
        f"/api/v1/artifact-versions/{version['id']}/validate",
        json={"actor": "capability.reviewer"},
    )
    assert validated.status_code == 200, validated.text
    published = client.post(
        f"/api/v1/artifact-versions/{version['id']}/publish",
        json={"actor": "capability.publisher"},
    )
    assert published.status_code == 200, published.text
    return published.json()


def onboard_snmp_device(client):
    response = client.post(
        "/api/v1/assets/devices",
        json={
            "name": "lab-core-activation-01",
            "kind": "switch",
            "management_ip": "10.30.0.10",
            "site": "LAB",
            "labels": {"environment": "lab"},
            "connections": [
                {
                    "protocol": "snmp",
                    "configuration": {
                        "modules": ["if_mib"],
                        "auth_module": "lab_v3",
                    },
                }
            ],
            "created_by": "lab.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def verify_snmp_connection(client, device):
    registration = client.post(
        "/api/v1/collector-workers/register",
        headers=REGISTRATION_HEADERS,
        json={
            "name": "lab-snmp-activation-worker",
            "site": "LAB",
            "capabilities": ["snmp_exporter"],
            "labels": {"environment": "lab"},
        },
    )
    assert registration.status_code == 200, registration.text
    worker = registration.json()["worker"]
    headers = {
        "Authorization": f"Bearer {registration.json()['access_token']}"
    }
    claimed = client.post(
        f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim",
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claimed.status_code == 200, claimed.text
    assignment = claimed.json()[0]
    completed = client.post(
        (
            f"/api/v1/collector-workers/{worker['id']}/device-preflights/"
            f"{assignment['preflight_id']}/complete"
        ),
        headers=headers,
        json={
            "lease_token": assignment["lease_token"],
            "status": "verified",
            "latency_ms": 12,
            "evidence": {
                "check": "snmp_exporter_query",
                "verification_level": "protocol_query",
                "verified": True,
                "sample_count": 42,
            },
        },
    )
    assert completed.status_code == 200, completed.text
    detail = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    return detail["connections"][0]


def activation_policy_payload(artifact_version_id, *, name="lab-snmp-policy"):
    return {
        "name": name,
        "protocol": "snmp",
        "artifact_version_id": artifact_version_id,
        "target_template": {
            "exporter_url": "http://127.0.0.1:9116",
            "target": "${management_ip}",
        },
        "configuration_defaults": {"timeout_seconds": 10},
        "worker_selector": {"site": "${site}"},
        "execution_mode": "scheduled",
        "schedule_seconds": 60,
        "created_by": "lab.admin",
    }


def publish_policy(client, payload):
    created = client.post("/api/v1/assets/activation-policies", json=payload)
    assert created.status_code == 201, created.text
    policy = created.json()
    validated = client.post(
        f"/api/v1/assets/activation-policies/{policy['id']}/validate",
        json={"actor": "activation.reviewer"},
    )
    assert validated.status_code == 200, validated.text
    assert len(validated.json()["content_hash"]) == 64
    published = client.post(
        f"/api/v1/assets/activation-policies/{policy['id']}/publish",
        json={"actor": "activation.publisher"},
    )
    assert published.status_code == 200, published.text
    return published.json()


def test_activation_preview_approval_deactivation_and_reactivation(client):
    artifact = publish_artifact(client, snmp_exporter_artifact_payload())
    artifact_version_id = artifact["id"]
    device = onboard_snmp_device(client)
    connection = verify_snmp_connection(client, device)
    policy = publish_policy(
        client,
        activation_policy_payload(artifact_version_id),
    )

    preview_url = (
        f"/api/v1/assets/devices/{device['id']}/connections/"
        f"{connection['id']}/activation/preview"
    )
    preview = client.post(preview_url, json={"policy_id": policy["id"]})
    assert preview.status_code == 200, preview.text
    plan = preview.json()
    assert plan["target"] == {
        "exporter_url": "http://127.0.0.1:9116",
        "target": "10.30.0.10",
    }
    assert plan["configuration"] == {
        "timeout_seconds": 10,
        "modules": ["if_mib"],
        "auth_module": "lab_v3",
    }
    assert plan["worker_selector"] == {"site": "LAB"}
    assert len(plan["plan_hash"]) == 64

    approve_url = (
        f"/api/v1/assets/devices/{device['id']}/connections/"
        f"{connection['id']}/activation/approve"
    )
    stale = client.post(
        approve_url,
        json={
            "policy_id": policy["id"],
            "expected_plan_hash": "0" * 64,
            "actor": "lab.admin",
            "reason": "Activate verified SNMP collection",
        },
    )
    assert stale.status_code == 409
    assert "preview" in stale.text
    assert client.get("/api/v1/collector-deployments").json() == []

    approved = client.post(
        approve_url,
        json={
            "policy_id": policy["id"],
            "expected_plan_hash": plan["plan_hash"],
            "actor": "lab.admin",
            "reason": "Activate verified SNMP collection",
        },
    )
    assert approved.status_code == 200, approved.text
    result = approved.json()
    assert result["activation"]["status"] == "active"
    assert result["deployment"]["enabled"] is True
    assert result["deployment"]["target"] == plan["target"]
    deployment_id = result["deployment"]["id"]

    detail = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    assert detail["onboarding_status"] == "monitoring_configured"
    assert detail["connections"][0]["activation"]["deployment_id"] == deployment_id

    idempotent = client.post(
        approve_url,
        json={
            "policy_id": policy["id"],
            "expected_plan_hash": plan["plan_hash"],
            "actor": "lab.admin",
            "reason": "Confirm existing activation",
        },
    )
    assert idempotent.status_code == 200
    assert idempotent.json()["deployment"]["id"] == deployment_id
    assert len(client.get("/api/v1/collector-deployments").json()) == 1

    deactivate_url = (
        f"/api/v1/assets/devices/{device['id']}/connections/"
        f"{connection['id']}/activation/deactivate"
    )
    deactivated = client.post(
        deactivate_url,
        json={"actor": "lab.admin", "reason": "Maintenance rollback"},
    )
    assert deactivated.status_code == 200, deactivated.text
    assert deactivated.json()["activation"]["status"] == "deactivated"
    assert deactivated.json()["deployment"]["enabled"] is False
    assert deactivated.json()["deployment"]["next_run_at"] is None
    assert client.get(f"/api/v1/assets/devices/{device['id']}").json()[
        "onboarding_status"
    ] == "verified"

    reactivated = client.post(
        approve_url,
        json={
            "policy_id": policy["id"],
            "expected_plan_hash": plan["plan_hash"],
            "actor": "lab.admin",
            "reason": "Maintenance complete",
        },
    )
    assert reactivated.status_code == 200, reactivated.text
    assert reactivated.json()["deployment"]["id"] == deployment_id
    assert reactivated.json()["deployment"]["enabled"] is True

    audits = client.get("/api/v1/audit-events").json()
    audit_text = json.dumps(audits)
    event_types = {item["event_type"] for item in audits}
    assert "device.connection.activation.approved" in event_types
    assert "device.connection.activation.deactivated" in event_types
    assert "lease_token" not in audit_text


def test_activation_policy_rejects_unsafe_templates_and_unverified_connections(client):
    snmp_artifact = publish_artifact(client, snmp_exporter_artifact_payload())
    windows_artifact = publish_artifact(
        client,
        windows_exporter_artifact_payload(),
    )
    device = onboard_snmp_device(client)
    connection = device["connections"][0]

    mismatched = activation_policy_payload(windows_artifact["id"])
    response = client.post("/api/v1/assets/activation-policies", json=mismatched)
    assert response.status_code == 422
    assert "requires adapter" in response.text

    unsafe = activation_policy_payload(snmp_artifact["id"], name="unsafe-policy")
    unsafe["configuration_defaults"] = {"password": "must-not-be-stored"}
    response = client.post("/api/v1/assets/activation-policies", json=unsafe)
    assert response.status_code == 422
    assert "inline secret" in response.text

    invalid = activation_policy_payload(snmp_artifact["id"], name="invalid-template")
    invalid["target_template"]["target"] = "${unknown_target}"
    created = client.post("/api/v1/assets/activation-policies", json=invalid)
    assert created.status_code == 201, created.text
    validation = client.post(
        f"/api/v1/assets/activation-policies/{created.json()['id']}/validate",
        json={"actor": "activation.reviewer"},
    )
    assert validation.status_code == 422
    assert "unsupported placeholders" in validation.text

    policy = publish_policy(
        client,
        activation_policy_payload(snmp_artifact["id"], name="safe-policy"),
    )
    pending_preview = client.post(
        (
            f"/api/v1/assets/devices/{device['id']}/connections/"
            f"{connection['id']}/activation/preview"
        ),
        json={"policy_id": policy["id"]},
    )
    assert pending_preview.status_code == 422
    assert "verified" in pending_preview.text

    second = publish_policy(
        client,
        activation_policy_payload(snmp_artifact["id"], name="safe-policy"),
    )
    assert second["version"] == 2
    policies = client.get(
        "/api/v1/assets/activation-policies",
        params={"protocol": "snmp"},
    ).json()
    safe_versions = {
        item["version"]: item["status"]
        for item in policies
        if item["name"] == "safe-policy"
    }
    assert safe_versions == {2: "published", 1: "deprecated"}


def test_activation_runtime_health_degradation_drift_and_approved_repair(client):
    artifact = publish_artifact(client, snmp_exporter_artifact_payload())
    device = onboard_snmp_device(client)
    connection = verify_snmp_connection(client, device)
    policy = publish_policy(
        client,
        activation_policy_payload(artifact["id"]),
    )
    base_url = (
        f"/api/v1/assets/devices/{device['id']}/connections/"
        f"{connection['id']}/activation"
    )
    plan = client.post(
        f"{base_url}/preview",
        json={"policy_id": policy["id"]},
    ).json()
    approved = client.post(
        f"{base_url}/approve",
        json={
            "policy_id": policy["id"],
            "expected_plan_hash": plan["plan_hash"],
            "actor": "lab.admin",
            "reason": "Enable runtime health acceptance",
        },
    )
    assert approved.status_code == 200, approved.text
    deployment_id = approved.json()["deployment"]["id"]
    assert approved.json()["activation"]["runtime_status"] == "awaiting_first_run"

    registration = client.post(
        "/api/v1/collector-workers/register",
        headers=REGISTRATION_HEADERS,
        json={
            "name": "lab-snmp-runtime-worker",
            "site": "LAB",
            "capabilities": ["snmp_exporter"],
            "labels": {"environment": "lab"},
        },
    ).json()
    headers = {"Authorization": f"Bearer {registration['access_token']}"}
    claim_url = (
        f"/api/v1/collector-workers/{registration['worker']['id']}/leases/claim"
    )
    claimed = client.post(
        claim_url,
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claimed.status_code == 200, claimed.text
    assignment = claimed.json()[0]
    completed = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/complete",
        headers=headers,
        json={
            "lease_token": assignment["lease_token"],
            "status": "succeeded",
            "stats": {"sample_count": 42},
        },
    )
    assert completed.status_code == 200, completed.text
    detail = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    assert detail["onboarding_status"] == "active"
    assert detail["connections"][0]["activation"]["runtime_status"] == "healthy"
    assert detail["connections"][0]["activation"]["consecutive_failures"] == 0

    with SessionLocal() as db:
        deployment = db.get(CollectorDeployment, deployment_id)
        deployment.next_run_at = utcnow()
        db.commit()
    second = client.post(
        claim_url,
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    ).json()[0]
    failed = client.post(
        f"/api/v1/collector-runs/{second['run_id']}/complete",
        headers=headers,
        json={
            "lease_token": second["lease_token"],
            "status": "failed",
            "error": "simulated target timeout",
        },
    )
    assert failed.status_code == 200, failed.text
    detail = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    assert detail["onboarding_status"] == "degraded"
    assert detail["connections"][0]["activation"]["runtime_status"] == "degraded"
    assert detail["connections"][0]["activation"]["consecutive_failures"] == 1

    with SessionLocal() as db:
        deployment = db.get(CollectorDeployment, deployment_id)
        deployment.target = {
            "exporter_url": "http://127.0.0.1:9116",
            "target": "192.0.2.250",
        }
        db.commit()
    reconciled = client.post(
        claim_url,
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert reconciled.status_code == 200, reconciled.text
    detail = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    assert detail["connections"][0]["activation"]["runtime_status"] == "drifted"

    repaired = client.post(
        f"{base_url}/approve",
        json={
            "policy_id": policy["id"],
            "expected_plan_hash": plan["plan_hash"],
            "actor": "lab.admin",
            "reason": "Restore the approved collector plan after drift",
        },
    )
    assert repaired.status_code == 200, repaired.text
    result = repaired.json()
    assert result["deployment"]["target"] == plan["target"]
    assert result["activation"]["runtime_status"] == "awaiting_first_run"
    assert result["activation"]["consecutive_failures"] == 0
    detail = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    assert detail["onboarding_status"] == "monitoring_configured"

    events = client.get("/api/v1/audit-events?limit=1000").json()
    event_types = {event["event_type"] for event in events}
    assert "device.connection.runtime_status_changed" in event_types
    assert "device.monitoring.status_changed" in event_types
