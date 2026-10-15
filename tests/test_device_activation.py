import json

from icheck.builtin_artifacts import (
    snmp_exporter_artifact_payload,
    snmp_topology_artifact_payload,
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
            "labels": {"environment": "lab", "io_supervisor_v1": True},
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


def topology_activation_policy_payload(artifact_version_id):
    return {
        "name": "lab-snmp-device-adjacency",
        "protocol": "snmp",
        "artifact_version_id": artifact_version_id,
        "target_template": {
            "exporter_url": "http://127.0.0.1:9116",
            "target": "${management_ip}",
            "local_device_key": "${device_id}",
            "local_display_name": "${device_name}",
        },
        "configuration_defaults": {"protocol": "lldp"},
        "worker_selector": {"site": "${site}"},
        "execution_mode": "scheduled",
        "schedule_seconds": 90,
        "created_by": "lab.admin",
    }


def preview_and_approve(client, device_id, connection_id, policy, reason):
    base_url = (
        f"/api/v1/assets/devices/{device_id}/connections/"
        f"{connection_id}/activation"
    )
    preview = client.post(
        f"{base_url}/preview",
        json={"policy_id": policy["id"]},
    )
    assert preview.status_code == 200, preview.text
    approved = client.post(
        f"{base_url}/approve",
        json={
            "policy_id": policy["id"],
            "expected_plan_hash": preview.json()["plan_hash"],
            "actor": "lab.admin",
            "reason": reason,
        },
    )
    assert approved.status_code == 200, approved.text
    return preview.json(), approved.json()


def test_identity_correction_waits_for_activation_deactivation(client):
    artifact = publish_artifact(client, snmp_exporter_artifact_payload())
    device = onboard_snmp_device(client)
    connection = verify_snmp_connection(client, device)
    policy = publish_policy(
        client, activation_policy_payload(artifact["id"])
    )
    _, approved = preview_and_approve(
        client, device["id"], connection["id"], policy,
        "Enable SNMP collection before target correction",
    )
    correction = {
        "expected_revision": device["revision"],
        "name": device["name"],
        "management_ip": "10.30.0.11",
        "site": "LAB",
    }
    base = f"/api/v1/assets/devices/{device['id']}/identity-correction"
    blocked = client.post(f"{base}/preview", json=correction)
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["can_commit"] is False
    assert any("active" in item for item in blocked.json()["blockers"])
    assert any("enabled" in item for item in blocked.json()["blockers"])
    refused = client.post(f"{base}/commit", json={
        **correction, "preview_hash": blocked.json()["preview_hash"],
        "actor": "lab.admin", "reason": "Move monitored device address",
    })
    assert refused.status_code == 409

    deactivated = client.post(
        f"/api/v1/assets/devices/{device['id']}/connections/"
        f"{connection['id']}/activation/deactivate",
        json={"actor": "lab.admin", "reason": "Retire old target before correction"},
    )
    assert deactivated.status_code == 200, deactivated.text
    ready = client.post(f"{base}/preview", json=correction)
    assert ready.status_code == 200, ready.text
    assert ready.json()["can_commit"] is True
    committed = client.post(f"{base}/commit", json={
        **correction, "preview_hash": ready.json()["preview_hash"],
        "actor": "lab.admin", "reason": "Move monitored device address",
    })
    assert committed.status_code == 200, committed.text
    assert committed.json()["connections"][0]["verification_status"] == "pending"
    with SessionLocal() as db:
        deployment = db.get(CollectorDeployment, approved["deployment"]["id"])
        assert deployment.enabled is False
        assert deployment.target["target"] == "10.30.0.10"


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


def test_policy_draft_edit_is_revision_guarded_audited_and_frozen_after_validation(client):
    artifact = publish_artifact(client, snmp_exporter_artifact_payload())
    original = activation_policy_payload(artifact["id"], name="editable-snmp-policy")
    created = client.post("/api/v1/assets/activation-policies", json=original)
    assert created.status_code == 201, created.text
    policy = created.json()
    assert (policy["version"], policy["revision"], policy["updated_by"]) == (
        1, 1, "lab.admin",
    )
    url = f"/api/v1/assets/activation-policies/{policy['id']}"
    edited_draft = {
        **original,
        "target_template": {**original["target_template"], "target": "${management_ip}"},
        "schedule_seconds": 120,
    }
    changed = client.patch(url, json={
        "expected_revision": 1, "draft": edited_draft, "actor": "lab.editor",
    })
    assert changed.status_code == 200, changed.text
    edited = changed.json()
    assert (edited["id"], edited["version"], edited["revision"]) == (
        policy["id"], 1, 2,
    )
    assert edited["schedule_seconds"] == 120
    assert edited["updated_by"] == "lab.editor"
    assert edited["updated_at"] is not None
    stale = client.patch(url, json={
        "expected_revision": 1, "draft": original, "actor": "lab.editor",
    })
    assert stale.status_code == 409
    unchanged = client.patch(url, json={
        "expected_revision": 2, "draft": edited_draft, "actor": "lab.editor",
    })
    assert unchanged.status_code == 200
    assert unchanged.json()["revision"] == 2
    unsafe_edit = client.patch(url, json={
        "expected_revision": 2,
        "draft": {**edited_draft, "configuration_defaults": {"password": "not-allowed"}},
        "actor": "lab.editor",
    })
    assert unsafe_edit.status_code == 422
    assert "inline secret" in unsafe_edit.text
    renamed = client.patch(url, json={
        "expected_revision": 2,
        "draft": {**edited_draft, "name": "different-name"},
        "actor": "lab.editor",
    })
    assert renamed.status_code == 422
    assert client.get(url).json()["revision"] == 2
    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "device.activation_policy.draft_updated"},
    )
    assert audits.status_code == 200
    assert len(audits.json()) == 1
    details = audits.json()[0]["details"]
    assert details["revision_before"] == 1
    assert details["revision_after"] == 2
    assert details["changed_fields"] == ["schedule_seconds"]
    assert "10.30.0.10" not in json.dumps(audits.json())

    missing_pin = client.post(f"{url}/validate", json={"actor": "lab.reviewer"})
    assert missing_pin.status_code == 409
    stale_pin = client.post(
        f"{url}/validate",
        json={"actor": "lab.reviewer", "expected_revision": 1},
    )
    assert stale_pin.status_code == 409
    validated = client.post(
        f"{url}/validate",
        json={"actor": "lab.reviewer", "expected_revision": 2},
    )
    assert validated.status_code == 200, validated.text
    assert validated.json()["status"] == "validated"
    frozen = client.patch(url, json={
        "expected_revision": 2, "draft": original, "actor": "lab.editor",
    })
    assert frozen.status_code == 409
    published = client.post(f"{url}/publish", json={"actor": "lab.publisher"})
    assert published.status_code == 200, published.text
    next_version = client.post("/api/v1/assets/activation-policies", json={
        **edited_draft, "schedule_seconds": 180,
    })
    assert next_version.status_code == 201, next_version.text
    assert (next_version.json()["version"], next_version.json()["revision"]) == (2, 1)
    assert client.get(url).json()["status"] == "published"


def test_multiple_capabilities_share_one_verified_connection(client):
    metrics_artifact = publish_artifact(client, snmp_exporter_artifact_payload())
    topology_artifact = publish_artifact(client, snmp_topology_artifact_payload())
    device = onboard_snmp_device(client)
    connection = verify_snmp_connection(client, device)
    metrics_policy = publish_policy(
        client,
        activation_policy_payload(
            metrics_artifact["id"],
            name="lab-snmp-metrics",
        ),
    )
    topology_policy = publish_policy(
        client,
        topology_activation_policy_payload(topology_artifact["id"]),
    )

    metrics_plan, metrics_result = preview_and_approve(
        client,
        device["id"],
        connection["id"],
        metrics_policy,
        "Activate interface metrics",
    )
    _, topology_result = preview_and_approve(
        client,
        device["id"],
        connection["id"],
        topology_policy,
        "Activate governed LLDP topology",
    )
    assert metrics_result["activation"]["capability_key"] == "lab-snmp-metrics"
    assert (
        topology_result["activation"]["capability_key"]
        == "lab-snmp-device-adjacency"
    )

    detail = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    activations = detail["connections"][0]["activations"]
    assert len(activations) == 2
    assert {item["status"] for item in activations} == {"active"}
    assert detail["onboarding_status"] == "monitoring_configured"

    legacy_deactivate = client.post(
        (
            f"/api/v1/assets/devices/{device['id']}/connections/"
            f"{connection['id']}/activation/deactivate"
        ),
        json={"actor": "lab.admin", "reason": "Ambiguous legacy request"},
    )
    assert legacy_deactivate.status_code == 409
    assert "multiple active capabilities" in legacy_deactivate.text

    exact_deactivate = client.post(
        (
            f"/api/v1/assets/devices/{device['id']}/connections/"
            f"{connection['id']}/activations/"
            f"{metrics_result['activation']['id']}/deactivate"
        ),
        json={"actor": "lab.admin", "reason": "Pause metrics only"},
    )
    assert exact_deactivate.status_code == 200, exact_deactivate.text
    assert exact_deactivate.json()["deployment"]["enabled"] is False
    detail = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    by_key = {
        item["capability_key"]: item
        for item in detail["connections"][0]["activations"]
    }
    assert by_key["lab-snmp-metrics"]["status"] == "deactivated"
    assert by_key["lab-snmp-device-adjacency"]["status"] == "active"
    assert detail["onboarding_status"] == "monitoring_configured"

    replacement_policy = publish_policy(
        client,
        {
            **activation_policy_payload(
                metrics_artifact["id"],
                name="lab-snmp-metrics",
            ),
            "schedule_seconds": 120,
        },
    )
    _, replacement_result = preview_and_approve(
        client,
        device["id"],
        connection["id"],
        replacement_policy,
        "Upgrade the metrics capability schedule",
    )
    assert replacement_result["activation"]["id"] == metrics_result["activation"]["id"]
    assert replacement_result["deployment"]["id"] != metrics_result["deployment"]["id"]
    assert replacement_result["deployment"]["schedule_seconds"] == 120
    detail = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    assert len(detail["connections"][0]["activations"]) == 2

    deployments = client.get("/api/v1/collector-deployments").json()
    deployment_by_id = {item["id"]: item for item in deployments}
    assert deployment_by_id[metrics_result["deployment"]["id"]]["enabled"] is False
    assert deployment_by_id[topology_result["deployment"]["id"]]["enabled"] is True
    assert replacement_result["activation"]["plan_hash"] != metrics_plan["plan_hash"]


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
            "labels": {"environment": "lab", "io_supervisor_v1": True},
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
    admitted = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/admit",
        headers=headers,
        json={
            "lease_token": assignment["lease_token"],
            "assignment_sha256": assignment["assignment_sha256"],
        },
    )
    assert admitted.status_code == 200, admitted.text
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
    admitted = client.post(
        f"/api/v1/collector-runs/{second['run_id']}/admit",
        headers=headers,
        json={
            "lease_token": second["lease_token"],
            "assignment_sha256": second["assignment_sha256"],
        },
    )
    assert admitted.status_code == 200, admitted.text
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
