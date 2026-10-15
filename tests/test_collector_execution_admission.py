"""An external Collector run must be admitted against its exact claim."""

from sqlalchemy import select

from icheck.database import SessionLocal
from icheck.models import (
    AuditEvent, CollectionEnvelope, CollectorDeployment, CollectorRun, Device,
)

from test_collectors import (
    REGISTRATION_HEADERS, publish_collector, register_collector_worker,
)
from test_device_identity_correction import _device
from test_generated_collector_target_classification import _generated_version


def _claimed_external(client):
    version_id = _generated_version(client)
    deployed = client.post("/api/v1/collector-deployments", json={
        "name": "execution-admission-source",
        "artifact_version_id": version_id,
        "target_classification": "external_source",
        "external_source_reason": "Separate organization API outside Device inventory",
        "target": {"url": "http://198.18.60.10/assets"},
        "worker_selector": {"site": "LAB"},
        "created_by": "admission.operator",
    })
    assert deployed.status_code == 201, deployed.text
    worker, headers = register_collector_worker(
        client, name="execution-admission-worker", site="LAB",
    )
    claimed = client.post(
        f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60}, headers=headers,
    )
    assert claimed.status_code == 200, claimed.text
    assert len(claimed.json()) == 1
    assignment = claimed.json()[0]
    assert len(assignment["assignment_sha256"]) == 64
    return deployed.json(), assignment, headers


def _claimed_device(
    client, *, target_url="https://inventory.example.test/assets",
    management_ip="198.18.62.10",
):
    device_response = client.post("/api/v1/devices", json={
        "name": "admission-device", "kind": "switch",
        "management_ip": management_ip, "site": "LAB",
        "created_by": "admission.operator",
    })
    assert device_response.status_code == 201, device_response.text
    device = device_response.json()
    _, version = publish_collector(client)
    deployed = client.post("/api/v1/collector-deployments", json={
        "name": "device-bound-execution-admission",
        "artifact_version_id": version["id"],
        "scope_device_id": device["id"],
        "scope_device_identity_revision": device["identity_revision"],
        "scope_site": "LAB",
        "target": {"url": target_url},
        "worker_selector": {"site": "LAB"},
        "created_by": "admission.operator",
    })
    assert deployed.status_code == 201, deployed.text
    worker, headers = register_collector_worker(
        client, name="device-admission-worker", site="LAB",
    )
    claimed = client.post(
        f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60}, headers=headers,
    )
    assert claimed.status_code == 200, claimed.text
    assert len(claimed.json()) == 1
    return device, deployed.json(), claimed.json()[0], headers


def _admit(client, assignment, headers, *, digest=None, lease_token=None):
    return client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/admit",
        json={
            "lease_token": lease_token or assignment["lease_token"],
            "assignment_sha256": digest or assignment["assignment_sha256"],
        },
        headers=headers,
    )


def _envelopes(client, assignment, headers):
    return client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/envelopes",
        json={
            "lease_token": assignment["lease_token"],
            "envelopes": [{
                "kind": "observation", "type": "inventory.asset",
                "source": "admission-test", "payload": {"id": "asset-1"},
            }],
        },
        headers=headers,
    )


def test_legacy_worker_cannot_claim_external_source(client):
    version_id = _generated_version(client)
    deployed = client.post("/api/v1/collector-deployments", json={
        "name": "legacy-worker-external-source",
        "artifact_version_id": version_id,
        "target_classification": "external_source",
        "external_source_reason": "Separate organization API outside Device inventory",
        "target": {"url": "http://198.18.61.10/assets"},
        "worker_selector": {"site": "LAB"},
        "created_by": "admission.operator",
    })
    assert deployed.status_code == 201, deployed.text
    registered = client.post("/api/v1/collector-workers/register", json={
        "name": "legacy-external-worker", "site": "LAB",
        "capabilities": ["http_json"], "labels": {"runtime": "python"},
    }, headers=REGISTRATION_HEADERS)
    assert registered.status_code == 200, registered.text
    worker = registered.json()["worker"]
    refused = client.post(
        f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60},
        headers={"Authorization": f"Bearer {registered.json()['access_token']}"},
    )
    assert refused.status_code == 200, refused.text
    assert refused.json() == []


def test_external_run_requires_admission_and_cancels_claim_drift(client):
    deployment, assignment, headers = _claimed_external(client)
    premature = _envelopes(client, assignment, headers)
    assert premature.status_code == 409, premature.text
    assert "requires execution admission" in premature.text
    for suffix, body in (
        ("credential-grant", {"lease_token": assignment["lease_token"]}),
        ("lease", {"lease_token": assignment["lease_token"], "lease_seconds": 60}),
        ("complete", {"lease_token": assignment["lease_token"],
                      "status": "failed", "error": "No adapter I/O started"}),
    ):
        denied = client.post(
            f"/api/v1/collector-runs/{assignment['run_id']}/{suffix}",
            json=body, headers=headers,
        )
        assert denied.status_code == 409, denied.text
        assert "requires execution admission" in denied.text
    assert _admit(client, assignment, headers, digest="f" * 64).status_code == 409
    assert _admit(client, assignment, headers, lease_token="x" * 32).status_code == 409

    admitted = _admit(client, assignment, headers)
    assert admitted.status_code == 200, admitted.text
    assert admitted.json()["execution_admitted_at"] is not None
    assert _admit(client, assignment, headers).status_code == 200

    with SessionLocal() as db:
        changed = db.get(CollectorDeployment, deployment["id"])
        changed.target = {"url": "http://198.18.60.11/assets"}
        db.commit()
    stale = _admit(client, assignment, headers)
    assert stale.status_code == 409, stale.text
    assert "run cancelled" in stale.text
    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        changed = db.get(CollectorDeployment, deployment["id"])
        assert run.status.value == "cancelled"
        assert run.finished_at is not None
        assert changed.enabled is False
        assert changed.lease_token_hash is None
        events = list(db.scalars(select(AuditEvent).where(
            AuditEvent.entity_id == run.id,
            AuditEvent.event_type == "collector.run.execution_admitted",
        )).all())
        assert len(events) == 1
    assert _envelopes(client, assignment, headers).status_code == 409


def test_inventory_change_after_admission_cancels_before_ingestion(client):
    deployment, assignment, headers = _claimed_external(client)
    assert _admit(client, assignment, headers).status_code == 200
    _device(client, name="new-external-target", ip="198.18.60.10")
    refused = _envelopes(client, assignment, headers)
    assert refused.status_code == 409, refused.text
    assert "run cancelled" in refused.text
    with SessionLocal() as db:
        assert db.get(CollectorRun, assignment["run_id"]).status.value == "cancelled"
        assert db.get(CollectorDeployment, deployment["id"]).enabled is False
        assert db.scalars(select(CollectionEnvelope).where(
            CollectionEnvelope.run_id == assignment["run_id"],
        )).all() == []


def test_worker_scope_change_cancels_run_without_disabling_source(client):
    deployment, assignment, headers = _claimed_external(client)
    assert _admit(client, assignment, headers).status_code == 200
    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        run.worker.labels = {
            "execution_admission_v1": False,
            "io_supervisor_v1": True,
        }
        db.commit()
    refused = _envelopes(client, assignment, headers)
    assert refused.status_code == 409, refused.text
    assert "Worker scope changed" in refused.text
    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        saved = db.get(CollectorDeployment, deployment["id"])
        assert run.status.value == "cancelled"
        assert run.stats["cancel_reason"] == "worker_scope_changed"
        assert saved.enabled is True
        assert saved.lease_token_hash is None


def test_device_run_requires_admission_and_cancels_target_drift(client):
    _device, deployment, assignment, headers = _claimed_device(client)
    premature = _envelopes(client, assignment, headers)
    assert premature.status_code == 409, premature.text
    assert "Device Collector run requires execution admission" in premature.text
    for suffix, body in (
        ("credential-grant", {"lease_token": assignment["lease_token"]}),
        ("lease", {"lease_token": assignment["lease_token"], "lease_seconds": 60}),
        ("complete", {"lease_token": assignment["lease_token"],
                      "status": "failed", "error": "No adapter I/O started"}),
    ):
        denied = client.post(
            f"/api/v1/collector-runs/{assignment['run_id']}/{suffix}",
            json=body, headers=headers,
        )
        assert denied.status_code == 409, denied.text
        assert "requires execution admission" in denied.text
    assert _admit(client, assignment, headers).status_code == 200
    with SessionLocal() as db:
        saved = db.get(CollectorDeployment, deployment["id"])
        saved.target = {"url": "https://changed.example.test/assets"}
        db.commit()
    refused = _admit(client, assignment, headers)
    assert refused.status_code == 409, refused.text
    assert "Device Collector target ownership changed; run cancelled" in refused.text
    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        saved = db.get(CollectorDeployment, deployment["id"])
        assert run.status.value == "cancelled"
        assert run.stats["cancel_reason"] == "device_target_drift"
        assert saved.enabled is False
        assert saved.lease_token_hash is None
    assert _envelopes(client, assignment, headers).status_code == 409


def test_device_identity_change_cancels_admitted_run(client):
    device, deployment, assignment, headers = _claimed_device(client)
    assert _admit(client, assignment, headers).status_code == 200
    with SessionLocal() as db:
        saved = db.get(Device, device["id"])
        saved.identity_revision += 1
        db.commit()
    refused = _admit(client, assignment, headers)
    assert refused.status_code == 409, refused.text
    assert "Device Collector target ownership changed; run cancelled" in refused.text
    with SessionLocal() as db:
        assert db.get(CollectorRun, assignment["run_id"]).status.value == "cancelled"
        assert db.get(CollectorDeployment, deployment["id"]).enabled is False


def test_device_worker_site_change_cancels_run_not_deployment(client):
    _device, deployment, assignment, headers = _claimed_device(client)
    assert _admit(client, assignment, headers).status_code == 200
    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        run.worker.site = "BRANCH"
        db.commit()
    refused = _admit(client, assignment, headers)
    assert refused.status_code == 409, refused.text
    assert "Device Collector Worker scope changed; run cancelled" in refused.text
    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        saved = db.get(CollectorDeployment, deployment["id"])
        assert run.stats["cancel_reason"] == "worker_scope_changed"
        assert saved.enabled is True
        assert saved.lease_token_hash is None
