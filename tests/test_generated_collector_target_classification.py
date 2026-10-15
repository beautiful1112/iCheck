"""Studio-generated Collectors require an operator-reviewed target owner."""

import pytest
from sqlalchemy.exc import IntegrityError

from icheck.database import SessionLocal
from icheck.models import CollectorDeployment
from icheck.services.collectors import _target_hosts

from test_collectors import collector_artifact_payload, register_collector_worker
from test_device_identity_correction import _device


def test_url_target_ipv6_host_uses_inventory_canonical_form():
    assert _target_hosts({"url": "https://[2001:0db8:0:0::1]/health"}) == {
        "2001:db8::1",
    }


def _generated_version(client):
    payload = collector_artifact_payload("studio-generated-api")
    payload["labels"] = {"generated": True, "studio_session_id": "reviewed-session"}
    created = client.post("/api/v1/artifacts", json=payload)
    assert created.status_code == 201, created.text
    version_id = created.json()["versions"][0]["id"]
    validated = client.post(
        f"/api/v1/artifact-versions/{version_id}/validate",
        json={"actor": "classification.reviewer"},
    )
    assert validated.status_code == 200, validated.text
    published = client.post(
        f"/api/v1/artifact-versions/{version_id}/publish",
        json={"actor": "classification.publisher"},
    )
    assert published.status_code == 200, published.text
    return version_id


def _deployment(client, version_id, name, target, **updates):
    payload = {
        "name": name,
        "artifact_version_id": version_id,
        "target": target,
        "worker_selector": {"site": "LAB"},
        "created_by": "classification.operator",
    }
    payload.update(updates)
    return client.post("/api/v1/collector-deployments", json=payload)


def test_generated_collector_requires_explicit_external_review(client):
    version_id = _generated_version(client)
    target = {"url": "https://inventory.example.test/assets"}
    missing = _deployment(client, version_id, "missing-review", target)
    assert missing.status_code == 422, missing.text
    assert "target_classification" in missing.text
    no_reason = _deployment(
        client, version_id, "missing-reason", target,
        target_classification="external_source",
    )
    assert no_reason.status_code == 422, no_reason.text
    assert "operator reason" in no_reason.text
    valid = _deployment(
        client, version_id, "reviewed-external", target,
        target_classification="external_source",
        external_source_reason="Organization inventory API, outside monitored device inventory",
    )
    assert valid.status_code == 201, valid.text
    assert valid.json()["target_classification"] == "external_source"
    assert valid.json()["scope_device_id"] is None
    with SessionLocal() as db:
        deployment = db.get(CollectorDeployment, valid.json()["id"])
        deployment.external_source_reason = None
        with pytest.raises(IntegrityError):
            db.commit()
    with SessionLocal() as db:
        deployment = db.get(CollectorDeployment, valid.json()["id"])
        deployment.target_classification = None
        with pytest.raises(IntegrityError):
            db.commit()


def test_generated_collector_device_binding_and_ip_target_match(client):
    device = _device(client)
    version_id = _generated_version(client)
    wrong_ip = _deployment(
        client, version_id, "wrong-device-address",
        {"url": "http://198.18.10.2/assets"},
        target_classification="registered_device",
        scope_device_id=device["id"],
        scope_device_identity_revision=device["identity_revision"],
        scope_site=device["site"],
    )
    assert wrong_ip.status_code == 422, wrong_ip.text
    assert "different registered device" in wrong_ip.text
    valid = _deployment(
        client, version_id, "reviewed-device-address",
        {"url": "http://198.18.10.1/assets"},
        target_classification="registered_device",
        scope_device_id=device["id"],
        scope_device_identity_revision=device["identity_revision"],
        scope_site=device["site"],
    )
    assert valid.status_code == 201, valid.text
    assert valid.json()["scope_device_id"] == device["id"]
    assert valid.json()["target_classification"] == "registered_device"


def test_generated_registered_target_rejects_unrelated_url_and_accepts_inventory_name(client):
    device = _device(client)
    version_id = _generated_version(client)
    binding = {
        "target_classification": "registered_device",
        "scope_device_id": device["id"],
        "scope_device_identity_revision": device["identity_revision"],
        "scope_site": device["site"],
    }
    unrelated = _deployment(
        client, version_id, "unrelated-registered-url",
        {"url": "https://api.example.test/assets"}, **binding,
    )
    assert unrelated.status_code == 422, unrelated.text
    assert "must match the Device management IP or name" in unrelated.text
    named = _deployment(
        client, version_id, "inventory-name-url",
        {"url": f"https://{device['name']}/assets"}, **binding,
    )
    assert named.status_code == 201, named.text


def test_generated_registered_target_drift_stops_before_worker_assignment(client):
    device = _device(client)
    version_id = _generated_version(client)
    created = _deployment(
        client, version_id, "drifting-device-endpoint",
        {"url": f"http://{device['management_ip']}/assets"},
        target_classification="registered_device",
        scope_device_id=device["id"],
        scope_device_identity_revision=device["identity_revision"],
        scope_site=device["site"],
    )
    assert created.status_code == 201, created.text
    with SessionLocal() as db:
        deployment = db.get(CollectorDeployment, created.json()["id"])
        deployment.target = {"url": "https://unregistered-proxy.example/assets"}
        db.commit()
    worker, headers = register_collector_worker(
        client, name="registered-host-drift-worker", site="LAB",
    )
    claim = client.post(
        f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60}, headers=headers,
    )
    assert claim.status_code == 200, claim.text
    assert claim.json() == []
    with SessionLocal() as db:
        deployment = db.get(CollectorDeployment, created.json()["id"])
        assert deployment.enabled is False
        assert deployment.lease_token_hash is None


def test_external_collector_stops_if_target_enters_device_inventory(client):
    version_id = _generated_version(client)
    reason = "External API target has no registered Device at review time"
    external = _deployment(
        client, version_id, "external-before-inventory",
        {"url": "http://198.18.99.1/assets"},
        target_classification="external_source",
        external_source_reason=reason,
    )
    assert external.status_code == 201, external.text
    registered = client.post("/api/v1/assets/devices", json={
        "name": "newly-registered-source", "kind": "linux_server",
        "management_ip": "198.18.99.1", "site": "LAB",
        "connections": [{"protocol": "icmp"}],
        "created_by": "classification.operator",
    })
    assert registered.status_code == 201, registered.text
    worker, headers = register_collector_worker(
        client, name="classification-worker-lab", site="LAB",
    )
    claim = client.post(
        f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60}, headers=headers,
    )
    assert claim.status_code == 200, claim.text
    assert claim.json() == []
    with SessionLocal() as db:
        deployment = db.get(CollectorDeployment, external.json()["id"])
        assert deployment.enabled is False
        assert deployment.lease_token_hash is None


def test_external_classification_cannot_hide_registered_device_id(client):
    device = _device(client)
    version_id = _generated_version(client)
    disguised = _deployment(
        client, version_id, "disguised-registered-target",
        {"url": "http://198.18.10.1/assets"},
        target_classification="external_source",
        external_source_reason="Claim this registered switch is outside inventory",
    )
    assert disguised.status_code == 422, disguised.text
    assert "different registered device" in disguised.text
    assert device["management_ip"] == "198.18.10.1"
