"""Device-scoped collectors cannot outlive a reviewed device identity."""

from icheck.database import SessionLocal
from icheck.models import CollectorDeployment

from test_collectors import publish_collector, register_collector_worker
from test_device_identity_correction import _commit, _device, _preview, _request


def _deployment(client, *, name, version_id, device, mode="scheduled", **changes):
    payload = {
        "name": name,
        "artifact_version_id": version_id,
        "scope_device_id": device["id"],
        "scope_device_identity_revision": device["identity_revision"],
        "scope_site": device["site"],
        "target": {
            "url": "https://inventory.example.test/assets",
            "device_id": device["id"],
            "site": device["site"],
        },
        "worker_selector": {"site": device["site"]},
        "execution_mode": mode,
        "created_by": "identity.test",
    }
    payload.update(changes)
    return client.post("/api/v1/collector-deployments", json=payload)


def test_scoped_collector_requires_matching_identity_and_all_site_hints(client):
    device = _device(client)
    _, version = publish_collector(client)
    missing = _deployment(
        client, name="missing-binding", version_id=version["id"],
        device=device, scope_device_identity_revision=None,
    )
    assert missing.status_code == 422, missing.text
    stale = _deployment(
        client, name="stale-binding", version_id=version["id"],
        device=device, scope_device_identity_revision=2,
    )
    assert stale.status_code == 409, stale.text
    wrong_target = _deployment(
        client, name="wrong-target", version_id=version["id"],
        device=device, target={"url": "https://inventory.example.test/assets", "device_id": "other"},
    )
    assert wrong_target.status_code == 422, wrong_target.text
    wrong_site = _deployment(
        client, name="wrong-site", version_id=version["id"],
        device=device, target={"url": "https://inventory.example.test/assets", "site": "OTHER"},
    )
    assert wrong_site.status_code == 422, wrong_site.text


def test_metadata_edit_preserves_binding_but_identity_change_invalidates_runtime(client):
    device = _device(client)
    _, version = publish_collector(client)
    scheduled = _deployment(
        client, name="bound-scheduled", version_id=version["id"], device=device,
    )
    assert scheduled.status_code == 201, scheduled.text
    on_demand = _deployment(
        client, name="bound-on-demand", version_id=version["id"],
        device=device, mode="on_demand",
    )
    assert on_demand.status_code == 201, on_demand.text

    metadata = client.patch(
        f"/api/v1/assets/devices/{device['id']}/metadata",
        json={
            "expected_revision": device["revision"], "kind": "switch",
            "vendor": "Test Vendor", "labels": {}, "actor": "identity.test",
        },
    )
    assert metadata.status_code == 200, metadata.text
    assert metadata.json()["revision"] == 2
    assert metadata.json()["identity_revision"] == 1
    trigger = client.post(
        f"/api/v1/collector-deployments/{on_demand.json()['id']}/trigger",
        json={"actor": "identity.test", "reason": "Verify binding after metadata edit"},
    )
    assert trigger.status_code == 200, trigger.text

    with SessionLocal() as db:
        for deployment_id in (scheduled.json()["id"], on_demand.json()["id"]):
            deployment = db.get(CollectorDeployment, deployment_id)
            deployment.enabled = False
            deployment.next_run_at = None
        db.commit()
    updated_device = metadata.json()
    correction_request = _request(updated_device)
    preview = _preview(client, updated_device, correction_request).json()
    assert preview["can_commit"] is True, preview
    corrected = _commit(client, updated_device, correction_request, preview)
    assert corrected.status_code == 200, corrected.text
    assert corrected.json()["identity_revision"] == 2

    old_epoch = _deployment(
        client, name="old-epoch", version_id=version["id"], device=device,
    )
    assert old_epoch.status_code == 409, old_epoch.text
    with SessionLocal() as db:
        for deployment_id in (scheduled.json()["id"], on_demand.json()["id"]):
            deployment = db.get(CollectorDeployment, deployment_id)
            deployment.enabled = True  # Simulate a stale external re-enable.
            if deployment_id == scheduled.json()["id"]:
                deployment.next_run_at = deployment.created_at
        db.commit()

    stale_trigger = client.post(
        f"/api/v1/collector-deployments/{on_demand.json()['id']}/trigger",
        json={"actor": "identity.test", "reason": "Try stale target"},
    )
    assert stale_trigger.status_code == 409, stale_trigger.text
    worker, headers = register_collector_worker(
        client, name="bound-worker-lab", site="LAB",
    )
    claim = client.post(
        f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60}, headers=headers,
    )
    assert claim.status_code == 200, claim.text
    assert claim.json() == []
    with SessionLocal() as db:
        stale = db.get(CollectorDeployment, scheduled.json()["id"])
        assert stale.enabled is False
        assert stale.lease_token_hash is None
    current = corrected.json()
    fresh = _deployment(
        client, name="fresh-epoch", version_id=version["id"],
        device=current, mode="on_demand",
    )
    assert fresh.status_code == 201, fresh.text
    assert fresh.json()["scope_device_identity_revision"] == 2


def test_unreviewed_legacy_epoch_never_claims_even_if_device_row_is_corrupt(client):
    device = _device(client)
    _, version = publish_collector(client)
    deployment = _deployment(
        client, name="unreviewed-legacy", version_id=version["id"], device=device,
    )
    assert deployment.status_code == 201, deployment.text
    with SessionLocal() as db:
        from icheck.models import Device

        db.get(Device, device["id"]).identity_revision = 0
        db.get(CollectorDeployment, deployment.json()["id"]).scope_device_identity_revision = 0
        db.commit()
    worker, headers = register_collector_worker(
        client, name="legacy-worker-lab", site="LAB",
    )
    claim = client.post(
        f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60}, headers=headers,
    )
    assert claim.status_code == 200, claim.text
    assert claim.json() == []
