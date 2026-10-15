import json

import pytest

from icheck.collectors.http_json import collect_http_json
from icheck.database import SessionLocal
from icheck.models import CollectorRun


REGISTRATION_HEADERS = {
    "X-iCheck-Registration-Token": "test-registration-token"
}


def register_collector_worker(client, *, name, site):
    response = client.post(
        "/api/v1/collector-workers/register",
        json={
            "name": name,
            "site": site,
            "capabilities": ["http_json"],
            "labels": {
                "execution_admission_v1": True,
                "io_supervisor_v1": True,
            },
        },
        headers=REGISTRATION_HEADERS,
    )
    assert response.status_code == 200, response.text
    registration = response.json()
    return registration["worker"], {
        "Authorization": f"Bearer {registration['access_token']}"
    }


def collector_artifact_payload(name="internal-api"):
    return {
        "name": name,
        "kind": "collector",
        "description": "Collect records from an internal JSON API.",
        "owner": "platform-team",
        "labels": {"domain": "inventory"},
        "initial_version": {
            "definition": {
                "purpose": "Collect inventory records",
                "normalization": "one observation per record",
            },
            "implementation": {"runtime": "builtin", "adapter": "http_json"},
            "tests": [{"name": "sample payload", "fixture": {"items": []}}],
            "created_by": "capability.author",
            "collector_definition": {
                "adapter_type": "http_json",
                "mode": "poll",
                "output_kinds": ["observation"],
                "target_schema": {
                    "type": "object",
                    "required": ["url"],
                },
                "config_schema": {"type": "object"},
                "defaults": {
                    "records_path": "items",
                    "envelope_kind": "observation",
                    "record_type": "inventory.asset",
                    "subject_field": "id",
                    "idempotency_field": "id",
                },
            },
        },
    }


def publish_collector(client):
    response = client.post("/api/v1/artifacts", json=collector_artifact_payload())
    assert response.status_code == 201, response.text
    artifact = response.json()
    version = artifact["versions"][0]
    assert version["status"] == "draft"

    validated = client.post(
        f"/api/v1/artifact-versions/{version['id']}/validate",
        json={"actor": "capability.reviewer"},
    )
    assert validated.status_code == 200, validated.text
    assert validated.json()["status"] == "validated"
    assert len(validated.json()["content_hash"]) == 64
    assert validated.json()["validated_by"] == "capability.reviewer"

    published = client.post(
        f"/api/v1/artifact-versions/{version['id']}/publish",
        json={"actor": "capability.publisher"},
    )
    assert published.status_code == 200, published.text
    assert published.json()["status"] == "published"
    assert published.json()["published_by"] == "capability.publisher"
    return artifact, published.json()


def test_artifact_lifecycle_requires_validation_and_rejects_inline_secrets(client):
    artifact, first_version = publish_collector(client)

    duplicate = client.post(
        "/api/v1/artifacts", json=collector_artifact_payload()
    )
    assert duplicate.status_code == 409

    unvalidated = client.post(
        f"/api/v1/artifacts/{artifact['id']}/versions",
        json={
            **collector_artifact_payload()["initial_version"],
            "created_by": "capability.author",
        },
    )
    assert unvalidated.status_code == 201, unvalidated.text
    second_version = unvalidated.json()["versions"][1]
    cannot_publish = client.post(
        f"/api/v1/artifact-versions/{second_version['id']}/publish",
        json={"actor": "capability.publisher"},
    )
    assert cannot_publish.status_code == 409
    assert first_version["status"] == "published"

    secret_payload = collector_artifact_payload(name="unsafe-api")
    secret_payload["initial_version"]["definition"]["token"] = "plaintext"
    rejected = client.post("/api/v1/artifacts", json=secret_payload)
    assert rejected.status_code == 422
    assert "secret reference" in rejected.text


def test_collector_worker_lease_envelope_and_completion_flow(client):
    artifact, version = publish_collector(client)
    deployment = client.post(
        "/api/v1/collector-deployments",
        json={
            "name": "inventory-hq",
            "artifact_version_id": version["id"],
            "target": {"url": "https://inventory.example.test/assets"},
            "configuration": {},
            "worker_selector": {"site": "HQ"},
            "schedule_seconds": 300,
            "created_by": "platform.operator",
        },
    )
    assert deployment.status_code == 201, deployment.text

    second_version = client.post(
        f"/api/v1/artifacts/{artifact['id']}/versions",
        json={
            **collector_artifact_payload()["initial_version"],
            "created_by": "capability.author",
        },
    ).json()["versions"][1]
    validated = client.post(
        f"/api/v1/artifact-versions/{second_version['id']}/validate",
        json={"actor": "capability.reviewer"},
    )
    assert validated.status_code == 200, validated.text
    published = client.post(
        f"/api/v1/artifact-versions/{second_version['id']}/publish",
        json={"actor": "capability.publisher"},
    )
    assert published.status_code == 200, published.text
    assert (
        client.get(f"/api/v1/artifacts/{artifact['id']}")
        .json()["versions"][0]["status"]
        == "deprecated"
    )

    first_worker, first_headers = register_collector_worker(
        client,
        name="collector-hq-01",
        site="HQ",
    )
    second_worker, second_headers = register_collector_worker(
        client,
        name="collector-hq-02",
        site="HQ",
    )
    wrong_site, wrong_site_headers = register_collector_worker(
        client,
        name="collector-sin-01",
        site="SIN",
    )
    wrong_site_claim = client.post(
        f"/api/v1/collector-workers/{wrong_site['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60},
        headers=wrong_site_headers,
    )
    assert wrong_site_claim.status_code == 200
    assert wrong_site_claim.json() == []

    claimed = client.post(
        f"/api/v1/collector-workers/{first_worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60},
        headers=first_headers,
    )
    assert claimed.status_code == 200, claimed.text
    assert len(claimed.json()) == 1
    assignment = claimed.json()[0]
    assert assignment["artifact_id"] == artifact["id"]
    assert assignment["artifact_version_id"] == version["id"]
    assert assignment["adapter_type"] == "http_json"
    assert assignment["output_kinds"] == ["observation"]

    double_claim = client.post(
        f"/api/v1/collector-workers/{second_worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60},
        headers=second_headers,
    )
    assert double_claim.status_code == 200
    assert double_claim.json() == []

    invalid_token = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/envelopes",
        json={
            "lease_token": "x" * 32,
            "envelopes": [
                {
                    "kind": "observation",
                    "type": "inventory.asset",
                    "source": "inventory-api",
                    "payload": {"id": "asset-1"},
                }
            ],
        },
        headers=first_headers,
    )
    assert invalid_token.status_code == 409

    envelope_batch = {
        "lease_token": assignment["lease_token"],
        "envelopes": [
            {
                "kind": "observation",
                "type": "inventory.asset",
                "source": "inventory-api",
                "subject": "asset-1",
                "idempotency_key": "asset-1:version-7",
                "payload": {"id": "asset-1", "version": 7},
            }
        ],
    }
    accepted = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/envelopes",
        json=envelope_batch,
        headers=first_headers,
    )
    duplicate = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/envelopes",
        json=envelope_batch,
        headers=first_headers,
    )
    assert accepted.json() == {"received": 1, "accepted": 1, "duplicates": 0}
    assert duplicate.json() == {"received": 1, "accepted": 0, "duplicates": 1}

    renewed = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/lease",
        json={"lease_token": assignment["lease_token"], "lease_seconds": 120},
        headers=first_headers,
    )
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["status"] == "running"

    completed = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/complete",
        json={
            "lease_token": assignment["lease_token"],
            "status": "succeeded",
            "stats": {"source_status": 200},
        },
        headers=first_headers,
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "succeeded"
    assert completed.json()["records_received"] == 1

    health = client.get("/api/v1/collectors/health")
    assert health.status_code == 200
    assert health.json() == {
        "workers_total": 3,
        "workers_online": 3,
        "workers_stale": 0,
        "deployments_total": 1,
        "deployments_enabled": 1,
        "deployments_leased": 0,
        "deployments_due": 0,
        "running_runs": 0,
        "failed_runs_last_hour": 0,
    }

    event_types = {
        item["event_type"]
        for item in client.get("/api/v1/audit-events").json()
    }
    assert {
        "artifact.created",
        "artifact.version.validated",
        "artifact.version.published",
        "collector.deployment.created",
        "collector.worker.registered",
        "collector.run.claimed",
        "collector.run.completed",
    } <= event_types


def test_legacy_worker_cannot_claim_regular_deployment(client):
    _, version = publish_collector(client)
    deployment = client.post("/api/v1/collector-deployments", json={
        "name": "legacy-gate-internal",
        "artifact_version_id": version["id"],
        "target": {"url": "https://inventory.example.test/assets"},
        "configuration": {},
        "worker_selector": {"site": "HQ"},
        "created_by": "platform.operator",
    })
    assert deployment.status_code == 201, deployment.text
    registered = client.post("/api/v1/collector-workers/register", json={
        "name": "legacy-collector", "site": "HQ",
        "capabilities": ["http_json"],
        "labels": {"execution_admission_v1": True},
    }, headers=REGISTRATION_HEADERS)
    assert registered.status_code == 200, registered.text
    worker = registered.json()["worker"]
    headers = {"Authorization": f"Bearer {registered.json()['access_token']}"}
    refused = client.post(
        f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60}, headers=headers,
    )
    assert refused.status_code == 200, refused.text
    assert refused.json() == []


@pytest.mark.parametrize("adapter", ["icmp", "ssh", "node_exporter", "cadvisor", "vmware_exporter"])
def test_monitoring_preflight_capability_cannot_claim_regular_deployment(client, adapter):
    from sqlalchemy import select
    from icheck.models import CollectorDefinition, CollectorWorker
    _, version = publish_collector(client)
    deployment = client.post("/api/v1/collector-deployments", json={
        "artifact_version_id": version["id"], "name": "preflight-only-fixture",
        "target": {"url": "https://inventory.example.test/assets"},
        "schedule_seconds": 60, "created_by": "platform.operator",
    })
    assert deployment.status_code == 201, deployment.text
    worker, headers = register_collector_worker(client, name="monitoring-preflight-worker", site="LAB")
    # A mistakenly scheduled endpoint must not acquire a routine envelope lease
    # merely because this worker advertises a metric-test executor. No I/O runs.
    with SessionLocal() as db:
        db.scalar(select(CollectorDefinition).where(
            CollectorDefinition.artifact_version_id == version["id"])).adapter_type = adapter
        db.get(CollectorWorker, worker["id"]).capabilities = [adapter]
        db.commit()
    response = client.post(f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json() == []


def test_lost_supervisor_marker_denies_active_run_mutations(client):
    _, version = publish_collector(client)
    deployment = client.post("/api/v1/collector-deployments", json={
        "name": "supervisor-marker-drift",
        "artifact_version_id": version["id"],
        "target": {"url": "https://inventory.example.test/assets"},
        "configuration": {},
        "worker_selector": {"site": "HQ"},
        "created_by": "platform.operator",
    })
    assert deployment.status_code == 201, deployment.text
    worker, headers = register_collector_worker(
        client, name="supervisor-marker-worker", site="HQ",
    )
    claimed = client.post(
        f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60}, headers=headers,
    )
    assert claimed.status_code == 200, claimed.text
    assignment = claimed.json()[0]
    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        run.worker.labels = {"execution_admission_v1": True}
        db.commit()
    denied = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/lease",
        json={"lease_token": assignment["lease_token"], "lease_seconds": 60},
        headers=headers,
    )
    assert denied.status_code == 409, denied.text
    assert "requires supervised adapter I/O" in denied.text


def test_worker_registration_authentication_and_token_rotation(client):
    payload = {
        "name": "collector-rotation-01",
        "site": "HQ",
        "capabilities": ["http_json"],
    }
    missing = client.post(
        "/api/v1/collector-workers/register",
        json=payload,
    )
    invalid = client.post(
        "/api/v1/collector-workers/register",
        json=payload,
        headers={"X-iCheck-Registration-Token": "wrong"},
    )
    assert missing.status_code == 401
    assert invalid.status_code == 401

    first = client.post(
        "/api/v1/collector-workers/register",
        json=payload,
        headers=REGISTRATION_HEADERS,
    ).json()
    worker_id = first["worker"]["id"]
    first_headers = {
        "Authorization": f"Bearer {first['access_token']}"
    }
    heartbeat = client.post(
        f"/api/v1/collector-workers/{worker_id}/heartbeat",
        json={"state": "online"},
        headers=first_headers,
    )
    assert heartbeat.status_code == 200

    second = client.post(
        "/api/v1/collector-workers/register",
        json=payload,
        headers=REGISTRATION_HEADERS,
    ).json()
    assert second["worker"]["id"] == worker_id
    assert second["access_token"] != first["access_token"]
    old_token = client.post(
        f"/api/v1/collector-workers/{worker_id}/heartbeat",
        json={"state": "online"},
        headers=first_headers,
    )
    new_token = client.post(
        f"/api/v1/collector-workers/{worker_id}/heartbeat",
        json={"state": "online"},
        headers={"Authorization": f"Bearer {second['access_token']}"},
    )
    assert old_token.status_code == 401
    assert new_token.status_code == 200


def test_json_schema_is_enforced_for_artifacts_and_deployments(client):
    remote_ref = collector_artifact_payload("remote-schema")
    remote_ref["initial_version"]["collector_definition"]["target_schema"] = {
        "$ref": "https://untrusted.example/schema.json"
    }
    created = client.post("/api/v1/artifacts", json=remote_ref)
    version_id = created.json()["versions"][0]["id"]
    rejected_schema = client.post(
        f"/api/v1/artifact-versions/{version_id}/validate",
        json={"actor": "capability.reviewer"},
    )
    assert rejected_schema.status_code == 422
    assert "only local JSON Schema references" in rejected_schema.text

    _, version = publish_collector(client)
    rejected_target = client.post(
        "/api/v1/collector-deployments",
        json={
            "name": "missing-target-url",
            "artifact_version_id": version["id"],
            "target": {},
            "configuration": {},
            "worker_selector": {},
            "schedule_seconds": 300,
            "created_by": "platform.operator",
        },
    )
    assert rejected_target.status_code == 422
    assert "'url' is a required property" in rejected_target.text


def test_credential_profiles_authorize_adapter_and_worker_scope(client):
    profile = client.post(
        "/api/v1/credential-profiles",
        json={
            "name": "inventory-readonly",
            "provider": "vault",
            "secret_ref": "kv/network/inventory-readonly",
            "allowed_adapters": ["snmp"],
            "worker_selector": {"site": "HQ"},
            "created_by": "security.operator",
        },
    )
    assert profile.status_code == 201, profile.text
    assert profile.json()["revision"] == 0
    assert "password" not in profile.text.lower()

    artifact_payload = collector_artifact_payload("credentialed-api")
    artifact_payload["initial_version"]["collector_definition"][
        "credential_profile_ref"
    ] = "inventory-readonly"
    artifact = client.post("/api/v1/artifacts", json=artifact_payload).json()
    version_id = artifact["versions"][0]["id"]
    assert client.post(
        f"/api/v1/artifact-versions/{version_id}/validate",
        json={"actor": "capability.reviewer"},
    ).status_code == 200
    assert client.post(
        f"/api/v1/artifact-versions/{version_id}/publish",
        json={"actor": "capability.publisher"},
    ).status_code == 200

    disallowed = client.post(
        "/api/v1/collector-deployments",
        json={
            "name": "credentialed-inventory",
            "artifact_version_id": version_id,
            "target": {"url": "https://inventory.example.test/assets"},
            "configuration": {},
            "worker_selector": {"site": "HQ"},
            "schedule_seconds": 300,
            "created_by": "platform.operator",
        },
    )
    assert disallowed.status_code == 422
    assert "does not allow adapter" in disallowed.text


def test_http_json_adapter_normalizes_records(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, _limit):
            return json.dumps(
                {
                    "items": [
                        {
                            "id": "edge-01",
                            "observed_at": "2026-09-15T15:00:00Z",
                            "cpu": 41,
                        }
                    ]
                }
            ).encode()

    class FakeOpener:
        def open(self, request, timeout):
            return FakeResponse()

    monkeypatch.setattr(
        "icheck.collectors.http_json.build_opener",
        lambda *handlers: FakeOpener(),
    )
    envelopes = collect_http_json(
        {
            "artifact_name": "device-health",
            "output_kinds": ["observation"],
            "target": {"url": "https://monitoring.example.test/devices"},
            "defaults": {
                "records_path": "items",
                "envelope_kind": "observation",
                "record_type": "device.health",
                "subject_field": "id",
                "idempotency_field": "id",
                "observed_at_field": "observed_at",
            },
            "configuration": {},
            "_runtime": {
                "http_allowed_hosts": ["monitoring.example.test"],
                "lease_seconds": 60,
            },
        }
    )
    assert envelopes == [
        {
            "kind": "observation",
            "type": "device.health",
            "source": "artifact:device-health",
            "subject": "edge-01",
            "observed_at": "2026-09-15T15:00:00+00:00",
            "payload": {
                "id": "edge-01",
                "observed_at": "2026-09-15T15:00:00Z",
                "cpu": 41,
            },
            "idempotency_key": "edge-01",
        }
    ]


def test_http_json_adapter_fails_closed_for_unapproved_host():
    with pytest.raises(ValueError, match="not in the worker allowlist"):
        collect_http_json(
            {
                "artifact_name": "unsafe-target",
                "output_kinds": ["observation"],
                "target": {"url": "http://169.254.169.254/latest/meta-data"},
                "configuration": {},
                "_runtime": {
                    "http_allowed_hosts": [],
                    "lease_seconds": 60,
                },
            }
        )


def test_run_scoped_credential_grant_requires_worker_and_active_lease(client):
    profile = client.post(
        "/api/v1/credential-profiles",
        json={
            "name": "inventory-http-readonly",
            "provider": "vault",
            "secret_ref": "vault-kv2://kv/network/inventory#token",
            "allowed_adapters": ["http_json"],
            "worker_selector": {"site": "HQ"},
            "created_by": "security.operator",
        },
    )
    assert profile.status_code == 201, profile.text
    _, version = publish_collector(client)
    deployment = client.post(
        "/api/v1/collector-deployments",
        json={
            "name": "credentialed-http-hq",
            "artifact_version_id": version["id"],
            "target": {"url": "https://inventory.example.test/assets"},
            "configuration": {},
            "worker_selector": {"site": "HQ"},
            "credential_profile_ref": "inventory-http-readonly",
            "schedule_seconds": 300,
            "created_by": "platform.operator",
        },
    )
    assert deployment.status_code == 201, deployment.text
    worker, worker_headers = register_collector_worker(
        client, name="credential-worker-hq", site="HQ"
    )
    other_worker, other_headers = register_collector_worker(
        client, name="credential-worker-other", site="HQ"
    )
    claim = client.post(
        f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60},
        headers=worker_headers,
    )
    assert claim.status_code == 200, claim.text
    assignment = claim.json()[0]
    grant_url = (
        f"/api/v1/collector-runs/{assignment['run_id']}/credential-grant"
    )

    wrong_worker = client.post(
        grant_url,
        json={"lease_token": assignment["lease_token"]},
        headers=other_headers,
    )
    assert wrong_worker.status_code == 401

    wrong_lease = client.post(
        grant_url,
        json={"lease_token": "x" * 32},
        headers=worker_headers,
    )
    assert wrong_lease.status_code == 409

    grant = client.post(
        grant_url,
        json={"lease_token": assignment["lease_token"]},
        headers=worker_headers,
    )
    assert grant.status_code == 200, grant.text
    assert grant.json()["provider"] == "vault"
    assert grant.json()["profile_revision"] == 0
    assert grant.json()["adapter_type"] == "http_json"
    assert grant.json()["deployment_id"] == deployment.json()["id"]
    assert grant.json()["secret_ref"] == (
        "vault-kv2://kv/network/inventory#token"
    )

    rotated = client.post(
        f"/api/v1/credential-profiles/{profile.json()['id']}/rotate",
        json={
            "expected_revision": 0,
            "secret_ref": "vault-kv2://kv/network/inventory-v2#token",
            "reason": "Move to the second managed secret path.",
            "actor": "security.operator",
        },
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["revision"] == 1
    stale = client.post(
        f"/api/v1/credential-profiles/{profile.json()['id']}/rotate",
        json={
            "expected_revision": 0,
            "secret_ref": "vault-kv2://kv/network/inventory-v3#token",
            "reason": "Stale concurrent operation.",
            "actor": "security.operator",
        },
    )
    assert stale.status_code == 409
    renewed_grant = client.post(
        grant_url,
        json={"lease_token": assignment["lease_token"]},
        headers=worker_headers,
    )
    assert renewed_grant.status_code == 200, renewed_grant.text
    assert renewed_grant.json()["profile_revision"] == 1
    assert renewed_grant.json()["secret_ref"] == (
        "vault-kv2://kv/network/inventory-v2#token"
    )

    events = client.get(
        "/api/v1/audit-events?event_type=credential.grant.issued"
    ).json()
    assert len(events) == 2
    assert "secret_ref" not in events[0]["details"]
    assert "network/inventory" not in json.dumps(events[0])
    rotation_events = client.get(
        "/api/v1/audit-events?event_type=credential.profile.rotated"
    ).json()
    assert len(rotation_events) == 1
    assert rotation_events[0]["details"]["revision"] == 1
    assert "inventory-v2" not in json.dumps(rotation_events)
    assert "Move to the second" not in json.dumps(rotation_events)

    completed = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/complete",
        json={
            "lease_token": assignment["lease_token"],
            "status": "succeeded",
        },
        headers=worker_headers,
    )
    assert completed.status_code == 200, completed.text
    expired = client.post(
        grant_url,
        json={"lease_token": assignment["lease_token"]},
        headers=worker_headers,
    )
    assert expired.status_code == 409
