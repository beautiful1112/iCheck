from __future__ import annotations

import base64
import copy
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from icheck.services.artifact_portability import (
    trusted_digest_signature_message,
)
from icheck.services.snmp_exporter_attestations import (
    attestation_statement_digest,
)
from icheck.database import SessionLocal
from icheck.models import ArtifactVersion
from icheck.services.collectors import publish_artifact_version
from icheck.snmp_attestation_schemas import (
    SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT,
    SNMPExporterAttestationStatement,
)
from test_capability_studio import (
    FakeStructuredOpener,
    MIB_PROPOSAL_SPEC,
    configure_authoring_route,
)
from test_mib_ingestion import ACME_MIB


REGISTRATION_HEADERS = {
    "X-iCheck-Registration-Token": "test-registration-token"
}


def _proposal(client, monkeypatch):
    configure_authoring_route(client)
    opener = FakeStructuredOpener([MIB_PROPOSAL_SPEC])
    monkeypatch.setattr(
        "icheck.services.structured_model.build_opener",
        lambda *_handlers: opener,
    )
    created = client.post(
        "/api/v1/capability-studio/sessions",
        json={
            "title": "ACME sensor MIB attestation",
            "brief": "Propose a bounded SNMP Exporter module for ACME sensors.",
            "mib_input": {"mib_document_text": ACME_MIB},
            "created_by": "capability.author",
        },
    )
    assert created.status_code == 201, created.text
    generated = client.post(
        f"/api/v1/capability-studio/sessions/{created.json()['id']}/generate",
        json={"actor": "capability.author"},
    )
    assert generated.status_code == 200, generated.text
    session = generated.json()
    artifact = client.get(
        f"/api/v1/artifacts/{session['artifact_id']}"
    ).json()
    return artifact, artifact["versions"][0]


def _attestor_key(client, *, purposes=None, name="lab-snmp-attestor"):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    fingerprint = hashlib.sha256(raw_public_key).hexdigest()
    registered = client.post(
        "/api/v1/artifact-trust-keys",
        json={
            "name": name,
            "public_key_pem": public_pem,
            "purposes": purposes or ["snmp_exporter_attestation"],
            "created_by": "platform.admin",
        },
    )
    assert registered.status_code == 201, registered.text
    return private_key, registered.json(), fingerprint


def _statement(version):
    now = datetime.now(UTC)
    report = version["validation_report"]
    return {
        "format_version": "icheck.snmp-exporter-attestation/v1",
        "proposal_artifact_id": version["artifact_id"],
        "proposal_version_id": version["id"],
        "proposal_version": version["version"],
        "proposal_content_hash": version["content_hash"],
        "mib_document_sha256": report["mib_document_sha256"],
        "generator_module_sha256": report["generator_module_sha256"],
        "exporter_module_name": MIB_PROPOSAL_SPEC["exporter_module_name"],
        "generator_name": "prometheus/snmp_exporter/generator",
        "generator_version": "0.30.1",
        "generator_binary_sha256": "1" * 64,
        "generated_config_sha256": "2" * 64,
        "installed_config_sha256": "2" * 64,
        "exporter_version": "0.30.1",
        "exporter_binary_sha256": "3" * 64,
        "installation_id": "lab-snmp-exporter-01",
        "target_sha256": hashlib.sha256(b"192.0.2.55").hexdigest(),
        "auth_module_sha256": hashlib.sha256(b"lab_v3").hexdigest(),
        "successful_scrapes": 3,
        "sample_count": 42,
        "series_count": 18,
        "label_name_count": 7,
        "maximum_scrape_duration_ms": 850,
        "timed_out_scrapes": 0,
        "evidence_sha256": "4" * 64,
        "tested_at": (now - timedelta(minutes=2)).isoformat(),
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=2)).isoformat(),
        "nonce": "snmp-attestation-nonce-0001",
    }


def _signed_payload(private_key, fingerprint, statement):
    typed = SNMPExporterAttestationStatement.model_validate(statement)
    digest = attestation_statement_digest(typed)
    signature = private_key.sign(
        trusted_digest_signature_message(
            SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT,
            digest,
        )
    )
    return {
        "signed_attestation": {
            "format_version": SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT,
            "statement": statement,
            "digest_sha256": digest,
            "signature": {
                "algorithm": "ed25519",
                "key_fingerprint_sha256": fingerprint,
                "signed_digest_sha256": digest,
                "signature_base64": base64.b64encode(signature).decode("ascii"),
            },
        },
        "actor": "capability.attestation_reviewer",
    }


def _accept(client, monkeypatch):
    artifact, proposal = _proposal(client, monkeypatch)
    private_key, key, fingerprint = _attestor_key(client)
    payload = _signed_payload(private_key, fingerprint, _statement(proposal))
    accepted = client.post(
        "/api/v1/snmp-exporter-attestations",
        json=payload,
    )
    assert accepted.status_code == 201, accepted.text
    return artifact, proposal, key, payload, accepted.json()


def test_signed_attestation_creates_validated_canary_only_version(
    client,
    monkeypatch,
):
    artifact, proposal, _key, payload, attestation = _accept(
        client,
        monkeypatch,
    )
    assert attestation["proposal_version_id"] == proposal["id"]
    assert attestation["statement"]["target_sha256"] == hashlib.sha256(
        b"192.0.2.55"
    ).hexdigest()
    versions = client.get(f"/api/v1/artifacts/{artifact['id']}").json()[
        "versions"
    ]
    assert [item["status"] for item in versions] == ["validated", "validated"]
    deployable = versions[1]
    assert deployable["id"] == attestation["deployable_version_id"]
    assert deployable["definition"]["schema"] == (
        "icheck.snmp-exporter-attested/v1"
    )
    assert deployable["validation_report"]["canary_required"] is True
    assert deployable["validation_report"]["publication_blocker"] == (
        "collector_canary_required"
    )

    bypass = client.post(
        f"/api/v1/artifact-versions/{deployable['id']}/publish",
        json={"actor": "capability.publisher"},
    )
    assert bypass.status_code == 409
    assert "live collector canary" in bypass.text

    replay = client.post(
        "/api/v1/snmp-exporter-attestations",
        json=payload,
    )
    assert replay.status_code == 409, replay.text
    assert "already been used" in replay.text
    versions_after = client.get(f"/api/v1/artifacts/{artifact['id']}").json()[
        "versions"
    ]
    assert len(versions_after) == 2


def test_attestation_rejects_untrusted_purpose_and_tampering(client, monkeypatch):
    _artifact, proposal = _proposal(client, monkeypatch)
    private_key, _key, fingerprint = _attestor_key(
        client,
        purposes=["artifact_bundle"],
        name="wrong-purpose-snmp-key",
    )
    statement = _statement(proposal)
    wrong_purpose = client.post(
        "/api/v1/snmp-exporter-attestations",
        json=_signed_payload(private_key, fingerprint, statement),
    )
    assert wrong_purpose.status_code == 422, wrong_purpose.text
    assert "not authorized for snmp_exporter_attestation" in wrong_purpose.text

    private_key, _key, fingerprint = _attestor_key(
        client,
        name="correct-purpose-snmp-key",
    )
    payload = _signed_payload(private_key, fingerprint, statement)
    tampered = copy.deepcopy(payload)
    tampered["signed_attestation"]["statement"]["sample_count"] = 43
    rejected = client.post(
        "/api/v1/snmp-exporter-attestations",
        json=tampered,
    )
    assert rejected.status_code == 422, rejected.text
    assert "digest does not match" in rejected.text

    drifted = copy.deepcopy(statement)
    drifted["proposal_content_hash"] = "f" * 64
    binding = client.post(
        "/api/v1/snmp-exporter-attestations",
        json=_signed_payload(private_key, fingerprint, drifted),
    )
    assert binding.status_code == 422, binding.text
    assert "exact proposal evidence" in binding.text


def test_revoked_attestor_key_blocks_canary_promotion(client, monkeypatch):
    _artifact, _proposal_version, key, _payload, attestation = _accept(
        client,
        monkeypatch,
    )
    revoked = client.post(
        f"/api/v1/artifact-trust-keys/{key['id']}/revoke",
        json={"actor": "platform.admin"},
    )
    assert revoked.status_code == 200, revoked.text
    with SessionLocal() as db:
        version = db.get(ArtifactVersion, attestation["deployable_version_id"])
        assert version is not None
        with pytest.raises(ValueError, match="not trusted or has been revoked"):
            publish_artifact_version(
                db,
                version,
                "capability.publisher",
                canary_promotion=True,
            )


def test_attested_version_publishes_only_after_platform_canary(client, monkeypatch):
    artifact, proposal, _key, _payload, attestation = _accept(
        client,
        monkeypatch,
    )
    candidate_id = attestation["deployable_version_id"]
    created_device = client.post("/api/v1/assets/devices", json={
        "name": "acme-snmp-canary-switch",
        "kind": "switch",
        "management_ip": "192.0.2.55",
        "site": "LAB",
        "connections": [{"protocol": "icmp"}],
        "created_by": "capability.reviewer",
    })
    assert created_device.status_code == 201, created_device.text
    device = created_device.json()
    rollout_response = client.post(
        "/api/v1/collector-canary-rollouts",
        json={
            "name": "acme-snmp-attested-canary",
            "artifact_version_id": candidate_id,
            "target_classification": "registered_device",
            "scope_device_id": device["id"],
            "scope_device_identity_revision": device["identity_revision"],
            "scope_site": "LAB",
            "target": {
                "exporter_url": "http://127.0.0.1:9116",
                "target": "192.0.2.55",
            },
            "configuration": {
                "modules": ["acme_sensors"],
                "auth_module": "lab_v3",
            },
            "worker_selector": {"site": "LAB"},
            "schedule_seconds": 30,
            "timeout_seconds": 300,
            "min_successful_runs": 1,
            "max_failed_runs": 1,
            "min_records_per_run": 1,
            "actor": "capability.reviewer",
        },
    )
    assert rollout_response.status_code == 201, rollout_response.text
    rollout = rollout_response.json()

    registered = client.post(
        "/api/v1/collector-workers/register",
        json={
            "name": "snmp-canary-worker-lab",
            "site": "LAB",
            "capabilities": ["snmp_exporter"],
            "labels": {"io_supervisor_v1": True},
        },
        headers=REGISTRATION_HEADERS,
    )
    assert registered.status_code == 200, registered.text
    registration = registered.json()
    headers = {"Authorization": f"Bearer {registration['access_token']}"}
    worker_id = registration["worker"]["id"]
    claimed = client.post(
        f"/api/v1/collector-workers/{worker_id}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60},
        headers=headers,
    )
    assert claimed.status_code == 200, claimed.text
    assignment = claimed.json()[0]
    assert assignment["artifact_version_id"] == candidate_id
    admitted = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/admit",
        json={
            "lease_token": assignment["lease_token"],
            "assignment_sha256": assignment["assignment_sha256"],
        },
        headers=headers,
    )
    assert admitted.status_code == 200, admitted.text

    accepted = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/envelopes",
        json={
            "lease_token": assignment["lease_token"],
            "envelopes": [
                {
                    "kind": "observation",
                    "type": "metric.sample",
                    "source": "snmp_exporter:acme",
                    "subject": "192.0.2.55",
                    "payload": {
                        "metric": "acmeTemperature",
                        "value": 21,
                    },
                    "idempotency_key": "acme-temperature-1",
                }
            ],
        },
        headers=headers,
    )
    assert accepted.status_code == 200, accepted.text
    completed = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/complete",
        json={
            "lease_token": assignment["lease_token"],
            "status": "succeeded",
            "stats": {"source_status": 200},
        },
        headers=headers,
    )
    assert completed.status_code == 200, completed.text
    assert client.get(
        f"/api/v1/collector-canary-rollouts/{rollout['id']}"
    ).json()["status"] == "passed"

    promoted = client.post(
        f"/api/v1/collector-canary-rollouts/{rollout['id']}/promote",
        json={
            "actor": "capability.publisher",
            "reason": "Signed generator evidence and platform canary both passed.",
        },
    )
    assert promoted.status_code == 200, promoted.text
    assert promoted.json()["status"] == "promoted"
    versions = client.get(f"/api/v1/artifacts/{artifact['id']}").json()[
        "versions"
    ]
    by_id = {item["id"]: item for item in versions}
    assert by_id[candidate_id]["status"] == "published"
    assert by_id[proposal["id"]]["status"] == "validated"

    audit_text = str([
        event for event in client.get("/api/v1/audit-events?limit=1000").json()
        if event["entity_type"] != "device"
    ])
    assert "192.0.2.55" not in audit_text
    assert "lab_v3" not in audit_text
