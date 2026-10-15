from __future__ import annotations

import base64
import copy
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from icheck.config import get_settings
from icheck.services.artifact_portability import artifact_signature_message


def create_report_artifact(client):
    response = client.post(
        "/api/v1/artifacts",
        json={
            "name": "portable-health-report",
            "kind": "report",
            "description": "Portable health summary contract.",
            "owner": "capability.author",
            "labels": {"domain": "operations"},
            "initial_version": {
                "definition": {
                    "title": "Device health",
                    "sections": [
                        {"name": "identity", "fields": ["name", "kind"]}
                    ],
                },
                "implementation": {
                    "runtime": "declarative",
                    "template": "health-summary",
                },
                "tests": [
                    {
                        "name": "base contract",
                        "expected_sections": ["identity"],
                    }
                ],
                "created_by": "capability.author",
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def validate_version(client, version_id):
    response = client.post(
        f"/api/v1/artifact-versions/{version_id}/validate",
        json={"actor": "capability.validator"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_semantic_diff_is_stable_named_and_bounded(client):
    artifact = create_report_artifact(client)
    first = validate_version(client, artifact["versions"][0]["id"])
    second_response = client.post(
        f"/api/v1/artifacts/{artifact['id']}/versions",
        json={
            "definition": {
                "title": "Device health and alerts",
                "sections": [
                    {"name": "identity", "fields": ["name", "kind", "site"]},
                    {"name": "alerts", "fields": ["severity", "status"]},
                ],
            },
            "implementation": {
                "runtime": "declarative",
                "template": "health-and-alert-summary",
            },
            "tests": [
                {
                    "name": "base contract",
                    "expected_sections": ["identity", "alerts"],
                }
            ],
            "created_by": "capability.author",
        },
    )
    assert second_response.status_code == 201, second_response.text
    second = validate_version(
        client,
        second_response.json()["versions"][1]["id"],
    )

    response = client.get(
        f"/api/v1/artifacts/{artifact['id']}/diff",
        params={"from_version": 1, "to_version": 2, "limit": 100},
    )
    assert response.status_code == 200, response.text
    diff = response.json()
    assert diff["from_content_hash"] == first["content_hash"]
    assert diff["to_content_hash"] == second["content_hash"]
    assert diff["truncated"] is False
    assert diff["change_count"] >= 5
    paths = {item["path"] for item in diff["changes"]}
    assert "$/definition/title" in paths
    assert "$/definition/sections[by=name]/alerts" in paths
    assert (
        "$/definition/sections[by=name]/identity/fields/2" in paths
    )

    bounded = client.get(
        f"/api/v1/artifacts/{artifact['id']}/diff",
        params={"from_version": 1, "to_version": 2, "limit": 2},
    )
    assert bounded.status_code == 200, bounded.text
    assert bounded.json()["truncated"] is True
    assert bounded.json()["change_count"] == 2


def test_export_import_verifies_digest_and_revalidates_content(client):
    artifact = create_report_artifact(client)
    version = validate_version(client, artifact["versions"][0]["id"])
    exported = client.get(
        f"/api/v1/artifact-versions/{version['id']}/export"
    )
    assert exported.status_code == 200, exported.text
    bundle = exported.json()
    assert bundle["format_version"] == "icheck.artifact.bundle/v1"
    assert bundle["source"]["content_hash"] == version["content_hash"]
    assert len(bundle["digest_sha256"]) == 64
    assert "validation_report" not in bundle["version"]

    imported_response = client.post(
        "/api/v1/artifact-imports",
        json={
            "bundle": bundle,
            "name_override": "imported-health-report",
            "created_by": "capability.importer",
        },
    )
    assert imported_response.status_code == 201, imported_response.text
    imported = imported_response.json()
    assert imported["name"] == "imported-health-report"
    assert imported["kind"] == "report"
    assert imported["owner"] == "capability.importer"
    assert imported["labels"]["imported"] is True
    assert imported["versions"][0]["status"] == "validated"
    assert imported["versions"][0]["content_hash"] == version["content_hash"]

    tampered = copy.deepcopy(bundle)
    tampered["version"]["definition"]["title"] = "Tampered title"
    rejected = client.post(
        "/api/v1/artifact-imports",
        json={
            "bundle": tampered,
            "name_override": "tampered-health-report",
            "created_by": "capability.importer",
        },
    )
    assert rejected.status_code == 422, rejected.text
    assert "bundle digest does not match" in rejected.text
    listed = client.get("/api/v1/artifacts").json()
    assert "tampered-health-report" not in {item["name"] for item in listed}


def test_export_rejects_draft_and_collector_round_trip_preserves_contract(client):
    draft = create_report_artifact(client)
    denied = client.get(
        f"/api/v1/artifact-versions/{draft['versions'][0]['id']}/export"
    )
    assert denied.status_code == 409, denied.text

    collector_response = client.post(
        "/api/v1/artifacts",
        json={
            "name": "portable-builtin-collector",
            "kind": "collector",
            "description": "Portable trusted built-in test collector.",
            "owner": "capability.author",
            "labels": {"protocol": "test"},
            "initial_version": {
                "definition": {"purpose": "Collect bounded test state."},
                "implementation": {
                    "runtime": "builtin",
                    "adapter": "test_builtin",
                },
                "tests": [{"name": "contract declared"}],
                "created_by": "capability.author",
                "collector_definition": {
                    "adapter_type": "test_builtin",
                    "mode": "poll",
                    "output_kinds": ["observation"],
                    "credential_profile_ref": None,
                    "config_schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {},
                    },
                    "target_schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {},
                    },
                    "defaults": {"max_records": 100},
                },
            },
        },
    )
    assert collector_response.status_code == 201, collector_response.text
    collector = collector_response.json()
    validated = validate_version(client, collector["versions"][0]["id"])
    exported = client.get(
        f"/api/v1/artifact-versions/{validated['id']}/export"
    )
    assert exported.status_code == 200, exported.text
    bundle = exported.json()
    imported_response = client.post(
        "/api/v1/artifact-imports",
        json={
            "bundle": bundle,
            "name_override": "imported-builtin-collector",
            "created_by": "capability.importer",
        },
    )
    assert imported_response.status_code == 201, imported_response.text
    imported = imported_response.json()
    imported_version = imported["versions"][0]
    assert imported_version["content_hash"] == validated["content_hash"]
    source_definition = collector["versions"][0]["collector_definition"]
    imported_definition = imported_version["collector_definition"]
    portable_fields = {
        "adapter_type",
        "mode",
        "output_kinds",
        "credential_profile_ref",
        "config_schema",
        "target_schema",
        "defaults",
    }
    assert {
        key: imported_definition[key] for key in portable_fields
    } == {
        key: source_definition[key] for key in portable_fields
    }


def test_restore_creates_revalidated_immutable_candidate_before_publish(client):
    artifact = create_report_artifact(client)
    first = validate_version(client, artifact["versions"][0]["id"])
    first_publish = client.post(
        f"/api/v1/artifact-versions/{first['id']}/publish",
        json={"actor": "capability.publisher"},
    )
    assert first_publish.status_code == 200, first_publish.text
    second_response = client.post(
        f"/api/v1/artifacts/{artifact['id']}/versions",
        json={
            "definition": {"title": "Changed health report", "sections": []},
            "implementation": {
                "runtime": "declarative",
                "template": "changed-health-summary",
            },
            "tests": [{"name": "changed contract"}],
            "created_by": "capability.author",
        },
    )
    assert second_response.status_code == 201, second_response.text
    second = validate_version(client, second_response.json()["versions"][1]["id"])
    second_publish = client.post(
        f"/api/v1/artifact-versions/{second['id']}/publish",
        json={"actor": "capability.publisher"},
    )
    assert second_publish.status_code == 200, second_publish.text

    restored_response = client.post(
        f"/api/v1/artifacts/{artifact['id']}/restore-candidates",
        json={
            "source_version": 1,
            "reason": "Version two regressed the expected report structure.",
            "actor": "capability.operator",
        },
    )
    assert restored_response.status_code == 201, restored_response.text
    restored = restored_response.json()
    assert restored["version"] == 3
    assert restored["status"] == "validated"
    assert restored["content_hash"] == first["content_hash"]

    before_publish = client.get(f"/api/v1/artifacts/{artifact['id']}").json()
    assert [item["status"] for item in before_publish["versions"]] == [
        "deprecated",
        "published",
        "validated",
    ]
    publish_restore = client.post(
        f"/api/v1/artifact-versions/{restored['id']}/publish",
        json={"actor": "capability.publisher"},
    )
    assert publish_restore.status_code == 200, publish_restore.text
    after_publish = client.get(f"/api/v1/artifacts/{artifact['id']}").json()
    assert [item["status"] for item in after_publish["versions"]] == [
        "deprecated",
        "deprecated",
        "published",
    ]


def test_signed_import_verifies_ed25519_trust_and_persists_provenance(
    client,
    monkeypatch,
):
    artifact = create_report_artifact(client)
    version = validate_version(client, artifact["versions"][0]["id"])
    bundle = client.get(
        f"/api/v1/artifact-versions/{version['id']}/export"
    ).json()

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
            "name": "test-release-key",
            "public_key_pem": public_pem,
            "created_by": "platform.admin",
        },
    )
    assert registered.status_code == 201, registered.text
    key = registered.json()
    assert key["fingerprint_sha256"] == fingerprint
    assert "PRIVATE" not in key["public_key_pem"]

    signature = private_key.sign(
        artifact_signature_message(bundle["digest_sha256"])
    )
    signed_bundle = {
        "format_version": "icheck.artifact.signed-bundle/v1",
        "bundle": bundle,
        "signature": {
            "algorithm": "ed25519",
            "key_fingerprint_sha256": fingerprint,
            "signed_digest_sha256": bundle["digest_sha256"],
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        },
    }
    imported_response = client.post(
        "/api/v1/artifact-signed-imports",
        json={
            "signed_bundle": signed_bundle,
            "name_override": "signed-health-report",
            "created_by": "capability.importer",
        },
    )
    assert imported_response.status_code == 201, imported_response.text
    imported = imported_response.json()
    assert imported["labels"]["signature_verified"] is True
    assert imported["labels"]["signing_key_fingerprint"] == fingerprint
    imported_version = imported["versions"][0]
    provenance = client.get(
        f"/api/v1/artifact-versions/{imported_version['id']}/signature-verification"
    )
    assert provenance.status_code == 200, provenance.text
    assert provenance.json()["trust_key_id"] == key["id"]
    assert provenance.json()["bundle_digest_sha256"] == bundle["digest_sha256"]

    tampered = copy.deepcopy(signed_bundle)
    tampered_signature = bytearray(signature)
    tampered_signature[0] ^= 1
    tampered["signature"]["signature_base64"] = base64.b64encode(
        bytes(tampered_signature)
    ).decode("ascii")
    rejected = client.post(
        "/api/v1/artifact-signed-imports",
        json={
            "signed_bundle": tampered,
            "name_override": "tampered-signed-report",
            "created_by": "capability.importer",
        },
    )
    assert rejected.status_code == 422
    assert "signature verification failed" in rejected.text

    revoked = client.post(
        f"/api/v1/artifact-trust-keys/{key['id']}/revoke",
        json={"actor": "platform.admin"},
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["enabled"] is False
    denied = client.post(
        "/api/v1/artifact-signed-imports",
        json={
            "signed_bundle": signed_bundle,
            "name_override": "revoked-key-report",
            "created_by": "capability.importer",
        },
    )
    assert denied.status_code == 422
    assert "not trusted or has been revoked" in denied.text

    monkeypatch.setattr(get_settings(), "artifact_signature_policy", "required")
    unsigned = client.post(
        "/api/v1/artifact-imports",
        json={
            "bundle": bundle,
            "name_override": "unsigned-policy-report",
            "created_by": "capability.importer",
        },
    )
    assert unsigned.status_code == 422
    assert "requires a trusted signed bundle" in unsigned.text
