from __future__ import annotations

import json


class ReplayExecutor:
    def validate(self, implementation, tests, output_kinds):
        return {
            "runtime": "python_sandbox_v1",
            "isolation": "test_hardened_process",
            "network": "denied",
            "tests": [{"name": "contract", "passed": True}],
        }

    def transform(self, implementation, records, configuration, output_kinds):
        field_name = "site" if implementation["source"] == "version-one" else "location"
        return [
            {
                **record,
                "payload": {
                    **record["payload"],
                    "normalized_site": record["payload"].get(field_name),
                },
            }
            for record in records
        ]


def _collector_version(source):
    return {
        "definition": {"purpose": "Normalize historical device samples."},
        "implementation": {
            "runtime": "python_sandbox_v1",
            "adapter": "http_json_sandbox",
            "entrypoint": "transform",
            "source": source,
        },
        "tests": [
            {
                "name": "authoring fixture",
                "fixture": [],
                "configuration": {},
                "expected": [],
            }
        ],
        "created_by": "capability.author",
        "collector_definition": {
            "adapter_type": "http_json_sandbox",
            "mode": "poll",
            "output_kinds": ["observation"],
            "config_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            "target_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["url"],
                "properties": {"url": {"type": "string"}},
            },
            "defaults": {},
        },
    }


def _create_versions(client, monkeypatch):
    executor = ReplayExecutor()
    monkeypatch.setattr(
        "icheck.services.collectors.default_sandbox_executor",
        lambda: executor,
    )
    monkeypatch.setattr(
        "icheck.services.artifact_replay.default_sandbox_executor",
        lambda: executor,
    )
    created = client.post(
        "/api/v1/artifacts",
        json={
            "name": "historical-device-normalizer",
            "kind": "collector",
            "description": "Replay acceptance collector.",
            "owner": "capability.author",
            "labels": {"generated": True},
            "initial_version": _collector_version("version-one"),
        },
    )
    assert created.status_code == 201, created.text
    artifact = created.json()
    first_id = artifact["versions"][0]["id"]
    validated = client.post(
        f"/api/v1/artifact-versions/{first_id}/validate",
        json={"actor": "capability.reviewer"},
    )
    assert validated.status_code == 200, validated.text
    published = client.post(
        f"/api/v1/artifact-versions/{first_id}/publish",
        json={"actor": "capability.publisher"},
    )
    assert published.status_code == 200, published.text

    second = client.post(
        f"/api/v1/artifacts/{artifact['id']}/versions",
        json=_collector_version("version-two"),
    )
    assert second.status_code == 201, second.text
    second_id = next(
        item["id"]
        for item in second.json()["versions"]
        if item["version"] == 2
    )
    validated_second = client.post(
        f"/api/v1/artifact-versions/{second_id}/validate",
        json={"actor": "capability.reviewer"},
    )
    assert validated_second.status_code == 200, validated_second.text
    return artifact["id"], first_id, second_id


def _envelope(payload):
    return {
        "kind": "observation",
        "type": "device.sample",
        "source": "historical-lab",
        "subject": "router-raw-01",
        "payload": payload,
        "idempotency_key": "snapshot-1",
    }


def test_historical_replay_passes_published_and_blocks_regressed_candidate(
    client,
    monkeypatch,
):
    artifact_id, first_id, second_id = _create_versions(client, monkeypatch)
    input_envelope = _envelope({"hostname": "router-raw-01", "site": "LAB"})
    expected_envelope = _envelope(
        {
            "hostname": "router-raw-01",
            "site": "LAB",
            "normalized_site": "LAB",
        }
    )
    created = client.post(
        f"/api/v1/artifact-replay/artifacts/{artifact_id}/cases",
        json={
            "name": "lab-device-snapshot",
            "source_label": "sanitized-lab-capture-2026-09-24",
            "configuration": {},
            "input_envelopes": [input_envelope],
            "expected_envelopes": [expected_envelope],
            "actor": "capability.reviewer",
        },
    )
    assert created.status_code == 201, created.text
    case = created.json()
    assert case["input_count"] == 1
    assert len(case["input_sha256"]) == 64
    assert "input_envelopes" not in case

    passed = client.post(
        f"/api/v1/artifact-replay/cases/{case['id']}/runs",
        json={
            "artifact_version_id": first_id,
            "actor": "capability.reviewer",
        },
    )
    assert passed.status_code == 201, passed.text
    assert passed.json()["status"] == "passed"
    assert passed.json()["mismatch_count"] == 0
    assert passed.json()["report"]["matching_count"] == 1

    failed = client.post(
        f"/api/v1/artifact-replay/cases/{case['id']}/runs",
        json={
            "artifact_version_id": second_id,
            "actor": "capability.reviewer",
        },
    )
    assert failed.status_code == 201, failed.text
    regression = failed.json()
    assert regression["status"] == "failed"
    assert regression["mismatch_count"] == 1
    mismatch = regression["report"]["mismatches"][0]
    assert mismatch["index"] == 0
    assert mismatch["change_type"] == "changed"
    assert len(mismatch["expected_sha256"]) == 64
    assert len(mismatch["actual_sha256"]) == 64
    assert client.get(
        f"/api/v1/artifact-replay/cases/{case['id']}/runs"
    ).json()[0]["status"] == "failed"

    audits = client.get("/api/v1/audit-events?limit=1000").json()
    audit_text = json.dumps(audits)
    assert "router-raw-01" not in audit_text
    assert {
        "artifact.replay_case.created",
        "artifact.replay.completed",
    } <= {item["event_type"] for item in audits}


def test_replay_case_rejects_secret_shapes_and_wrong_artifact(client, monkeypatch):
    artifact_id, _first_id, _second_id = _create_versions(client, monkeypatch)
    unsafe = client.post(
        f"/api/v1/artifact-replay/artifacts/{artifact_id}/cases",
        json={
            "name": "unsafe-capture",
            "source_label": "must-fail",
            "input_envelopes": [_envelope({"password": "do-not-store"})],
            "expected_envelopes": [_envelope({"password": "do-not-store"})],
            "actor": "capability.reviewer",
        },
    )
    assert unsafe.status_code == 422
    assert "inline secret" in unsafe.text

    other = client.post(
        "/api/v1/artifacts",
        json={
            "name": "other-declarative-artifact",
            "kind": "report",
            "description": "Not a collector.",
            "owner": "capability.author",
            "initial_version": {
                "definition": {},
                "implementation": {},
                "tests": [],
                "created_by": "capability.author",
            },
        },
    )
    assert other.status_code == 201, other.text
    rejected = client.post(
        f"/api/v1/artifact-replay/artifacts/{other.json()['id']}/cases",
        json={
            "name": "wrong-kind",
            "source_label": "must-fail",
            "input_envelopes": [_envelope({"site": "LAB"})],
            "expected_envelopes": [_envelope({"site": "LAB"})],
            "actor": "capability.reviewer",
        },
    )
    assert rejected.status_code == 422
    assert "Collector Artifacts" in rejected.text
