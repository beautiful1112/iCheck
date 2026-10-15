import json
import subprocess
import sys
from pathlib import Path

import pytest

from icheck import sandbox_harness
from icheck.collectors.http_json_sandbox import collect_http_json_sandbox
from icheck.sandbox import (
    BubblewrapSandboxExecutor,
    HardenedProcessSandboxExecutor,
    SandboxRejected,
)


TRANSFORM_SOURCE = """\
def transform(records, configuration):
    result = []
    for envelope in records:
        item = envelope.copy()
        payload = item.get("payload").copy()
        payload["normalized_name"] = str(payload.get("name", "")).upper()
        item["payload"] = payload
        result.append(item)
    return result
"""


FIXTURE = [
    {
        "kind": "observation",
        "type": "inventory.asset",
        "source": "fixture",
        "subject": "edge-01",
        "payload": {"name": "edge-01"},
        "idempotency_key": "edge-01",
    }
]
EXPECTED = [
    {
        **FIXTURE[0],
        "payload": {"name": "edge-01", "normalized_name": "EDGE-01"},
    }
]


def invoke_harness(payload):
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(sandbox_harness.__file__)),
        ],
        input=json.dumps(payload).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=8,
        check=True,
    )
    return json.loads(completed.stdout)


def sandbox_request(source=TRANSFORM_SOURCE):
    return {
        "operation": "validate",
        "source": source,
        "entrypoint": "transform",
        "output_kinds": ["observation"],
        "tests": [
            {
                "name": "normalizes inventory name",
                "fixture": FIXTURE,
                "configuration": {},
                "expected": EXPECTED,
            }
        ],
    }


def test_harness_runs_deterministic_fixture_without_project_imports():
    result = invoke_harness(sandbox_request())
    assert result["ok"] is True
    assert result["tests"][0]["passed"] is True
    assert result["tests"][0]["output_count"] == 1
    assert len(result["tests"][0]["output_sha256"]) == 64


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (
            "import socket\ndef transform(records, configuration):\n return records",
            "only function definitions",
        ),
        (
            "def transform(records, configuration):\n return records.__class__",
            "method '__class__' is not allowed",
        ),
        (
            "def transform(records, configuration):\n"
            " while True:\n  records = records\n return records",
            "forbidden syntax: While",
        ),
        (
            "def transform(records, configuration):\n"
            " api_token = 'not-allowed'\n return records",
            "may not handle credential material",
        ),
    ],
)
def test_harness_rejects_hostile_or_unbounded_source(source, message):
    result = invoke_harness(sandbox_request(source))
    assert result["ok"] is False
    assert message in result["error"]


def test_bubblewrap_command_denies_network_and_mounts_only_runtime():
    executor = BubblewrapSandboxExecutor(
        bwrap_path="/usr/bin/bwrap",
        python_path="/usr/bin/python3",
        harness_path="/opt/icheck/sandbox_harness.py",
    )
    command = executor._command()
    assert "--unshare-all" in command
    assert "--share-net" not in command
    start = command.index("--ro-bind")
    assert ["--ro-bind", "/usr", "/usr"] == command[start : start + 3]
    assert "--cap-drop" in command
    assert command[-1] == "/sandbox/runner.py"


def test_implementation_contract_rejects_embedded_secret_literal():
    executor = HardenedProcessSandboxExecutor(python_path="/usr/bin/python3")
    with pytest.raises(SandboxRejected, match="credential literal"):
        executor.validate(
            {
                "runtime": "python_sandbox_v1",
                "adapter": "http_json_sandbox",
                "entrypoint": "transform",
                "source": (
                    "def transform(records, configuration):\n"
                    "    value = 'Authorization: Bearer abcdefghijklmnop'\n"
                    "    return records\n"
                ),
            },
            sandbox_request()["tests"],
            ["observation"],
        )


def test_real_hardened_executor_enforces_kernel_isolation_and_fixture():
    executor = HardenedProcessSandboxExecutor(
        python_path="/usr/bin/python3",
    )
    report = executor.validate(
        {
            "runtime": "python_sandbox_v1",
            "adapter": "http_json_sandbox",
            "entrypoint": "transform",
            "source": TRANSFORM_SOURCE,
        },
        sandbox_request()["tests"],
        ["observation"],
    )
    assert report["isolation"] == "landlock_seccomp_process"
    assert report["network"] == "denied"
    assert report["tests"][0]["passed"] is True
    probe = executor.isolation_probe()
    assert probe["filesystem_denied"] is True
    assert probe["network_denied"] is True
    assert probe["process_creation_denied"] is True
    assert probe["landlock_abi"] >= 1
    assert probe["seccomp"] is True


class DirectHarnessExecutor:
    def validate(self, implementation, tests, output_kinds):
        result = invoke_harness(
            {
                "operation": "validate",
                "source": implementation["source"],
                "entrypoint": implementation["entrypoint"],
                "output_kinds": output_kinds,
                "tests": tests,
            }
        )
        if not result["ok"]:
            raise SandboxRejected(result["error"])
        return {
            "runtime": "python_sandbox_v1",
            "isolation": "test_harness",
            "network": "denied_by_production_executor",
            "tests": result["tests"],
        }

    def transform(self, implementation, records, configuration, output_kinds):
        result = invoke_harness(
            {
                "operation": "transform",
                "source": implementation["source"],
                "entrypoint": implementation["entrypoint"],
                "output_kinds": output_kinds,
                "records": records,
                "configuration": configuration,
            }
        )
        if not result["ok"]:
            raise SandboxRejected(result["error"])
        return result["output"]


def sandbox_artifact_payload():
    return {
        "name": "generated-inventory-transformer",
        "kind": "collector",
        "description": "Trusted HTTP fetch plus isolated normalization.",
        "owner": "platform-team",
        "labels": {"generated": True},
        "initial_version": {
            "definition": {"purpose": "Normalize inventory records"},
            "implementation": {
                "runtime": "python_sandbox_v1",
                "adapter": "http_json_sandbox",
                "entrypoint": "transform",
                "source": TRANSFORM_SOURCE,
            },
            "tests": [
                {
                    "name": "normalizes inventory name",
                    "fixture": FIXTURE,
                    "configuration": {},
                    "expected": EXPECTED,
                }
            ],
            "created_by": "capability.author",
            "collector_definition": {
                "adapter_type": "http_json_sandbox",
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


def test_sandbox_artifact_must_pass_fixture_before_publish(client, monkeypatch):
    executor = DirectHarnessExecutor()
    monkeypatch.setattr(
        "icheck.services.collectors.default_sandbox_executor",
        lambda: executor,
    )
    created = client.post("/api/v1/artifacts", json=sandbox_artifact_payload())
    assert created.status_code == 201, created.text
    version_id = created.json()["versions"][0]["id"]
    validated = client.post(
        f"/api/v1/artifact-versions/{version_id}/validate",
        json={"actor": "capability.reviewer"},
    )
    assert validated.status_code == 200, validated.text
    report = validated.json()["validation_report"]
    assert report["runtime"] == "python_sandbox_v1"
    assert report["tests"][0]["passed"] is True
    assert client.post(
        f"/api/v1/artifact-versions/{version_id}/publish",
        json={"actor": "capability.publisher"},
    ).status_code == 200


class FakeHTTPResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, _limit):
        return b'{"items":[{"id":"edge-01","name":"edge-01"}]}'


class FakeHTTPOpener:
    def open(self, _request, timeout):
        assert timeout == 10
        return FakeHTTPResponse()


def test_sandbox_collector_uses_trusted_fetch_then_isolated_transform(monkeypatch):
    monkeypatch.setattr(
        "icheck.collectors.http_json.build_opener",
        lambda *_handlers: FakeHTTPOpener(),
    )
    assignment = {
        "artifact_name": "generated-inventory-transformer",
        "implementation": sandbox_artifact_payload()["initial_version"][
            "implementation"
        ],
        "output_kinds": ["observation"],
        "target": {"url": "https://inventory.example.test/assets"},
        "defaults": sandbox_artifact_payload()["initial_version"][
            "collector_definition"
        ]["defaults"],
        "configuration": {},
        "_runtime": {
            "http_allowed_hosts": ["inventory.example.test"],
            "lease_seconds": 60,
            "sandbox_executor": DirectHarnessExecutor(),
        },
    }
    envelopes = collect_http_json_sandbox(assignment)
    assert envelopes[0]["payload"]["normalized_name"] == "EDGE-01"


def test_published_studio_http_collector_activates_on_verified_https_device(
    client, monkeypatch,
):
    monkeypatch.setattr(
        "icheck.services.collectors.default_sandbox_executor",
        lambda: DirectHarnessExecutor(),
    )
    created = client.post("/api/v1/artifacts", json=sandbox_artifact_payload())
    assert created.status_code == 201, created.text
    version_id = created.json()["versions"][0]["id"]
    for action in ("validate", "publish"):
        response = client.post(
            f"/api/v1/artifact-versions/{version_id}/{action}",
            json={"actor": "capability.reviewer"},
        )
        assert response.status_code == 200, response.text

    catalog = client.get("/api/v1/assets/activation-collectors")
    assert catalog.status_code == 200, catalog.text
    assert catalog.json() == [{
        "artifact_version_id": version_id,
        "artifact_name": "generated-inventory-transformer",
        "version": 1,
        "adapter_type": "http_json_sandbox",
        "target_schema": {"type": "object", "required": ["url"]},
        "config_schema": {"type": "object"},
        "defaults": sandbox_artifact_payload()["initial_version"]["collector_definition"]["defaults"],
    }]
    assert "source" not in catalog.text

    policy_payload = {
        "name": "lab-controller-inventory",
        "protocol": "https_api",
        "artifact_version_id": version_id,
        "target_template": {
            "url": "https://${management_ip}:${port}/api/v1/inventory",
        },
        "configuration_defaults": {},
        "worker_selector": {"site": "${site}"},
        "execution_mode": "scheduled",
        "schedule_seconds": 300,
        "created_by": "lab.admin",
    }
    wrong_protocol = client.post(
        "/api/v1/assets/activation-policies",
        json={**policy_payload, "protocol": "snmp"},
    )
    assert wrong_protocol.status_code == 422
    assert "requires adapter" in wrong_protocol.text
    policy = client.post("/api/v1/assets/activation-policies", json=policy_payload)
    assert policy.status_code == 201, policy.text
    policy_id = policy.json()["id"]
    for action in ("validate", "publish"):
        response = client.post(
            f"/api/v1/assets/activation-policies/{policy_id}/{action}",
            json={"actor": "lab.admin"},
        )
        assert response.status_code == 200, response.text

    credential = client.post(
        "/api/v1/credential-profiles",
        json={
            "name": "controller-readonly",
            "provider": "vault",
            "secret_ref": "kv/lab/controller-readonly",
            "allowed_adapters": ["http_json", "http_json_sandbox"],
            "worker_selector": {"site": "LAB"},
            "created_by": "lab.admin",
        },
    )
    assert credential.status_code == 201, credential.text

    device = client.post(
        "/api/v1/assets/devices",
        json={
            "name": "lab-controller-01",
            "kind": "wireless_controller",
            "management_ip": "10.31.0.10",
            "site": "LAB",
            "connections": [{
                "protocol": "https_api",
                "credential_profile_ref": credential.json()["id"],
            }],
            "created_by": "lab.admin",
        },
    )
    assert device.status_code == 201, device.text
    device_id = device.json()["id"]
    connection = device.json()["connections"][0]
    assert connection["adapter_type"] == "http_json"
    registration = client.post(
        "/api/v1/collector-workers/register",
        headers={"X-iCheck-Registration-Token": "test-registration-token"},
        json={
            "name": "lab-controller-worker",
            "site": "LAB",
            "capabilities": ["http_json", "http_json_sandbox"],
        },
    )
    assert registration.status_code == 200, registration.text
    worker_id = registration.json()["worker"]["id"]
    headers = {"Authorization": f"Bearer {registration.json()['access_token']}"}
    base = f"/api/v1/assets/devices/{device_id}/connections/{connection['id']}/activation"
    premature = client.post(f"{base}/preview", json={"policy_id": policy_id})
    assert premature.status_code == 422

    claimed = client.post(
        f"/api/v1/collector-workers/{worker_id}/device-preflights/claim",
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claimed.status_code == 200, claimed.text
    assert len(claimed.json()) == 1
    assignment = claimed.json()[0]
    completed = client.post(
        f"/api/v1/collector-workers/{worker_id}/device-preflights/{assignment['preflight_id']}/complete",
        headers=headers,
        json={
            "lease_token": assignment["lease_token"],
            "status": "verified",
            "latency_ms": 12,
            "evidence": {
                "check": "https_connect",
                "verification_level": "transport",
                "verified": True,
                "authentication_tested": False,
            },
        },
    )
    assert completed.status_code == 200, completed.text
    preview = client.post(f"{base}/preview", json={"policy_id": policy_id})
    assert preview.status_code == 200, preview.text
    plan = preview.json()
    assert plan["target"]["url"] == "https://10.31.0.10:443/api/v1/inventory"
    assert plan["worker_selector"] == {"site": "LAB"}
    assert any("authentication" in warning for warning in plan["warnings"])
    approval = client.post(
        f"{base}/approve",
        json={
            "policy_id": policy_id,
            "expected_plan_hash": plan["plan_hash"],
            "actor": "lab.admin",
            "reason": "Enable reviewed controller inventory collection",
        },
    )
    assert approval.status_code == 200, approval.text
    assert approval.json()["deployment"]["artifact_version_id"] == version_id
    assert approval.json()["deployment"]["credential_profile_ref"] == credential.json()["id"]
    assert approval.json()["activation"]["status"] == "active"

    base_only = client.post(
        "/api/v1/credential-profiles",
        json={
            "name": "controller-preflight-only",
            "provider": "vault",
            "secret_ref": "kv/lab/controller-preflight-only",
            "allowed_adapters": ["http_json"],
            "worker_selector": {"site": "LAB"},
            "created_by": "lab.admin",
        },
    )
    assert base_only.status_code == 201, base_only.text
    limited_device = client.post(
        "/api/v1/assets/devices",
        json={
            "name": "lab-controller-preflight-only",
            "kind": "wireless_controller",
            "management_ip": "10.31.0.11",
            "site": "LAB",
            "connections": [{
                "protocol": "https_api",
                "credential_profile_ref": base_only.json()["id"],
            }],
            "created_by": "lab.admin",
        },
    )
    assert limited_device.status_code == 201, limited_device.text
    limited_connection = limited_device.json()["connections"][0]
    claimed = client.post(
        f"/api/v1/collector-workers/{worker_id}/device-preflights/claim",
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claimed.status_code == 200, claimed.text
    assert len(claimed.json()) == 1
    assignment = claimed.json()[0]
    completed = client.post(
        f"/api/v1/collector-workers/{worker_id}/device-preflights/{assignment['preflight_id']}/complete",
        headers=headers,
        json={
            "lease_token": assignment["lease_token"],
            "status": "verified",
            "evidence": {"check": "https_connect", "verified": True},
        },
    )
    assert completed.status_code == 200, completed.text
    limited_preview = client.post(
        f"/api/v1/assets/devices/{limited_device.json()['id']}/connections/"
        f"{limited_connection['id']}/activation/preview",
        json={"policy_id": policy_id},
    )
    assert limited_preview.status_code == 422
    assert "does not allow adapter 'http_json_sandbox'" in limited_preview.text
