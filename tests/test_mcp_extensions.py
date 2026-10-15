"""Executable extension authoring; fixtures are never live-target acceptance."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from icheck.config import get_settings
from icheck.database import SessionLocal
from icheck.extension_schemas import BACKUP_OUTPUT, GeneratedExtensionSpec
from icheck.extension_runtime import AuthorizedNetmikoTarget, ExtensionMCPServer, NetmikoReadBackend
from icheck.models import ArtifactVersion, AgentToolRegistration
from icheck.sandbox import HardenedProcessSandboxExecutor
from icheck.services.mcp_extensions import extension_documents, validate_extension_contract
from icheck.services.structured_model import StructuredGenerationResult


DEVICE = "00000000-0000-4000-8000-000000000001"
RECEIPT = {"backup_id": "00000000-0000-4000-8000-000000000002",
    "created_at": "2026-10-13T09:00:00Z", "sha256": "a" * 64, "bytes": 20}
SPEC = {"artifact_name": "switch-operations", "description": "Read interface states and save protected configuration backups.",
    "dependencies": ["netmiko==4.8.0"], "device_type": "cisco_ios", "tools": [
    {"name": "get_interface_status", "description": "Read interface names and their link states.",
     "operation": "read", "commands": ["show interfaces status"],
     "source": "def transform(records, configuration):\n    rows = []\n    for line in records[0].split('\\n'):\n        parts = line.split()\n        if len(parts) == 2:\n            rows.append({'name': parts[0], 'state': parts[1]})\n    return {'interfaces': rows}\n",
     "output_schema": {"type": "object", "properties": {"interfaces": {"type": "array", "maxItems": 1000,
        "items": {"type": "object", "properties": {"name": {"type": "string"}, "state": {"type": "string"}},
            "required": ["name", "state"], "additionalProperties": False}}}, "required": ["interfaces"], "additionalProperties": False},
     "fixtures": [{"name": "one-interface", "readings": ["Gi0/1 connected"],
        "expected_output": {"interfaces": [{"name": "Gi0/1", "state": "connected"}]}}]},
    {"name": "backup_configuration", "description": "Save configuration in protected platform custody, returning only a receipt.",
     "operation": "backup", "commands": ["show running-config"], "source": "def transform(records, configuration):\n    return records[0]\n",
     "output_schema": BACKUP_OUTPUT, "fixtures": [{"name": "protected-receipt", "readings": [RECEIPT], "expected_output": RECEIPT}]}]}


def test_operation_specific_fixture_schema_preserves_existing_package_shape():
    schema = GeneratedExtensionSpec.model_json_schema()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    document = GeneratedExtensionSpec.model_validate(SPEC).model_dump(mode="json")
    assert validator.is_valid(document)
    assert document["tools"] == SPEC["tools"]
    assert GeneratedExtensionSpec.model_validate_json(json.dumps(document)).model_dump(mode="json") == document
    # Read tools still support multiple reviewed command outputs, not just one.
    document["tools"][0]["commands"].append("show version")
    document["tools"][0]["fixtures"][0]["readings"].append("Synthetic IOS version")
    assert validator.is_valid(document)
    GeneratedExtensionSpec.model_validate(document)


@pytest.mark.parametrize("defect", [
    "backup-json-string", "backup-two-readings", "backup-missing-bytes", "backup-extra-field",
    "backup-invalid-sha", "backup-invalid-uuid", "backup-zero-bytes", "backup-string-bytes",
    "backup-boolean-bytes", "backup-expected-json-string", "backup-expected-missing-bytes",
    "read-object", "missing-operation", "unknown-operation", "extra-fixture-field",
])
def test_provider_and_local_schema_reject_operation_specific_fixture_defects(defect):
    document = deepcopy(SPEC)
    read = document["tools"][0]["fixtures"][0]
    backup = document["tools"][1]["fixtures"][0]
    if defect == "backup-json-string": backup["readings"] = [json.dumps(RECEIPT)]
    if defect == "backup-two-readings": backup["readings"].append(deepcopy(RECEIPT))
    if defect == "backup-missing-bytes": del backup["readings"][0]["bytes"]
    if defect == "backup-extra-field": backup["readings"][0]["configuration"] = "synthetic text"
    if defect == "backup-invalid-sha": backup["readings"][0]["sha256"] = "invalid"
    if defect == "backup-invalid-uuid": backup["readings"][0]["backup_id"] = "invalid"
    if defect == "backup-zero-bytes": backup["readings"][0]["bytes"] = 0
    if defect == "backup-string-bytes": backup["readings"][0]["bytes"] = "20"
    if defect == "backup-boolean-bytes": backup["readings"][0]["bytes"] = True
    if defect == "backup-expected-json-string": backup["expected_output"] = json.dumps(RECEIPT)
    if defect == "backup-expected-missing-bytes": backup["expected_output"] = {k:v for k,v in RECEIPT.items() if k != "bytes"}
    if defect == "read-object": read["readings"] = [{"text": "Gi0/1 connected"}]
    if defect == "missing-operation": del document["tools"][1]["operation"]
    if defect == "unknown-operation": document["tools"][1]["operation"] = "configure"
    if defect == "extra-fixture-field": backup["path"] = "/tmp/not-allowed"
    validator = Draft202012Validator(GeneratedExtensionSpec.model_json_schema(), format_checker=FormatChecker())
    assert not validator.is_valid(document), defect
    with pytest.raises(ValidationError):
        GeneratedExtensionSpec.model_validate(document)


@pytest.mark.parametrize("stringified_backup", [False, True])
def test_studio_sends_operation_specific_schema_and_rejects_noncompliant_provider(client, monkeypatch, stringified_backup):
    from test_capability_studio import FakeStructuredOpener, configure_authoring_route

    monkeypatch.setenv("ICHECK_SANDBOX_ENABLED", "true")
    monkeypatch.setenv("ICHECK_SANDBOX_BACKEND", "process")
    get_settings.cache_clear()
    configure_authoring_route(client)
    document = deepcopy(SPEC)
    if stringified_backup:
        document["tools"][1]["fixtures"][0]["readings"] = [json.dumps(RECEIPT)]
    opener = FakeStructuredOpener([document])
    monkeypatch.setattr("icheck.services.structured_model.build_opener", lambda *_: opener)
    created = client.post("/api/v1/capability-studio/sessions/extensions", json={
        "title": "Fixture schema regression", "brief": "Create interface and protected backup tools.", "created_by": "engineer"})
    assert created.status_code == 201, created.text
    base = f"/api/v1/capability-studio/sessions/{created.json()['id']}"
    response = client.post(base + "/generate", json={"actor": "engineer", "request_key": str(uuid4())})
    assert response.status_code == (503 if stringified_backup else 200), response.text
    assert len(opener.requests) == 1
    payload = json.loads(opener.requests[0][0].data)
    assert payload["response_format"]["json_schema"]["strict"] is True
    wire = Draft202012Validator(payload["response_format"]["json_schema"]["schema"])
    assert wire.is_valid(SPEC)
    invalid = deepcopy(SPEC)
    invalid["tools"][1]["fixtures"][0]["readings"] = [json.dumps(RECEIPT)]
    assert not wire.is_valid(invalid)
    assert "never JSON-encoded strings" in payload["messages"][0]["content"]
    session = client.get(base).json()
    attempt, = client.get(base + "/generations").json()
    assert attempt["usage_recorded"] and attempt["tokens_used"] == 42
    assert session["status"] == ("failed" if stringified_backup else "validated")
    if stringified_backup:
        assert session["artifact_id"] is None and session["artifact_version_id"] is None
    else:
        artifact = client.get("/api/v1/artifacts/" + session["artifact_id"]).json()
        assert artifact["versions"][0]["validation_report"]["fixture_count"] == 2
        assert artifact["versions"][0]["status"] == "validated"
    with SessionLocal() as db:
        assert db.query(AgentToolRegistration).filter(AgentToolRegistration.name.like("switch-operations%")).count() == 0


@pytest.fixture
def sandbox():
    # Real child with Landlock/seccomp; no mock exec and no fallback to unisolated Python.
    return HardenedProcessSandboxExecutor(python_path="/usr/bin/python3")


def test_generated_package_executes_source_and_preserves_mcp_schemas(sandbox):
    spec = GeneratedExtensionSpec.model_validate(SPEC)
    definition, implementation, tests = extension_documents(spec)
    report = validate_extension_contract(definition, implementation, tests, sandbox_executor=sandbox)
    assert report["fixture_count"] == 2 and not report["installed"] and not report["registered"]
    assert set(implementation["files"]) == {"server.py", "extension.json", "requirements.txt",
        "tools/get_interface_status.py", "tools/backup_configuration.py"}
    server = ExtensionMCPServer(spec, sandbox=sandbox, fixture=True)
    assert "error" in server.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    server.dispatch({"jsonrpc": "2.0", "id": 2, "method": "initialize"})
    catalog = server.dispatch({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})["result"]["tools"]
    assert [item["name"] for item in catalog] == [tool["name"] for tool in SPEC["tools"]]
    response = server.dispatch({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "get_interface_status", "arguments": {"device_id": DEVICE}}})["result"]
    assert response["structuredContent"] == SPEC["tools"][0]["fixtures"][0]["expected_output"]
    assert response["_meta"]["icheck/evidence"] == "fixture"
    assert server.call("backup_configuration", {"device_id": DEVICE}) == RECEIPT
    with pytest.raises(ValueError):
        server.call("get_interface_status", {"device_id": DEVICE, "host": "127.0.0.1"})
    with pytest.raises(ValueError):
        server.call("get_interface_status", {"device_id": "not-a-uuid"})


@pytest.mark.parametrize("defect", ["import", "command-injection", "configuration-as-read", "configuration-alias", "dependency", "fake-backup", "fixture-mismatch", "package-drift"])
def test_generated_extension_rejects_untrusted_execution_or_false_evidence(sandbox, defect):
    document = deepcopy(SPEC)
    if defect == "import": document["tools"][0]["source"] = "import os\ndef transform(records, configuration):\n    return {}"
    if defect == "command-injection": document["tools"][0]["commands"] = ["show interfaces; reload"]
    if defect == "configuration-as-read": document["tools"][0]["commands"] = ["show running-config"]
    if defect == "configuration-alias": document["tools"][0]["commands"] = ["show run"]
    if defect == "dependency": document["dependencies"] = ["netmiko @ https://untrusted.invalid/package"]
    if defect == "fake-backup": document["tools"][1]["source"] = "def transform(records, configuration):\n    result = records[0].copy()\n    result['bytes'] = 5\n    return result"
    if defect == "fixture-mismatch": document["tools"][0]["fixtures"][0]["expected_output"] = {"interfaces": []}
    with pytest.raises(ValueError):
        definitions = list(extension_documents(GeneratedExtensionSpec.model_validate(document)))
        if defect == "package-drift": definitions[1]["files"]["server.py"] += "print('unreviewed')"
        validate_extension_contract(*definitions, sandbox_executor=sandbox)


def test_netmiko_boundary_uses_strict_host_keys_and_hides_configuration(monkeypatch, tmp_path, sandbox):
    known_hosts = tmp_path / "known_hosts"; known_hosts.write_text("fixture-host-key"); known_hosts.chmod(0o600)
    checked, connect_arguments, commands, stored = [], [], [], []
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def send_command(self, command, **kwargs):
            commands.append(command)
            assert kwargs["read_timeout"] == 20
            return "sensitive configuration body" if command == "show running-config" else "Gi0/1 connected"
    def connect(**kwargs): connect_arguments.append(kwargs); return Connection()
    monkeypatch.setattr("icheck.ssh_compatibility.netmiko_connection", connect)
    monkeypatch.setattr("icheck.extension_runtime.version", lambda _: "4.8.0")
    def resolve(spec, tool, device_id):
        return AuthorizedNetmikoTarget(device_id, "198.18.0.1", 22, spec.device_type,
            "fixture-user", "fixture-pass", str(known_hosts), tuple(tool.commands), lambda: checked.append(True))
    def store(target, body): stored.append(body); return RECEIPT
    server = ExtensionMCPServer(SPEC, sandbox=sandbox, backend=NetmikoReadBackend(resolve, store))
    assert server.call("backup_configuration", {"device_id": DEVICE}) == RECEIPT
    assert stored == [b"sensitive configuration body"] and len(checked) == 4
    assert connect_arguments[0]["ssh_strict"] and connect_arguments[0]["alt_host_keys"]
    assert connect_arguments[0]["profile"] == "modern"
    assert not connect_arguments[0]["allow_agent"] and connect_arguments[0]["session_log"] is None
    assert commands == ["show running-config"]
    assert "fixture-pass" not in repr(resolve(server.spec, server.spec.tools[0], DEVICE))


def test_package_entrypoint_is_real_stdio_mcp_with_explicit_fixture_label(tmp_path):
    _, implementation, _ = extension_documents(SPEC)
    for name, body in implementation["files"].items():
        path = tmp_path / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(body)
    messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_interface_status", "arguments": {"device_id": DEVICE}}}]
    result = subprocess.run([sys.executable, str(tmp_path / "server.py"), "--fixture"],
        input="".join(json.dumps(row) + "\n" for row in messages), text=True, capture_output=True, timeout=15,
        env={**os.environ, "ICHECK_SANDBOX_ENABLED": "true", "ICHECK_SANDBOX_BACKEND": "process"})
    assert result.returncode == 0, result.stderr
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(replies) == 3 and len(replies[1]["result"]["tools"]) == 2
    assert replies[2]["result"]["isError"] is False
    assert replies[2]["result"]["_meta"]["icheck/evidence"] == "fixture"


def test_studio_generates_and_revises_executable_versions_without_registration(client, monkeypatch):
    monkeypatch.setenv("ICHECK_SANDBOX_ENABLED", "true")
    monkeypatch.setenv("ICHECK_SANDBOX_BACKEND", "process")
    get_settings.cache_clear()
    calls = []
    def generate(self, **kwargs):
        calls.append(kwargs)
        return StructuredGenerationResult(document=GeneratedExtensionSpec.model_validate(SPEC),
            route_id="fixture-route", model_id="fixture-model", tokens_used=10)
    monkeypatch.setattr("icheck.services.structured_model.OpenAICompatibleStructuredGenerator.generate", generate)
    created = client.post("/api/v1/capability-studio/sessions/extensions", json={
        "title": "Switch plugin", "brief": "Build a Netmiko MCP server for interface checks and configuration backups.", "created_by": "engineer"})
    assert created.status_code == 201, created.text
    identifier = created.json()["id"]
    request_key = str(uuid4())
    first = client.post(f"/api/v1/capability-studio/sessions/{identifier}/generate", json={"actor": "engineer", "request_key": request_key})
    assert first.status_code == 200, first.text
    repeated = client.post(f"/api/v1/capability-studio/sessions/{identifier}/generate", json={"actor": "engineer", "request_key": request_key})
    assert repeated.status_code == 200 and len(calls) == 1
    revised = client.post(f"/api/v1/capability-studio/sessions/{identifier}/messages", json={"actor": "engineer", "content": "Retain the two reviewed tools and refine the descriptions.", "request_key": str(uuid4())})
    assert revised.status_code == 200, revised.text
    assert revised.json()["artifact_id"] == first.json()["artifact_id"]
    assert revised.json()["artifact_version_id"] != first.json()["artifact_version_id"]
    with SessionLocal() as db:
        version = db.get(ArtifactVersion, revised.json()["artifact_version_id"])
        assert version.version == 2 and version.validation_report["package_generated"]
        assert not version.validation_report["installed"] and not version.validation_report["registered"]
        assert db.query(AgentToolRegistration).filter(AgentToolRegistration.name.like("switch-operations%" )).count() == 0
    assert len(calls) == 2 and calls[1]["prompt_document"]["current_spec"]["format_version"] == "icheck.mcp-extension/v1"
