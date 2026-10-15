from __future__ import annotations

import json
from types import SimpleNamespace
import pytest

from icheck.services.mcp_gateway import _canonical_hash, mcp_contract_hash
from icheck.services.tool_skills import tool_artifact_documents, validate_tool_artifact_contract
from icheck.studio_schemas import GeneratedToolSpec


TOOL_SPEC = {
    "artifact_name": "dns-record-lookup-tool",
    "tool_name": "dns.lookup_record",
    "description": "Look up one DNS record through a governed MCP server.",
    "transport": "mcp",
    "mcp_server_name": "network-readonly",
    "mcp_tool_name": "lookup_dns_record",
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["name"],
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 253},
            "record_type": {"enum": ["A", "AAAA", "CNAME"]},
        },
    },
    "output_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["answers"],
        "properties": {
            "answers": {
                "type": "array",
                "maxItems": 100,
                "items": {"type": "string"},
            }
        },
    },
    "risk_level": "diagnose",
    "read_only": True,
    "requires_approval": False,
    "required_permissions": ["network.diagnostics.read"],
    "timeout_seconds": 10,
    "max_result_bytes": 100000,
    "fixtures": [
        {
            "name": "A record answer",
            "arguments": {"name": "router.example.test", "record_type": "A"},
            "expected_output": {"answers": ["192.0.2.10"]},
        }
    ],
}


def test_existing_tool_artifact_remains_canonical_without_lookup_designation():
    spec = GeneratedToolSpec.model_validate(TOOL_SPEC)
    definition, implementation, fixtures = tool_artifact_documents(spec)
    assert "outcome_lookup_tool_name" not in definition["spec"]
    assert "outcome_lookup_correlation" not in definition["spec"]
    assert "independent_verification" not in definition["spec"]
    validate_tool_artifact_contract(definition, implementation, fixtures)
    server = SimpleNamespace(id="legacy-server")
    version = SimpleNamespace(content_hash="legacy-content")
    assert mcp_contract_hash(server, version, spec) == _canonical_hash({
        "artifact_content_hash": version.content_hash,
        "server_id": server.id,
        "spec": definition["spec"],
    })


def test_read_only_tool_cannot_claim_outcome_lookup_authority():
    with pytest.raises(ValueError, match="outcome lookup"):
        GeneratedToolSpec.model_validate({
            **TOOL_SPEC, "outcome_lookup_tool_name": "dns.other_tool",
        })


def test_frozen_lookup_correlation_is_exact_and_does_not_change_legacy_artifacts():
    write = {
        **TOOL_SPEC, "artifact_name": "provider-write", "tool_name": "provider.write",
        "mcp_tool_name": "write", "risk_level": "change", "read_only": False,
        "requires_approval": True, "outcome_lookup_tool_name": "provider.lookup",
    }
    correlation = {
        "tool_name": "provider.lookup",
        "operation_key_transport": "mcp_tools_call_meta",
        "operation_key_name": "icheck/toolCallId",
        "lookup_argument_name": "source_tool_call_id",
        "lookup_result_name": "source_tool_call_id",
        "consistency_window_seconds": 300,
        "max_observation_age_seconds": 900,
    }
    spec = GeneratedToolSpec.model_validate({
        **write, "outcome_lookup_correlation": correlation,
    })
    definition, implementation, fixtures = tool_artifact_documents(spec)
    assert definition["spec"]["outcome_lookup_correlation"] == correlation
    validate_tool_artifact_contract(definition, implementation, fixtures)
    for invalid in (
        {**correlation, "tool_name": "provider.other"},
        {**correlation, "operation_key_name": "untrusted/requestId"},
        {**correlation, "consistency_window_seconds": 0},
        {**correlation, "max_observation_age_seconds": 86401},
    ):
        with pytest.raises(ValueError):
            GeneratedToolSpec.model_validate({
                **write, "outcome_lookup_correlation": invalid,
            })
    with pytest.raises(ValueError, match="outcome lookup"):
        GeneratedToolSpec.model_validate({
            **TOOL_SPEC, "outcome_lookup_correlation": correlation,
        })


def test_independent_verification_requires_distinct_tool_and_exact_delivery_identity():
    write = {
        **TOOL_SPEC, "artifact_name": "report-send-tool", "tool_name": "report.send",
        "mcp_tool_name": "send_report", "risk_level": "change", "read_only": False,
        "requires_approval": True, "outcome_lookup_tool_name": "report.lookup",
    }
    contract = {
        "tool_name": "report.verify_recipient", "kind": "recipient_receipt",
        "max_age_seconds": 300,
        "bindings": [
            {"original_argument_path": "recipient_id", "observed_value_key": "recipient_id", "value_type": "string"},
            {"original_argument_path": "report.content_hash", "observed_value_key": "document_digest", "value_type": "string"},
        ],
    }
    spec = GeneratedToolSpec.model_validate({**write, "independent_verification": contract})
    definition, implementation, fixtures = tool_artifact_documents(spec)
    assert definition["spec"]["independent_verification"] == contract
    validate_tool_artifact_contract(definition, implementation, fixtures)
    for invalid in (
        {**contract, "tool_name": "report.lookup"},
        {**contract, "tool_name": "report.send"},
        {**contract, "bindings": contract["bindings"][:1]},
        {**contract, "bindings": [
            {"original_argument_path": "credentials.token", "observed_value_key": "recipient_id", "value_type": "string"},
            contract["bindings"][1],
        ]},
        {**contract, "bindings": [
            {"original_argument_path": "credentials.api_token", "observed_value_key": "recipient_id", "value_type": "string"},
            contract["bindings"][1],
        ]},
        {**contract, "bindings": [
            {"original_argument_path": "credentials.apiToken", "observed_value_key": "recipient_id", "value_type": "string"},
            contract["bindings"][1],
        ]},
        {**contract, "bindings": [
            {"original_argument_path": "recipient_id", "observed_value_key": "recipient_secret", "value_type": "string"},
            contract["bindings"][1],
        ]},
    ):
        with pytest.raises(ValueError):
            GeneratedToolSpec.model_validate({**write, "independent_verification": invalid})

SKILL_SPEC = {
    "artifact_name": "device-alert-triage-skill",
    "skill_name": "device.alert_triage",
    "description": "Correlate device state with open alerts using read-only evidence.",
    "instructions": (
        "Load the requested device, inspect its current alert evidence, cite every "
        "claim, and escalate when the evidence cannot support a conclusion."
    ),
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["device_id"],
        "properties": {
            "device_id": {"type": "string", "minLength": 1, "maxLength": 36}
        },
    },
    "output_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["summary", "confidence", "evidence_ids"],
        "properties": {
            "summary": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "evidence_ids": {
                "type": "array",
                "maxItems": 100,
                "items": {"type": "string"},
            },
        },
    },
    "allowed_tools": ["inventory.get_device", "alerts.list_open"],
    "success_criteria": [
        "Every conclusion cites persisted evidence.",
        "Confidence and uncertainty are explicit.",
    ],
    "escalation_conditions": [
        "Required evidence is unavailable.",
        "The iteration or tool-call budget is exhausted.",
    ],
    "evidence_required": True,
    "read_only": True,
    "max_iterations": 5,
    "max_tool_calls": 10,
    "max_total_tokens": 15000,
}


class FakeResponse:
    def __init__(self, document):
        self.body = json.dumps(
            {
                "choices": [{"message": {"content": json.dumps(document)}}],
                "usage": {"total_tokens": 41},
            }
        ).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, limit):
        return self.body[:limit]


class FakeOpener:
    def __init__(self, documents):
        self.documents = list(documents)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeResponse(self.documents.pop(0))


def configure_route(client):
    provider = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "contract-author-provider",
            "provider_type": "openai_compatible",
            "base_url": "https://models.example.test/v1",
            "auth_type": "none",
            "created_by": "platform.admin",
        },
    ).json()
    model = client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": provider["id"],
            "display_name": "Contract author",
            "model_name": "contract-author",
            "capabilities": ["chat", "json_schema"],
            "created_by": "platform.admin",
        },
    ).json()
    route = client.post(
        "/api/v1/ai/routes",
        json={
            "purpose": "capability.authoring",
            "primary_model_id": model["id"],
            "created_by": "platform.admin",
        },
    )
    assert route.status_code == 201, route.text
    return route.json(), model


def register_tool(
    client,
    *,
    name: str,
    read_only: bool = True,
    risk_level: str = "observe",
):
    response = client.post(
        "/api/v1/agent/tools",
        json={
            "name": name,
            "description": f"Test registry tool {name}.",
            "transport": "internal",
            "handler": name,
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            "output_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            "risk_level": risk_level,
            "read_only": read_only,
            "required_permissions": [f"{name}.read"],
            "timeout_seconds": 10,
            "max_result_bytes": 100000,
            "enabled": True,
            "created_by": "platform.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def create_session(client, kind: str):
    response = client.post(
        f"/api/v1/capability-studio/sessions/{kind}s",
        json={
            "title": f"Test {kind} contract",
            "brief": (
                "Create a governed, bounded contract that exposes only the "
                "minimum inputs and outputs required for network diagnosis."
            ),
            "created_by": "capability.author",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_tool_studio_validates_publishes_refines_without_registration(
    client,
    monkeypatch,
):
    route, model = configure_route(client)
    refined = {
        **TOOL_SPEC,
        "description": "Look up a bounded DNS answer through a governed MCP server.",
        "max_result_bytes": 50000,
    }
    opener = FakeOpener([TOOL_SPEC, refined])
    monkeypatch.setattr(
        "icheck.services.structured_model.build_opener",
        lambda *_handlers: opener,
    )
    created = create_session(client, "tool")
    assert created["artifact_kind"] == "tool"

    generated = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/generate",
        json={"actor": "capability.author"},
    )
    assert generated.status_code == 200, generated.text
    document = generated.json()
    assert document["status"] == "validated"
    assert document["route_id"] == route["id"]
    assert document["model_id"] == model["id"]
    assert document["tokens_used"] == 41
    report = document["messages"][-1]["structured_content"][
        "validation_report"
    ]
    assert report["runtime"] == "icheck_mcp_tool_v1"
    assert report["isolation"] == "declarative_mcp_contract"
    assert report["activation"] == "separate_review_required"
    assert report["fixture_count"] == 1

    artifact = client.get(f"/api/v1/artifacts/{document['artifact_id']}").json()
    assert artifact["kind"] == "tool"
    assert artifact["versions"][0]["implementation"] == {
        "runtime": "icheck_mcp_tool_v1",
        "transport": "mcp",
        "handler": "network-readonly/lookup_dns_record",
        "activation": "separate_review_required",
    }
    tools = client.get("/api/v1/agent/tools").json()
    assert "dns.lookup_record" not in {item["name"] for item in tools}

    published = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/publish",
        json={"actor": "capability.publisher", "expected_artifact_version_id": document["artifact_version_id"]},
    )
    assert published.status_code == 200, published.text
    assert published.json()["status"] == "published"
    tools = client.get("/api/v1/agent/tools").json()
    assert "dns.lookup_record" not in {item["name"] for item in tools}

    refined_response = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/messages",
        json={
            "actor": "capability.author",
            "content": "Reduce the maximum response size while preserving the contract.",
        },
    )
    assert refined_response.status_code == 200, refined_response.text
    revision = refined_response.json()
    assert revision["status"] == "validated"
    assert revision["tokens_used"] == 82
    revised_artifact = client.get(
        f"/api/v1/artifacts/{revision['artifact_id']}"
    ).json()
    assert [item["version"] for item in revised_artifact["versions"]] == [1, 2]
    assert revised_artifact["versions"][0]["status"] == "published"
    assert revised_artifact["versions"][1]["status"] == "validated"


def test_tool_studio_rejects_fixture_that_violates_output_schema(
    client,
    monkeypatch,
):
    configure_route(client)
    invalid = {
        **TOOL_SPEC,
        "fixtures": [
            {
                "name": "invalid output",
                "arguments": {"name": "router.example.test"},
                "expected_output": {"answers": "not-an-array"},
            }
        ],
    }
    opener = FakeOpener([invalid])
    monkeypatch.setattr(
        "icheck.services.structured_model.build_opener",
        lambda *_handlers: opener,
    )
    created = create_session(client, "tool")
    generated = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/generate",
        json={"actor": "capability.author"},
    )
    assert generated.status_code == 422, generated.text
    assert "tool fixture 'invalid output' output is invalid" in generated.text
    failed = client.get(
        f"/api/v1/capability-studio/sessions/{created['id']}"
    ).json()
    assert failed["status"] == "failed"
    assert failed["tokens_used"] == 41
    assert failed["artifact_id"] is None


def test_skill_studio_snapshots_read_only_tool_dependencies_and_publishes(
    client,
    monkeypatch,
):
    device_tool = register_tool(client, name="inventory.get_device")
    alert_tool = register_tool(client, name="alerts.list_open")
    configure_route(client)
    opener = FakeOpener([SKILL_SPEC])
    monkeypatch.setattr(
        "icheck.services.structured_model.build_opener",
        lambda *_handlers: opener,
    )
    created = create_session(client, "skill")
    generated = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/generate",
        json={"actor": "capability.author"},
    )
    assert generated.status_code == 200, generated.text
    document = generated.json()
    report = document["messages"][-1]["structured_content"][
        "validation_report"
    ]
    assert report["runtime"] == "icheck_agent_skill_v1"
    assert report["isolation"] == "bounded_read_only_agent_skill"
    assert report["budgets"] == {
        "max_iterations": 5,
        "max_tool_calls": 10,
        "max_total_tokens": 15000,
    }
    dependencies = report["tool_dependencies"]
    assert {item["id"] for item in dependencies} == {
        device_tool["id"],
        alert_tool["id"],
    }
    assert all(len(item["input_schema_sha256"]) == 64 for item in dependencies)
    assert report["required_permissions"] == [
        "alerts.list_open.read",
        "inventory.get_device.read",
    ]

    request = json.loads(opener.requests[0][0].data)
    prompt = json.loads(request["messages"][1]["content"])
    assert {item["name"] for item in prompt["tool_catalog"]} == {
        "inventory.get_device",
        "alerts.list_open",
    }
    artifact = client.get(f"/api/v1/artifacts/{document['artifact_id']}").json()
    assert artifact["kind"] == "skill"
    assert artifact["versions"][0]["definition"]["format_version"] == (
        "icheck.skill/v1"
    )
    published = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/publish",
        json={"actor": "capability.publisher", "expected_artifact_version_id": document["artifact_version_id"]},
    )
    assert published.status_code == 200, published.text


def test_skill_studio_rejects_state_changing_tool_dependency(
    client,
    monkeypatch,
):
    register_tool(client, name="inventory.get_device")
    register_tool(client, name="alerts.list_open")
    register_tool(
        client,
        name="network.shutdown_interface",
        read_only=False,
        risk_level="change",
    )
    configure_route(client)
    invalid = {
        **SKILL_SPEC,
        "allowed_tools": ["network.shutdown_interface"],
    }
    opener = FakeOpener([invalid])
    monkeypatch.setattr(
        "icheck.services.structured_model.build_opener",
        lambda *_handlers: opener,
    )
    created = create_session(client, "skill")
    generated = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/generate",
        json={"actor": "capability.author"},
    )
    assert generated.status_code == 422, generated.text
    assert "diagnostic skills may reference only read-only tools" in generated.text
    failed = client.get(
        f"/api/v1/capability-studio/sessions/{created['id']}"
    ).json()
    assert failed["status"] == "failed"
    assert failed["tokens_used"] == 41
    assert failed["artifact_id"] is None
