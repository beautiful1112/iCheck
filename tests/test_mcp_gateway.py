from __future__ import annotations

import ast
import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.error import URLError

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from sqlalchemy import select

from icheck.credentials import EnvironmentCredentialProvider, WorkerCredentialBroker
from icheck.agent_schemas import AgentExecutionAssignment
from icheck.agent_worker import execute_remote_assignment
from icheck.agent_runtime_protocol import RemoteToolExecutor
from icheck.database import SessionLocal
from icheck.langgraph_runtime import (
    GraphDecision,
    GraphToolOutcomeUnknown,
    GraphToolRequest,
    initial_graph_state,
)
from icheck.mcp_attestor_worker import attest_assignment
from icheck.mcp_schemas import (
    MCPToolAttestationAssignment,
)
from icheck.models import (
    AgentActionProposal,
    AgentExecution,
    AgentExecutionStatus,
    AgentToolRegistration,
    AgentWorker,
    AgentWorkerState,
    Alert,
    AlertStatus,
    CredentialProfile,
    Investigation,
    InvestigationToolCall,
    MCPToolAttestation,
    MCPToolActivation,
    utcnow,
)
from icheck.services.agent_tools import DatabaseToolExecutor
from icheck.services.agent_graph import run_database_investigation
from icheck.services.mcp_gateway import (
    MCPGatewayError,
    MCPWriteOutcomeUnknown,
    MCPWorkerRuntime,
    mcp_activation_allows_investigation,
)
from icheck.services.tool_skills import tool_artifact_documents
from icheck.studio_schemas import GeneratedToolSpec


BASE_SPEC = {
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
    "max_result_bytes": 100_000,
    "fixtures": [
        {
            "name": "A record answer",
            "arguments": {"name": "router.example.test"},
            "expected_output": {"answers": ["192.0.2.10"]},
        }
    ],
}


class FakeMCPResponse:
    def __init__(self, document):
        self.body = json.dumps(document).encode("utf-8")
        self.headers = {"Content-Type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, limit):
        return self.body[:limit]


class FakeMCPOpener:
    def __init__(self, tools, *, call_result=None):
        self.tools = tools
        self.call_result = call_result or {"answers": ["192.0.2.10"]}
        self.requests = []

    def open(self, request, timeout):
        document = json.loads(request.data.decode("utf-8"))
        headers = {key.lower(): value for key, value in request.header_items()}
        self.requests.append(
            {
                "method": document["method"],
                "params": document["params"],
                "headers": headers,
                "timeout": timeout,
            }
        )
        if document["method"] == "tools/list":
            result = {"tools": self.tools}
        elif document["method"] == "tools/call":
            result = {
                "content": [{"type": "text", "text": "bounded result"}],
                "structuredContent": self.call_result,
                "isError": False,
            }
        else:
            raise AssertionError(f"Unexpected MCP method {document['method']}")
        return FakeMCPResponse(
            {
                "jsonrpc": "2.0",
                "id": document["id"],
                "result": result,
            }
        )


class FailingMCPCallOpener(FakeMCPOpener):
    def open(self, request, timeout):
        document = json.loads(request.data.decode("utf-8"))
        if document["method"] == "tools/call":
            raise URLError("simulated MCP transport outage")
        return super().open(request, timeout)


class AcceptedThenLostMCPCallOpener(FakeMCPOpener):
    def __init__(self, tools):
        super().__init__(tools)
        self.accepted_writes = 0
        self.last_call = None

    def open(self, request, timeout):
        document = json.loads(request.data.decode("utf-8"))
        if document["method"] == "tools/call":
            self.accepted_writes += 1
            self.last_call = document
            raise URLError("simulated lost response after provider acceptance")
        return super().open(request, timeout)


@pytest.mark.parametrize("read_only, expected_status", [
    (False, "outcome_unknown"),
    (True, "failed"),
])
def test_remote_worker_classifies_lost_mcp_reply_without_replaying(
    monkeypatch, read_only, expected_status,
):
    opener = AcceptedThenLostMCPCallOpener([_tool_advertisement(BASE_SPEC)])
    monkeypatch.setattr("icheck.services.mcp_gateway.build_opener", lambda *_handlers: opener)
    executor = RemoteToolExecutor(
        client=None, execution_id="execution", lease_token="lease",
        mcp_allowed_hosts=["mcp.example.test"],
    )
    result = executor._run_mcp({
        "invocation_id": "a" * 64,
        "tool_call_id": "stable-call-id",
        "read_only": read_only,
        "endpoint": "https://mcp.example.test/rpc",
        "mcp_tool_name": BASE_SPEC["mcp_tool_name"],
        "arguments": {"name": "router.example.test"},
        "output_schema": BASE_SPEC["output_schema"],
        "metadata": {"icheck/toolCallId": "stable-call-id"},
    })
    assert result["status"] == expected_status
    assert opener.accepted_writes == 1
    assert opener.last_call["params"]["_meta"]["icheck/toolCallId"] == "stable-call-id"


def test_remote_tool_failure_preserves_unknown_outcome_type():
    class UnknownResultClient:
        def request(self, _method, _path, payload):
            return {
                "protocol_version": "icheck.agent-runtime/v1",
                "operation_id": payload["operation_id"],
                "status": "failed",
                "failure": {"error_type": "OutcomeUnknown",
                    "tool_call_ids": ["stable-call-id"], "evidence_ids": []},
            }

    executor = RemoteToolExecutor(
        client=UnknownResultClient(), execution_id="execution", lease_token="lease",
    )
    with pytest.raises(GraphToolOutcomeUnknown) as caught:
        executor(GraphToolRequest(tool_name="dns.flush_cache", arguments={}, purpose="test"), {})
    assert caught.value.tool_call_ids == ["stable-call-id"]


class APIAgentControlClient:
    def __init__(self, client, access_token):
        self.client = client
        self.access_token = access_token

    def request(self, method, path, payload, **_kwargs):
        response = self.client.request(
            method,
            path,
            headers={"Authorization": f"Bearer {self.access_token}"},
            json=payload,
        )
        assert response.status_code < 400, response.text
        if response.status_code == 204 or not response.content:
            return None
        return response.json()


def _tool_advertisement(spec):
    return {
        "name": spec["mcp_tool_name"],
        "description": spec["description"],
        "inputSchema": spec["input_schema"],
        "outputSchema": spec["output_schema"],
    }


def _publish_tool(client, spec=BASE_SPEC):
    definition, implementation, tests = tool_artifact_documents(
        GeneratedToolSpec.model_validate(spec)
    )
    created = client.post(
        "/api/v1/artifacts",
        json={
            "name": spec["artifact_name"],
            "kind": "tool",
            "description": spec["description"],
            "owner": "capability.author",
            "labels": {},
            "initial_version": {
                "definition": definition,
                "implementation": implementation,
                "tests": tests,
                "created_by": "capability.author",
            },
        },
    )
    assert created.status_code == 201, created.text
    version_id = created.json()["versions"][0]["id"]
    validated = client.post(
        f"/api/v1/artifact-versions/{version_id}/validate",
        json={"actor": "capability.reviewer"},
    )
    assert validated.status_code == 200, validated.text
    published = client.post(
        f"/api/v1/artifact-versions/{version_id}/publish",
        json={"actor": "capability.publisher"},
    )
    assert published.status_code == 200, published.text
    return version_id


def _credential_profile(client):
    response = client.post(
        "/api/v1/credential-profiles",
        json={
            "name": "mcp-runtime-token",
            "provider": "environment",
            "secret_ref": "env://ICHECK_TEST_MCP_TOKEN",
            "allowed_adapters": ["mcp:network-readonly"],
            "worker_selector": {},
            "created_by": "platform.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _server(client, profile_id=None):
    response = client.post(
        "/api/v1/mcp/servers",
        json={
            "name": "network-readonly",
            "endpoint_url": "https://mcp.example.test/rpc",
            "protocol_version": "2026-07-28",
            "credential_profile_ref": profile_id,
            "created_by": "platform.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _attest_tool(client, server, version_id, opener):
    queued = client.post(
        f"/api/v1/mcp/servers/{server['id']}/attestations",
        json={
            "artifact_version_id": version_id,
            "reason": "Verify the live Worker-side MCP contract.",
            "actor": "platform.approver",
        },
    )
    assert queued.status_code == 201, queued.text
    registration = client.post(
        "/api/v1/mcp/attestors/register",
        headers={
            "X-iCheck-Registration-Token": "test-mcp-attestor-registration-token"
        },
        json={
            "name": "mcp-contract-attestor",
            "labels": {"zone": "lab", "role": "mcp_attestor"},
        },
    )
    assert registration.status_code == 200, registration.text
    worker_id = registration.json()["worker"]["id"]
    token = registration.json()["access_token"]
    authorization = {"Authorization": f"Bearer {token}"}
    claimed = client.post(
        f"/api/v1/mcp/attestors/{worker_id}/attestations/claim",
        headers=authorization,
        json={"max_assignments": 1, "lease_seconds": 120},
    )
    assert claimed.status_code == 200, claimed.text
    assert len(claimed.json()) == 1
    assignment = MCPToolAttestationAssignment.model_validate(claimed.json()[0])
    result = attest_assignment(
        assignment,
        credential_broker=WorkerCredentialBroker(
            {"environment": EnvironmentCredentialProvider()}
        ),
        allowed_hosts=["mcp.example.test"],
        opener=opener,
    )
    completed = client.post(
        (
            f"/api/v1/mcp/attestors/{worker_id}/attestations/"
            f"{assignment.attestation_id}/complete"
        ),
        headers=authorization,
        json=result.model_dump(mode="json"),
    )
    assert completed.status_code == 200, completed.text
    return completed.json()


def _configure_investigation(client):
    provider = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "mcp-agent-provider",
            "provider_type": "openai_compatible",
            "base_url": "https://models.example.test/v1",
            "auth_type": "none",
            "created_by": "platform.admin",
        },
    )
    model = client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": provider.json()["id"],
            "display_name": "MCP agent reasoner",
            "model_name": "mcp-agent-reasoner",
            "capabilities": ["chat", "tools", "json_schema"],
            "created_by": "platform.admin",
        },
    )
    route = client.post(
        "/api/v1/ai/routes",
        json={
            "purpose": "investigation",
            "primary_model_id": model.json()["id"],
            "max_iterations": 3,
            "max_tool_calls": 5,
            "timeout_seconds": 300,
            "token_budget": 1000,
            "created_by": "platform.admin",
        },
    )
    assert route.status_code == 201, route.text
    investigation = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": "Resolve DNS evidence",
            "objective": "Resolve the device DNS record using governed evidence.",
            "scope": {},
            "created_by": "l1.operator",
        },
    )
    assert investigation.status_code == 201, investigation.text
    started = client.post(
        f"/api/v1/agent/investigations/{investigation.json()['id']}/start",
        json={"actor": "l1.operator"},
    )
    assert started.status_code == 200, started.text
    return investigation.json()["id"]


def _runtime(db, investigation_id, opener):
    investigation = db.get(Investigation, investigation_id)
    execution = db.scalar(
        select(AgentExecution).where(
            AgentExecution.investigation_id == investigation_id
        )
    )
    worker = AgentWorker(
        name="mcp-agent-worker",
        capabilities=["openai_compatible", "mcp"],
        labels={"zone": "lab"},
        auth_token_hash="0" * 64,
        state=AgentWorkerState.ONLINE,
    )
    db.add(worker)
    db.flush()
    execution.status = AgentExecutionStatus.RUNNING
    execution.worker_id = worker.id
    execution.lease_expires_at = utcnow() + timedelta(minutes=5)
    db.commit()
    runtime = MCPWorkerRuntime(
        worker=worker,
        execution=execution,
        credential_broker=WorkerCredentialBroker(
            {"environment": EnvironmentCredentialProvider()}
        ),
        allowed_hosts=["mcp.example.test"],
        opener=opener,
    )
    return investigation, worker, execution, runtime


def _state(investigation):
    state = initial_graph_state(
        investigation_id=investigation.id,
        objective=investigation.objective,
        scope=investigation.scope,
        max_iterations=investigation.max_iterations,
        max_tool_calls=investigation.max_tool_calls,
        token_budget=investigation.token_budget,
    )
    state["iteration"] = 1
    return state


def test_mcp_tool_activation_execution_redaction_and_deactivation(
    client,
    monkeypatch,
):
    version_id = _publish_tool(client)
    profile = _credential_profile(client)
    server = _server(client, profile["id"])
    opener = FakeMCPOpener(
        [_tool_advertisement(BASE_SPEC)],
        call_result={"answers": ["unit-test-mcp-token"]},
    )
    monkeypatch.setattr(
        "icheck.services.mcp_gateway.build_opener",
        lambda *_handlers: opener,
    )

    checked = client.post(f"/api/v1/mcp/servers/{server['id']}/check")
    assert checked.status_code == 200, checked.text
    assert checked.json()["tool_names"] == ["lookup_dns_record"]
    attestation = _attest_tool(client, server, version_id, opener)
    assert attestation["status"] == "passed"
    activated = client.post(
        f"/api/v1/mcp/servers/{server['id']}/activations",
        json={
            "artifact_version_id": version_id,
            "attestation_id": attestation["id"],
            "canary_percent": 100,
            "minimum_successful_calls": 1,
            "circuit_failure_threshold": 2,
            "reason": "Approved read-only diagnostic contract.",
            "actor": "platform.approver",
        },
    )
    assert activated.status_code == 201, activated.text
    activation = activated.json()
    assert activation["status"] == "active"
    assert len(activation["contract_sha256"]) == 64

    raw_mcp = client.post(
        "/api/v1/agent/tools",
        json={
            "name": "bypass.mcp",
            "description": "Must not bypass attestation.",
            "transport": "mcp",
            "handler": "network-readonly/bypass",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "created_by": "platform.admin",
        },
    )
    assert raw_mcp.status_code == 422
    assert "published Tool Artifact" in raw_mcp.text

    investigation_id = _configure_investigation(client)
    with SessionLocal() as db:
        investigation, _worker, _execution, runtime = _runtime(
            db,
            investigation_id,
            opener,
        )
        result = DatabaseToolExecutor(
            db,
            investigation,
            mcp_runtime=runtime,
        )(
            GraphToolRequest(
                tool_name=BASE_SPEC["tool_name"],
                arguments={"name": "router.example.test"},
                purpose="Collect one bounded DNS answer.",
            ),
            _state(investigation),
        )
        assert result.status == "succeeded"
        assert result.result == {"answers": ["[REDACTED]"]}
        assert len(result.evidence_ids) == 1
        call = db.get(InvestigationToolCall, result.call_id)
        assert call.result == {"answers": ["[REDACTED]"]}

    rollout = next(
        item
        for item in client.get("/api/v1/mcp/activations").json()
        if item["id"] == activation["id"]
    )
    assert rollout["rollout_state"] == "canary"
    assert rollout["successful_calls"] == 1
    promoted = client.post(
        f"/api/v1/mcp/activations/{activation['id']}/promote",
        json={
            "expected_revision": rollout["revision"],
            "reason": "The bounded canary call passed with schema evidence.",
            "actor": "platform.approver",
        },
    )
    assert promoted.status_code == 200, promoted.text
    assert promoted.json()["rollout_state"] == "full"
    assert promoted.json()["traffic_percent"] == 100

    call_request = [
        item for item in opener.requests if item["method"] == "tools/call"
    ][0]
    assert call_request["headers"]["mcp-protocol-version"] == "2026-07-28"
    assert call_request["headers"]["mcp-method"] == "tools/call"
    assert call_request["headers"]["mcp-name"] == "lookup_dns_record"
    assert call_request["headers"]["authorization"] == (
        "Bearer unit-test-mcp-token"
    )
    assert call_request["params"]["_meta"]["icheck/investigationId"] == (
        investigation_id
    )
    assert call_request["params"]["_meta"]["icheck/toolCallId"] == result.call_id

    audits = client.get("/api/v1/audit-events?limit=1000").json()
    assert "unit-test-mcp-token" not in json.dumps(audits)
    deactivated = client.post(
        f"/api/v1/mcp/activations/{activation['id']}/deactivate",
        json={
            "reason": "Retire this exact contract version.",
            "actor": "platform.approver",
        },
    )
    assert deactivated.status_code == 200, deactivated.text
    assert deactivated.json()["status"] == "inactive"
    tools = client.get("/api/v1/agent/tools").json()
    tool = next(item for item in tools if item["name"] == BASE_SPEC["tool_name"])
    assert tool["enabled"] is False


def test_http_only_agent_delegates_mcp_and_keeps_credentials_worker_local(
    client,
    monkeypatch,
):
    version_id = _publish_tool(client)
    profile = _credential_profile(client)
    server = _server(client, profile["id"])
    opener = FakeMCPOpener(
        [_tool_advertisement(BASE_SPEC)],
        call_result={"answers": ["unit-test-mcp-token"]},
    )
    monkeypatch.setattr(
        "icheck.services.mcp_gateway.build_opener",
        lambda *_handlers: opener,
    )
    assert client.post(
        f"/api/v1/mcp/servers/{server['id']}/check"
    ).status_code == 200
    attestation = _attest_tool(client, server, version_id, opener)
    assert attestation["status"] == "passed"
    activation = client.post(
        f"/api/v1/mcp/servers/{server['id']}/activations",
        json={
            "artifact_version_id": version_id,
            "attestation_id": attestation["id"],
            "canary_percent": 100,
            "reason": "Approve delegated Worker-local credential execution.",
            "actor": "platform.approver",
        },
    )
    assert activation.status_code == 201, activation.text
    investigation_id = _configure_investigation(client)
    execution = client.get(
        f"/api/v1/agent/investigations/{investigation_id}/execution"
    ).json()
    registration = client.post(
        "/api/v1/agent/workers/register",
        headers={
            "X-iCheck-Registration-Token": "test-agent-registration-token"
        },
        json={
            "name": "remote-mcp-agent-worker",
            "capabilities": ["openai_compatible", "mcp"],
            "labels": {"zone": "lab"},
        },
    )
    assert registration.status_code == 200, registration.text
    token = registration.json()["access_token"]
    worker_id = registration.json()["worker"]["id"]
    claim = client.post(
        f"/api/v1/agent/workers/{worker_id}/executions/claim",
        headers={"Authorization": f"Bearer {token}"},
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claim.status_code == 200, claim.text
    assignment = AgentExecutionAssignment.model_validate(claim.json()[0])
    reason_calls = []

    def reasoner(state):
        reason_calls.append(dict(state))
        if not state["tool_results"]:
            return GraphDecision(
                action="continue",
                plan=["Resolve the DNS record", "Evaluate the answer"],
                tool_requests=[
                    GraphToolRequest(
                        tool_name=BASE_SPEC["tool_name"],
                        arguments={"name": "router.example.test"},
                        purpose="Collect one bounded DNS answer.",
                    )
                ],
                token_usage=20,
            )
        assert state["tool_results"][0]["result"] == {
            "answers": ["[REDACTED]"]
        }
        return GraphDecision(
            action="complete",
            plan=state["plan"],
            confidence=0.9,
            conclusion="The governed DNS lookup completed.",
            token_usage=15,
        )

    monkeypatch.setattr(
        "icheck.services.agent_remote_runtime.OpenAICompatibleReasoner",
        lambda *_args, **_kwargs: reasoner,
    )
    completed = execute_remote_assignment(
        APIAgentControlClient(client, token),
        assignment,
        lease_seconds=60,
        credential_broker=WorkerCredentialBroker(
            {"environment": EnvironmentCredentialProvider()}
        ),
        mcp_allowed_hosts=["mcp.example.test"],
    )
    diagnostic_events = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events"
    ).json()
    diagnostic_investigation = client.get(
        f"/api/v1/agent/investigations/{investigation_id}"
    ).json()
    assert completed["status"] == "succeeded", repr(
        [
            completed["error"],
            diagnostic_investigation["status"],
            diagnostic_investigation["escalation_reason"],
            [
                (item["status"], item["error"], item["result"])
                for item in reason_calls[-1]["tool_results"]
            ],
            [
                (item["event_type"], item["payload"])
                for item in diagnostic_events
            ],
        ]
    )
    assert len(reason_calls) == 2

    rollout = next(
        item
        for item in client.get("/api/v1/mcp/activations").json()
        if item["id"] == activation.json()["id"]
    )
    assert rollout["rollout_state"] == "canary"
    assert rollout["successful_calls"] == 1

    mcp_calls = [
        item for item in opener.requests if item["method"] == "tools/call"
    ]
    assert len(mcp_calls) == 1
    assert mcp_calls[0]["headers"]["authorization"] == (
        "Bearer unit-test-mcp-token"
    )
    with SessionLocal() as db:
        call = db.scalar(
            select(InvestigationToolCall).where(
                InvestigationToolCall.investigation_id == investigation_id
            )
        )
        assert call is not None
        assert call.result == {"answers": ["[REDACTED]"]}
        assert mcp_calls[0]["params"]["_meta"]["icheck/toolCallId"] == call.id
    events = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events"
    ).json()
    assert "unit-test-mcp-token" not in json.dumps(events)


def test_mcp_canary_cohort_is_deterministic_and_fail_closed():
    activation = SimpleNamespace(
        id="activation-stable-cohort",
        status="active",
        rollout_state="canary",
        circuit_state="closed",
        traffic_percent=20,
    )
    decisions = {
        investigation_id: mcp_activation_allows_investigation(
            activation,
            investigation_id,
        )
        for investigation_id in (
            f"investigation-{index}" for index in range(100)
        )
    }
    assert any(decisions.values())
    assert not all(decisions.values())
    assert all(
        decision
        == mcp_activation_allows_investigation(
            activation,
            investigation_id,
        )
        for investigation_id, decision in decisions.items()
    )

    activation.rollout_state = "full"
    assert mcp_activation_allows_investigation(
        activation,
        "investigation-outside-canary",
    )
    activation.rollout_state = "blocked"
    assert not mcp_activation_allows_investigation(
        activation,
        "investigation-outside-canary",
    )


def test_mcp_activation_rejects_schema_drift(client, monkeypatch):
    version_id = _publish_tool(client)
    server = _server(client)
    drifted = _tool_advertisement(BASE_SPEC)
    drifted["inputSchema"] = {
        **BASE_SPEC["input_schema"],
        "required": [],
    }
    opener = FakeMCPOpener([drifted])
    monkeypatch.setattr(
        "icheck.services.mcp_gateway.build_opener",
        lambda *_handlers: opener,
    )
    attestation = _attest_tool(client, server, version_id, opener)
    assert attestation["status"] == "failed"
    assert attestation["failure_code"] == "contract_mismatch"
    response = client.post(
        f"/api/v1/mcp/servers/{server['id']}/activations",
        json={
            "artifact_version_id": version_id,
            "attestation_id": attestation["id"],
            "reason": "Attempt to activate a drifted server contract.",
            "actor": "platform.approver",
        },
    )
    assert response.status_code == 422, response.text
    assert "fresh, unconsumed Worker attestation" in response.text
    assert client.get("/api/v1/mcp/activations").json() == []
    assert BASE_SPEC["tool_name"] not in {
        item["name"] for item in client.get("/api/v1/agent/tools").json()
    }


def test_change_risk_mcp_tool_interrupts_before_remote_call(client, monkeypatch):
    spec = {
        **BASE_SPEC,
        "artifact_name": "dns-cache-flush-tool",
        "tool_name": "dns.flush_cache",
        "description": "Flush one managed DNS cache after approval.",
        "mcp_tool_name": "flush_dns_cache",
        "risk_level": "change",
        "read_only": False,
        "requires_approval": True,
        "required_permissions": [],
        "fixtures": [
            {
                "name": "flush result",
                "arguments": {"name": "router.example.test"},
                "expected_output": {"answers": ["flushed"]},
            }
        ],
    }
    version_id = _publish_tool(client, spec)
    server = _server(client)
    opener = FakeMCPOpener([_tool_advertisement(spec)])
    monkeypatch.setattr(
        "icheck.services.mcp_gateway.build_opener",
        lambda *_handlers: opener,
    )
    attestation = _attest_tool(client, server, version_id, opener)
    assert attestation["status"] == "passed"
    activated = client.post(
        f"/api/v1/mcp/servers/{server['id']}/activations",
        json={
            "artifact_version_id": version_id,
            "attestation_id": attestation["id"],
            "canary_percent": 100,
            "reason": "Approved contract, but every call still needs approval.",
            "actor": "platform.approver",
        },
    )
    assert activated.status_code == 201, activated.text
    investigation_id = _configure_investigation(client)
    with SessionLocal() as db:
        investigation, _worker, _execution, runtime = _runtime(
            db,
            investigation_id,
            opener,
        )
        result = run_database_investigation(
            db,
            investigation,
            reasoner=lambda _state: GraphDecision(
                action="continue",
                tool_requests=[
                    GraphToolRequest(
                        tool_name=spec["tool_name"],
                        arguments={"name": "router.example.test"},
                        purpose="Flush the cache only after four-eyes approval.",
                    )
                ],
                token_usage=10,
            ),
            checkpointer=InMemorySaver(),
            mcp_runtime=runtime,
        )
        assert result["status"] == "waiting_approval"
        proposal = db.scalar(
            select(AgentActionProposal).where(
                AgentActionProposal.investigation_id == investigation_id
            )
        )
        assert proposal is not None
        assert proposal.status == "pending"
        assert db.scalar(
            select(InvestigationToolCall).where(
                InvestigationToolCall.investigation_id == investigation_id
            )
        ) is None
    assert not any(item["method"] == "tools/call" for item in opener.requests)


def test_dispatched_mcp_write_lost_reply_is_unknown_not_a_failed_send(client):
    spec = {
        **BASE_SPEC,
        "artifact_name": "dns-cache-flush-loss-tool",
        "tool_name": "dns.flush_cache_lost_reply",
        "description": "Flush one cache with an uncertain provider response.",
        "mcp_tool_name": "flush_dns_cache_lost_reply",
        "risk_level": "change",
        "read_only": False,
        "requires_approval": True,
        "required_permissions": [],
        "fixtures": [{
            "name": "flush result",
            "arguments": {"name": "router.example.test"},
            "expected_output": {"answers": ["flushed"]},
        }],
    }
    version_id = _publish_tool(client, spec)
    server = _server(client)
    healthy = FakeMCPOpener([_tool_advertisement(spec)])
    attestation = _attest_tool(client, server, version_id, healthy)
    activated = client.post(f"/api/v1/mcp/servers/{server['id']}/activations", json={
        "artifact_version_id": version_id, "attestation_id": attestation["id"],
        "canary_percent": 100, "reason": "Controlled lost-reply acceptance.",
        "actor": "platform.approver",
    })
    assert activated.status_code == 201, activated.text
    opener = AcceptedThenLostMCPCallOpener([_tool_advertisement(spec)])
    investigation_id = _configure_investigation(client)
    with SessionLocal() as db:
        investigation, _worker, _execution, runtime = _runtime(db, investigation_id, opener)
        tool = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == spec["tool_name"]))
        assert tool is not None
        with pytest.raises(ValueError):
            runtime.execute(db, tool, {"name": 123}, investigation=investigation, tool_call_id="local-test-call")
        assert opener.accepted_writes == 0
        with pytest.raises(MCPWriteOutcomeUnknown, match="independent provider reconciliation"):
            runtime.execute(db, tool, {"name": "router.example.test"}, investigation=investigation, tool_call_id="local-test-call")
        assert opener.accepted_writes == 1
        assert opener.last_call["params"]["_meta"]["icheck/toolCallId"] == "local-test-call"


def test_mcp_attestor_requires_authenticated_capability_and_rejects_replay(client):
    version_id = _publish_tool(client)
    server = _server(client)
    opener = FakeMCPOpener([_tool_advertisement(BASE_SPEC)])
    queued = client.post(
        f"/api/v1/mcp/servers/{server['id']}/attestations",
        json={
            "artifact_version_id": version_id,
            "reason": "Exercise authenticated claim and one-time lease handling.",
            "actor": "platform.approver",
        },
    )
    assert queued.status_code == 201, queued.text

    reserved = client.post(
        "/api/v1/agent/workers/register",
        headers={
            "X-iCheck-Registration-Token": "test-agent-registration-token"
        },
        json={
            "name": "attempted-attestor-bypass",
            "capabilities": ["mcp_attestation"],
            "labels": {"role": "mcp_attestor"},
        },
    )
    assert reserved.status_code == 422
    assert "reserved" in reserved.text

    wrong = client.post(
        "/api/v1/agent/workers/register",
        headers={
            "X-iCheck-Registration-Token": "test-agent-registration-token"
        },
        json={
            "name": "not-an-attestor",
            "capabilities": ["openai_compatible"],
            "labels": {},
        },
    ).json()
    denied = client.post(
        f"/api/v1/mcp/attestors/{wrong['worker']['id']}/attestations/claim",
        headers={"Authorization": f"Bearer {wrong['access_token']}"},
        json={"max_assignments": 1, "lease_seconds": 120},
    )
    assert denied.status_code == 409
    assert "mcp_attestation" in denied.text
    heartbeat_escalation = client.post(
        f"/api/v1/agent/workers/{wrong['worker']['id']}/heartbeat",
        headers={"Authorization": f"Bearer {wrong['access_token']}"},
        json={
            "state": "online",
            "capabilities": ["mcp_attestation"],
            "labels": {"role": "mcp_attestor"},
        },
    )
    assert heartbeat_escalation.status_code == 422

    registration = client.post(
        "/api/v1/mcp/attestors/register",
        headers={
            "X-iCheck-Registration-Token": "test-mcp-attestor-registration-token"
        },
        json={
            "name": "authenticated-mcp-attestor",
            "labels": {"role": "mcp_attestor"},
        },
    ).json()
    worker_id = registration["worker"]["id"]
    claim_path = f"/api/v1/mcp/attestors/{worker_id}/attestations/claim"
    assert client.post(
        claim_path,
        json={"max_assignments": 1, "lease_seconds": 120},
    ).status_code == 401
    headers = {"Authorization": f"Bearer {registration['access_token']}"}
    claimed = client.post(
        claim_path,
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 120},
    )
    assert claimed.status_code == 200, claimed.text
    assert len(claimed.json()) == 1
    assert "unit-test-mcp-token" not in json.dumps(claimed.json())
    assignment = MCPToolAttestationAssignment.model_validate(claimed.json()[0])
    assert assignment.worker_id == worker_id
    result = attest_assignment(
        assignment,
        credential_broker=WorkerCredentialBroker({}),
        allowed_hosts=["mcp.example.test"],
        opener=opener,
    )
    assert result.status == "passed"
    complete_path = (
        f"/api/v1/mcp/attestors/{worker_id}/attestations/"
        f"{assignment.attestation_id}/complete"
    )
    invalid = client.post(
        complete_path,
        headers=headers,
        json=result.model_copy(
            update={"lease_token": "wrong-lease-token-value-123456789"}
        ).model_dump(mode="json"),
    )
    assert invalid.status_code == 409
    completed = client.post(
        complete_path,
        headers=headers,
        json=result.model_dump(mode="json"),
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "passed"
    replay = client.post(
        complete_path,
        headers=headers,
        json=result.model_dump(mode="json"),
    )
    assert replay.status_code == 409

    activated = client.post(
        f"/api/v1/mcp/servers/{server['id']}/activations",
        json={
            "artifact_version_id": version_id,
            "attestation_id": completed.json()["id"],
            "canary_percent": 100,
            "reason": "Consume the authenticated attestation exactly once.",
            "actor": "platform.approver",
        },
    )
    assert activated.status_code == 201, activated.text
    ledger = client.get(
        f"/api/v1/mcp/attestations?artifact_version_id={version_id}"
    ).json()
    assert ledger[0]["status"] == "consumed"
    assert ledger[0]["consumed_by_activation_id"] == activated.json()["id"]


def test_mcp_canary_circuit_opens_and_requires_fresh_attestation_recovery(
    client,
):
    version_id = _publish_tool(client)
    server = _server(client)
    healthy_opener = FakeMCPOpener([_tool_advertisement(BASE_SPEC)])
    attestation = _attest_tool(client, server, version_id, healthy_opener)
    activated = client.post(
        f"/api/v1/mcp/servers/{server['id']}/activations",
        json={
            "artifact_version_id": version_id,
            "attestation_id": attestation["id"],
            "canary_percent": 100,
            "minimum_successful_calls": 2,
            "maximum_failed_calls": 10,
            "circuit_failure_threshold": 2,
            "reason": "Start a deterministic full-cohort canary for fault testing.",
            "actor": "platform.approver",
        },
    )
    assert activated.status_code == 201, activated.text
    blocked_id = activated.json()["id"]
    too_early = client.post(
        f"/api/v1/mcp/activations/{blocked_id}/promote",
        json={
            "expected_revision": activated.json()["revision"],
            "reason": "Attempt promotion before the evidence threshold.",
            "actor": "platform.approver",
        },
    )
    assert too_early.status_code == 409
    assert "minimum successful" in too_early.text

    investigation_id = _configure_investigation(client)
    failing_opener = FailingMCPCallOpener([_tool_advertisement(BASE_SPEC)])
    with SessionLocal() as db:
        investigation, _worker, _execution, runtime = _runtime(
            db,
            investigation_id,
            failing_opener,
        )
        tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == BASE_SPEC["tool_name"]
            )
        )
        for _ in range(2):
            with pytest.raises(MCPGatewayError, match="request failed"):
                runtime.execute(
                    db,
                    tool,
                    {"name": "router.example.test"},
                    investigation=investigation,
                    tool_call_id="circuit-test-call",
                )
            db.commit()
        rollout = db.get(MCPToolActivation, blocked_id)
        db.refresh(tool)
        assert rollout.rollout_state == "blocked"
        assert rollout.circuit_state == "open"
        assert rollout.failed_calls == 2
        assert rollout.consecutive_failures == 2
        assert len(rollout.last_failure_sha256) == 64
        assert tool.enabled is False
        alert = db.scalar(
            select(Alert).where(Alert.event_type == "mcp.tool.circuit.open")
        )
        assert alert is not None
        assert alert.status == AlertStatus.OPEN
        assert alert.entity_id == blocked_id
        alert_id = alert.id
        blocked_revision = rollout.revision

    fresh = _attest_tool(client, server, version_id, healthy_opener)
    recovered = client.post(
        f"/api/v1/mcp/activations/{blocked_id}/recover",
        json={
            "expected_revision": blocked_revision,
            "attestation_id": fresh["id"],
            "canary_percent": 100,
            "reason": "Fresh Worker evidence confirms the endpoint recovered.",
            "actor": "platform.approver",
        },
    )
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["rollout_state"] == "canary"
    assert recovered.json()["circuit_state"] == "closed"
    assert recovered.json()["failed_calls"] == 0
    assert recovered.json()["consecutive_failures"] == 0
    assert recovered.json()["revision"] == blocked_revision + 1
    with SessionLocal() as db:
        alert = db.get(Alert, alert_id)
        assert alert is not None
        assert alert.status == AlertStatus.RESOLVED
        assert alert.resolved_by == "platform.approver"


def test_mcp_attestation_fails_closed_on_credential_revision_drift(client):
    version_id = _publish_tool(client)
    profile = _credential_profile(client)
    server = _server(client, profile["id"])
    opener = FakeMCPOpener([_tool_advertisement(BASE_SPEC)])
    queued = client.post(
        f"/api/v1/mcp/servers/{server['id']}/attestations",
        json={
            "artifact_version_id": version_id,
            "reason": "Pin the exact credential profile revision.",
            "actor": "platform.approver",
        },
    )
    assert queued.status_code == 201, queued.text
    registration = client.post(
        "/api/v1/mcp/attestors/register",
        headers={
            "X-iCheck-Registration-Token": "test-mcp-attestor-registration-token"
        },
        json={
            "name": "revision-drift-attestor",
            "labels": {},
        },
    ).json()
    worker_id = registration["worker"]["id"]
    headers = {"Authorization": f"Bearer {registration['access_token']}"}
    claimed = client.post(
        f"/api/v1/mcp/attestors/{worker_id}/attestations/claim",
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 120},
    )
    assignment = MCPToolAttestationAssignment.model_validate(claimed.json()[0])
    result = attest_assignment(
        assignment,
        credential_broker=WorkerCredentialBroker(
            {"environment": EnvironmentCredentialProvider()}
        ),
        allowed_hosts=["mcp.example.test"],
        opener=opener,
    )
    assert result.status == "passed"
    with SessionLocal() as db:
        stored = db.get(CredentialProfile, profile["id"])
        stored.revision += 1
        db.commit()
    completed = client.post(
        (
            f"/api/v1/mcp/attestors/{worker_id}/attestations/"
            f"{assignment.attestation_id}/complete"
        ),
        headers=headers,
        json=result.model_dump(mode="json"),
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "failed"
    assert completed.json()["failure_code"] == "snapshot_drift"


def test_mcp_attestation_retry_is_bounded_and_dead_letters(client):
    version_id = _publish_tool(client)
    server = _server(client)
    queued = client.post(
        f"/api/v1/mcp/servers/{server['id']}/attestations",
        json={
            "artifact_version_id": version_id,
            "reason": "Prove retry backoff stops after the configured bound.",
            "actor": "platform.approver",
        },
    )
    assert queued.status_code == 201, queued.text
    registration = client.post(
        "/api/v1/mcp/attestors/register",
        headers={
            "X-iCheck-Registration-Token": "test-mcp-attestor-registration-token"
        },
        json={"name": "bounded-retry-attestor", "labels": {}},
    ).json()
    worker_id = registration["worker"]["id"]
    headers = {"Authorization": f"Bearer {registration['access_token']}"}
    claim_path = f"/api/v1/mcp/attestors/{worker_id}/attestations/claim"

    for attempt in range(1, 4):
        claimed = client.post(
            claim_path,
            headers=headers,
            json={"max_assignments": 1, "lease_seconds": 120},
        )
        assert claimed.status_code == 200, claimed.text
        assignment = MCPToolAttestationAssignment.model_validate(
            claimed.json()[0]
        )
        assert assignment.attempt == attempt
        completed = client.post(
            (
                f"/api/v1/mcp/attestors/{worker_id}/attestations/"
                f"{assignment.attestation_id}/complete"
            ),
            headers=headers,
            json={
                "lease_token": assignment.lease_token,
                "status": "failed",
                "checked_at": utcnow().isoformat(),
                "failure_code": "transport_error",
                "failure_sha256": "a" * 64,
                "retryable": True,
            },
        )
        assert completed.status_code == 200, completed.text
        expected = "pending" if attempt < 3 else "dead_letter"
        assert completed.json()["status"] == expected
        if attempt < 3:
            with SessionLocal() as db:
                stored = db.get(MCPToolAttestation, assignment.attestation_id)
                stored.next_attempt_at = utcnow() - timedelta(seconds=1)
                db.commit()

    exhausted = client.post(
        claim_path,
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 120},
    )
    assert exhausted.status_code == 200, exhausted.text
    assert exhausted.json() == []


def test_mcp_attestor_worker_has_no_direct_database_dependency():
    import icheck.mcp_attestor_worker as worker_module

    source_path = Path(worker_module.__file__).resolve()
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
    assert "sqlalchemy" not in imported_modules
    assert "database" not in imported_modules
    assert "models" not in imported_modules
    assert "SessionLocal" not in source
    assert "ICHECK_DATABASE_URL" not in source
    environment_template = (
        source_path.parents[2] / "deploy/systemd/mcp-attestor.env.example"
    ).read_text(encoding="utf-8")
    assert "ICHECK_DATABASE_URL" not in environment_template
