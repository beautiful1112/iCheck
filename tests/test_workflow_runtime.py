from __future__ import annotations

import json

from langgraph.checkpoint.memory import InMemorySaver
from sqlalchemy import select

from icheck.builtin_agent_tools import ensure_builtin_agent_tools
from icheck.database import SessionLocal
from icheck.langgraph_runtime import GraphToolRequest, initial_graph_state
from icheck.models import (
    AgentToolRegistration,
    Investigation,
    InvestigationToolCall,
    WorkflowTriggerEvent,
)
from icheck.services.agent_graph import run_database_investigation
from icheck.services.agent_tools import DatabaseToolExecutor
from icheck.services.workflow_reasoner import WorkflowReasoner
from icheck.services.workflow_runtime import (
    dispatch_workflow_trigger_events,
    workflow_plan_marker,
)
from icheck.services.workflow_templates import workflow_artifact_documents
from icheck.studio_schemas import GeneratedWorkflowSpec


WORKFLOW_SPEC = {
    "artifact_name": "device-triage-runtime",
    "description": "Load a device, then let a bounded agent inspect open alerts.",
    "trigger": {"trigger_type": "manual", "event_type": None},
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["device_id"],
        "properties": {
            "device_id": {"type": "string", "minLength": 1, "maxLength": 36}
        },
    },
    "start_node": "load_device",
    "nodes": [
        {
            "node_id": "load_device",
            "title": "Load device evidence",
            "node_type": "tool",
            "tool_name": "inventory.get_device",
            "input_bindings": [
                {"argument": "device_id", "input_path": "device_id"}
            ],
            "on_success": "analyze_alerts",
            "requires_approval": False,
        },
        {
            "node_id": "analyze_alerts",
            "title": "Analyze related operational risk",
            "node_type": "agent_loop",
            "objective": "Inspect open alerts and explain whether operator attention is needed.",
            "allowed_tools": ["alerts.list_open"],
            "on_success": "complete",
            "max_iterations": 2,
        },
        {
            "node_id": "complete",
            "title": "Complete triage",
            "node_type": "end",
        },
    ],
    "max_runtime_seconds": 180,
    "max_total_tool_calls": 5,
    "max_total_tokens": 1000,
}


ALERT_WORKFLOW_SPEC = {
    "artifact_name": "alert-triage-runtime",
    "description": "Start a bounded alert triage when a device becomes unreachable.",
    "trigger": {
        "trigger_type": "alert",
        "event_type": "device.unreachable",
    },
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["severity"],
        "properties": {
            "severity": {
                "type": "string",
                "enum": ["critical", "warning", "info"],
            }
        },
    },
    "start_node": "load_alerts",
    "nodes": [
        {
            "node_id": "load_alerts",
            "title": "Load matching open alerts",
            "node_type": "tool",
            "tool_name": "alerts.list_open",
            "input_bindings": [
                {"argument": "severity", "input_path": "severity"}
            ],
            "on_success": "complete",
            "requires_approval": False,
        },
        {
            "node_id": "complete",
            "title": "Complete triggered triage",
            "node_type": "end",
        },
    ],
    "max_runtime_seconds": 120,
    "max_total_tool_calls": 2,
    "max_total_tokens": 500,
}


class WorkflowResponse:
    def __init__(self, document, tokens):
        self.body = json.dumps(
            {
                "choices": [{"message": {"content": json.dumps(document)}}],
                "usage": {"total_tokens": tokens},
            }
        ).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, limit):
        return self.body[:limit]


class WorkflowOpener:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout):
        payload = json.loads(request.data)
        prompt = json.loads(payload["messages"][1]["content"])
        self.requests.append(prompt)
        assert {item["name"] for item in prompt["available_tools"]} == {
            "alerts.list_open"
        }
        context = prompt["workflow_agent_loop"]
        assert context["node_id"] == "analyze_alerts"
        assert context["input"]["device_id"]
        if len(self.requests) == 1:
            return WorkflowResponse(
                {
                    "action": "continue",
                    "plan": ["Inspect the active alert ledger"],
                    "tool_requests": [
                        {
                            "tool_name": "alerts.list_open",
                            "arguments": {"limit": 10},
                            "purpose": "Ground the triage in active alerts",
                        }
                    ],
                },
                80,
            )
        return WorkflowResponse(
            {
                "action": "complete",
                "plan": ["Triage complete"],
                "confidence": 0.88,
                "conclusion": "Device and alert evidence were collected.",
                "uncertainty": [],
            },
            60,
        )


def _configure_route(client):
    provider = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "workflow-runtime-provider",
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
            "display_name": "Workflow runtime model",
            "model_name": "workflow-runtime-model",
            "capabilities": ["chat", "json_schema"],
            "created_by": "platform.admin",
        },
    ).json()
    response = client.post(
        "/api/v1/ai/routes",
        json={
            "purpose": "investigation",
            "primary_model_id": model["id"],
            "max_iterations": 8,
            "max_tool_calls": 20,
            "timeout_seconds": 300,
            "token_budget": 20000,
            "created_by": "platform.admin",
        },
    )
    assert response.status_code == 201, response.text


def _publish_workflow(client, spec_document=WORKFLOW_SPEC):
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        definition, implementation, tests = workflow_artifact_documents(
            db,
            GeneratedWorkflowSpec.model_validate(spec_document),
        )
    created = client.post(
        "/api/v1/artifacts",
        json={
            "name": spec_document["artifact_name"],
            "kind": "workflow",
            "description": spec_document["description"],
            "owner": "capability.author",
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
    return published.json()


def _device(client):
    response = client.post(
        "/api/v1/assets/devices",
        json={
            "name": "workflow-router-01",
            "kind": "router",
            "management_ip": "192.0.2.91",
            "site": "LAB",
            "labels": {"role": "edge"},
            "connections": [
                {
                    "protocol": "icmp",
                    "configuration": {"probe_timeout_seconds": 2},
                }
            ],
            "created_by": "l1.operator",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_published_workflow_runs_fixed_and_agent_nodes_on_shared_graph(client):
    _configure_route(client)
    version = _publish_workflow(client)
    device_id = _device(client)

    listed = client.get("/api/v1/workflow-runtime/workflows")
    assert listed.status_code == 200, listed.text
    assert listed.json()[0]["artifact_name"] == "device-triage-runtime"
    started = client.post(
        f"/api/v1/workflow-runtime/workflows/{version['id']}/investigations",
        json={
            "title": "Run governed triage Workflow",
            "workflow_input": {"device_id": device_id},
            "scope": {"device_ids": [device_id]},
            "operator_context": "Triage the lab edge router.",
            "actor": "l1.operator",
        },
    )
    assert started.status_code == 200, started.text
    document = started.json()["investigation"]
    assert document["workflow_input"] == {"device_id": device_id}
    assert document["workflow_artifact_version_id"] == version["id"]
    assert document["max_tool_calls"] == 5
    assert document["timeout_seconds"] == 180
    assert document["token_budget"] == 1000

    with SessionLocal() as db:
        investigation = db.get(Investigation, document["id"])
        assert investigation is not None
        opener = WorkflowOpener()
        result = run_database_investigation(
            db,
            investigation,
            reasoner=WorkflowReasoner(db, investigation, opener=opener),
            checkpointer=InMemorySaver(),
        )
        assert result["status"] == "completed"
        assert result["structured_output"]["terminal_node"] == "complete"
        assert len(result["structured_output"]["evidence_ids"]) == 1
        assert len(opener.requests) == 2
        db.refresh(investigation)
        assert investigation.status == "completed"
        assert investigation.tokens_used == 140
        calls = list(
            db.scalars(
                select(InvestigationToolCall).where(
                    InvestigationToolCall.investigation_id == investigation.id
                )
            ).all()
        )
        assert len(calls) == 2

        device_tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "inventory.get_device"
            )
        )
        assert device_tool is not None
        state = initial_graph_state(
            investigation_id=investigation.id,
            objective=investigation.objective,
            scope=investigation.scope,
            max_iterations=investigation.max_iterations,
            max_tool_calls=investigation.max_tool_calls,
            token_budget=investigation.token_budget,
        )
        state["plan"] = [workflow_plan_marker("analyze_alerts", "agent", 1)]
        try:
            DatabaseToolExecutor(db, investigation)(
                GraphToolRequest(
                    tool_name=device_tool.name,
                    arguments={"device_id": device_id},
                    purpose="Attempt to escape the Workflow node allowlist",
                ),
                state,
            )
        except PermissionError as exc:
            assert "does not allow" in str(exc)
        else:
            raise AssertionError("Workflow agent-loop allowed an undeclared tool")


def test_workflow_runtime_rejects_invalid_input_and_dependency_drift(client):
    _configure_route(client)
    version = _publish_workflow(client)
    invalid = client.post(
        f"/api/v1/workflow-runtime/workflows/{version['id']}/investigations",
        json={
            "workflow_input": {"unexpected": True},
            "scope": {},
            "actor": "l1.operator",
        },
    )
    assert invalid.status_code == 422
    assert "workflow input is invalid" in invalid.text

    with SessionLocal() as db:
        tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "alerts.list_open"
            )
        )
        assert tool is not None
        tool.enabled = False
        db.commit()
    drifted = client.post(
        f"/api/v1/workflow-runtime/workflows/{version['id']}/investigations",
        json={
            "workflow_input": {"device_id": "device-01"},
            "scope": {},
            "actor": "l1.operator",
        },
    )
    assert drifted.status_code == 422
    assert "unavailable tools" in drifted.text


def test_alert_trigger_activation_uses_idempotent_outbox_dispatch(client):
    _configure_route(client)
    version = _publish_workflow(client, ALERT_WORKFLOW_SPEC)
    activated = client.post(
        f"/api/v1/workflow-runtime/workflows/{version['id']}/trigger-activation",
        json={
            "authorization_scope": {},
            "input_mapping": {"severity": "alert.severity"},
            "actor": "capability.publisher",
        },
    )
    assert activated.status_code == 201, activated.text
    activation = activated.json()
    assert activation["event_type"] == "device.unreachable"

    emitted = client.post(
        "/api/v1/alerts/events",
        json={
            "dedup_key": "workflow-trigger:router-01",
            "event_type": "device.unreachable",
            "entity_type": "device",
            "entity_id": "router-01",
            "title": "Router is unreachable",
            "severity": "critical",
            "details": {"failed_probes": 3},
        },
    )
    assert emitted.status_code == 201, emitted.text
    events = client.get("/api/v1/workflow-runtime/trigger-events").json()
    assert len(events) == 1
    assert events[0]["status"] == "pending"

    with SessionLocal() as db:
        assert dispatch_workflow_trigger_events(db) == 1
        event = db.get(WorkflowTriggerEvent, events[0]["id"])
        assert event is not None
        assert event.status == "succeeded"
        investigations = list(
            db.scalars(
                select(Investigation).where(
                    Investigation.workflow_trigger_event_id == event.id
                )
            ).all()
        )
        assert len(investigations) == 1
        assert investigations[0].workflow_input == {"severity": "critical"}
        assert investigations[0].status == "running"
        assert dispatch_workflow_trigger_events(db) == 0

    repeated = client.post(
        "/api/v1/alerts/events",
        json={
            "dedup_key": "workflow-trigger:router-01",
            "event_type": "device.unreachable",
            "entity_type": "device",
            "entity_id": "router-01",
            "title": "Router is still unreachable",
            "severity": "critical",
            "details": {"failed_probes": 4},
        },
    )
    assert repeated.status_code == 201
    assert repeated.json()["id"] == emitted.json()["id"]
    assert len(client.get("/api/v1/workflow-runtime/trigger-events").json()) == 1

    disabled = client.post(
        f"/api/v1/workflow-runtime/trigger-activations/{activation['id']}/disable",
        json={"actor": "capability.publisher"},
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["enabled"] is False
