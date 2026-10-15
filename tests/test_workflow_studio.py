from __future__ import annotations

import json
from copy import deepcopy

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from icheck.builtin_agent_tools import ensure_builtin_agent_tools
from icheck.database import SessionLocal
from icheck.services.workflow_templates import validate_workflow_spec
from icheck.studio_schemas import GeneratedWorkflowSpec
from icheck.studio_schemas import WorkflowNode
from test_preview_alert_workspace import administrator


WORKFLOW_SPEC = {
    "artifact_name": "device-triage-workflow",
    "description": "Inspect a device and open alerts, then run bounded diagnosis.",
    "trigger": {"trigger_type": "manual", "event_type": None},
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["device_id"],
        "properties": {
            "device_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 36,
            }
        },
    },
    "start_node": "load_device",
    "nodes": [
        {
            "node_id": "load_device",
            "title": "Load device state",
            "node_type": "tool",
            "tool_name": "inventory.get_device",
            "objective": None,
            "input_bindings": [
                {"argument": "device_id", "input_path": "device_id"}
            ],
            "allowed_tools": [],
            "on_success": "load_alerts",
            "on_failure": "complete",
            "requires_approval": False,
            "rollback_node_id": None,
            "max_iterations": None,
        },
        {
            "node_id": "load_alerts",
            "title": "Load current alerts",
            "node_type": "tool",
            "tool_name": "alerts.list_open",
            "objective": None,
            "input_bindings": [],
            "allowed_tools": [],
            "on_success": "diagnose",
            "on_failure": "complete",
            "requires_approval": False,
            "rollback_node_id": None,
            "max_iterations": None,
        },
        {
            "node_id": "diagnose",
            "title": "Bounded evidence diagnosis",
            "node_type": "agent_loop",
            "tool_name": None,
            "objective": "Explain the most likely device issue from read-only evidence.",
            "input_bindings": [],
            "allowed_tools": [
                "inventory.get_device",
                "alerts.list_open",
            ],
            "on_success": "complete",
            "on_failure": "complete",
            "requires_approval": False,
            "rollback_node_id": None,
            "max_iterations": 3,
        },
        {
            "node_id": "complete",
            "title": "Complete",
            "node_type": "end",
            "tool_name": None,
            "objective": None,
            "input_bindings": [],
            "allowed_tools": [],
            "on_success": None,
            "on_failure": None,
            "requires_approval": False,
            "rollback_node_id": None,
            "max_iterations": None,
        },
    ],
    "max_runtime_seconds": 300,
    "max_total_tool_calls": 12,
    "max_total_tokens": 20000,
}


@pytest.mark.parametrize("node_type", ["tool", "post_check", "rollback", "agent_loop", "approval", "end"])
def test_workflow_provider_schema_matches_conditional_node_shapes(node_type):
    schema = GeneratedWorkflowSpec.model_json_schema()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    node = {"node_id": "review", "title": "Review stored evidence", "node_type": node_type}
    if node_type != "end":
        node["on_success"] = "complete"
    if node_type in {"tool", "post_check", "rollback"}:
        node["tool_name"] = "inventory.get_device"
    if node_type == "agent_loop":
        node.update(objective="Review saved evidence only.", allowed_tools=["inventory.get_device"], max_iterations=3)
    document = deepcopy(WORKFLOW_SPEC)
    document["start_node"] = "review"
    document["nodes"] = [node, {"node_id": "complete", "title": "Complete", "node_type": "end"}]
    # Both sparse input and the existing persisted form with null/default keys
    # remain accepted; schema generation does not change runtime serialization.
    validator.validate(document)
    normalized = GeneratedWorkflowSpec.model_validate(document).model_dump()
    validator.validate(normalized)
    assert "on_success" in normalized["nodes"][0]

    invalid_nodes = [{**node, "unexpected_execution_field": True}]
    if node_type != "end":
        invalid_nodes.extend([
            {key: value for key, value in node.items() if key != "on_success"},
            {**node, "on_success": None},
            {**node, "on_success": ""},
        ])
    else:
        invalid_nodes.extend({**node, **patch} for patch in [
            {"on_success": "complete"}, {"on_failure": "complete"},
            {"rollback_node_id": "complete"}, {"objective": "Execute something"},
            {"input_bindings": [{"argument": "device_id", "input_path": "device_id"}]},
            {"requires_approval": True},
        ])
    if node_type in {"tool", "post_check", "rollback"}:
        invalid_nodes.extend([
            {key: value for key, value in node.items() if key != "tool_name"},
            {**node, "tool_name": None},
        ])
    else:
        invalid_nodes.append({**node, "tool_name": "inventory.get_device"})
    if node_type == "agent_loop":
        for field in ("objective", "max_iterations", "allowed_tools"):
            invalid_nodes.append({key: value for key, value in node.items() if key != field})
        invalid_nodes.extend({**node, **patch} for patch in [
            {"objective": None}, {"max_iterations": None}, {"max_iterations": 26}, {"allowed_tools": []},
        ])
    else:
        invalid_nodes.extend([
            {**node, "allowed_tools": ["inventory.get_device"]}, {**node, "max_iterations": 1},
        ])
    for invalid in invalid_nodes:
        document["nodes"][0] = invalid
        assert not validator.is_valid(document), invalid
        with pytest.raises(ValidationError):
            WorkflowNode.model_validate(invalid)


class FakeResponse:
    def __init__(self, document):
        self.body = json.dumps(
            {
                "choices": [
                    {"message": {"content": json.dumps(document)}}
                ],
                "usage": {"total_tokens": 57},
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
            "name": "workflow-author-provider",
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
            "display_name": "Workflow author",
            "model_name": "workflow-author",
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


def seed_tools():
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)


@pytest.mark.parametrize("kind",["workflow","skill"])
def test_studio_restore_keeps_conversation_exact_review_and_active_version(client,monkeypatch,kind):
    from copy import deepcopy
    from test_skill_runtime import SKILL_SPEC
    configure_route(client); seed_tools()
    first=deepcopy(WORKFLOW_SPEC if kind=="workflow" else SKILL_SPEC)
    revised={**first,"description":"Revised bounded check description for operator review."}
    opener=FakeOpener([first,revised]); monkeypatch.setattr("icheck.services.structured_model.build_opener",lambda *_:opener)
    created=client.post(f"/api/v1/capability-studio/sessions/{kind}s",json={"title":"Reusable check","brief":"Create a reusable read-only check for the selected device, citing evidence.","created_by":"author"})
    assert created.status_code==201,created.text
    path="/api/v1/capability-studio/sessions/"+created.json()["id"]
    generated=client.post(path+"/generate",json={"actor":"author"})
    assert generated.status_code==200,generated.text
    original=generated.json(); original_id=original["artifact_version_id"]
    assert client.post(path+"/publish",json={"actor":"publisher","expected_artifact_version_id":original_id}).status_code==200
    revised_response=client.post(path+"/messages",json={"actor":"author","content":"Revise the description without changing the tools or objective."})
    assert revised_response.status_code==200,revised_response.text
    current=revised_response.json()["artifact_version_id"]
    stale=client.post(path+"/restore-preview",json={"actor":"operator","source_version":1,"reason":"Restore original description.","expected_artifact_version_id":original_id})
    assert stale.status_code==409
    restored=client.post(path+"/restore-preview",json={"actor":"operator","source_version":1,"reason":"Restore original description.","expected_artifact_version_id":current})
    assert restored.status_code==201,restored.text
    document=restored.json()
    assert document["status"]=="validated" and document["current_spec"]["description"]==first["description"]
    assert document["generation_attempt_id"] is None and document["artifact_version_id"] not in {current,original_id}
    assert document["messages"][-1]["structured_content"]["artifact_version_id"]==document["artifact_version_id"]
    versions=client.get("/api/v1/artifacts/"+document["artifact_id"]).json()["versions"]
    assert len(versions)==3 and next(row for row in versions if row["id"]==original_id)["status"]=="published"
    assert versions[-1]["content_hash"]==versions[0]["content_hash"] and len(opener.requests)==2
    saved=client.post(path+"/publish",json={"actor":"publisher","expected_artifact_version_id":document["artifact_version_id"]})
    assert saved.status_code==200 and saved.json()["status"]=="published",saved.text


def test_studio_restore_failure_rolls_back_candidate_and_preserves_current_draft(client,monkeypatch):
    from icheck.models import AgentToolRegistration
    from sqlalchemy import select
    configure_route(client); seed_tools()
    opener=FakeOpener([WORKFLOW_SPEC]); monkeypatch.setattr("icheck.services.structured_model.build_opener",lambda *_:opener)
    created=create_workflow_session(client); path="/api/v1/capability-studio/sessions/"+created["id"]
    generated=client.post(path+"/generate",json={"actor":"author"}).json()
    with SessionLocal() as db:
        db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name=="inventory.get_device")).enabled=False; db.commit()
    response=client.post(path+"/restore-preview",json={"actor":"operator","source_version":1,"reason":"Retain prior behavior.","expected_artifact_version_id":generated["artifact_version_id"]})
    assert response.status_code==422,response.text
    current=client.get(path).json()
    assert current["artifact_version_id"]==generated["artifact_version_id"] and current["status"]=="validated"
    assert len(client.get("/api/v1/artifacts/"+generated["artifact_id"]).json()["versions"])==1
    assert len(opener.requests)==1


def test_restore_preview_requires_global_current_actor_and_preserves_namespace(client,administrator,monkeypatch):
    from icheck.database import DEFAULT_TENANT_ID,DEFAULT_REGION_ID
    client.headers.update(administrator)
    client.headers.update({"X-Icheck-Tenant-ID":DEFAULT_TENANT_ID,"X-Icheck-Region-ID":DEFAULT_REGION_ID})
    configure_route(client); seed_tools()
    opener=FakeOpener([WORKFLOW_SPEC]); monkeypatch.setattr("icheck.services.structured_model.build_opener",lambda *_:opener)
    created=create_workflow_session(client); path="/api/v1/capability-studio/sessions/"+created["id"]
    generated=client.post(path+"/generate",json={"actor":"spoofed-author"}).json()
    payload={"actor":"spoofed-restorer","source_version":1,"reason":"Restore the reviewed original.","expected_artifact_version_id":generated["artifact_version_id"]}
    role=client.post("/api/v1/auth/roles",json={"name":"site-studio-review","description":"Scoped fixture","permissions":["capabilities.manage"]}).json()
    account=client.post("/api/v1/auth/principals",json={"subject":"site.studio.fixture","display_name":"Scoped fixture"}).json()
    assert client.post(f"/api/v1/auth/principals/{account['id']}/bindings",json={"role_id":role["id"],"scope":{"sites":["LAB"]}}).status_code==201
    token=client.post(f"/api/v1/auth/principals/{account['id']}/tokens",json={"name":"scoped","expires_in_hours":1}).json()["access_token"]
    assert client.post(path+"/restore-preview",json=payload,headers={"Authorization":"Bearer "+token}).status_code==403
    assert client.post(path+"/restore-preview",json=payload,headers={"Authorization":"Bearer not-a-token"}).status_code==401
    restored=client.post(path+"/restore-preview",json=payload)
    assert restored.status_code==201,restored.text
    versions=client.get("/api/v1/artifacts/"+generated["artifact_id"]).json()["versions"]
    assert len(versions)==2 and versions[-1]["created_by"]=="preview.admin@example.test"


def test_conversation_created_revised_and_restored_workflow_runs_on_existing_graph(client,monkeypatch):
    from copy import deepcopy
    from langgraph.checkpoint.memory import InMemorySaver
    from test_workflow_runtime import WORKFLOW_SPEC as RUNTIME_SPEC,WorkflowOpener,_configure_route,_device
    from icheck.models import Investigation,InvestigationToolCall
    from icheck.services.agent_graph import run_database_investigation
    from icheck.services.workflow_reasoner import WorkflowReasoner
    from sqlalchemy import select
    configure_route(client); _configure_route(client); seed_tools()
    spec=deepcopy(RUNTIME_SPEC)
    opener=FakeOpener([spec,{**spec,"description":"A revised operator check."}]); monkeypatch.setattr("icheck.services.structured_model.build_opener",lambda *_:opener)
    created=create_workflow_session(client); path="/api/v1/capability-studio/sessions/"+created["id"]
    first=client.post(path+"/generate",json={"actor":"author"}).json()
    second=client.post(path+"/messages",json={"actor":"author","content":"Revise the operator-facing description only."})
    assert second.status_code==200,second.text
    restored=client.post(path+"/restore-preview",json={"actor":"operator","source_version":1,"reason":"Use the prior triage wording.","expected_artifact_version_id":second.json()["artifact_version_id"]})
    assert restored.status_code==201,restored.text
    version_id=restored.json()["artifact_version_id"]
    assert version_id not in {first["artifact_version_id"],second.json()["artifact_version_id"]}
    assert client.post(path+"/publish",json={"actor":"publisher","expected_artifact_version_id":version_id}).status_code==200
    device_id=_device(client)
    started=client.post(f"/api/v1/workflow-runtime/workflows/{version_id}/investigations",json={"workflow_input":{"device_id":device_id},"scope":{"device_ids":[device_id]},"actor":"operator"})
    assert started.status_code==200,started.text
    with SessionLocal() as db:
        investigation=db.get(Investigation,started.json()["investigation"]["id"])
        reasoner_wire=WorkflowOpener()
        result=run_database_investigation(db,investigation,reasoner=WorkflowReasoner(db,investigation,opener=reasoner_wire),checkpointer=InMemorySaver())
        assert result["status"]=="completed" and result["structured_output"]["evidence_ids"]
        calls=db.scalars(select(InvestigationToolCall).where(InvestigationToolCall.investigation_id==investigation.id)).all()
        assert len(calls)==2 and len(reasoner_wire.requests)==2
        assert investigation.workflow_artifact_version_id==version_id and len(opener.requests)==2


def create_workflow_session(client):
    response = client.post(
        "/api/v1/capability-studio/sessions/workflows",
        json={
            "title": "Device triage",
            "brief": (
                "Build a bounded device triage workflow that loads device and "
                "alert evidence before a read-only diagnostic loop."
            ),
            "route_purpose": "capability.authoring",
            "created_by": "workflow.author",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def register_test_tool(client, name, *, read_only):
    response = client.post(
        "/api/v1/agent/tools",
        json={
            "name": name,
            "description": f"Acceptance tool {name}",
            "transport": "internal",
            "handler": name,
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["device_id"],
                "properties": {"device_id": {"type": "string"}},
            },
            "output_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"ok": {"type": "boolean"}},
            },
            "risk_level": "observe" if read_only else "change",
            "read_only": read_only,
            "required_permissions": [
                "assets.read" if read_only else "changes.execute"
            ],
            "created_by": "test.setup",
        },
    )
    assert response.status_code == 201, response.text


def test_workflow_studio_generates_validates_publishes_and_refines(
    client,
    monkeypatch,
):
    seed_tools()
    route, model = configure_route(client)
    refined_spec = {
        **WORKFLOW_SPEC,
        "artifact_name": "model-must-not-rename-existing-workflow",
        "description": "Refined device triage with a tighter wall-clock budget.",
        "max_runtime_seconds": 240,
    }
    opener = FakeOpener([WORKFLOW_SPEC, refined_spec])
    monkeypatch.setattr(
        "icheck.services.structured_model.build_opener",
        lambda *_handlers: opener,
    )

    created = create_workflow_session(client)
    assert created["artifact_kind"] == "workflow"
    assert created["status"] == "draft"
    assert created["sample_document"] == {}

    generated = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/generate",
        json={"actor": "workflow.author"},
    )
    assert generated.status_code == 200, generated.text
    document = generated.json()
    assert document["status"] == "validated"
    assert document["route_id"] == route["id"]
    assert document["model_id"] == model["id"]
    assert document["tokens_used"] == 57
    report = document["messages"][-1]["structured_content"][
        "validation_report"
    ]
    assert report["runtime"] == "icheck_workflow_v1"
    assert report["isolation"] == "declarative_graph"
    assert report["node_count"] == 4
    assert report["end_nodes"] == ["complete"]
    assert report["cycles"] == []
    assert report["tool_dependencies"] == [
        "alerts.list_open",
        "inventory.get_device",
    ]
    assert report["required_permissions"] == ["alerts.read", "assets.read"]
    assert report["budgets"] == {
        "max_runtime_seconds": 300,
        "max_total_tool_calls": 12,
        "max_total_tokens": 20000,
    }

    request = json.loads(opener.requests[0][0].data)
    assert 'node_type="end"' in request["messages"][0]["content"]
    assert "omit tool_name" in request["messages"][0]["content"]
    prompt = json.loads(request["messages"][1]["content"])
    assert {item["name"] for item in prompt["tool_catalog"]} >= {
        "inventory.get_device",
        "alerts.list_open",
    }
    assert request["response_format"]["json_schema"]["strict"] is True
    wire_validator = Draft202012Validator(request["response_format"]["json_schema"]["schema"])
    wire_validator.validate(WORKFLOW_SPEC)
    missing_transition = deepcopy(WORKFLOW_SPEC)
    missing_transition["nodes"][2]["on_success"] = None
    assert not wire_validator.is_valid(missing_transition)
    attachment_contract = prompt["scheduled_report_attachment_contract"]
    assert attachment_contract["manifest_schema"]["properties"]["format_version"]["const"] == "icheck.report-attachment/v1"
    assert "body" not in attachment_contract["manifest_schema"]["properties"]
    assert attachment_contract["document_bytes_in_model_context"] is False

    artifact_id = document["artifact_id"]
    first_version_id = document["artifact_version_id"]
    artifact = client.get(f"/api/v1/artifacts/{artifact_id}").json()
    assert artifact["kind"] == "workflow"
    assert artifact["name"] == WORKFLOW_SPEC["artifact_name"]
    assert artifact["versions"][0]["implementation"] == {
        "runtime": "icheck_workflow_v1",
        "entrypoint": "load_device",
    }
    assert artifact["versions"][0]["definition"]["format_version"] == (
        "icheck.workflow/v1"
    )

    published = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/publish",
        json={"actor": "workflow.publisher", "expected_artifact_version_id": document["artifact_version_id"]},
    )
    assert published.status_code == 200, published.text
    assert published.json()["status"] == "published"

    refined = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/messages",
        json={
            "actor": "workflow.author",
            "content": "Reduce the wall-clock budget to four minutes.",
        },
    )
    assert refined.status_code == 200, refined.text
    assert refined.json()["status"] == "validated"
    assert refined.json()["tokens_used"] == 114
    assert refined.json()["current_spec"]["artifact_name"] == (
        WORKFLOW_SPEC["artifact_name"]
    )
    second_version_id = refined.json()["artifact_version_id"]
    assert second_version_id != first_version_id
    versions = client.get(f"/api/v1/artifacts/{artifact_id}").json()[
        "versions"
    ]
    assert {item["status"] for item in versions} == {"published", "validated"}


def test_workflow_rejects_unregistered_tools_and_persists_model_accounting(
    client,
    monkeypatch,
):
    seed_tools()
    configure_route(client)
    invalid = json.loads(json.dumps(WORKFLOW_SPEC))
    invalid["nodes"][0]["tool_name"] = "unregistered.read"
    opener = FakeOpener([invalid])
    monkeypatch.setattr(
        "icheck.services.structured_model.build_opener",
        lambda *_handlers: opener,
    )
    created = create_workflow_session(client)

    generated = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/generate",
        json={"actor": "workflow.author"},
    )
    assert generated.status_code == 422, generated.text
    assert "unavailable tools" in generated.text
    failed = client.get(
        f"/api/v1/capability-studio/sessions/{created['id']}"
    ).json()
    assert failed["status"] == "failed"
    assert failed["tokens_used"] == 57
    assert failed["artifact_id"] is None


def test_workflow_rejects_unbounded_deterministic_cycle(client):
    seed_tools()
    cyclic = json.loads(json.dumps(WORKFLOW_SPEC))
    cyclic["nodes"] = [
        {
            **WORKFLOW_SPEC["nodes"][0],
            "node_id": "first",
            "on_success": "second",
            "on_failure": "complete",
        },
        {
            **WORKFLOW_SPEC["nodes"][0],
            "node_id": "second",
            "on_success": "first",
            "on_failure": "complete",
        },
        WORKFLOW_SPEC["nodes"][3],
    ]
    cyclic["start_node"] = "first"
    spec = GeneratedWorkflowSpec.model_validate(cyclic)
    with SessionLocal() as db, pytest.raises(
        ValueError,
        match="cycles require a bounded agent_loop",
    ):
        validate_workflow_spec(db, spec)


def test_state_changing_workflow_requires_dominating_approval_postcheck_and_rollback(
    client,
):
    register_test_tool(client, "test.change", read_only=False)
    register_test_tool(client, "test.verify", read_only=True)
    register_test_tool(client, "test.rollback", read_only=False)
    binding = [{"argument": "device_id", "input_path": "device_id"}]
    nodes = [
        {
            "node_id": "approve",
            "title": "Approve exact change plan",
            "node_type": "approval",
            "tool_name": None,
            "objective": "Require a separate principal to approve the plan.",
            "input_bindings": [],
            "allowed_tools": [],
            "on_success": "change",
            "on_failure": "complete",
            "requires_approval": False,
            "rollback_node_id": None,
            "max_iterations": None,
        },
        {
            "node_id": "change",
            "title": "Apply change",
            "node_type": "tool",
            "tool_name": "test.change",
            "objective": None,
            "input_bindings": binding,
            "allowed_tools": [],
            "on_success": "verify",
            "on_failure": "rollback",
            "requires_approval": True,
            "rollback_node_id": "rollback",
            "max_iterations": None,
        },
        {
            "node_id": "verify",
            "title": "Verify outcome",
            "node_type": "post_check",
            "tool_name": "test.verify",
            "objective": None,
            "input_bindings": binding,
            "allowed_tools": [],
            "on_success": "complete",
            "on_failure": "rollback",
            "requires_approval": False,
            "rollback_node_id": None,
            "max_iterations": None,
        },
        {
            "node_id": "rollback",
            "title": "Restore prior state",
            "node_type": "rollback",
            "tool_name": "test.rollback",
            "objective": None,
            "input_bindings": binding,
            "allowed_tools": [],
            "on_success": "complete",
            "on_failure": "complete",
            "requires_approval": True,
            "rollback_node_id": None,
            "max_iterations": None,
        },
        WORKFLOW_SPEC["nodes"][3],
    ]
    governed = GeneratedWorkflowSpec.model_validate(
        {
            **WORKFLOW_SPEC,
            "artifact_name": "governed-change",
            "start_node": "approve",
            "nodes": nodes,
        }
    )
    with SessionLocal() as db:
        report, _dependencies = validate_workflow_spec(db, governed)
    assert report["approval_nodes"] == ["approve"]
    assert report["state_change_nodes"] == ["change", "rollback"]
    assert report["required_permissions"] == [
        "assets.read",
        "changes.execute",
    ]

    bypass = GeneratedWorkflowSpec.model_validate(
        {
            **WORKFLOW_SPEC,
            "artifact_name": "unsafe-change",
            "start_node": "change",
            "nodes": nodes[1:],
        }
    )
    with SessionLocal() as db, pytest.raises(
        ValueError,
        match="can bypass an approval node",
    ):
        validate_workflow_spec(db, bypass)
