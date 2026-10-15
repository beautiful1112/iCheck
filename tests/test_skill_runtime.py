from __future__ import annotations

import json

from langgraph.checkpoint.memory import InMemorySaver
from sqlalchemy import select

from icheck.builtin_agent_tools import ensure_builtin_agent_tools
from icheck.database import SessionLocal
from icheck.langgraph_runtime import GraphToolRequest, initial_graph_state
from icheck.models import AgentToolRegistration, Investigation, InvestigationToolCall
from icheck.services.agent_graph import run_database_investigation
from icheck.services.agent_tools import DatabaseToolExecutor
from icheck.services.model_reasoner import OpenAICompatibleReasoner
from icheck.services.tool_skills import skill_artifact_documents
from icheck.studio_schemas import GeneratedSkillSpec


SKILL_SPEC = {
    "artifact_name": "device-health-runtime-skill",
    "skill_name": "device.health_runtime",
    "description": "Inspect one device and return a typed health result.",
    "instructions": (
        "Load only the requested device, ground the summary in persisted device "
        "evidence, and escalate instead of guessing when evidence is missing."
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
    "allowed_tools": ["inventory.get_device"],
    "success_criteria": ["The summary cites persisted device evidence."],
    "escalation_conditions": ["The requested device cannot be read."],
    "evidence_required": True,
    "read_only": True,
    "max_iterations": 3,
    "max_tool_calls": 2,
    "max_total_tokens": 500,
}


class SkillResponse:
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


class SkillOpener:
    def __init__(self, device_id):
        self.device_id = device_id
        self.requests = []

    def open(self, request, timeout):
        payload = json.loads(request.data)
        prompt = json.loads(payload["messages"][1]["content"])
        self.requests.append(prompt)
        assert {item["name"] for item in prompt["available_tools"]} == {
            "inventory.get_device"
        }
        assert prompt["skill"]["name"] == "device.health_runtime"
        assert prompt["skill"]["input"] == {"device_id": self.device_id}
        assert "subordinate" in payload["messages"][0]["content"]
        if len(self.requests) == 1:
            return SkillResponse(
                {
                    "action": "continue",
                    "plan": ["Read the requested device"],
                    "tool_requests": [
                        {
                            "tool_name": "inventory.get_device",
                            "arguments": {"device_id": self.device_id},
                            "purpose": "Collect persisted device evidence",
                        }
                    ],
                },
                70,
            )
        evidence_ids = prompt["investigation"]["evidence_ids"]
        return SkillResponse(
            {
                "action": "complete",
                "plan": prompt["investigation"]["plan"],
                "confidence": 0.9,
                "conclusion": "The requested device is present in inventory.",
                "structured_output": {
                    "summary": "The requested device is present in inventory.",
                    "confidence": 0.9,
                    "evidence_ids": evidence_ids,
                },
            },
            60,
        )


def _configure_investigation_route(client):
    provider = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "skill-runtime-provider",
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
            "display_name": "Skill runtime model",
            "model_name": "skill-runtime-model",
            "capabilities": ["chat", "json_schema"],
            "created_by": "platform.admin",
        },
    ).json()
    route = client.post(
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
    assert route.status_code == 201, route.text


def _publish_skill(client):
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        definition, implementation, tests = skill_artifact_documents(
            db,
            GeneratedSkillSpec.model_validate(SKILL_SPEC),
        )
    created = client.post(
        "/api/v1/artifacts",
        json={
            "name": SKILL_SPEC["artifact_name"],
            "kind": "skill",
            "description": SKILL_SPEC["description"],
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
    artifact = created.json()
    version_id = artifact["versions"][0]["id"]
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
    return artifact["id"], published.json()


def _device(client):
    created = client.post(
        "/api/v1/assets/devices",
        json={
            "name": "skill-runtime-router-01",
            "kind": "router",
            "management_ip": "192.0.2.87",
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
    assert created.status_code == 201, created.text
    return created.json()["id"]


def _start_skill(client, version_id, device_id):
    response = client.post(
        f"/api/v1/skill-runtime/skills/{version_id}/investigations",
        json={
            "title": "Run device health Skill",
            "skill_input": {"device_id": device_id},
            "scope": {"device_ids": [device_id]},
            "operator_context": "Check the lab edge router.",
            "actor": "l1.operator",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["investigation"]


def test_published_skill_runs_on_langgraph_with_pinned_tools_and_typed_output(client):
    _configure_investigation_route(client)
    _artifact_id, version = _publish_skill(client)
    device_id = _device(client)

    listed = client.get("/api/v1/skill-runtime/skills")
    assert listed.status_code == 200, listed.text
    assert listed.json()[0]["skill_name"] == "device.health_runtime"
    investigation_document = _start_skill(client, version["id"], device_id)
    assert investigation_document["status"] == "running"
    assert investigation_document["max_iterations"] == 3
    assert investigation_document["max_tool_calls"] == 2
    assert investigation_document["token_budget"] == 500
    assert investigation_document["skill_input"] == {"device_id": device_id}

    with SessionLocal() as db:
        investigation = db.get(Investigation, investigation_document["id"])
        assert investigation is not None
        opener = SkillOpener(device_id)
        result = run_database_investigation(
            db,
            investigation,
            reasoner=OpenAICompatibleReasoner(
                db,
                investigation,
                opener=opener,
            ),
            checkpointer=InMemorySaver(),
        )
        assert result["status"] == "completed"
        assert result["structured_output"]["confidence"] == 0.9
        db.refresh(investigation)
        assert investigation.status == "completed"
        assert investigation.structured_output == result["structured_output"]
        assert investigation.tool_calls_used == 1
        calls = list(
            db.scalars(
                select(InvestigationToolCall).where(
                    InvestigationToolCall.investigation_id == investigation.id
                )
            ).all()
        )
        device_tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "inventory.get_device"
            )
        )
        assert device_tool is not None
        assert [item.tool_id for item in calls] == [device_tool.id]

        alerts_tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "alerts.list_open"
            )
        )
        assert alerts_tool is not None
        try:
            DatabaseToolExecutor(db, investigation)(
                GraphToolRequest(
                    tool_name=alerts_tool.name,
                    arguments={},
                    purpose="Attempt to escape the Skill allowlist",
                ),
                initial_graph_state(
                    investigation_id=investigation.id,
                    objective=investigation.objective,
                    scope=investigation.scope,
                    max_iterations=3,
                    max_tool_calls=2,
                    token_budget=500,
                ),
            )
        except PermissionError as exc:
            assert "does not allow" in str(exc)
        else:
            raise AssertionError("Skill allowed an undeclared tool")


def test_skill_runtime_rejects_invalid_input_and_dependency_drift(client):
    _configure_investigation_route(client)
    _artifact_id, version = _publish_skill(client)
    invalid = client.post(
        f"/api/v1/skill-runtime/skills/{version['id']}/investigations",
        json={
            "skill_input": {"unexpected": True},
            "scope": {},
            "actor": "l1.operator",
        },
    )
    assert invalid.status_code == 422
    assert "skill input is invalid" in invalid.text

    with SessionLocal() as db:
        tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "inventory.get_device"
            )
        )
        assert tool is not None
        tool.enabled = False
        db.commit()
    drifted = client.post(
        f"/api/v1/skill-runtime/skills/{version['id']}/investigations",
        json={
            "skill_input": {"device_id": "device-1"},
            "scope": {},
            "actor": "l1.operator",
        },
    )
    assert drifted.status_code == 422
    assert "unavailable tools" in drifted.text
