import json

from langgraph.checkpoint.memory import InMemorySaver
from sqlalchemy import select

from icheck.builtin_agent_tools import ensure_builtin_agent_tools
from icheck.database import SessionLocal
from icheck.langgraph_runtime import GraphDecision, GraphToolRequest
from icheck.models import (
    AuditEvent,
    AgentToolRegistration,
    Investigation,
    InvestigationCheckpoint,
    InvestigationEvidence,
    InvestigationToolCall,
)
from icheck.services.agent_graph import (
    resume_database_investigation,
    run_database_investigation,
)
from icheck.services.model_reasoner import OpenAICompatibleReasoner


class FakeChatResponse:
    def __init__(self, document):
        self.body = json.dumps(document).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, limit):
        return self.body[:limit]


class FakeChatOpener:
    def __init__(self, device_id):
        self.device_id = device_id
        self.requests = []

    def open(self, request, timeout):
        assert request.full_url == (
            "https://models.example.test/v1/chat/completions"
        )
        assert request.get_method() == "POST"
        assert request.get_header("Content-type") == "application/json"
        assert 0 < timeout <= 20
        payload = json.loads(request.data)
        prompt = json.loads(payload["messages"][1]["content"])
        assert payload["model"] == "graph-integration-reasoner"
        assert payload["stream"] is False
        assert payload["response_format"]["type"] == "json_schema"
        assert payload["response_format"]["json_schema"]["strict"] is False
        assert {item["name"] for item in prompt["available_tools"]} == {
            "alerts.list_open",
            "inventory.get_device",
            "inventory.get_endpoint_history",
            "metrics.query_instant",
        }
        self.requests.append(prompt)

        if len(self.requests) == 1:
            decision = {
                "action": "continue",
                "plan": ["Read the device", "Evaluate monitoring readiness"],
                "hypotheses": [
                    {
                        "statement": "The device is awaiting verification.",
                        "confidence": 0.4,
                    }
                ],
                "tool_requests": [
                    {
                        "tool_name": "inventory.get_device",
                        "arguments": {"device_id": self.device_id},
                        "purpose": "Read bounded device monitoring state",
                    }
                ],
            }
            tokens = 60
        else:
            investigation = prompt["investigation"]
            observed = investigation["tool_results"][0]["result"]
            assert observed["id"] == self.device_id
            assert "configuration" not in observed["connections"][0]
            assert "credential_profile_ref" not in observed["connections"][0]
            decision = {
                "action": "complete",
                "plan": investigation["plan"],
                "hypotheses": [
                    {
                        "statement": "The device is awaiting verification.",
                        "confidence": 0.95,
                        "supporting_evidence_ids": investigation["evidence_ids"],
                    }
                ],
                "confidence": 0.95,
                "conclusion": (
                    "The device is onboarded and its ICMP connection still "
                    "requires preflight verification."
                ),
                "uncertainty": [
                    "No completed preflight evidence exists yet."
                ],
            }
            tokens = 40
        return FakeChatResponse(
            {
                "choices": [
                    {"message": {"content": json.dumps(decision)}}
                ],
                "usage": {"total_tokens": tokens},
            }
        )


class InvalidChatOpener:
    def open(self, _request, timeout):
        assert timeout > 0
        return FakeChatResponse(
            {
                "choices": [
                    {
                        "message": {
                            "content": "model-private-invalid-response"
                        }
                    }
                ]
            }
        )


def _configure_route(client):
    provider = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "graph-integration-provider",
            "provider_type": "openai_compatible",
            "base_url": "https://models.example.test/v1",
            "auth_type": "none",
            "created_by": "platform.admin",
        },
    )
    assert provider.status_code == 201, provider.text
    model = client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": provider.json()["id"],
            "display_name": "Graph integration reasoner",
            "model_name": "graph-integration-reasoner",
            "capabilities": ["chat", "tools", "json_schema"],
            "created_by": "platform.admin",
        },
    )
    assert model.status_code == 201, model.text
    route = client.post(
        "/api/v1/ai/routes",
        json={
            "purpose": "investigation",
            "primary_model_id": model.json()["id"],
            "max_iterations": 4,
            "max_tool_calls": 3,
            "timeout_seconds": 300,
            "token_budget": 1000,
            "created_by": "platform.admin",
        },
    )
    assert route.status_code == 201, route.text


def _start_investigation(client, device_id):
    created = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": "Inspect the lab core",
            "objective": "Establish the target's monitoring state.",
            "scope": {"device_ids": [device_id]},
            "route_purpose": "investigation",
            "created_by": "l1.operator",
        },
    )
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]
    started = client.post(
        f"/api/v1/agent/investigations/{investigation_id}/start",
        json={"actor": "l1.operator"},
    )
    assert started.status_code == 200, started.text
    return investigation_id


def test_database_graph_executes_builtin_tool_and_persists_evidence(client):
    _configure_route(client)
    device_response = client.post(
        "/api/v1/assets/devices",
        json={
            "name": "lab-core-graph-01",
            "kind": "switch",
            "management_ip": "192.0.2.41",
            "site": "LAB",
            "labels": {"role": "core"},
            "connections": [
                {
                    "protocol": "icmp",
                    "configuration": {"probe_timeout_seconds": 2},
                }
            ],
            "created_by": "l1.operator",
        },
    )
    assert device_response.status_code == 201, device_response.text
    device_id = device_response.json()["id"]
    investigation_id = _start_investigation(client, device_id)

    with SessionLocal() as db:
        first_seed = ensure_builtin_agent_tools(db)
        second_seed = ensure_builtin_agent_tools(db)
        assert [tool.id for tool in first_seed] == [
            tool.id for tool in second_seed
        ]
        assert len(db.scalars(select(AgentToolRegistration)).all()) == 4

        investigation = db.get(Investigation, investigation_id)
        assert investigation is not None

        saver = InMemorySaver()
        opener = FakeChatOpener(device_id)
        reasoner = OpenAICompatibleReasoner(
            db,
            investigation,
            opener=opener,
        )
        interrupted = run_database_investigation(
            db,
            investigation,
            reasoner=reasoner,
            checkpointer=saver,
            interrupt_after=["tools"],
        )
        assert interrupted["status"] == "running"
        assert interrupted["current_node"] == "tools"
        assert interrupted["tool_calls_used"] == 1
        assert len(opener.requests) == 1

        # Rebuild the graph as a replacement worker/process would, then
        # continue from the same checkpoint thread without replaying the tool.
        result = resume_database_investigation(
            db,
            investigation,
            reasoner=reasoner,
            checkpointer=saver,
        )

        assert result["status"] == "completed"
        assert result["iteration"] == 2
        assert result["tool_calls_used"] == 1
        assert result["tokens_used"] == 100
        assert len(opener.requests) == 2

        db.refresh(investigation)
        assert investigation.status == "completed"
        assert investigation.iterations_used == 2
        assert investigation.tool_calls_used == 1
        assert investigation.tokens_used == 100
        assert investigation.confidence == 0.95

        checkpoints = list(
            db.scalars(
                select(InvestigationCheckpoint)
                .where(
                    InvestigationCheckpoint.investigation_id
                    == investigation_id
                )
                .order_by(InvestigationCheckpoint.sequence)
            ).all()
        )
        assert [item.node for item in checkpoints] == [
            "start",
            "reason",
            "tools",
            "reason",
        ]
        assert checkpoints[-1].state["status"] == "completed"

        evidence = list(
            db.scalars(
                select(InvestigationEvidence).where(
                    InvestigationEvidence.investigation_id
                    == investigation_id
                )
            ).all()
        )
        assert len(evidence) == 1
        assert evidence[0].evidence_type == "device"
        assert evidence[0].evidence_id == device_id

        calls = list(
            db.scalars(
                select(InvestigationToolCall).where(
                    InvestigationToolCall.investigation_id
                    == investigation_id
                )
            ).all()
        )
        assert len(calls) == 1
        assert calls[0].status == "succeeded"
        assert calls[0].result["id"] == device_id
        assert calls[0].result_hash

        snapshot = saver.get_tuple(
            {"configurable": {"thread_id": investigation_id}}
        )
        assert snapshot is not None
        assert snapshot.checkpoint["channel_values"]["status"] == "completed"

        audits = client.get("/api/v1/audit-events?limit=1000").json()
        model_audits = [
            item
            for item in audits
            if item["event_type"] == "investigation.model.completed"
        ]
        assert [
            item["details"]["token_usage"]
            for item in sorted(
                model_audits,
                key=lambda item: item["details"]["iteration"],
            )
        ] == [
            60,
            40,
        ]
        assert "chat/completions" not in json.dumps(model_audits)


def test_invalid_model_response_is_audited_and_durably_escalated(client):
    _configure_route(client)
    investigation_id = _start_investigation(client, "device-not-needed")

    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        investigation = db.get(Investigation, investigation_id)
        assert investigation is not None
        result = run_database_investigation(
            db,
            investigation,
            reasoner=OpenAICompatibleReasoner(
                db,
                investigation,
                opener=InvalidChatOpener(),
            ),
            checkpointer=InMemorySaver(),
        )

        assert result["status"] == "escalated"
        assert result["escalation_reason"] == (
            "Reasoner failed: ModelReasonerUnavailable"
        )
        db.refresh(investigation)
        assert investigation.status == "escalated"
        assert investigation.escalation_reason == result["escalation_reason"]

        model_failure = db.scalar(
            select(AuditEvent).where(
                AuditEvent.event_type == "investigation.model.failed"
            )
        )
        assert model_failure is not None
        assert model_failure.details["error"] == (
            "AI provider returned invalid token usage"
        )
        assert "model-private-invalid-response" not in json.dumps(
            model_failure.details
        )


def test_graph_rejects_hallucinated_change_tool_without_waiting_state(client):
    _configure_route(client)
    change_tool = client.post(
        "/api/v1/agent/tools",
        json={
            "name": "network.shutdown_interface",
            "description": "State-changing tool that the graph must not call.",
            "transport": "internal",
            "handler": "network.shutdown_interface",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
            },
            "output_schema": {"type": "object"},
            "risk_level": "change",
            "read_only": False,
            "created_by": "platform.admin",
        },
    )
    assert change_tool.status_code == 201, change_tool.text
    investigation_id = _start_investigation(client, "device-not-needed")

    def hallucinated_change(_state):
        return GraphDecision(
            action="continue",
            tool_requests=[
                GraphToolRequest(
                    tool_name="network.shutdown_interface",
                    arguments={},
                    purpose="Unsafe model-selected action",
                )
            ],
        )

    with SessionLocal() as db:
        investigation = db.get(Investigation, investigation_id)
        assert investigation is not None
        result = run_database_investigation(
            db,
            investigation,
            reasoner=hallucinated_change,
            checkpointer=InMemorySaver(),
        )
        assert result["status"] == "escalated"
        assert result["escalation_reason"] == (
            "Tool execution failed for 'network.shutdown_interface': ValueError"
        )
        db.refresh(investigation)
        assert investigation.status == "escalated"
        assert investigation.tool_calls_used == 0
        assert db.scalar(
            select(InvestigationToolCall).where(
                InvestigationToolCall.investigation_id == investigation_id
            )
        ) is None
