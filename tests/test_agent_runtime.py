import json


def configure_investigation_route(client, *, max_tool_calls=2):
    provider = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "agent-test-provider",
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
            "display_name": "Agent test reasoner",
            "model_name": "agent-test-reasoner",
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
            "max_iterations": 3,
            "max_tool_calls": max_tool_calls,
            "timeout_seconds": 300,
            "token_budget": 1000,
            "created_by": "platform.admin",
        },
    )
    assert route.status_code == 201, route.text
    return route.json()


def register_read_tool(client):
    response = client.post(
        "/api/v1/agent/tools",
        json={
            "name": "inventory.get_device",
            "description": "Return one device by durable identifier.",
            "transport": "internal",
            "handler": "inventory.get_device",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["device_id"],
                "properties": {
                    "device_id": {"type": "string", "minLength": 1},
                },
            },
            "output_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "name"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                },
            },
            "risk_level": "observe",
            "read_only": True,
            "required_permissions": ["assets.read", "assets.read"],
            "timeout_seconds": 10,
            "max_result_bytes": 4096,
            "created_by": "platform.admin",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["required_permissions"] == ["assets.read"]
    return response.json()


def create_and_start_investigation(client, *, title="Core switch errors"):
    created = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": title,
            "objective": "Determine why the core switch error rate is rising.",
            "scope": {"site": "LAB", "device_ids": ["device-1"]},
            "route_purpose": "investigation",
            "created_by": "l1.operator",
        },
    )
    assert created.status_code == 201, created.text
    investigation = created.json()
    assert investigation["status"] == "pending"
    assert investigation["max_iterations"] == 3
    started = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/start",
        json={"actor": "l1.operator"},
    )
    assert started.status_code == 200, started.text
    assert started.json()["investigation"]["status"] == "running"
    assert started.json()["checkpoint"]["sequence"] == 1
    assert len(started.json()["checkpoint"]["state_hash"]) == 64
    return investigation


def test_investigation_checkpoint_evidence_and_typed_tool_lifecycle(client):
    route = configure_investigation_route(client)
    tool = register_read_tool(client)
    investigation = create_and_start_investigation(client)
    assert investigation["max_tool_calls"] == route["max_tool_calls"]

    evidence = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/evidence",
        json={
            "evidence_type": "alert",
            "evidence_id": "alert-17",
            "summary": "Interface error threshold exceeded.",
        },
    )
    assert evidence.status_code == 201, evidence.text
    duplicate_evidence = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/evidence",
        json={
            "evidence_type": "alert",
            "evidence_id": "alert-17",
            "summary": "Repeated reference is idempotent.",
        },
    )
    assert duplicate_evidence.json()["id"] == evidence.json()["id"]

    call = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/tool-calls",
        json={
            "tool_id": tool["id"],
            "iteration": 1,
            "arguments": {"device_id": "device-1"},
        },
    )
    assert call.status_code == 201, call.text
    assert call.json()["status"] == "running"
    assert len(call.json()["call_hash"]) == 64
    duplicate = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/tool-calls",
        json={
            "tool_id": tool["id"],
            "iteration": 2,
            "arguments": {"device_id": "device-1"},
        },
    )
    assert duplicate.status_code == 409
    assert "Duplicate tool call" in duplicate.text

    invalid_result = client.post(
        f"/api/v1/agent/tool-calls/{call.json()['id']}/complete",
        json={"status": "succeeded", "result": {"id": "device-1"}},
    )
    assert invalid_result.status_code == 409
    completed = client.post(
        f"/api/v1/agent/tool-calls/{call.json()['id']}/complete",
        json={
            "status": "succeeded",
            "result": {"id": "device-1", "name": "lab-core-01"},
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "succeeded"
    assert len(completed.json()["result_hash"]) == 64
    listed = client.get(f"/api/v1/agent/investigations/{investigation['id']}/tool-calls")
    assert listed.status_code == 200
    assert listed.json()[0]["tool_name"] == tool["name"]
    assert listed.json()[0]["result"] == completed.json()["result"]

    checkpoint = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/checkpoints",
        json={
            "node": "evaluate",
            "state": {
                "investigation_id": investigation["id"],
                "objective": investigation["objective"],
                "scope": investigation["scope"],
                "status": "completed",
                "iteration": 1,
                "plan": ["Read device", "Evaluate evidence"],
                "hypotheses": [
                    {
                        "statement": "The interface is accumulating errors.",
                        "confidence": 0.8,
                        "supporting_evidence_ids": [evidence.json()["id"]],
                    }
                ],
                "evidence_ids": [evidence.json()["id"]],
                "tool_call_ids": [call.json()["id"]],
                "confidence": 0.8,
                "conclusion": "Inspect the physical uplink.",
                "uncertainty": ["No optical telemetry yet."],
            },
            "token_usage": 120,
            "actor": "agent.worker-01",
        },
    )
    assert checkpoint.status_code == 201, checkpoint.text
    assert checkpoint.json()["sequence"] == 2
    final = client.get(
        f"/api/v1/agent/investigations/{investigation['id']}"
    ).json()
    assert final["status"] == "completed"
    assert final["tokens_used"] == 120
    assert final["confidence"] == 0.8
    assert len(client.get(
        f"/api/v1/agent/investigations/{investigation['id']}/checkpoints"
    ).json()) == 2

    audits = client.get("/api/v1/audit-events?limit=1000").json()
    audit_text = json.dumps(audits)
    assert "lab-core-01" not in audit_text
    assert {
        "investigation.created",
        "investigation.started",
        "investigation.evidence.linked",
        "investigation.tool.started",
        "investigation.tool.completed",
        "investigation.checkpoint.saved",
    } <= {item["event_type"] for item in audits}


def test_agent_policy_blocks_secrets_changes_and_exhausted_tool_budget(client):
    configure_investigation_route(client)
    tool = register_read_tool(client)

    unsafe_tool = client.post(
        "/api/v1/agent/tools",
        json={
            "name": "unsafe.token_tool",
            "description": "Unsafe schema.",
            "transport": "internal",
            "handler": "unsafe.token_tool",
            "input_schema": {
                "type": "object",
                "properties": {"token": {"type": "string"}},
            },
            "output_schema": {"type": "object"},
            "risk_level": "observe",
            "read_only": True,
            "created_by": "platform.admin",
        },
    )
    assert unsafe_tool.status_code == 422
    assert "inline secret" in unsafe_tool.text

    change_tool = client.post(
        "/api/v1/agent/tools",
        json={
            "name": "network.shutdown_interface",
            "description": "State-changing test tool.",
            "transport": "internal",
            "handler": "network.shutdown_interface",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "risk_level": "change",
            "read_only": False,
            "created_by": "platform.admin",
        },
    )
    assert change_tool.status_code == 201, change_tool.text
    protected = create_and_start_investigation(client, title="Protected change")
    blocked = client.post(
        f"/api/v1/agent/investigations/{protected['id']}/tool-calls",
        json={
            "tool_id": change_tool.json()["id"],
            "iteration": 1,
            "arguments": {},
        },
    )
    assert blocked.status_code == 409
    assert "governed action engine" in blocked.text
    assert client.get(
        f"/api/v1/agent/investigations/{protected['id']}"
    ).json()["status"] == "waiting_approval"

    budgeted = create_and_start_investigation(client, title="Budget test")
    for iteration, device_id in [(1, "device-a"), (2, "device-b")]:
        response = client.post(
            f"/api/v1/agent/investigations/{budgeted['id']}/tool-calls",
            json={
                "tool_id": tool["id"],
                "iteration": iteration,
                "arguments": {"device_id": device_id},
            },
        )
        assert response.status_code == 201, response.text
        finished = client.post(
            f"/api/v1/agent/tool-calls/{response.json()['id']}/complete",
            json={
                "status": "succeeded",
                "result": {"id": device_id, "name": device_id},
            },
        )
        assert finished.status_code == 200, finished.text
    exhausted = client.post(
        f"/api/v1/agent/investigations/{budgeted['id']}/tool-calls",
        json={
            "tool_id": tool["id"],
            "iteration": 3,
            "arguments": {"device_id": "device-c"},
        },
    )
    assert exhausted.status_code == 409
    assert "budget exhausted" in exhausted.text
    final = client.get(
        f"/api/v1/agent/investigations/{budgeted['id']}"
    ).json()
    assert final["status"] == "escalated"
    assert final["escalation_reason"] == "Tool-call budget exhausted"
