import json
from datetime import timedelta

from langgraph.checkpoint.memory import InMemorySaver

from icheck.agent_schemas import AgentExecutionAssignment
from icheck.agent_worker import execute_assignment
from icheck.database import SessionLocal
from icheck.langgraph_runtime import GraphDecision
from icheck.models import AgentExecution, AgentWorker, Investigation, utcnow


REGISTRATION_HEADERS = {
    "X-iCheck-Registration-Token": "test-agent-registration-token"
}


def configure_execution_route(client):
    provider = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "execution-test-provider",
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
            "display_name": "Execution test reasoner",
            "model_name": "execution-test-reasoner",
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
            "max_tool_calls": 4,
            "timeout_seconds": 300,
            "token_budget": 2000,
            "created_by": "platform.admin",
        },
    )
    assert route.status_code == 201, route.text


def start_execution(client, *, title="Execution lifecycle"):
    created = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": title,
            "objective": "Inspect the target without changing it.",
            "scope": {"device_ids": ["device-1"]},
            "route_purpose": "investigation",
            "created_by": "l1.operator",
        },
    )
    assert created.status_code == 201, created.text
    investigation = created.json()
    started = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/start",
        json={"actor": "l1.operator"},
    )
    assert started.status_code == 200, started.text
    execution = client.get(
        f"/api/v1/agent/investigations/{investigation['id']}/execution"
    )
    assert execution.status_code == 200, execution.text
    assert execution.json()["status"] == "queued"
    assert execution.json()["attempt_count"] == 0
    return investigation, execution.json()


def register_worker(client, name, *, capabilities=None):
    response = client.post(
        "/api/v1/agent/workers/register",
        headers=REGISTRATION_HEADERS,
        json={
            "name": name,
            "capabilities": capabilities or ["openai_compatible"],
            "labels": {"pool": "default"},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_agent_execution_claim_renew_cancel_and_ordered_events(client):
    configure_execution_route(client)
    investigation, execution = start_execution(client)

    unauthorized_registration = client.post(
        "/api/v1/agent/workers/register",
        json={"name": "agent-worker-unauthorized"},
    )
    assert unauthorized_registration.status_code == 401

    registration = register_worker(client, "agent-worker-01")
    worker = registration["worker"]
    access_token = registration["access_token"]
    assert access_token not in json.dumps(worker)

    unauthorized_claim = client.post(
        f"/api/v1/agent/workers/{worker['id']}/executions/claim",
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert unauthorized_claim.status_code == 401
    claim = client.post(
        f"/api/v1/agent/workers/{worker['id']}/executions/claim",
        headers=bearer(access_token),
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claim.status_code == 200, claim.text
    assignment = claim.json()[0]
    assert assignment["execution_id"] == execution["id"]
    assert assignment["attempt"] == 1
    assert assignment["resume_required"] is False
    assert len(assignment["lease_token"]) >= 20

    second_claim = client.post(
        f"/api/v1/agent/workers/{worker['id']}/executions/claim",
        headers=bearer(access_token),
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert second_claim.status_code == 200
    assert second_claim.json() == []

    invalid_renewal = client.post(
        f"/api/v1/agent/executions/{execution['id']}/lease",
        headers=bearer(access_token),
        json={
            "lease_token": "invalid-lease-token-value",
            "lease_seconds": 60,
        },
    )
    assert invalid_renewal.status_code == 409
    renewed = client.post(
        f"/api/v1/agent/executions/{execution['id']}/lease",
        headers=bearer(access_token),
        json={
            "lease_token": assignment["lease_token"],
            "lease_seconds": 120,
        },
    )
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["status"] == "running"
    assert "lease_token" not in renewed.json()
    assert "lease_token_hash" not in renewed.json()

    cancellation = client.post(
        f"/api/v1/agent/executions/{execution['id']}/cancel",
        json={
            "actor": "l1.operator",
            "reason": "Operator no longer needs this investigation.",
        },
    )
    assert cancellation.status_code == 200, cancellation.text
    assert cancellation.json()["status"] == "running"
    assert cancellation.json()["cancellation_requested_at"] is not None

    completed = client.post(
        f"/api/v1/agent/executions/{execution['id']}/complete",
        headers=bearer(access_token),
        json={
            "lease_token": assignment["lease_token"],
            "status": "cancelled",
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "cancelled"
    assert completed.json()["worker_id"] is None
    assert client.get(
        f"/api/v1/agent/investigations/{investigation['id']}"
    ).json()["status"] == "cancelled"

    events = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events"
    ).json()
    assert [item["sequence"] for item in events] == [1, 2, 3, 4]
    assert [item["event_type"] for item in events] == [
        "execution.queued",
        "execution.claimed",
        "execution.cancellation_requested",
        "execution.completed",
    ]
    tail = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events",
        params={"after_sequence": 2},
    ).json()
    assert [item["sequence"] for item in tail] == [3, 4]

    audits = client.get("/api/v1/audit-events?limit=1000").json()
    audit_text = json.dumps(audits)
    assert access_token not in audit_text
    assert assignment["lease_token"] not in audit_text
    assert {
        "agent.execution.queued",
        "agent.worker.registered",
        "agent.execution.claimed",
        "agent.execution.cancel_requested",
        "agent.execution.completed",
    } <= {item["event_type"] for item in audits}


def test_expired_execution_is_reassigned_and_signals_checkpoint_resume(client):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Resume lifecycle")
    first = register_worker(client, "agent-worker-first")
    first_claim = client.post(
        f"/api/v1/agent/workers/{first['worker']['id']}/executions/claim",
        headers=bearer(first["access_token"]),
        json={"max_assignments": 1, "lease_seconds": 15},
    )
    assert first_claim.status_code == 200, first_claim.text
    first_assignment = first_claim.json()[0]

    checkpoint = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/checkpoints",
        json={
            "node": "reason",
            "state": {
                "investigation_id": investigation["id"],
                "objective": investigation["objective"],
                "scope": investigation["scope"],
                "status": "running",
                "iteration": 1,
                "plan": ["Resume after worker loss"],
            },
            "token_usage": 10,
            "actor": "agent.worker-first",
        },
    )
    assert checkpoint.status_code == 201, checkpoint.text

    with SessionLocal() as db:
        stored = db.get(AgentExecution, execution["id"])
        assert stored is not None
        stored.lease_expires_at = utcnow() - timedelta(seconds=1)
        db.commit()

    second = register_worker(client, "agent-worker-second")
    second_claim = client.post(
        f"/api/v1/agent/workers/{second['worker']['id']}/executions/claim",
        headers=bearer(second["access_token"]),
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert second_claim.status_code == 200, second_claim.text
    reassigned = second_claim.json()[0]
    assert reassigned["execution_id"] == execution["id"]
    assert reassigned["attempt"] == 2
    assert reassigned["resume_required"] is True
    assert reassigned["lease_token"] != first_assignment["lease_token"]

    stale_worker = client.post(
        f"/api/v1/agent/executions/{execution['id']}/lease",
        headers=bearer(first["access_token"]),
        json={
            "lease_token": first_assignment["lease_token"],
            "lease_seconds": 60,
        },
    )
    assert stale_worker.status_code == 401

    failed = client.post(
        f"/api/v1/agent/executions/{execution['id']}/complete",
        headers=bearer(second["access_token"]),
        json={
            "lease_token": reassigned["lease_token"],
            "status": "failed",
            "error": "Resume checkpoint was unavailable in this test.",
        },
    )
    assert failed.status_code == 200, failed.text
    assert failed.json()["status"] == "failed"
    events = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events"
    ).json()
    assert [item["event_type"] for item in events] == [
        "execution.queued",
        "execution.claimed",
        "execution.reassigned",
        "execution.completed",
    ]


def test_queued_execution_can_cancel_immediately_and_capabilities_filter(client):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Queued cancel")
    incompatible = register_worker(
        client,
        "agent-worker-incompatible",
        capabilities=["another_provider"],
    )
    claim = client.post(
        f"/api/v1/agent/workers/{incompatible['worker']['id']}/executions/claim",
        headers=bearer(incompatible["access_token"]),
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claim.status_code == 200
    assert claim.json() == []

    cancelled = client.post(
        f"/api/v1/agent/executions/{execution['id']}/cancel",
        json={
            "actor": "l1.operator",
            "reason": "Cancelled before a compatible worker claimed it.",
        },
    )
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["finished_at"] is not None
    assert client.get(
        f"/api/v1/agent/investigations/{investigation['id']}"
    ).json()["status"] == "cancelled"


def test_standalone_worker_executes_claim_and_emits_graph_progress(
    client,
    monkeypatch,
):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Worker execution")
    registration = register_worker(client, "agent-worker-executor")
    worker_id = registration["worker"]["id"]
    claim = client.post(
        f"/api/v1/agent/workers/{worker_id}/executions/claim",
        headers=bearer(registration["access_token"]),
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claim.status_code == 200, claim.text
    assignment = AgentExecutionAssignment.model_validate(claim.json()[0])

    def reasoner(_state):
        return GraphDecision(
            action="complete",
            plan=["Use existing evidence"],
            confidence=0.9,
            conclusion="No further diagnostic tool is required.",
            uncertainty=["No live target was queried in this acceptance test."],
            token_usage=25,
        )

    monkeypatch.setattr(
        "icheck.agent_worker.OpenAICompatibleReasoner",
        lambda *_args, **_kwargs: reasoner,
    )
    with SessionLocal() as db:
        worker = db.get(AgentWorker, worker_id)
        assert worker is not None
        completed = execute_assignment(
            db,
            worker,
            assignment,
            checkpointer=InMemorySaver(),
            lease_seconds=60,
        )
        assert completed.status.value == "succeeded"
        stored_investigation = db.get(Investigation, investigation["id"])
        assert stored_investigation is not None
        assert stored_investigation.status == "completed"
        assert stored_investigation.tokens_used == 25

    stored = client.get(
        f"/api/v1/agent/executions/{execution['id']}"
    ).json()
    assert stored["status"] == "succeeded"
    assert stored["worker_id"] is None
    events = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events"
    ).json()
    assert [item["event_type"] for item in events] == [
        "execution.queued",
        "execution.claimed",
        "graph.reason",
        "graph.finalize",
        "execution.completed",
    ]
    stream = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events/stream",
        headers={"Last-Event-ID": "2"},
    )
    assert stream.status_code == 200, stream.text
    assert stream.headers["content-type"].startswith("text/event-stream")
    assert "id: 3" in stream.text
    assert "event: graph.reason" in stream.text
    assert "event: execution.completed" in stream.text
    assert "event: stream.end" in stream.text
    assert '"status":"succeeded"' in stream.text


def test_scheduler_reconciles_terminal_graph_commit_after_worker_crash(client):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Crash reconciliation")
    first = register_worker(client, "agent-worker-before-crash")
    claim = client.post(
        f"/api/v1/agent/workers/{first['worker']['id']}/executions/claim",
        headers=bearer(first["access_token"]),
        json={"max_assignments": 1, "lease_seconds": 15},
    )
    assert claim.status_code == 200, claim.text

    with SessionLocal() as db:
        stored_execution = db.get(AgentExecution, execution["id"])
        stored_investigation = db.get(Investigation, investigation["id"])
        assert stored_execution is not None
        assert stored_investigation is not None
        stored_investigation.status = "completed"
        stored_investigation.conclusion = "Graph committed before worker exit."
        stored_investigation.finished_at = utcnow()
        stored_execution.lease_expires_at = utcnow() - timedelta(seconds=1)
        db.commit()

    replacement = register_worker(client, "agent-worker-after-crash")
    replacement_claim = client.post(
        f"/api/v1/agent/workers/{replacement['worker']['id']}/executions/claim",
        headers=bearer(replacement["access_token"]),
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert replacement_claim.status_code == 200, replacement_claim.text
    assert replacement_claim.json() == []
    reconciled = client.get(
        f"/api/v1/agent/executions/{execution['id']}"
    ).json()
    assert reconciled["status"] == "succeeded"
    assert reconciled["worker_id"] is None
    events = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events"
    ).json()
    assert events[-1]["event_type"] == "execution.reconciled"
    assert events[-1]["payload"]["reason"] == "terminal_investigation"
