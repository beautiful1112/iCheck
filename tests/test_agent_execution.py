import json
from datetime import timedelta
import pytest

from icheck.agent_schemas import AgentExecutionAssignment
from icheck.agent_worker import (
    RemoteLeasedCheckpointHook,
    execute_remote_assignment,
)
from icheck.collector_worker import ControlPlaneHTTPError
from icheck.database import SessionLocal
from icheck.langgraph_runtime import GraphDecision, initial_graph_state
from icheck.models import AgentExecution, AgentWorker, Investigation, utcnow
from icheck.models import (
    InvestigationCheckpoint,
    InvestigationEvidence,
    InvestigationToolCall,
)
from icheck.builtin_agent_tools import ensure_builtin_agent_tools


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


def start_execution(
    client,
    *,
    title="Execution lifecycle",
    device_id="device-1",
):
    created = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": title,
            "objective": "Inspect the target without changing it.",
            "scope": {"device_ids": [device_id]},
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


class RecordingAgentControlClient:
    def __init__(self):
        self.requests = []

    def request(self, method, path, payload):
        self.requests.append((method, path, payload))
        if path.endswith("/lease"):
            return {"cancellation_requested_at": None}
        if path.endswith("/progress"):
            return {
                "event_type": f"graph.{payload['node']}",
                "sequence": 3,
            }
        raise AssertionError(f"Unexpected Agent control request: {path}")


class APIAgentControlClient:
    def __init__(self, client, access_token):
        self.client = client
        self.access_token = access_token

    def request(self, method, path, payload, **_kwargs):
        response = self.client.request(
            method,
            path,
            headers=bearer(self.access_token),
            json=payload,
        )
        assert response.status_code < 400, response.text
        if response.status_code == 204 or not response.content:
            return None
        return response.json()


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


def test_cancel_rejects_after_product_terminal_commit_before_worker_ack(client):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Committed before ack")
    registration = register_worker(client, "agent-worker-committed-before-ack")
    worker_id = registration["worker"]["id"]
    headers = bearer(registration["access_token"])
    assignment = client.post(
        f"/api/v1/agent/workers/{worker_id}/executions/claim",
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    ).json()[0]
    with SessionLocal() as db:
        stored = db.get(Investigation, investigation["id"])
        stored.status = "completed"
        stored.finished_at = utcnow()
        db.commit()

    cancellation = client.post(
        f"/api/v1/agent/executions/{execution['id']}/cancel",
        json={"actor": "l1.operator", "reason": "Too late to stop committed result"},
    )
    assert cancellation.status_code == 409
    assert "already terminal" in cancellation.text
    acknowledged = client.post(
        f"/api/v1/agent/executions/{execution['id']}/complete",
        headers=headers,
        json={"lease_token": assignment["lease_token"], "status": "succeeded"},
    )
    assert acknowledged.status_code == 200, acknowledged.text
    assert acknowledged.json()["status"] == "succeeded"
    assert acknowledged.json()["cancellation_requested_at"] is None


def test_accepted_cancellation_wins_over_stale_worker_success_and_progress(client):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Cancellation wins")
    registration = register_worker(client, "agent-worker-cancellation-wins")
    worker_id = registration["worker"]["id"]
    headers = bearer(registration["access_token"])
    assignment = client.post(
        f"/api/v1/agent/workers/{worker_id}/executions/claim",
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    ).json()[0]
    cancellation = client.post(
        f"/api/v1/agent/executions/{execution['id']}/cancel",
        json={"actor": "l1.operator", "reason": "Stop the current reasoning"},
    )
    assert cancellation.status_code == 200, cancellation.text
    assert cancellation.json()["status"] == "running"
    progress = client.post(
        f"/api/v1/agent/executions/{execution['id']}/progress",
        headers=headers,
        json={
            "lease_token": assignment["lease_token"],
            "node": "reason",
            "status": "running",
            "iteration": 0,
            "tokens_used": 0,
            "tool_calls_used": 0,
            "evidence_count": 0,
        },
    )
    assert progress.status_code == 409
    assert "cancellation was requested" in progress.text
    completed = client.post(
        f"/api/v1/agent/executions/{execution['id']}/complete",
        headers=headers,
        json={"lease_token": assignment["lease_token"], "status": "succeeded"},
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "cancelled"
    replay = client.post(
        f"/api/v1/agent/executions/{execution['id']}/complete",
        headers=headers,
        json={"lease_token": assignment["lease_token"], "status": "succeeded"},
    )
    assert replay.status_code == 200, replay.text
    assert replay.json() == completed.json()
    assert client.get(
        f"/api/v1/agent/investigations/{investigation['id']}"
    ).json()["status"] == "cancelled"
    events = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events"
    ).json()
    assert events[-1]["payload"]["requested_status"] == "succeeded"
    assert events[-1]["payload"]["status"] == "cancelled"


def test_completion_response_loss_replay_is_bound_and_does_not_duplicate_events(client):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Completion replay")
    registration = register_worker(client, "agent-worker-completion-replay")
    worker_id = registration["worker"]["id"]
    headers = bearer(registration["access_token"])
    claim = client.post(
        f"/api/v1/agent/workers/{worker_id}/executions/claim",
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claim.status_code == 200, claim.text
    lease_token = claim.json()[0]["lease_token"]
    with SessionLocal() as db:
        stored = db.get(Investigation, investigation["id"])
        stored.status = "completed"
        stored.finished_at = utcnow()
        db.commit()

    path = f"/api/v1/agent/executions/{execution['id']}/complete"
    document = {"lease_token": lease_token, "status": "succeeded"}
    first = client.post(path, headers=headers, json=document)
    assert first.status_code == 200, first.text
    assert "completion_token_hash" not in first.json()
    assert "completion_request_hash" not in first.json()
    replay = client.post(path, headers=headers, json=document)
    assert replay.status_code == 200, replay.text
    assert replay.json() == first.json()
    assert client.post(
        path, headers=headers,
        json={**document, "lease_token": "different-lease-token-long-enough"},
    ).status_code == 409
    assert client.post(
        path, headers=headers,
        json={**document, "status": "failed", "error": "changed-response"},
    ).status_code == 409
    another = register_worker(client, "agent-worker-completion-forger")
    assert client.post(
        path, headers=bearer(another["access_token"]), json=document,
    ).status_code == 401
    events = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events"
    ).json()
    assert [item["event_type"] for item in events].count("execution.completed") == 1
    audits = client.get("/api/v1/audit-events?limit=1000").json()
    assert sum(
        item["event_type"] == "agent.execution.completed"
        and item["entity_id"] == execution["id"]
        for item in audits
    ) == 1
    with SessionLocal() as db:
        stored_execution = db.get(AgentExecution, execution["id"])
        assert stored_execution.lease_token_hash is None
        assert stored_execution.completion_worker_id == worker_id
        assert stored_execution.completion_token_hash is not None
        assert stored_execution.completion_request_hash is not None


def test_worker_progress_api_is_lease_bound_and_matches_persisted_state(client):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Remote progress")
    registration = register_worker(client, "agent-worker-remote-progress")
    worker_id = registration["worker"]["id"]
    headers = bearer(registration["access_token"])
    claim = client.post(
        f"/api/v1/agent/workers/{worker_id}/executions/claim",
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assignment = claim.json()[0]
    progress = {
        "lease_token": assignment["lease_token"],
        "node": "reason",
        "status": "running",
        "iteration": 0,
        "tokens_used": 0,
        "tool_calls_used": 0,
        "evidence_count": 0,
    }

    unauthorized = client.post(
        f"/api/v1/agent/executions/{execution['id']}/progress",
        json=progress,
    )
    assert unauthorized.status_code == 401
    bad_node = client.post(
        f"/api/v1/agent/executions/{execution['id']}/progress",
        headers=headers,
        json={**progress, "node": "untrusted-node"},
    )
    assert bad_node.status_code == 422
    drifted = client.post(
        f"/api/v1/agent/executions/{execution['id']}/progress",
        headers=headers,
        json={**progress, "tokens_used": 1},
    )
    assert drifted.status_code == 409
    assert "persisted investigation state" in drifted.text

    accepted = client.post(
        f"/api/v1/agent/executions/{execution['id']}/progress",
        headers=headers,
        json=progress,
    )
    assert accepted.status_code == 200, accepted.text
    event = accepted.json()
    assert event["event_type"] == "graph.reason"
    assert event["payload"] == {
        "status": "running",
        "iteration": 0,
        "tokens_used": 0,
        "tool_calls_used": 0,
        "evidence_count": 0,
    }
    assert assignment["lease_token"] not in json.dumps(event)

    completed = client.post(
        f"/api/v1/agent/executions/{execution['id']}/complete",
        headers=headers,
        json={
            "lease_token": assignment["lease_token"],
            "status": "failed",
            "error": "Test completed after progress contract validation.",
        },
    )
    assert completed.status_code == 200
    assert client.get(
        f"/api/v1/agent/investigations/{investigation['id']}"
    ).json()["status"] == "failed"


def test_exact_replayed_worker_progress_does_not_duplicate_product_checkpoint(client):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Replayed progress")
    registration = register_worker(client, "agent-worker-replayed-progress")
    headers = bearer(registration["access_token"])
    claim = client.post(
        f"/api/v1/agent/workers/{registration['worker']['id']}/executions/claim",
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claim.status_code == 200, claim.text
    assignment = claim.json()[0]
    state = initial_graph_state(
        investigation_id=investigation["id"],
        objective=investigation["objective"],
        scope=investigation["scope"],
        max_iterations=investigation["max_iterations"],
        max_tool_calls=investigation["max_tool_calls"],
        token_budget=investigation["token_budget"],
    )
    state.update(
        current_node="reason",
        iteration=1,
        tokens_used=5,
        plan=["Read the target"],
    )
    payload = {
        "lease_token": assignment["lease_token"],
        "node": "reason",
        "status": "running",
        "iteration": 1,
        "tokens_used": 5,
        "tool_calls_used": 0,
        "evidence_count": 0,
        "state": state,
    }
    url = f"/api/v1/agent/executions/{execution['id']}/progress"
    first = client.post(url, headers=headers, json=payload)
    second = client.post(url, headers=headers, json=payload)
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert "checkpoint_replayed" not in first.json()["payload"]
    assert second.json()["payload"]["checkpoint_replayed"] is True
    with SessionLocal() as db:
        checkpoints = (
            db.query(InvestigationCheckpoint)
            .filter(InvestigationCheckpoint.investigation_id == investigation["id"])
            .order_by(InvestigationCheckpoint.sequence)
            .all()
        )
        assert [item.node for item in checkpoints] == ["start", "reason"]


def test_runtime_protocol_is_lease_bound_and_rejects_thread_and_operation_tamper(
    client,
):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Runtime security")
    registration = register_worker(client, "agent-worker-runtime-security")
    worker_id = registration["worker"]["id"]
    headers = bearer(registration["access_token"])
    claim = client.post(
        f"/api/v1/agent/workers/{worker_id}/executions/claim",
        headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assignment = claim.json()[0]
    bootstrap_payload = {
        "protocol_version": "icheck.agent-runtime/v1",
        "lease_token": assignment["lease_token"],
    }

    assert client.post(
        f"/api/v1/agent/executions/{execution['id']}/runtime/bootstrap",
        json=bootstrap_payload,
    ).status_code == 401
    assert client.post(
        f"/api/v1/agent/executions/{execution['id']}/runtime/bootstrap",
        headers=headers,
        json={
            **bootstrap_payload,
            "lease_token": "invalid-runtime-lease-token",
        },
    ).status_code == 409

    bootstrap = client.post(
        f"/api/v1/agent/executions/{execution['id']}/runtime/bootstrap",
        headers=headers,
        json=bootstrap_payload,
    )
    assert bootstrap.status_code == 200, bootstrap.text
    assert bootstrap.json()["protocol_version"] == "icheck.agent-runtime/v1"
    assert bootstrap.json()["resume_required"] is False

    wrong_thread = client.post(
        (
            f"/api/v1/agent/executions/{execution['id']}"
            "/runtime/checkpoints/get"
        ),
        headers=headers,
        json={
            **bootstrap_payload,
            "config": {
                "configurable": {
                    "thread_id": "another-investigation",
                }
            },
        },
    )
    assert wrong_thread.status_code == 409
    assert "does not match" in wrong_thread.text

    tampered_reason = client.post(
        f"/api/v1/agent/executions/{execution['id']}/runtime/reason",
        headers=headers,
        json={
            **bootstrap_payload,
            "operation_id": "0" * 64,
            "state": bootstrap.json()["initial_state"],
        },
    )
    assert tampered_reason.status_code == 409
    assert "operation ID" in tampered_reason.text


def test_remote_checkpoint_hook_renews_and_publishes_over_http(client):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Remote hook")
    registration = register_worker(client, "agent-worker-remote-hook")
    worker_id = registration["worker"]["id"]
    claim = client.post(
        f"/api/v1/agent/workers/{worker_id}/executions/claim",
        headers=bearer(registration["access_token"]),
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assignment = AgentExecutionAssignment.model_validate(claim.json()[0])
    remote = RecordingAgentControlClient()

    with SessionLocal() as db:
        stored_investigation = db.get(Investigation, investigation["id"])
        assert stored_investigation is not None
        state = initial_graph_state(
            investigation_id=investigation["id"],
            objective=investigation["objective"],
            scope=investigation["scope"],
            max_iterations=stored_investigation.max_iterations,
            max_tool_calls=stored_investigation.max_tool_calls,
            token_budget=stored_investigation.token_budget,
        )
    hook = RemoteLeasedCheckpointHook(
        remote,
        assignment,
        lease_seconds=60,
    )
    hook("reason", state)

    assert [item[1].rsplit("/", 1)[-1] for item in remote.requests] == [
        "lease",
        "progress",
    ]
    progress = remote.requests[1][2]
    assert progress == {
        "lease_token": assignment.lease_token,
        "node": "reason",
        "status": "running",
        "iteration": 0,
        "tokens_used": 0,
        "tool_calls_used": 0,
        "evidence_count": 0,
        "state": state,
    }


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
        "icheck.services.agent_remote_runtime.OpenAICompatibleReasoner",
        lambda *_args, **_kwargs: reasoner,
    )
    completed = execute_remote_assignment(
        APIAgentControlClient(client, registration["access_token"]),
        assignment,
        lease_seconds=60,
        credential_broker=None,
        mcp_allowed_hosts=["mcp.example.test"],
    )
    assert completed["status"] == "succeeded"
    with SessionLocal() as db:
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


@pytest.mark.parametrize(
    "lost_response",
    [
        TimeoutError("Completion committed, response dropped"),
        ControlPlaneHTTPError(502, "upstream connection closed"),
    ],
)
def test_worker_retries_identical_completion_after_committed_response_is_lost(
    client, monkeypatch, lost_response,
):
    configure_execution_route(client)
    investigation, execution = start_execution(client, title="Lost completion response")
    registration = register_worker(client, "agent-worker-lost-completion-response")
    claim = client.post(
        f"/api/v1/agent/workers/{registration['worker']['id']}/executions/claim",
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
        "icheck.services.agent_remote_runtime.OpenAICompatibleReasoner",
        lambda *_args, **_kwargs: reasoner,
    )

    class LostCompletionResponseClient(APIAgentControlClient):
        completion_documents = []

        def request(self, method, path, payload, **kwargs):
            result = super().request(method, path, payload, **kwargs)
            if path.endswith("/complete"):
                self.completion_documents.append(payload.copy())
                if len(self.completion_documents) == 1:
                    raise lost_response
            return result

    transport = LostCompletionResponseClient(client, registration["access_token"])
    completed = execute_remote_assignment(
        transport,
        assignment,
        lease_seconds=60,
        credential_broker=None,
        mcp_allowed_hosts=["mcp.example.test"],
    )
    assert completed["status"] == "succeeded"
    assert len(transport.completion_documents) == 2
    assert transport.completion_documents[0] == transport.completion_documents[1]
    assert client.get(
        f"/api/v1/agent/investigations/{investigation['id']}"
    ).json()["status"] == "completed"
    events = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events"
    ).json()
    assert [item["event_type"] for item in events].count("execution.completed") == 1


def test_http_only_worker_runs_reason_tool_evidence_loop(client, monkeypatch):
    configure_execution_route(client)
    device = client.post(
        "/api/v1/assets/devices",
        json={
            "name": "remote-runtime-switch",
            "kind": "switch",
            "management_ip": "192.0.2.88",
            "site": "LAB",
            "connections": [
                {
                    "protocol": "icmp",
                    "configuration": {"probe_timeout_seconds": 2},
                }
            ],
            "created_by": "l1.operator",
        },
    )
    assert device.status_code == 201, device.text
    device_id = device.json()["id"]
    investigation, execution = start_execution(
        client,
        title="Remote Tool execution",
        device_id=device_id,
    )
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)

    registration = register_worker(client, "agent-worker-runtime-tool")
    claim = client.post(
        (
            f"/api/v1/agent/workers/{registration['worker']['id']}"
            "/executions/claim"
        ),
        headers=bearer(registration["access_token"]),
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assignment = AgentExecutionAssignment.model_validate(claim.json()[0])
    reason_calls = []

    def reasoner(state):
        reason_calls.append(dict(state))
        if not state["tool_results"]:
            return GraphDecision(
                action="continue",
                plan=["Read the device", "Evaluate the evidence"],
                tool_requests=[
                    {
                        "tool_name": "inventory.get_device",
                        "arguments": {"device_id": device_id},
                        "purpose": "Read the bounded device state",
                    }
                ],
                token_usage=30,
            )
        assert state["tool_results"][0]["result"]["id"] == device_id
        return GraphDecision(
            action="complete",
            plan=state["plan"],
            confidence=0.95,
            conclusion="The device is registered and awaiting live verification.",
            uncertainty=["No live collector run has completed."],
            token_usage=20,
        )

    monkeypatch.setattr(
        "icheck.services.agent_remote_runtime.OpenAICompatibleReasoner",
        lambda *_args, **_kwargs: reasoner,
    )
    completed = execute_remote_assignment(
        APIAgentControlClient(client, registration["access_token"]),
        assignment,
        lease_seconds=60,
        credential_broker=None,
        mcp_allowed_hosts=["mcp.example.test"],
    )
    assert completed["status"] == "succeeded"
    assert len(reason_calls) == 2

    with SessionLocal() as db:
        stored = db.get(Investigation, investigation["id"])
        assert stored is not None
        assert stored.status == "completed"
        assert stored.iterations_used == 2
        assert stored.tool_calls_used == 1
        assert stored.tokens_used == 50
        checkpoints = (
            db.query(InvestigationCheckpoint)
            .filter(
                InvestigationCheckpoint.investigation_id == investigation["id"]
            )
            .order_by(InvestigationCheckpoint.sequence)
            .all()
        )
        assert [item.node for item in checkpoints] == [
            "start",
            "reason",
            "tools",
            "reason",
        ]
        calls = (
            db.query(InvestigationToolCall)
            .filter(InvestigationToolCall.investigation_id == investigation["id"])
            .all()
        )
        evidence = (
            db.query(InvestigationEvidence)
            .filter(InvestigationEvidence.investigation_id == investigation["id"])
            .all()
        )
        assert len(calls) == 1
        assert calls[0].status == "succeeded"
        assert len(evidence) == 1
        assert evidence[0].evidence_id == device_id

    events = client.get(
        f"/api/v1/agent/executions/{execution['id']}/events"
    ).json()
    assert [item["event_type"] for item in events] == [
        "execution.queued",
        "execution.claimed",
        "graph.reason",
        "graph.tools",
        "graph.reason",
        "graph.finalize",
        "execution.completed",
    ]


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
