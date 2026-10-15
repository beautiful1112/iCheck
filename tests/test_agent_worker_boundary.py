from __future__ import annotations

import ast
from io import BytesIO
from http.client import IncompleteRead
from pathlib import Path
from urllib.error import HTTPError

import pytest

from icheck import agent_schemas
import icheck.agent_worker as agent_worker
from icheck.collector_worker import ControlPlaneClient, ControlPlaneHTTPError


def test_agent_worker_has_no_direct_database_or_outbox_dependency():
    source_path = Path(agent_worker.__file__).resolve()
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
    assert "services.agent_runtime" not in imported_modules
    assert "services.workflow_runtime" not in imported_modules
    for forbidden in (
        "ICHECK_DATABASE_URL",
        "SessionLocal",
        "dispatch_workflow",
        "enqueue_due_workflow",
    ):
        assert forbidden not in source

    environment_template = (
        source_path.parents[2] / "deploy/systemd/agent-worker.env.example"
    ).read_text(encoding="utf-8")
    assert "ICHECK_DATABASE_URL" not in environment_template


def test_runtime_checkpoint_messages_have_an_aggregate_bound(monkeypatch):
    monkeypatch.setattr(
        agent_schemas,
        "MAX_AGENT_RUNTIME_MESSAGE_WIRE_CHARS",
        7,
    )
    wire = {"type": "json", "data_base64": "e30="}
    base = {
        "protocol_version": "icheck.agent-runtime/v1",
        "lease_token": "l" * 20,
        "config": {"configurable": {"thread_id": "investigation-1"}},
    }
    with pytest.raises(ValueError, match="checkpoint message"):
        agent_schemas.AgentRuntimeCheckpointPut.model_validate(
            {
                **base,
                "checkpoint": wire,
                "metadata": wire,
                "new_versions": wire,
            }
        )
    with pytest.raises(ValueError, match="checkpoint writes"):
        agent_schemas.AgentRuntimeCheckpointWrites.model_validate(
            {
                **base,
                "writes": [["first", wire], ["second", wire]],
                "task_id": "task-1",
            }
        )


def test_control_plane_client_bounds_requests_and_responses():
    client = ControlPlaneClient(
        "http://127.0.0.1:8000",
        max_message_bytes=10,
    )
    with pytest.raises(ValueError, match="request exceeds"):
        client.request("POST", "/test", {"value": "too-large"})

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            assert size == 11
            return b"x" * size

    class _Opener:
        def open(self, *_args: object, **_kwargs: object) -> _Response:
            return _Response()

    client.opener = _Opener()
    with pytest.raises(RuntimeError, match="response exceeds"):
        client.request("GET", "/test")


def test_control_plane_client_preserves_upstream_status_for_completion_retry():
    client = ControlPlaneClient("http://127.0.0.1:8000")

    class _Opener:
        def open(self, *_args: object, **_kwargs: object) -> None:
            raise HTTPError(
                "http://127.0.0.1:8000/complete",
                502,
                "Bad Gateway",
                {},
                BytesIO(b'{"detail":"upstream unavailable"}'),
            )

    client.opener = _Opener()
    with pytest.raises(ControlPlaneHTTPError) as failure:
        client.request("POST", "/complete", {"status": "succeeded"})
    assert failure.value.status_code == 502
    assert "upstream unavailable" in str(failure.value)


@pytest.mark.parametrize("length,error", [(10, IncompleteRead), (101, RuntimeError), (-1, ValueError), ("invalid", ValueError)])
def test_control_plane_client_distinguishes_truncated_and_invalid_http_lengths(length, error):
    client = ControlPlaneClient("http://127.0.0.1:8000", max_message_bytes=100)
    class Response:
        headers = {"Content-Length": str(length)}
        def __enter__(self): return self
        def __exit__(self, *_args): pass
        def read(self, size): return b"{}"
    class Opener:
        def open(self, *_args, **_kwargs): return Response()
    client.opener = Opener()
    with pytest.raises(error): client.request("GET", "/test")


def test_recorded_mcp_acknowledgment_never_invokes_adapter(monkeypatch):
    from icheck.agent_runtime_protocol import RemoteToolExecutor
    from icheck.langgraph_runtime import GraphToolRequest, initial_graph_state
    class Client:
        def __init__(self): self.requests = []
        def request(self, _method, _path, payload):
            self.requests.append(payload)
            if len(self.requests) == 1:
                return {"protocol_version": "icheck.agent-runtime/v1", "operation_id": payload["operation_id"],
                    "status": "interrupted", "interrupt": {"kind": "recorded_mcp_result", "tool_call_id": "recorded-call"}}
            return {"protocol_version": "icheck.agent-runtime/v1", "operation_id": payload["operation_id"],
                "status": "completed", "result": {"call_id": "recorded-call", "tool_name": "test.recorded",
                    "arguments": {}, "status": "succeeded", "result": {"ok": True}}}
    client = Client()
    executor = RemoteToolExecutor(client, "execution", "lease-token")
    def no_io(_payload): raise AssertionError("Recorded result acknowledgment attempted adapter I/O")
    monkeypatch.setattr(executor, "_run_mcp", no_io)
    result = executor(GraphToolRequest(tool_name="test.recorded", arguments={}, purpose="Recover existing evidence"),
        initial_graph_state(investigation_id="investigation", objective="Recover evidence", scope={},
            max_iterations=2, max_tool_calls=2, token_budget=100))
    assert result.result == {"ok": True}
    assert client.requests[1]["resume_value"] == {"kind": "recorded_mcp_ack", "tool_call_id": "recorded-call"}


@pytest.mark.parametrize("value", [None, "false", 0, {}])
def test_legacy_or_untyped_invocation_requires_reconciliation(value):
    from icheck.services.agent_approvals import ActionOutcomeUnknown
    from icheck.services.agent_remote_runtime import _pending_mcp_result_call
    with pytest.raises(ActionOutcomeUnknown, match="Unbound delegated invocation"):
        _pending_mcp_result_call(None, {"kind": "mcp_invocation", "read_only": value},
            execution=None, worker=None, resume_value=None)
