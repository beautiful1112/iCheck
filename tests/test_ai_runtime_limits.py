"""No paid inference: deadline, Qwen and safe validation regressions."""
import json
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, build_opener, ProxyHandler

import pytest
from sqlalchemy import select

from icheck.ai_failure_diagnostics import model_validation_diagnostic
from icheck.ai_runtime_policy import qwen_runtime_parameters
from icheck.agent_runtime_protocol import RemoteReasoner
from icheck.bounded_http import read_bounded_response
from icheck.collector_worker import ControlPlaneClient
from icheck.langgraph_runtime import GraphDecision, initial_graph_state
from icheck.models import AIModelConfig, Investigation, AuditEvent
from icheck.services.model_reasoner import OpenAICompatibleReasoner, ModelReasonerUnavailable
from test_openrouter_setup import managed_key, provider_network, connect, configure, namespace_session


def state():
    return initial_graph_state(investigation_id="investigation", objective="Read inventory", scope={},
        max_iterations=2, max_tool_calls=2, token_budget=50000)


def test_worker_reason_wait_uses_investigation_deadline_and_renews_lease():
    calls, renewals = [], []
    class Client:
        def request(self, method, path, document, **kwargs):
            calls.append(kwargs)
            return {"protocol_version": "icheck.agent-runtime/v1", "operation_id": document["operation_id"],
                "decision": {"action": "complete", "conclusion": "No mutation"}}
    result = RemoteReasoner(Client(), "execution", "lease-token", reasoning_deadline=datetime.now(UTC) + timedelta(seconds=90),
        before_call=lambda: renewals.append(True))(state())
    assert result.action == "complete" and renewals == [True]
    assert 90 < calls[0]["timeout_seconds"] <= 95
    assert calls[0]["allow_extended_timeout"] is True


def test_worker_expired_budget_never_calls_reason_endpoint():
    class Client:
        def request(self, *args, **kwargs): raise AssertionError("Expired reasoning made a call")
    result = RemoteReasoner(Client(), "execution", "lease-token", reasoning_deadline=datetime.now(UTC) - timedelta(seconds=1))(state())
    assert result.action == "escalate" and "deadline exhausted" in result.escalation_reason


def test_worker_transport_timeout_is_safe_and_not_a_device_failure():
    class Client:
        def request(self, *args, **kwargs): raise TimeoutError("secret-token private provider body")
    result = RemoteReasoner(Client(), "execution", "lease-token")(state())
    assert "Worker timed out" in result.escalation_reason
    assert "secret-token" not in result.escalation_reason and "device connectivity" in result.escalation_reason


def test_control_plane_extended_wait_is_explicit_and_reason_only():
    calls = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size): return b"{}"
    class Opener:
        def open(self, request, timeout): calls.append(timeout); return Response()
    client = ControlPlaneClient("http://127.0.0.1:8000"); client.opener = Opener()
    client.request("POST", "/api/v1/agent/executions/e/runtime/reason", {}, timeout_seconds=95, allow_extended_timeout=True)
    client.request("GET", "/normal", timeout_seconds=95)
    assert calls == [95, 30]
    for path, timeout in [("/normal", 95), ("/api/v1/agent/executions/e/runtime/reason", 3606)]:
        with pytest.raises(ValueError, match="Extended timeout"):
            client.request("POST", path, {}, timeout_seconds=timeout, allow_extended_timeout=True)


def test_keepalive_bytes_cannot_extend_model_total_deadline():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "100"); self.end_headers()
            try:
                for _ in range(30):
                    self.wfile.write(b" "); self.wfile.flush(); time.sleep(0.025)
            except (BrokenPipeError, ConnectionResetError): pass
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            read_bounded_response(build_opener(ProxyHandler({})), Request(f"http://127.0.0.1:{server.server_port}"), timeout=0.15, max_bytes=1000)
        assert time.monotonic() - started < 0.8
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


@pytest.mark.parametrize("remaining,output", [(50000, 4096), (200, 200), (8000, 4096)])
def test_existing_qwen_profile_gets_bounded_runtime_defaults(remaining, output):
    original = {"max_tokens": 131072, "provider": {"require_parameters": True}, "reasoning": {"enabled": False}}
    result = qwen_runtime_parameters("https://openrouter.ai/api/v1", "qwen/qwen3.8-max-0902", original, remaining)
    assert result["max_tokens"] == output
    assert result["reasoning"] == {"enabled": True, "effort": "minimal"}
    assert original["reasoning"]["enabled"] is False
    assert qwen_runtime_parameters("https://elsewhere.test/v1", "qwen/qwen3.8-max-0902", original, remaining) == original


@pytest.mark.parametrize("document,rule,path", [
    ({"action": "continue"}, "continue_requires_tools", "$"),
    ({"action": "complete"}, "complete_requires_conclusion", "$"),
    ({"action": "escalate"}, "escalate_requires_reason", "$"),
    ({"action": "complete", "conclusion": "safe", "confidence": 2}, "less_than_equal", "confidence"),
    ({"action": "complete", "conclusion": "safe", "secret-token-as-field": "private-input"}, "extra_forbidden", "<unknown-field>"),
    ({"action": "continue", "tool_requests": [{"arguments": {}, "purpose": "safe"}]}, "missing", "tool_requests.0.tool_name"),
])
def test_exact_validation_rule_and_path_never_echo_values(document, rule, path):
    with pytest.raises(ValueError) as failure: GraphDecision.model_validate(document)
    value = model_validation_diagnostic(failure.value)
    assert {"path": path, "rule": rule} in value["validation_errors"]
    assert "secret-token" not in json.dumps(value) and "private-input" not in json.dumps(value)


def test_truncated_json_retains_finish_reason_and_safe_position():
    with pytest.raises(json.JSONDecodeError) as failure: json.loads('{"private-input":')
    value = model_validation_diagnostic(failure.value, finish_reason="length")
    assert value["finish_reason"] == "length"
    assert value["validation_errors"][0]["rule"] == "output_token_limit_reached"
    assert value["validation_errors"][1]["line"] == 1
    assert "private-input" not in json.dumps(value)


@pytest.mark.parametrize("timeout", [False, True])
def test_remote_agent_retains_typed_failure_and_accounts_usage(client, managed_key, provider_network, monkeypatch, timeout):
    from icheck.agent_schemas import AgentExecutionAssignment
    from icheck.agent_worker import execute_remote_assignment
    from test_agent_execution import register_worker, bearer, APIAgentControlClient
    connection = connect(client); configured = configure(client, connection).json()
    with namespace_session() as db:
        model = db.get(AIModelConfig, configured["model"]["id"])
        model.model_name = "qwen/qwen3.8-max-0902"; model.max_output_tokens = 131072; db.commit()
    row = client.post("/api/v1/agent/investigations", json={"title": "Safe failure", "objective": "Read inventory", "created_by": "operator"}).json()
    assert client.post(f"/api/v1/agent/investigations/{row['id']}/start", json={"actor": "operator"}).status_code == 200
    worker = register_worker(client, "runtime-limit-fixture")
    claim = client.post(f"/api/v1/agent/workers/{worker['worker']['id']}/executions/claim", headers=bearer(worker["access_token"]), json={"max_assignments": 1, "lease_seconds": 60})
    assignment = AgentExecutionAssignment.model_validate(claim.json()[0])
    calls = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size): return json.dumps({"usage": {"total_tokens": 321}, "choices": [{"finish_reason": "stop", "message": {"content": '{"action":"continue"}'}}]}).encode()
    class Opener:
        def open(self, request, timeout):
            payload = json.loads(request.data); calls.append(payload)
            assert payload["max_tokens"] == 4096 and payload["reasoning"] == {"enabled": True, "effort": "minimal"}
            if test_timeout: raise TimeoutError("private-token")
            return Response()
    test_timeout = timeout
    monkeypatch.setattr("icheck.services.model_reasoner.build_opener", lambda *args: Opener())
    execute_remote_assignment(APIAgentControlClient(client, worker["access_token"]), assignment, lease_seconds=60, credential_broker=None, mcp_allowed_hosts=[])
    result = client.get(f"/api/v1/agent/investigations/{row['id']}").json()
    assert result["status"] == "escalated" and result["tool_calls_used"] == 0
    assert result["tokens_used"] == (0 if timeout else 321)
    diagnosis = client.get(f"/api/v1/agent/investigations/{row['id']}/diagnosis").json()
    assert diagnosis["diagnostic"]["code"] == ("provider_timeout" if timeout else "model_schema_invalid")
    if timeout: assert diagnosis["model_usage"]["unresolved_charges"] is True
    else: assert diagnosis["diagnostic"]["validation_errors"] == [{"path": "$", "rule": "continue_requires_tools"}]
    assert len(calls) == 1
    assert "private-token" not in client.get("/api/v1/audit-events").text


def test_legacy_late_validation_failure_is_identified_without_rewriting_history(client, managed_key, provider_network):
    connection = connect(client); configure(client, connection)
    row = client.post("/api/v1/agent/investigations", json={"title": "Legacy", "objective": "Read inventory", "created_by": "operator"}).json()
    with namespace_session() as db:
        investigation = db.get(Investigation, row["id"]); investigation.status = "escalated"; investigation.escalation_reason = "Reasoner failed: TimeoutError"
        db.add(AuditEvent(event_type="investigation.model.failed", actor_type="agent", actor_id="l1", entity_type="investigation", entity_id=row["id"], outcome="failure", details={"model_id": investigation.model_id, "error": "AI provider returned an invalid graph decision", "token_usage": 10547}))
        db.commit()
    diagnosis = client.get(f"/api/v1/agent/investigations/{row['id']}/diagnosis").json()
    assert diagnosis["diagnostic"]["code"] == "model_schema_invalid"
    assert diagnosis["diagnostic"]["root_cause_known"] is False
    assert "exact field/rule was not retained" in diagnosis["diagnostic"]["cause"]
    assert client.get(f"/api/v1/agent/investigations/{row['id']}").json()["escalation_reason"] == "Reasoner failed: TimeoutError"
