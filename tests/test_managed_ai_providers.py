"""Offline provider contracts: no real keys, paid calls or device operations."""
import json
from copy import deepcopy
from urllib.error import HTTPError
from io import BytesIO

import pytest
from sqlalchemy import select
from pydantic import BaseModel

from icheck.ai_provider_presets import PRESETS
from icheck.ai_provider_transport import prepare_completion, normalize_completion, RESULT_TOOL
from icheck.langgraph_runtime import GraphDecision
from icheck.models import AIManagedConnection, AIProviderConfig, AuditEvent, Investigation
from icheck.services.ai_settings import _models_request_headers, validated_provider_url
from icheck.services.openrouter_setup import ManagedAIUnavailable
from test_openrouter_setup import managed_key, namespace_session, KEY
from test_password_login import bootstrap, login, required_auth


class Response:
    status = 200
    def __init__(self, document): self.body = json.dumps(document).encode()
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def read(self, limit): return self.body[:limit]


def connect(client, preset):
    r = client.post("/api/v1/ai/managed/connections", json={
        "preset": preset, "name": preset, "api_key": KEY, "approve_outbound": True})
    assert r.status_code == 201, r.text
    assert KEY not in r.text and r.headers["cache-control"] == "no-store"
    return r.json()


def completion(preset, value):
    if preset == "anthropic":
        return {"type": "message", "stop_reason": "tool_use",
                "content": [{"type": "tool_use", "name": RESULT_TOOL, "input": value}],
                "usage": {"input_tokens": 30, "output_tokens": 10, "cache_read_input_tokens": 2}}
    return {"choices": [{"message": {"content": json.dumps(value)}}], "usage": {"total_tokens": 42}}


class Network:
    def __init__(self, preset):
        self.preset = PRESETS[preset]
        self.requests = []
        self.value = {"action": "complete", "conclusion": "Fixture only"}
        self.model = "fixture/reasoner" if preset == "openrouter" else "fixture-reasoner"

    def open(self, request, timeout):
        self.requests.append(request)
        p = self.preset
        assert request.full_url.startswith(p.base_url + "/")
        assert 0 < timeout <= 120
        if p.id == "anthropic":
            assert request.get_header("X-api-key") == KEY
            assert request.get_header("Anthropic-version") == "2023-06-01"
            assert request.get_header("Authorization") is None
        else:
            assert request.get_header("Authorization") == "Bearer " + KEY
            assert request.get_header("X-api-key") is None
        path = request.full_url[len(p.base_url):]
        if path == "/key":
            assert p.id == "openrouter"
            return Response({"data": {"is_management_key": False}})
        if path.startswith("/models"):
            return Response({"data": [{"id": self.model, "supported_parameters": ["response_format", "structured_outputs"],
                                       "top_provider": {"max_completion_tokens": 4096}}]})
        body = json.loads(request.data)
        assert body["model"] == self.model and body["stream"] is False
        assert body.get("max_tokens", body.get("max_completion_tokens")) > 0
        if p.id == "anthropic":
            assert path == "/messages" and "response_format" not in body
            assert body["tools"][0]["name"] == RESULT_TOOL and "input_schema" in body["tools"][0]
            assert body["tool_choice"] == {"type": "auto", "disable_parallel_tool_use": True}
        else:
            assert path == "/chat/completions"
            if p.id in {"deepseek", "qwen_cn", "qwen_sg"}:
                assert body["response_format"] == {"type": "json_object"}
                assert "JSON Schema" in body["messages"][-1]["content"]
            if p.id == "openai":
                assert "max_completion_tokens" in body and "max_tokens" not in body
        if p.id != "openrouter":
            assert "provider" not in body  # No OpenRouter routing parameters leaked.
        return Response(completion(p.id, self.value))


def configure(client, row, network):
    prefix = f"/api/v1/ai/managed/{row['provider_id']}"
    checked = client.post(prefix + "/check").json()
    assert checked["health"]["status"] == "healthy", checked
    probe = client.post(prefix + "/probe", json={"expected_connection_revision": row["revision"],
        "model_id": network.model, "approve_charge": True})
    assert probe.status_code == 200 and probe.json()["passed"], probe.text
    payload = {"expected_connection_revision": row["revision"], "model_id": network.model,
        "display_name": row["name"] + " reasoner", "purposes": ["investigation", "capability.authoring"],
        "probe_reservation_id": probe.json()["quota_reservation_id"], "expected_configuration_hash": checked["configuration_hash"]}
    result = client.post(prefix + "/configure", json=payload)
    assert result.status_code == 200, result.text
    return result.json(), payload


@pytest.mark.parametrize("preset", PRESETS)
def test_presets_encrypt_and_bind_exact_origin_protocol_without_network(client, managed_key, monkeypatch, preset):
    monkeypatch.setattr("icheck.services.openrouter_setup.build_opener", lambda *_: pytest.fail("Saving a key must not contact a provider"))
    row = connect(client, preset)
    assert row["preset"] == preset and row["base_url"] == PRESETS[preset].base_url
    with namespace_session() as db:
        custody = db.scalar(select(AIManagedConnection))
        assert KEY.encode() not in custody.encrypted_secret
        p = db.get(AIProviderConfig, row["provider_id"])
        assert validated_provider_url(db, p) == PRESETS[preset].base_url
        with _models_request_headers(db, p) as headers:
            assert KEY in headers.get("Authorization", headers.get("X-API-Key", ""))
        p.base_url = "https://attacker.example/v1"
        with pytest.raises(ManagedAIUnavailable, match="approved endpoint"): validated_provider_url(db, p)
        db.rollback()
    assert KEY not in client.get("/api/v1/ai/managed/setup").text


@pytest.mark.parametrize("preset", PRESETS)
def test_end_to_end_setup_agent_and_studio_use_same_wire_adapter(client, managed_key, monkeypatch, preset):
    from icheck.langgraph_runtime import initial_graph_state
    from icheck.services.model_reasoner import OpenAICompatibleReasoner
    from icheck.services.structured_model import OpenAICompatibleStructuredGenerator
    network = Network(preset)
    monkeypatch.setattr("icheck.services.openrouter_setup.build_opener", lambda *_: network)
    row = connect(client, preset)
    configured, _ = configure(client, row, network)
    assert "json_schema" in configured["model"]["capabilities"]
    assert configured["model"]["default_parameters"] == ({"provider": {"require_parameters": True}} if preset == "openrouter" else {})
    created = client.post("/api/v1/agent/investigations", json={"title": "Provider fixture",
        "objective": "Return a fixture conclusion", "created_by": "operator"})
    assert created.status_code == 201, created.text
    identity = created.json()["id"]
    assert client.post(f"/api/v1/agent/investigations/{identity}/start", json={"actor": "operator"}).status_code == 200
    from test_agent_execution import register_worker, bearer
    worker = register_worker(client, "provider-fixture-worker", capabilities=["openai_compatible", "anthropic"])
    claimed = client.post(f"/api/v1/agent/workers/{worker['worker']['id']}/executions/claim",
                          headers=bearer(worker["access_token"]), json={"max_assignments": 1, "lease_seconds": 60})
    assert claimed.status_code == 200 and claimed.json()[0]["investigation_id"] == identity, claimed.text
    with namespace_session() as db:
        investigation = db.get(Investigation, identity)
        state = initial_graph_state(investigation_id=identity, objective=investigation.objective, scope={},
                                    max_iterations=8, max_tool_calls=20, token_budget=50000)
        decision = OpenAICompatibleReasoner(db, investigation, opener=network)(state)
        assert decision.action == "complete" and decision.token_usage == 42
        class Result(BaseModel):
            result: str
        network.value = {"result": "Studio fixture"}
        generated = OpenAICompatibleStructuredGenerator(db, opener=network).generate(
            route_purpose="capability.authoring", response_model=Result, schema_name="fixture",
            system_prompt="Return a fixture", prompt_document={}, entity_type="fixture", entity_id="fixture", actor_id="operator")
        assert generated.document.result == "Studio fixture"
        assert generated.tokens_used == 42
        assert KEY not in json.dumps([e.details for e in db.scalars(select(AuditEvent))])


@pytest.mark.parametrize("preset", ["openai", "anthropic", "deepseek"])
def test_direct_catalog_is_not_proof_and_probe_cannot_be_bypassed_or_reused(client, managed_key, monkeypatch, preset):
    network = Network(preset)
    monkeypatch.setattr("icheck.services.openrouter_setup.build_opener", lambda *_: network)
    row = connect(client, preset)
    prefix = f"/api/v1/ai/managed/{row['provider_id']}"
    catalog = client.post(prefix + "/check").json()
    assert catalog["models"][0]["capabilities"] == ["chat"]
    payload = {"expected_connection_revision": 1, "model_id": network.model, "display_name": "No bypass",
               "purposes": ["investigation"]}
    assert client.post(prefix + "/configure", json=payload).status_code == 422
    assert client.post(prefix.replace("/managed/", "/openrouter/") + "/configure", json=payload).status_code == 409
    _, valid = configure(client, row, network)
    previous = client.get("/api/v1/ai/routes").json()
    assert client.put(prefix + "/connection", json={"expected_revision": 1, "outbound_enabled": True, "api_key": KEY}).status_code == 200
    valid.update(expected_connection_revision=2, replace_existing_routes=True)
    assert client.post(prefix + "/configure", json=valid).status_code == 409
    assert client.get("/api/v1/ai/routes").json() == previous


@pytest.mark.parametrize("extra", [{"preset": "unknown"}, {"base_url": "https://evil.example"}, {"api_key": KEY + " "}])
def test_generic_validation_redacts_secret_and_rejects_custom_origins(client, managed_key, extra):
    result = client.post("/api/v1/ai/managed/connections", json={"preset": "openai", "name": "fixture",
        "api_key": KEY, "approve_outbound": True, **extra})
    assert result.status_code == 422 and KEY not in result.text and '"input"' not in result.text


def test_provider_http_errors_are_sanitized(client, managed_key, monkeypatch):
    row = connect(client, "anthropic")
    class Rejected:
        def open(self, request, timeout): raise HTTPError(request.full_url, 401, KEY, {}, BytesIO(KEY.encode()))
    monkeypatch.setattr("icheck.services.openrouter_setup.build_opener", lambda *_: Rejected())
    result = client.post(f"/api/v1/ai/managed/{row['provider_id']}/check")
    assert result.json()["health"]["error"] == "Anthropic Claude API key was rejected"
    assert KEY not in result.text + client.get("/api/v1/audit-events").text


@pytest.mark.parametrize("mutation", ["truncated", "wrong_tool", "multiple_tools", "missing_usage", "bool_usage", "invalid_result"])
def test_claude_result_envelope_never_executes_tools_or_accepts_bad_usage(mutation):
    value = completion("anthropic", {"action": "complete", "conclusion": "Fixture"})
    if mutation == "truncated": value["stop_reason"] = "max_tokens"
    if mutation == "wrong_tool": value["content"][0]["name"] = "device.configure"
    if mutation == "multiple_tools": value["content"] *= 2
    if mutation == "missing_usage": value.pop("usage")
    if mutation == "bool_usage": value["usage"]["input_tokens"] = True
    if mutation == "invalid_result": value["content"][0]["input"] = {"action": "continue"}
    normalized = normalize_completion("anthropic", value)
    if mutation in {"missing_usage", "bool_usage"}:
        assert normalized["usage"]["total_tokens"] is None
    else:
        assert normalized["usage"]["total_tokens"] == 42
        with pytest.raises(ValueError): GraphDecision.model_validate_json(normalized["choices"][0]["message"]["content"])


def test_wire_adaptation_does_not_mutate_payload_or_openrouter_contract():
    payload = {"model": "fixture", "messages": [{"role": "user", "content": "fixture"}], "max_tokens": 512,
               "response_format": {"type": "json_schema", "json_schema": {"schema": GraphDecision.model_json_schema(), "strict": False}}}
    original = deepcopy(payload)
    for p in PRESETS.values(): prepare_completion(p.provider_type, p.base_url, payload)
    assert payload == original
    url, body = prepare_completion("openai_compatible", PRESETS["openrouter"].base_url, payload)
    assert body == original and url.endswith("/chat/completions")
    with pytest.raises(ValueError, match="unsupported parameters were not sent"):
        prepare_completion("anthropic", PRESETS["anthropic"].base_url, {**payload, "private-parameter": "do-not-echo"})


def test_new_connection_and_probe_preserve_existing_openrouter_routes(client, managed_key, monkeypatch):
    old_network = Network("openrouter")
    monkeypatch.setattr("icheck.services.openrouter_setup.build_opener", lambda *_: old_network)
    configure(client, connect(client, "openrouter"), old_network)
    routes, models = client.get("/api/v1/ai/routes").json(), client.get("/api/v1/ai/models").json()
    new_network = Network("anthropic")
    monkeypatch.setattr("icheck.services.openrouter_setup.build_opener", lambda *_: new_network)
    row = connect(client, "anthropic")
    prefix = f"/api/v1/ai/managed/{row['provider_id']}"
    assert client.post(prefix + "/check").status_code == 200
    assert client.post(prefix + "/probe", json={"expected_connection_revision": 1,
        "model_id": new_network.model, "approve_charge": True}).json()["passed"]
    assert client.get("/api/v1/ai/routes").json() == routes
    assert client.get("/api/v1/ai/models").json() == models


def test_generic_api_requires_human_admin_and_browser_csrf(client, managed_key, required_auth):
    _, admin_headers = bootstrap(client)
    signed_in = login(client)
    payload = {"preset": "anthropic", "name": "claude", "api_key": KEY, "approve_outbound": True}
    assert client.post("/api/v1/ai/managed/connections", json=payload).status_code == 403
    saved = client.post("/api/v1/ai/managed/connections", json=payload,
        headers={"X-Icheck-CSRF-Token": signed_in.json()["csrf_token"]})
    assert saved.status_code == 201 and KEY not in saved.text
    client.cookies.clear()
    viewer = client.post("/api/v1/auth/principals", headers=admin_headers,
        json={"subject": "viewer", "display_name": "Viewer", "principal_type": "user"}).json()
    role = next(r for r in client.get("/api/v1/auth/roles", headers=admin_headers).json() if r["name"] == "viewer")
    assert client.post(f"/api/v1/auth/principals/{viewer['id']}/bindings", headers=admin_headers,
        json={"role_id": role["id"], "scope": {"all": True}}).status_code == 201
    token = client.post(f"/api/v1/auth/principals/{viewer['id']}/tokens", headers=admin_headers,
        json={"name": "viewer", "expires_in_hours": 1}).json()["access_token"]
    assert client.get("/api/v1/ai/managed/setup", headers={"Authorization": "Bearer " + token}).status_code == 403
