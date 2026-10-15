"""Managed keys are write-only, provider-bound and absent from retained evidence."""
import json
import os
from urllib.error import HTTPError
from io import BytesIO
from contextlib import contextmanager

import pytest
from sqlalchemy import select

from icheck.config import get_settings
from icheck.database import SessionLocal, set_session_namespace
from icheck.models import AIManagedConnection, AIModelConfig, AIModelRoute, AIProviderConfig, AuditEvent, CredentialProfile
from icheck.services.ai_settings import _models_request_headers, validated_provider_url, AIProviderUnavailable
from icheck.services.openrouter_setup import BASE, ManagedAIUnavailable, connection_for
from test_password_login import bootstrap, login, required_auth

KEY = "sk-or-v1-synthetic-inference-key-not-a-real-secret"
@contextmanager
def namespace_session():
    with SessionLocal() as db:
        set_session_namespace(db, "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002")
        yield db
CATALOG = {"data": [
    {"id": "openai/gpt-4o", "supported_parameters": ["response_format", "structured_outputs", "tools"],
     "context_length": 128000, "top_provider": {"max_completion_tokens": 16384}},
    {"id": "example/no-tools", "supported_parameters": ["response_format", "structured_outputs"]},
    {"id": "example/plain-text", "supported_parameters": ["tools"]},
    {"id": "bad id", "supported_parameters": ["response_format", "structured_outputs"]},
]}


@pytest.fixture
def managed_key(tmp_path, monkeypatch):
    path = tmp_path / "managed.key"
    path.write_bytes(os.urandom(32))
    path.chmod(0o400)
    with monkeypatch.context() as patch:
        patch.setenv("ICHECK_AI_MANAGED_SECRET_KEY_FILE", str(path))
        get_settings.cache_clear()
        yield path
    get_settings.cache_clear()


@pytest.fixture
def provider_network(monkeypatch):
    requests = []

    class Response:
        status = 200
        def __init__(self, doc): self.body = json.dumps(doc).encode()
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self, limit): return self.body[:limit]

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            assert request.full_url in {BASE + "/key", BASE + "/models"}
            assert request.get_header("Authorization") == "Bearer " + KEY
            return Response({"data": {"is_management_key": False, "label": KEY}} if request.full_url.endswith("/key") else CATALOG)

    monkeypatch.setattr("icheck.services.openrouter_setup.build_opener", lambda *args: Opener())
    return requests


def connect(client, **fields):
    response = client.post("/api/v1/ai/openrouter/connections", json={"name": "openrouter", "api_key": KEY, "approve_outbound": True, **fields})
    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "no-store"
    assert KEY not in response.text
    return response.json()


def configure(client, connection, **fields):
    return client.post(f"/api/v1/ai/openrouter/{connection['provider_id']}/configure", json={
        "expected_connection_revision": connection["revision"], "model_id": "openai/gpt-4o",
        "display_name": "Operations reasoner", "purposes": ["investigation", "capability.authoring"], **fields,
    })


def test_complete_setup_encrypted_custody_health_models_and_atomic_routes(client, managed_key, provider_network):
    assert client.get("/api/v1/ai/openrouter/setup").json()["storage_ready"] is True
    connected = connect(client)
    with namespace_session() as db:
        custody = db.scalar(select(AIManagedConnection))
        assert KEY.encode() not in custody.encrypted_secret
        assert custody.encrypted_secret[:1] == b"\x01"
        provider = db.get(AIProviderConfig, connected["provider_id"])
        assert validated_provider_url(db, provider) == BASE
        with _models_request_headers(db, provider) as headers:
            assert headers["Authorization"] == "Bearer " + KEY
        assert "openrouter.ai" not in get_settings().ai_allowed_host_list
    checked = client.post(f"/api/v1/ai/openrouter/{connected['provider_id']}/check")
    assert checked.status_code == 200, checked.text
    assert checked.json()["health"]["status"] == "healthy"
    assert {model["id"] for model in checked.json()["models"]} == {"openai/gpt-4o", "example/no-tools"}
    assert checked.json()["models"][0]["capabilities"] == ["chat", "json_schema"]
    assert KEY not in checked.text
    assert [r.full_url for r in provider_network] == [BASE + "/key", BASE + "/models"]
    configured = configure(client, connected)
    assert configured.status_code == 200, configured.text
    assert configured.json()["model"]["default_parameters"] == {"provider": {"require_parameters": True}}
    assert {r["purpose"] for r in configured.json()["routes"]} == {"investigation", "capability.authoring"}
    assert {r["token_budget"] for r in configured.json()["routes"]} == {50000}
    with namespace_session() as db:
        audits = json.dumps([event.details for event in db.scalars(select(AuditEvent))])
        assert KEY not in audits and "encrypted_secret" not in audits
    for url in ["/api/v1/ai/openrouter/setup", "/api/v1/credential-profiles", "/api/v1/ai/providers", "/api/v1/ai/models", "/api/v1/ai/routes", "/api/v1/audit-events"]:
        assert KEY not in client.get(url).text


def test_storage_unavailable_or_unsafe_fails_before_metadata_creation(client, managed_key):
    managed_key.chmod(0o644)
    assert client.get("/api/v1/ai/openrouter/setup").json()["storage_ready"] is False
    response = client.post("/api/v1/ai/openrouter/connections", json={"name": "openrouter", "api_key": KEY, "approve_outbound": True})
    assert response.status_code == 503 and KEY not in response.text
    assert client.get("/api/v1/ai/providers").json() == []
    assert client.get("/api/v1/credential-profiles").json() == []


@pytest.mark.parametrize("payload", [
    {"api_key": KEY + " "}, {"api_key": {"nested": KEY}}, {"api_key": KEY, "token": KEY},
    {"api_key": KEY, "base_url": KEY}, {"api_key": KEY, "approve_outbound": False},
])
def test_validation_never_echoes_secret_input(client, managed_key, payload):
    response = client.post("/api/v1/ai/openrouter/connections", json={"name": "openrouter", "approve_outbound": True, **payload})
    assert response.status_code == 422
    assert KEY not in response.text and "\"input\"" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_provider_failure_does_not_echo_response_or_exception_secret(client, managed_key, monkeypatch):
    connected = connect(client)
    class Rejected:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 401, KEY, {}, BytesIO(KEY.encode()))
    monkeypatch.setattr("icheck.services.openrouter_setup.build_opener", lambda *args: Rejected())
    response = client.post(f"/api/v1/ai/openrouter/{connected['provider_id']}/check")
    assert response.json()["health"]["status"] == "unhealthy"
    assert response.json()["health"]["error"] == "OpenRouter API key was rejected"
    assert KEY not in response.text
    assert KEY not in client.get("/api/v1/ai/providers").text
    assert KEY not in client.get("/api/v1/audit-events").text


def test_rotation_revision_revocation_and_wrong_master_key_fail_closed(client, managed_key, monkeypatch):
    connected = connect(client)
    url = f"/api/v1/ai/openrouter/{connected['provider_id']}/connection"
    disabled = client.put(url, json={"expected_revision": 1, "outbound_enabled": False})
    assert disabled.status_code == 200 and disabled.json()["revision"] == 2
    assert client.put(url, json={"expected_revision": 1, "api_key": KEY, "outbound_enabled": True}).status_code == 409
    monkeypatch.setenv("ICHECK_AI_ALLOWED_HOSTS", "openrouter.ai")
    get_settings.cache_clear()
    with namespace_session() as db:
        provider = db.get(AIProviderConfig, connected["provider_id"])
        with pytest.raises(ManagedAIUnavailable, match="disabled"):
            validated_provider_url(db, provider)
    rotated = client.put(url, json={"expected_revision": 2, "api_key": KEY + "-rotated", "outbound_enabled": True})
    assert rotated.status_code == 200 and KEY not in rotated.text
    with namespace_session() as db:
        provider = db.get(AIProviderConfig, connected["provider_id"])
        with _models_request_headers(db, provider) as headers:
            assert headers["Authorization"] == "Bearer " + KEY + "-rotated"
    managed_key.chmod(0o600); managed_key.write_bytes(os.urandom(32)); managed_key.chmod(0o400)
    with namespace_session() as db:
        with pytest.raises(AIProviderUnavailable, match="cannot be decrypted"):
            with _models_request_headers(db, db.get(AIProviderConfig, connected["provider_id"])): pass


def test_provider_binding_and_namespace_cannot_reuse_managed_key(client, managed_key):
    connected = connect(client)
    source = client.get("/api/v1/ai/providers").json()[0]
    copied = {k: source[k] for k in ["name", "provider_type", "base_url", "auth_type", "credential_profile_ref", "privacy_tier", "data_residency", "enabled", "request_timeout_seconds"]}
    copied.update(name="stolen-key", base_url="https://models.example.test/v1", created_by="test")
    assert client.post("/api/v1/ai/providers", json=copied).status_code == 422
    del copied["created_by"]
    copied.update(actor="test", base_url=BASE, credential_profile_ref=None)
    assert client.put(f"/api/v1/ai/providers/{connected['provider_id']}", json=copied).status_code == 422
    with namespace_session() as db:
        set_session_namespace(db, "other-tenant", "other-region")
        assert connection_for(db, connected["provider_id"]) is None
        assert db.scalar(select(AIManagedConnection)) is None


def test_configure_preserves_routes_without_explicit_replacement_and_rechecks_catalog(client, managed_key, provider_network):
    connected = connect(client)
    assert configure(client, connected).status_code == 200
    previous = client.get("/api/v1/ai/routes").json()
    assert configure(client, connected, token_budget=9000).status_code == 409
    assert client.get("/api/v1/ai/routes").json() == previous
    assert configure(client, connected, replace_existing_routes=True, model_id="example/plain-text").status_code == 422
    assert client.get("/api/v1/ai/routes").json() == previous
    replaced = configure(client, connected, replace_existing_routes=True, model_id="example/no-tools", display_name="No-tools reasoner", token_budget=9000)
    assert replaced.status_code == 200, replaced.text
    assert all(route["token_budget"] == 9000 for route in replaced.json()["routes"])
    with namespace_session() as db:
        assert len(list(db.scalars(select(AIModelRoute)))) == 2
        assert len(list(db.scalars(select(AIModelConfig)))) == 2


def test_browser_admin_session_requires_csrf_and_viewers_cannot_save_keys(client, managed_key, required_auth):
    _, admin_headers = bootstrap(client)
    signed_in = login(client)
    payload = {"name": "openrouter", "api_key": KEY, "approve_outbound": True}
    assert client.post("/api/v1/ai/openrouter/connections", json=payload).status_code == 403
    response = client.post("/api/v1/ai/openrouter/connections", headers={"X-Icheck-CSRF-Token": signed_in.json()["csrf_token"]}, json=payload)
    assert response.status_code == 201, response.text
    client.cookies.clear()
    viewer = client.post("/api/v1/auth/principals", headers=admin_headers, json={"subject": "viewer", "display_name": "Viewer", "principal_type": "user"}).json()
    role = next(r for r in client.get("/api/v1/auth/roles", headers=admin_headers).json() if r["name"] == "viewer")
    assert client.post(f"/api/v1/auth/principals/{viewer['id']}/bindings", headers=admin_headers, json={"role_id": role["id"], "scope": {"all": True}}).status_code == 201
    raw = client.post(f"/api/v1/auth/principals/{viewer['id']}/tokens", headers=admin_headers, json={"name": "viewer", "expires_in_hours": 1}).json()["access_token"]
    assert client.get("/api/v1/ai/openrouter/setup", headers={"Authorization": "Bearer " + raw}).status_code == 403


@pytest.mark.parametrize("qwen", [False, True])
def test_both_model_runtimes_use_managed_approval_key_and_schema_parameters(client, managed_key, provider_network, qwen):
    from pydantic import BaseModel
    from icheck.models import Investigation
    from icheck.langgraph_runtime import initial_graph_state
    from icheck.services.model_reasoner import OpenAICompatibleReasoner
    from icheck.services.structured_model import OpenAICompatibleStructuredGenerator
    from test_model_fallback import FakeChatResponse
    connected = connect(client)
    assert configure(client, connected).status_code == 200
    created = client.post("/api/v1/agent/investigations", json={
        "title": "Managed model request", "objective": "Read-only fixture", "route_purpose": "investigation", "created_by": "l1.operator",
    })
    assert created.status_code == 201, created.text
    assert client.post(f"/api/v1/agent/investigations/{created.json()['id']}/start", json={"actor": "l1.operator"}).status_code == 200
    worker = client.post("/api/v1/agent/workers/register", headers={"X-iCheck-Registration-Token": "test-agent-registration-token"},
        json={"name": "managed-model-fixture", "capabilities": ["openai_compatible"]}).json()
    claim = client.post(f"/api/v1/agent/workers/{worker['worker']['id']}/executions/claim",
        headers={"Authorization": "Bearer " + worker["access_token"]}, json={"max_assignments": 1, "lease_seconds": 60})
    assert claim.status_code == 200 and claim.json()[0]["investigation_id"] == created.json()["id"]
    requests = []

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            assert request.full_url == BASE + "/chat/completions"
            assert request.get_header("Authorization") == "Bearer " + KEY
            payload = json.loads(request.data)
            assert payload["provider"] == {"require_parameters": True}
            assert payload["response_format"]["type"] == "json_schema"
            assert payload["response_format"]["json_schema"]["strict"] is (qwen or len(requests) == 2)
            content = {"action": "complete", "plan": ["Read-only fixture"], "confidence": 0.8, "conclusion": "Fixture complete"} if len(requests) == 1 else {"answer": "Fixture answer"}
            return FakeChatResponse({"choices": [{"message": {"content": json.dumps(content)}}], "usage": {"total_tokens": 12}})

    class Document(BaseModel):
        answer: str

    with namespace_session() as db:
        if qwen:
            db.scalar(select(AIModelConfig)).model_name = "qwen/qwen3.8-max-0902"
            db.commit()
        investigation = db.get(Investigation, created.json()["id"])
        state = initial_graph_state(investigation_id=investigation.id, objective=investigation.objective,
            scope=investigation.scope, max_iterations=investigation.max_iterations,
            max_tool_calls=investigation.max_tool_calls, token_budget=investigation.token_budget)
        assert OpenAICompatibleReasoner(db, investigation, opener=Opener())(state).action == "complete"
        result = OpenAICompatibleStructuredGenerator(db, opener=Opener()).generate(
            route_purpose="capability.authoring", response_model=Document, schema_name="fixture",
            system_prompt="Read-only fixture", prompt_document={"goal": "Fixture"}, entity_type="fixture", entity_id="fixture", actor_id="test-admin")
        assert result.document.answer == "Fixture answer"
    assert len(requests) == 2
    assert KEY not in client.get("/api/v1/audit-events").text
