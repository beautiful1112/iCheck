import json


class FakeModelListResponse:
    def __init__(self):
        self.body = json.dumps(
            {
                "object": "list",
                "data": [
                    {"id": "ops-reasoner", "object": "model"},
                    {"id": "fast-summarizer", "object": "model"},
                ],
            }
        ).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, limit):
        return self.body[:limit]


class FakeAIProviderOpener:
    def __init__(self, requests):
        self.requests = requests

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        assert request.full_url == "https://models.example.test/v1/models"
        assert request.get_header("Authorization") == (
            "Bearer unit-test-provider-token"
        )
        assert timeout == 12
        return FakeModelListResponse()


def create_ai_credential(client, *, name="ai-runtime-token", secret_ref=None):
    response = client.post(
        "/api/v1/credential-profiles",
        json={
            "name": name,
            "provider": "environment",
            "secret_ref": secret_ref or "env://ICHECK_TEST_AI_PROVIDER_TOKEN",
            "allowed_adapters": ["ai_provider"],
            "created_by": "platform.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def create_ai_provider(client, *, credential_ref="ai-runtime-token"):
    response = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "primary-ai-gateway",
            "provider_type": "openai_compatible",
            "base_url": "https://models.example.test/v1/",
            "auth_type": "bearer",
            "credential_profile_ref": credential_ref,
            "request_timeout_seconds": 12,
            "created_by": "platform.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_ai_provider_model_route_health_and_audit(client, monkeypatch):
    requests = []
    monkeypatch.setattr(
        "icheck.services.ai_settings.build_opener",
        lambda *handlers: FakeAIProviderOpener(requests),
    )
    credential = create_ai_credential(client)
    provider = create_ai_provider(client, credential_ref=credential["name"])
    assert provider["base_url"] == "https://models.example.test/v1"
    assert "token" not in provider

    health = client.post(
        f"/api/v1/ai/providers/{provider['id']}/health",
        params={"actor": "platform.admin"},
    )
    assert health.status_code == 200, health.text
    assert health.json()["status"] == "healthy"
    assert health.json()["model_count"] == 2
    assert len(requests) == 1

    model = client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": provider["id"],
            "display_name": "Operations reasoner",
            "model_name": "ops-reasoner",
            "capabilities": ["chat", "tools", "json_schema", "tools"],
            "context_window": 128000,
            "max_output_tokens": 16384,
            "default_parameters": {"temperature": 0.1},
            "created_by": "platform.admin",
        },
    )
    assert model.status_code == 201, model.text
    assert model.json()["capabilities"] == ["chat", "tools", "json_schema"]

    route = client.post(
        "/api/v1/ai/routes",
        json={
            "purpose": "investigation",
            "primary_model_id": model.json()["id"],
            "max_iterations": 8,
            "max_tool_calls": 20,
            "timeout_seconds": 300,
            "token_budget": 50000,
            "created_by": "platform.admin",
        },
    )
    assert route.status_code == 201, route.text
    assert route.json()["purpose"] == "investigation"
    assert route.json()["max_iterations"] == 8

    assert len(client.get("/api/v1/ai/providers").json()) == 1
    assert len(client.get("/api/v1/ai/models").json()) == 1
    assert len(client.get("/api/v1/ai/routes").json()) == 1

    audits = client.get(
        "/api/v1/audit-events",
        params={"entity_type": "ai_provider"},
    ).json()
    assert {item["event_type"] for item in audits} == {
        "ai.provider.created",
        "ai.provider.health_checked",
    }
    assert "unit-test-provider-token" not in json.dumps(audits)


def test_ai_settings_reject_inline_secrets_and_unapproved_hosts(client):
    create_ai_credential(client)
    inline_token = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "unsafe-inline-token",
            "provider_type": "openai_compatible",
            "base_url": "https://models.example.test/v1",
            "auth_type": "bearer",
            "credential_profile_ref": "ai-runtime-token",
            "token": "must-not-be-accepted",
            "created_by": "platform.admin",
        },
    )
    assert inline_token.status_code == 422
    assert "extra_forbidden" in inline_token.text

    unsafe_host = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "metadata-service",
            "provider_type": "openai_compatible",
            "base_url": "http://169.254.169.254/latest",
            "auth_type": "none",
            "created_by": "platform.admin",
        },
    )
    assert unsafe_host.status_code == 422
    assert "AI provider allowlist" in unsafe_host.text

    provider = create_ai_provider(client)
    inline_default = client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": provider["id"],
            "display_name": "Unsafe model defaults",
            "model_name": "unsafe-model",
            "default_parameters": {"api_key": "must-not-be-stored"},
            "created_by": "platform.admin",
        },
    )
    assert inline_default.status_code == 422
    assert "inline secret" in inline_default.text


def test_ai_provider_health_fails_closed_when_secret_is_missing(client):
    create_ai_credential(
        client,
        name="missing-ai-token",
        secret_ref="env://ICHECK_MISSING_AI_PROVIDER_TOKEN",
    )
    provider = create_ai_provider(client, credential_ref="missing-ai-token")
    health = client.post(
        f"/api/v1/ai/providers/{provider['id']}/health",
        params={"actor": "platform.admin"},
    )
    assert health.status_code == 200, health.text
    assert health.json()["status"] == "unhealthy"
    assert health.json()["error"] == "Referenced environment secret is unavailable"
