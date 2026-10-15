import json
from urllib.error import URLError

import pytest
from sqlalchemy import select

from icheck.database import SessionLocal
from icheck.langgraph_runtime import initial_graph_state
from icheck.models import AIModelRoute, AIProviderConfig, AuditEvent, Investigation
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


class FallbackChatOpener:
    def __init__(self, primary_failure):
        self.requests = []
        self.primary_failure = primary_failure

    def open(self, request, timeout):
        payload = json.loads(request.data)
        self.requests.append((request.full_url, payload["model"], timeout))
        if payload["model"] == "primary-reasoner":
            if self.primary_failure == "invalid_decision":
                return FakeChatResponse(
                    {
                        "choices": [
                            {"message": {"content": "not-valid-decision-json"}}
                        ],
                        "usage": {"total_tokens": 11},
                    }
                )
            raise URLError("primary endpoint intentionally unavailable")
        assert payload["model"] == "fallback-reasoner"
        return FakeChatResponse(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "action": "complete",
                                    "plan": ["Use the available fallback model"],
                                    "confidence": 0.82,
                                    "conclusion": "The fallback route completed.",
                                    "uncertainty": [
                                        "The primary provider was unavailable."
                                    ],
                                }
                            )
                        }
                    }
                ],
                "usage": {"total_tokens": 37},
            }
        )


def _provider(client, name, path):
    response = client.post(
        "/api/v1/ai/providers",
        json={
            "name": name,
            "provider_type": "openai_compatible",
            "base_url": f"https://models.example.test/{path}",
            "auth_type": "none",
            "created_by": "platform.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _model(client, provider_id, display_name, model_name):
    response = client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": provider_id,
            "display_name": display_name,
            "model_name": model_name,
            "capabilities": ["chat", "tools", "json_schema"],
            "created_by": "platform.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.parametrize(
    ("primary_failure", "disable_primary", "expected_tokens", "expected_error"),
    [
        ("transport", False, 37, "AI provider request failed"),
        ("disabled", True, 37, "AI provider candidate is unavailable"),
        (
            "invalid_decision",
            False,
            48,
            "AI provider returned an invalid graph decision",
        ),
    ],
)
def test_investigation_snapshots_and_executes_ordered_model_fallback(
    client,
    primary_failure,
    disable_primary,
    expected_tokens,
    expected_error,
):
    primary_provider = _provider(client, "primary-fallback-test", "primary/v1")
    fallback_provider = _provider(client, "secondary-fallback-test", "fallback/v1")
    primary_model = _model(
        client,
        primary_provider["id"],
        "Primary fallback test model",
        "primary-reasoner",
    )
    fallback_model = _model(
        client,
        fallback_provider["id"],
        "Secondary fallback test model",
        "fallback-reasoner",
    )
    route = client.post(
        "/api/v1/ai/routes",
        json={
            "purpose": "investigation",
            "primary_model_id": primary_model["id"],
            "fallback_model_ids": [fallback_model["id"]],
            "max_iterations": 3,
            "max_tool_calls": 2,
            "timeout_seconds": 300,
            "token_budget": 1000,
            "created_by": "platform.admin",
        },
    )
    assert route.status_code == 201, route.text

    created = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": "Fallback route test",
            "objective": "Complete through the configured fallback model.",
            "route_purpose": "investigation",
            "created_by": "l1.operator",
        },
    )
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]
    assert created.json()["fallback_model_ids"] == [fallback_model["id"]]
    started = client.post(
        f"/api/v1/agent/investigations/{investigation_id}/start",
        json={"actor": "l1.operator"},
    )
    assert started.status_code == 200, started.text

    with SessionLocal() as db:
        # Route edits after creation must not change this investigation's
        # candidate chain. The production API is create-only, but this mutation
        # proves the persisted investigation snapshot is the runtime authority.
        stored_route = db.get(AIModelRoute, route.json()["id"])
        stored_primary = db.get(AIProviderConfig, primary_provider["id"])
        assert stored_route is not None
        assert stored_primary is not None
        stored_route.fallback_model_ids = []
        if disable_primary:
            stored_primary.enabled = False
        db.commit()

    registration = client.post(
        "/api/v1/agent/workers/register",
        headers={
            "X-iCheck-Registration-Token": "test-agent-registration-token"
        },
        json={
            "name": "fallback-worker",
            "capabilities": ["openai_compatible"],
        },
    )
    assert registration.status_code == 200, registration.text
    claim = client.post(
        f"/api/v1/agent/workers/{registration.json()['worker']['id']}/executions/claim",
        headers={"Authorization": f"Bearer {registration.json()['access_token']}"},
        json={"max_assignments": 1, "lease_seconds": 60},
    )
    assert claim.status_code == 200, claim.text
    assert claim.json()[0]["investigation_id"] == investigation_id

    opener = FallbackChatOpener(primary_failure)
    with SessionLocal() as db:
        investigation = db.get(Investigation, investigation_id)
        assert investigation is not None
        assert investigation.fallback_model_ids == [fallback_model["id"]]
        decision = OpenAICompatibleReasoner(
            db,
            investigation,
            opener=opener,
        )(
            initial_graph_state(
                investigation_id=investigation.id,
                objective=investigation.objective,
                scope=investigation.scope,
                max_iterations=investigation.max_iterations,
                max_tool_calls=investigation.max_tool_calls,
                token_budget=investigation.token_budget,
            )
        )
        attempts = list(
            db.scalars(
                select(AuditEvent).where(
                    AuditEvent.entity_id == investigation_id,
                    AuditEvent.event_type.in_(
                        [
                            "investigation.model.failed",
                            "investigation.model.completed",
                        ]
                    ),
                )
            ).all()
        )

    assert decision.action == "complete"
    assert decision.token_usage == expected_tokens
    assert [item[:2] for item in opener.requests] == (
        [
            (
                "https://models.example.test/fallback/v1/chat/completions",
                "fallback-reasoner",
            )
        ]
        if disable_primary
        else [
            (
                "https://models.example.test/primary/v1/chat/completions",
                "primary-reasoner",
            ),
            (
                "https://models.example.test/fallback/v1/chat/completions",
                "fallback-reasoner",
            ),
        ]
    )
    assert all(0 < item[2] <= 20 for item in opener.requests)
    failed = next(item for item in attempts if item.event_type.endswith("failed"))
    completed = next(
        item for item in attempts if item.event_type.endswith("completed")
    )
    details = dict(failed.details)
    assert 0 <= details.pop("elapsed_seconds") < 30
    if primary_failure == "invalid_decision":
        value = details.pop("diagnostic")
        assert value["code"] == "model_schema_invalid"
        assert value["validation_errors"][0]["rule"] == "invalid_json"
    assert details == {
        "model_id": primary_model["id"],
        "provider_id": primary_provider["id"],
        "iteration": 1,
        "candidate_index": 0,
        "fallback_used": False,
        "error": expected_error,
        "retryable": True,
        "token_usage": 11 if primary_failure == "invalid_decision" else 0,
    }
    assert completed.details["model_id"] == fallback_model["id"]
    assert completed.details["provider_id"] == fallback_provider["id"]
    assert completed.details["candidate_index"] == 1
    assert completed.details["fallback_used"] is True
    assert completed.details["token_usage"] == 37
    assert completed.details["cumulative_token_usage"] == expected_tokens
