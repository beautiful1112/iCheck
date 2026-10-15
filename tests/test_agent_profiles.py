from __future__ import annotations

import pytest

from icheck.database import SessionLocal
from icheck.models import Investigation
from icheck.services.agent_tools import INTERNAL_HANDLERS
from icheck.services.model_reasoner import OpenAICompatibleReasoner


def _configure_private_route(client) -> tuple[dict, dict, dict]:
    provider = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "private-hkg-agent-gateway",
            "provider_type": "openai_compatible",
            "base_url": "https://models.example.test/v1",
            "auth_type": "none",
            "privacy_tier": "private",
            "data_residency": "hkg",
            "created_by": "platform.admin",
        },
    )
    assert provider.status_code == 201, provider.text
    model = client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": provider.json()["id"],
            "display_name": "Private low-cost reasoner",
            "model_name": "private-low-reasoner",
            "capabilities": ["chat", "tools", "json_schema"],
            "cost_class": "low",
            "created_by": "platform.admin",
        },
    )
    assert model.status_code == 201, model.text
    route = client.post(
        "/api/v1/ai/routes",
        json={
            "purpose": "investigation",
            "primary_model_id": model.json()["id"],
            "max_iterations": 12,
            "max_tool_calls": 30,
            "timeout_seconds": 600,
            "token_budget": 100000,
            "created_by": "platform.admin",
        },
    )
    assert route.status_code == 201, route.text
    return provider.json(), model.json(), route.json()


def _register_tool(client, name: str) -> dict:
    response = client.post(
        "/api/v1/agent/tools",
        json={
            "name": name,
            "description": f"AgentProfile acceptance Tool {name}",
            "transport": "internal",
            "handler": name,
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            "output_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"ok": {"type": "boolean"}},
            },
            "risk_level": "observe",
            "read_only": True,
            "required_permissions": [],
            "created_by": "platform.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_agent_profile_enforces_model_policy_and_freezes_runtime(client, monkeypatch):
    provider, model, _route = _configure_private_route(client)
    assert provider["privacy_tier"] == "private"
    assert provider["data_residency"] == "hkg"
    assert model["cost_class"] == "low"

    default_profiles = client.get("/api/v1/ai/agent-profiles")
    assert default_profiles.status_code == 200, default_profiles.text
    assert [item["name"] for item in default_profiles.json()] == ["l1-operator"]

    rejected = client.post(
        "/api/v1/ai/agent-profiles",
        json={
            "name": "local-only-operator",
            "description": "Must never leave a local inference boundary.",
            "role_instructions": "Diagnose only from authorized evidence.",
            "route_purpose": "investigation",
            "minimum_provider_privacy": "local",
            "allowed_data_residencies": ["hkg"],
            "allowed_model_cost_classes": ["low"],
            "created_by": "platform.admin",
        },
    )
    assert rejected.status_code == 422, rejected.text
    assert "does not meet AgentProfile privacy tier" in rejected.text

    _register_tool(client, "profile.allowed")
    _register_tool(client, "profile.denied")
    monkeypatch.setitem(
        INTERNAL_HANDLERS,
        "profile.allowed",
        lambda _db, _arguments: ({"ok": True}, []),
    )
    monkeypatch.setitem(
        INTERNAL_HANDLERS,
        "profile.denied",
        lambda _db, _arguments: ({"ok": True}, []),
    )
    created = client.post(
        "/api/v1/ai/agent-profiles",
        json={
            "name": "private-l1",
            "description": "Private low-cost L1 operator.",
            "role_instructions": "Prefer observation and cite every conclusion.",
            "escalation_instructions": "Escalate when the allowed Tool is insufficient.",
            "route_purpose": "investigation",
            "tool_policy": "allowlist",
            "allowed_tool_names": ["profile.allowed"],
            "minimum_provider_privacy": "private",
            "allowed_data_residencies": ["hkg"],
            "allowed_model_cost_classes": ["low"],
            "max_iterations": 4,
            "max_tool_calls": 5,
            "timeout_seconds": 120,
            "token_budget": 8000,
            "created_by": "platform.admin",
        },
    )
    assert created.status_code == 201, created.text
    profile = created.json()
    assert profile["revision"] == 1

    investigation = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": "Profile-bound private investigation",
            "objective": "Use only the bounded private L1 policy.",
            "route_purpose": "investigation",
            "agent_profile": profile["name"],
            "created_by": "l1.operator",
        },
    )
    assert investigation.status_code == 201, investigation.text
    document = investigation.json()
    assert document["agent_profile_id"] == profile["id"]
    assert document["agent_profile_snapshot"]["revision"] == 1
    assert document["max_iterations"] == 4
    assert document["max_tool_calls"] == 5
    assert document["timeout_seconds"] == 120
    assert document["token_budget"] == 8000
    started = client.post(
        f"/api/v1/agent/investigations/{document['id']}/start",
        json={"actor": "l1.operator"},
    )
    assert started.status_code == 200, started.text

    with SessionLocal() as db:
        stored = db.get(Investigation, document["id"])
        assert stored is not None
        reasoner = OpenAICompatibleReasoner(db, stored)
        assert [item["name"] for item in reasoner.tool_catalog] == [
            "profile.allowed"
        ]
        assert reasoner.profile_snapshot is not None
        assert reasoner.profile_snapshot["role_instructions"].startswith(
            "Prefer observation"
        )

    updated_payload = {
        **{
            key: profile[key]
            for key in (
                "name",
                "description",
                "role_instructions",
                "escalation_instructions",
                "route_purpose",
                "tool_policy",
                "allowed_tool_names",
                "minimum_provider_privacy",
                "allowed_data_residencies",
                "allowed_model_cost_classes",
                "max_iterations",
                "max_tool_calls",
                "timeout_seconds",
                "token_budget",
                "enabled",
            )
        },
        "expected_revision": profile["revision"],
        "reason": "Tighten the bounded L1 iteration budget.",
        "actor": "platform.admin",
        "max_iterations": 3,
    }
    updated = client.put(
        f"/api/v1/ai/agent-profiles/{profile['id']}",
        json=updated_payload,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["revision"] == 2

    stale = client.put(
        f"/api/v1/ai/agent-profiles/{profile['id']}",
        json=updated_payload,
    )
    assert stale.status_code == 409, stale.text

    with SessionLocal() as db:
        stored = db.get(Investigation, document["id"])
        assert stored is not None
        with pytest.raises(ValueError, match="AgentProfile has drifted"):
            OpenAICompatibleReasoner(db, stored)

    audits = client.get(
        "/api/v1/audit-events",
        params={"entity_type": "agent_profile"},
    )
    assert audits.status_code == 200, audits.text
    assert {item["event_type"] for item in audits.json()} == {
        "ai.agent_profile.created",
        "ai.agent_profile.updated",
    }
