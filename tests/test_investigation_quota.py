"""Agent model calls share durable UTC-day admission with structured authoring."""

from uuid import uuid4

import pytest
from sqlalchemy import select

from icheck.config import get_settings
from icheck.database import (
    DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace,
)
from icheck.langgraph_runtime import initial_graph_state
from icheck.models import AIAuthoringQuotaReservation, Investigation
from icheck.services.ai_authoring_quota import (
    AuthoringQuotaConflict,
    AuthoringQuotaExceeded,
    reserve_authoring_tokens,
)
from icheck.services.model_reasoner import (
    ModelReasonerUnavailable,
    OpenAICompatibleReasoner,
)
from test_model_fallback import FallbackChatOpener, _model, _provider


def _investigation(client, *, fallback: bool, budget: int = 100) -> str:
    primary_provider = _provider(client, "quota-primary", "quota-primary/v1")
    primary = _model(
        client, primary_provider["id"], "Quota primary", "primary-reasoner",
    )
    fallback_ids = []
    if fallback:
        fallback_provider = _provider(client, "quota-fallback", "quota-fallback/v1")
        secondary = _model(
            client, fallback_provider["id"], "Quota fallback", "fallback-reasoner",
        )
        fallback_ids = [secondary["id"]]
    route = client.post("/api/v1/ai/routes", json={
        "purpose": "investigation", "primary_model_id": primary["id"],
        "fallback_model_ids": fallback_ids, "max_iterations": 3,
        "max_tool_calls": 2, "timeout_seconds": 300,
        "token_budget": budget, "created_by": "platform.admin",
    })
    assert route.status_code == 201, route.text
    created = client.post("/api/v1/agent/investigations", json={
        "title": "Quota-controlled investigation",
        "objective": "Review the current device state through the model route.",
        "route_purpose": "investigation", "created_by": "l1.operator",
    })
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]
    started = client.post(
        f"/api/v1/agent/investigations/{investigation_id}/start",
        json={"actor": "l1.operator"},
    )
    assert started.status_code == 200, started.text
    return investigation_id


def _limit(client, tokens: int) -> None:
    response = client.put("/api/v1/ai/authoring-quota", json={
        "expected_revision": 1, "daily_token_limit": tokens,
        "actor_daily_token_limit": tokens,
        "reason": "Bound Agent and structured authoring model calls together.",
    })
    assert response.status_code == 200, response.text


def _reasoner(db, investigation_id: str, opener):
    investigation = db.get(Investigation, investigation_id)
    assert investigation is not None
    reasoner = OpenAICompatibleReasoner(db, investigation, opener=opener)
    state = initial_graph_state(
        investigation_id=investigation.id, objective=investigation.objective,
        scope=investigation.scope, max_iterations=investigation.max_iterations,
        max_tool_calls=investigation.max_tool_calls,
        token_budget=investigation.token_budget,
    )
    return reasoner, state


def test_investigation_quota_denies_before_provider_io(client):
    investigation_id = _investigation(client, fallback=False)
    _limit(client, 99)
    opener = FallbackChatOpener("transport")
    with SessionLocal() as db:
        reasoner, state = _reasoner(db, investigation_id, opener)
        with pytest.raises(AuthoringQuotaExceeded):
            reasoner(state)
    assert opener.requests == []
    snapshot = client.get(
        "/api/v1/ai/authoring-quota", params={"actor": "l1.operator"},
    ).json()
    assert snapshot["actor_used"] == 0


def test_known_fallback_usage_releases_unused_investigation_reservation(client):
    investigation_id = _investigation(client, fallback=True)
    _limit(client, 100)
    opener = FallbackChatOpener("invalid_decision")
    with SessionLocal() as db:
        reasoner, state = _reasoner(db, investigation_id, opener)
        decision = reasoner(state)
        rows = db.scalars(select(AIAuthoringQuotaReservation)).all()
        assert len(rows) == 1
        assert rows[0].entity_type == "investigation_step"
        assert rows[0].source_entity_type == "investigation"
        assert rows[0].source_entity_id == investigation_id
        assert rows[0].source_step == 0
        assert rows[0].status == "settled"
        assert rows[0].reserved_tokens == 100
        assert rows[0].known_tokens == 48
        assert rows[0].charged_tokens == 48
        assert rows[0].external_charge_unknown is False
        with pytest.raises(AuthoringQuotaConflict):
            reasoner(state)
    assert decision.token_usage == 48
    assert len(opener.requests) == 2
    snapshot = client.get(
        "/api/v1/ai/authoring-quota", params={"actor": "l1.operator"},
    ).json()
    assert snapshot["actor_used"] == 48
    assert snapshot["actor_available"] == 52


def test_uncertain_primary_charge_remains_held_after_successful_fallback(client):
    investigation_id = _investigation(client, fallback=True)
    _limit(client, 100)
    opener = FallbackChatOpener("transport")
    with SessionLocal() as db:
        reasoner, state = _reasoner(db, investigation_id, opener)
        decision = reasoner(state)
        receipt = db.scalar(select(AIAuthoringQuotaReservation))
        assert receipt is not None
        assert receipt.known_tokens == 37
        assert receipt.charged_tokens == 100
        assert receipt.external_charge_unknown is True
    assert decision.token_usage == 37
    assert len(opener.requests) == 2
    snapshot = client.get(
        "/api/v1/ai/authoring-quota", params={"actor": "l1.operator"},
    ).json()
    assert snapshot["actor_used"] == 100
    assert snapshot["unknown_charge_requests"] == 1


def test_failed_investigation_model_call_keeps_uncertain_charge(client):
    investigation_id = _investigation(client, fallback=False)
    _limit(client, 100)
    opener = FallbackChatOpener("transport")
    with SessionLocal() as db:
        reasoner, state = _reasoner(db, investigation_id, opener)
        with pytest.raises(ModelReasonerUnavailable) as failure:
            reasoner(state)
        assert failure.value.token_usage == 0
        assert failure.value.external_charge_unknown is True
        receipt = db.scalar(select(AIAuthoringQuotaReservation))
        assert receipt is not None
        assert receipt.status == "settled"
        assert receipt.charged_tokens == 100
    assert len(opener.requests) == 1


def test_investigation_only_operator_can_read_but_not_change_shared_quota(
    client, monkeypatch,
):
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    try:
        boot = client.post(
            "/api/v1/auth/bootstrap",
            headers={"X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token"},
            json={"subject": "admin@example.test", "display_name": "Admin"},
        )
        assert boot.status_code == 201, boot.text
        admin = {"Authorization": f"Bearer {boot.json()['token']['access_token']}"}
        role = client.post("/api/v1/auth/roles", headers=admin, json={
            "name": "investigation-quota-reader",
            "description": "May launch investigations but not author or administer AI.",
            "permissions": ["investigations.create"],
        })
        assert role.status_code == 201, role.text
        principal = client.post("/api/v1/auth/principals", headers=admin, json={
            "subject": "investigator@example.test", "display_name": "Investigator",
        })
        assert principal.status_code == 201, principal.text
        principal_id = principal.json()["id"]
        binding = client.post(
            f"/api/v1/auth/principals/{principal_id}/bindings", headers=admin,
            json={"role_id": role.json()["id"], "scope": {"all": True}},
        )
        assert binding.status_code == 201, binding.text
        issued = client.post(
            f"/api/v1/auth/principals/{principal_id}/tokens", headers=admin,
            json={"name": "quota-reader", "expires_in_hours": 24},
        )
        assert issued.status_code == 201, issued.text
        operator = {"Authorization": f"Bearer {issued.json()['access_token']}"}
        with SessionLocal() as db:
            set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
            admin_receipt = reserve_authoring_tokens(
                db, actor="admin@example.test", entity_type="test_ai_call",
                entity_id=str(uuid4()), token_budget=100,
            )
        own = client.get(
            "/api/v1/ai/authoring-quota", headers=operator,
            params={"actor": "admin@example.test"},
        )
        assert own.status_code == 200, own.text
        assert own.json()["actor"] == "investigator@example.test"
        own_receipts = client.get(
            "/api/v1/ai/authoring-quota/reservations", headers=operator,
            params={"actor": "admin@example.test", "scope": "mine", "state": "all"},
        )
        assert own_receipts.status_code == 200, own_receipts.text
        assert own_receipts.json()["items"] == []
        assert client.get(
            "/api/v1/ai/authoring-quota/reservations", headers=operator,
            params={"scope": "namespace"},
        ).status_code == 403
        admin_receipts = client.get(
            "/api/v1/ai/authoring-quota/reservations", headers=admin,
            params={"scope": "namespace", "state": "all"},
        )
        assert admin_receipts.status_code == 200, admin_receipts.text
        assert [item["id"] for item in admin_receipts.json()["items"]] == [admin_receipt]
        assert client.put(
            "/api/v1/ai/authoring-quota", headers=operator,
            json={"expected_revision": 1, "daily_token_limit": 1000,
                  "actor_daily_token_limit": 100,
                  "reason": "Attempt to change someone else's quota."},
        ).status_code == 403
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()
