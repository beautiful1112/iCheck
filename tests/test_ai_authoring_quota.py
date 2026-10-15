"""Durable admission quotas shared by activation and Studio authoring."""

from urllib.error import URLError
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from icheck.config import get_settings
from icheck.database import (
    DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace,
)
from icheck.models import AIModelRoute, AIAuthoringQuotaReservation
from icheck.services import ai_authoring_quota as quota_service
from icheck.sandbox import HardenedProcessSandboxExecutor
from icheck.services.structured_model import OpenAICompatibleStructuredGenerator
from test_activation_policy_proposals import (
    _published_http_artifact,
    _request,
    _suggestion,
)
from test_capability_studio import (
    FIRST_SPEC,
    FakeStructuredOpener,
    configure_authoring_route,
    studio_payload,
)


def _route_budget(route_id: str, amount: int) -> None:
    with SessionLocal() as db:
        row = db.get(AIModelRoute, route_id)
        row.token_budget = amount
        db.commit()


def _configure_quota(client, *, namespace: int | None, actor: int | None):
    response = client.put(
        "/api/v1/ai/authoring-quota",
        json={
            "expected_revision": 1,
            "daily_token_limit": namespace,
            "actor_daily_token_limit": actor,
            "reason": "Set a controlled daily authoring admission budget.",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_known_usage_releases_unused_reservation_before_next_request(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    route, _ = configure_authoring_route(client)
    _route_budget(route["id"], 100)
    policy = _configure_quota(client, namespace=142, actor=142)
    assert policy["policy_revision"] == 2
    opener = FakeStructuredOpener([
        _suggestion().model_dump(mode="json"),
        _suggestion().model_dump(mode="json"),
    ])
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda db: OpenAICompatibleStructuredGenerator(db, opener=opener),
    )
    payload = {**_request(version_id), "actor": "development"}
    first = client.post("/api/v1/assets/activation-policy-proposals", json=payload)
    assert first.status_code == 200, first.text
    after_first = client.get("/api/v1/ai/authoring-quota").json()
    assert after_first["actor"] == "development"
    assert after_first["actor_used"] == 42
    assert after_first["namespace_used"] == 42
    assert after_first["actor_available"] == 100
    second = client.post("/api/v1/assets/activation-policy-proposals", json=payload)
    assert second.status_code == 200, second.text
    after_second = client.get("/api/v1/ai/authoring-quota").json()
    assert after_second["actor_used"] == 84
    denied = client.post("/api/v1/assets/activation-policy-proposals", json=payload)
    assert denied.status_code == 429, denied.text
    assert len(opener.requests) == 2
    assert client.get("/api/v1/ai/authoring-quota").json()["actor_used"] == 84
    audits = client.get(
        "/api/v1/audit-events", params={"event_type": "ai.authoring_quota.denied"},
    ).json()
    assert len(audits) == 1
    assert audits[0]["details"]["requested_tokens"] == 100
    assert audits[0]["details"]["scope"] == "namespace"


def test_uncertain_external_charge_keeps_daily_reservation(client, monkeypatch):
    version_id = _published_http_artifact(client)
    route, _ = configure_authoring_route(client)
    _route_budget(route["id"], 100)
    _configure_quota(client, namespace=100, actor=100)

    class UncertainOpener:
        def __init__(self):
            self.calls = 0

        def open(self, request, timeout):
            self.calls += 1
            raise URLError("Synthetic provider timeout")

    opener = UncertainOpener()
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda db: OpenAICompatibleStructuredGenerator(db, opener=opener),
    )
    payload = {**_request(version_id), "actor": "development"}
    failed = client.post("/api/v1/assets/activation-policy-proposals", json=payload)
    assert failed.status_code == 503, failed.text
    snapshot = client.get("/api/v1/ai/authoring-quota").json()
    assert snapshot["actor_used"] == 100
    assert snapshot["actor_available"] == 0
    assert snapshot["unknown_charge_requests"] == 1
    denied = client.post("/api/v1/assets/activation-policy-proposals", json=payload)
    assert denied.status_code == 429, denied.text
    assert opener.calls == 1
    with SessionLocal() as db:
        rows = db.query(AIAuthoringQuotaReservation).all()
        assert len(rows) == 1
        assert rows[0].known_tokens == 0
        assert rows[0].charged_tokens == 100
        assert rows[0].external_charge_unknown is True


def test_custom_studio_route_cannot_bypass_shared_authoring_quota(
    client, monkeypatch,
):
    route, model = configure_authoring_route(client)
    custom = client.post("/api/v1/ai/routes", json={
        "purpose": "studio.custom",
        "primary_model_id": model["id"],
        "timeout_seconds": 15,
        "token_budget": 100,
        "created_by": "platform.admin",
    })
    assert custom.status_code == 201, custom.text
    _configure_quota(client, namespace=100, actor=100)
    opener = FakeStructuredOpener([FIRST_SPEC])
    monkeypatch.setattr("icheck.services.structured_model.build_opener", lambda *_: opener)
    monkeypatch.setattr(
        "icheck.services.collectors.default_sandbox_executor",
        lambda: HardenedProcessSandboxExecutor(python_path="/usr/bin/python3"),
    )
    payload = {**studio_payload(), "route_purpose": "studio.custom"}
    first = client.post("/api/v1/capability-studio/sessions", json=payload)
    assert first.status_code == 201, first.text
    generated = client.post(
        f"/api/v1/capability-studio/sessions/{first.json()['id']}/generate",
        json={"actor": "capability.author"},
    )
    assert generated.status_code == 200, generated.text
    second = client.post("/api/v1/capability-studio/sessions", json=payload)
    assert second.status_code == 201, second.text
    denied = client.post(
        f"/api/v1/capability-studio/sessions/{second.json()['id']}/generate",
        json={"actor": "capability.author"},
    )
    assert denied.status_code == 429, denied.text
    assert len(opener.requests) == 1
    failed = client.get(
        f"/api/v1/capability-studio/sessions/{second.json()['id']}"
    ).json()
    assert failed["status"] == "failed"
    assert failed["tokens_used"] == 0


def test_operator_can_view_own_quota_but_not_configure_it(client, monkeypatch):
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
        role = next(
            item for item in client.get("/api/v1/auth/roles", headers=admin).json()
            if item["name"] == "operator"
        )
        principal = client.post(
            "/api/v1/auth/principals", headers=admin,
            json={"subject": "operator@example.test", "display_name": "Operator"},
        )
        assert principal.status_code == 201, principal.text
        principal_id = principal.json()["id"]
        binding = client.post(
            f"/api/v1/auth/principals/{principal_id}/bindings", headers=admin,
            json={"role_id": role["id"], "scope": {"sites": ["LAB"]}},
        )
        assert binding.status_code == 201, binding.text
        token = client.post(
            f"/api/v1/auth/principals/{principal_id}/tokens", headers=admin,
            json={"name": "quota-test", "expires_in_hours": 24},
        )
        assert token.status_code == 201, token.text
        operator = {"Authorization": f"Bearer {token.json()['access_token']}"}
        snapshot = client.get("/api/v1/ai/authoring-quota", headers=operator)
        assert snapshot.status_code == 200, snapshot.text
        assert snapshot.json()["actor"] == "operator@example.test"
        spoofed = client.get(
            "/api/v1/ai/authoring-quota", headers=operator,
            params={"actor": "admin@example.test"},
        )
        assert spoofed.status_code == 200
        assert spoofed.json()["actor"] == "operator@example.test"
        action = {
            "expected_revision": 1, "daily_token_limit": 10000,
            "actor_daily_token_limit": 1000,
            "reason": "Set a controlled authoring quota policy.",
        }
        assert client.put(
            "/api/v1/ai/authoring-quota", headers=operator, json=action,
        ).status_code == 403
        updated = client.put(
            "/api/v1/ai/authoring-quota", headers=admin, json=action,
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["policy_revision"] == 2
        stale = client.put(
            "/api/v1/ai/authoring-quota", headers=admin, json=action,
        )
        assert stale.status_code == 409
        own = client.get("/api/v1/ai/authoring-quota", headers=operator).json()
        assert own["actor_limit"] == 1000
        assert own["policy_revision"] == 2
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()


def test_utc_day_rollover_and_idempotent_settlement_keep_old_hold(
    monkeypatch,
):
    clock = [datetime(2026, 10, 4, 23, 59, tzinfo=UTC)]
    monkeypatch.setattr(quota_service, "_utc_now", lambda _db: clock[0])
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        quota_service.configure_authoring_quota(
            db, actor="admin@example.test", expected_revision=1,
            daily_token_limit=100, actor_daily_token_limit=100,
            reason="Enforce one reserved authoring budget per UTC day.",
        )
        old = quota_service.reserve_authoring_tokens(
            db, actor="operator@example.test", entity_type="test_authoring",
            entity_id=str(uuid4()), token_budget=100,
        )
        first = quota_service.authoring_quota_snapshot(db, actor="operator@example.test")
        assert first["period_start"].isoformat() == "2026-10-04"
        assert first["actor_used"] == 100
        assert first["pending_requests"] == 1
        clock[0] += timedelta(minutes=2)
        new = quota_service.reserve_authoring_tokens(
            db, actor="operator@example.test", entity_type="test_authoring",
            entity_id=str(uuid4()), token_budget=100,
        )
        quota_service.settle_authoring_tokens(
            db, new, known_tokens=20, external_charge_unknown=False,
        )
        quota_service.settle_authoring_tokens(
            db, new, known_tokens=20, external_charge_unknown=False,
        )
        second = quota_service.authoring_quota_snapshot(db, actor="operator@example.test")
        assert second["period_start"].isoformat() == "2026-10-05"
        assert second["actor_used"] == 20
        assert second["pending_requests"] == 0
        clock[0] -= timedelta(minutes=2)
        original = quota_service.authoring_quota_snapshot(db, actor="operator@example.test")
        assert original["actor_used"] == 100
        assert original["pending_requests"] == 1
        assert old != new


def test_quota_rows_are_namespace_local(monkeypatch):
    clock = datetime(2026, 10, 4, 12, tzinfo=UTC)
    monkeypatch.setattr(quota_service, "_utc_now", lambda _db: clock)
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        quota_service.reserve_authoring_tokens(
            db, actor="shared@example.test", entity_type="test_authoring",
            entity_id=str(uuid4()), token_budget=100,
        )
    with SessionLocal() as db:
        set_session_namespace(db, "other-tenant", "other-region")
        other = quota_service.authoring_quota_snapshot(db, actor="shared@example.test")
        assert other["actor_used"] == 0
        assert other["namespace_used"] == 0
        quota_service.reserve_authoring_tokens(
            db, actor="shared@example.test", entity_type="test_authoring",
            entity_id=str(uuid4()), token_budget=50,
        )
        assert quota_service.authoring_quota_snapshot(
            db, actor="shared@example.test",
        )["actor_used"] == 50
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        assert quota_service.authoring_quota_snapshot(
            db, actor="shared@example.test",
        )["actor_used"] == 100
