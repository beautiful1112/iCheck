from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from icheck.agent_schemas import InvestigationToolCallCreate
from icheck.builtin_agent_tools import ensure_builtin_agent_tools
from icheck.config import Settings, get_settings
from icheck.database import SessionLocal
from icheck.models import (
    AuditEvent,
    AgentToolRegistration,
    ControlPlaneAccessToken,
    ControlPlaneBrowserSession,
    ControlPlaneRole,
    Investigation,
)
from icheck.services.agent_runtime import create_tool_call
from icheck.services.model_reasoner import OpenAICompatibleReasoner
from icheck.worker_auth import hash_token


BOOTSTRAP_HEADERS = {
    "X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token"
}


def test_production_cannot_disable_control_plane_authentication():
    with pytest.raises(ValueError, match="production requires"):
        Settings(
            environment="production",
            control_plane_auth_mode="disabled",
        )


def test_production_requires_governed_change_contracts():
    with pytest.raises(ValueError, match="GOVERNED_CHANGE_CONTRACTS"):
        Settings(
            environment="production",
            control_plane_auth_mode="required",
            control_plane_session_cookie_secure=True,
            require_governed_change_contracts=False,
        )
    settings = Settings(
        environment="production",
        control_plane_auth_mode="required",
        control_plane_session_cookie_secure=True,
        require_governed_change_contracts=True,
        auto_create_schema=False,
    )
    assert settings.require_governed_change_contracts is True


def test_production_never_initializes_application_schema_at_runtime():
    with pytest.raises(ValueError, match="AUTO_CREATE_SCHEMA=false"):
        Settings(
            environment="production",
            control_plane_auth_mode="required",
            control_plane_session_cookie_secure=True,
            require_governed_change_contracts=True,
            auto_create_schema=True,
        )


def _required_auth(monkeypatch) -> None:
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()


def _restore_disabled_auth(monkeypatch) -> None:
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
    get_settings.cache_clear()


def test_disabled_mode_exposes_explicit_development_principal(client):
    response = client.get("/api/v1/auth/me")

    assert response.status_code == 200
    assert response.json() == {
        "principal_id": None,
        "subject": "development",
        "principal_type": "development",
        "permissions": ["*"],
        "role_names": ["development-admin"],
        "authorization_scope": {"all": True},
        "auth_method": "disabled",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "tenant_slug": "local",
        "region_id": "00000000-0000-0000-0000-000000000002",
        "region_code": "primary",
        "platform_admin": True,
    }


def test_required_mode_bootstrap_rbac_issue_and_revoke(client, monkeypatch):
    _required_auth(monkeypatch)
    try:
        assert client.get("/api/v1/auth/me").status_code == 401
        invalid = client.post(
            "/api/v1/auth/bootstrap",
            headers={"X-Icheck-Bootstrap-Token": "wrong"},
            json={
                "subject": "admin@example.test",
                "display_name": "Initial Admin",
            },
        )
        assert invalid.status_code == 401

        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            headers=BOOTSTRAP_HEADERS,
            json={
                "subject": "admin@example.test",
                "display_name": "Initial Admin",
                "token_name": "acceptance-admin",
                "expires_in_hours": 24,
            },
        )
        assert bootstrap.status_code == 201, bootstrap.text
        body = bootstrap.json()
        admin_token = body["token"]["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        assert admin_token.startswith("icp_")

        with SessionLocal() as db:
            stored = db.scalar(select(ControlPlaneAccessToken))
            assert stored is not None
            assert stored.token_hash == hash_token(admin_token)
            assert stored.token_hash != admin_token

        me = client.get("/api/v1/auth/me", headers=admin_headers)
        assert me.status_code == 200
        assert me.json()["permissions"] == ["*"]
        assert me.json()["authorization_scope"] == {"all": True}

        roles = client.get("/api/v1/auth/roles", headers=admin_headers)
        assert roles.status_code == 200
        viewer_role = next(role for role in roles.json() if role["name"] == "viewer")

        created = client.post(
            "/api/v1/auth/principals",
            headers=admin_headers,
            json={
                "subject": "viewer@example.test",
                "display_name": "Site Viewer",
            },
        )
        assert created.status_code == 201, created.text
        viewer_id = created.json()["id"]

        binding = client.post(
            f"/api/v1/auth/principals/{viewer_id}/bindings",
            headers=admin_headers,
            json={
                "role_id": viewer_role["id"],
                "scope": {"sites": ["Hong Kong"]},
            },
        )
        assert binding.status_code == 201, binding.text

        issued = client.post(
            f"/api/v1/auth/principals/{viewer_id}/tokens",
            headers=admin_headers,
            json={"name": "viewer-acceptance", "expires_in_hours": 24},
        )
        assert issued.status_code == 201, issued.text
        viewer_token = issued.json()["access_token"]
        viewer_token_id = issued.json()["token"]["id"]
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

        viewer_me = client.get("/api/v1/auth/me", headers=viewer_headers)
        assert viewer_me.status_code == 200
        assert "assets.read" in viewer_me.json()["permissions"]
        assert viewer_me.json()["authorization_scope"] == {
            "sites": ["Hong Kong"]
        }
        forbidden = client.post(
            "/api/v1/auth/principals",
            headers=viewer_headers,
            json={"subject": "denied", "display_name": "Denied"},
        )
        assert forbidden.status_code == 403
        assert (
            client.get(
                "/api/v1/mcp/fleet/telemetry",
                headers=viewer_headers,
            ).status_code
            == 403
        )

        revoked = client.post(
            f"/api/v1/auth/tokens/{viewer_token_id}/revoke",
            headers=admin_headers,
            json={"reason": "Acceptance-test revocation"},
        )
        assert revoked.status_code == 200
        assert revoked.json()["revoked_at"] is not None
        assert client.get("/api/v1/auth/me", headers=viewer_headers).status_code == 401

        duplicate = client.post(
            "/api/v1/auth/bootstrap",
            headers=BOOTSTRAP_HEADERS,
            json={
                "subject": "second-admin@example.test",
                "display_name": "Second Admin",
            },
        )
        assert duplicate.status_code == 409

        with SessionLocal() as db:
            audit_document = json.dumps(
                [
                    {"event_type": event.event_type, "details": event.details}
                    for event in db.scalars(select(AuditEvent)).all()
                ]
            )
        assert admin_token not in audit_document
        assert viewer_token not in audit_document
    finally:
        _restore_disabled_auth(monkeypatch)


def test_principal_disable_and_role_revocation_are_immediate_and_audited(
    client,
    monkeypatch,
):
    _required_auth(monkeypatch)
    try:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            headers=BOOTSTRAP_HEADERS,
            json={
                "subject": "lifecycle.admin@example.test",
                "display_name": "Lifecycle Admin",
            },
        )
        assert bootstrap.status_code == 201, bootstrap.text
        admin_id = bootstrap.json()["principal"]["id"]
        admin_token = bootstrap.json()["token"]["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        roles = client.get("/api/v1/auth/roles", headers=admin_headers)
        viewer_role = next(role for role in roles.json() if role["name"] == "viewer")
        principal = client.post(
            "/api/v1/auth/principals",
            headers=admin_headers,
            json={
                "subject": "lifecycle.viewer@example.test",
                "display_name": "Lifecycle Viewer",
            },
        )
        assert principal.status_code == 201, principal.text
        principal_id = principal.json()["id"]
        binding = client.post(
            f"/api/v1/auth/principals/{principal_id}/bindings",
            headers=admin_headers,
            json={"role_id": viewer_role["id"], "scope": {"all": True}},
        )
        assert binding.status_code == 201, binding.text
        binding_id = binding.json()["id"]
        issued = client.post(
            f"/api/v1/auth/principals/{principal_id}/tokens",
            headers=admin_headers,
            json={"name": "lifecycle", "expires_in_hours": 24},
        )
        assert issued.status_code == 201, issued.text
        viewer_token = issued.json()["access_token"]
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
        browser = client.post(
            "/api/v1/auth/browser-sessions",
            headers=viewer_headers,
        )
        assert browser.status_code == 201, browser.text

        removed = client.post(
            f"/api/v1/auth/bindings/{binding_id}/revoke",
            headers=admin_headers,
            json={"reason": "Remove obsolete viewer access."},
        )
        assert removed.status_code == 204, removed.text
        after_binding = client.get("/api/v1/auth/me", headers=viewer_headers)
        assert after_binding.status_code == 200, after_binding.text
        assert after_binding.json()["permissions"] == []
        assert after_binding.json()["authorization_scope"] == {}

        self_bindings = client.get(
            f"/api/v1/auth/principals/{admin_id}/bindings",
            headers=admin_headers,
        )
        assert self_bindings.status_code == 200, self_bindings.text
        self_revoke = client.post(
            f"/api/v1/auth/bindings/{self_bindings.json()[0]['id']}/revoke",
            headers=admin_headers,
            json={"reason": "Unsafe self revocation."},
        )
        assert self_revoke.status_code == 409

        disabled = client.patch(
            f"/api/v1/auth/principals/{principal_id}",
            headers=admin_headers,
            json={"enabled": False, "reason": "Offboarding complete."},
        )
        assert disabled.status_code == 200, disabled.text
        assert disabled.json()["enabled"] is False
        assert client.get("/api/v1/auth/me", headers=viewer_headers).status_code == 401
        denied_issue = client.post(
            f"/api/v1/auth/principals/{principal_id}/tokens",
            headers=admin_headers,
            json={"name": "must-not-issue", "expires_in_hours": 24},
        )
        assert denied_issue.status_code == 409

        with SessionLocal() as db:
            token = db.get(ControlPlaneAccessToken, issued.json()["token"]["id"])
            assert token is not None
            assert token.revoked_at is not None
            assert token.revocation_reason == "principal_disabled"
            session = db.scalar(
                select(ControlPlaneBrowserSession).where(
                    ControlPlaneBrowserSession.principal_id == principal_id
                )
            )
            assert session is not None
            assert session.revoked_at is not None
            assert session.revocation_reason_sha256 == hash_token(
                "Offboarding complete."
            )
            events = {
                event.event_type
                for event in db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id.in_([principal_id, binding_id])
                    )
                ).all()
            }
            assert "auth.principal.updated" in events
            assert "auth.role_binding.revoked" in events

        reenabled = client.patch(
            f"/api/v1/auth/principals/{principal_id}",
            headers=admin_headers,
            json={"enabled": True, "reason": "Account restored after review."},
        )
        assert reenabled.status_code == 200, reenabled.text
        assert reenabled.json()["enabled"] is True
        assert client.get("/api/v1/auth/me", headers=viewer_headers).status_code == 401
        replacement = client.post(
            f"/api/v1/auth/principals/{principal_id}/tokens",
            headers=admin_headers,
            json={"name": "replacement", "expires_in_hours": 24},
        )
        assert replacement.status_code == 201, replacement.text

        self_disable = client.patch(
            f"/api/v1/auth/principals/{admin_id}",
            headers=admin_headers,
            json={"enabled": False, "reason": "Unsafe self disable."},
        )
        assert self_disable.status_code == 409
    finally:
        _restore_disabled_auth(monkeypatch)


def test_browser_session_is_http_only_csrf_protected_and_revocable(
    client,
    monkeypatch,
):
    _required_auth(monkeypatch)
    try:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            headers=BOOTSTRAP_HEADERS,
            json={
                "subject": "browser.admin@example.test",
                "display_name": "Browser Admin",
            },
        )
        bearer = bootstrap.json()["token"]["access_token"]
        issued = client.post(
            "/api/v1/auth/browser-sessions",
            headers={"Authorization": f"Bearer {bearer}"},
        )
        assert issued.status_code == 201, issued.text
        assert issued.json()["principal"]["subject"] == "browser.admin@example.test"
        csrf = issued.json()["csrf_token"]
        cookie = issued.headers["set-cookie"]
        assert "icheck_session=" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie

        me = client.get("/api/v1/auth/me")
        assert me.status_code == 200, me.text
        assert me.json()["auth_method"] == "browser_session"

        missing_csrf = client.post(
            "/api/v1/auth/principals",
            json={"subject": "no.csrf", "display_name": "No CSRF"},
        )
        assert missing_csrf.status_code == 403

        created = client.post(
            "/api/v1/auth/principals",
            headers={"X-Icheck-CSRF-Token": csrf},
            json={
                "subject": "csrf.accepted@example.test",
                "display_name": "CSRF Accepted",
            },
        )
        assert created.status_code == 201, created.text
        assert created.json()["created_by"] == "browser.admin@example.test"

        rotated = client.get("/api/v1/auth/browser-sessions/current/csrf")
        assert rotated.status_code == 200, rotated.text
        next_csrf = rotated.json()["csrf_token"]
        assert next_csrf != csrf
        stale = client.post(
            "/api/v1/auth/principals",
            headers={"X-Icheck-CSRF-Token": csrf},
            json={"subject": "stale.csrf", "display_name": "Stale CSRF"},
        )
        assert stale.status_code == 403

        closed = client.delete(
            "/api/v1/auth/browser-sessions/current",
            headers={"X-Icheck-CSRF-Token": next_csrf},
        )
        assert closed.status_code == 204, closed.text
        assert client.get("/api/v1/auth/me").status_code == 401
    finally:
        _restore_disabled_auth(monkeypatch)


def test_admin_can_list_and_revoke_redacted_browser_session(
    client,
    monkeypatch,
):
    _required_auth(monkeypatch)
    try:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            headers=BOOTSTRAP_HEADERS,
            json={
                "subject": "session.admin@example.test",
                "display_name": "Session Admin",
            },
        )
        bearer = bootstrap.json()["token"]["access_token"]
        admin_headers = {"Authorization": f"Bearer {bearer}"}
        issued = client.post(
            "/api/v1/auth/browser-sessions",
            headers=admin_headers,
        )
        assert issued.status_code == 201, issued.text

        sessions = client.get(
            "/api/v1/auth/browser-sessions",
            params={"active": True},
            headers=admin_headers,
        )
        assert sessions.status_code == 200, sessions.text
        assert len(sessions.json()) == 1
        session = sessions.json()[0]
        assert session["auth_source"] == "local_token"
        assert session["federated_identity_id"] is None
        assert "token_hash" not in session
        assert "csrf_token_hash" not in session

        revoked = client.post(
            f"/api/v1/auth/browser-sessions/{session['id']}/revoke",
            headers=admin_headers,
            json={"reason": "Security response."},
        )
        assert revoked.status_code == 200, revoked.text
        assert revoked.json()["revoked_at"] is not None
        assert revoked.json()["revoked_by"] == "session.admin@example.test"
        assert revoked.json()["revocation_reason_sha256"] == hash_token(
            "Security response."
        )
        assert client.get("/api/v1/auth/me").status_code == 401

        reissued = client.post(
            "/api/v1/auth/browser-sessions",
            headers=admin_headers,
        )
        assert reissued.status_code == 201, reissued.text
        bulk = client.post(
            (
                f"/api/v1/auth/principals/"
                f"{bootstrap.json()['principal']['id']}"
                "/browser-sessions/revoke"
            ),
            headers=admin_headers,
            json={"reason": "Terminate all sessions."},
        )
        assert bulk.status_code == 200, bulk.text
        assert bulk.json()["revoked_count"] == 1
        assert client.get("/api/v1/auth/me").status_code == 401
    finally:
        _restore_disabled_auth(monkeypatch)


def test_investigation_uses_immutable_server_side_permission_snapshot(
    client,
    monkeypatch,
):
    provider = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "auth-snapshot-provider",
            "provider_type": "openai_compatible",
            "base_url": "https://models.example.test/v1",
            "auth_type": "none",
            "created_by": "setup",
        },
    ).json()
    model = client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": provider["id"],
            "display_name": "Auth snapshot model",
            "model_name": "auth-snapshot-model",
            "capabilities": ["chat", "json_schema"],
            "created_by": "setup",
        },
    ).json()
    route = client.post(
        "/api/v1/ai/routes",
        json={
            "purpose": "investigation",
            "primary_model_id": model["id"],
            "created_by": "setup",
        },
    )
    assert route.status_code == 201, route.text
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)

    _required_auth(monkeypatch)
    try:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            headers=BOOTSTRAP_HEADERS,
            json={
                "subject": "admin@example.test",
                "display_name": "Initial Admin",
            },
        )
        admin_token = bootstrap.json()["token"]["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        role = client.post(
            "/api/v1/auth/roles",
            headers=admin_headers,
            json={
                "name": "asset-investigator",
                "description": "Can investigate inventory but not alerts or metrics.",
                "permissions": [
                    "investigations.create",
                    "investigations.read",
                    "assets.read",
                ],
            },
        )
        assert role.status_code == 201, role.text
        principal = client.post(
            "/api/v1/auth/principals",
            headers=admin_headers,
            json={
                "subject": "operator@example.test",
                "display_name": "Asset Operator",
            },
        )
        principal_id = principal.json()["id"]
        binding = client.post(
            f"/api/v1/auth/principals/{principal_id}/bindings",
            headers=admin_headers,
            json={"role_id": role.json()["id"], "scope": {"all": True}},
        )
        assert binding.status_code == 201, binding.text
        issued = client.post(
            f"/api/v1/auth/principals/{principal_id}/tokens",
            headers=admin_headers,
            json={"name": "operator-token", "expires_in_hours": 24},
        )
        operator_headers = {
            "Authorization": f"Bearer {issued.json()['access_token']}"
        }

        created = client.post(
            "/api/v1/agent/investigations",
            headers=operator_headers,
            json={
                "title": "Authorization snapshot",
                "objective": "Inspect one device without reading alert or metric data.",
                "scope": {"device_ids": ["device-1"]},
                "route_purpose": "investigation",
                "created_by": "forged-admin-subject",
            },
        )
        assert created.status_code == 201, created.text
        snapshot = created.json()
        assert snapshot["created_by"] == "operator@example.test"
        assert snapshot["requested_by_principal_id"] == principal_id
        assert snapshot["permission_snapshot"] == [
            "assets.read",
            "investigations.create",
            "investigations.read",
        ]

        # Later role expansion cannot silently grant an already-created run
        # additional tools.
        with SessionLocal() as db:
            stored_role = db.get(ControlPlaneRole, role.json()["id"])
            assert stored_role is not None
            stored_role.permissions = [*stored_role.permissions, "alerts.read"]
            db.commit()
            investigation = db.get(Investigation, snapshot["id"])
            assert investigation is not None
            reasoner = OpenAICompatibleReasoner(db, investigation)
            names = {tool["name"] for tool in reasoner.tool_catalog}
            assert {
                "inventory.get_device",
                "knowledge.find_paths",
                "knowledge.query_graph",
            } <= names
            assert "alerts.list_open" not in names
            # Plugin additions remain bounded by the immutable permission snapshot,
            # including after the current human role expands.
            assert all(set(tool["required_permissions"]) <= set(snapshot["permission_snapshot"])
                for tool in reasoner.tool_catalog)
            alert_tool = db.scalar(
                select(AgentToolRegistration).where(
                    AgentToolRegistration.name == "alerts.list_open"
                )
            )
            assert alert_tool is not None

        started = client.post(
            f"/api/v1/agent/investigations/{snapshot['id']}/start",
            headers=operator_headers,
            json={"actor": "forged-admin-subject"},
        )
        assert started.status_code == 200, started.text
        assert started.json()["checkpoint"]["created_by"] == "operator@example.test"

        with SessionLocal() as db:
            investigation = db.get(Investigation, snapshot["id"])
            alert_tool = db.scalar(
                select(AgentToolRegistration).where(
                    AgentToolRegistration.name == "alerts.list_open"
                )
            )
            assert investigation is not None
            assert alert_tool is not None
            with pytest.raises(PermissionError):
                create_tool_call(
                    db,
                    investigation,
                    InvestigationToolCallCreate(
                        tool_id=alert_tool.id,
                        iteration=1,
                        arguments={},
                    ),
                )
            denied = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == snapshot["id"],
                    AuditEvent.event_type
                    == "investigation.tool.permission_denied",
                )
            )
            assert denied is not None
    finally:
        _restore_disabled_auth(monkeypatch)
