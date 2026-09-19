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
            assert {tool["name"] for tool in reasoner.tool_catalog} == {
                "inventory.get_device"
            }
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
