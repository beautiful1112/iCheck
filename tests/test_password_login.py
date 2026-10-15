from datetime import UTC, datetime, timedelta
import json

import pytest
from sqlalchemy import select

from icheck.config import get_settings
from icheck.database import SessionLocal
from icheck.models import AuditEvent, ControlPlanePrincipal, ControlPlaneBrowserSession, Tenant
from icheck.passwords import hash_password, verify_password

PASSWORD = "A private lab passphrase 2026!"
NEW_PASSWORD = "A different private passphrase 2026!"


@pytest.fixture
def required_auth(monkeypatch):
    with monkeypatch.context() as patch:
        patch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
        patch.setenv("ICHECK_CONTROL_PLANE_PASSWORD_LOGIN_ENABLED", "true")
        patch.setenv("ICHECK_CONTROL_PLANE_LOCAL_BROWSER_LOGIN_ENABLED", "true")
        get_settings.cache_clear()
        yield
    get_settings.cache_clear()


def bootstrap(client, *, password=PASSWORD):
    payload = {"subject": "admin", "display_name": "Administrator"}
    if password is not None:
        payload["password"] = password
    response = client.post("/api/v1/auth/bootstrap", headers={
        "X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token",
    }, json=payload)
    assert response.status_code == 201, response.text
    document = response.json()
    return document["principal"]["id"], {"Authorization": "Bearer " + document["token"]["access_token"]}


def login(client, username="admin", password=PASSWORD, **fields):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password, **fields})


def test_hashes_are_salted_versioned_and_not_token_hashes():
    first, second = hash_password(PASSWORD), hash_password(PASSWORD)
    assert first != second
    assert first.startswith("pbkdf2_sha256$600000$")
    assert verify_password(PASSWORD, first)
    assert not verify_password("incorrect", first)
    assert not verify_password(PASSWORD, None)
    assert not verify_password(PASSWORD, "pbkdf2_sha256$999999999999$00$00")
    assert not verify_password(PASSWORD, "broken")


def test_token_to_cookie_exchange_is_opt_in(monkeypatch):
    from icheck.config import Settings
    monkeypatch.delenv("ICHECK_CONTROL_PLANE_LOCAL_BROWSER_LOGIN_ENABLED", raising=False)
    assert Settings(_env_file=None).control_plane_local_browser_login_enabled is False


def test_passwords_are_not_trimmed_or_truncated(client, required_auth):
    password = "  " + PASSWORD + "  "
    bootstrap(client, password=password)
    assert login(client, password=password.strip()).status_code == 401
    assert login(client, password=password).status_code == 201


def test_invalid_password_unicode_is_rejected_without_echo(client, required_auth):
    response = client.post("/api/v1/auth/login", headers={"Content-Type": "application/json"},
        content=json.dumps({"username": "admin", "password": chr(0xD800)}))
    assert response.status_code == 422
    assert "input" not in response.text


def test_wrong_tenant_never_borrows_another_tenants_username(client, required_auth):
    bootstrap(client)
    assert login(client, tenant="unassigned-tenant").status_code == 401
    assert login(client).status_code == 201


def test_password_session_passes_sensitive_human_authority_guard_and_reset_invalidates_it(client, required_auth):
    from icheck.database import set_session_namespace
    from icheck.services.control_plane_auth import authenticate_browser_session
    from icheck.services.current_authority import current_human_authority
    principal_id, headers = bootstrap(client)
    assert login(client).status_code == 201
    with SessionLocal() as db:
        actor = authenticate_browser_session(db, client.cookies.get("icheck_session"))
        set_session_namespace(db, actor.tenant_id, actor.region_id)
        current_human_authority(db, actor, permissions=("auth.admin",),
            tenant_id=actor.tenant_id, region_id=actor.region_id).assert_live(db)
        db.rollback()
    assert client.put(f"/api/v1/auth/principals/{principal_id}/password", headers=headers,
        json={"password": NEW_PASSWORD, "reason": "Revoke previous human authority"}).status_code == 200
    with SessionLocal() as db:
        set_session_namespace(db, actor.tenant_id, actor.region_id)
        with pytest.raises(PermissionError):
            current_human_authority(db, actor, permissions=("auth.admin",),
                tenant_id=actor.tenant_id, region_id=actor.region_id)


def test_password_login_issues_cookie_not_api_token(client, required_auth):
    principal_id, api_headers = bootstrap(client)
    assert client.get("/api/v1/auth/login/config").json() == {"enabled": True}
    signed_in = login(client)
    assert signed_in.status_code == 201, signed_in.text
    assert signed_in.json()["principal"]["auth_method"] == "browser_session"
    assert "access_token" not in signed_in.json()
    assert "HttpOnly" in signed_in.headers["set-cookie"]
    assert "SameSite=strict" in signed_in.headers["set-cookie"]
    assert signed_in.headers["cache-control"] == "no-store"
    assert client.get("/api/v1/auth/me").json()["subject"] == "admin"
    denied = client.post("/api/v1/auth/principals", json={"subject": "viewer", "display_name": "Viewer"})
    assert denied.status_code == 403
    allowed = client.post("/api/v1/auth/principals", headers={
        "X-Icheck-CSRF-Token": signed_in.json()["csrf_token"],
    }, json={"subject": "viewer", "display_name": "Viewer"})
    assert allowed.status_code == 201
    with SessionLocal() as db:
        stored = db.get(ControlPlanePrincipal, principal_id)
        assert stored.password_hash != PASSWORD and verify_password(PASSWORD, stored.password_hash)
        assert db.scalar(select(ControlPlaneBrowserSession)).auth_source == "local_password"
        audit = json.dumps([event.details for event in db.scalars(select(AuditEvent))])
        assert PASSWORD not in audit and stored.password_hash not in audit
    assert client.get("/api/v1/auth/me", headers=api_headers).status_code == 200
    csrf = client.get("/api/v1/auth/browser-sessions/current/csrf").json()["csrf_token"]
    assert client.delete("/api/v1/auth/browser-sessions/current", headers={"X-Icheck-CSRF-Token": csrf}).status_code == 204
    assert client.get("/api/v1/auth/me").status_code == 401


@pytest.mark.parametrize("username,password", [("missing", PASSWORD), ("admin", "wrong")])
def test_login_denials_are_generic_and_do_not_set_cookies(client, required_auth, username, password):
    bootstrap(client)
    response = login(client, username, password)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid username or password"}
    assert "set-cookie" not in response.headers


def test_existing_token_only_account_can_be_enrolled_without_reissuing_token(client, required_auth):
    principal_id, headers = bootstrap(client, password=None)
    assert login(client).status_code == 401
    reset = client.put(f"/api/v1/auth/principals/{principal_id}/password", headers=headers,
        json={"password": PASSWORD, "reason": "Enable human sign-in"})
    assert reset.status_code == 200, reset.text
    assert reset.json()["password_login_configured"] is True
    assert "password_hash" not in reset.json()
    assert PASSWORD not in reset.text
    assert login(client).status_code == 201
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200


def test_password_reset_revokes_sessions_not_api_tokens(client, required_auth):
    principal_id, headers = bootstrap(client)
    assert login(client).status_code == 201
    old_cookie = client.cookies.get("icheck_session")
    result = client.put(f"/api/v1/auth/principals/{principal_id}/password", headers=headers,
        json={"password": NEW_PASSWORD, "reason": "Account recovery"})
    assert result.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    assert login(client).status_code == 401
    assert login(client, password=NEW_PASSWORD).status_code == 201
    assert client.cookies.get("icheck_session") != old_cookie


def test_self_service_change_requires_current_password_and_rotates_session(client, required_auth):
    bootstrap(client)
    first = login(client)
    original_cookie = client.cookies.get("icheck_session")
    headers = {"X-Icheck-CSRF-Token": first.json()["csrf_token"]}
    wrong = client.post("/api/v1/auth/password/change", headers=headers,
        json={"current_password": "wrong", "new_password": NEW_PASSWORD})
    assert wrong.status_code == 400
    correct = client.post("/api/v1/auth/password/change", headers=headers,
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert correct.status_code == 201, correct.text
    assert client.cookies.get("icheck_session") != original_cookie
    assert client.get("/api/v1/auth/me").status_code == 200
    with SessionLocal() as db:
        sessions = list(db.scalars(select(ControlPlaneBrowserSession)))
        assert len(sessions) == 2
        assert sum(session.revoked_at is None for session in sessions) == 1
    client.cookies.set("icheck_session", original_cookie, domain="testserver.local", path="/")
    assert client.get("/api/v1/auth/me").status_code == 401
    assert login(client, password=NEW_PASSWORD).status_code == 201


def test_lockout_is_persisted_and_expires(client, required_auth):
    principal_id, _ = bootstrap(client)
    for _ in range(5):
        assert login(client, password="wrong").status_code == 401
    assert login(client).status_code == 401
    with SessionLocal() as db:
        stored = db.get(ControlPlanePrincipal, principal_id)
        assert stored.password_failed_attempts == 5
        assert stored.password_locked_until is not None
        stored.password_locked_until = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    assert login(client).status_code == 201
    with SessionLocal() as db:
        stored = db.get(ControlPlanePrincipal, principal_id)
        assert stored.password_failed_attempts == 0 and stored.password_locked_until is None


def test_password_and_token_login_switches_are_independent(client, required_auth, monkeypatch):
    _, headers = bootstrap(client)
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_LOCAL_BROWSER_LOGIN_ENABLED", "false")
    get_settings.cache_clear()
    assert login(client).status_code == 201
    assert client.post("/api/v1/auth/browser-sessions", headers=headers).status_code == 403
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_PASSWORD_LOGIN_ENABLED", "false")
    get_settings.cache_clear()
    assert client.get("/api/v1/auth/login/config").json() == {"enabled": False}
    assert login(client).status_code == 403
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200


def test_service_accounts_cannot_receive_passwords_or_login(client, required_auth):
    _, headers = bootstrap(client)
    created = client.post("/api/v1/auth/principals", headers=headers,
        json={"subject": "collector-service", "display_name": "Collector", "principal_type": "service"})
    assert created.status_code == 201
    target = created.json()["id"]
    assert client.put(f"/api/v1/auth/principals/{target}/password", headers=headers,
        json={"password": PASSWORD, "reason": "Invalid request"}).status_code == 422
    assert login(client, "collector-service").status_code == 401


def test_disabled_principal_or_tenant_cannot_login(client, required_auth):
    principal_id, _ = bootstrap(client)
    with SessionLocal() as db:
        stored = db.get(ControlPlanePrincipal, principal_id)
        stored.enabled = False
        db.commit()
    assert login(client).status_code == 401
    with SessionLocal() as db:
        stored = db.get(ControlPlanePrincipal, principal_id)
        stored.enabled = True
        db.get(Tenant, stored.tenant_id).enabled = False
        db.commit()
    assert login(client).status_code == 401


def test_login_rejects_foreign_origin_and_form_submission(client, required_auth):
    bootstrap(client)
    assert client.post("/api/v1/auth/login", headers={"Origin": "https://attacker.example"},
        json={"username": "admin", "password": PASSWORD}).status_code == 403
    assert client.post("/api/v1/auth/login", data={"username": "admin", "password": PASSWORD}).status_code == 422
    assert client.post("/api/v1/auth/login", headers={"Origin": "http://localhost:3000"},
        json={"username": "admin", "password": PASSWORD}).status_code == 201


@pytest.mark.parametrize("body", [
    {"password": "do-not-echo-this-secret"},
    {"username": "admin", "password": "x" * 257},
    {"username": "admin", "password": PASSWORD, "unexpected": "do-not-echo-this-secret"},
])
def test_validation_never_echoes_sensitive_inputs(client, required_auth, body):
    response = client.post("/api/v1/auth/login", json=body)
    assert response.status_code == 422
    assert "do-not-echo-this-secret" not in response.text
    assert PASSWORD not in response.text
    assert "x" * 257 not in response.text
    assert all("input" not in item and "ctx" not in item for item in response.json()["detail"])


def test_password_admin_requires_global_permission_and_self_change_requires_csrf(client, required_auth):
    principal_id, headers = bootstrap(client)
    result = client.post("/api/v1/auth/principals", headers=headers,
        json={"subject": "viewer", "display_name": "Viewer"})
    target = result.json()["id"]
    client.put(f"/api/v1/auth/principals/{target}/password", headers=headers,
        json={"password": PASSWORD, "reason": "Enrollment"})
    assert login(client, "viewer").status_code == 201
    assert client.post("/api/v1/auth/password/change",
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD}).status_code == 403
    csrf = client.get("/api/v1/auth/browser-sessions/current/csrf").json()["csrf_token"]
    forbidden = client.put(f"/api/v1/auth/principals/{principal_id}/password",
        headers={"X-Icheck-CSRF-Token": csrf}, json={"password": NEW_PASSWORD, "reason": "Denied"})
    assert forbidden.status_code == 403
    changed = client.post("/api/v1/auth/password/change", headers={"X-Icheck-CSRF-Token": csrf},
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert changed.status_code == 201, changed.text
