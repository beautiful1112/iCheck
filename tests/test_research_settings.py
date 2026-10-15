"""GUI settings persist into the real agent/Studio research paths without live I/O."""
import json
import pytest
from sqlalchemy import select

from icheck.config import get_settings
from icheck.database import set_session_namespace
from icheck.models import AuditEvent, ResearchSettings
from icheck.public_research_http import ResearchUnavailable
from icheck.services import research, research_authoring, research_settings
from icheck.services.control_plane_auth import development_principal
from test_openrouter_setup import managed_key, namespace_session
from test_password_login import bootstrap, login, required_auth

KEY = "brave-synthetic-key-not-a-real-secret"


@pytest.fixture
def online(monkeypatch):
    monkeypatch.setenv("ICHECK_RESEARCH_ENABLED", "true")
    get_settings.cache_clear()
    calls = []
    def transport(url, **kwargs):
        calls.append((url, kwargs))
        if url.startswith("https://api.search.brave.com/"):
            assert kwargs["headers"]["X-Subscription-Token"] == KEY
            return url, "application/json", json.dumps({"web": {"results": [
                {"title": "SNMP documentation", "url": "https://prometheus.io/docs/", "description": "Public reference"}]}}).encode()
        if url.startswith("https://search.example.org/"):
            assert "headers" not in kwargs
            return url, "application/json", b'{"results":[]}'
        assert url == "https://prometheus.io/docs/"
        return url, "text/plain", b"A synthetic public reference, no device contact."
    monkeypatch.setattr(research, "fetch", transport)
    yield calls
    get_settings.cache_clear()


def save(client, **updates):
    response = client.put("/api/v1/research/settings", json={"expected_revision": 0,
        "provider": "brave", "enabled": True, "api_key": KEY, "daily_limit": 100, **updates})
    assert response.status_code == 200, response.text
    assert KEY not in response.text and response.headers["cache-control"] == "no-store"
    return response.json()


def test_save_is_write_only_and_does_not_call_provider(client, managed_key, online):
    initial = client.get("/api/v1/research/settings").json()
    assert initial["revision"] == 0 and initial["storage_ready"]
    saved = save(client)
    assert saved["revision"] == 1 and saved["key_configured"] and saved["last_test_status"] is None
    assert not online
    with namespace_session() as db:
        row = db.scalar(select(ResearchSettings))
        assert KEY.encode() not in row.encrypted_secret
        assert research_settings.decrypt(row) == KEY
        assert KEY not in json.dumps([event.details for event in db.scalars(select(AuditEvent))])
    assert KEY not in client.get("/api/v1/research/settings").text
    checked = client.post("/api/v1/research/settings/test", json={"expected_revision": 1, "approve_charge": True})
    assert checked.status_code == 200, checked.text
    assert checked.json()["status"] == "passed" and checked.json()["settings"]["calls_today"] == 1
    assert len(online) == 1
    assert client.get("/api/v1/research/status").json()["availability_tested"]


def test_real_agent_and_studio_share_saved_provider_and_budget(client, managed_key, online):
    save(client)
    with namespace_session() as db:
        result, _ = research.tools_for_ai("research.search", db, {"query": "Cisco SNMP"}, development_principal())
        assert result["status"] == "ok"
        evidence = research_authoring.references({"brief": "Cisco SNMP ARP tables"}, db=db)
        assert evidence["status"] == "ok" and evidence["documents"]
    assert len(online) == 3  # Two searches, one public reference read.
    assert client.get("/api/v1/research/settings").json()["calls_today"] == 2


def test_disable_keeps_key_and_never_falls_back_to_environment(client, managed_key, online):
    save(client)
    disabled = save(client, expected_revision=1, enabled=False, api_key=None)
    assert disabled["key_configured"] and disabled["revision"] == 2
    response = client.post("/api/v1/research/search", json={"query": "Cisco SNMP"})
    assert response.json()["status"] == "unavailable" and not online
    save(client, expected_revision=2, api_key=None)
    assert client.post("/api/v1/research/search", json={"query": "Cisco SNMP"}).json()["status"] == "ok"


def test_provider_switch_drops_key_and_never_sends_it_to_new_host(client, managed_key, online):
    save(client)
    switched = save(client, expected_revision=1, provider="searxng", api_key=None, searxng_url="https://search.example.org/search")
    assert not switched["key_configured"]
    result = client.post("/api/v1/research/search", json={"query": "Cisco SNMP"})
    assert result.json()["provider"] == "searxng" and result.json()["status"] == "no_results"
    assert len(online) == 1
    denied = client.put("/api/v1/research/settings", json={"expected_revision": 2, "provider": "brave", "enabled": True})
    assert denied.status_code == 422


def test_limits_survive_edit_and_failed_searches_consume_admission(client, managed_key, online, monkeypatch):
    save(client, daily_limit=1)
    def failed(*args, **kwargs):
        online.append("failed")
        raise ResearchUnavailable(KEY)
    monkeypatch.setattr(research, "fetch", failed)
    first = client.post("/api/v1/research/search", json={"query": "Cisco SNMP"})
    assert first.json()["status"] == "unavailable" and KEY not in first.text
    save(client, expected_revision=1, api_key=None, daily_limit=1)
    second = client.post("/api/v1/research/search", json={"query": "Cisco SNMP"})
    assert second.json()["status"] == "unavailable" and "limit" in second.json()["warning"]
    assert len(online) == 1
    with namespace_session() as db:
        row = research_settings.connection(db)
        row.quota_day = "2020-01-01"
        db.commit()
    client.post("/api/v1/research/search", json={"query": "Cisco SNMP"})
    assert len(online) == 2 and client.get("/api/v1/research/settings").json()["calls_today"] == 1


def test_stale_save_test_and_missing_charge_approval_do_not_call_network(client, managed_key, online):
    save(client)
    assert client.put("/api/v1/research/settings", json={"expected_revision": 0, "provider": "brave", "enabled": False}).status_code == 409
    assert client.post("/api/v1/research/settings/test", json={"expected_revision": 2, "approve_charge": True}).status_code == 409
    for value in [{"expected_revision": 1}, {"expected_revision": 1, "approve_charge": False}]:
        assert client.post("/api/v1/research/settings/test", json=value).status_code == 422
    assert not online


@pytest.mark.parametrize("extra", [{"api_key": KEY + " "}, {"api_key": {"nested": KEY}}, {"unexpected": KEY},
                                  {"api_key": KEY, "provider": KEY}])
def test_invalid_fields_never_echo_secret_input(client, managed_key, extra):
    response = client.put("/api/v1/research/settings", json={"expected_revision": 0, "provider": "brave", "enabled": True, **extra})
    assert response.status_code == 422 and KEY not in response.text and '"input"' not in response.text
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("url", ["http://search.example.org", "https://127.0.0.1/search", "https://user:secret@search.example.org/",
                               "https://search.example.org/search?api_key=secret", "https://search.example.org/#fragment"])
def test_unsafe_searxng_endpoints_rejected_before_network(client, online, url):
    response = client.put("/api/v1/research/settings", json={"expected_revision": 0, "provider": "searxng", "enabled": True, "searxng_url": url})
    assert response.status_code == 422 and not online


def test_namespace_and_provider_binding_prevent_key_reuse(client, managed_key, online):
    save(client)
    with namespace_session() as db:
        row = research_settings.connection(db)
        row.provider = "searxng"
        with pytest.raises(ResearchUnavailable): research_settings.decrypt(row)
        row.provider = "brave"
        row.tenant_id = "different-tenant"
        with pytest.raises(ResearchUnavailable): research_settings.decrypt(row)
        db.rollback()
        set_session_namespace(db, "other-tenant", "other-region")
        assert research_settings.connection(db) is None
        assert not research_settings.setup_status(db).key_configured


def test_bad_storage_cannot_create_key_and_wrong_master_key_blocks_search(client, managed_key, online):
    managed_key.chmod(0o644)
    assert not client.get("/api/v1/research/settings").json()["storage_ready"]
    response = client.put("/api/v1/research/settings", json={"expected_revision": 0, "provider": "brave", "enabled": True, "api_key": KEY})
    assert response.status_code == 503 and not online
    assert client.get("/api/v1/research/settings").json()["revision"] == 0
    managed_key.chmod(0o400)
    save(client)
    managed_key.chmod(0o600); managed_key.write_bytes(b"x" * 32); managed_key.chmod(0o400)
    assert client.post("/api/v1/research/search", json={"query": "Cisco SNMP"}).json()["status"] == "unavailable"
    assert not online


def test_malformed_provider_response_is_not_a_successful_test(client, managed_key, online, monkeypatch):
    save(client)
    monkeypatch.setattr(research, "fetch", lambda url, **kw: (url, "application/json", b'{"error":"invalid key"}'))
    result = client.post("/api/v1/research/settings/test", json={"expected_revision": 1, "approve_charge": True})
    assert result.json()["status"] == "failed"


def test_server_switch_still_blocks_gui_enabled_search(client, managed_key, online, monkeypatch):
    save(client)
    monkeypatch.setenv("ICHECK_RESEARCH_ENABLED", "false"); get_settings.cache_clear()
    assert not client.get("/api/v1/research/settings").json()["server_enabled"]
    assert client.post("/api/v1/research/search", json={"query": "Cisco SNMP"}).json()["status"] == "unavailable"
    assert not online


def test_key_rotation_during_connection_test_cannot_mark_new_settings_healthy(client, managed_key, online, monkeypatch):
    save(client)
    original = research.fetch
    def concurrent_update(url, **kwargs):
        from icheck.research_schemas import ResearchSettingsUpdate
        with namespace_session() as db:
            research_settings.save(db, ResearchSettingsUpdate(expected_revision=1, provider="brave", enabled=True,
                api_key=KEY + "-new"), actor="other-admin")
        return original(url, **kwargs)
    monkeypatch.setattr(research, "fetch", concurrent_update)
    response = client.post("/api/v1/research/settings/test", json={"expected_revision": 1, "approve_charge": True})
    assert response.status_code == 409
    state = client.get("/api/v1/research/settings").json()
    assert state["revision"] == 2 and state["last_test_status"] is None


def test_provider_cannot_reflect_key_into_search_results(client, managed_key, online, monkeypatch):
    save(client)
    monkeypatch.setattr(research, "fetch", lambda url, **kwargs: (url, "application/json", json.dumps({"web": {"results": [
        {"title": "reflected secret", "url": "https://example.com/reference", "description": KEY}]}}).encode()))
    response = client.post("/api/v1/research/search", json={"query": "Cisco SNMP"})
    assert response.status_code == 200 and KEY not in response.text and response.json()["sources"] == []


def test_browser_csrf_readonly_and_service_users_cannot_manage_search(client, managed_key, required_auth):
    _, headers = bootstrap(client)
    signed_in = login(client)
    payload = {"expected_revision": 0, "provider": "brave", "enabled": True, "api_key": KEY}
    assert client.put("/api/v1/research/settings", json=payload).status_code == 403
    assert client.put("/api/v1/research/settings", json=payload,
        headers={"X-Icheck-CSRF-Token": signed_in.json()["csrf_token"]}).status_code == 200
    assert client.post("/api/v1/research/settings/test", json={"expected_revision": 1, "approve_charge": True}).status_code == 403
    client.cookies.clear()
    roles = client.get("/api/v1/auth/roles", headers=headers).json()
    for kind, role_name in [("user", "viewer"), ("service", "admin")]:
        response = client.post("/api/v1/auth/principals", headers=headers, json={"subject": "research-" + kind,
            "display_name": "Research test", "principal_type": kind})
        assert response.status_code == 201, response.text
        identity = response.json()["id"]
        role = next(item for item in roles if item["name"] == role_name)
        assert client.post(f"/api/v1/auth/principals/{identity}/bindings", headers=headers,
            json={"role_id": role["id"], "scope": {"all": True}}).status_code == 201
        token = client.post(f"/api/v1/auth/principals/{identity}/tokens", headers=headers,
            json={"name": "test", "expires_in_hours": 1}).json()["access_token"]
        assert client.get("/api/v1/research/settings", headers={"Authorization": "Bearer " + token}).status_code == 403
