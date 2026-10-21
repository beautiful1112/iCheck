from dataclasses import replace

from icheck.auth import current_principal
from icheck.config import get_settings
from icheck.main import app
from icheck.services.control_plane_auth import development_principal


def test_integration_catalog_reports_implementation_not_connection_readiness(client):
    response = client.get("/api/v1/integrations/providers")
    assert response.status_code == 200
    providers = {item["provider"]: item for item in response.json()}
    assert set(providers) == {"zabbix", "solarwinds_orion", "rest_webhook"}
    assert providers["zabbix"]["development_stage"] == "guided_sync"
    assert providers["zabbix"]["configurable"] is True
    assert providers["zabbix"]["implemented_operations"] == [
        "resources.read", "alerts.read", "metrics.history.read",
    ]
    assert providers["solarwinds_orion"]["implemented_operations"] == ["resources.read", "alerts.read", "metrics.history.read"]
    assert providers["solarwinds_orion"]["development_stage"] == "guided_sync"
    assert all(not item["live_qualified"]
               and not item["requires_prometheus"] for item in providers.values())
    assert providers["solarwinds_orion"]["configurable"]
    assert providers["rest_webhook"]["configurable"]
    assert client.post("/api/v1/integrations/providers", json={}).status_code == 405


def test_catalog_requires_authenticated_reader(client, monkeypatch):
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    try:
        assert client.get("/api/v1/integrations/providers").status_code == 401
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()


def test_catalog_requires_metrics_read_permission(client):
    principal = development_principal()
    app.dependency_overrides[current_principal] = lambda: replace(principal, permissions=frozenset())
    try:
        assert client.get("/api/v1/integrations/providers").status_code == 403
    finally:
        app.dependency_overrides.pop(current_principal, None)
