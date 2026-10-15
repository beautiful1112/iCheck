from datetime import UTC, datetime

import pytest

from icheck.config import get_settings


@pytest.fixture
def administrator(client, monkeypatch):
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    response = client.post("/api/v1/auth/bootstrap", headers={
        "X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token",
    }, json={"subject": "preview.admin@example.test", "display_name": "Preview administrator"})
    assert response.status_code == 201, response.text
    yield {"Authorization": f"Bearer {response.json()['token']['access_token']}"}
    get_settings.cache_clear()


def rule():
    return {"name": "Preview lab RSSI", "event_type": "wireless.rssi.low",
            "severity": "critical", "conditions": {"threshold": -60},
            "cooldown_seconds": 300, "enabled": True}


def test_authenticated_rule_observation_active_display_and_acknowledgement(client, administrator):
    created = client.post("/api/v1/alert-rules", headers=administrator, json=rule())
    assert created.status_code == 201, created.text
    controller = client.post("/api/v1/devices", headers=administrator, json={
        "name": "preview-controller", "kind": "wireless_controller",
        "management_ip": "198.18.0.20", "site": "LAB",
    })
    assert controller.status_code == 201, controller.text
    now = datetime.now(UTC).isoformat()
    observed = client.post("/api/v1/inventory/wireless-snapshots", headers=administrator, json={
        "controller_id": controller.json()["id"], "complete_snapshot": True, "observed_at": now,
        "clients": [{"mac_address": "02:00:00:00:00:01", "ip_address": "198.18.1.2",
                     "ssid": "PREVIEW-TEST", "rssi": -70, "observed_at": now}],
    })
    assert observed.status_code == 200, observed.text
    active = client.get("/api/v1/alerts?status=open", headers=administrator).json()
    alert = next(row for row in active if row["rule_id"] == created.json()["id"])
    assert alert["severity"] == "critical" and alert["status"] == "open"
    acknowledgement = client.post(f"/api/v1/alerts/{alert['id']}/acknowledge",
                                  headers=administrator, json={"actor": "spoofed-actor"})
    assert acknowledgement.status_code == 200, acknowledgement.text
    assert acknowledgement.json()["acknowledged_by"] == "preview.admin@example.test"
    assert acknowledgement.json()["status"] == "acknowledged"
    assert acknowledgement.json()["resolved_at"] is None
    assert client.get("/api/v1/alerts?status=open", headers=administrator).json() == []
    assert client.get("/api/v1/alerts?status=acknowledged", headers=administrator).json()[0]["id"] == alert["id"]


def test_site_scoped_rule_admin_cannot_modify_namespace_policy(client, administrator):
    role = client.post("/api/v1/auth/roles", headers=administrator, json={
        "name": "site-alert-admin", "description": "Scoped fixture",
        "permissions": ["alerts.admin", "alerts.read"],
    })
    assert role.status_code == 201, role.text
    principal = client.post("/api/v1/auth/principals", headers=administrator, json={
        "subject": "site.admin@example.test", "display_name": "Site administrator",
    }).json()
    binding = client.post(f"/api/v1/auth/principals/{principal['id']}/bindings", headers=administrator,
                          json={"role_id": role.json()["id"], "scope": {"sites": ["LAB"]}})
    assert binding.status_code == 201, binding.text
    issued = client.post(f"/api/v1/auth/principals/{principal['id']}/tokens", headers=administrator,
                         json={"name": "fixture-token", "expires_in_hours": 1})
    assert issued.status_code == 201, issued.text
    scoped = {"Authorization": f"Bearer {issued.json()['access_token']}"}
    denied = client.post("/api/v1/alert-rules", headers=scoped, json=rule())
    assert denied.status_code == 403
    assert "global authorization scope" in denied.json()["detail"]
    assert client.get("/api/v1/alert-rules", headers=scoped).status_code == 200
    assert all(row["name"] != rule()["name"] for row in client.get("/api/v1/alert-rules", headers=administrator).json())


def test_unauthenticated_rule_mutation_is_denied(client, administrator):
    assert client.post("/api/v1/alert-rules", json=rule()).status_code == 401
