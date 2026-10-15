"""Inventory/alert home without Service Intelligence reads; synthetic observations."""
from datetime import UTC, datetime

from sqlalchemy import event

from icheck.database import engine
from test_preview_alert_workspace import administrator, rule


def controller(client, auth, name, site, ip):
    response = client.post("/api/v1/devices", headers=auth, json={"name": name,
        "kind": "wireless_controller", "management_ip": ip, "site": site})
    assert response.status_code == 201
    return response.json()["id"]


def observation(client, auth, identifier):
    now = datetime.now(UTC).isoformat()
    assert client.post("/api/v1/inventory/wireless-snapshots", headers=auth, json={
        "controller_id": identifier, "complete_snapshot": True, "observed_at": now,
        "clients": [{"mac_address": "02:00:00:00:00:01", "ip_address": "198.18.1.2",
                     "ssid": "FIXTURE", "rssi": -70, "observed_at": now}]}).status_code == 200


def test_summary_reads_inventory_and_alerts_without_service_or_situation_queries(client, administrator):
    assert client.post("/api/v1/alert-rules", headers=administrator, json=rule()).status_code == 201
    identifier = controller(client, administrator, "east", "LAB", "198.18.0.20")
    observation(client, administrator, identifier)
    statements = []
    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())
    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = client.get("/api/v1/operator/summary", headers=administrator)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 200
    body = response.json()
    assert body["devices"] == 1 and body["active_wireless_clients"] == 1
    assert body["open_alerts"] == body["critical_alerts"] == 1
    assert len(body["recent_alerts"]) == 1
    assert not any("situation" in key or "service" in key for key in body)
    assert not any("situations" in query or "service_catalog" in query for query in statements)
    assert client.get("/api/v1/situations", headers=administrator).status_code == 200
    assert client.get("/api/v1/dashboard/summary", headers=administrator).status_code == 200


def test_summary_is_authenticated_and_scoped_to_visible_inventory_and_alerts(client, administrator):
    assert client.get("/api/v1/operator/summary").status_code == 401
    controller(client, administrator, "east", "LAB", "198.18.0.20")
    west = controller(client, administrator, "west", "OTHER", "198.18.0.21")
    assert client.post("/api/v1/alert-rules", headers=administrator, json=rule()).status_code == 201
    observation(client, administrator, west)
    role = client.post("/api/v1/auth/roles", headers=administrator, json={"name": "scoped-operator",
        "description": "Fixture", "permissions": ["operations.read", "assets.read", "endpoints.read", "alerts.read"]}).json()
    user = client.post("/api/v1/auth/principals", headers=administrator, json={"subject": "east.operator", "display_name": "East operator"}).json()
    assert client.post(f"/api/v1/auth/principals/{user['id']}/bindings", headers=administrator,
        json={"role_id": role["id"], "scope": {"sites": ["LAB"]}}).status_code == 201
    token = client.post(f"/api/v1/auth/principals/{user['id']}/tokens", headers=administrator,
        json={"name": "fixture", "expires_in_hours": 1}).json()["access_token"]
    scoped = client.get("/api/v1/operator/summary", headers={"Authorization": "Bearer " + token})
    assert scoped.status_code == 200
    assert scoped.json()["devices"] == 1 and scoped.json()["open_alerts"] == 0
    assert scoped.json()["recent_alerts"] == []
