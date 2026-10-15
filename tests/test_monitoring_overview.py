"""One monitoring inventory journey: inclusion, scope and measurement evidence."""
from dataclasses import replace
from datetime import timedelta

import pytest
from icheck.auth import current_principal
from icheck.database import SessionLocal
from icheck.main import app
from icheck.models import Device, DeviceConnection, DeviceMonitoringEnrollment, Alert, AlertStatus, AlertSeverity, utcnow
from icheck.services.control_plane_auth import development_principal
from test_asset_inventory_health import monitored, reply, vector
from test_monitoring_enrollments import seeded


@pytest.mark.parametrize("state", ["enabled", "failing", "stale", "disabled", "pending", "expired"])
def test_overview_retains_configured_targets_and_honest_collection_state(client, monkeypatch, state):
    device, connection, enrollment, _ = monitored(client)
    reply(monkeypatch, vector(device, connection, enrollment, up="0" if state == "failing" else "1", age=200 if state == "stale" else 10))
    with SessionLocal() as db:
        c = db.get(DeviceConnection, connection["id"])
        c.configuration = {"private_unused_value": "secret-must-not-be-returned"}
        # Keep normal authority except where this scenario intentionally removes it.
        from icheck.services.monitoring import _connection_fingerprint
        db.get(DeviceMonitoringEnrollment, enrollment["id"]).connection_fingerprint = _connection_fingerprint(c)
        if state == "disabled": c.enabled = False
        if state == "pending": c.verification_status = "pending"
        if state == "expired": db.get(DeviceMonitoringEnrollment, enrollment["id"]).approved_until = utcnow() - timedelta(seconds=1)
        db.add(Alert(dedup_key="overview-alert", title="Target alert", event_type="metric.prometheus", entity_type="device",
            entity_id=device["id"], status=AlertStatus.ACKNOWLEDGED, severity=AlertSeverity.WARNING))
        db.commit()
    response = client.get("/api/v1/monitoring/overview")
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert "secret-must-not-be-returned" not in response.text
    data = response.json()
    assert data["total"] == 1 and data["categories"][0]["count"] == 1
    item = data["items"][0]
    assert item["state"] == ("pending" if state == "expired" else state)
    assert item["device_alert_count"] == 1
    assert "fresh_samples_verified" not in item  # up alone is not complete metric proof.
    assert item["id"] == device["id"] and item["checks"][0]["connection_id"] == connection["id"]
    alerts = client.get("/api/v1/alerts", params={"device_id": device["id"]}).json()
    assert len(alerts) == 1
    assert client.get("/api/v1/alerts?device_id=not-this-device").json() == []


def test_overview_categories_search_pagination_and_future_plugins(client):
    with SessionLocal() as db:
        for index, protocol in enumerate(["snmp", "node_exporter", "windows_exporter", "https_api", "cadvisor", "vmware_exporter", "custom-api"]):
            device = Device(name=f"target-{index}", kind="other", management_ip=f"198.18.0.{index+1}", site="LAB")
            db.add(device); db.flush()
            db.add(DeviceConnection(device_id=device.id, protocol=protocol, adapter_type=protocol, verification_status="pending", created_by="test"))
        db.commit()
    data = client.get("/api/v1/monitoring/overview?limit=2&offset=2").json()
    assert data["total"] == 7 and len(data["items"]) == 2
    assert all(row["count"] == (0 if row["id"] == "services" else 1) for row in data["categories"])
    assert client.get("/api/v1/monitoring/overview?category=http").json()["items"][0]["checks"][0]["protocol"] == "https_api"
    assert client.get("/api/v1/monitoring/overview?category=other").json()["items"][0]["checks"][0]["protocol"] == "custom-api"
    assert client.get("/api/v1/monitoring/overview?search=target-6").json()["total"] == 1
    assert client.get("/api/v1/monitoring/overview?search=%25").json()["total"] == 0
    assert client.get("/api/v1/monitoring/overview?limit=51").status_code == 422


def test_overview_and_measurements_do_not_expose_other_device_scopes(client):
    device, connection, _, _ = seeded(client)
    try:
        app.dependency_overrides[current_principal] = lambda: replace(development_principal(), authorization_scope={"sites": ["OTHER"]})
        data = client.get("/api/v1/monitoring/overview").json()
        assert data["items"] == [] and data["total"] == 0
        assert all(row["count"] == 0 for row in data["categories"])
        assert client.get(f"/api/v1/assets/devices/{device['id']}/connections/{connection['id']}/monitoring/measurements").status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_unbound_measurements_cannot_use_up_as_expected_measurements(client):
    device, connection, _, _ = seeded(client)
    data = client.get(f"/api/v1/assets/devices/{device['id']}/connections/{connection['id']}/monitoring/measurements").json()
    assert not data["fresh_samples_verified"] and data["metric_evidence"] == []
    assert "No bound Studio" in data["diagnostic"]


def test_multiple_methods_are_one_resource_and_ssh_is_not_a_check(client):
    with SessionLocal() as db:
        for index in range(3):
            device = Device(name=f"switch-{index}", kind="switch", management_ip=f"198.18.1.{index+1}")
            db.add(device); db.flush()
            for protocol in (["ssh", "snmp", "https_api"] if index == 0 else ["ssh"]):
                db.add(DeviceConnection(device_id=device.id, protocol=protocol, adapter_type=protocol, created_by="test"))
        db.commit()
    data = client.get("/api/v1/monitoring/overview?limit=1").json()
    assert data["total"] == 3 and data["categories"][0]["count"] == 3
    assert len(data["items"]) == 1
    assert {row["protocol"] for row in data["items"][0]["checks"]} == {"snmp", "https_api"}
    other = client.get("/api/v1/monitoring/overview?limit=1&offset=1").json()["items"][0]
    assert other["id"] != data["items"][0]["id"] and other["state"] == "not_monitored"
    assert other["checks"] == []
    assert client.get("/api/v1/monitoring/overview?search=ssh").json()["total"] == 0


def test_http_services_are_inventory_resources_not_the_retired_business_catalog(client):
    from icheck.models import ServiceCatalogEntry
    with SessionLocal() as db:
        db.add(ServiceCatalogEntry(name="Payments", service_key="payments", owner_team="ops", criticality="tier_1",
            business_impact="high", created_by="fixture", updated_by="fixture"))
        db.add(Device(name="Payments API", kind="http_service", site="LAB")); db.commit()
    data = client.get("/api/v1/monitoring/overview?category=http").json()
    assert data["total"] == 1 and data["items"][0]["resource_type"] == "service"
    assert data["items"][0]["state"] == "not_monitored"
    try:
        app.dependency_overrides[current_principal] = lambda: replace(development_principal(), permissions=frozenset({"assets.read"}))
        assert client.get("/api/v1/monitoring/overview").json()["total"] == 1
        app.dependency_overrides[current_principal] = lambda: replace(development_principal(), authorization_scope={"sites": ["OTHER"]})
        assert client.get("/api/v1/monitoring/overview").json()["total"] == 0
    finally:
        app.dependency_overrides.clear()
