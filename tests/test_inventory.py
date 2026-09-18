from datetime import UTC, datetime, timedelta


def create_device(client, *, name="core-01", kind="switch"):
    response = client.post(
        "/api/v1/devices",
        json={
            "name": name,
            "kind": kind,
            "management_ip": "10.0.0.10" if kind == "switch" else "10.0.0.20",
            "site": "HQ",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_network_observations_keep_ip_and_mac_history(client):
    switch = create_device(client)
    observed_at = datetime.now(UTC)
    base = {
        "mac_address": "00-1B-44-11-3A-B7",
        "source": "arp",
        "collector_device_id": switch["id"],
        "interface_name": "Vlan120",
        "vlan_id": 120,
        "hostname": "ops-laptop",
    }

    first = client.post(
        "/api/v1/inventory/network-observations",
        json={"observations": [{**base, "ip_address": "10.20.1.10", "observed_at": observed_at.isoformat()}]},
    )
    assert first.status_code == 200, first.text
    assert first.json()["endpoints_created"] == 1

    second = client.post(
        "/api/v1/inventory/network-observations",
        json={
            "observations": [
                {
                    **base,
                    "ip_address": "10.20.1.11",
                    "observed_at": (observed_at + timedelta(minutes=5)).isoformat(),
                }
            ]
        },
    )
    assert second.status_code == 200, second.text

    endpoints = client.get("/api/v1/endpoints", params={"search": "10.20.1.11"})
    assert endpoints.status_code == 200
    endpoint = endpoints.json()[0]
    assert endpoint["mac_address"] == "00:1b:44:11:3a:b7"
    assert [item["address"] for item in endpoint["current_ips"]] == ["10.20.1.11"]
    assert endpoint["current_attachments"][0]["interface_name"] == "Vlan120"

    alerts = client.get("/api/v1/alerts", params={"status": "open"}).json()
    assert any(alert["event_type"] == "endpoint.ip.changed" for alert in alerts)


def test_wifi_controller_snapshot_persists_sessions_and_closes_missing_clients(client):
    controller = create_device(client, name="wlc-01", kind="wireless_controller")
    now = datetime.now(UTC)
    client_payload = {
        "mac_address": "A4:83:E7:10:2F:91",
        "ip_address": "10.30.1.54",
        "hostname": "mira-iphone",
        "access_point": "AP-17F-03",
        "ssid": "CORP",
        "band": "5 GHz",
        "channel": 44,
        "vlan_id": 131,
        "rssi": -82,
        "snr": 13,
        "observed_at": now.isoformat(),
    }

    response = client.post(
        "/api/v1/inventory/wireless-snapshots",
        json={
            "controller_id": controller["id"],
            "complete_snapshot": True,
            "observed_at": now.isoformat(),
            "clients": [client_payload],
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["wireless_sessions_written"] == 1
    assert len(result["alert_ids"]) == 1

    endpoint = client.get("/api/v1/endpoints").json()[0]
    assert endpoint["current_wireless_sessions"][0]["access_point"] == "AP-17F-03"
    assert endpoint["current_wireless_sessions"][0]["rssi"] == -82

    alerts = client.get("/api/v1/alerts", params={"status": "open"}).json()
    weak_signal = next(alert for alert in alerts if alert["event_type"] == "wireless.rssi.low")
    acknowledged = client.post(
        f"/api/v1/alerts/{weak_signal['id']}/acknowledge", json={"actor": "noc.operator"}
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"

    recovered = {**client_payload, "rssi": -55, "snr": 34, "observed_at": (now + timedelta(minutes=1)).isoformat()}
    response = client.post(
        "/api/v1/inventory/wireless-snapshots",
        json={
            "controller_id": controller["id"],
            "complete_snapshot": True,
            "observed_at": (now + timedelta(minutes=1)).isoformat(),
            "clients": [recovered],
        },
    )
    assert response.status_code == 200, response.text
    resolved = client.get("/api/v1/alerts", params={"status": "resolved"}).json()
    assert any(alert["id"] == weak_signal["id"] for alert in resolved)

    empty_snapshot = client.post(
        "/api/v1/inventory/wireless-snapshots",
        json={
            "controller_id": controller["id"],
            "complete_snapshot": True,
            "observed_at": (now + timedelta(minutes=2)).isoformat(),
            "clients": [],
        },
    )
    assert empty_snapshot.status_code == 200
    assert empty_snapshot.json()["sessions_closed"] == 1
    endpoint = client.get("/api/v1/endpoints").json()[0]
    assert endpoint["current_wireless_sessions"] == []


def test_manual_alerts_are_deduplicated_and_resolved(client):
    payload = {
        "event_type": "device.unreachable",
        "entity_type": "device",
        "entity_id": "router-01",
        "title": "Router is unreachable",
        "description": "Three consecutive probes failed.",
        "severity": "critical",
        "details": {"failed_probes": 3},
    }
    first = client.post("/api/v1/alerts/events", json=payload)
    second = client.post("/api/v1/alerts/events", json=payload)
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert second.json()["occurrence_count"] == 2

    resolved = client.post(
        f"/api/v1/alerts/{first.json()['id']}/resolve", json={"actor": "noc.lead"}
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"

