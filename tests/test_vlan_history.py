from datetime import UTC, datetime, timedelta


def test_vlan_transition_keeps_only_the_latest_ip_observation_active(client):
    device = client.post(
        "/api/v1/devices",
        json={
            "name": "access-01",
            "kind": "switch",
            "management_ip": "10.0.0.31",
            "site": "HQ",
        },
    ).json()
    now = datetime.now(UTC)

    for vlan, observed_at in ((10, now), (20, now + timedelta(minutes=1))):
        response = client.post(
            "/api/v1/inventory/network-observations",
            json={
                "observations": [
                    {
                        "mac_address": "00:aa:bb:cc:dd:ee",
                        "ip_address": "10.30.0.50",
                        "source": "arp",
                        "collector_device_id": device["id"],
                        "interface_name": f"Vlan{vlan}",
                        "vlan_id": vlan,
                        "observed_at": observed_at.isoformat(),
                    }
                ]
            },
        )
        assert response.status_code == 200, response.text

    endpoint = client.get("/api/v1/endpoints").json()[0]
    assert len(endpoint["current_ips"]) == 1
    assert endpoint["current_ips"][0]["vlan_id"] == 20
    assert len(endpoint["current_attachments"]) == 1
    assert endpoint["current_attachments"][0]["interface_name"] == "Vlan20"

