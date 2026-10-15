from __future__ import annotations

import json
from datetime import UTC, datetime


TOPOLOGY_SPEC = {
    "artifact_name": "hq-access-topology",
    "description": "Show HQ infrastructure and attached wired and Wi-Fi endpoints.",
    "node_types": ["device", "endpoint"],
    "edge_types": [
        "wired_attachment",
        "wireless_association",
        "ip_observation",
    ],
    "device_kinds": ["switch", "wireless_controller"],
    "sites": ["HQ"],
    "enabled_devices_only": True,
    "active_edges_only": True,
    "layout": "force",
    "group_by": "kind",
    "max_nodes": 50,
    "max_edges": 100,
}


class FakeResponse:
    def __init__(self, document):
        self.body = json.dumps(
            {
                "choices": [
                    {"message": {"content": json.dumps(document)}}
                ],
                "usage": {"total_tokens": 33},
            }
        ).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, limit):
        return self.body[:limit]


class FakeOpener:
    def __init__(self, documents):
        self.documents = list(documents)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeResponse(self.documents.pop(0))


def configure_route(client):
    provider = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "topology-author-provider",
            "provider_type": "openai_compatible",
            "base_url": "https://models.example.test/v1",
            "auth_type": "none",
            "created_by": "platform.admin",
        },
    ).json()
    model = client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": provider["id"],
            "display_name": "Topology author",
            "model_name": "topology-author",
            "capabilities": ["chat", "json_schema"],
            "created_by": "platform.admin",
        },
    ).json()
    route = client.post(
        "/api/v1/ai/routes",
        json={
            "purpose": "capability.authoring",
            "primary_model_id": model["id"],
            "created_by": "platform.admin",
        },
    )
    assert route.status_code == 201, route.text
    return route.json(), model


def create_device(client, *, name, kind, address):
    response = client.post(
        "/api/v1/devices",
        json={
            "name": name,
            "kind": kind,
            "management_ip": address,
            "site": "HQ",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def seed_topology(client):
    switch = create_device(
        client,
        name="core-hq-01",
        kind="switch",
        address="10.0.0.10",
    )
    controller = create_device(
        client,
        name="wlc-hq-01",
        kind="wireless_controller",
        address="10.0.0.20",
    )
    now = datetime.now(UTC).isoformat()
    network = client.post(
        "/api/v1/inventory/network-observations",
        json={
            "observations": [
                {
                    "mac_address": "00:1b:44:11:3a:b7",
                    "ip_address": "10.20.1.10",
                    "source": "arp",
                    "collector_device_id": switch["id"],
                    "interface_name": "Vlan120",
                    "vlan_id": 120,
                    "hostname": "ops-laptop",
                    "username": "must-not-enter-preview",
                    "observed_at": now,
                    "raw_data": {"private_vendor_field": "omit-me"},
                }
            ]
        },
    )
    assert network.status_code == 200, network.text
    wireless = client.post(
        "/api/v1/inventory/wireless-snapshots",
        json={
            "controller_id": controller["id"],
            "complete_snapshot": True,
            "observed_at": now,
            "clients": [
                {
                    "mac_address": "a4:83:e7:10:2f:91",
                    "ip_address": "10.30.1.54",
                    "hostname": "mobile-client",
                    "username": "also-private",
                    "access_point": "AP-HQ-01",
                    "ssid": "CORP",
                    "vlan_id": 131,
                    "rssi": -55,
                    "observed_at": now,
                    "raw_data": {"controller_blob": "omit-me"},
                }
            ],
        },
    )
    assert wireless.status_code == 200, wireless.text


def create_session(client):
    response = client.post(
        "/api/v1/capability-studio/sessions/topologies",
        json={
            "title": "HQ access topology",
            "brief": (
                "Create a grouped view of HQ switches, wireless controllers, "
                "and their currently attached endpoints."
            ),
            "created_by": "topology.author",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_topology_studio_generates_bounded_minimized_preview_and_publishes(
    client,
    monkeypatch,
):
    seed_topology(client)
    route, model = configure_route(client)
    opener = FakeOpener([TOPOLOGY_SPEC])
    monkeypatch.setattr(
        "icheck.services.structured_model.build_opener",
        lambda *_handlers: opener,
    )
    created = create_session(client)
    assert created["artifact_kind"] == "topology"

    generated = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/generate",
        json={"actor": "topology.author"},
    )
    assert generated.status_code == 200, generated.text
    document = generated.json()
    assert document["status"] == "validated"
    assert document["route_id"] == route["id"]
    assert document["model_id"] == model["id"]
    assert document["tokens_used"] == 33
    report = document["messages"][-1]["structured_content"][
        "validation_report"
    ]
    assert report["runtime"] == "icheck_topology_view_v1"
    assert report["isolation"] == "declarative_view"
    assert report["layout"] == "force"
    preview = report["preview"]
    assert preview["node_count"] == 4
    # The Wi-Fi snapshot contributes both association and controller-sourced
    # IP-observation relationships, in addition to the wired attachment/IP pair.
    assert preview["edge_count"] == 4
    assert {item["node_type"] for item in preview["nodes"]} == {
        "device",
        "endpoint",
    }
    assert {item["edge_type"] for item in preview["edges"]} == {
        "wired_attachment",
        "wireless_association",
        "ip_observation",
    }
    preview_document = json.dumps(preview)
    assert "00:1b:44:11:3a:b7" in preview_document
    assert "10.20.1.10" in preview_document
    assert "must-not-enter-preview" not in preview_document
    assert "also-private" not in preview_document
    assert "private_vendor_field" not in preview_document
    assert "controller_blob" not in preview_document

    request = json.loads(opener.requests[0][0].data)
    prompt = json.loads(request["messages"][1]["content"])
    catalog = prompt["inventory_catalog"]
    assert catalog["device_count"] == 2
    assert catalog["endpoint_count"] == 2
    assert catalog["device_kinds"] == ["switch", "wireless_controller"]
    assert "core-hq-01" not in json.dumps(catalog)
    assert "00:1b:44:11:3a:b7" not in json.dumps(catalog)

    artifact = client.get(
        f"/api/v1/artifacts/{document['artifact_id']}"
    ).json()
    assert artifact["kind"] == "topology"
    assert artifact["versions"][0]["definition"]["format_version"] == (
        "icheck.topology/v1"
    )
    published = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/publish",
        json={"actor": "topology.publisher", "expected_artifact_version_id": document["artifact_version_id"]},
    )
    assert published.status_code == 200, published.text
    assert published.json()["status"] == "published"


def test_topology_rejects_model_selectors_not_present_in_inventory(
    client,
    monkeypatch,
):
    seed_topology(client)
    configure_route(client)
    invalid = {**TOPOLOGY_SPEC, "sites": ["Imaginary Site"]}
    opener = FakeOpener([invalid])
    monkeypatch.setattr(
        "icheck.services.structured_model.build_opener",
        lambda *_handlers: opener,
    )
    created = create_session(client)
    generated = client.post(
        f"/api/v1/capability-studio/sessions/{created['id']}/generate",
        json={"actor": "topology.author"},
    )
    assert generated.status_code == 422, generated.text
    assert "unavailable sites" in generated.text
    failed = client.get(
        f"/api/v1/capability-studio/sessions/{created['id']}"
    ).json()
    assert failed["status"] == "failed"
    assert failed["artifact_id"] is None
    assert failed["tokens_used"] == 33
