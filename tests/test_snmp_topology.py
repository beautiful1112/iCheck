from urllib.parse import parse_qs, urlsplit

import pytest

from icheck.builtin_artifacts import snmp_topology_artifact_payload
from icheck.collectors.snmp_topology import collect_snmp_topology


class FakeResponse:
    def __init__(self, body: str):
        self.body = body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, limit):
        return self.body[:limit]


class FakeOpener:
    def __init__(self, requests, body: str):
        self.requests = requests
        self.body = body

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeResponse(self.body)


def topology_assignment():
    return {
        "artifact_name": "builtin-snmp-device-adjacency",
        "output_kinds": ["relationship"],
        "target": {
            "exporter_url": "http://127.0.0.1:9116",
            "target": "10.20.30.40",
            "local_device_key": "core-01",
            "local_display_name": "Core 01",
        },
        "defaults": {
            "protocol": "lldp",
            "modules": ["icheck_lldp"],
            "auth_module": "network_v3",
            "neighbor_metric": "icheck_lldp_neighbor_info",
            "scrape_health_metric": "snmp_scrape_walk_duration_seconds",
            "local_port_label": "local_port",
            "remote_device_key_labels": [
                "remote_chassis_id",
                "remote_system_name",
            ],
            "remote_system_name_label": "remote_system_name",
            "remote_port_label": "remote_port",
            "remote_management_ip_label": "remote_management_ip",
            "complete_snapshot": True,
            "max_neighbors": 100,
        },
        "configuration": {},
        "_runtime": {
            "exporter_allowed_hosts": ["127.0.0.1"],
            "snmp_allowed_targets": ["10.0.0.0/8"],
            "lease_seconds": 60,
        },
    }


def test_snmp_topology_builds_a_bounded_complete_snapshot(monkeypatch):
    body = (
        "# TYPE snmp_scrape_walk_duration_seconds gauge\n"
        'snmp_scrape_walk_duration_seconds{module="icheck_lldp"} 0.12\n'
        "# TYPE icheck_lldp_neighbor_info gauge\n"
        'icheck_lldp_neighbor_info{local_port="Gi0/2",'
        'remote_chassis_id="00:11:22:33:44:66",'
        'remote_system_name="access-02",remote_port="Gi0/48",'
        'remote_management_ip="10.20.30.42"} 1\n'
        'icheck_lldp_neighbor_info{local_port="Gi0/1",'
        'remote_chassis_id="00:11:22:33:44:55",'
        'remote_system_name="access-01",remote_port="Gi0/48",'
        'remote_management_ip="10.20.30.41"} 1\n'
    )
    requests = []
    monkeypatch.setattr(
        "icheck.collectors.snmp_exporter.build_opener",
        lambda *handlers: FakeOpener(requests, body),
    )

    envelopes = collect_snmp_topology(topology_assignment())

    assert len(envelopes) == 1
    envelope = envelopes[0]
    assert envelope["kind"] == "relationship"
    assert envelope["type"] == "icheck.network.device-adjacency-snapshot/v1"
    assert envelope["subject"] == "core-01"
    assert len(envelope["idempotency_key"]) == 64
    assert envelope["payload"] == {
        "local_device_key": "core-01",
        "local_display_name": "Core 01",
        "protocol": "lldp",
        "complete_snapshot": True,
        "neighbors": [
            {
                "remote_device_key": "00:11:22:33:44:55",
                "remote_system_name": "access-01",
                "local_port": "Gi0/1",
                "remote_port": "Gi0/48",
                "management_ip": "10.20.30.41",
            },
            {
                "remote_device_key": "00:11:22:33:44:66",
                "remote_system_name": "access-02",
                "local_port": "Gi0/2",
                "remote_port": "Gi0/48",
                "management_ip": "10.20.30.42",
            },
        ],
    }
    query = parse_qs(urlsplit(requests[0][0].full_url).query)
    assert query == {
        "target": ["10.20.30.40"],
        "auth": ["network_v3"],
        "module": ["icheck_lldp"],
    }


def test_complete_topology_snapshot_requires_scrape_health_evidence(monkeypatch):
    body = (
        "# TYPE icheck_lldp_neighbor_info gauge\n"
        'icheck_lldp_neighbor_info{local_port="Gi0/1",'
        'remote_chassis_id="00:11:22:33:44:55",'
        'remote_system_name="access-01",remote_port="Gi0/48"} 1\n'
    )
    monkeypatch.setattr(
        "icheck.collectors.snmp_exporter.build_opener",
        lambda *handlers: FakeOpener([], body),
    )

    with pytest.raises(ValueError, match="scrape_health_metric"):
        collect_snmp_topology(topology_assignment())


def test_builtin_snmp_topology_artifact_validates_publishes_and_deploys(client):
    created = client.post(
        "/api/v1/artifacts",
        json=snmp_topology_artifact_payload(),
    )
    assert created.status_code == 201, created.text
    version_id = created.json()["versions"][0]["id"]
    validated = client.post(
        f"/api/v1/artifact-versions/{version_id}/validate",
        json={"actor": "system.bootstrap"},
    )
    assert validated.status_code == 200, validated.text
    published = client.post(
        f"/api/v1/artifact-versions/{version_id}/publish",
        json={"actor": "system.bootstrap"},
    )
    assert published.status_code == 200, published.text
    deployment = client.post(
        "/api/v1/collector-deployments",
        json={
            "name": "lldp-core-01",
            "artifact_version_id": version_id,
            "scope_site": "HQ",
            "target": {
                "exporter_url": "http://127.0.0.1:9116",
                "target": "10.20.30.40",
                "local_device_key": "core-01",
            },
            "configuration": {
                "auth_module": "network_v3",
            },
            "worker_selector": {"site": "HQ"},
            "schedule_seconds": 300,
            "created_by": "network.operator",
        },
    )
    assert deployment.status_code == 201, deployment.text

