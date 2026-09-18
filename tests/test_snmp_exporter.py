from urllib.parse import parse_qs, urlsplit

import pytest

from icheck.builtin_artifacts import snmp_exporter_artifact_payload
from icheck.collectors.snmp_exporter import collect_snmp_exporter


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, limit):
        body = (
            "# HELP ifHCInOctets Bytes received\n"
            "# TYPE ifHCInOctets counter\n"
            'ifHCInOctets{ifIndex="1",ifName="Gi0/1"} 12345\n'
            "# TYPE sysUpTime gauge\n"
            "sysUpTime 42\n"
        ).encode("utf-8")
        return body[:limit]


class FakeOpener:
    def __init__(self, requests):
        self.requests = requests

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeResponse()


def snmp_assignment(target="10.20.30.40"):
    return {
        "artifact_name": "builtin-snmp-exporter",
        "output_kinds": ["observation"],
        "target": {
            "exporter_url": "http://127.0.0.1:9116",
            "target": target,
        },
        "defaults": {
            "modules": ["if_mib", "system"],
            "auth_module": "network_v3",
            "timeout_seconds": 10,
            "max_metrics": 100,
            "include_metric_prefixes": ["ifHC"],
        },
        "configuration": {},
        "_runtime": {
            "exporter_allowed_hosts": ["127.0.0.1"],
            "snmp_allowed_targets": ["10.0.0.0/8"],
            "lease_seconds": 60,
        },
    }


def test_snmp_exporter_normalizes_selected_metrics(monkeypatch):
    requests = []
    monkeypatch.setattr(
        "icheck.collectors.snmp_exporter.build_opener",
        lambda *handlers: FakeOpener(requests),
    )
    envelopes = collect_snmp_exporter(snmp_assignment())
    assert len(envelopes) == 1
    envelope = envelopes[0]
    assert envelope["kind"] == "observation"
    assert envelope["type"] == "metric.sample"
    assert envelope["subject"] == "10.20.30.40"
    assert envelope["payload"] == {
        "metric": "ifHCInOctets_total",
        "labels": {"ifIndex": "1", "ifName": "Gi0/1"},
        "value": 12345.0,
        "target": "10.20.30.40",
        "modules": ["if_mib", "system"],
        "auth_module": "network_v3",
    }
    query = parse_qs(urlsplit(requests[0][0].full_url).query)
    assert query == {
        "target": ["10.20.30.40"],
        "auth": ["network_v3"],
        "module": ["if_mib", "system"],
    }


def test_snmp_exporter_target_allowlist_fails_closed(monkeypatch):
    monkeypatch.setattr(
        "icheck.collectors.snmp_exporter.build_opener",
        lambda *handlers: FakeOpener([]),
    )
    with pytest.raises(ValueError, match="SNMP target host"):
        collect_snmp_exporter(snmp_assignment("169.254.169.254"))


def test_builtin_snmp_artifact_validates_publishes_and_deploys(client):
    created = client.post(
        "/api/v1/artifacts",
        json=snmp_exporter_artifact_payload(),
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
            "name": "snmp-edge-01",
            "artifact_version_id": version_id,
            "target": {
                "exporter_url": "http://127.0.0.1:9116",
                "target": "10.20.30.40",
            },
            "configuration": {
                "modules": ["if_mib"],
                "auth_module": "network_v3",
                "include_metric_prefixes": ["ifHC", "sysUpTime"],
            },
            "worker_selector": {"site": "HQ"},
            "schedule_seconds": 300,
            "created_by": "network.operator",
        },
    )
    assert deployment.status_code == 201, deployment.text
