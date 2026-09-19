from types import SimpleNamespace

import pytest

from icheck import collector_worker
from icheck import device_preflight_worker as preflights


BASE_OPTIONS = {
    "allowed_targets": ["10.20.0.0/16"],
    "timeout_seconds": 5,
    "snmp_exporter_url": None,
    "exporter_allowed_hosts": ["127.0.0.1"],
    "snmp_allowed_targets": ["10.20.0.0/16"],
    "lease_seconds": 60,
}


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class FakeClient:
    def __init__(self):
        self.calls = []

    def request(self, method, path, payload=None, **_):
        self.calls.append((method, path, payload))
        return {}


def test_tcp_preflight_is_allowlisted_and_reports_transport_scope(monkeypatch):
    calls = []

    def connect(address, *, timeout):
        calls.append((address, timeout))
        return FakeSocket()

    monkeypatch.setattr(preflights.socket, "create_connection", connect)
    evidence, latency = preflights.execute_device_preflight(
        {
            "target_host": "10.20.0.20",
            "adapter_type": "ssh",
            "port": 22,
        },
        **BASE_OPTIONS,
    )
    assert calls == [(("10.20.0.20", 22), 5)]
    assert latency >= 0
    assert evidence == {
        "check": "tcp_connect",
        "verification_level": "transport",
        "authentication_tested": False,
        "reachable": True,
        "port": 22,
        "address_family": 4,
    }

    with pytest.raises(preflights.DevicePreflightFailure, match="not allowlisted"):
        preflights.execute_device_preflight(
            {
                "target_host": "192.0.2.10",
                "adapter_type": "ssh",
                "port": 22,
            },
            **BASE_OPTIONS,
        )
    assert len(calls) == 1


def test_icmp_preflight_uses_argument_array_without_capturing_output(monkeypatch):
    observed = {}
    monkeypatch.setattr(preflights.shutil, "which", lambda _: "/usr/bin/ping")

    def run(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(preflights.subprocess, "run", run)
    evidence, _ = preflights.execute_device_preflight(
        {
            "target_host": "10.20.1.1",
            "adapter_type": "icmp",
            "port": None,
        },
        **BASE_OPTIONS,
    )
    assert observed["command"][-1] == "10.20.1.1"
    assert "shell" not in observed["kwargs"]
    assert evidence["reachable"] is True
    assert evidence["verification_level"] == "network_reachability"


def test_snmp_preflight_requires_exporter_and_reports_bounded_query(monkeypatch):
    assignment = {
        "target_host": "10.20.2.2",
        "adapter_type": "snmp_exporter",
        "port": 161,
        "configuration": {"modules": ["if_mib"], "auth_module": "lab_v3"},
    }
    with pytest.raises(
        preflights.DevicePreflightFailure,
        match="requires a site-local SNMP Exporter",
    ):
        preflights.execute_device_preflight(assignment, **BASE_OPTIONS)

    captured = {}

    def collect(value):
        captured.update(value)
        return [{"kind": "observation"}, {"kind": "observation"}]

    monkeypatch.setattr(preflights, "collect_snmp_exporter", collect)
    evidence, _ = preflights.execute_device_preflight(
        assignment,
        **{**BASE_OPTIONS, "snmp_exporter_url": "http://127.0.0.1:9116"},
    )
    assert captured["target"] == {
        "exporter_url": "http://127.0.0.1:9116",
        "target": "10.20.2.2",
    }
    assert captured["configuration"]["max_metrics"] == 100
    assert evidence["verification_level"] == "protocol_query"
    assert evidence["sample_count"] == 2
    assert evidence["auth_module"] == "lab_v3"


def test_worker_reports_bounded_success_and_failure_evidence(monkeypatch):
    client = FakeClient()
    assignment = {
        "preflight_id": "preflight-1",
        "lease_token": "lease-token-value",
        "target_host": "10.20.0.20",
        "adapter_type": "ssh",
        "port": 22,
    }
    monkeypatch.setattr(
        collector_worker,
        "execute_device_preflight",
        lambda *_, **__: ({"check": "tcp_connect", "reachable": True}, 7),
    )
    assert collector_worker.run_device_preflight(
        client,
        "worker-1",
        assignment,
        **BASE_OPTIONS,
    )
    payload = client.calls[-1][2]
    assert payload == {
        "lease_token": "lease-token-value",
        "status": "verified",
        "latency_ms": 7,
        "evidence": {"check": "tcp_connect", "reachable": True},
    }

    def fail(*_, **__):
        raise preflights.DevicePreflightFailure(
            "connection refused",
            {"check": "tcp_connect", "reachable": False},
            9,
        )

    monkeypatch.setattr(collector_worker, "execute_device_preflight", fail)
    assert not collector_worker.run_device_preflight(
        client,
        "worker-1",
        {**assignment, "preflight_id": "preflight-2"},
        **BASE_OPTIONS,
    )
    failed_payload = client.calls[-1][2]
    assert failed_payload["status"] == "failed"
    assert failed_payload["error"] == "connection refused"
    assert failed_payload["evidence"]["reachable"] is False
