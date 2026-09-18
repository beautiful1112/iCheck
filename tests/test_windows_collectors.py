from urllib.parse import parse_qs, urlsplit

import pytest

from icheck.builtin_artifacts import (
    psrp_cim_artifact_payload,
    windows_exporter_artifact_payload,
)
from icheck.collectors.psrp_cim import CIM_OPERATIONS, collect_psrp_cim
from icheck.collectors.windows_exporter import collect_windows_exporter


REGISTRATION_HEADERS = {
    "X-iCheck-Registration-Token": "test-registration-token"
}


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, limit):
        body = (
            "# TYPE windows_cpu_time_seconds_total counter\n"
            'windows_cpu_time_seconds_total{core="0",mode="idle"} 123\n'
            "# TYPE go_goroutines gauge\n"
            "go_goroutines 8\n"
        ).encode("utf-8")
        return body[:limit]


class FakeOpener:
    def __init__(self, requests):
        self.requests = requests

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeResponse()


def windows_exporter_assignment(host="10.20.7.42"):
    return {
        "artifact_name": "builtin-windows-exporter",
        "output_kinds": ["observation"],
        "target": {"url": f"http://{host}:9182/metrics"},
        "defaults": {
            "collectors": ["cpu", "os"],
            "include_metric_prefixes": ["windows_"],
            "timeout_seconds": 10,
            "max_metrics": 100,
            "max_response_bytes": 1_000_000,
        },
        "configuration": {},
        "_runtime": {
            "windows_exporter_allowed_hosts": ["10.20.0.0/16"],
            "lease_seconds": 60,
        },
    }


def psrp_assignment(executor=None, operations=None):
    return {
        "artifact_name": "builtin-psrp-cim-diagnostics",
        "output_kinds": ["observation"],
        "credential_profile_ref": "windows-readonly",
        "target": {"host": "win-app-01.example.test", "use_ssl": True},
        "defaults": {
            "operations": operations or ["operating_system"],
            "timeout_seconds": 10,
            "max_records": 50,
            "max_response_bytes": 100_000,
        },
        "configuration": {},
        "_runtime": {
            "windows_allowed_targets": ["*.example.test"],
            "lease_seconds": 60,
            "psrp_cim_executor": executor,
        },
    }


def publish_artifact(client, payload):
    created = client.post("/api/v1/artifacts", json=payload)
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
    return version_id


def test_windows_exporter_normalizes_only_selected_metrics(monkeypatch):
    requests = []
    monkeypatch.setattr(
        "icheck.collectors.windows_exporter.build_opener",
        lambda *handlers: FakeOpener(requests),
    )
    envelopes = collect_windows_exporter(windows_exporter_assignment())
    assert len(envelopes) == 1
    assert envelopes[0]["type"] == "metric.sample"
    assert envelopes[0]["subject"] == "10.20.7.42"
    assert envelopes[0]["payload"] == {
        "exporter": "windows_exporter",
        "metric": "windows_cpu_time_seconds_total",
        "labels": {"core": "0", "mode": "idle"},
        "value": 123.0,
        "target": "10.20.7.42",
        "collectors": ["cpu", "os"],
    }
    query = parse_qs(urlsplit(requests[0][0].full_url).query)
    assert query == {"collect[]": ["cpu", "os"]}


def test_windows_exporter_target_allowlist_fails_closed(monkeypatch):
    monkeypatch.setattr(
        "icheck.collectors.windows_exporter.build_opener",
        lambda *handlers: FakeOpener([]),
    )
    with pytest.raises(ValueError, match="Windows exporter host"):
        collect_windows_exporter(windows_exporter_assignment("169.254.169.254"))


def test_psrp_cim_uses_only_published_read_only_template():
    calls = []

    def executor(**kwargs):
        calls.append(kwargs)
        return {"Caption": "Windows Server 2025", "BuildNumber": "26100"}

    envelopes = collect_psrp_cim(psrp_assignment(executor))
    assert len(envelopes) == 1
    assert envelopes[0]["type"] == "windows.cim.operating_system"
    assert envelopes[0]["payload"]["data"]["BuildNumber"] == "26100"
    assert calls[0]["script"] == CIM_OPERATIONS["operating_system"]
    assert calls[0]["credential_profile_ref"] == "windows-readonly"
    assert calls[0]["use_ssl"] is True

    with pytest.raises(ValueError, match="Unsupported read-only CIM operation"):
        collect_psrp_cim(psrp_assignment(executor, ["invoke_expression"]))


def test_psrp_cim_fails_closed_without_credential_executor():
    with pytest.raises(RuntimeError, match="credential-provider-backed"):
        collect_psrp_cim(psrp_assignment())


def test_windows_artifacts_and_on_demand_diagnostic_lifecycle(client):
    windows_version_id = publish_artifact(
        client,
        windows_exporter_artifact_payload(),
    )
    windows_deployment = client.post(
        "/api/v1/collector-deployments",
        json={
            "name": "windows-metrics-preview",
            "artifact_version_id": windows_version_id,
            "target": {"url": "http://10.20.7.42:9182/metrics"},
            "configuration": {"collectors": ["cpu", "os"]},
            "worker_selector": {"site": "HQ"},
            "created_by": "windows.operator",
        },
    )
    assert windows_deployment.status_code == 201, windows_deployment.text
    assert windows_deployment.json()["execution_mode"] == "scheduled"

    psrp_version_id = publish_artifact(client, psrp_cim_artifact_payload())
    credential = client.post(
        "/api/v1/credential-profiles",
        json={
            "name": "windows-readonly",
            "provider": "vault",
            "secret_ref": "kv/windows/readonly",
            "allowed_adapters": ["psrp_cim"],
            "worker_selector": {"site": "HQ"},
            "created_by": "security.operator",
        },
    )
    assert credential.status_code == 201, credential.text

    scheduled_diagnostic = client.post(
        "/api/v1/collector-deployments",
        json={
            "name": "scheduled-windows-diagnostics",
            "artifact_version_id": psrp_version_id,
            "target": {"host": "win-app-01.example.test", "use_ssl": True},
            "configuration": {"operations": ["operating_system"]},
            "worker_selector": {"site": "HQ"},
            "credential_profile_ref": "windows-readonly",
            "created_by": "windows.operator",
        },
    )
    assert scheduled_diagnostic.status_code == 422
    assert "on_demand" in scheduled_diagnostic.text

    missing_credential = client.post(
        "/api/v1/collector-deployments",
        json={
            "name": "unsafe-windows-diagnostics",
            "artifact_version_id": psrp_version_id,
            "target": {"host": "win-app-01.example.test", "use_ssl": True},
            "configuration": {"operations": ["operating_system"]},
            "worker_selector": {"site": "HQ"},
            "execution_mode": "on_demand",
            "created_by": "windows.operator",
        },
    )
    assert missing_credential.status_code == 422
    assert "credential_profile_ref" in missing_credential.text

    deployment = client.post(
        "/api/v1/collector-deployments",
        json={
            "name": "windows-diagnostics",
            "artifact_version_id": psrp_version_id,
            "target": {"host": "win-app-01.example.test", "use_ssl": True},
            "configuration": {"operations": ["operating_system"]},
            "worker_selector": {"site": "HQ"},
            "credential_profile_ref": "windows-readonly",
            "execution_mode": "on_demand",
            "created_by": "windows.operator",
        },
    )
    assert deployment.status_code == 201, deployment.text
    deployment_id = deployment.json()["id"]
    assert deployment.json()["next_run_at"] is None
    assert deployment.json()["credential_profile_ref"] == "windows-readonly"

    worker_registration = client.post(
        "/api/v1/collector-workers/register",
        json={
            "name": "windows-diagnostics-hq-01",
            "site": "HQ",
            "capabilities": ["psrp_cim"],
        },
        headers=REGISTRATION_HEADERS,
    )
    assert worker_registration.status_code == 200, worker_registration.text
    registration = worker_registration.json()
    worker_id = registration["worker"]["id"]
    worker_headers = {
        "Authorization": f"Bearer {registration['access_token']}"
    }
    no_work = client.post(
        f"/api/v1/collector-workers/{worker_id}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 120},
        headers=worker_headers,
    )
    assert no_work.status_code == 200
    assert no_work.json() == []

    triggered = client.post(
        f"/api/v1/collector-deployments/{deployment_id}/trigger",
        json={
            "actor": "windows.operator",
            "reason": "Investigate application latency",
        },
    )
    assert triggered.status_code == 200, triggered.text
    assert triggered.json()["next_run_at"] is not None

    claimed = client.post(
        f"/api/v1/collector-workers/{worker_id}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 120},
        headers=worker_headers,
    )
    assert claimed.status_code == 200, claimed.text
    assignment = claimed.json()[0]
    assert assignment["adapter_type"] == "psrp_cim"
    assert assignment["credential_profile_ref"] == "windows-readonly"

    completed = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/complete",
        json={
            "lease_token": assignment["lease_token"],
            "status": "succeeded",
            "stats": {"operations": 1},
        },
        headers=worker_headers,
    )
    assert completed.status_code == 200, completed.text
    stored = {
        item["id"]: item
        for item in client.get("/api/v1/collector-deployments").json()
    }[deployment_id]
    assert stored["next_run_at"] is None

    triggered_events = client.get(
        "/api/v1/audit-events?event_type=collector.deployment.triggered"
    ).json()
    assert len(triggered_events) == 1
    assert triggered_events[0]["details"] == {
        "reason": "Investigate application latency"
    }
