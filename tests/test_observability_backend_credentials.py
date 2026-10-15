import base64
import json
from urllib.error import URLError


class FakeResponse:
    def __init__(self, document):
        self.body = json.dumps(document).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, limit):
        return self.body[:limit]


class RecordingOpener:
    def __init__(self, requests, document):
        self.requests = requests
        self.document = document

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeResponse(self.document)


class SecretEchoingErrorOpener:
    def __init__(self, secret):
        self.secret = secret

    def open(self, request, timeout):
        raise URLError(f"upstream rejected {self.secret}")


PROMETHEUS_SUCCESS = {
    "status": "success",
    "data": {"resultType": "vector", "result": []},
}

LOKI_SUCCESS = {
    "status": "success",
    "data": {"resultType": "streams", "result": []},
}


def _credential(
    client,
    *,
    name,
    environment_name,
    allowed_adapters,
    worker_selector=None,
):
    response = client.post(
        "/api/v1/credential-profiles",
        json={
            "name": name,
            "provider": "environment",
            "secret_ref": f"env://{environment_name}",
            "allowed_adapters": allowed_adapters,
            "worker_selector": worker_selector or {},
            "created_by": "security.operator",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _query_metric(client, backend_id):
    return client.post(
        f"/api/v1/metrics/backends/{backend_id}/query",
        json={"query": "up", "actor": "ai.l1.operator"},
    )


def _query_logs(client, backend_id):
    return client.post(
        f"/api/v1/logs/backends/{backend_id}/query-range",
        json={
            "query": '{job="system"}',
            "start": "2026-09-29T12:00:00Z",
            "end": "2026-09-29T12:05:00Z",
            "actor": "ai.l1.operator",
        },
    )


def _headers(request):
    return {key.lower(): value for key, value in request.header_items()}


def test_prometheus_bearer_and_basic_credentials_are_request_local(
    client,
    monkeypatch,
):
    bearer_secret = "prometheus-bearer-secret"
    basic_secret = "metrics-reader:correct-horse-battery-staple"
    monkeypatch.setenv("ICHECK_TEST_PROMETHEUS_BEARER", bearer_secret)
    monkeypatch.setenv("ICHECK_TEST_PROMETHEUS_BASIC", basic_secret)
    _credential(
        client,
        name="prometheus-bearer",
        environment_name="ICHECK_TEST_PROMETHEUS_BEARER",
        allowed_adapters=["prometheus_query"],
    )
    _credential(
        client,
        name="prometheus-basic",
        environment_name="ICHECK_TEST_PROMETHEUS_BASIC",
        allowed_adapters=["prometheus_query"],
    )
    requests = []
    monkeypatch.setattr(
        "icheck.services.metrics.build_opener",
        lambda *_handlers: RecordingOpener(requests, PROMETHEUS_SUCCESS),
    )

    bearer = client.post(
        "/api/v1/metrics/backends",
        json={
            "name": "authenticated-prometheus",
            "provider": "prometheus",
            "query_base_url": "https://prometheus.example.test",
            "auth_type": "bearer",
            "credential_profile_ref": "prometheus-bearer",
            "created_by": "metrics.operator",
        },
    )
    assert bearer.status_code == 201, bearer.text
    assert bearer.json()["auth_type"] == "bearer"
    assert _query_metric(client, bearer.json()["id"]).status_code == 200
    assert _headers(requests[-1][0])["authorization"] == (
        f"Bearer {bearer_secret}"
    )

    basic = client.post(
        "/api/v1/metrics/backends",
        json={
            "name": "basic-prometheus",
            "provider": "prometheus",
            "query_base_url": "https://prometheus.example.test",
            "auth_type": "basic",
            "credential_profile_ref": "prometheus-basic",
            "created_by": "metrics.operator",
        },
    )
    assert basic.status_code == 201, basic.text
    assert _query_metric(client, basic.json()["id"]).status_code == 200
    encoded = base64.b64encode(basic_secret.encode("utf-8")).decode("ascii")
    assert _headers(requests[-1][0])["authorization"] == f"Basic {encoded}"

    external_state = json.dumps(
        {
            "backends": client.get("/api/v1/metrics/backends").json(),
            "audits": client.get("/api/v1/audit-events").json(),
        }
    )
    assert bearer_secret not in external_state
    assert basic_secret not in external_state
    assert encoded not in external_state


def test_loki_custom_header_and_error_redaction(client, monkeypatch):
    secret = "tenant-secret-that-must-not-leak"
    monkeypatch.setenv("ICHECK_TEST_LOKI_HEADER", secret)
    _credential(
        client,
        name="loki-tenant-header",
        environment_name="ICHECK_TEST_LOKI_HEADER",
        allowed_adapters=["loki_query"],
    )
    requests = []
    success_with_echo = {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {"instance": "app-01", "job": "system"},
                    "values": [["1790683200000000000", f"echoed {secret}"]],
                }
            ],
        },
    }
    monkeypatch.setattr(
        "icheck.services.logs.build_opener",
        lambda *_handlers: RecordingOpener(requests, success_with_echo),
    )
    backend = client.post(
        "/api/v1/logs/backends",
        json={
            "name": "authenticated-loki",
            "provider": "loki",
            "query_base_url": "https://loki.example.test",
            "auth_type": "header",
            "auth_header_name": "X-Scope-OrgID",
            "credential_profile_ref": "loki-tenant-header",
            "created_by": "logs.operator",
        },
    )
    assert backend.status_code == 201, backend.text
    assert backend.json()["auth_header_name"] == "X-Scope-OrgID"
    response = _query_logs(client, backend.json()["id"])
    assert response.status_code == 200, response.text
    assert _headers(requests[-1][0])["x-scope-orgid"] == secret
    assert secret not in response.text
    assert "echoed [REDACTED]" in response.text

    monkeypatch.setattr(
        "icheck.services.logs.build_opener",
        lambda *_handlers: SecretEchoingErrorOpener(secret),
    )
    rejected = _query_logs(client, backend.json()["id"])
    assert rejected.status_code == 503
    assert secret not in rejected.text
    assert "[REDACTED]" in rejected.text
    assert secret not in json.dumps(client.get("/api/v1/audit-events").json())


def test_observability_auth_contract_rejects_unsafe_configuration(
    client,
    monkeypatch,
):
    missing_profile = client.post(
        "/api/v1/metrics/backends",
        json={
            "name": "missing-profile",
            "provider": "prometheus",
            "query_base_url": "https://prometheus.example.test",
            "auth_type": "bearer",
            "created_by": "metrics.operator",
        },
    )
    assert missing_profile.status_code == 422
    assert "credential_profile_ref is required" in missing_profile.text

    monkeypatch.setenv("ICHECK_TEST_OBSERVABILITY_AUTH", "value")
    profile = _credential(
        client,
        name="observability-auth",
        environment_name="ICHECK_TEST_OBSERVABILITY_AUTH",
        allowed_adapters=["loki_query"],
    )
    none_with_profile = client.post(
        "/api/v1/logs/backends",
        json={
            "name": "ambiguous-auth",
            "provider": "loki",
            "query_base_url": "https://loki.example.test",
            "credential_profile_ref": profile["id"],
            "created_by": "logs.operator",
        },
    )
    assert none_with_profile.status_code == 422
    assert "must be empty" in none_with_profile.text

    protected_header = client.post(
        "/api/v1/logs/backends",
        json={
            "name": "protected-header",
            "provider": "loki",
            "query_base_url": "https://loki.example.test",
            "auth_type": "header",
            "auth_header_name": "Authorization",
            "credential_profile_ref": profile["id"],
            "created_by": "logs.operator",
        },
    )
    assert protected_header.status_code == 422
    assert "protected HTTP header" in protected_header.text

    wrong_adapter = client.post(
        "/api/v1/metrics/backends",
        json={
            "name": "wrong-adapter",
            "provider": "prometheus",
            "query_base_url": "https://prometheus.example.test",
            "auth_type": "bearer",
            "credential_profile_ref": profile["id"],
            "created_by": "metrics.operator",
        },
    )
    assert wrong_adapter.status_code == 422
    assert "does not allow adapter" in wrong_adapter.text

    scoped_profile = _credential(
        client,
        name="worker-only-loki",
        environment_name="ICHECK_TEST_OBSERVABILITY_AUTH",
        allowed_adapters=["loki_query"],
        worker_selector={"site": "LAB"},
    )
    worker_scoped = client.post(
        "/api/v1/logs/backends",
        json={
            "name": "worker-scoped",
            "provider": "loki",
            "query_base_url": "https://loki.example.test",
            "auth_type": "bearer",
            "credential_profile_ref": scoped_profile["id"],
            "created_by": "logs.operator",
        },
    )
    assert worker_scoped.status_code == 422
    assert "must not be scoped to workers" in worker_scoped.text


def test_metric_backend_updates_are_revision_checked_and_audited(
    client,
    monkeypatch,
):
    secret = "rotatable-prometheus-token"
    monkeypatch.setenv("ICHECK_TEST_METRIC_UPDATE", secret)
    profile = _credential(
        client,
        name="metric-update-token",
        environment_name="ICHECK_TEST_METRIC_UPDATE",
        allowed_adapters=["prometheus_query"],
    )
    created = client.post(
        "/api/v1/metrics/backends",
        json={
            "name": "editable-prometheus",
            "provider": "prometheus",
            "query_base_url": "https://prometheus.example.test",
            "external_labels": {"region": "lab"},
            "created_by": "metrics.operator",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["revision"] == 0
    update_payload = {
        "expected_revision": 0,
        "name": "editable-prometheus",
        "provider": "prometheus",
        "query_base_url": "https://prometheus.example.test/prometheus",
        "remote_write_url": "https://metrics.example.test/api/v1/write",
        "auth_type": "bearer",
        "credential_profile_ref": profile["id"],
        "external_labels": {"region": "lab", "environment": "test"},
        "enabled": False,
        "actor": "metrics.operator",
    }
    updated = client.put(
        f"/api/v1/metrics/backends/{created.json()['id']}",
        json=update_payload,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["revision"] == 1
    assert updated.json()["auth_type"] == "bearer"
    assert updated.json()["enabled"] is False
    assert secret not in updated.text

    stale = client.put(
        f"/api/v1/metrics/backends/{created.json()['id']}",
        json=update_payload,
    )
    assert stale.status_code == 409
    assert "revision conflict" in stale.text

    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "metrics.backend.updated"},
    ).json()
    assert len(audits) == 1
    assert audits[0]["details"]["revision"] == 1
    assert "credential_profile" in audits[0]["details"]["changed_fields"]
    assert secret not in json.dumps(audits)


def test_log_backend_can_be_reconfigured_and_disabled(client, monkeypatch):
    secret = "loki-lifecycle-token"
    monkeypatch.setenv("ICHECK_TEST_LOG_UPDATE", secret)
    profile = _credential(
        client,
        name="log-update-token",
        environment_name="ICHECK_TEST_LOG_UPDATE",
        allowed_adapters=["loki_query"],
    )
    created = client.post(
        "/api/v1/logs/backends",
        json={
            "name": "editable-loki",
            "provider": "loki",
            "query_base_url": "https://loki.example.test",
            "created_by": "logs.operator",
        },
    )
    assert created.status_code == 201, created.text
    original = created.json()
    payload = {
        "expected_revision": 0,
        "name": original["name"],
        "provider": "loki",
        "query_base_url": original["query_base_url"],
        "auth_type": "header",
        "auth_header_name": "X-Scope-OrgID",
        "credential_profile_ref": profile["name"],
        "device_label": original["device_label"],
        "allowed_labels": original["allowed_labels"],
        "enabled": True,
        "actor": "logs.operator",
    }
    authenticated = client.put(
        f"/api/v1/logs/backends/{original['id']}",
        json=payload,
    )
    assert authenticated.status_code == 200, authenticated.text
    assert authenticated.json()["revision"] == 1
    assert authenticated.json()["auth_header_name"] == "X-Scope-OrgID"

    disabled = client.put(
        f"/api/v1/logs/backends/{original['id']}",
        json={**payload, "expected_revision": 1, "enabled": False},
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["revision"] == 2
    assert disabled.json()["enabled"] is False
    rejected = _query_logs(client, original["id"])
    assert rejected.status_code == 503
    assert "disabled" in rejected.text

    unsafe = client.put(
        f"/api/v1/logs/backends/{original['id']}",
        json={
            **payload,
            "expected_revision": 2,
            "auth_header_name": "Host",
        },
    )
    assert unsafe.status_code == 422
    stored = client.get("/api/v1/logs/backends").json()[0]
    assert stored["revision"] == 2
    assert stored["enabled"] is False
    assert secret not in json.dumps(client.get("/api/v1/audit-events").json())
