import json
from urllib.parse import parse_qs, urlsplit


class FakeResponse:
    def __init__(self, document):
        self.body = json.dumps(document).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, limit):
        return self.body[:limit]


class FakePrometheusOpener:
    def __init__(self, requests):
        self.requests = requests

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        fields = parse_qs(request.data.decode("utf-8"))
        if urlsplit(request.full_url).path.endswith("/query_range"):
            document = {
                "status": "success",
                "data": {
                    "resultType": "matrix",
                    "result": [
                        {
                            "metric": {
                                "__name__": "if_utilization_ratio",
                                "instance": "edge-01",
                            },
                            "values": [[1_789_689_600, "0.81"]],
                        }
                    ],
                },
                "warnings": ["partial data outside retention"],
            }
        else:
            document = {
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [
                        {
                            "metric": {"__name__": "up", "instance": "edge-01"},
                            "value": [1_789_689_600, "1"],
                        }
                    ],
                },
            }
        assert int(fields["limit"][0]) >= 1
        assert fields["timeout"][0].endswith("s")
        return FakeResponse(document)


class FakePrometheusErrorOpener:
    def open(self, request, timeout):
        return FakeResponse(
            {
                "status": "error",
                "errorType": "bad_data",
                "error": "invalid expression",
            }
        )


def create_metric_backend(client):
    response = client.post(
        "/api/v1/metrics/backends",
        json={
            "name": "regional-prometheus",
            "provider": "prometheus",
            "query_base_url": "https://prometheus.example.test/prometheus",
            "remote_write_url": "https://metrics.example.test/api/v1/write",
            "external_labels": {"region": "hkg"},
            "created_by": "metrics.operator",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_metric_backend_query_range_health_and_audit(client, monkeypatch):
    requests = []
    monkeypatch.setattr(
        "icheck.services.metrics.build_opener",
        lambda *handlers: FakePrometheusOpener(requests),
    )
    backend = create_metric_backend(client)

    instant = client.post(
        f"/api/v1/metrics/backends/{backend['id']}/query",
        json={
            "query": 'up{site="HKG"}',
            "timeout_seconds": 10,
            "limit": 25,
            "actor": "ai.l1.operator",
        },
    )
    assert instant.status_code == 200, instant.text
    assert instant.json()["result_type"] == "vector"
    assert instant.json()["result"][0]["metric"]["instance"] == "edge-01"

    ranged = client.post(
        f"/api/v1/metrics/backends/{backend['id']}/query-range",
        json={
            "query": "if_utilization_ratio > 0.8",
            "start": "2026-09-18T00:00:00Z",
            "end": "2026-09-18T01:00:00Z",
            "step_seconds": 60,
            "timeout_seconds": 10,
            "limit": 100,
            "actor": "ai.l1.operator",
        },
    )
    assert ranged.status_code == 200, ranged.text
    assert ranged.json()["result_type"] == "matrix"
    assert ranged.json()["warnings"] == ["partial data outside retention"]

    health = client.post(
        f"/api/v1/metrics/backends/{backend['id']}/health",
        params={"actor": "metrics.operator"},
    )
    assert health.status_code == 200, health.text
    assert health.json()["status"] == "healthy"
    stored = client.get("/api/v1/metrics/backends").json()[0]
    assert stored["last_health_status"] == "healthy"

    assert urlsplit(requests[0][0].full_url).path == (
        "/prometheus/api/v1/query"
    )
    assert urlsplit(requests[1][0].full_url).path == (
        "/prometheus/api/v1/query_range"
    )
    events = client.get(
        "/api/v1/audit-events",
        params={"event_type": "metrics.query.executed"},
    ).json()
    assert len(events) == 2
    assert all(len(item["details"]["query_sha256"]) == 64 for item in events)
    assert "if_utilization_ratio" not in json.dumps(events)


def test_metric_backend_allowlist_and_query_budget_fail_closed(client):
    unsafe = client.post(
        "/api/v1/metrics/backends",
        json={
            "name": "metadata-service",
            "provider": "prometheus",
            "query_base_url": "http://169.254.169.254",
            "created_by": "metrics.operator",
        },
    )
    assert unsafe.status_code == 422
    assert "metrics allowlist" in unsafe.text

    backend = create_metric_backend(client)
    oversized = client.post(
        f"/api/v1/metrics/backends/{backend['id']}/query-range",
        json={
            "query": "up",
            "start": "2026-07-01T00:00:00Z",
            "end": "2026-09-18T00:00:00Z",
            "step_seconds": 60,
            "actor": "ai.l1.operator",
        },
    )
    assert oversized.status_code == 422
    assert "must not exceed 31 days" in oversized.text


def test_failed_metric_query_is_redacted_and_audited(client, monkeypatch):
    backend = create_metric_backend(client)
    monkeypatch.setattr(
        "icheck.services.metrics.build_opener",
        lambda *handlers: FakePrometheusErrorOpener(),
    )
    response = client.post(
        f"/api/v1/metrics/backends/{backend['id']}/query",
        json={
            "query": 'up{customer="sensitive-name"}',
            "actor": "ai.l1.operator",
        },
    )
    assert response.status_code == 422
    events = client.get(
        "/api/v1/audit-events",
        params={"event_type": "metrics.query.failed"},
    ).json()
    assert len(events) == 1
    assert events[0]["outcome"] == "failure"
    assert events[0]["details"]["error_type"] == "MetricQueryError"
    assert "sensitive-name" not in json.dumps(events)
