import json
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select

from icheck.builtin_agent_tools import BUILTIN_AGENT_TOOLS, ensure_builtin_agent_tools
from icheck.database import SessionLocal
from icheck.models import AgentToolRegistration
from icheck.schema_validation import validate_instance
from icheck.services.agent_tools import execute_internal_tool


class FakeLokiResponse:
    def __init__(self, document):
        self.body = json.dumps(document).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, limit):
        return self.body[:limit]


class FakeLokiOpener:
    def __init__(self, requests, *, instance="lab-app-01"):
        self.requests = requests
        self.instance = instance

    def open(self, request, timeout):
        fields = parse_qs(urlsplit(request.full_url).query)
        self.requests.append((request, timeout, fields))
        return FakeLokiResponse(
            {
                "status": "success",
                "data": {
                    "resultType": "streams",
                    "result": [
                        {
                            "stream": {
                                "instance": self.instance,
                                "job": "windows-events",
                                "level": "error",
                                "username": "private.operator",
                            },
                            "values": [
                                [
                                    "1789812000000000000",
                                    "login failed password=hunter2 "
                                    "Authorization: Bearer abcdef.ghi.jkl",
                                ],
                                [
                                    "1789812060000000000",
                                    "service recovered token=top-secret",
                                ],
                            ],
                        }
                    ],
                },
                "warnings": ["test warning"],
            }
        )


def _create_backend(client):
    response = client.post(
        "/api/v1/logs/backends",
        json={
            "name": "lab-loki",
            "provider": "loki",
            "query_base_url": "https://loki.example.test",
            "device_label": "instance",
            "allowed_labels": ["instance", "job", "level"],
            "created_by": "platform.operator",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _tool(db, name):
    tool = db.scalar(
        select(AgentToolRegistration).where(AgentToolRegistration.name == name)
    )
    assert tool is not None
    return tool


def test_loki_backend_query_is_bounded_redacted_and_audited(client, monkeypatch):
    rejected = client.post(
        "/api/v1/logs/backends",
        json={
            "name": "untrusted-loki",
            "provider": "loki",
            "query_base_url": "https://untrusted.example.test",
            "created_by": "platform.operator",
        },
    )
    assert rejected.status_code == 422
    assert "logs allowlist" in rejected.text

    sensitive_label = client.post(
        "/api/v1/logs/backends",
        json={
            "name": "unsafe-label-loki",
            "provider": "loki",
            "query_base_url": "https://loki.example.test",
            "allowed_labels": ["instance", "username"],
            "created_by": "platform.operator",
        },
    )
    assert sensitive_label.status_code == 422
    assert "sensitive" in sensitive_label.text

    backend = _create_backend(client)
    requests = []
    monkeypatch.setattr(
        "icheck.services.logs.build_opener",
        lambda *handlers: FakeLokiOpener(requests),
    )
    query = '{instance="lab-app-01"} |= "login"'
    response = client.post(
        f"/api/v1/logs/backends/{backend['id']}/query-range",
        json={
            "query": query,
            "start": "2026-09-19T10:00:00Z",
            "end": "2026-09-19T11:00:00Z",
            "direction": "backward",
            "limit": 20,
            "timeout_seconds": 7,
            "actor": "l1.operator",
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert len(result["entries"]) == 2
    assert result["entries"][0]["labels"] == {
        "instance": "lab-app-01",
        "job": "windows-events",
        "level": "error",
    }
    serialized = json.dumps(result)
    assert "private.operator" not in serialized
    assert "hunter2" not in serialized
    assert "top-secret" not in serialized
    assert "abcdef.ghi.jkl" not in serialized
    assert serialized.count("[REDACTED]") >= 3
    assert requests[0][0].get_method() == "GET"
    assert requests[0][1] == 9
    assert requests[0][2]["query"] == [query]
    assert requests[0][2]["limit"] == ["20"]

    device = client.post(
        "/api/v1/devices",
        json={
            "name": "lab-app-01",
            "kind": "windows_server",
            "management_ip": "192.0.2.61",
            "site": "LAB",
        },
    )
    assert device.status_code == 201, device.text
    device_response = client.post(
        f"/api/v1/logs/backends/{backend['id']}/devices/"
        f"{device.json()['id']}/query-range",
        json={
            "start": "2026-09-19T10:00:00Z",
            "end": "2026-09-19T11:00:00Z",
            "limit": 20,
            "actor": "l1.operator",
        },
    )
    assert device_response.status_code == 200, device_response.text
    assert len(device_response.json()["entries"]) == 2
    assert requests[1][2]["query"][0].startswith('{instance=~"^')

    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "logs.query.executed"},
    ).json()
    assert len(audits) == 2
    assert all(item["actor_type"] == "user" for item in audits)
    assert all(item["actor_id"] == "l1.operator" for item in audits)
    assert all(item["details"]["entry_count"] == 2 for item in audits)
    assert query not in json.dumps(audits)
    assert len(audits[0]["details"]["query_sha256"]) == 64


def test_agent_log_tools_enforce_bounds_and_device_selector(client, monkeypatch):
    backend = _create_backend(client)
    device = client.post(
        "/api/v1/devices",
        json={
            "name": "lab-app-01",
            "kind": "windows_server",
            "management_ip": "192.0.2.61",
            "site": "LAB",
        },
    )
    assert device.status_code == 201, device.text
    requests = []
    monkeypatch.setattr(
        "icheck.services.logs.build_opener",
        lambda *handlers: FakeLokiOpener(requests),
    )
    with SessionLocal() as db:
        tools = ensure_builtin_agent_tools(db)
        assert len(tools) == len(BUILTIN_AGENT_TOOLS)
        assert {tool.name for tool in tools} == {spec["name"] for spec in BUILTIN_AGENT_TOOLS}
        raw_tool = _tool(db, "logs.query_range")
        raw_result, raw_evidence = execute_internal_tool(
            db,
            raw_tool,
            {
                "backend_id": backend["id"],
                "query": '{job="windows-events"}',
                "start": "2026-09-19T10:00:00Z",
                "end": "2026-09-19T11:00:00Z",
                "limit": 10,
            },
        )
        validate_instance(raw_result, raw_tool.output_schema, "raw log result")
        device_tool = _tool(db, "logs.get_device_range")
        device_result, device_evidence = execute_internal_tool(
            db,
            device_tool,
            {
                "backend_id": backend["id"],
                "device_id": device.json()["id"],
                "start": "2026-09-19T10:00:00Z",
                "end": "2026-09-19T11:00:00Z",
                "limit": 10,
            },
        )
        validate_instance(
            device_result,
            device_tool.output_schema,
            "device log result",
        )
        with pytest.raises(ValueError, match="24 hours"):
            execute_internal_tool(
                db,
                raw_tool,
                {
                    "backend_id": backend["id"],
                    "query": '{job="windows-events"}',
                    "start": "2026-09-18T00:00:00Z",
                    "end": "2026-09-19T00:00:01Z",
                },
            )

    assert raw_evidence[0].evidence_type == "log_range_query"
    assert device_result["device_id"] == device.json()["id"]
    assert device_evidence[0].evidence_type == "device_log_range"
    device_query = requests[1][2]["query"][0]
    assert device_query.startswith('{instance=~"^')
    assert "lab\\\\-app\\\\-01" in device_query
    assert "192\\\\.0\\\\.2\\\\.61" in device_query

    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "logs.query.executed"},
    ).json()
    assert len(audits) == 2
    assert all(item["actor_type"] == "agent" for item in audits)
    assert all(item["actor_id"] == "agent.runtime" for item in audits)
