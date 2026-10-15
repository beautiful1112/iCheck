from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from urllib.parse import parse_qs

import pytest
from sqlalchemy import select

from icheck.builtin_agent_tools import ensure_builtin_agent_tools
from icheck.config import get_settings
from icheck.database import SessionLocal
from icheck.models import (
    AgentToolRegistration,
    Investigation,
    KnowledgeEntity,
    KnowledgeRelationship,
    utcnow,
)
from icheck.services.agent_tools import execute_internal_tool
from test_metric_query_scope import selector_labels


BOOTSTRAP_HEADERS = {
    "X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token"
}


class _MetricResponse:
    def __init__(self, instance: str, labels: dict) -> None:
        self.body = json.dumps(
            {
                "status": "success",
                "data": {
                    "resultType": "matrix",
                    "result": [
                        {
                            "metric": {
                                "__name__": "windows_os_info",
                                "instance": instance,
                                **labels,
                            },
                            "values": [[1_789_689_600, "1"]],
                        }
                    ],
                },
            }
        ).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


class _ScopedMetricOpener:
    def __init__(self, queries: list[str]) -> None:
        self.queries = queries

    def open(self, request, timeout):
        fields = parse_qs(request.data.decode("utf-8"))
        self.queries.append(fields["query"][0])
        return _MetricResponse("10.11.0.10:9182", selector_labels(fields["query"][0]))


def _device(client, *, name: str, site: str, address: str) -> dict:
    response = client.post(
        "/api/v1/devices",
        json={
            "name": name,
            "kind": "switch",
            "management_ip": address,
            "site": site,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _required_auth(monkeypatch) -> None:
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()


def _restore_disabled_auth(monkeypatch) -> None:
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
    get_settings.cache_clear()


def test_site_operator_is_scoped_across_control_plane_routes(
    client,
    monkeypatch,
):
    hk = _device(
        client,
        name="hk-access-01",
        site="Hong Kong",
        address="10.1.0.10",
    )
    ny = _device(
        client,
        name="ny-access-01",
        site="New York",
        address="10.2.0.10",
    )
    observed_at = datetime.now(UTC).isoformat()
    for device, address in ((hk, "10.1.20.10"), (ny, "10.2.20.10")):
        response = client.post(
            "/api/v1/inventory/network-observations",
            json={
                "observations": [
                    {
                        "mac_address": "02:00:00:00:00:42",
                        "ip_address": address,
                        "source": "arp",
                        "collector_device_id": device["id"],
                        "interface_name": "Ethernet1/42",
                        "observed_at": observed_at,
                    }
                ]
            },
        )
        assert response.status_code == 200, response.text

    alerts = {}
    for device in (hk, ny):
        response = client.post(
            "/api/v1/alerts/events",
            json={
                "event_type": "device.unreachable",
                "entity_type": "device",
                "entity_id": device["id"],
                "title": f"{device['name']} unreachable",
                "severity": "critical",
            },
        )
        assert response.status_code == 201, response.text
        alerts[device["id"]] = response.json()

    for name, site in (("collector-hk", "Hong Kong"), ("collector-ny", "New York")):
        response = client.post(
            "/api/v1/collector-workers/register",
            headers={"X-Icheck-Registration-Token": "test-registration-token"},
            json={"name": name, "site": site, "capabilities": ["snmp_exporter"]},
        )
        assert response.status_code == 200, response.text

    services = {}
    for device, key in ((hk, "hk-branch"), (ny, "ny-branch")):
        response = client.post(
            "/api/v1/services",
            json={
                "service_key": key,
                "name": f"{device['name']} service",
                "owner_team": "Branch Operations",
                "criticality": "tier_2",
                "business_impact": "moderate",
                "components": [
                    {
                        "node_type": "device",
                        "entity_id": device["id"],
                        "role": "network",
                    }
                ],
                "created_by": "platform.admin",
            },
        )
        assert response.status_code == 201, response.text
        services[device["id"]] = response.json()

    _required_auth(monkeypatch)
    try:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            headers=BOOTSTRAP_HEADERS,
            json={
                "subject": "admin@example.test",
                "display_name": "Initial Admin",
            },
        )
        assert bootstrap.status_code == 201, bootstrap.text
        admin_headers = {
            "Authorization": (
                f"Bearer {bootstrap.json()['token']['access_token']}"
            )
        }
        cross_scope_dependency = client.post(
            f"/api/v1/services/{services[hk['id']]['id']}/dependencies",
            headers=admin_headers,
            json={
                "expected_revision": 1,
                "target_service_id": services[ny["id"]]["id"],
                "dependency_type": "shared_infrastructure",
                "critical": False,
                "evidence_note": "Reviewed cross-region catalog assertion.",
                "actor": "admin@example.test",
            },
        )
        assert cross_scope_dependency.status_code == 201, cross_scope_dependency.text
        roles = client.get("/api/v1/auth/roles", headers=admin_headers).json()
        operator_role = next(
            item for item in roles if item["name"] == "operator"
        )
        principal = client.post(
            "/api/v1/auth/principals",
            headers=admin_headers,
            json={
                "subject": "hk.operator@example.test",
                "display_name": "Hong Kong Operator",
            },
        ).json()
        binding = client.post(
            f"/api/v1/auth/principals/{principal['id']}/bindings",
            headers=admin_headers,
            json={
                "role_id": operator_role["id"],
                "scope": {"sites": ["Hong Kong"]},
            },
        )
        assert binding.status_code == 201, binding.text
        token = client.post(
            f"/api/v1/auth/principals/{principal['id']}/tokens",
            headers=admin_headers,
            json={"name": "site-operator", "expires_in_hours": 24},
        ).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        devices = client.get("/api/v1/devices", headers=headers)
        assert [item["id"] for item in devices.json()] == [hk["id"]]
        paged_devices = client.get(
            "/api/v1/assets/devices/page",
            headers=headers,
            params={"limit": 1},
        )
        assert paged_devices.status_code == 200, paged_devices.text
        assert [item["id"] for item in paged_devices.json()["items"]] == [hk["id"]]
        assert paged_devices.json()["next_cursor"] is None
        assert (
            client.get(
                f"/api/v1/assets/devices/{ny['id']}", headers=headers
            ).status_code
            == 404
        )

        denied_create = client.post(
            "/api/v1/devices",
            headers=headers,
            json={
                "name": "ny-forbidden",
                "kind": "switch",
                "management_ip": "10.2.0.11",
                "site": "New York",
                "created_by": "forged-admin",
            },
        )
        assert denied_create.status_code == 403
        allowed_create = client.post(
            "/api/v1/devices",
            headers=headers,
            json={
                "name": "hk-allowed",
                "kind": "switch",
                "management_ip": "10.1.0.11",
                "site": "Hong Kong",
                "created_by": "forged-admin",
            },
        )
        assert allowed_create.status_code == 201, allowed_create.text
        assert allowed_create.json()["created_by"] == "hk.operator@example.test"

        endpoints = client.get("/api/v1/endpoints", headers=headers).json()
        assert len(endpoints) == 1
        assert [item["address"] for item in endpoints[0]["current_ips"]] == [
            "10.1.20.10"
        ]
        assert {
            item["collector_device_id"]
            for item in endpoints[0]["current_attachments"]
        } == {hk["id"]}

        visible_alerts = client.get("/api/v1/alerts", headers=headers).json()
        assert alerts[hk["id"]]["id"] in {item["id"] for item in visible_alerts}
        assert alerts[ny["id"]]["id"] not in {
            item["id"] for item in visible_alerts
        }
        visible_situations = client.get(
            "/api/v1/situations", headers=headers
        )
        assert visible_situations.status_code == 200, visible_situations.text
        assert {
            item["primary_entity_id"] for item in visible_situations.json()
        } == {hk["id"]}
        ny_situation = next(
            item
            for item in client.get(
                "/api/v1/situations", headers=admin_headers
            ).json()
            if item["primary_entity_id"] == ny["id"]
        )
        assert (
            client.get(
                f"/api/v1/situations/{ny_situation['id']}",
                headers=headers,
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/api/v1/situations/{ny_situation['id']}/impact",
                headers=headers,
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/api/v1/situations/{ny_situation['id']}/hypotheses",
                headers=headers,
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/api/v1/situations/{ny_situation['id']}/impact-assessments",
                headers=headers,
            ).status_code
            == 404
        )
        hk_situation = visible_situations.json()[0]
        impact = client.get(
            f"/api/v1/situations/{hk_situation['id']}/impact",
            headers=headers,
        )
        assert impact.status_code == 200, impact.text
        assert impact.json()["scope_applied"] is True
        assert f"device:{ny['id']}" not in {
            item["id"] for item in impact.json()["nodes"]
        }
        assert f"service:{services[ny['id']]['id']}" not in {
            item["id"] for item in impact.json()["nodes"]
        }
        assert impact.json()["summary"]["service_dependency_count"] == 0
        visible_services = client.get(
            "/api/v1/services", headers=headers
        )
        assert visible_services.status_code == 200, visible_services.text
        assert [item["service_key"] for item in visible_services.json()] == [
            "hk-branch"
        ]
        assert (
            client.get(
                f"/api/v1/services/{services[ny['id']]['id']}",
                headers=headers,
            ).status_code
            == 404
        )
        visible_dependencies = client.get(
            f"/api/v1/services/{services[hk['id']]['id']}/dependencies",
            headers=headers,
        )
        assert visible_dependencies.status_code == 200, visible_dependencies.text
        assert visible_dependencies.json() == []
        denied_service_create = client.post(
            "/api/v1/services",
            headers=headers,
            json={
                "service_key": "hk-forbidden-create",
                "name": "Forbidden service create",
                "owner_team": "Branch Operations",
                "criticality": "tier_3",
                "business_impact": "low",
                "components": [
                    {"node_type": "device", "entity_id": hk["id"]}
                ],
                "created_by": "hk.operator@example.test",
            },
        )
        assert denied_service_create.status_code == 403
        acknowledged = client.post(
            f"/api/v1/alerts/{alerts[hk['id']]['id']}/acknowledge",
            headers=headers,
            json={"actor": "forged-admin"},
        )
        assert acknowledged.status_code == 200, acknowledged.text
        assert (
            acknowledged.json()["acknowledged_by"]
            == "hk.operator@example.test"
        )
        assert (
            client.post(
                f"/api/v1/alerts/{alerts[ny['id']]['id']}/acknowledge",
                headers=headers,
                json={"actor": "hk.operator@example.test"},
            ).status_code
            == 404
        )

        summary = client.get("/api/v1/dashboard/summary", headers=headers)
        assert summary.status_code == 200, summary.text
        assert summary.json()["devices"] == 2
        assert summary.json()["endpoints"] == 1

        workers = client.get(
            "/api/v1/collector-workers", headers=headers
        ).json()
        assert [item["name"] for item in workers] == ["collector-hk"]
        assert client.get("/api/v1/ai/providers", headers=headers).status_code == 403

        denied_scope = client.post(
            "/api/v1/agent/investigations",
            headers=headers,
            json={
                "title": "Out-of-scope request",
                "objective": "Inspect New York",
                "scope": {"site": "New York"},
                "created_by": "forged-admin",
            },
        )
        assert denied_scope.status_code == 403
    finally:
        _restore_disabled_auth(monkeypatch)


def test_agent_tool_execution_enforces_investigation_scope(client, monkeypatch):
    hk = _device(
        client,
        name="hk-tool-target",
        site="Hong Kong",
        address="10.11.0.10",
    )
    ny = _device(
        client,
        name="ny-tool-target",
        site="New York",
        address="10.12.0.10",
    )
    backend = client.post(
        "/api/v1/metrics/backends",
        json={
            "name": "scoped-agent-prometheus",
            "provider": "prometheus",
            "query_base_url": "https://prometheus.example.test/prometheus",
            "created_by": "platform.operator",
        },
    )
    assert backend.status_code == 201, backend.text
    metric_queries: list[str] = []
    monkeypatch.setattr(
        "icheck.services.metrics.build_opener",
        lambda *handlers: _ScopedMetricOpener(metric_queries),
    )
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "inventory.get_device"
            )
        )
        assert tool is not None
        investigation = Investigation(
            title="Scoped tool boundary",
            objective="Inspect only Hong Kong",
            scope={"site": "Hong Kong"},
            route_id="route-not-persisted",
            model_id="model-not-persisted",
            max_iterations=2,
            max_tool_calls=2,
            timeout_seconds=30,
            token_budget=1000,
            permission_snapshot=["assets.read", "metrics.read"],
            authorization_scope={"sites": ["Hong Kong"]},
            created_by="hk.operator@example.test",
        )

        result, _ = execute_internal_tool(
            db,
            tool,
            {"device_id": hk["id"]},
            investigation=investigation,
        )
        assert result["id"] == hk["id"]
        with pytest.raises(LookupError, match="Device not found"):
            execute_internal_tool(
                db,
                tool,
                {"device_id": ny["id"]},
                investigation=investigation,
            )

        diagnostic_request_tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "windows.request_diagnostics"
            )
        )
        assert diagnostic_request_tool is not None
        with pytest.raises(LookupError, match="Device not found"):
            execute_internal_tool(
                db,
                diagnostic_request_tool,
                {
                    "device_id": ny["id"],
                    "operations": ["operating_system"],
                    "reason": "Inspect an out-of-scope device",
                },
                investigation=investigation,
            )

        now = utcnow()
        hk_entity = KnowledgeEntity(
            namespace="artifact:scope-test",
            scope_key=f"device:{hk['id']}",
            scope_device_id=hk["id"],
            scope_site="Hong Kong",
            entity_type="network.interface",
            external_key="Ethernet1",
            display_name="HK Ethernet1",
            active=True,
            attributes={},
            first_seen=now,
            last_seen=now,
            observed_at=now,
        )
        ny_entity = KnowledgeEntity(
            namespace="artifact:scope-test",
            scope_key=f"device:{ny['id']}",
            scope_device_id=ny["id"],
            scope_site="New York",
            entity_type="network.interface",
            external_key="Ethernet1",
            display_name="NY Ethernet1",
            active=True,
            attributes={},
            first_seen=now,
            last_seen=now,
            observed_at=now,
        )
        db.add_all([hk_entity, ny_entity])
        db.commit()
        graph_tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "knowledge.query_graph"
            )
        )
        assert graph_tool is not None
        graph_result, _ = execute_internal_tool(
            db,
            graph_tool,
            {"entity_id": hk_entity.id},
            investigation=investigation,
        )
        assert graph_result["root"]["id"] == hk_entity.id
        with pytest.raises(LookupError, match="Knowledge entity not found"):
            execute_internal_tool(
                db,
                graph_tool,
                {"entity_id": ny_entity.id},
                investigation=investigation,
            )

        path_tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "knowledge.find_paths"
            )
        )
        assert path_tool is not None
        with pytest.raises(LookupError, match="Knowledge entity not found"):
            execute_internal_tool(
                db,
                path_tool,
                {
                    "source_entity_id": hk_entity.id,
                    "target_entity_id": ny_entity.id,
                },
                investigation=investigation,
            )

        device_metric_tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "metrics.get_device_range"
            )
        )
        assert device_metric_tool is not None
        device_metric_result, _ = execute_internal_tool(
            db,
            device_metric_tool,
            {
                "backend_id": backend.json()["id"],
                "device_id": hk["id"],
                "metric": "windows_os_info",
                "start": "2026-09-19T10:00:00Z",
                "end": "2026-09-19T11:00:00Z",
            },
            investigation=investigation,
        )
        assert device_metric_result["device_id"] == hk["id"]
        assert len(metric_queries) == 1
        assert selector_labels(metric_queries[0])["icheck_device_id"] == hk["id"]
        assert "instance=~" not in metric_queries[0]
        with pytest.raises(LookupError, match="Device not found"):
            execute_internal_tool(
                db,
                device_metric_tool,
                {
                    "backend_id": backend.json()["id"],
                    "device_id": ny["id"],
                    "metric": "windows_os_info",
                    "start": "2026-09-19T10:00:00Z",
                    "end": "2026-09-19T11:00:00Z",
                },
                investigation=investigation,
            )

        raw_metric_tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "metrics.query_range"
            )
        )
        assert raw_metric_tool is not None
        raw_result, _ = execute_internal_tool(
                db,
                raw_metric_tool,
                {
                    "backend_id": backend.json()["id"],
                    "query": "windows_os_info",
                    "start": "2026-09-19T10:00:00Z",
                    "end": "2026-09-19T11:00:00Z",
                },
                investigation=investigation,
        )
        assert raw_result["mode"] == "range" and len(metric_queries) == 2
        assert selector_labels(metric_queries[1])["icheck_device_id"] == hk["id"]
        assert ny["id"] not in metric_queries[1]

        raw_log_tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "logs.query_range"
            )
        )
        assert raw_log_tool is not None
        with pytest.raises(PermissionError, match="scope-enforcing"):
            execute_internal_tool(
                db,
                raw_log_tool,
                {
                    "backend_id": "out-of-scope-backend",
                    "query": '{job="windows-events"}',
                    "start": "2026-09-19T10:00:00Z",
                    "end": "2026-09-19T11:00:00Z",
                },
                investigation=investigation,
            )

        device_log_tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "logs.get_device_range"
            )
        )
        assert device_log_tool is not None
        with pytest.raises(LookupError, match="Device not found"):
            execute_internal_tool(
                db,
                device_log_tool,
                {
                    "backend_id": "out-of-scope-backend",
                    "device_id": ny["id"],
                    "start": "2026-09-19T10:00:00Z",
                    "end": "2026-09-19T11:00:00Z",
                },
                investigation=investigation,
            )
