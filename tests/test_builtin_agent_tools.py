from dataclasses import replace
import json
import re
from urllib.parse import parse_qs

import pytest
from sqlalchemy import select

from icheck.builtin_agent_tools import BUILTIN_AGENT_TOOLS, ensure_builtin_agent_tools
from icheck.database import SessionLocal
from icheck.models import (
    AgentToolRegistration,
    Investigation,
    KnowledgeEntity,
    KnowledgeRelationship,
    MetricBackend,
    utcnow,
)
from icheck.schema_validation import validate_instance
from icheck.services.agent_tools import execute_internal_tool
from test_metric_query_scope import selector_labels


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
        fields = parse_qs(request.data.decode("utf-8"))
        self.requests.append((request, timeout, fields))
        is_range = request.full_url.endswith("/query_range")
        requested_query = fields["query"][0]
        requested_labels = selector_labels(requested_query)
        return FakeResponse(
            {
                "status": "success",
                "data": {
                    "resultType": "matrix" if is_range else "vector",
                    "result": [
                        {
                            "metric": {
                                **requested_labels,
                                "instance": "lab-core-01",
                                "username": "must-not-leave-the-gateway",
                            },
                            **(
                                {
                                    "values": [
                                        [1_789_689_600, "1"],
                                        [1_789_693_200, "0"],
                                    ]
                                }
                                if is_range
                                else {"value": [1_789_689_600, "1"]}
                            ),
                        }
                    ],
                },
            }
        )


def _tool(db, name):
    tool = db.scalar(
        select(AgentToolRegistration).where(AgentToolRegistration.name == name)
    )
    assert tool is not None
    return tool


def test_endpoint_history_tool_returns_bounded_wired_and_wireless_evidence(client):
    controller = client.post(
        "/api/v1/devices",
        json={
            "name": "lab-wlc-01",
            "kind": "wireless_controller",
            "management_ip": "192.0.2.10",
            "site": "LAB",
        },
    )
    assert controller.status_code == 201, controller.text
    controller_id = controller.json()["id"]

    first = client.post(
        "/api/v1/inventory/network-observations",
        json={
            "observations": [
                {
                    "mac_address": "00-1B-44-11-3A-B7",
                    "ip_address": "10.20.17.19",
                    "source": "arp",
                    "interface_name": "Gi1/0/18",
                    "vlan_id": 120,
                    "hostname": "ops-laptop-17",
                    "username": "private.user",
                    "vendor": "Lenovo",
                    "observed_at": "2026-09-19T10:00:00Z",
                }
            ]
        },
    )
    assert first.status_code == 200, first.text
    second = client.post(
        "/api/v1/inventory/network-observations",
        json={
            "observations": [
                {
                    "mac_address": "00:1b:44:11:3a:b7",
                    "ip_address": "10.20.17.21",
                    "source": "arp",
                    "interface_name": "Gi1/0/19",
                    "vlan_id": 120,
                    "observed_at": "2026-09-19T10:05:00Z",
                }
            ]
        },
    )
    assert second.status_code == 200, second.text
    wireless = client.post(
        "/api/v1/inventory/wireless-snapshots",
        json={
            "controller_id": controller_id,
            "observed_at": "2026-09-19T10:10:00Z",
            "clients": [
                {
                    "mac_address": "00:1b:44:11:3a:b7",
                    "ip_address": "10.20.31.54",
                    "access_point": "AP-LAB-01",
                    "ssid": "LAB",
                    "band": "5 GHz",
                    "channel": 36,
                    "vlan_id": 131,
                    "rssi": -63,
                    "snr": 31,
                    "observed_at": "2026-09-19T10:10:00Z",
                }
            ],
        },
    )
    assert wireless.status_code == 200, wireless.text

    with SessionLocal() as db:
        first_seed = ensure_builtin_agent_tools(db)
        second_seed = ensure_builtin_agent_tools(db)
        assert [item.id for item in first_seed] == [item.id for item in second_seed]
        assert len(first_seed) == len(BUILTIN_AGENT_TOOLS)
        assert any(item.name == "situations.get_recovery_evidence" and item.read_only for item in first_seed)
        assert any(item.name == "situations.close_reviewed" and not item.read_only for item in first_seed)
        assert any(item.name == "quality.get_execution_health" and item.read_only for item in first_seed)
        assert any(item.name == "quality.get_remediation_outcomes" and item.read_only for item in first_seed)
        assert "capacity.get_worker_scaling" in {
            item.name for item in first_seed
        }
        assert "metrics.query_range" in {item.name for item in first_seed}
        assert "windows.request_diagnostics" in {
            item.name for item in first_seed
        }
        assert "logs.get_device_range" in {item.name for item in first_seed}
        tool = _tool(db, "inventory.get_endpoint_history")
        result, evidence = execute_internal_tool(
            db,
            tool,
            {"mac_address": "00-1B-44-11-3A-B7", "limit": 100},
        )
        validate_instance(result, tool.output_schema, "endpoint history result")

    assert result["mac_address"] == "00:1b:44:11:3a:b7"
    assert result["hostname"] == "ops-laptop-17"
    assert "username" not in result
    assert {item["address"] for item in result["ip_history"]} == {
        "10.20.17.19",
        "10.20.17.21",
        "10.20.31.54",
    }
    assert [item["interface_name"] for item in result["wired_history"]] == [
        "Gi1/0/19",
        "Gi1/0/18",
    ]
    assert result["wireless_history"][0]["controller_id"] == controller_id
    assert result["wireless_history"][0]["access_point"] == "AP-LAB-01"
    assert evidence[0].evidence_type == "endpoint"
    assert evidence[0].evidence_id == result["id"]


def test_wireless_controller_tool_filters_clients_omits_private_data_and_scopes(
    client,
):
    lab_controller = client.post(
        "/api/v1/devices",
        json={
            "name": "lab-wlc-tool-01",
            "kind": "wireless_controller",
            "management_ip": "192.0.2.30",
            "site": "LAB",
        },
    )
    remote_controller = client.post(
        "/api/v1/devices",
        json={
            "name": "remote-wlc-tool-01",
            "kind": "wireless_controller",
            "management_ip": "198.51.100.30",
            "site": "REMOTE",
        },
    )
    assert lab_controller.status_code == 201, lab_controller.text
    assert remote_controller.status_code == 201, remote_controller.text
    observed_at = utcnow().isoformat()
    lab_snapshot = client.post(
        "/api/v1/inventory/wireless-snapshots",
        json={
            "controller_id": lab_controller.json()["id"],
            "observed_at": observed_at,
            "clients": [
                {
                    "mac_address": "02:00:00:00:10:01",
                    "ip_address": "10.20.30.41",
                    "hostname": "healthy-laptop",
                    "username": "private.user",
                    "vendor": "Example",
                    "access_point": "AP-LAB-01",
                    "ssid": "CORP",
                    "bssid": "02:00:00:00:aa:01",
                    "radio": "slot-1",
                    "band": "5 GHz",
                    "channel": 36,
                    "vlan_id": 130,
                    "rssi": -58,
                    "snr": 36,
                    "observed_at": observed_at,
                    "raw_data": {"private_vendor_blob": "must-not-enter-agent"},
                },
                {
                    "mac_address": "02:00:00:00:10:02",
                    "ip_address": "10.20.30.42",
                    "hostname": "weak-tablet",
                    "username": "another.private.user",
                    "vendor": "Example",
                    "access_point": "AP-LAB-02",
                    "ssid": "CORP",
                    "bssid": "02:00:00:00:aa:02",
                    "radio": "slot-0",
                    "band": "2.4 GHz",
                    "channel": 6,
                    "vlan_id": 130,
                    "rssi": -82,
                    "snr": 8,
                    "observed_at": observed_at,
                    "raw_data": {"session_token": "must-also-stay-out"},
                },
            ],
        },
    )
    remote_snapshot = client.post(
        "/api/v1/inventory/wireless-snapshots",
        json={
            "controller_id": remote_controller.json()["id"],
            "observed_at": observed_at,
            "clients": [
                {
                    "mac_address": "02:00:00:00:20:01",
                    "ip_address": "10.99.30.41",
                    "access_point": "AP-REMOTE-01",
                    "ssid": "REMOTE",
                    "rssi": -60,
                    "snr": 30,
                    "observed_at": observed_at,
                }
            ],
        },
    )
    assert lab_snapshot.status_code == 200, lab_snapshot.text
    assert remote_snapshot.status_code == 200, remote_snapshot.text

    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        tool = _tool(db, "wireless.list_controller_clients")
        assert tool.risk_level == "diagnose"
        assert tool.required_permissions == ["assets.read", "endpoints.read"]
        result, evidence = execute_internal_tool(
            db,
            tool,
            {
                "controller_id": lab_controller.json()["id"],
                "ssid": "CORP",
                "rssi_at_most": -75,
                "max_age_minutes": 60,
                "limit": 10,
            },
        )
        validate_instance(
            result,
            tool.output_schema,
            "wireless controller clients result",
        )
        truncated_result, _ = execute_internal_tool(
            db,
            tool,
            {
                "controller_id": lab_controller.json()["id"],
                "max_age_minutes": 60,
                "limit": 1,
            },
        )
        scoped_investigation = Investigation(
            title="Scoped Wi-Fi diagnosis",
            objective="Inspect only the LAB controller",
            scope={"site": "LAB"},
            route_id="route-not-persisted",
            model_id="model-not-persisted",
            max_iterations=2,
            max_tool_calls=2,
            timeout_seconds=30,
            token_budget=1000,
            permission_snapshot=["assets.read", "endpoints.read"],
            authorization_scope={"sites": ["LAB"]},
            created_by="lab.operator@example.test",
        )
        scoped_result, _ = execute_internal_tool(
            db,
            tool,
            {
                "controller_id": lab_controller.json()["id"],
                "max_age_minutes": 60,
            },
            investigation=scoped_investigation,
        )
        with pytest.raises(LookupError, match="Wireless controller not found"):
            execute_internal_tool(
                db,
                tool,
                {
                    "controller_id": remote_controller.json()["id"],
                    "max_age_minutes": 60,
                },
                investigation=scoped_investigation,
            )

    assert result["controller"]["id"] == lab_controller.json()["id"]
    assert result["filters"]["rssi_at_most"] == -75
    assert [item["hostname"] for item in result["clients"]] == ["weak-tablet"]
    assert result["clients"][0]["mac_address"] == "02:00:00:00:10:02"
    assert result["clients"][0]["ip_address"] == "10.20.30.42"
    assert result["clients"][0]["bssid"] == "02:00:00:00:aa:02"
    assert "username" not in result["clients"][0]
    assert "raw_data" not in result["clients"][0]
    assert "must-not-enter-agent" not in json.dumps(result)
    assert "must-also-stay-out" not in json.dumps(result)
    assert evidence[0].evidence_type == "wireless_controller_clients"
    assert evidence[0].evidence_id.startswith(lab_controller.json()["id"] + ":")
    assert len(evidence[0].evidence_id.rsplit(":", 1)[1]) == 64
    assert truncated_result["truncated"] is True
    assert len(truncated_result["clients"]) == 1
    assert len(scoped_result["clients"]) == 2


def test_knowledge_graph_tool_is_bounded_typed_and_omits_attributes(client):
    device = client.post(
        "/api/v1/devices",
        json={
            "name": "graph-tool-anchor",
            "kind": "switch",
            "site": "LAB",
        },
    )
    assert device.status_code == 201, device.text
    now = utcnow()
    with SessionLocal() as db:
        root = KnowledgeEntity(
            namespace="artifact:test-graph",
            scope_key=f"device:{device.json()['id']}",
            scope_device_id=device.json()["id"],
            scope_site="LAB",
            entity_type="application.service",
            external_key="checkout",
            display_name="Checkout",
            status="degraded",
            active=True,
            attributes={"internal_owner": "must-not-enter-agent-result"},
            first_seen=now,
            last_seen=now,
            observed_at=now,
        )
        neighbor = KnowledgeEntity(
            namespace="artifact:test-graph",
            scope_key=f"device:{device.json()['id']}",
            scope_device_id=device.json()["id"],
            scope_site="LAB",
            entity_type="application.database",
            external_key="orders-db",
            display_name="Orders DB",
            status="healthy",
            active=True,
            attributes={"opaque_detail": "must-also-stay-out"},
            first_seen=now,
            last_seen=now,
            observed_at=now,
        )
        terminal = KnowledgeEntity(
            namespace="artifact:test-graph",
            scope_key=f"device:{device.json()['id']}",
            scope_device_id=device.json()["id"],
            scope_site="LAB",
            entity_type="application.cache",
            external_key="sessions-cache",
            display_name="Sessions Cache",
            status="healthy",
            active=True,
            attributes={"internal_cluster": "must-not-enter-path-result"},
            first_seen=now,
            last_seen=now,
            observed_at=now,
        )
        db.add_all([root, neighbor, terminal])
        db.flush()
        db.add_all(
            [
            KnowledgeRelationship(
                namespace="artifact:test-graph",
                scope_key=f"device:{device.json()['id']}",
                scope_device_id=device.json()["id"],
                scope_site="LAB",
                relationship_type="application.depends_on",
                source_entity_id=root.id,
                target_entity_id=neighbor.id,
                directed=True,
                active=True,
                attributes={"credential_hint": "never-return-this"},
                first_seen=now,
                last_seen=now,
                observed_at=now,
            ),
            KnowledgeRelationship(
                namespace="artifact:test-graph",
                scope_key=f"device:{device.json()['id']}",
                scope_device_id=device.json()["id"],
                scope_site="LAB",
                relationship_type="application.depends_on",
                source_entity_id=neighbor.id,
                target_entity_id=terminal.id,
                directed=True,
                active=True,
                attributes={"private_weight": "must-not-enter-path-result"},
                first_seen=now,
                last_seen=now,
                observed_at=now,
            ),
            ]
        )
        db.commit()

        ensure_builtin_agent_tools(db)
        tool = _tool(db, "knowledge.query_graph")
        result, evidence = execute_internal_tool(
            db,
            tool,
            {
                "entity_type": "application.service",
                "external_key": "checkout",
                "relationship_types": ["application.depends_on"],
                "direction": "outgoing",
                "limit": 10,
            },
        )
        validate_instance(result, tool.output_schema, "knowledge graph result")

        path_tool = _tool(db, "knowledge.find_paths")
        path_result, path_evidence = execute_internal_tool(
            db,
            path_tool,
            {
                "source_entity_id": root.id,
                "target_entity_id": terminal.id,
                "relationship_types": ["application.depends_on"],
                "direction": "outgoing",
                "max_depth": 3,
                "max_paths": 5,
            },
        )
        validate_instance(
            path_result,
            path_tool.output_schema,
            "knowledge path result",
        )
        shallow_result, _ = execute_internal_tool(
            db,
            path_tool,
            {
                "source_entity_id": root.id,
                "target_entity_id": terminal.id,
                "direction": "outgoing",
                "max_depth": 1,
            },
        )

    assert result["root"]["external_key"] == "checkout"
    assert [item["external_key"] for item in result["neighbors"]] == [
        "orders-db"
    ]
    assert result["relationships"][0]["relationship_type"] == (
        "application.depends_on"
    )
    assert result["truncated"] is False
    assert "attributes" not in result["root"]
    assert "must-not-enter-agent-result" not in json.dumps(result)
    assert "must-also-stay-out" not in json.dumps(result)
    assert "never-return-this" not in json.dumps(result)
    assert evidence[0].evidence_type == "knowledge_graph"
    assert evidence[0].evidence_id == result["root"]["id"]
    assert [node["external_key"] for node in path_result["paths"][0]["nodes"]] == [
        "checkout",
        "orders-db",
        "sessions-cache",
    ]
    assert len(path_result["paths"][0]["relationships"]) == 2
    assert path_result["truncated"] is False
    assert shallow_result["paths"] == []
    assert "attributes" not in json.dumps(path_result)
    assert "must-not-enter-path-result" not in json.dumps(path_result)
    assert path_evidence[0].evidence_type == "knowledge_path"
    assert "not a causal claim" in path_evidence[0].summary


def test_metric_backend_discovery_is_bounded_namespace_scoped_and_metadata_only(client, monkeypatch):
    from icheck.services.agent_tools import _list_metric_backends
    from icheck.services.control_plane_auth import development_principal

    principal = development_principal()
    monkeypatch.setattr("icheck.services.metrics.build_opener",
        lambda *args: pytest.fail("Discovery must not connect to a backend"))
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        tool = _tool(db, "metrics.backends.list")
        assert tool.read_only and tool.required_permissions == ["metrics.read"]
        empty, evidence = execute_internal_tool(db, tool, {})
        assert empty["backends"] == [] and empty["truncated"] is False and evidence == []
        assert "No enabled metric backend" in empty["next_action"]
        for name, changes in [
            ("B-prometheus", {}), ("A-prometheus", {}), ("C-prometheus", {}),
            ("Disabled", {"enabled": False}),
            ("Foreign-tenant", {"tenant_id": "foreign-tenant"}),
            ("Foreign-region", {"region_id": "foreign-region"}),
        ]:
            db.add(MetricBackend(name=name, provider="prometheus", created_by="fixture",
                query_base_url="https://private-host.invalid", remote_write_url="https://write-host.invalid",
                credential_profile_ref="secret-reference-not-for-model", external_labels={"private": "hidden-label"},
                last_health_error="private diagnostic body", **changes))
        db.commit()
        result, evidence = execute_internal_tool(db, tool, {"limit": 2})
        validate_instance(result, tool.output_schema, "metric backend discovery")
        assert [row["name"] for row in result["backends"]] == ["A-prometheus", "B-prometheus"]
        assert result["truncated"] and "exact name" in result["next_action"] and evidence == []
        assert all(set(row) == {"backend_id", "name", "provider"} for row in result["backends"])
        assert all(value not in json.dumps(result) for value in
            ["private-host", "write-host", "secret-reference", "hidden-label", "diagnostic body", "Foreign", "Disabled"])
        exact, _ = execute_internal_tool(db, tool, {"name": "C-prometheus"})
        assert len(exact["backends"]) == 1 and not exact["truncated"]
        assert execute_internal_tool(db, tool, {"name": "%"})[0]["backends"] == []
        for limit in [0, 101]:
            with pytest.raises(ValueError):
                validate_instance({"limit": limit}, tool.input_schema, "metric discovery bounds")
        with pytest.raises(PermissionError, match="metrics.read"):
            _list_metric_backends(db, {}, replace(principal, permissions=frozenset()))
        scoped, _ = _list_metric_backends(db, {}, replace(principal, authorization_scope={"sites": ["LAB"]}))
        assert len(scoped["backends"]) == 3, "Backend identity is workspace metadata, not unrestricted metric access"


def test_metric_query_tool_enforces_agent_bounds_and_redacts_audit(
    client,
    monkeypatch,
):
    backend = client.post(
        "/api/v1/metrics/backends",
        json={
            "name": "agent-prometheus",
            "provider": "prometheus",
            "query_base_url": "https://prometheus.example.test/prometheus",
            "created_by": "platform.operator",
        },
    )
    assert backend.status_code == 201, backend.text
    device = client.post(
        "/api/v1/devices",
        json={
            "name": "lab-core-01",
            "kind": "windows_server",
            "management_ip": "192.0.2.51",
            "site": "LAB",
        },
    )
    assert device.status_code == 201, device.text
    requests = []
    monkeypatch.setattr(
        "icheck.services.metrics.build_opener",
        lambda *handlers: FakePrometheusOpener(requests),
    )
    query = 'if_oper_status{site="sensitive-lab"}'

    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        discovered, _ = execute_internal_tool(db, _tool(db, "metrics.backends.list"), {"name": "agent-prometheus"})
        backend_id = discovered["backends"][0]["backend_id"]
        assert backend_id == backend.json()["id"]
        instant_tool = _tool(db, "metrics.query_instant")
        assert instant_tool.risk_level == "diagnose"
        assert instant_tool.required_permissions == ["metrics.read"]
        result, evidence = execute_internal_tool(
            db,
            instant_tool,
            {
                "backend_id": backend_id,
                "query": query,
                "timeout_seconds": 7,
                "limit": 12,
            },
        )
        validate_instance(
            result,
            instant_tool.output_schema,
            "metric query result",
        )
        with pytest.raises(LookupError, match="Metric backend not found"):
            execute_internal_tool(db, instant_tool, {"backend_id": "icheck-prometheus", "query": "up"})

        range_tool = _tool(db, "metrics.query_range")
        range_result, range_evidence = execute_internal_tool(
            db,
            range_tool,
            {
                "backend_id": backend.json()["id"],
                "query": query,
                "start": "2026-09-19T10:00:00Z",
                "end": "2026-09-19T11:00:00Z",
                "step_seconds": 60,
                "timeout_seconds": 8,
                "limit": 20,
            },
        )
        validate_instance(
            range_result,
            range_tool.output_schema,
            "metric range query result",
        )
        with pytest.raises(ValueError, match="seven days"):
            execute_internal_tool(
                db,
                range_tool,
                {
                    "backend_id": backend.json()["id"],
                    "query": query,
                    "start": "2026-09-01T00:00:00Z",
                    "end": "2026-09-09T00:00:00Z",
                    "step_seconds": 300,
                },
            )
        with pytest.raises(ValueError, match="2000 evaluation steps"):
            execute_internal_tool(
                db,
                range_tool,
                {
                    "backend_id": backend.json()["id"],
                    "query": query,
                    "start": "2026-09-18T00:00:00Z",
                    "end": "2026-09-19T00:00:00Z",
                    "step_seconds": 30,
                },
            )

        device_tool = _tool(db, "metrics.get_device_range")
        device_result, device_evidence = execute_internal_tool(
            db,
            device_tool,
            {
                "backend_id": backend.json()["id"],
                "device_id": device.json()["id"],
                "metric": "windows_cpu_time_seconds_total",
                "start": "2026-09-19T10:00:00Z",
                "end": "2026-09-19T11:00:00Z",
                "step_seconds": 60,
                "limit": 10,
            },
        )
        validate_instance(
            device_result,
            device_tool.output_schema,
            "device metric range result",
        )
        with pytest.raises(ValueError, match="namespace allowlist"):
            execute_internal_tool(
                db,
                device_tool,
                {
                    "backend_id": backend.json()["id"],
                    "device_id": device.json()["id"],
                    "metric": "business_customer_revenue",
                    "start": "2026-09-19T10:00:00Z",
                    "end": "2026-09-19T11:00:00Z",
                },
            )

    assert result["mode"] == "instant"
    assert result["result_type"] == "vector"
    assert result["result"][0]["metric"]["instance"] == "lab-core-01"
    assert requests[0][1] == 9
    assert requests[0][2]["timeout"] == ["7s"]
    assert requests[0][2]["limit"] == ["12"]
    assert query not in evidence[0].summary
    assert len(evidence[0].evidence_id.rsplit(":", 1)[1]) == 64
    assert range_result["mode"] == "range"
    assert range_result["result_type"] == "matrix"
    assert len(range_result["result"][0]["values"]) == 2
    assert query not in range_evidence[0].summary
    assert range_evidence[0].evidence_type == "metric_range_query"
    assert len(range_evidence[0].evidence_id.rsplit(":", 1)[1]) == 64
    assert requests[1][1] == 10
    assert requests[1][2]["step"] == ["60s"]
    assert requests[1][2]["limit"] == ["20"]
    assert device_result["device_id"] == device.json()["id"]
    assert device_result["metric"] == "windows_cpu_time_seconds_total"
    assert "username" not in device_result["result"][0]["metric"]
    assert device_evidence[0].evidence_type == "device_metric_range"
    assert query not in device_evidence[0].summary
    device_query = requests[2][2]["query"][0]
    labels = selector_labels(device_query)
    assert labels["__name__"] == "windows_cpu_time_seconds_total"
    assert labels["icheck_device_id"] == device.json()["id"]
    assert "instance=~" not in device_query and "192.0.2.51" not in device_query

    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "metrics.query.executed"},
    ).json()
    assert len(audits) == 3
    assert all(item["actor_id"] == "agent.runtime" for item in audits)
    assert all(item["actor_type"] == "agent" for item in audits)
    assert "sensitive-lab" not in json.dumps(audits)
