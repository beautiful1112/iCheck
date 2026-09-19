import json
from urllib.parse import parse_qs

from sqlalchemy import select

from icheck.builtin_agent_tools import ensure_builtin_agent_tools
from icheck.database import SessionLocal
from icheck.models import AgentToolRegistration
from icheck.schema_validation import validate_instance
from icheck.services.agent_tools import execute_internal_tool


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
        return FakeResponse(
            {
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [
                        {
                            "metric": {
                                "__name__": "if_oper_status",
                                "instance": "lab-core-01",
                            },
                            "value": [1_789_689_600, "1"],
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
        assert len(first_seed) == 4
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
    requests = []
    monkeypatch.setattr(
        "icheck.services.metrics.build_opener",
        lambda *handlers: FakePrometheusOpener(requests),
    )
    query = 'if_oper_status{site="sensitive-lab"}'

    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        tool = _tool(db, "metrics.query_instant")
        assert tool.risk_level == "diagnose"
        assert tool.required_permissions == ["metrics.read"]
        result, evidence = execute_internal_tool(
            db,
            tool,
            {
                "backend_id": backend.json()["id"],
                "query": query,
                "timeout_seconds": 7,
                "limit": 12,
            },
        )
        validate_instance(result, tool.output_schema, "metric query result")

    assert result["mode"] == "instant"
    assert result["result_type"] == "vector"
    assert result["result"][0]["metric"]["instance"] == "lab-core-01"
    assert requests[0][1] == 9
    assert requests[0][2]["timeout"] == ["7s"]
    assert requests[0][2]["limit"] == ["12"]
    assert query not in evidence[0].summary
    assert len(evidence[0].evidence_id.rsplit(":", 1)[1]) == 64

    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "metrics.query.executed"},
    ).json()
    assert len(audits) == 1
    assert audits[0]["actor_id"] == "agent.runtime"
    assert "sensitive-lab" not in json.dumps(audits)
