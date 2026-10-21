from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4
import base64

import pytest
from icheck.monitoring_connectors.contracts import SourceIdentity, ReadScope, HistoryQuery
from icheck.monitoring_connectors.orion import OrionConnector, compile_query
from icheck.monitoring_connectors.bridge import BridgeConnector
from icheck.monitoring_connectors.https_transport import canonical_endpoint, OrionHTTPSTransport
from icheck.monitoring_connectors.zabbix import ConnectorError
from icheck.services.integration_alerts import severity

NOW = datetime(2026, 10, 20, 12, tzinfo=UTC)
SCOPE = ReadScope(group_ids=("2",))


def source(provider):
    return SourceIdentity(tenant_id=uuid4(), region_id=uuid4(), connection_id=uuid4(), provider=provider)


class Orion:
    def __init__(self):
        self.calls = []
        self.responses = {
            "groups": [{"id": 2, "name": "Branch"}],
            "manifest": [{"id": 10}],
            "resources": [{"id": 10, "name": "Router", "unmanaged": False}],
            "active": [{"id": 100}],
            "events": [{"id": 100, "episode": 200, "subject": 300, "occurred": NOW.isoformat(),
                        "title": "Node unreachable", "severity": 2, "enabled": True,
                        "uri": "swis://orion/Orion/Orion.Nodes/NodeID=10", "entity_type": "Orion.Nodes",
                        "node_id": 10, "active_id": 200, "acknowledged": False}],
            "recoveries": [],
            "suppression": [{"EntityUri": "swis://orion/Orion/Orion.Nodes/NodeID=10", "SuppressionMode": 0}],
            "history": [{"node_id": 10, "timestamp": NOW.isoformat(), "value": 12.5}],
        }

    def request(self, payload, **bounds):
        self.calls.append(payload)
        assert bounds["max_response_bytes"] == 2_000_000
        return {"results": deepcopy(self.responses[payload["operation"]])}


def test_orion_scoped_discovery_metrics_and_history():
    transport = Orion(); connector = OrionConnector(source("solarwinds_orion"), transport)
    assert connector.discover_groups()["items"][0]["id"] == "2"
    assert connector.resource_manifest(SCOPE) == ["10"]
    assert connector.discover_resources(SCOPE).items[0].ref.object_type == "node"
    assert connector.read_resource_batch(SCOPE, ["10"]).items[0].monitoring_enabled
    assert connector.list_metrics(SCOPE, "10")["items"][0]["metric_id"] == "response_time"
    batch = connector.query_history(SCOPE, HistoryQuery(resource_id="10", metric_id="response_time",
        value_type="float", start=NOW-timedelta(minutes=1), end=NOW+timedelta(minutes=1)))
    assert batch.items[0].value == 12.5 and batch.items[0].unit == "ms"


@pytest.mark.parametrize("mode,stopped", [(0, False), (1, True), (2, True), (3, False), (4, False)])
def test_orion_effective_parent_suppression_stops_investigation(mode, stopped):
    transport = Orion(); transport.responses["suppression"][0]["SuppressionMode"] = mode
    connector = OrionConnector(source("solarwinds_orion"), transport)
    assert connector.active_event_manifest(SCOPE) == ["100"]
    event = connector.read_events(SCOPE, event_ids=["100"]).items[0]
    assert event.investigation_stop_required is stopped
    transport.responses["events"][0]["acknowledged"] = True
    assert connector.read_events(SCOPE, event_ids=["100"]).items[0].investigation_stop_required is stopped


@pytest.mark.parametrize("event_type", [1, 8])
def test_orion_reset_and_explicit_clear_use_same_episode_evidence(event_type):
    transport = Orion()
    transport.responses["events"][0]["active_id"] = None
    transport.responses["recoveries"] = [{"id": 101, "episode": 200, "subject": 300,
        "occurred": (NOW+timedelta(seconds=1)).isoformat(), "event_type": event_type}]
    connector = OrionConnector(source("solarwinds_orion"), transport)
    event = connector.read_events(SCOPE, event_ids=["100"]).items[0]
    assert event.state == "resolved" and event.recovery_ref.remote_id == "101"
    transport.responses["recoveries"] = []
    assert not connector.read_events(SCOPE, event_ids=["100"]).items  # unknown, not recovered


@pytest.mark.parametrize("defect", ["wrong_episode", "wrong_node", "wrong_event", "missing_mute", "invalid_type", "old_recovery", "nonfinite"])
def test_orion_rejects_mismatched_or_malformed_evidence(defect):
    transport = Orion(); connector = OrionConnector(source("solarwinds_orion"), transport)
    if defect == "wrong_episode": transport.responses["events"][0]["active_id"] = 201
    if defect == "wrong_node": transport.responses["resources"][0]["id"] = 11
    if defect == "wrong_event": transport.responses["events"][0]["id"] = 99
    if defect == "missing_mute": transport.responses["suppression"] = []
    if defect == "invalid_type": transport.responses["events"][0]["enabled"] = "true"
    if defect == "old_recovery":
        transport.responses["recoveries"] = [{"id": 99, "episode": 200, "subject": 300, "occurred": NOW.isoformat(), "event_type": 1}]
    if defect == "nonfinite": transport.responses["events"][0]["severity"] = float("nan")
    with pytest.raises(ConnectorError):
        connector.read_events(SCOPE, event_ids=["100"])


def test_swql_compiler_only_allows_fixed_reads_and_bound_parameters():
    payload = {"operation": "resources", "groups": ["2"], "ids": ["10"], "limit": 2}
    query = compile_query(payload)
    assert query["query"].startswith("SELECT TOP 2")
    assert "IN @groups" in query["query"] and query["parameters"]["ids"] == [10]
    for bad in ({**payload, "query": "DELETE anything"}, {**payload, "operation": "delete"},
                {**payload, "groups": []}, {**payload, "ids": ["10; DROP TABLE"]}, {**payload, "limit": 10002}):
        with pytest.raises((ValueError, ConnectorError)):
            compile_query(bad)
    assert canonical_endpoint("https://orion.example.test:17774", "solarwinds_orion").endswith("/Json/Query")
    credential = base64.b64encode(b"readonly:synthetic-password").decode()
    wire = OrionHTTPSTransport("https://orion.example.test:17774", credential)
    assert wire._prepare(payload)[1] == "Basic " + credential
    assert wire._secrets()[-1] == "synthetic-password"
    assert "GetAlertSuppressionState" in wire._path({"operation": "suppression"}, "/Json/Query")
    assert severity("solarwinds_orion", "4").value == "info"
    assert severity("solarwinds_orion", "2").value == "critical"


class Bridge:
    def __init__(self):
        self.rows = {"groups": [{"id": "2", "name": "Branch"}], "manifest": ["10"], "active": ["100"],
            "resources": [{"id": "10", "name": "Router", "monitoring_enabled": True, "group_ids": ["2"]}],
            "events": [{"id": "100", "subject_id": "300", "title": "Loss", "native_severity": "4", "state": "open",
                        "acknowledged": False, "suppressed": False, "occurred_at": NOW.isoformat(), "resolved_at": None,
                        "recovery_id": None, "resources": [{"id": "10", "name": "Router", "monitoring_enabled": True, "group_ids": ["2"]}]}],
            "metrics": [{"metric_id": "400", "name": "Traffic", "value_type": "uint", "unit": "bps"}],
            "history": [{"metric_id": "400", "resource_id": "10", "timestamp": NOW.isoformat(),
                         "nanoseconds": 0, "value": 2**63, "unit": "bps"}]}
        self.truncated = False

    def request(self, payload, **bounds):
        return {"protocol": payload["protocol"], "operation": payload["operation"],
                "items": deepcopy(self.rows[payload["operation"]]), "truncated": self.truncated}


def test_bridge_contract_constructs_local_source_and_preserves_counter_precision():
    transport = Bridge(); identity = source("rest_webhook"); connector = BridgeConnector(identity, transport)
    assert connector.discover_groups()["items"][0]["id"] == "2"
    assert connector.resource_manifest(SCOPE) == ["10"]
    assert connector.read_resource_batch(SCOPE, ["10"]).source == identity
    assert connector.read_events(SCOPE, after="99", since=NOW).items[0].resources[0].ref.source == identity
    assert connector.list_metrics(SCOPE, "10")["items"][0]["metric_id"] == "400"
    query = HistoryQuery(resource_id="10", metric_id="400", value_type="uint", start=NOW-timedelta(seconds=1), end=NOW)
    assert connector.query_history(SCOPE, query).items[0].value == 2**63
    transport.truncated = True
    with pytest.raises(ConnectorError):
        connector.resource_manifest(SCOPE)
    with pytest.raises(ConnectorError):
        connector.read_events(SCOPE, event_ids=["100"])


@pytest.mark.parametrize("field,value", [("id", "99"), ("native_severity", "critical"), ("state", "resolved"),
                                      ("occurred_at", "invalid"), ("ref", {"source": "forged"})])
def test_bridge_rejects_unbound_events(field, value):
    transport = Bridge(); connector = BridgeConnector(source("rest_webhook"), transport)
    transport.rows["events"][0][field] = value
    with pytest.raises(ConnectorError):
        connector.read_events(SCOPE, event_ids=["100"])


@pytest.mark.parametrize("value", [-1, 1.5, 2**64])
def test_bridge_rejects_invalid_unsigned_counters(value):
    transport = Bridge(); connector = BridgeConnector(source("rest_webhook"), transport)
    transport.rows["history"][0]["value"] = value
    with pytest.raises(ConnectorError):
        connector.query_history(SCOPE, HistoryQuery(resource_id="10", metric_id="400", value_type="uint",
            start=NOW-timedelta(seconds=1), end=NOW))


def test_bridge_rejects_resources_outside_selected_groups():
    transport = Bridge(); connector = BridgeConnector(source("rest_webhook"), transport)
    transport.rows["resources"][0]["group_ids"] = ["99"]
    with pytest.raises(ConnectorError):
        connector.read_resource_batch(SCOPE, ["10"])


@pytest.mark.parametrize("provider", ["solarwinds_orion", "rest_webhook"])
def test_bounded_alert_preview_reports_larger_manifest(provider):
    if provider == "solarwinds_orion":
        transport = Orion()
        transport.responses["active"] = [{"id": 100 + n} for n in range(101)]
        connector = OrionConnector(source(provider), transport)
    else:
        transport = Bridge()
        transport.rows["active"] = [str(100 + n) for n in range(101)]
        connector = BridgeConnector(source(provider), transport)
    assert connector.read_alerts(SCOPE).truncated
