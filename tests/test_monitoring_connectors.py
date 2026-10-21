from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError

from icheck.monitoring_connectors.contracts import (
    AlertObservation, HistoryQuery, MetricSample, ObservationBatch, ReadScope,
    RemoteRef, ResourceObservation, SourceIdentity,
)
from icheck.monitoring_connectors.zabbix import ConnectorError, MAX_RESPONSE_BYTES, ZabbixConnector


@pytest.fixture(autouse=True)
def clean_database():
    # These adapter tests have no database dependency and must not initialize one.
    yield


NOW = datetime(2026, 1, 2, 12, tzinfo=UTC)
SOURCE = SourceIdentity(
    tenant_id=UUID(int=1), region_id=UUID(int=2), connection_id=UUID(int=3), provider="zabbix",
)
SCOPE = ReadScope(group_ids=("2",), limit=2)
HOST = {
    "hostid": "101", "host": "switch.example.test", "name": "Branch switch",
    "status": "0", "hostgroups": [{"groupid": "2"}],
    "ipmi_password": "fixture-private-value", "macros": [{"value": "fixture-private-value"}],
}
PROBLEM = {
    "eventid": "701", "objectid": "501", "source": "0", "object": "0",
    "name": "Uplink unavailable", "severity": "4", "clock": "1767351600",
    "acknowledged": "0", "suppressed": "0", "r_eventid": "0", "r_clock": "0",
    "opdata": "fixture-private-value",
}
ITEM = {"itemid": "201", "hostid": "101", "value_type": "3", "units": "B"}
SAMPLE = {"itemid": "201", "clock": "1767351601", "ns": "9", "value": "18446744073709551615"}


class Transport:
    def __init__(self, **results):
        self.results = {"apiinfo.version": "7.0.20", **results}
        self.calls = []

    def request(self, payload, **bounds):
        self.calls.append((deepcopy(payload), bounds))
        assert set(payload) == {"jsonrpc", "id", "method", "params"}
        assert bounds["max_response_bytes"] == MAX_RESPONSE_BYTES
        assert bounds["timeout_seconds"] == SCOPE.timeout_seconds
        result = self.results[payload["method"]]
        if isinstance(result, Exception):
            raise result
        return {"jsonrpc": "2.0", "id": payload["id"], "result": deepcopy(result)}


def adapter(**results):
    transport = Transport(**results)
    return ZabbixConnector(SOURCE, transport, now=lambda: NOW), transport


def history(**updates):
    return HistoryQuery(**{
        "resource_id": "101", "metric_id": "201", "value_type": "uint",
        "start": datetime.fromtimestamp(1767351600, UTC),
        "end": datetime.fromtimestamp(1767351700, UTC), "limit": 2, **updates,
    })


def test_source_identity_is_connection_and_namespace_specific():
    one, _ = adapter(**{"host.get": [HOST]})
    two = ZabbixConnector(SOURCE.model_copy(update={"connection_id": UUID(int=4)}),
                          Transport(**{"host.get": [HOST]}), now=lambda: NOW)
    three = ZabbixConnector(SOURCE.model_copy(update={"tenant_id": UUID(int=5)}),
                            Transport(**{"host.get": [HOST]}), now=lambda: NOW)
    refs = [reader.discover_resources(SCOPE).items[0].ref for reader in (one, two, three)]
    assert len(set(refs)) == 3
    assert {ref.remote_id for ref in refs} == {"101"}


def test_discovery_is_bounded_minimized_and_not_resource_health():
    rows = [HOST, {**HOST, "hostid": "102", "status": "1"}, {**HOST, "hostid": "103"}]
    reader, transport = adapter(**{"host.get": rows})
    batch = reader.discover_resources(SCOPE)
    assert batch.truncated and not batch.authoritative_snapshot
    assert len(batch.items) == 2 and batch.fetched_at == NOW
    assert [item.monitoring_enabled for item in batch.items] == [True, False]
    assert all(item.health == "unknown" for item in batch.items)
    assert "fixture-private-value" not in batch.model_dump_json()
    params = transport.calls[-1][0]["params"]
    assert params["groupids"] == ["2"] and params["limit"] == 3
    assert "selectMacros" not in params
    assert params["output"] == ["hostid", "host", "name", "status"]


def test_empty_discovery_is_not_authoritative_deletion_evidence():
    reader, _ = adapter(**{"host.get": []})
    result = reader.discover_resources(SCOPE)
    assert result.items == () and not result.authoritative_snapshot and not result.truncated


@pytest.mark.parametrize("rows,code", [
    ([HOST, HOST], "duplicate_source_identity"),
    ([{**HOST, "hostgroups": [{"groupid": "9"}]}], "source_scope_mismatch"),
    ([{**HOST, "status": "2"}], "invalid_source_response"),
    ([{**HOST, "name": "private\nline"}], "invalid_source_response"),
    ([{**HOST, "hostid": "0"}], "invalid_source_response"),
    ({"101": HOST}, "invalid_source_response"),
    ([HOST] * 4, "invalid_source_response"),
])
def test_invalid_discovery_is_rejected_without_partial_results(rows, code):
    reader, _ = adapter(**{"host.get": rows})
    with pytest.raises(ConnectorError, match=f"^{code}$"):
        reader.discover_resources(SCOPE)


@pytest.mark.parametrize("version", ["6.0.40", "7.2.1", "8.0.0", "7.4.0alpha1", None, {}])
def test_unqualified_version_stops_before_data_requests(version):
    reader, transport = adapter(**{"apiinfo.version": version})
    with pytest.raises(ConnectorError, match="unsupported_source_version"):
        reader.discover_resources(SCOPE)
    assert len(transport.calls) == 1


@pytest.mark.parametrize("version", ["7.0.0", "7.4.2"])
def test_supported_protocol_targets(version):
    reader, _ = adapter(**{"apiinfo.version": version, "host.get": []})
    assert reader.discover_resources(SCOPE).items == ()


@pytest.mark.parametrize("groups", [(), ("",), ("2/../3",), ("2",) * 101])
def test_empty_or_invalid_scope_is_rejected(groups):
    with pytest.raises(ValidationError):
        ReadScope(group_ids=groups)


def test_non_numeric_zabbix_scope_is_rejected_before_io():
    reader, transport = adapter()
    with pytest.raises(ConnectorError, match="invalid_source_response"):
        reader.discover_resources(ReadScope(group_ids=("all",)))
    assert transport.calls == []


@pytest.mark.parametrize("acknowledged,suppressed,recovered,stop", [
    (False, False, False, False), (True, False, False, False),
    (False, True, False, True), (True, True, False, True),
    (False, False, True, True), (True, False, True, True),
])
def test_alert_states_are_independent(acknowledged, suppressed, recovered, stop):
    row = {**PROBLEM, "acknowledged": str(int(acknowledged)), "suppressed": str(int(suppressed)),
           "r_eventid": "702" if recovered else "0", "r_clock": "1767351650" if recovered else "0"}
    reader, transport = adapter(**{"problem.get": [row]})
    batch = reader.read_alerts(SCOPE)
    alert = batch.items[0]
    assert alert.acknowledged is acknowledged and alert.suppressed is suppressed
    assert alert.state == ("resolved" if recovered else "open")
    assert alert.investigation_stop_required is stop
    assert alert.subject.object_type == "trigger"  # Never pretend trigger ID is a device ID.
    assert alert.native_severity == "4"
    assert bool(alert.recovery_ref) is recovered
    assert not batch.authoritative_snapshot
    assert "fixture-private-value" not in batch.model_dump_json()
    params = transport.calls[-1][0]["params"]
    assert params["recent"] is True and params["groupids"] == ["2"]


@pytest.mark.parametrize("patch,code", [
    ({"r_eventid": "702"}, "invalid_recovery_evidence"),
    ({"r_clock": "1767351650"}, "invalid_recovery_evidence"),
    ({"r_eventid": "702", "r_clock": "1"}, "invalid_source_response"),
    ({"suppressed": None}, "invalid_source_response"),
    ({"acknowledged": "2"}, "invalid_source_response"),
    ({"severity": "6"}, "invalid_source_response"),
    ({"object": "4"}, "unsupported_source_object"),
    ({"source": "3"}, "unsupported_source_object"),
])
def test_alert_validation_does_not_invent_state(patch, code):
    reader, _ = adapter(**{"problem.get": [{**PROBLEM, **patch}]})
    with pytest.raises(ConnectorError, match=f"^{code}$"):
        reader.read_alerts(SCOPE)


def test_empty_recent_problem_response_does_not_prove_recovery():
    reader, _ = adapter(**{"problem.get": []})
    batch = reader.read_alerts(SCOPE)
    assert batch.items == () and not batch.authoritative_snapshot


def test_numeric_history_checks_resource_and_item_and_preserves_uint_precision():
    reader, transport = adapter(**{"host.get": [HOST], "item.get": [ITEM], "history.get": [SAMPLE]})
    batch = reader.query_history(SCOPE, history())
    sample = batch.items[0]
    assert type(sample.value) is int and sample.value == 2**64 - 1
    assert sample.nanoseconds == 9
    assert sample.unit == "B"
    assert sample.resource.remote_id == "101" and sample.metric.remote_id == "201"
    assert [call[0]["method"] for call in transport.calls] == [
        "apiinfo.version", "host.get", "item.get", "history.get",
    ]
    params = transport.calls[-1][0]["params"]
    assert params["history"] == 3 and params["itemids"] == ["201"]
    assert params["hostids"] == ["101"] and params["limit"] == 3


@pytest.mark.parametrize("hosts,items,code", [
    ([], [ITEM], "resource_unavailable_in_scope"),
    ([HOST], [], "metric_unavailable_in_scope"),
    ([HOST], [{**ITEM, "hostid": "999"}], "metric_scope_or_type_mismatch"),
    ([HOST], [{**ITEM, "itemid": "999"}], "metric_scope_or_type_mismatch"),
    ([HOST], [{**ITEM, "value_type": "4"}], "metric_scope_or_type_mismatch"),
])
def test_history_cannot_read_unbound_or_text_metrics(hosts, items, code):
    reader, transport = adapter(**{"host.get": hosts, "item.get": items})
    with pytest.raises(ConnectorError, match=f"^{code}$"):
        reader.query_history(SCOPE, history())
    assert "history.get" not in [call[0]["method"] for call in transport.calls]


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity", "1e999", True, {}, "fixture-private-value"])
def test_non_numeric_or_non_finite_history_is_rejected(value):
    reader, _ = adapter(**{"host.get": [HOST], "item.get": [{**ITEM, "value_type": "0"}],
                          "history.get": [{**SAMPLE, "value": value}]})
    with pytest.raises(ConnectorError, match="^invalid_source_response$"):
        reader.query_history(SCOPE, history(value_type="float"))


def test_float_history_and_truncation():
    rows = [{**SAMPLE, "ns": str(i), "value": str(i / 10)} for i in (1, 2, 3)]
    reader, _ = adapter(**{"host.get": [HOST], "item.get": [{**ITEM, "value_type": "0"}], "history.get": rows})
    batch = reader.query_history(SCOPE, history(value_type="float"))
    assert batch.truncated and [sample.value for sample in batch.items] == [0.1, 0.2]


@pytest.mark.parametrize("rows,code", [
    ([SAMPLE, SAMPLE], "duplicate_source_sample"),
    ([{**SAMPLE, "itemid": "999"}], "metric_scope_or_type_mismatch"),
    ([{**SAMPLE, "ns": "1000000000"}], "invalid_source_response"),
    ([{**SAMPLE, "value": "18446744073709551616"}], "invalid_source_response"),
])
def test_history_rejects_wrong_identity_duplicates_and_overflow(rows, code):
    reader, _ = adapter(**{"host.get": [HOST], "item.get": [ITEM], "history.get": rows})
    with pytest.raises(ConnectorError, match=f"^{code}$"):
        reader.query_history(SCOPE, history())


def test_history_window_rejects_naive_reversed_or_excessive_ranges():
    for patch in ({"end": NOW - timedelta(days=100)}, {"end": NOW + timedelta(days=40)},
                  {"start": NOW.replace(tzinfo=None)}, {"limit": 2001}):
        with pytest.raises(ValidationError):
            history(**patch)


def test_history_keeps_exact_nanosecond_boundary_and_truncation():
    rows = [{**SAMPLE, "ns": "0"}, {**SAMPLE, "ns": "1"}, {**SAMPLE, "ns": "2"}]
    reader, _ = adapter(**{"host.get": [HOST], "item.get": [ITEM], "history.get": rows})
    batch = reader.query_history(SCOPE, history(end=datetime.fromtimestamp(1767351601, UTC)))
    assert len(batch.items) == 1 and batch.items[0].nanoseconds == 0
    assert batch.truncated


def test_history_does_not_accept_out_of_range_source_samples():
    reader, _ = adapter(**{"host.get": [HOST], "item.get": [ITEM],
                          "history.get": [{**SAMPLE, "clock": "1767351800"}]})
    with pytest.raises(ConnectorError, match="source_time_range_mismatch"):
        reader.query_history(SCOPE, history())


def test_transport_failures_do_not_leak_vendor_or_credential_text():
    reader, _ = adapter(**{"apiinfo.version": RuntimeError("fixture-private-value")})
    with pytest.raises(ConnectorError, match="^source_unavailable$") as error:
        reader.read_alerts(SCOPE)
    assert error.value.__suppress_context__


@pytest.mark.parametrize("envelope,code", [
    ({"jsonrpc": "1.0", "id": "same", "result": []}, "invalid_rpc_envelope"),
    ({"jsonrpc": "2.0", "id": "wrong", "result": []}, "invalid_rpc_envelope"),
    ({"jsonrpc": "2.0", "id": "same"}, "invalid_rpc_envelope"),
    ({"jsonrpc": "2.0", "id": "same", "error": {"data": "fixture-private-value"}}, "source_rejected_request"),
    ({"jsonrpc": "2.0", "id": "same", "result": "x" * MAX_RESPONSE_BYTES}, "source_response_too_large"),
])
def test_rpc_response_validation(envelope, code):
    class BrokenTransport:
        def request(self, payload, **_):
            return {**envelope, "id": payload["id"] if envelope["id"] == "same" else envelope["id"]}
    reader = ZabbixConnector(SOURCE, BrokenTransport())
    with pytest.raises(ConnectorError, match=f"^{code}$"):
        reader.discover_resources(SCOPE)


def test_adapter_has_no_write_or_arbitrary_method_path():
    reader, transport = adapter()
    for method in ("event.acknowledge", "host.create", "script.execute", "user.login"):
        with pytest.raises(ConnectorError, match="unsupported_operation"):
            reader._rpc(method, {}, 10)
    assert transport.calls == []


def test_batches_and_evidence_reject_cross_source_references():
    other = SOURCE.model_copy(update={"connection_id": UUID(int=4)})
    local_ref = RemoteRef(source=SOURCE, object_type="host", remote_id="101")
    other_ref = RemoteRef(source=other, object_type="host", remote_id="101")
    with pytest.raises(ValidationError, match="one source"):
        MetricSample(metric=local_ref, resource=other_ref, timestamp=NOW, nanoseconds=0, value=1)
    with pytest.raises(ValidationError, match="one source"):
        AlertObservation(ref=local_ref, subject=other_ref, title="Problem", native_severity="4",
                         state="open", acknowledged=False, suppressed=False, occurred_at=NOW)
    with pytest.raises(ValidationError, match="declared source"):
        ObservationBatch[ResourceObservation](source=SOURCE, fetched_at=NOW, truncated=False,
            items=(ResourceObservation(ref=other_ref, name="Switch", monitoring_enabled=True),))


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), "1"])
def test_shared_metric_contract_rejects_ambiguous_values(value):
    ref = RemoteRef(source=SOURCE, object_type="item", remote_id="201")
    with pytest.raises(ValidationError):
        MetricSample(metric=ref, resource=ref, timestamp=NOW, nanoseconds=0, value=value)


def test_alert_response_is_explicitly_truncated():
    reader, _ = adapter(**{"problem.get": [{**PROBLEM, "eventid": str(i)} for i in (701, 702, 703)]})
    batch = reader.read_alerts(SCOPE)
    assert len(batch.items) == 2 and batch.truncated and not batch.authoritative_snapshot


def test_out_of_bounds_source_timestamp_is_a_sanitized_error():
    reader, _ = adapter(**{"problem.get": [{**PROBLEM, "clock": "18446744073709551615"}]})
    with pytest.raises(ConnectorError, match="^invalid_source_response$"):
        reader.read_alerts(SCOPE)
