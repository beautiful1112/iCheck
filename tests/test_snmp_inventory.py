from copy import deepcopy
import pytest
from icheck.collectors.snmp_inventory import normalize_tables
from icheck.projection_schemas import NetworkObservationProjectionV2


def sample(metric, value=1, **labels):
    return {"kind": "observation", "type": "metric.sample", "observed_at": "2026-10-14T10:00:00Z",
            "payload": {"metric": metric, "value": value, "labels": labels}}


def fixture():
    return [sample("snmp_scrape_walk_duration_seconds", .1),
        sample("ifName", ifIndex="101", ifName="Gi1/0/1"),
        sample("dot1dBasePortIfIndex", 101, dot1dBasePort="5"),
        sample("dot1qVlanFdbId", 900, dot1qVlanIndex="20", dot1qVlanTimeMark="0"),
        sample("dot1qTpFdbPort", 5, dot1qFdbId="900", dot1qTpFdbAddress="00:11:22:33:44:55"),
        sample("ipNetToMediaPhysAddress", ipNetToMediaIfIndex="101", ipNetToMediaNetAddress="192.0.2.10", ipNetToMediaPhysAddress="0x001122334455")]


def normalize(rows, **kwargs):
    return normalize_tables(rows, target="192.0.2.1", source="fixture", **kwargs)


def test_normalizes_database_records_not_per_mac_prometheus_metrics():
    result = normalize(fixture())
    assert len(result) == 2
    for row in result:
        assert row["type"] == "icheck.inventory.network-observation/v2"
        NetworkObservationProjectionV2.model_validate(row["payload"])
    arp, mac = result
    assert arp["payload"]["ip_bindings"] == [{"ip_address": "192.0.2.10"}]
    assert mac["payload"]["attachments"] == [{"interface_name": "Gi1/0/1", "vlan_id": 20}]


def test_fdb_id_is_not_assumed_to_be_a_vlan_id():
    with pytest.raises(ValueError, match="not a VLAN ID"):
        normalize([row for row in fixture() if row["payload"]["metric"] != "dot1qVlanFdbId"])


def test_bridge_port_is_not_assumed_to_be_ifindex():
    with pytest.raises(ValueError, match="bridge-port"):
        normalize([row for row in fixture() if row["payload"]["metric"] != "dot1dBasePortIfIndex"])


def test_shared_fdb_does_not_invent_multiple_vlan_bindings():
    rows = fixture() + [sample("dot1qVlanFdbId", 900, dot1qVlanIndex="30", dot1qVlanTimeMark="0")]
    with pytest.raises(ValueError, match="unambiguous"):
        normalize(rows)


def test_invalid_neighbor_is_not_a_live_endpoint():
    rows = fixture() + [sample("ipNetToMediaType", 2, ipNetToMediaIfIndex="101", ipNetToMediaNetAddress="192.0.2.10")]
    assert len(normalize(rows)) == 1


def test_complete_walk_required_even_for_empty_table():
    with pytest.raises(ValueError, match="walk-completion"): normalize([])
    assert normalize([sample("snmp_scrape_walk_duration_seconds", .1)]) == []


def test_conflicting_mapping_fails_before_any_partial_output():
    with pytest.raises(ValueError, match="conflicting"):
        normalize(fixture() + [sample("dot1dBasePortIfIndex", 102, dot1dBasePort="5")])


def test_dual_stack_ip_sets_preserved():
    rows = fixture() + [sample("ipNetToPhysicalPhysAddress", ipNetToPhysicalIfIndex="101",
        ipNetToPhysicalNetAddress="2001:db8::1", ipNetToPhysicalPhysAddress="00:11:22:33:44:55")]
    arp = normalize(rows)[0]["payload"]
    assert arp["ip_family_scope"] == "dual_stack" and len(arp["ip_bindings"]) == 2


def test_legacy_bridge_preserves_explicit_context_without_guessing():
    rows = [row for row in fixture() if not row["payload"]["metric"].startswith("dot1q")]
    rows.append(sample("dot1dTpFdbPort", 5, dot1dTpFdbAddress="00:11:22:33:44:55"))
    assert normalize(rows, context_vlan=17)[1]["payload"]["attachments"][0]["vlan_id"] == 17
