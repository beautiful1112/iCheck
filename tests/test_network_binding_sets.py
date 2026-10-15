"""Explicit source-local binding sets, not inference from vendor row omission."""
from copy import deepcopy
from datetime import timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from icheck.database import SessionLocal
from icheck.models import Endpoint, EndpointAttachment, IPAddressObservation, NetworkObservationState, utcnow
from icheck.network_binding_schemas import NetworkObservationV2, NETWORK_OBSERVATION_V2
from icheck.services.network_observations import equivalent_versioned_body
from test_inventory import create_device
import test_network_observation_ordering as legacy
import test_studio_projection_contracts as studio

session = SessionLocal


def body(device, at, **updates):
    return {"mac_address": legacy.MAC, "source": "arp", "collector_device_id": device,
        "hostname": "current-host", "observed_at": at.isoformat(), "ip_family_scope": "dual_stack",
        "ip_bindings": [{"ip_address": "192.0.2.10", "vlan_id": 10}, {"ip_address": "192.0.2.10", "vlan_id": 20}, {"ip_address": "2001:db8::10", "vlan_id": 10}],
        "attachments": [{"interface_name": "eth1", "vlan_id": 10}, {"interface_name": "eth2", "vlan_id": 20}], **updates}


def post(client, *items, success=True):
    response = client.post("/api/v1/inventory/network-observations/v2", json={"observations": list(items)})
    assert (response.status_code == 200) is success, response.text
    return response


def pairs(db, model, *where):
    attr = "ip_address" if model is IPAddressObservation else "interface_name"
    return {(getattr(row, attr), row.vlan_id) for row in db.scalars(select(model).where(model.active.is_(True), *where))}


def test_simultaneous_ip_vlans_and_parallel_ports_are_not_collapsed(client):
    device, now = create_device(client)["id"], utcnow()
    response = post(client, body(device, now))
    assert response.json()["ip_observations_written"] == 3
    assert response.json()["attachments_written"] == 2
    with session() as db:
        assert pairs(db, IPAddressObservation) == {("192.0.2.10", 10), ("192.0.2.10", 20), ("2001:db8::10", 10)}
        assert pairs(db, EndpointAttachment) == {("eth1", 10), ("eth2", 20)}
    visible = client.get("/api/v1/endpoints").json()[0]
    assert {(row["address"], row["vlan_id"]) for row in visible["current_ips"]} == {("192.0.2.10", 10), ("192.0.2.10", 20), ("2001:db8::10", 10)}
    assert len(visible["current_attachments"]) == 2
    assert all(row["independently_verified"] is False and row["authorizes_incident_closure"] is False
        for row in visible["current_ips"] + visible["current_attachments"])


def test_ipv4_only_set_replaces_only_declared_family_and_omitted_ports_keep_their_clock(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now))
    response = post(client, body(device, now + timedelta(seconds=1), ip_family_scope="ipv4",
        ip_bindings=[{"ip_address": "192.0.2.20", "vlan_id": 30}], attachments=None))
    assert set(response.json()["network_dispositions"][0]["channels"]) == {"metadata", "ipv4"}
    with session() as db:
        assert pairs(db, IPAddressObservation) == {("192.0.2.20", 30), ("2001:db8::10", 10)}
        assert pairs(db, EndpointAttachment) == {("eth1", 10), ("eth2", 20)}
        assert db.scalar(select(NetworkObservationState).where(NetworkObservationState.dimension == "attachment")).observed_at.replace(tzinfo=now.tzinfo) == now


def test_optional_null_or_omitted_sets_do_not_invent_disappearance(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now))
    post(client, body(device, now + timedelta(seconds=1), ip_bindings=None, ip_family_scope=None, attachments=None))
    bare = {"mac_address": legacy.MAC, "source": "arp", "collector_device_id": device,
        "observed_at": (now + timedelta(seconds=2)).isoformat()}
    post(client, bare)
    with session() as db:
        assert len(pairs(db, IPAddressObservation)) == 3 and len(pairs(db, EndpointAttachment)) == 2


def test_empty_sets_clear_only_owned_dimensions_and_delayed_frames_cannot_resurrect(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now))
    post(client, body(device, now + timedelta(seconds=2), ip_family_scope="ipv4", ip_bindings=[], attachments=[]))
    late = post(client, body(device, now + timedelta(seconds=1)))
    assert late.json()["network_dispositions"][0]["channels"]["ipv4"] == "stale"
    assert late.json()["network_dispositions"][0]["channels"]["attachment"] == "stale"
    with session() as db:
        assert pairs(db, IPAddressObservation) == {("2001:db8::10", 10)}
        assert pairs(db, EndpointAttachment) == set()


def test_empty_first_complete_sets_block_late_creation_in_every_declared_dimension(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now + timedelta(seconds=2), ip_bindings=[], attachments=[]))
    delayed = post(client, body(device, now))
    assert set(delayed.json()["network_dispositions"][0]["channels"].values()) == {"stale"}
    with session() as db:
        assert db.scalar(select(func.count()).select_from(IPAddressObservation)) == 0
        assert db.scalar(select(func.count()).select_from(EndpointAttachment)) == 0


def test_reordering_and_normalized_spelling_are_duplicate_without_history_writes(client):
    device, now = create_device(client)["id"], utcnow()
    item = body(device, now)
    post(client, item)
    retry = deepcopy(item)
    retry["mac_address"] = "00-1B-44-11-3A-B7"
    retry["ip_bindings"][2]["ip_address"] = "2001:0DB8:0:0:0:0:0:10"
    retry["ip_bindings"].reverse()
    retry["attachments"].reverse()
    result = post(client, retry).json()
    assert set(result["network_dispositions"][0]["channels"].values()) == {"duplicate"}
    assert result["ip_observations_written"] == result["attachments_written"] == 0
    with session() as db:
        assert db.scalar(select(func.count()).select_from(IPAddressObservation)) == 3


def test_conflicting_sets_retain_all_previous_pairs_until_a_newer_coherent_frame(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now))
    changed = body(device, now, ip_bindings=[{"ip_address": "192.0.2.99", "vlan_id": 30}],
        attachments=[{"interface_name": "eth3", "vlan_id": 30}])
    result = post(client, changed).json()
    assert result["network_dispositions"][0]["channels"]["ipv4"] == "conflict"
    assert result["network_dispositions"][0]["channels"]["attachment"] == "conflict"
    post(client, body(device, now))
    with session() as db:
        assert len(pairs(db, IPAddressObservation)) == 3 and len(pairs(db, EndpointAttachment)) == 2
    visible = client.get("/api/v1/endpoints").json()[0]
    assert all(row["network_observation_state"] == "conflict" for row in visible["current_ips"] + visible["current_attachments"])
    post(client, {**changed, "observed_at": (now + timedelta(seconds=1)).isoformat()})
    with session() as db:
        assert pairs(db, IPAddressObservation) == {("192.0.2.99", 30)}
        assert pairs(db, EndpointAttachment) == {("eth3", 30)}
        assert set(db.scalars(select(NetworkObservationState.state))) == {"accepted"}


def test_conflicting_same_clock_batch_fails_before_any_endpoint_or_cursor(client):
    device, now = create_device(client)["id"], utcnow()
    response = post(client, body(device, now), body(device, now, attachments=[]), success=False)
    assert response.status_code == 422
    with session() as db:
        assert db.scalar(select(func.count()).select_from(Endpoint)) == 0
        assert db.scalar(select(func.count()).select_from(NetworkObservationState)) == 0


def test_source_and_collector_replacement_do_not_clear_someone_elses_bindings(client):
    first, second, now = create_device(client)["id"], create_device(client, name="core-02", kind="linux_server")["id"], utcnow()
    post(client, body(first, now), body(second, now), body(first, now, source="dhcp"))
    post(client, body(first, now + timedelta(seconds=1), ip_bindings=[], attachments=[]))
    with session() as db:
        assert pairs(db, IPAddressObservation, IPAddressObservation.collector_device_id == second)
        assert pairs(db, EndpointAttachment, EndpointAttachment.collector_device_id == second)
        assert len(list(db.scalars(select(IPAddressObservation).where(IPAddressObservation.active.is_(True))))) == 6
        assert len(list(db.scalars(select(EndpointAttachment).where(EndpointAttachment.active.is_(True))))) == 4


def test_reactivation_creates_new_episodes_without_overwriting_inactive_history(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now))
    with session() as db:
        old_ips = {row.id for row in db.scalars(select(IPAddressObservation))}
        old_ports = {row.id for row in db.scalars(select(EndpointAttachment))}
    cleared = now + timedelta(seconds=1)
    post(client, body(device, cleared, ip_bindings=[], attachments=[]))
    post(client, body(device, now + timedelta(seconds=2)))
    with session() as db:
        for model, old in ((IPAddressObservation, old_ips), (EndpointAttachment, old_ports)):
            rows = list(db.scalars(select(model)))
            assert len(rows) == 2 * len(old)
            assert all(not row.active and row.last_seen.replace(tzinfo=now.tzinfo) == cleared for row in rows if row.id in old)
            assert all(row.active and row.first_seen.replace(tzinfo=now.tzinfo) == now + timedelta(seconds=2) for row in rows if row.id not in old)


@pytest.mark.parametrize("v1_first", [True, False])
def test_equal_semantic_retry_across_versions_is_duplicate_not_false_conflict(client, v1_first):
    device, now = create_device(client)["id"], utcnow()
    old = legacy.body(device, now)
    new = body(device, now, ip_family_scope="ipv4", ip_bindings=[{"ip_address": "192.0.2.10", "vlan_id": 10}],
        attachments=[{"interface_name": "eth1", "vlan_id": 10}])
    if v1_first:
        legacy.post(client, old)
        result = post(client, new)
    else:
        post(client, new)
        result = legacy.post(client, old)
    assert set(result.json()["network_dispositions"][0]["channels"].values()) == {"duplicate"}


def test_unknown_legacy_observer_is_not_equivalent_to_an_explicit_empty_attachment_set(client):
    device, now = create_device(client)["id"], utcnow()
    legacy.post(client, legacy.body(device, now, interface_name=None, ip_address=None))
    response = post(client, body(device, now, ip_bindings=None, ip_family_scope=None, attachments=[]))
    assert response.json()["network_dispositions"][0]["channels"]["attachment"] == "conflict"
    with session() as db:
        assert pairs(db, EndpointAttachment) == {(None, 10)}


INVALID = [
    {"ip_family_scope": None}, {"ip_bindings": None}, {"ip_family_scope": "guess"},
    {"ip_family_scope": "ipv4"}, {"source": "wifi_controller"},
    *[{"ip_bindings": [{"ip_address": "192.0.2.10", "vlan_id": value}]} for value in (True, 10.0, "10", 0, 4095)],
    {"ip_bindings": [{"ip_address": "2001:db8::10", "vlan_id": 10}, {"ip_address": "2001:0db8:0:0:0:0:0:10", "vlan_id": 10}]},
    {"ip_bindings": [None]}, {"ip_bindings": ["192.0.2.10"]},
    {"attachments": [{"interface_name": "eth1", "vlan_id": 10}] * 2},
    {"attachments": [None]}, {"attachments": [{"interface_name": None}]},
    *[{"attachments": [{"interface_name": value}]} for value in ("", " eth1", "eth1 ", "eth\n1")],
    {"attachments": [{"interface_name": "eth1", "vlan_id": False}]},
    {"attachments": [{"interface_name": f"eth{index}"} for index in range(65)]},
    {"ip_bindings": [{"ip_address": f"10.0.{index // 256}.{index % 256}"} for index in range(257)]},
]


@pytest.mark.parametrize("updates", INVALID)
def test_invalid_explicit_sets_are_not_coerced_filtered_or_silently_dropped(updates):
    with pytest.raises(ValidationError):
        NetworkObservationV2.model_validate(body(None, utcnow(), **updates))


@pytest.mark.parametrize("updates", INVALID[:14])
def test_invalid_api_batch_is_atomic_even_after_a_valid_item(client, updates):
    device, now = create_device(client)["id"], utcnow()
    response = post(client, body(device, now), body(device, now, **updates), success=False)
    assert response.status_code == 422
    with session() as db:
        assert db.scalar(select(func.count()).select_from(Endpoint)) == 0
        assert db.scalar(select(func.count()).select_from(NetworkObservationState)) == 0


@pytest.mark.parametrize("field", ["ip_bindings", "ip_family_scope", "attachments"])
def test_v2_fields_on_v1_api_are_rejected_instead_of_ignored(client, field):
    device = create_device(client)["id"]
    response = legacy.post(client, {**legacy.body(device, utcnow()), field: None}, success=False)
    assert response.status_code == 422


@pytest.mark.parametrize("field,value", [("ip_address", "192.0.2.10"), ("ip_addresses", []),
    ("vlan_id", 10), ("interface_name", "eth1"), ("attachment_present", True)])
def test_v1_fields_on_v2_api_are_rejected_instead_of_ambiguously_combined(client, field, value):
    device = create_device(client)["id"]
    response = post(client, body(device, utcnow(), **{field: value}), success=False)
    assert response.status_code == 422


@pytest.mark.parametrize("previous,current,dimension", [
    ('{"addresses":[],"vlan_id":true}', {"bindings": []}, "ipv4"),
    ('{"addresses":[],"vlan_id":4095}', {"bindings": []}, "ipv4"),
    ('{"attached":true,"interface_name":null,"vlan_id":10,"raw_data":{}}', {"attachments": [], "raw_data": {}}, "attachment"),
    ('{"addresses":[],"vlan_id":10,"unsupported":true}', {"bindings": []}, "ipv4"),
    ('not-json', {"bindings": []}, "ipv4"),
])
def test_cross_version_comparison_refuses_unknown_or_invalid_legacy_bodies(previous, current, dimension):
    assert equivalent_versioned_body(dimension, previous, current) is False


def test_studio_v2_publication_reaches_scoped_multi_binding_inventory(client, monkeypatch):
    studio.test_studio_published_collector_reaches_scoped_inventory_without_ide(client, monkeypatch, NETWORK_OBSERVATION_V2)


def test_vendor_arrays_publish_v2_bindings_without_an_ide(client, monkeypatch):
    payload = studio.PAYLOADS[NETWORK_OBSERVATION_V2]
    sample = {"identity": {"mac": payload["mac_address"]},
        "addresses": [{"local": row["ip_address"], "segment": row["vlan_id"]} for row in payload["ip_bindings"]],
        "ports": [{"name": row["interface_name"], "tag": row["vlan_id"]} for row in payload["attachments"]]}
    mappings = [
        {"source_field": "identity.mac", "destination_field": "mac_address"},
        {"constant": "arp", "destination_field": "source"},
        {"constant": "dual_stack", "destination_field": "ip_family_scope"},
        {"source_field": "addresses", "destination_field": "ip_bindings", "item_mappings": [
            {"source_field": "local", "destination_field": "ip_address"},
            {"source_field": "segment", "destination_field": "vlan_id"}]},
        {"source_field": "ports", "destination_field": "attachments", "item_mappings": [
            {"source_field": "name", "destination_field": "interface_name"},
            {"source_field": "tag", "destination_field": "vlan_id"}]},
    ]
    spec = {**studio.contract_spec(NETWORK_OBSERVATION_V2).model_dump(mode="json"), "field_mappings": mappings}
    studio.test_studio_published_collector_reaches_scoped_inventory_without_ide(client, monkeypatch,
        NETWORK_OBSERVATION_V2, vendor_sample=sample, vendor_spec=spec)


@pytest.mark.parametrize("limit,ip_count,port_count,truncated", [(50, 256, 64, "IP, wired"), (100, 256, 64, "IP"), (100, 3, 2, None)])
def test_maximum_binding_sets_and_bounded_agent_history_disclose_missing_rows(client, limit, ip_count, port_count, truncated):
    from icheck.builtin_agent_tools import ensure_builtin_agent_tools
    from icheck.schema_validation import validate_instance
    from icheck.services.agent_tools import execute_internal_tool
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now, ip_family_scope="ipv4",
        ip_bindings=[{"ip_address": f"10.1.0.{index}", "vlan_id": 10} for index in range(ip_count)],
        attachments=[{"interface_name": f"eth{index}", "vlan_id": 10} for index in range(port_count)]))
    with session() as db:
        tools = ensure_builtin_agent_tools(db)
        tool = next(row for row in tools if row.name == "inventory.get_endpoint_history")
        arguments = {"mac_address": legacy.MAC, "limit": limit}
        validate_instance(arguments, tool.input_schema, "v2 bounded history arguments")
        result, evidence = execute_internal_tool(db, tool, arguments)
        validate_instance(result, tool.output_schema, "v2 bounded history")
        assert len(result["ip_history"]) == min(limit, ip_count)
        assert len(result["wired_history"]) == min(limit, port_count)
        if truncated is None:
            assert "truncated" not in evidence[0].summary
        else:
            assert f"truncated: {truncated}." in evidence[0].summary
        assert "not an independently verified complete current source snapshot" in evidence[0].summary
        assert len(pairs(db, IPAddressObservation)) == ip_count and len(pairs(db, EndpointAttachment)) == port_count


def test_topology_keeps_parallel_port_vlan_edges_and_discloses_budget(client):
    from icheck.services.topology_views import _topology_graph
    from icheck.studio_schemas import GeneratedTopologySpec
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now, attachments=[{"interface_name": "eth1", "vlan_id": 10},
        {"interface_name": "eth1", "vlan_id": 20}, {"interface_name": "eth2", "vlan_id": 20}]))
    spec = GeneratedTopologySpec(artifact_name="parallel-vlan-bindings", description="Logical parallel links",
        node_types=["device", "endpoint"], edge_types=["wired_attachment"])
    with session() as db:
        graph = _topology_graph(db, spec, node_limit=10, edge_limit=10)
        assert len(graph["edges"]) == len({row["id"] for row in graph["edges"]}) == 3
        assert {(row["metadata"]["interface_name"], row["metadata"]["vlan_id"]) for row in graph["edges"]} == {
            ("eth1", 10), ("eth1", 20), ("eth2", 20)}
        assert graph["edges_truncated"] is False
        bounded = _topology_graph(db, spec, node_limit=10, edge_limit=1)
        assert len(bounded["edges"]) == 1 and bounded["edges_truncated"] is True
