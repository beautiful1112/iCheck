"""Vendor-shaped array normalization without model code or manufactured absence."""
from copy import deepcopy

import pytest
from pydantic import ValidationError

from icheck.projection_schemas import NETWORK_OBSERVATION_V1, WIRELESS_SNAPSHOT_V1
from icheck.sandbox import HardenedProcessSandboxExecutor, SandboxRejected
from icheck.services.capability_studio import _fixture
from icheck.studio_schemas import GeneratedCollectorSpec
import test_studio_projection_contracts as prior


def raw_spec(mapping, **updates):
    return GeneratedCollectorSpec.model_validate({
        **prior.FIRST_SPEC, "records_path": None, "subject_field": None,
        "idempotency_field": None, "preserve_unmapped_fields": False,
        "field_mappings": [mapping], **updates,
    })


def extractor(**updates):
    return {"source_field": "rows", "destination_field": "values", "item_field": "address", **updates}


def sandbox_transform(spec, fixture, configuration=None):
    return HardenedProcessSandboxExecutor(python_path="/usr/bin/python3").transform(
        prior.implementation(spec), fixture, configuration or {}, ["observation"]
    )


def test_array_extraction_preserves_order_duplicates_and_explicit_null_not_filtering():
    sample = {"rows": [{"address": "192.0.2.42"}, {"address": None}, {"address": "192.0.2.42"}]}
    spec = raw_spec(extractor())
    original = deepcopy(sample)
    fixture, expected = _fixture(spec, sample)
    assert expected[0]["payload"] == {"values": ["192.0.2.42", None, "192.0.2.42"]}
    assert sandbox_transform(spec, fixture) == expected and sample == original


def test_object_arrays_map_nested_destinations_and_keep_all_rows_and_source_metadata_unchanged():
    literal = "quote'\n__import__('os').system('false')"
    spec = raw_spec({"source_field": "rows", "destination_field": "clients", "item_mappings": [
        {"source_field": "identity.mac", "destination_field": "identity.mac_address"},
        {"source_field": "addresses.0.local", "destination_field": "ip_address"},
        {"constant": literal, "destination_field": "metadata.note"},
    ]})
    sample = {"rows": [{"identity": {"mac": "aa:bb:cc:dd:ee:55", "vendor_secret_shape": "not-copied"}, "addresses": [{"local": "192.0.2.42"}]}]}
    original = deepcopy(sample)
    fixture, expected = _fixture(spec, sample)
    assert sandbox_transform(spec, fixture) == expected
    assert expected[0]["payload"]["clients"] == [{"identity": {"mac_address": "aa:bb:cc:dd:ee:55"}, "ip_address": "192.0.2.42", "metadata": {"note": literal}}]
    assert sample == original and fixture[0]["payload"] == original


def test_nested_arrays_preserve_ragged_lengths_empty_rows_and_relative_source_scope():
    spec = raw_spec({"source_field": "sites", "destination_field": "sites", "item_mappings": [
        {"source_field": "name", "destination_field": "name"},
        {"source_field": "ports", "destination_field": "ports", "item_mappings": [
            {"source_field": "name", "destination_field": "interface_name"},
            {"source_field": "ips", "destination_field": "ip_addresses", "item_field": "local"},
        ]},
    ]})
    sample = {"sites": [{"name": "HQ", "ports": [{"name": "eth1", "ips": [{"local": "192.0.2.42"}, {"local": "2001:db8::42"}]}, {"name": "eth2", "ips": []}]}, {"name": "Branch", "ports": []}]}
    fixture, expected = _fixture(spec, sample)
    assert expected[0]["payload"] == {"sites": [{"name": "HQ", "ports": [{"interface_name": "eth1", "ip_addresses": ["192.0.2.42", "2001:db8::42"]}, {"interface_name": "eth2", "ip_addresses": []}]}, {"name": "Branch", "ports": []}]}
    assert sandbox_transform(spec, fixture) == expected


@pytest.mark.parametrize("singleton", [False, True])
def test_vendor_singleton_object_is_only_wrapped_when_explicitly_declared(singleton):
    spec = raw_spec(extractor(accept_single_object=singleton))
    sample = {"rows": {"address": "192.0.2.42"}}
    if singleton:
        fixture, expected = _fixture(spec, sample)
        assert expected[0]["payload"] == {"values": ["192.0.2.42"]}
        assert sandbox_transform(spec, fixture) == expected
    else:
        with pytest.raises(ValueError, match="must resolve to a list"):
            _fixture(spec, sample)


def test_empty_observed_array_remains_empty_but_all_empty_fixture_cannot_prove_an_item_path():
    spec = raw_spec(extractor(), records_path="frames")
    sample = {"frames": [{"rows": [{"address": "192.0.2.42"}]}, {"rows": []}]}
    fixture, expected = _fixture(spec, sample)
    assert expected[1]["payload"] == {"values": []}
    assert sandbox_transform(spec, fixture) == expected
    with pytest.raises(ValueError, match="not present in the sample objects"):
        _fixture(spec, {"frames": [{"rows": []}]})


@pytest.mark.parametrize("bad", [None, "not-a-list", {"address": "192.0.2.42"}, [1], [None], [{}], [{"address": "ok"}, "tail"], [{"address": "one"}, {"address": "two"}, {"address": "three"}]])
def test_malformed_array_fails_entire_runtime_batch_never_partial_or_empty_output(bad):
    spec = raw_spec(extractor(max_items=2), records_path="frames")
    fixture, _expected = _fixture(spec, {"frames": [{"rows": [{"address": "valid"}]}]})
    invalid = {**fixture[0], "payload": {"rows": bad}}
    with pytest.raises(ValueError):
        _fixture(spec, {"frames": [fixture[0]["payload"], invalid["payload"]]})
    with pytest.raises(SandboxRejected, match="transform must return a list"):
        sandbox_transform(spec, [fixture[0], invalid], {"drop_invalid": True, "max_items": 10000})


def test_missing_array_or_nested_array_is_not_unknown_empty_snapshot():
    spec = raw_spec(extractor())
    fixture, _expected = _fixture(spec, {"rows": [{"address": "valid"}]})
    with pytest.raises(ValueError, match="not present"):
        _fixture(spec, {})
    with pytest.raises(SandboxRejected):
        sandbox_transform(spec, [{**fixture[0], "payload": {}}])
    nested = raw_spec({"source_field": "rows", "destination_field": "rows", "item_mappings": [extractor(source_field="children")]})
    good = {"rows": [{"children": [{"address": "valid"}]}]}
    nested_fixture, _expected = _fixture(nested, good)
    with pytest.raises(ValueError):
        _fixture(nested, {"rows": [{"children": [{"address": "valid"}]}, {"children": None}]})
    with pytest.raises(SandboxRejected):
        sandbox_transform(nested, [{**nested_fixture[0], "payload": {"rows": [{"children": None}]}}])


@pytest.mark.parametrize("updates", [
    {"item_field": None}, {"item_mappings": [{"constant": "x", "destination_field": "label"}]},
    {"max_items": True}, {"max_items": 0}, {"max_items": 10001}, {"accept_single_object": 1},
    {"item_field": "__import__('os')"}, {"filter": "only healthy"}, {"source_field": "rows[*]"},
])
def test_array_spec_cannot_introduce_ambiguous_modes_unbounded_loops_filters_or_expressions(updates):
    with pytest.raises(ValidationError):
        raw_spec(extractor(**updates))


@pytest.mark.parametrize("paths", [["identity", "identity.mac_address"], ["a", "a"], ["a..b"]])
def test_nested_item_destinations_obey_the_same_nonoverlap_and_path_guards(paths):
    with pytest.raises(ValidationError):
        raw_spec({"source_field": "rows", "destination_field": "rows", "item_mappings": [{"constant": "safe", "destination_field": path} for path in paths]})


def test_array_plan_depth_and_total_node_limits_are_not_only_per_list_limits():
    mapping = extractor()
    for _ in range(8):
        mapping = {"source_field": "rows", "destination_field": "rows", "item_mappings": [mapping]}
    with pytest.raises(ValidationError, match="eight nested"):
        raw_spec(mapping)
    huge = [{"source_field": "rows", "destination_field": f"row{index}", "item_mappings": [{"constant": 1, "destination_field": f"value{child}"} for child in range(64)]} for index in range(2)]
    with pytest.raises(ValidationError, match="128 total"):
        raw_spec(huge[0], field_mappings=huge)


def test_response_wide_item_budget_cannot_be_reset_per_envelope_or_overridden_by_configuration():
    spec = raw_spec(extractor())
    fixture, _expected = _fixture(spec, {"rows": [{"address": "x"}]})
    # About 1.8 MiB of bounded input; no device/model/network calls. Every list
    # is individually valid but the complete response visits 101,000 items.
    frames = [{**fixture[0], "payload": {"rows": [{"address": "x"}] * 1000}} for _ in range(101)]
    with pytest.raises(SandboxRejected, match="transform must return a list"):
        sandbox_transform(spec, frames, {"max_total_array_items": 1000000000, "mapping_budget": 1000000000})


@pytest.mark.parametrize("kind", ["linux_addresses", "controller_clients"])
def test_vendor_array_studio_publication_reaches_normalized_scoped_inventory(client, monkeypatch, kind):
    if kind == "linux_addresses":
        record_type = NETWORK_OBSERVATION_V1
        sample = {"address": "aa:bb:cc:dd:ee:55", "ifname": "eth0", "addr_info": [{"local": address} for address in prior.PAYLOADS[record_type]["ip_addresses"]]}
        mappings = [{"source_field": "address", "destination_field": "mac_address"},
            {"source_field": "addr_info", "destination_field": "ip_addresses", "item_field": "local"},
            {"constant": "manual", "destination_field": "source"},
            {"source_field": "ifname", "destination_field": "interface_name"}]
    else:
        record_type = WIRELESS_SNAPSHOT_V1
        sample = {"snapshot": {"complete": True}, "associated": [{"identity": {"mac": "aa:bb:cc:dd:ee:55"}, "address": "192.0.2.42", "wireless": {"network": "Lab"}}]}
        mappings = [{"source_field": "snapshot.complete", "destination_field": "complete_snapshot"},
            {"source_field": "associated", "destination_field": "clients", "item_mappings": [
                {"source_field": "identity.mac", "destination_field": "mac_address"},
                {"source_field": "address", "destination_field": "ip_address"},
                {"source_field": "wireless.network", "destination_field": "ssid"}]}]
    spec = {**prior.contract_spec(record_type).model_dump(mode="json"), "field_mappings": mappings}
    prior.test_studio_published_collector_reaches_scoped_inventory_without_ide(client, monkeypatch, record_type, vendor_sample=sample, vendor_spec=spec, device_kind="linux_server" if kind == "linux_addresses" else None)


def test_recursive_mapping_schema_is_json_serializable_and_legacy_shape_is_unchanged():
    import json
    schema = GeneratedCollectorSpec.model_json_schema()
    assert json.loads(json.dumps(schema))["$defs"]["CollectorArrayMapping"]["properties"]["item_mappings"]
    assert GeneratedCollectorSpec.model_validate(prior.FIRST_SPEC).model_dump(mode="json") == prior.FIRST_SPEC


@pytest.mark.parametrize("value", ["aa:bb:cc:dd:ee:55", 7, None, False, ["nested"]])
def test_scalar_root_records_match_trusted_adapter_value_wrapper(value):
    from icheck.collectors.http_json import document_to_envelopes
    spec = raw_spec({"source_field": "value", "destination_field": "observed_value"})
    fixture, expected = _fixture(spec, [value])
    trusted = document_to_envelopes({"output_kinds": ["observation"]}, [value], {"record_type": spec.record_type, "source": spec.source})
    assert fixture[0]["payload"] == trusted[0]["payload"] == {"value": value}
    assert sandbox_transform(spec, fixture) == expected


def test_scalar_array_items_can_be_extracted_or_remapped_as_objects_without_type_coercion():
    spec = raw_spec({"source_field": "rows", "destination_field": "rows", "item_mappings": [
        {"source_field": "value", "destination_field": "measurement"},
        {"constant": "unknown-is-not-quiet", "destination_field": "label"},
    ]})
    sample = {"rows": [1, None, False, "7"]}
    fixture, expected = _fixture(spec, sample)
    assert sandbox_transform(spec, fixture) == expected
    assert [row["measurement"] for row in expected[0]["payload"]["rows"]] == sample["rows"]
    assert [type(row["measurement"]) for row in expected[0]["payload"]["rows"]] == [int, type(None), bool, str]
    scalar = raw_spec(extractor(item_field="value"))
    scalar_fixture, scalar_expected = _fixture(scalar, sample)
    assert scalar_expected[0]["payload"] == {"values": sample["rows"]}
    assert sandbox_transform(scalar, scalar_fixture) == scalar_expected


def test_primitive_record_identity_retry_and_clock_fields_match_fixture_and_trusted_envelopes():
    from icheck.collectors.http_json import document_to_envelopes
    spec = raw_spec({"source_field": "value", "destination_field": "collection_time"},
        subject_field="value", idempotency_field="value", observed_at_field="value")
    sample = ["2026-10-05T12:00:00+02:00"]
    fixture, expected = _fixture(spec, sample)
    trusted = document_to_envelopes({"output_kinds": ["observation"]}, sample,
        {"record_type": spec.record_type, "source": spec.source, "subject_field": "value", "idempotency_field": "value", "observed_at_field": "value"})
    assert trusted == fixture
    assert trusted[0]["observed_at"] == "2026-10-05T10:00:00+00:00"
    assert trusted[0]["subject"] == trusted[0]["idempotency_key"] == sample[0]
    assert sandbox_transform(spec, trusted) == expected
