"""Candidate structure and real sandbox-to-inventory flow, not live truth."""
from copy import deepcopy
import json

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from icheck.collector_condition_schemas import COLLECTOR_CONDITION_V1
from icheck.collectors.http_json import document_to_envelopes
from icheck.collectors.http_json_sandbox import collect_http_json_sandbox
from icheck.database import SessionLocal
from icheck.models import Endpoint, KnowledgeEntity, KnowledgeProjectionStatus, KnowledgeRelationship, utcnow
from icheck.projection_schemas import (
    ALERT_EVENT_V1,
    DEVICE_ADJACENCY_SNAPSHOT_V1,
    KNOWLEDGE_ENTITY_V1,
    KNOWLEDGE_RELATIONSHIP_V1,
    NETWORK_OBSERVATION_V1,
    NETWORK_OBSERVATION_V2,
    PROJECTION_CONTRACT_MODELS,
    SUPPORTED_PROJECTION_CONTRACTS,
    WIRELESS_SNAPSHOT_V1,
)
from icheck.sandbox import HardenedProcessSandboxExecutor, SandboxRejected
from icheck.service_indicator_schemas import ARTIFACT_INDICATOR_CONTRACT
from icheck.services.capability_studio import _compile_transform, _fixture
from icheck.schema_validation import validate_instance
from icheck.services.knowledge_projection import claim_projections, process_projection_assignment, register_projection_worker
from icheck.studio_schemas import GeneratedCollectorSpec
from test_capability_studio import FIRST_SPEC, FakeStructuredOpener, configure_authoring_route, studio_payload


session = SessionLocal
CONDITION = {"key": "cpu.high", "event_type": "device.cpu.high", "entity_type": "device", "title": "High CPU", "operator": "gt", "expected": 90}
PAYLOADS = {
    NETWORK_OBSERVATION_V1: {"mac_address": "aa:bb:cc:dd:ee:55", "ip_addresses": ["192.0.2.42", "192.0.2.43", "2001:db8::42"], "source": "arp", "interface_name": "Ethernet1/3", "vlan_id": 20},
    NETWORK_OBSERVATION_V2: {"mac_address": "aa:bb:cc:dd:ee:55", "source": "arp", "ip_family_scope": "dual_stack",
        "ip_bindings": [{"ip_address": "192.0.2.42", "vlan_id": 20}, {"ip_address": "192.0.2.42", "vlan_id": 30}, {"ip_address": "2001:db8::42", "vlan_id": 20}],
        "attachments": [{"interface_name": "Ethernet1/3", "vlan_id": 20}, {"interface_name": "Ethernet1/4", "vlan_id": 30}]},
    WIRELESS_SNAPSHOT_V1: {"complete_snapshot": True, "clients": [{"mac_address": "aa:bb:cc:dd:ee:55", "ip_address": "192.0.2.42", "ssid": "Lab"}]},
    KNOWLEDGE_ENTITY_V1: {"entity_type": "network_device", "external_key": "edge-01", "display_name": "Edge one", "attributes": {"platform": "test"}},
    KNOWLEDGE_RELATIONSHIP_V1: {"relationship_type": "connected_to", "source": {"entity_type": "network_device", "external_key": "edge-01"}, "target": {"entity_type": "network_device", "external_key": "edge-02"}},
    DEVICE_ADJACENCY_SNAPSHOT_V1: {"local_device_key": "edge-01", "protocol": "lldp", "neighbors": [{"remote_device_key": "edge-02", "local_port": "Ethernet1/1", "remote_port": "Ethernet1/2"}]},
    ALERT_EVENT_V1: {"event_type": "lab.link.down", "entity_type": "device", "entity_id": "edge-01", "title": "Link down"},
    COLLECTOR_CONDITION_V1: {"condition_key": "cpu.high", "value": 99},
    ARTIFACT_INDICATOR_CONTRACT: {"contract_version": ARTIFACT_INDICATOR_CONTRACT, "binding_key": "lab.cpu", "value": 42.0},
}


def contract_spec(record_type, **updates):
    return GeneratedCollectorSpec.model_validate({
        **FIRST_SPEC, "records_path": None, "record_type": record_type,
        "subject_field": None, "idempotency_field": None, "preserve_unmapped_fields": False,
        "field_mappings": [{"source_field": key, "destination_field": key} for key in PAYLOADS[record_type]],
        **({"condition_contracts": [CONDITION]} if record_type == COLLECTOR_CONDITION_V1 else {}),
        **updates,
    })


def implementation(spec):
    return {"runtime": "python_sandbox_v1", "adapter": "http_json_sandbox", "entrypoint": "transform", "source": _compile_transform(spec)}


def test_studio_contract_catalog_matches_runtime_dispatch_and_denies_authority(client):
    response = client.get("/api/v1/capability-studio/collector-contracts")
    assert response.status_code == 200, response.text
    documents = response.json()
    assert {(item["envelope_kind"], item["record_type"]) for item in documents} == {
        (kind.value, name) for kind, name in SUPPORTED_PROJECTION_CONTRACTS
    }
    assert len(documents) == len(PAYLOADS) == 9
    assert all(item["payload_schema"]["type"] == "object" and item["qualification"] == "structural_only"
               and item["independently_verified"] is False and item["authorizes_incident_closure"] is False for item in documents)


@pytest.mark.parametrize("record_type", list(PAYLOADS))
def test_registered_candidates_use_exact_payload_contract_and_real_sandbox_kind(record_type):
    spec = contract_spec(record_type)
    fixture, expected = _fixture(spec, deepcopy(PAYLOADS[record_type]))
    kind = PROJECTION_CONTRACT_MODELS[record_type][0].value
    assert fixture[0]["kind"] == expected[0]["kind"] == kind
    report = HardenedProcessSandboxExecutor(python_path="/usr/bin/python3").validate(
        implementation(spec),
        [{"name": "normalized contract", "fixture": fixture, "configuration": {}, "expected": expected}], [kind],
    )
    assert report["network"] == "denied" and report["tests"][0]["passed"] is True
    assert expected[0]["payload"] == PAYLOADS[record_type]


@pytest.mark.parametrize("record_type", ["icheck.unknown/v1", "icheck.inventory.network-observation/v3", "https://bad.test/schema", "bad/name", "__import__('os')"])
def test_unregistered_versioned_or_executable_record_names_are_refused(record_type):
    with pytest.raises(ValidationError, match="registered projection contract"):
        GeneratedCollectorSpec.model_validate({**FIRST_SPEC, "record_type": record_type})


@pytest.mark.parametrize("paths", [["source", "source.external_key"], ["source.external_key", "source"], ["a.b", "a.b.c"], ["a", "a"], ["a..b"], ["a.0"], ["a.b.c.d.e.f.g.h.i"]])
def test_nested_destinations_reject_parent_overlap_duplicates_or_invalid_shapes(paths):
    with pytest.raises(ValidationError):
        GeneratedCollectorSpec.model_validate({**FIRST_SPEC, "field_mappings": [{"constant": "safe", "destination_field": path} for path in paths]})


def test_nested_source_indices_and_destinations_copy_on_write_and_do_not_execute_literals():
    source = {"ports": [{"id": "edge-01"}], "metadata": {"retained": "yes"}}
    original = deepcopy(source)
    literal = "quote'\n__import__('os').system('false')"
    spec = GeneratedCollectorSpec.model_validate({**FIRST_SPEC, "records_path": None, "subject_field": None, "idempotency_field": None,
        "field_mappings": [{"source_field": "ports.0.id", "destination_field": "metadata.identity"}, {"constant": literal, "destination_field": "metadata.label"}]})
    fixture, expected = _fixture(spec, source)
    assert source == original and fixture[0]["payload"] == original
    assert expected[0]["payload"]["metadata"] == {"retained": "yes", "identity": "edge-01", "label": literal}
    executor = HardenedProcessSandboxExecutor(python_path="/usr/bin/python3")
    output = executor.transform(implementation(spec), fixture, {}, ["observation"])
    assert output == expected and fixture[0]["payload"] == original
    # A runtime parent changing to a scalar must fail the entire transform,
    # not discard it, silently overwrite it, or relax the sandbox AST policy.
    broken = deepcopy(fixture)
    broken[0]["payload"]["metadata"] = "not-an-object"
    with pytest.raises(SandboxRejected):
        executor.transform(implementation(spec), broken, {}, ["observation"])


@pytest.mark.parametrize("value", [None, True, 123, {}, "not-a-time"])
def test_explicit_clock_mapping_rejects_missing_or_invalid_clock_in_fixture_and_adapter(value):
    spec = contract_spec(NETWORK_OBSERVATION_V1, observed_at_field="clock")
    record = {**PAYLOADS[NETWORK_OBSERVATION_V1], "clock": value}
    with pytest.raises(ValueError):
        _fixture(spec, record)
    with pytest.raises(ValueError):
        document_to_envelopes({"output_kinds": ["observation"]}, record, {"observed_at_field": "clock"})


def test_source_clock_is_required_in_every_record_and_matches_worker_utc_normalization():
    spec = contract_spec(NETWORK_OBSERVATION_V1, observed_at_field="clock", records_path="rows")
    record = {**PAYLOADS[NETWORK_OBSERVATION_V1], "clock": "2026-10-05T12:00:00+02:00"}
    fixture, expected = _fixture(spec, {"rows": [record]})
    trusted = document_to_envelopes({"output_kinds": ["observation"]}, record, {"observed_at_field": "clock"})
    assert trusted[0]["observed_at"] == fixture[0]["observed_at"] == expected[0]["observed_at"] == "2026-10-05T10:00:00+00:00"
    with pytest.raises(ValueError, match="not found"):
        _fixture(spec, {"rows": [record, PAYLOADS[NETWORK_OBSERVATION_V1]]})
    with pytest.raises(ValueError, match="not found"):
        document_to_envelopes({"output_kinds": ["observation"]}, PAYLOADS[NETWORK_OBSERVATION_V1], {"observed_at_field": "clock"})


@pytest.mark.parametrize("key", ["envelope_kind", "record_type", "source", "records_path", "subject_field", "idempotency_field", "observed_at_field"])
def test_deployment_configuration_cannot_rewrite_reviewed_output_or_disable_clock(key):
    from icheck.models import CapabilityStudioSession
    from icheck.services.capability_studio import _artifact_payload
    spec = contract_spec(NETWORK_OBSERVATION_V1, observed_at_field="clock")
    sample = {**PAYLOADS[NETWORK_OBSERVATION_V1], "clock": "2026-10-05T10:00:00Z"}
    candidate = _artifact_payload(CapabilityStudioSession(id="fixture-session", sample_document=sample, source_context={}, target_url="https://inventory.example.test/data"), spec, actor="test")
    schema = candidate.initial_version.collector_definition.config_schema
    validate_instance({}, schema, "configuration")
    validate_instance({key: candidate.initial_version.collector_definition.defaults.get(key)}, schema, "configuration")
    with pytest.raises(ValueError):
        validate_instance({key: "rewritten"}, schema, "configuration")
    if key == "observed_at_field":
        for value in (None, ""):
            with pytest.raises(ValueError):
                validate_instance({key: value}, schema, "configuration")


@pytest.mark.parametrize("change", ["invalid_mac", "duplicate_ip", "ambiguous_ip", "boolean_vlan", "contradictory_detach", "wifi_bypass", "extra_vendor_field"])
def test_invalid_normalized_network_fixture_cannot_be_sandbox_validated(change):
    payload = deepcopy(PAYLOADS[NETWORK_OBSERVATION_V1])
    if change == "invalid_mac": payload["mac_address"] = "not-a-mac"
    elif change == "duplicate_ip": payload["ip_addresses"] = ["2001:db8::42", "2001:0db8::42"]
    elif change == "ambiguous_ip": payload["ip_address"] = "192.0.2.44"
    elif change == "boolean_vlan": payload["vlan_id"] = True
    elif change == "contradictory_detach": payload["attachment_present"] = False
    elif change == "wifi_bypass": payload["source"] = "wifi_controller"
    elif change == "extra_vendor_field": payload["vendor_payload"] = {"unsafe": "raw"}
    spec = contract_spec(NETWORK_OBSERVATION_V1, preserve_unmapped_fields=True)
    with pytest.raises(ValueError):
        _fixture(spec, payload)


@pytest.mark.parametrize("change", ["boolean_completeness", "boolean_rssi", "duplicate_mac", "mismatched_clock"])
def test_invalid_wireless_candidate_keeps_runtime_coherence_guards(change):
    payload = deepcopy(PAYLOADS[WIRELESS_SNAPSHOT_V1])
    if change == "boolean_completeness": payload["complete_snapshot"] = 1
    elif change == "boolean_rssi": payload["clients"][0]["rssi"] = True
    elif change == "duplicate_mac": payload["clients"].append({"mac_address": "AA-BB-CC-DD-EE-55"})
    elif change == "mismatched_clock": payload["clients"][0]["observed_at"] = "2026-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        _fixture(contract_spec(WIRELESS_SNAPSHOT_V1), payload)


def _generate_publish(client, monkeypatch, spec, sample):
    configure_authoring_route(client)
    opener = FakeStructuredOpener([spec.model_dump(mode="json")])
    monkeypatch.setattr("icheck.services.structured_model.build_opener", lambda *_: opener)
    executor = HardenedProcessSandboxExecutor(python_path="/usr/bin/python3")
    monkeypatch.setattr("icheck.services.collectors.default_sandbox_executor", lambda: executor)
    created = client.post("/api/v1/capability-studio/sessions", json={**studio_payload(), "sample_document": sample})
    assert created.status_code == 201, created.text
    sid = created.json()["id"]
    generated = client.post(f"/api/v1/capability-studio/sessions/{sid}/generate", json={"actor": "capability.author"})
    assert generated.status_code == 200 and generated.json()["status"] == "validated", generated.text
    prompt = json.loads(opener.requests[0][0].data)["messages"][1]["content"]
    assert "projection_contracts" in prompt
    if spec.record_type in PROJECTION_CONTRACT_MODELS:
        assert spec.record_type in prompt
    document = generated.json()
    published = client.post(f"/api/v1/capability-studio/sessions/{sid}/publish", json={"actor": "capability.publisher", "expected_artifact_version_id": document["artifact_version_id"]})
    assert published.status_code == 200, published.text
    return client.get(f'/api/v1/artifacts/{document["artifact_id"]}').json()["versions"][0], executor


@pytest.mark.parametrize("record_type", [NETWORK_OBSERVATION_V1, WIRELESS_SNAPSHOT_V1, KNOWLEDGE_ENTITY_V1, KNOWLEDGE_RELATIONSHIP_V1])
def test_studio_published_collector_reaches_scoped_inventory_without_ide(client, monkeypatch, record_type, *, vendor_sample=None, vendor_spec=None, device_kind=None):
    sample = deepcopy(PAYLOADS[record_type] if vendor_sample is None else vendor_sample)
    sample["collection_clock"] = utcnow().isoformat()
    sample["frame_id"] = "controlled-collection-frame"
    spec = contract_spec(record_type, observed_at_field="collection_clock", idempotency_field="frame_id") if vendor_spec is None else GeneratedCollectorSpec.model_validate({
        **vendor_spec, "observed_at_field": "collection_clock", "idempotency_field": "frame_id"
    })
    version, executor = _generate_publish(client, monkeypatch, spec, sample)
    kind = PROJECTION_CONTRACT_MODELS[record_type][0].value
    assert version["collector_definition"]["output_kinds"] == [kind]
    assert version["definition"]["projection_contract"]["support"] == "registered_structural"
    device = client.post("/api/v1/devices", json={"name": "inventory.example.test", "kind": device_kind or ("wireless_controller" if record_type == WIRELESS_SNAPSHOT_V1 else "switch"), "site": "HQ", "created_by": "test"})
    assert device.status_code == 201, device.text
    device = device.json()
    deployment_payload = {"name": "studio-normalized", "artifact_version_id": version["id"],
        "scope_device_id": device["id"], "scope_device_identity_revision": device["identity_revision"], "scope_site": "HQ", "target_classification": "registered_device",
        "target": {"url": "https://inventory.example.test/data"}, "configuration": {}, "worker_selector": {"site": "HQ"}, "schedule_seconds": 300, "created_by": "test"}
    for key, value in {"record_type": "icheck.unknown/v1", "envelope_kind": "rewritten", "observed_at_field": None}.items():
        denied = client.post("/api/v1/collector-deployments", json={**deployment_payload, "name": "denied-"+key, "configuration": {key: value}})
        assert denied.status_code == 422, denied.text
    deployment = client.post("/api/v1/collector-deployments", json=deployment_payload)
    assert deployment.status_code == 201, deployment.text
    # Use a controlled valid registration token, never an auth dependency bypass.
    from icheck import collector_api
    token = "studio-native-controlled-registration"
    monkeypatch.setattr(collector_api.settings, "collector_registration_token", token)
    registered = client.post("/api/v1/collector-workers/register", json={"name": "studio-collector", "site": "HQ", "capabilities": ["http_json_sandbox"], "labels": {"io_supervisor_v1": True}}, headers={"X-iCheck-Registration-Token": token})
    assert registered.status_code == 200, registered.text
    headers = {"Authorization": "Bearer " + registered.json()["access_token"]}
    claimed = client.post(f'/api/v1/collector-workers/{registered.json()["worker"]["id"]}/leases/claim', json={"max_assignments": 1, "lease_seconds": 120}, headers=headers)
    assert claimed.status_code == 200 and len(claimed.json()) == 1, claimed.text
    assignment = claimed.json()[0]
    admitted = client.post(f'/api/v1/collector-runs/{assignment["run_id"]}/admit', json={"lease_token": assignment["lease_token"], "assignment_sha256": assignment["assignment_sha256"]}, headers=headers)
    assert admitted.status_code == 200, admitted.text

    class FixtureResponse:
        def __enter__(self): return self
        def __exit__(self, *_): return None
        def read(self, limit): return json.dumps(sample).encode()[:limit]
    class FixtureTransport:
        def open(self, request, timeout):
            assert request.full_url == "https://inventory.example.test/data" and request.method == "GET"
            return FixtureResponse()
    monkeypatch.setattr("icheck.collectors.http_json.build_opener", lambda *_: FixtureTransport())
    output = collect_http_json_sandbox({**assignment, "_runtime": {"http_allowed_hosts": ["inventory.example.test"], "lease_seconds": 120, "sandbox_executor": executor}})
    assert output[0]["kind"] == kind and output[0]["type"] == record_type
    accepted = client.post(f'/api/v1/collector-runs/{assignment["run_id"]}/envelopes', json={"lease_token": assignment["lease_token"], "envelopes": output}, headers=headers)
    assert accepted.status_code == 200 and accepted.json()["accepted"] == 1, accepted.text
    duplicate = client.post(f'/api/v1/collector-runs/{assignment["run_id"]}/envelopes', json={"lease_token": assignment["lease_token"], "envelopes": output}, headers=headers)
    assert duplicate.status_code == 200 and duplicate.json()["duplicates"] == 1, duplicate.text
    with session() as db:
        worker = register_projection_worker(db, name="studio-projection")
        claimed_projections = claim_projections(db, worker, limit=1, lease_seconds=120)
        assert len(claimed_projections) == 1
        result = process_projection_assignment(db, worker, claimed_projections[0])
        assert result.status == KnowledgeProjectionStatus.SUCCEEDED, result.error_type
        if record_type in {NETWORK_OBSERVATION_V1, NETWORK_OBSERVATION_V2, WIRELESS_SNAPSHOT_V1}:
            endpoint = db.scalar(select(Endpoint).where(Endpoint.mac_address == "aa:bb:cc:dd:ee:55"))
            assert endpoint is not None
            if record_type == NETWORK_OBSERVATION_V1:
                assert {row.ip_address for row in endpoint.ip_observations if row.active} == set(PAYLOADS[record_type]["ip_addresses"])
            elif record_type == NETWORK_OBSERVATION_V2:
                assert {(row.ip_address, row.vlan_id) for row in endpoint.ip_observations if row.active} == {
                    (row["ip_address"], row["vlan_id"]) for row in PAYLOADS[record_type]["ip_bindings"]}
                assert {(row.interface_name, row.vlan_id) for row in endpoint.attachments if row.active} == {
                    (row["interface_name"], row["vlan_id"]) for row in PAYLOADS[record_type]["attachments"]}
            else:
                assert len([row for row in endpoint.wireless_sessions if row.active]) == 1
        elif record_type == KNOWLEDGE_ENTITY_V1:
            entity = db.scalar(select(KnowledgeEntity).where(KnowledgeEntity.external_key == "edge-01"))
            assert entity is not None and entity.scope_device_id == device["id"]
        else:
            relationship = db.scalar(select(KnowledgeRelationship))
            assert relationship is not None and relationship.scope_device_id == device["id"]


def test_custom_raw_collector_remains_compatible_but_does_not_claim_normalized_inventory(client, monkeypatch):
    spec = GeneratedCollectorSpec.model_validate(FIRST_SPEC)
    assert spec.model_dump(mode="json") == FIRST_SPEC
    version, _executor = _generate_publish(client, monkeypatch, spec, studio_payload()["sample_document"])
    assert version["definition"]["projection_contract"]["support"] == "raw_only"
    assert version["collector_definition"]["output_kinds"] == ["observation"]
    sessions = client.get("/api/v1/capability-studio/sessions").json()
    assert "raw-only" in sessions[0]["messages"][-2]["content"] or any("raw-only" in item["content"] for item in sessions[0]["messages"])


def test_invalid_normalized_generation_is_terminal_accounted_and_traceable_without_publishable_candidate(client, monkeypatch):
    configure_authoring_route(client)
    spec = contract_spec(NETWORK_OBSERVATION_V1)
    opener = FakeStructuredOpener([spec.model_dump(mode="json")])
    monkeypatch.setattr("icheck.services.structured_model.build_opener", lambda *_: opener)
    sample = {**PAYLOADS[NETWORK_OBSERVATION_V1], "mac_address": "not-a-mac"}
    created = client.post("/api/v1/capability-studio/sessions", json={**studio_payload(), "sample_document": sample})
    assert created.status_code == 201, created.text
    sid = created.json()["id"]
    generated = client.post(f"/api/v1/capability-studio/sessions/{sid}/generate", json={"actor": "capability.author"})
    assert generated.status_code == 422, generated.text
    failed = client.get(f"/api/v1/capability-studio/sessions/{sid}").json()
    assert failed["status"] == "failed" and failed["tokens_used"] == 42
    assert failed["artifact_id"] is None and failed["artifact_version_id"] is None
    assert failed["current_spec"]["record_type"] == NETWORK_OBSERVATION_V1
    attempts = client.get(f"/api/v1/capability-studio/sessions/{sid}/generations").json()
    assert len(attempts) == 1 and attempts[0]["status"] == "failed"
    publish = client.post(f"/api/v1/capability-studio/sessions/{sid}/publish", json={"actor": "capability.publisher", "expected_artifact_version_id": "absent"})
    assert publish.status_code in {409, 422}, publish.text


def test_contract_catalog_requires_authenticated_global_authoring_permission(client, monkeypatch):
    from icheck.config import get_settings
    from test_control_plane_auth import _required_auth, _restore_disabled_auth
    _required_auth(monkeypatch)
    try:
        assert client.get("/api/v1/capability-studio/collector-contracts").status_code == 401
        bootstrap = client.post("/api/v1/auth/bootstrap", headers={"X-Icheck-Bootstrap-Token": get_settings().control_plane_bootstrap_token},
            json={"subject": "catalog-admin", "display_name": "Catalog administrator", "token_name": "catalog-admin", "expires_in_hours": 24})
        assert bootstrap.status_code == 201, bootstrap.text
        admin = {"Authorization": "Bearer " + bootstrap.json()["token"]["access_token"]}
        assert client.get("/api/v1/capability-studio/collector-contracts", headers=admin).status_code == 200
        roles = client.get("/api/v1/auth/roles", headers=admin).json()
        viewer = next(role for role in roles if role["name"] == "viewer")
        created = client.post("/api/v1/auth/principals", headers=admin, json={"subject": "catalog-viewer", "display_name": "Catalog viewer"})
        assert created.status_code == 201, created.text
        pid = created.json()["id"]
        bound = client.post(f"/api/v1/auth/principals/{pid}/bindings", headers=admin, json={"role_id": viewer["id"], "scope": {"sites": ["HQ"]}})
        assert bound.status_code == 201, bound.text
        issued = client.post(f"/api/v1/auth/principals/{pid}/tokens", headers=admin, json={"name": "catalog-viewer", "expires_in_hours": 24})
        assert issued.status_code == 201, issued.text
        denied = client.get("/api/v1/capability-studio/collector-contracts", headers={"Authorization": "Bearer " + issued.json()["access_token"]})
        assert denied.status_code == 403, denied.text
    finally:
        _restore_disabled_auth(monkeypatch)
