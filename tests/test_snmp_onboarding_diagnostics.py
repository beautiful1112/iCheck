import io
import ipaddress
import json
from urllib.error import HTTPError

import pytest

from icheck import device_preflight_worker as preflights
from icheck.collectors.snmp_exporter import SNMPExporterFailure, _http_failure
from icheck.database import SessionLocal
from icheck.models import Device, DeviceConnection, DeviceMonitoringEnrollment, utcnow
from icheck.snmp_modules import safe_sysname, validate_modules
from test_device_preflights import onboard_device, register_worker
from test_device_onboarding import create_network_credential
from test_managed_device_credentials import device_key, credential


@pytest.mark.parametrize("modules", [["snmp_exporter"], ["snmp_topology"], ["does_not_exist"],
    [], ["if_mib", "if_mib"], "if_mib", ["bad name"], [None]])
def test_modules_are_catalog_names_not_adapter_permissions(modules):
    with pytest.raises(ValueError):
        validate_modules(modules, available=["if_mib", "system"])


def test_catalog_and_all_onboarding_paths_reject_invalid_modules(client):
    create_network_credential(client)
    catalog = client.get("/api/v1/assets/snmp-modules")
    assert catalog.status_code == 200 and "system" in catalog.json()["modules"]
    assert "snmp_exporter" not in catalog.json()["modules"]
    response = client.post("/api/v1/assets/devices", json={"name": "test", "kind": "switch",
        "management_ip": "198.18.0.20", "created_by": "operator", "connections": [{"protocol": "snmp",
            "configuration": {"modules": ["snmp_exporter", "snmp_topology"]}}]})
    assert response.status_code == 422 and "not SNMP modules" in response.text
    plan = client.post("/api/v1/assets/onboarding/preview", json={"credential_profile_ref": "lab-network-readonly",
        "devices": [{"name": "test", "kind": "switch", "management_ip": "198.18.0.20"}],
        "modules": ["snmp_exporter", "snmp_topology"]})
    assert plan.status_code == 422 and "not SNMP modules" in plan.text
    assert client.get("/api/v1/assets/devices").json() == []


@pytest.mark.parametrize("body,code", [(b"Unknown module 'if_mib'\n", "snmp_unknown_module"),
    (b"Unknown auth 'public_v2'\n", "snmp_unknown_auth"),
    (b"Unknown module 'secret-value'", "snmp_exporter_http_error"),
    (b"password=secret-value; community=secret-value", "snmp_exporter_http_error"),
    (b"x" * 10000, "snmp_exporter_http_error")])
def test_http_400_diagnostics_are_exact_only_for_safe_recognized_constraints(body, code):
    error = HTTPError("http://127.0.0.1/snmp", 400, "Bad Request", {}, io.BytesIO(body))
    failure = _http_failure(error, ["if_mib"], "public_v2")
    assert failure.diagnostic["code"] == code
    assert failure.diagnostic["http_status"] == 400
    assert "secret-value" not in str(failure) + json.dumps(failure.diagnostic)
    assert len(str(failure)) < 500 and error.fp.closed


def test_preflight_uses_fixed_identity_query_and_nondefault_port(monkeypatch):
    captured = []
    def collect(assignment):
        captured.append(assignment)
        return [{"payload": {"metric": "sysName", "labels": {"sysName": "access"}}},
            {"payload": {"metric": "sysUpTime", "labels": {}}}]
    monkeypatch.setattr(preflights, "collect_snmp_exporter", collect)
    evidence, _ = preflights._snmp_preflight({"port": 1161, "configuration": {"modules": ["if_mib"]},
        "_runtime": {"credential": {"community": "synthetic-only"}}}, ipaddress.ip_address("198.18.0.20"),
        exporter_url="http://127.0.0.1:9116", exporter_allowed_hosts=["127.0.0.1"],
        snmp_allowed_targets=["198.18.0.0/15"], timeout_seconds=10, lease_seconds=60)
    assert captured[0]["_runtime"]["snmp_identity_preflight"] is True
    assert captured[0]["target"]["target"] == "198.18.0.20:1161"
    assert captured[0]["configuration"]["include_metric_prefixes"] == ["sysName", "sysDescr", "sysObjectID", "sysUpTime"]
    assert evidence["discovered_name"] == "access" and evidence["modules"] == ["icheck_identity"]
    assert evidence["monitoring_modules"] == ["if_mib"] and evidence["target_host"] == "198.18.0.20"
    assert "synthetic-only" not in json.dumps(evidence)


@pytest.mark.parametrize("name", [None, "", "x" * 256, "bad\nname", "bad\x7fname"])
def test_invalid_device_names_are_not_published(name):
    assert safe_sysname(name) is None


def test_discovery_does_not_retain_echoed_community(monkeypatch):
    monkeypatch.setattr(preflights, "collect_snmp_exporter", lambda assignment: [
        {"payload": {"metric": "sysName", "labels": {"sysName": "synthetic-secret"}}}])
    evidence, _ = preflights._snmp_preflight({"configuration": {},
        "_runtime": {"credential": {"community": "synthetic-secret"}}}, ipaddress.ip_address("198.18.0.20"),
        exporter_url="http://127.0.0.1:9116", exporter_allowed_hosts=["127.0.0.1"],
        snmp_allowed_targets=["198.18.0.0/15"], timeout_seconds=10, lease_seconds=60)
    assert "discovered_name" not in evidence and "synthetic-secret" not in json.dumps(evidence)


def test_discovery_persists_and_is_searchable_without_overwriting_alias(client):
    device = onboard_device(client, protocol="snmp")
    worker, auth = register_worker(client, name="identity-worker", site="LAB", capabilities=["snmp_exporter"])
    assignment = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim", headers=auth,
        json={"max_assignments": 1, "lease_seconds": 60}).json()[0]
    path = f"/api/v1/collector-workers/{worker['id']}/device-preflights/{assignment['preflight_id']}/complete"
    payload = {"lease_token": assignment["lease_token"], "status": "verified", "evidence": {
        "check": "snmp_exporter_query", "target_host": "192.0.2.200", "discovered_name": "access"}}
    assert client.post(path, headers=auth, json=payload).status_code == 409
    payload["evidence"]["target_host"] = device["management_ip"]
    payload["evidence"]["identity_revision"] = 999  # Untrusted worker cannot choose the binding.
    result = client.post(path, headers=auth, json=payload)
    assert result.status_code == 200, result.text
    detail = client.get(f"/api/v1/assets/devices/{device['id']}").json()
    assert detail["name"] == device["name"] and detail["discovered_name"] == "access"
    assert detail["connections"][0]["last_verification_evidence"]["identity_revision"] == detail["identity_revision"]
    assert client.get("/api/v1/assets/devices/page?search=access").json()["items"][0]["id"] == device["id"]
    assert client.get("/api/v1/assets/devices?search=access").json()[0]["id"] == device["id"]
    with SessionLocal() as db:
        row = db.get(Device, device["id"]); row.identity_revision += 1; db.commit()
    assert client.get(f"/api/v1/assets/devices/{device['id']}").json()["discovered_name"] is None
    assert client.get("/api/v1/assets/devices/page?search=access").json()["items"] == []


def test_existing_bad_connection_can_be_repaired_without_reenrollment(client):
    device = onboard_device(client, protocol="snmp")
    connection = device["connections"][0]
    with SessionLocal() as db:
        row = db.get(DeviceConnection, connection["id"])
        row.configuration = {"modules": ["snmp_exporter", "snmp_topology"]}
        row.verification_status = "failed"
        row.last_verification_error = "Old HTTP 400"
        db.commit()
    path = f"/api/v1/assets/devices/{device['id']}/connections/{connection['id']}/snmp-configuration"
    payload = {"expected_revision": device["revision"], "modules": ["if_mib"], "actor": "operator",
        "reason": "Correct invalid legacy SNMP module configuration."}
    assert client.patch(path, json={**payload, "modules": ["snmp_exporter"]}).status_code == 422
    repaired = client.patch(path, json=payload)
    assert repaired.status_code == 200, repaired.text
    current = repaired.json()
    assert current["id"] == device["id"] and current["name"] == device["name"]
    assert current["revision"] == device["revision"] + 1
    assert current["connections"][0]["configuration"]["modules"] == ["if_mib"]
    assert current["connections"][0]["verification_status"] == "pending"
    assert current["connections"][0]["credential_profile_ref"] == connection["credential_profile_ref"]
    assert current["connections"][0]["worker_selector"] == connection["worker_selector"]
    assert client.patch(path, json=payload).status_code == 409
    assert len(client.get("/api/v1/assets/devices").json()) == 1
    audits = client.get("/api/v1/audit-events?event_type=device.connection.snmp_configuration.updated").json()
    assert audits[0]["details"]["old_modules"] == ["snmp_exporter", "snmp_topology"]


def test_repair_cannot_race_an_active_verification(client):
    device = onboard_device(client, protocol="snmp")
    worker, auth = register_worker(client, name="race-worker", site="LAB", capabilities=["snmp_exporter"])
    assert client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim", headers=auth,
        json={"max_assignments": 1, "lease_seconds": 60}).json()
    path = f"/api/v1/assets/devices/{device['id']}/connections/{device['connections'][0]['id']}/snmp-configuration"
    result = client.patch(path, json={"expected_revision": device["revision"], "modules": ["system"],
        "actor": "operator", "reason": "Change module while verification is running."})
    assert result.status_code == 409 and "running" in result.text


def test_config_correction_withdraws_old_monitoring_intent(client, device_key):
    profile = credential(client)
    result = client.post("/api/v1/assets/devices", json={"name": "monitoring-correction", "kind": "switch",
        "management_ip": "198.18.0.30", "created_by": "operator", "request_monitoring": True,
        "connections": [{"protocol": "snmp", "credential_profile_ref": profile["id"]}]})
    assert result.status_code == 201, result.text
    device = result.json(); connection = device["connections"][0]
    path = f"/api/v1/assets/devices/{device['id']}/connections/{connection['id']}/snmp-configuration"
    corrected = client.patch(path, json={"expected_revision": device["revision"], "modules": ["if_mib", "system"],
        "actor": "operator", "reason": "Change SNMP modules and withdraw stale collection approval."})
    assert corrected.status_code == 200, corrected.text
    preview = client.get(f"/api/v1/assets/devices/{device['id']}/connections/{connection['id']}/monitoring").json()
    assert preview["enrollment"]["enabled"] is False and preview["enrollment"]["revision"] == 2
    assert preview["currently_authorized"] is False
    assert client.get("/api/v1/monitoring/targets").json()["targets"] == []


def test_agent_device_result_matches_additive_schema_and_preserves_custom_definitions(client):
    from icheck.builtin_agent_tools import ensure_builtin_agent_tools
    from icheck.services.agent_tools import _get_device
    from icheck.services.control_plane_auth import development_principal
    from icheck.schema_validation import validate_instance
    device = onboard_device(client, protocol="snmp")
    with SessionLocal() as db:
        tool = next(t for t in ensure_builtin_agent_tools(db) if t.name == "inventory.get_device")
        legacy = {**tool.output_schema, "properties": dict(tool.output_schema["properties"])}
        legacy["properties"].pop("discovered_name")
        tool.output_schema = legacy; db.commit()
        ensure_builtin_agent_tools(db)
        result, _ = _get_device(db, {"device_id": device["id"]}, development_principal())
        assert "discovered_name" in result
        validate_instance(result, tool.output_schema, "tool result")
        # A user-customized old schema is neither replaced nor given extra output.
        tool.output_schema = {**legacy, "title": "Operator customized schema"}; db.commit()
        ensure_builtin_agent_tools(db)
        assert tool.output_schema["title"] == "Operator customized schema"
        result, _ = _get_device(db, {"device_id": device["id"]}, development_principal())
        assert "discovered_name" not in result
        validate_instance(result, tool.output_schema, "tool result")
