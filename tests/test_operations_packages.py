"""Portable installation A -> B with synthetic data and no live execution."""
from copy import deepcopy
from dataclasses import replace
import json
from uuid import uuid4

import pytest
from sqlalchemy import select, func

from icheck.auth import current_principal
from icheck.config import get_settings
from icheck.database import SessionLocal, set_session_namespace
from icheck.main import app
from icheck.models import (Artifact, ArtifactVersion, AgentToolRegistration, OperationsPackageInstallation,
                           WorkflowScheduleActivation, ManagedExtensionInstallation)
from icheck.operations_package_schemas import OperationsReview, OperationsInstall
from icheck.services import operations_packages as service
from icheck.services.control_plane_auth import development_principal
from icheck.builtin_operations import packages, network_server
from icheck.services.mcp_extensions import extension_documents, validate_extension_contract
from icheck.sandbox import HardenedProcessSandboxExecutor

BASE = "/api/v1/operations-packages"


@pytest.fixture(autouse=True)
def registry():
    from icheck.builtin_agent_tools import ensure_builtin_agent_tools
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)


def package(client, name="http-api-diagnostics"):
    response = client.get(BASE + "/builtins")
    assert response.status_code == 200, response.text
    return next(p for p in response.json() if p["name"] == name)


def test_builtins_are_offline_reusable_and_inactive(client):
    documents = client.get(BASE + "/builtins").json()
    assert len(documents) == 6
    assert len({c["name"] for p in documents for c in p["components"]}) == sum(len(p["components"]) for p in documents)
    network = next(p for p in documents if p["name"] == "network-diagnostics")
    servers = [c for c in network["components"] if c["kind"] == "mcp"]
    assert len(servers) == 3 and all(len(c["spec"]["tools"]) == 2 for c in servers)
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(OperationsPackageInstallation)) == 0
        assert db.scalar(select(func.count()).select_from(ManagedExtensionInstallation)) == 0
        assert db.scalar(select(func.count()).select_from(WorkflowScheduleActivation)) == 0


def test_review_import_receipt_idempotency_and_no_activation(client):
    document = package(client)
    body = {"package": document}
    preview = client.post(BASE + "/preview", json=body)
    assert preview.status_code == 200 and preview.json()["installable"], preview.text
    response = client.post(BASE + "/import", json={**body, "confirm": True})
    assert response.status_code == 201, response.text
    assert response.json()["activated"] is False
    ids = response.json()["artifact_version_ids"]
    again = client.post(BASE + "/import", json={**body, "confirm": True})
    assert again.status_code == 201 and again.json()["id"] == response.json()["id"]
    with SessionLocal() as db:
        assert {db.get(ArtifactVersion, id).status.value for id in ids} == {"validated"}
        assert db.scalar(select(func.count()).select_from(WorkflowScheduleActivation)) == 0
        assert db.scalar(select(func.count()).select_from(ManagedExtensionInstallation)) == 0
    assert client.post(BASE + "/import", json=body).status_code == 422


def test_cross_installation_rebuilds_tool_ids_and_keeps_contracts(client):
    first = package(client)
    imported = client.post(BASE + "/import", json={"package": first, "confirm": True}).json()
    response = client.post(BASE + "/export", json={"name": "team-health", "version": "1.0.0",
        "description": "Portable health operations", "artifact_version_ids": imported["artifact_version_ids"]})
    assert response.status_code == 200, response.text
    exported = response.json()
    with SessionLocal() as db:
        old_ids = [t.id for t in db.scalars(select(AgentToolRegistration))]
        for id in old_ids:
            assert id not in json.dumps(exported)
        # A clean destination registry has the same contracts and different IDs.
        db.query(OperationsPackageInstallation).delete()
        db.query(ArtifactVersion).delete()
        db.query(Artifact).delete()
        for tool in db.scalars(select(AgentToolRegistration)):
            tool.id = str(uuid4())
        db.commit()
    second = client.post(BASE + "/import", json={"package": exported, "confirm": True})
    assert second.status_code == 201, second.text
    with SessionLocal() as db:
        for id in second.json()["artifact_version_ids"]:
            version = db.get(ArtifactVersion, id)
            material = json.dumps(version.definition) + json.dumps(version.tests)
            assert not any(old in material for old in old_ids)


def test_changed_local_tool_contract_is_blocked(client):
    document = package(client)
    with SessionLocal() as db:
        db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == "inventory.get_device")).read_only = False
        db.commit()
    result = client.post(BASE + "/preview", json={"package": document})
    assert result.status_code == 200 and not result.json()["installable"]
    assert client.post(BASE + "/import", json={"package": document, "confirm": True}).status_code == 422
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(OperationsPackageInstallation)) == 0


@pytest.mark.parametrize("bad", ["env://CUSTOM_TOKEN", "https://private.internal/read", "10.20.30.40", "sk-" + "x" * 32])
def test_export_rejects_local_configuration_and_secret_literals(client, bad):
    document = package(client)
    document["components"][0]["spec"]["instructions"] += " " + bad
    document["digest_sha256"] = service.digest({k: v for k, v in document.items() if k != "digest_sha256"})
    result = client.post(BASE + "/preview", json={"package": document})
    assert result.status_code == 422 and bad not in result.text


def test_digest_and_built_in_substitution_are_rejected(client):
    document = package(client)
    document["description"] += " tampered"
    assert client.post(BASE + "/preview", json={"package": document}).status_code == 422
    document["digest_sha256"] = service.digest({k: v for k, v in document.items() if k != "digest_sha256"})
    assert client.post(BASE + "/builtins/http-api-diagnostics/import", json={"package": document, "confirm": True}).status_code == 422


def test_signature_requirement_cannot_be_bypassed_by_builtin_flag(client, monkeypatch):
    document = package(client)
    monkeypatch.setenv("ICHECK_ARTIFACT_SIGNATURE_POLICY", "required"); get_settings.cache_clear()
    try:
        assert not client.post(BASE + "/preview", json={"package": document}).json()["installable"]
        assert client.post(BASE + "/import", json={"package": document, "confirm": True}).status_code == 422
        assert client.post(BASE + "/import", json={"package": document, "confirm": True, "builtin": True}).status_code == 422
        assert client.post(BASE + "/builtins/http-api-diagnostics/import",
                           json={"package": document, "confirm": True}).status_code == 201
    finally:
        get_settings.cache_clear()


def test_connector_and_backup_dependencies_have_explicit_readiness(client):
    for name in ("zabbix-operations", "solarwinds-orion-operations", "configuration-backups"):
        doc = package(client, name)
        result = client.post(BASE + "/preview", json={"package": doc})
        assert result.status_code == 200 and not result.json()["installable"], result.text
        assert result.json()["blockers"]


@pytest.mark.parametrize("vendor", ["cisco_ios", "cisco_nxos", "juniper_junos"])
def test_shipped_mcp_server_fixtures_execute_in_real_sandbox(vendor):
    component = network_server(vendor)
    documents = extension_documents(component.spec)
    report = validate_extension_contract(*documents, sandbox_executor=HardenedProcessSandboxExecutor(python_path="/usr/bin/python3"))
    assert report["fixture_count"] == 3 and not report["installed"]


def test_package_permissions_and_namespace_failure(client):
    principal = development_principal()
    app.dependency_overrides[current_principal] = lambda: replace(principal, permissions=frozenset({"capabilities.read"}))
    try:
        assert client.get(BASE + "/choices").status_code == 403
        assert client.post(BASE + "/export", json={}).status_code == 403
    finally:
        app.dependency_overrides.pop(current_principal, None)


def test_multi_component_package_stages_mcp_dependency_then_prepares_and_exports(client, tmp_path, monkeypatch):
    from icheck.builtin_operations import backup_workflow
    from icheck.extension_schemas import ExtensionInstall
    from icheck.services import managed_extensions
    from icheck.models import Tenant, Region
    from icheck.builtin_agent_tools import ensure_builtin_agent_tools
    root = tmp_path / "packages"; root.mkdir(mode=0o700)
    monkeypatch.setenv("ICHECK_EXTENSION_PACKAGES_ROOT", str(root))
    monkeypatch.setenv("ICHECK_SANDBOX_ENABLED", "true")
    monkeypatch.setenv("ICHECK_SANDBOX_BACKEND", "process")
    get_settings.cache_clear()
    try:
        document = service.build_package("team-backup", "1.0.0", "Shared MCP server and scheduled workflow",
                                         [network_server(), backup_workflow()])
        response = client.post(BASE + "/import", json={"package": document.model_dump(mode="json"), "confirm": True})
        assert response.status_code == 201 and response.json()["pending"], response.text
        receipt = response.json()
        server = next(c for c in receipt["components"] if c["kind"] == "mcp")
        installed = client.post("/api/v1/capability-studio/extensions/install",
            json={"artifact_version_id": server["id"], "expected_revision": 0, "access_mode": "authorized_inventory"})
        assert installed.status_code == 200, installed.text
        assert set(installed.json()["tool_ids"]) == {"get_interface_status", "backup_configuration"}
        with SessionLocal() as db:
            service.compile_component(db, backup_workflow(), {})
        prepared = client.post(BASE + "/" + receipt["id"] + "/prepare", json={})
        assert prepared.status_code == 200 and not prepared.json()["pending"], prepared.text
        exported = client.post(BASE + "/export", json={"name": "team-backup", "version": "1.0.1",
            "description": "Portable multi-component operations", "artifact_version_ids": receipt["artifact_version_ids"]})
        assert exported.status_code == 200, exported.text
        source_ids = [receipt["id"], server["id"], installed.json()["id"], *installed.json()["tool_ids"].values()]
        assert all(id not in exported.text for id in source_ids)
        # Clean installation B is represented by a separate namespace/registry;
        # no source credentials, registry IDs or enabled schedules are copied.
        actor = replace(development_principal(), tenant_id=str(uuid4()), region_id=str(uuid4()))
        with SessionLocal() as db:
            db.add(Tenant(id=actor.tenant_id, tenant_id=actor.tenant_id, region_id=actor.region_id,
                          name="Destination", slug="destination", default_region_id=actor.region_id,
                          enabled=True, created_by="fixture"))
            db.add(Region(id=actor.region_id, tenant_id=actor.tenant_id, region_id=actor.region_id,
                          name="Destination", code="destination", enabled=True, created_by="fixture"))
            db.commit()
            set_session_namespace(db, actor.tenant_id, actor.region_id)
            ensure_builtin_agent_tools(db)
            second = service.install(db, OperationsInstall(package=exported.json(), confirm=True), actor)
            assert second["pending"]
            target = next(c for c in second["components"] if c["kind"] == "mcp")
            managed_extensions.install(db, actor, ExtensionInstall(artifact_version_id=target["id"],
                                       expected_revision=0, access_mode="authorized_inventory"))
            prepared = service.prepare(db, second["id"], actor)
            assert not prepared["pending"] and all(c["status"] == "validated" for c in prepared["components"])
            assert db.scalar(select(func.count()).select_from(WorkflowScheduleActivation)) == 0
    finally:
        get_settings.cache_clear()


def test_package_signature_verified_and_revocation_blocks_acceptance(client):
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from icheck.models import ArtifactTrustKey
    from icheck.services.artifact_portability import trusted_digest_signature_message
    from icheck.operations_package_schemas import FORMAT
    document = package(client)
    private = Ed25519PrivateKey.generate()
    pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    response = client.post("/api/v1/artifact-trust-keys",
        json={"name": "team-key", "public_key_pem": pem, "purposes": ["capability_pack"], "created_by": "fixture"})
    assert response.status_code == 201, response.text
    key = response.json()
    signature = {"algorithm": "ed25519", "key_fingerprint_sha256": key["fingerprint_sha256"],
        "signed_digest_sha256": document["digest_sha256"],
        "signature_base64": base64.b64encode(private.sign(trusted_digest_signature_message(FORMAT, document["digest_sha256"]))).decode()}
    body = {"package": document, "signature": signature, "confirm": True}
    assert client.post(BASE + "/import", json=body).status_code == 201
    bad = deepcopy(body); bad["signature"]["signature_base64"] = base64.b64encode(b"x" * 64).decode()
    assert client.post(BASE + "/import", json=bad).status_code == 422
    with SessionLocal() as db:
        db.get(ArtifactTrustKey, key["id"]).enabled = False
        db.commit()
    assert client.post(BASE + "/import", json=body).status_code == 422


def test_imported_builtin_workflow_executes_fixed_and_agent_nodes_with_fake_model(client):
    from test_workflow_runtime import _configure_route, _device, WorkflowResponse
    from langgraph.checkpoint.memory import InMemorySaver
    from icheck.models import Investigation, InvestigationToolCall
    from icheck.services.agent_graph import run_database_investigation
    from icheck.services.workflow_reasoner import WorkflowReasoner
    _configure_route(client)
    document = package(client)
    response = client.post(BASE + "/import", json={"package": document, "confirm": True})
    assert response.status_code == 201, response.text
    workflow = next(c for c in response.json()["components"] if c["kind"] == "workflow")
    published = client.post(f"/api/v1/artifact-versions/{workflow['id']}/publish", json={"actor": "fixture"})
    assert published.status_code == 200, published.text
    device = _device(client)
    response = client.post(f"/api/v1/workflow-runtime/workflows/{workflow['id']}/investigations",
        json={"title": "Built-in fixture execution", "workflow_input": {"device_id": device},
              "scope": {"device_ids": [device]}, "operator_context": "Check stored evidence only", "actor": "fixture"})
    assert response.status_code == 200, response.text
    class SyntheticModel:
        calls = 0
        def open(self, request, timeout):
            self.calls += 1
            prompt = json.loads(json.loads(request.data)["messages"][1]["content"])
            assert prompt["workflow_agent_loop"]["node_id"] == "diagnose"
            if self.calls == 1:
                return WorkflowResponse({"action": "continue", "plan": ["Read alert evidence"],
                    "tool_requests": [{"tool_name": "alerts.list_open", "arguments": {"limit": 10},
                                       "purpose": "Review stored alerts"}]}, 40)
            return WorkflowResponse({"action": "complete", "plan": ["Done"], "confidence": 0.8,
                "conclusion": "Stored evidence reviewed; live service qualification remains open.", "uncertainty": []}, 40)
    with SessionLocal() as db:
        run = db.get(Investigation, response.json()["investigation"]["id"])
        fake = SyntheticModel()
        result = run_database_investigation(db, run, reasoner=WorkflowReasoner(db, run, opener=fake),
                                            checkpointer=InMemorySaver())
        assert result["status"] == "completed" and fake.calls == 2
        assert result["structured_output"]["terminal_node"] == "finish"
        assert db.scalar(select(func.count()).select_from(InvestigationToolCall)
                         .where(InvestigationToolCall.investigation_id == run.id)) == 2


def test_collector_export_removes_credential_binding_and_imports_without_deployment(client):
    from test_collectors import collector_artifact_payload
    from icheck.operations_package_schemas import OperationComponent
    from icheck.models import CollectorDeployment
    payload = collector_artifact_payload()
    payload["initial_version"]["collector_definition"]["credential_profile_ref"] = "env://SOURCE_COLLECTOR_TOKEN"
    response = client.post("/api/v1/artifacts", json=payload)
    assert response.status_code == 201, response.text
    version = response.json()["versions"][0]["id"]
    assert client.post(f"/api/v1/artifact-versions/{version}/validate", json={"actor": "fixture"}).status_code == 200
    response = client.post(BASE + "/export", json={"name": "collector-share", "version": "1.0.0",
        "description": "Portable collector", "artifact_version_ids": [version]})
    assert response.status_code == 200, response.text
    assert "SOURCE_COLLECTOR_TOKEN" not in response.text
    component = response.json()["components"][0]
    assert component["spec"]["collector_definition"]["credential_profile_ref"] is None
    component["name"] = "destination-collector"
    document = service.build_package("collector-share", "1.0.1", "Local renamed fixture",
                                     [OperationComponent.model_validate(component)])
    response = client.post(BASE + "/import", json={"package": document.model_dump(mode="json"), "confirm": True})
    assert response.status_code == 201, response.text
    with SessionLocal() as db:
        version = db.get(ArtifactVersion, response.json()["artifact_version_ids"][0])
        assert version.collector_definition.credential_profile_ref is None
        assert db.scalar(select(func.count()).select_from(CollectorDeployment)) == 0


def test_external_tool_binds_destination_mcp_without_registration_or_contact(client):
    from icheck.models import MCPServer
    from icheck.operations_package_schemas import OperationComponent
    from test_tool_skill_studio import TOOL_SPEC
    with SessionLocal() as db:
        server = MCPServer(name="destination-server", endpoint_url="https://mcp.example.test/mcp", created_by="fixture")
        db.add(server); db.commit()
    component = OperationComponent(name=TOOL_SPEC["artifact_name"], kind="tool", spec=TOOL_SPEC)
    document = service.build_package("external-tool-share", "1.0.0", "Portable external tool", [component])
    body = {"package": document.model_dump(mode="json"), "mcp_servers": {component.name: "destination-server"}}
    assert client.post(BASE + "/preview", json=body).json()["installable"]
    response = client.post(BASE + "/import", json={**body, "confirm": True})
    assert response.status_code == 201, response.text
    with SessionLocal() as db:
        version = db.get(ArtifactVersion, response.json()["artifact_version_ids"][0])
        assert version.definition["spec"]["mcp_server_name"] == "destination-server"
        assert db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == TOOL_SPEC["tool_name"])) is None
