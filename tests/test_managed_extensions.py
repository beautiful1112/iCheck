"""Reviewed native lifecycle integration; acquisition fixtures never claim lab evidence."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import os
from uuid import uuid4

import paramiko
import pytest
from fastapi import HTTPException
from sqlalchemy import select

from icheck.config import get_settings
from icheck.database import SessionLocal, set_session_namespace, DEFAULT_TENANT_ID, DEFAULT_REGION_ID
from icheck.extension_host import NativeExtensionProcess
from icheck.extension_runtime import load_extension_package
from icheck.models import (Artifact, ArtifactKind, ArtifactVersion, ArtifactVersionStatus, Device, DeviceConnection,
    AgentToolRegistration, ManagedExtensionInstallation, ManagedExtensionTest, ControlPlanePrincipal,
    ControlPlaneRole, ControlPlaneRoleBinding, Investigation, CredentialProfile, ExtensionConfigurationBackup, utcnow)
from icheck.sandbox import HardenedProcessSandboxExecutor, execute_extension_tool
from icheck.services import managed_extensions as runtime
from icheck.services.agent_tools import DatabaseToolExecutor
from icheck.services.collectors import artifact_content_hash
from icheck.services.control_plane_auth import development_principal
from icheck.services.mcp_extensions import extension_documents
from test_mcp_extensions import SPEC
from test_agent_runtime import configure_investigation_route


@pytest.fixture
def setup(client, tmp_path, monkeypatch):
    root = tmp_path / "extensions"; root.mkdir(mode=0o700)
    secret_key = tmp_path / "key"; secret_key.write_bytes(os.urandom(32)); secret_key.chmod(0o400)
    monkeypatch.setenv("ICHECK_EXTENSION_PACKAGES_ROOT", str(root))
    monkeypatch.setenv("ICHECK_SANDBOX_ENABLED", "true")
    monkeypatch.setenv("ICHECK_DEVICE_MANAGED_SECRET_KEY_FILE", str(secret_key)); get_settings.cache_clear()
    credential = client.post("/api/v1/device-credentials", json={"name": "extension-ssh", "kind": "ssh_password",
        "site": "LAB", "username": "monitor", "password": "synthetic-device-password"})
    assert credential.status_code == 201, credential.text
    key = paramiko.RSAKey.generate(2048)
    public_key = key.get_name() + " " + key.get_base64()
    artifact_id, device_id, connection_id = [str(uuid4()) for _ in range(3)]
    with SessionLocal() as db:
        db.add_all([Artifact(id=artifact_id, name=SPEC["artifact_name"], kind=ArtifactKind.TOOL, owner="fixture"),
            Device(id=device_id, name="simulated-device", kind="switch", management_ip="198.18.0.1", site="LAB")]); db.flush()
        db.add(DeviceConnection(id=connection_id, device_id=device_id, protocol="ssh", adapter_type="ssh", port=22,
            credential_profile_ref=credential.json()["id"], worker_selector={"site": "LAB"}, created_by="fixture")); db.commit()
    calls = []
    class Host:
        def discover(self, path): return NativeExtensionProcess().discover(path)
        def call(self, path, name, arguments, *, resolve, store_backup):
            spec = load_extension_package(path)
            tool = next(row for row in spec.tools if row.name == name)
            target = resolve(spec, tool, arguments["device_id"])
            assert target.password == "synthetic-device-password" and target.username == "monitor"
            target.revalidate()
            calls.append((str(path), name, target.device_id))
            readings = ([store_backup(target, b"synthetic protected device configuration")]
                if tool.operation == "backup" else ["Gi0/1 connected"])
            result = execute_extension_tool(tool.source, readings, arguments,
                executor=HardenedProcessSandboxExecutor(python_path="/usr/bin/python3"))
            target.revalidate()
            return result
    monkeypatch.setattr(runtime, "HOST", Host)
    def version(number):
        document = deepcopy(SPEC); document["description"] += f" revision {number}"
        definition, implementation, tests = extension_documents(document)
        identifier = str(uuid4())
        with SessionLocal() as db:
            row = ArtifactVersion(id=identifier, artifact_id=artifact_id, version=number,
                status=ArtifactVersionStatus.VALIDATED, definition=definition, implementation=implementation, tests=tests,
                created_by="fixture", content_hash=artifact_content_hash(kind=ArtifactKind.TOOL,
                    definition=definition, implementation=implementation, tests=tests, collector_definition=None))
            db.add(row); db.commit()
        return identifier
    try:
        yield {"artifact": artifact_id, "device": device_id, "connection": connection_id,
            "credential": credential.json()["id"], "host_key": public_key, "version": version, "calls": calls}
    finally:
        get_settings.cache_clear()


def _run_tests(client, setup, version):
    tests = []
    for tool in SPEC["tools"]:
        payload = {"request_key": str(uuid4()), "artifact_version_id": version, "connection_id": setup["connection"],
            "tool_name": tool["name"], "host_public_key": setup["host_key"]}
        response = client.post("/api/v1/capability-studio/extensions/tests", json=payload)
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "succeeded", response.text
        before = len(setup["calls"])
        assert client.post("/api/v1/capability-studio/extensions/tests", json=payload).json()["id"] == response.json()["id"]
        assert len(setup["calls"]) == before
        tests.append(response.json()["id"])
    return tests


def install(client, version, tests, revision=0):
    return client.post("/api/v1/capability-studio/extensions/install", json={"artifact_version_id": version,
        "test_ids": tests, "expected_revision": revision})


def test_gui_api_tests_install_revision_disable_and_rollback(client, setup):
    first = setup["version"](1)
    tests = _run_tests(client, setup, first)
    assert install(client, first, tests[:1]).status_code == 409
    response = install(client, first, tests)
    assert response.status_code == 200, response.text
    installed = response.json(); assert installed["enabled"] and len(installed["tool_ids"]) == 2
    with SessionLocal() as db:
        tools = list(db.scalars(select(AgentToolRegistration).where(AgentToolRegistration.transport == "managed_mcp")))
        assert len(tools) == 2 and all(tool.enabled and first in tool.handler for tool in tools)
        # One server installation owns both tools; tools are not installations.
        installations = list(db.scalars(select(ManagedExtensionInstallation)))
        assert len(installations) == 1 and installations[0].id == installed["id"]
        assert set(installed["tool_ids"]) == {"get_interface_status", "backup_configuration"}
        assert all(tool.handler.startswith(installed["id"] + ":" + first + ":") for tool in tools)
    assert install(client, first, tests).status_code == 409
    second = setup["version"](2)
    second_tests = _run_tests(client, setup, second)
    revised = install(client, second, second_tests, revision=1)
    assert revised.status_code == 200, revised.text
    assert revised.json()["previous_version_id"] == first
    assert revised.json()["id"] == installed["id"]
    with SessionLocal() as db:
        assert len(list(db.scalars(select(ManagedExtensionInstallation)))) == 1
    prefix = "/api/v1/capability-studio/extensions/" + installed["id"]
    restored = client.post(prefix + "/rollback", json={"expected_revision": 2})
    assert restored.status_code == 200 and restored.json()["active_version_id"] == first
    assert client.post(prefix + "/disable", json={"expected_revision": 2}).status_code == 409
    # Disable remains possible even if the installed artifact is later deprecated.
    with SessionLocal() as db:
        db.get(ArtifactVersion, first).status = ArtifactVersionStatus.DEPRECATED; db.commit()
    disabled = client.post(prefix + "/disable", json={"expected_revision": 3})
    assert disabled.status_code == 200 and not disabled.json()["enabled"]
    with SessionLocal() as db:
        assert all(not tool.enabled for tool in db.scalars(select(AgentToolRegistration).where(AgentToolRegistration.transport == "managed_mcp")))
    assert client.get("/api/v1/capability-studio/extensions").json()["items"][0]["revision"] == 4


@pytest.mark.parametrize("change", ["credential", "target", "scope", "expired", "contract", "newer_failure"])
def test_changed_or_unscoped_test_cannot_authorize_installation(client, setup, change):
    version = setup["version"](1); tests = _run_tests(client, setup, version)
    with SessionLocal() as db:
        if change == "credential": db.get(CredentialProfile, setup["credential"]).revision += 1
        elif change == "target": db.get(Device, setup["device"]).management_ip = "198.18.0.2"
        elif change == "expired":
            for identifier in tests: db.get(ManagedExtensionTest, identifier).completed_at = utcnow() - timedelta(hours=1)
        elif change == "contract": db.get(ArtifactVersion, version).content_hash = "f" * 64
        elif change == "newer_failure":
            old = db.get(ManagedExtensionTest, tests[0])
            db.add(ManagedExtensionTest(id=str(uuid4()), request_key=str(uuid4()), artifact_version_id=version,
                version_hash=old.version_hash, tool_name=old.tool_name, binding=old.binding,
                status="failed", result={}, created_by="fixture", created_at=utcnow(), completed_at=utcnow()))
        elif change == "scope":
            with pytest.raises(HTTPException) as denied:
                runtime._assert_binding(db, replace(development_principal(), authorization_scope={"device_ids": []}),
                    db.get(ManagedExtensionTest, tests[0]).binding)
            assert denied.value.status_code == 404
            return
        db.commit()
    assert install(client, version, tests).status_code == 409
    with SessionLocal() as db:
        assert db.scalar(select(ManagedExtensionInstallation)) is None
        assert db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.transport == "managed_mcp")) is None


@pytest.mark.parametrize("reusable", [False, True])
def test_registered_tool_uses_existing_executor_and_current_identity(client, setup, monkeypatch, reusable):
    from icheck.services.model_reasoner import OpenAICompatibleReasoner
    version = setup["version"](1)
    if reusable:
        identity_url = f"/api/v1/capability-studio/extensions/targets/{setup['connection']}/identity"
        state = client.get(identity_url).json()
        assert client.post(identity_url + "/confirm", json={"binding_hash": state["binding_hash"], "host_public_key": setup["host_key"]}).status_code == 200
        response = package_install(client, version)
    else:
        response = install(client, version, _run_tests(client, setup, version))
    assert response.status_code == 200, response.text
    installed = response.json()
    route = configure_investigation_route(client)
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        principal = ControlPlanePrincipal(id=str(uuid4()), subject="extension-operator", display_name="Operator", created_by="fixture")
        role = ControlPlaneRole(id=str(uuid4()), name="extension-observer", permissions=runtime.TOOL_PERMISSIONS, created_by="fixture")
        db.add_all([principal, role]); db.flush()
        db.add(ControlPlaneRoleBinding(principal_id=principal.id, role_id=role.id, scope={"device_ids": [setup["device"]]}, created_by="fixture"))
        investigation = Investigation(id=str(uuid4()), title="Read installed MCP tool", objective="Read interface status",
            route_id=route["id"], model_id=route["primary_model_id"], status="running", requested_by_principal_id=principal.id,
            permission_snapshot=runtime.TOOL_PERMISSIONS, authorization_scope={"device_ids": [setup["device"]]},
            max_iterations=3, max_tool_calls=5, token_budget=1000, timeout_seconds=60, created_by=principal.subject)
        db.add(investigation); db.commit()
        tool = db.get(AgentToolRegistration, installed["tool_ids"]["get_interface_status"])
        assert runtime.available(db, tool, investigation)
        assert tool.name in {item["name"] for item in OpenAICompatibleReasoner(db, investigation).tool_catalog}
        result, evidence = DatabaseToolExecutor(db, investigation)._execute(tool, {"device_id": setup["device"]}, tool_call_id=str(uuid4()))
        assert result["interfaces"][0]["state"] == "connected" and evidence[0].evidence_type == "native_mcp_result"
        db.commit()
        original_host = runtime.HOST
        class FailingBackup(original_host):
            def call(self, *args, **kwargs):
                super().call(*args, **kwargs)
                raise ValueError("synthetic failure after acquisition")
        backup_count = len(list(db.scalars(select(ExtensionConfigurationBackup))))
        monkeypatch.setattr(runtime, "HOST", FailingBackup)
        with pytest.raises(ValueError):
            DatabaseToolExecutor(db, investigation)._execute(db.get(AgentToolRegistration, installed["tool_ids"]["backup_configuration"]),
                {"device_id": setup["device"]}, tool_call_id=str(uuid4()))
        db.commit()
        assert len(list(db.scalars(select(ExtensionConfigurationBackup)))) == backup_count
        assert db.get(ManagedExtensionInstallation, installed["id"]).last_health_status == "call_failed"
        monkeypatch.setattr(runtime, "HOST", original_host)
        before = len(setup["calls"])
        with pytest.raises((PermissionError, HTTPException)):
            DatabaseToolExecutor(db, investigation)._execute(tool, {"device_id": str(uuid4())}, tool_call_id=str(uuid4()))
        principal.enabled = False; db.commit()
        with pytest.raises(PermissionError):
            DatabaseToolExecutor(db, investigation)._execute(tool, {"device_id": setup["device"]}, tool_call_id=str(uuid4()))
        assert len(setup["calls"]) == before
        runtime.lifecycle(db, development_principal(), installed["id"], 1, "disable")
        assert tool.name not in {item["name"] for item in OpenAICompatibleReasoner(db, investigation).tool_catalog}
        tool.description = "registered managed tool"
        payload = {"name": "forged.extension", "description": "forged managed transport", "transport": "managed_mcp", "handler": tool.handler,
            "input_schema": tool.input_schema, "output_schema": tool.output_schema, "created_by": "fixture"}
    assert client.post("/api/v1/agent/tools", json=payload).status_code == 422


def package_install(client, version, revision=0):
    return client.post("/api/v1/capability-studio/extensions/install", json={"artifact_version_id": version,
        "access_mode": "authorized_inventory", "expected_revision": revision})


def test_package_install_requires_no_device_setup_and_scales_without_bindings(client, setup):
    version = setup["version"](1)
    # No identity, no live test, and no runnable device is required to install.
    with SessionLocal() as db:
        db.get(DeviceConnection, setup["connection"]).enabled = False; db.commit()
    response = package_install(client, version)
    assert response.status_code == 200, response.text
    installed = response.json()
    assert installed["bindings"] == [] and installed["target_policy"] == {"mode": "authorized_inventory", "scope": {"all": True}}
    assert len(installed["tool_ids"]) == 2 and installed["runtime_state"] == "ready_on_demand"
    with SessionLocal() as db:
        db.add_all([Device(name=f"fleet-switch-{index}", kind="switch", site="LAB") for index in range(1000)])
        db.commit()
        assert db.get(ManagedExtensionInstallation, installed["id"]).bindings == []
        assert db.scalar(select(ManagedExtensionTest)) is None
    assert setup["calls"] == []
    assert package_install(client, version).status_code == 409
    result = client.get("/api/v1/capability-studio/extensions", params={"artifact_id": setup["artifact"]}).json()
    assert len(result["items"]) == 1
    assert client.get("/api/v1/capability-studio/extensions", params={"artifact_id": str(uuid4())}).json()["items"] == []


def test_explicit_scope_upgrade_and_rollback_preserve_legacy_authority(client, setup):
    version = setup["version"](1)
    old = install(client, version, _run_tests(client, setup, version)).json()
    assert old["target_policy"] is None and len(old["bindings"]) == 1
    new = package_install(client, version, 1).json()
    assert new["id"] == old["id"] and new["bindings"] == [] and new["previous_target_policy"] is None
    assert new["previous_bindings"] == old["bindings"]
    restored = client.post(f"/api/v1/capability-studio/extensions/{new['id']}/rollback", json={"expected_revision": 2})
    assert restored.status_code == 200, restored.text
    assert restored.json()["target_policy"] is None and restored.json()["bindings"] == old["bindings"]


@pytest.mark.parametrize("failure", ["fixture", "startup"])
def test_package_install_automatically_checks_fixtures_and_startup_atomically(client, setup, monkeypatch, failure):
    version = setup["version"](1)
    if failure == "fixture":
        with SessionLocal() as db:
            row = db.get(ArtifactVersion, version)
            spec = deepcopy(SPEC); spec["tools"][0]["fixtures"][0]["expected_output"]["interfaces"] = []
            row.definition, row.implementation, row.tests = extension_documents(spec)
            row.content_hash = artifact_content_hash(kind=ArtifactKind.TOOL, definition=row.definition,
                implementation=row.implementation, tests=row.tests, collector_definition=None)
            db.commit()
    else:
        class Broken:
            def discover(self, _): raise ValueError("synthetic startup failure")
        monkeypatch.setattr(runtime, "HOST", Broken)
    assert package_install(client, version).status_code == 409
    with SessionLocal() as db:
        assert db.scalar(select(ManagedExtensionInstallation)) is None
        assert db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.transport == "managed_mcp")) is None
    assert setup["calls"] == []


def test_runtime_intersects_package_policy_and_caller_scope(client, setup):
    actor = development_principal()
    with SessionLocal() as db:
        with pytest.raises(HTTPException):
            runtime._inventory_binding(db, actor, {"mode": "authorized_inventory", "scope": {"sites": ["OTHER"]}}, setup["device"])
        with pytest.raises(HTTPException):
            runtime._inventory_binding(db, replace(actor, authorization_scope={"sites": ["OTHER"]}),
                {"mode": "authorized_inventory", "scope": {"all": True}}, setup["device"])
        with pytest.raises(runtime.ExtensionReviewConflict, match="Device access needs setup"):
            runtime._inventory_binding(db, actor, {"mode": "authorized_inventory", "scope": {"all": True}}, setup["device"])
    assert setup["calls"] == []
