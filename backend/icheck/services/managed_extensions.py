"""Reviewed Studio installations using the existing Artifact and Tool registries."""
import base64
from dataclasses import replace
from contextlib import contextmanager, nullcontext
from datetime import UTC, timedelta
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import tempfile

from sqlalchemy import select, update
from sqlalchemy.orm import Session, selectinload

from ..config import get_settings
from ..database import set_session_namespace, validate_session_namespace
from ..extension_host import NativeExtensionProcess, install_package
from ..extension_runtime import AuthorizedNetmikoTarget
from ..extension_schemas import DEVICE_INPUT, EXTENSION_FORMAT, GeneratedExtensionSpec
from ..models import (AgentToolRegistration, Artifact, ArtifactKind, ArtifactVersion, ArtifactVersionStatus,
    ControlPlanePrincipal, ControlPlaneRoleBinding, Device, DeviceConnection, Investigation,
    ManagedDeviceCredential, ManagedExtensionInstallation, ManagedExtensionTest, new_id, utcnow)
from .agent_authorization import investigation_principal
from .audit import record_audit_event
from .authorization_scope import device_scope_clause, namespace_clause, require_device_access
from .collectors import artifact_content_hash
from .control_plane_auth import principal_context
from .current_authority import current_human_authority
from .device_credentials import profile, resolve as resolve_credential
from .extension_backups import store_configuration_backup
from .mcp_extensions import extension_documents

HUMAN_PERMISSIONS = ("capabilities.manage", "assets.read", "assets.activate", "tools.admin")
TOOL_PERMISSIONS = ["assets.read", "investigations.create"]
HOST = NativeExtensionProcess


class ExtensionReviewConflict(ValueError):
    """Safe operator-facing review conflict, without any credential/driver content."""


def _time(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _development(actor):
    return (get_settings().control_plane_auth_mode == "disabled" and actor.principal_type == "development"
        and actor.auth_method == "disabled")


def human(db, actor):
    if not actor.permits(*HUMAN_PERMISSIONS):
        raise PermissionError("Extension target tests and installation require capability, device-read and activation permissions")
    if not _development(actor):
        current_human_authority(db, actor, permissions=HUMAN_PERMISSIONS,
            tenant_id=actor.tenant_id, region_id=actor.region_id)


def _current_actor(db, actor, device_id, investigation_id=None):
    """Brief independent reads do not hold revocation locks across SSH I/O."""
    if _development(actor):
        require_device_access(db, actor, device_id)
        return
    # SQLite's test pool shares one connection; closing another Session would
    # roll back the caller's transaction. PostgreSQL gets an independent read.
    context = nullcontext(db) if db.get_bind().dialect.name == "sqlite" else Session(db.get_bind())
    with context as current:
        set_session_namespace(current, actor.tenant_id, actor.region_id)
        validate_session_namespace(current)
        if investigation_id:
            inv = current.get(Investigation, investigation_id)
            if inv is None or inv.status not in {"pending", "running", "waiting_approval"}:
                raise PermissionError("Investigation is no longer active")
            principal = current.scalar(select(ControlPlanePrincipal).where(ControlPlanePrincipal.id == actor.principal_id)
                .options(selectinload(ControlPlanePrincipal.role_bindings).selectinload(ControlPlaneRoleBinding.role)))
            if principal is None or not principal.enabled or principal.principal_type != "user":
                raise PermissionError("Initiating identity is no longer active")
            now = principal_context(principal, db=current, tenant_selector=actor.tenant_id, region_selector=actor.region_id)
            if not now.permits(*TOOL_PERMISSIONS) or not actor.permits(*TOOL_PERMISSIONS):
                raise PermissionError("Current and initiating tool permissions are required")
        else:
            now = current_human_authority(current, actor, permissions=HUMAN_PERMISSIONS,
                tenant_id=actor.tenant_id, region_id=actor.region_id).actor
        require_device_access(current, actor, device_id)
        require_device_access(current, now, device_id)


def _root():
    value = get_settings().extension_packages_root
    if not value:
        raise ValueError("Native extension storage/runtime is not provisioned")
    root = Path(value)
    if not root.is_absolute() or root.resolve() != root or not root.is_dir():
        raise ValueError("Native extension storage/runtime is unavailable")
    return root


def _version(db, actor, identifier):
    version = db.scalar(select(ArtifactVersion).where(ArtifactVersion.id == identifier,
        namespace_clause(ArtifactVersion, actor)).execution_options(populate_existing=True))
    artifact = db.get(Artifact, version.artifact_id) if version else None
    if (version is None or artifact is None or artifact.kind != ArtifactKind.TOOL
            or version.status not in {ArtifactVersionStatus.VALIDATED, ArtifactVersionStatus.PUBLISHED}
            or version.definition.get("format_version") != EXTENSION_FORMAT):
        raise ValueError("Select a validated executable extension version")
    spec = GeneratedExtensionSpec.model_validate(version.definition["spec"])
    if (version.definition, version.implementation, version.tests) != extension_documents(spec):
        raise ValueError("Executable version differs from its canonical package")
    digest = artifact_content_hash(kind=ArtifactKind.TOOL, definition=version.definition,
        implementation=version.implementation, tests=version.tests, collector_definition=None)
    if version.content_hash != digest:
        raise ValueError("Executable version changed after validation")
    return version, artifact, spec


def _public_key(value):
    from paramiko import PKey
    parts = value.strip().split()
    if len(parts) < 2 or parts[0] not in {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}:
        raise ValueError("Supply the device's independently verified OpenSSH public host key")
    try:
        key = PKey.from_type_string(parts[0], base64.b64decode(parts[1], validate=True))
        if key.get_name() != parts[0]: raise ValueError()
    except Exception:
        raise ValueError("SSH public host key is invalid") from None
    return f"{parts[0]} {key.get_base64()}"


def _connection_binding(db, actor, connection_id):
    connection = db.scalar(select(DeviceConnection).where(DeviceConnection.id == connection_id,
        namespace_clause(DeviceConnection, actor)).execution_options(populate_existing=True))
    if connection is None or connection.protocol != "ssh" or not connection.enabled:
        raise ValueError("Select an enabled SSH connection")
    device = require_device_access(db, actor, connection.device_id)
    db.refresh(device)
    address = ipaddress.ip_address(device.management_ip or "")
    checked_address = getattr(address, "ipv4_mapped", None) or address
    if (not device.enabled or checked_address.is_loopback or checked_address.is_link_local
            or checked_address.is_multicast or checked_address.is_unspecified or checked_address.is_reserved):
        raise ValueError("Extension target must be an enabled inventory device, not a local or special address")
    credential = profile(db, connection.credential_profile_ref)
    managed = db.scalar(select(ManagedDeviceCredential).where(
        ManagedDeviceCredential.credential_profile_id == credential.id)) if credential else None
    if (credential is None or not credential.enabled or managed is None or managed.kind != "ssh_password"
            or (device.site and managed.site != device.site) or credential.worker_selector != {"site": managed.site}
            or "ssh" not in credential.allowed_adapters):
        raise ValueError("Select a managed SSH username/password credential scoped to this device's site")
    if connection.worker_selector not in ({}, {"site": managed.site}):
        raise ValueError("This native extension cannot bypass a connection pinned to a remote worker")
    binding = {"device_id": device.id, "connection_id": connection.id, "host": str(address),
        "port": connection.port or 22, "site": device.site or managed.site, "device_revision": device.revision,
        "identity_revision": device.identity_revision,
        "connection_configuration": hashlib.sha256(json.dumps(connection.configuration, sort_keys=True).encode()).hexdigest(),
        "credential_id": credential.id, "credential_revision": credential.revision}
    from ..ssh_compatibility import connection_profile
    selected, current = connection_profile(connection.configuration, binding)
    return {**binding, "ssh_profile": selected, "ssh_profile_current": current}


def _binding(db, actor, connection_id, host_key=None):
    from .ssh_host_identity import saved_key
    binding = _connection_binding(db, actor, connection_id)
    if not binding["ssh_profile_current"]:
        raise ExtensionReviewConflict("SSH target changed; review and save its compatibility profile again")
    stored = saved_key(db, binding)
    key = _public_key(host_key) if host_key else stored
    if not key:
        raise ExtensionReviewConflict("Device access needs setup: confirm its SSH fingerprint in Assets → device settings")
    if stored and key != stored:
        raise ExtensionReviewConflict("SSH identity differs from the saved fingerprint; review it again")
    return {**binding, "host_public_key": key}


def _assert_binding(db, actor, binding):
    if _binding(db, actor, binding["connection_id"], binding["host_public_key"]) != binding:
        raise ExtensionReviewConflict("Target or credential changed; test and review the updated binding")


@contextmanager
def _target_resolver(db, actor, binding, *, revalidate):
    # A public host key is not a credential. Its private file still prevents local
    # tampering while Paramiko reads it. First use requires explicit human
    # fingerprint confirmation (or an independently verified API-supplied key).
    with tempfile.NamedTemporaryFile(mode="w", dir=_root(), prefix=".host-key-", encoding="utf-8") as known:
        os.fchmod(known.fileno(), 0o600)
        host = binding["host"] if binding["port"] == 22 else f'[{binding["host"]}]:{binding["port"]}'
        known.write(f'{host} {binding["host_public_key"]}\n'); known.flush()
        def resolve(spec, tool, device_id):
            if device_id != binding["device_id"]:
                raise PermissionError("Tool call is outside the reviewed target")
            revalidate()
            values = resolve_credential(db, profile(db, binding["credential_id"]))
            return AuthorizedNetmikoTarget(device_id, binding["host"], binding["port"], spec.device_type,
                values["username"], values["password"], known.name, tuple(tool.commands), revalidate,
                timeout_seconds=15, ssh_profile=binding["ssh_profile"])
        yield resolve


def _audit(db, actor, event, row):
    record_audit_event(db, event_type="extension." + event, actor_type="user", actor_id=actor.subject,
        entity_type="managed_extension", entity_id=row.id, details={"artifact_id": row.artifact_id,
            "version_id": row.active_version_id, "revision": row.revision, "enabled": row.enabled,
            "target_policy": row.target_policy, "target_count": len(row.bindings)})


def test_target(db, actor, payload):
    human(db, actor)
    version, _, spec = _version(db, actor, str(payload.artifact_version_id))
    if payload.tool_name not in {tool.name for tool in spec.tools}:
        raise ValueError("Unknown extension tool")
    binding = _binding(db, actor, str(payload.connection_id), payload.host_public_key)
    prior = db.scalar(select(ManagedExtensionTest).where(ManagedExtensionTest.request_key == str(payload.request_key),
        namespace_clause(ManagedExtensionTest, actor)))
    if prior:
        if (prior.artifact_version_id != version.id or prior.tool_name != payload.tool_name or prior.binding != binding):
            raise ValueError("Test request key already belongs to another request")
        return prior
    path = install_package(_root(), version.id, spec)
    row = ManagedExtensionTest(id=new_id(), request_key=str(payload.request_key), artifact_version_id=version.id,
        version_hash=version.content_hash, tool_name=payload.tool_name, binding=binding, created_by=actor.subject)
    db.add(row); db.commit()
    identifier, pinned_hash = row.id, row.version_hash
    def check():
        _current_actor(db, actor, binding["device_id"])
        _assert_binding(db, actor, binding)
        current, _, _ = _version(db, actor, str(payload.artifact_version_id))
        if current.content_hash != pinned_hash: raise PermissionError("Reviewed package changed")
    try:
        with _target_resolver(db, actor, binding, revalidate=check) as resolver:
            result = HOST().call(path, payload.tool_name, {"device_id": binding["device_id"]}, resolve=resolver,
                store_backup=lambda target, body: store_configuration_backup(db, actor, version_id=version.id,
                    connection_id=binding["connection_id"], tool_name=payload.tool_name, target=target, body=body))
        check()
        row.status, row.result = "succeeded", result
    except Exception:
        db.rollback()
        row = db.get(ManagedExtensionTest, identifier)
        row.status, row.result = "failed", {"error": "Target test failed; check connection, host key, credentials and declared output"}
    row.completed_at = utcnow()
    db.commit()
    return row


def test_view(row):
    return {"id": row.id, "artifact_version_id": row.artifact_version_id, "tool_name": row.tool_name,
        "device_id": row.binding["device_id"], "connection_id": row.binding["connection_id"],
        "host_public_key": row.binding["host_public_key"], "status": row.status, "result": row.result,
        "binding_hash": hashlib.sha256(json.dumps({key: value for key, value in row.binding.items()
            if key != "host_public_key"}, sort_keys=True).encode()).hexdigest(),
        "created_at": row.created_at, "completed_at": row.completed_at}


def installation_view(row):
    return {"id": row.id, "artifact_id": row.artifact_id, "active_version_id": row.active_version_id,
        "previous_version_id": row.previous_version_id, "revision": row.revision, "enabled": row.enabled,
        "bindings": row.bindings, "previous_bindings": row.previous_bindings, "tool_ids": row.tool_ids, "transport": "managed_mcp",
        "target_policy": row.target_policy, "previous_target_policy": row.previous_target_policy,
        "runtime_state": "ready_on_demand" if row.enabled else "disabled",
        "last_health_status": row.last_health_status, "last_checked_at": row.last_checked_at}


def _register(db, actor, row, artifact, spec):
    for old in db.scalars(select(AgentToolRegistration).where(
            AgentToolRegistration.transport == "managed_mcp", AgentToolRegistration.handler.like(row.id + ":%"))):
        old.enabled = False
    tool_ids = {}
    for tool in spec.tools:
        name = "extensions." + artifact.name + "." + tool.name
        registered = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == name))
        if registered is not None and (registered.transport != "managed_mcp" or not registered.handler.startswith(row.id + ":")):
            raise ValueError("Tool name conflicts with an existing registration")
        if registered is None:
            registered = AgentToolRegistration(id=new_id(), name=name, created_by=actor.subject)
            db.add(registered)
        registered.description, registered.transport = tool.description, "managed_mcp"
        registered.handler = f"{row.id}:{row.active_version_id}:{tool.name}"
        registered.input_schema, registered.output_schema = DEVICE_INPUT, tool.output_schema
        # These tools do not change monitored infrastructure. Backup storage is a
        # platform-side effect, explicitly disclosed in Studio and MCP annotations.
        registered.risk_level, registered.read_only, registered.change_contract = "observe", True, None
        registered.required_permissions = TOOL_PERMISSIONS
        registered.timeout_seconds, registered.max_result_bytes, registered.enabled = 60, 131072, row.enabled
        tool_ids[tool.name] = registered.id
    row.tool_ids = tool_ids
    db.flush()


def _legacy_install_bindings(db, actor, payload, version, spec):
    """Compatibility path; never silently widen previously reviewed targets."""
    identifiers = set(map(str, payload.test_ids))
    tests = list(db.scalars(select(ManagedExtensionTest).where(ManagedExtensionTest.id.in_(identifiers),
        namespace_clause(ManagedExtensionTest, actor))))
    if len(tests) != len(identifiers): raise ValueError("Selected target tests are unavailable")
    groups = {}
    for test in tests:
        if (test.status != "succeeded" or test.artifact_version_id != version.id or test.version_hash != version.content_hash
                or test.completed_at is None or _time(test.completed_at) < utcnow() - timedelta(minutes=30)):
            raise ValueError("Every tool needs a recent successful test of this exact version and target")
        latest = db.scalar(select(ManagedExtensionTest.id).where(
            ManagedExtensionTest.artifact_version_id == version.id,
            ManagedExtensionTest.tool_name == test.tool_name,
            ManagedExtensionTest.binding["connection_id"].as_string() == test.binding["connection_id"])
            .order_by(ManagedExtensionTest.created_at.desc(), ManagedExtensionTest.id.desc()).limit(1))
        if latest != test.id:
            raise ExtensionReviewConflict("A newer target test supersedes this result; refresh and review it")
        identity = json.dumps(test.binding, sort_keys=True)
        groups.setdefault(identity, set()).add(test.tool_name)
    if not groups or len(groups) > 32 or any(names != {tool.name for tool in spec.tools} for names in groups.values()):
        raise ValueError("Test every declared tool on each selected target before installation")
    bindings = [json.loads(identity) for identity in groups]
    if len({binding["device_id"] for binding in bindings}) != len(bindings):
        raise ValueError("Select only one reviewed SSH binding per device")
    for binding in bindings: _assert_binding(db, actor, binding)
    return bindings


def install(db, actor, payload):
    human(db, actor)
    version, artifact, spec = _version(db, actor, str(payload.artifact_version_id))
    db.scalar(select(Artifact).where(Artifact.id == artifact.id).with_for_update())
    row = db.scalar(select(ManagedExtensionInstallation).where(ManagedExtensionInstallation.artifact_id == artifact.id)
        .with_for_update().execution_options(populate_existing=True))
    if (row.revision if row else 0) != payload.expected_revision:
        raise ExtensionReviewConflict("Installation changed; refresh before approving it")
    policy = None
    if payload.access_mode == "authorized_inventory":
        # The approver's scope is an upper bound, intersected with the caller's
        # current authority on every invocation. No device enumeration or I/O.
        policy = {"mode": "authorized_inventory", "scope": actor.authorization_scope}
        bindings = []
        from .mcp_extensions import validate_extension_contract
        validate_extension_contract(version.definition, version.implementation, version.tests)
    else:
        bindings = _legacy_install_bindings(db, actor, payload, version, spec)
    path = install_package(_root(), version.id, spec)
    HOST().discover(path)
    human(db, actor)
    if row is None:
        row = ManagedExtensionInstallation(id=new_id(), artifact_id=artifact.id, active_version_id=version.id,
            revision=1, enabled=True, bindings=bindings, previous_bindings=[], target_policy=policy, created_by=actor.subject)
        db.add(row)
    else:
        row.previous_version_id, row.previous_bindings = row.active_version_id, row.bindings
        row.previous_target_policy, row.target_policy = row.target_policy, policy
        row.active_version_id, row.bindings, row.enabled = version.id, bindings, True
        row.revision += 1
    row.last_health_status, row.last_checked_at, row.updated_at = "discovered", utcnow(), utcnow()
    _register(db, actor, row, artifact, spec)
    _audit(db, actor, "installed", row)
    db.commit()
    return row


def lifecycle(db, actor, identifier, expected_revision, action):
    human(db, actor)
    row = db.scalar(select(ManagedExtensionInstallation).where(ManagedExtensionInstallation.id == identifier,
        namespace_clause(ManagedExtensionInstallation, actor)).with_for_update().execution_options(populate_existing=True))
    if row is None: raise LookupError("Installed extension not found")
    if row.revision != expected_revision: raise ValueError("Installation changed; refresh before reviewing it")
    if action == "rollback":
        if not row.previous_version_id: raise ValueError("There is no previously installed version")
        version, artifact, spec = _version(db, actor, row.previous_version_id)
        for binding in row.previous_bindings: _assert_binding(db, actor, binding)
        HOST().discover(install_package(_root(), version.id, spec))
        row.active_version_id, row.previous_version_id = row.previous_version_id, row.active_version_id
        row.bindings, row.previous_bindings = row.previous_bindings, row.bindings
        row.target_policy, row.previous_target_policy = row.previous_target_policy, row.target_policy
        row.enabled = True
    elif action == "disable":
        row.enabled = False
    else:
        raise ValueError("Unsupported extension lifecycle action")
    row.revision += 1
    row.updated_at = utcnow()
    row.last_health_status = "discovered" if row.enabled else "disabled"
    if action == "disable":
        db.execute(update(AgentToolRegistration).where(AgentToolRegistration.transport == "managed_mcp",
            AgentToolRegistration.handler.like(row.id + ":%")).values(enabled=False))
    else:
        _register(db, actor, row, artifact, spec)
    _audit(db, actor, action, row)
    db.commit()
    return row


def _registered(db, actor, tool):
    installation_id, version_id, name = tool.handler.split(":", 2)
    row = db.scalar(select(ManagedExtensionInstallation).where(ManagedExtensionInstallation.id == installation_id,
        namespace_clause(ManagedExtensionInstallation, actor)).execution_options(populate_existing=True))
    if not row or not row.enabled or row.active_version_id != version_id or row.tool_ids.get(name) != tool.id:
        raise PermissionError("Native MCP registration is not active")
    _, artifact, spec = _version(db, actor, version_id)
    declared = next((item for item in spec.tools if item.name == name), None)
    if (declared is None or not tool.enabled or tool.transport != "managed_mcp" or not tool.read_only
            or tool.risk_level != "observe" or tool.change_contract is not None
            or tool.name != f"extensions.{artifact.name}.{name}" or tool.input_schema != DEVICE_INPUT
            or tool.output_schema != declared.output_schema or tool.required_permissions != TOOL_PERMISSIONS):
        raise PermissionError("Native MCP tool differs from the installed contract")
    return row, spec, name


def available(db, tool, investigation):
    actor = investigation_principal(investigation)
    try:
        _root()
        row, _, _ = _registered(db, actor, tool)
        if row.target_policy:
            policy_actor = _policy_actor(actor, row.target_policy)
            return db.scalar(select(Device.id).where(device_scope_clause(actor),
                device_scope_clause(policy_actor), Device.enabled.is_(True)).limit(1)) is not None
        for binding in row.bindings:
            try:
                require_device_access(db, actor, binding["device_id"])
                return True
            except Exception:
                continue
    except (ValueError, PermissionError):
        pass
    return False


def _policy_actor(actor, policy):
    if set(policy) != {"mode", "scope"} or policy["mode"] != "authorized_inventory" or not isinstance(policy["scope"], dict):
        raise PermissionError("Invalid installed package access policy")
    return replace(actor, authorization_scope=policy["scope"])


def _inventory_binding(db, actor, policy, device_id):
    # Inventory—not generated code—owns addresses, credentials and trust. Freeze
    # this fresh binding for the duration of one call and recheck before each I/O.
    require_device_access(db, actor, device_id)
    require_device_access(db, _policy_actor(actor, policy), device_id)
    connections = list(db.scalars(select(DeviceConnection.id).where(
        namespace_clause(DeviceConnection, actor), DeviceConnection.device_id == device_id,
        DeviceConnection.protocol == "ssh", DeviceConnection.enabled.is_(True)).limit(2)))
    if len(connections) != 1:
        raise ExtensionReviewConflict("Device access needs setup: configure one enabled SSH connection in Assets → device settings")
    return _binding(db, actor, connections[0])


def execute(db, tool, arguments, investigation, tool_call_id):
    from ..agent_schemas import InvestigationEvidenceCreate
    actor = investigation_principal(investigation)
    row, spec, name = _registered(db, actor, tool)
    if set(arguments) != {"device_id"}:
        raise PermissionError("Select an inventory device for this tool")
    binding = (_inventory_binding(db, actor, row.target_policy, arguments["device_id"]) if row.target_policy
        else next((item for item in row.bindings if item["device_id"] == arguments["device_id"]), None))
    if binding is None:
        raise PermissionError("Device is not a reviewed extension target")
    revision, version_id = row.revision, row.active_version_id
    def check():
        _current_actor(db, actor, binding["device_id"], investigation.id)
        _assert_binding(db, actor, binding)
        current_tool = db.get(AgentToolRegistration, tool.id, populate_existing=True)
        current, _, _ = _registered(db, actor, current_tool)
        if current.revision != revision: raise PermissionError("Extension changed during execution")
    check()
    path = install_package(_root(), version_id, spec)
    try:
        # Failed/revoked calls do not leave backup bodies or saved-body audits
        # committed alongside a failed ToolCall. Preserve the caller's transaction.
        with db.begin_nested():
            with _target_resolver(db, actor, binding, revalidate=check) as resolver:
                result = HOST().call(path, name, arguments, resolve=resolver,
                    store_backup=lambda target, body: store_configuration_backup(db, actor, version_id=version_id,
                        connection_id=binding["connection_id"], tool_name=name, target=target, body=body))
            check()
    except Exception:
        if db.is_active:
            db.execute(update(ManagedExtensionInstallation).where(ManagedExtensionInstallation.id == row.id,
                ManagedExtensionInstallation.revision == revision).values(last_health_status="call_failed", last_checked_at=utcnow()))
        raise
    db.execute(update(ManagedExtensionInstallation).where(ManagedExtensionInstallation.id == row.id,
        ManagedExtensionInstallation.revision == revision).values(last_health_status="target_ok", last_checked_at=utcnow()))
    return result, [InvestigationEvidenceCreate(evidence_type="native_mcp_result",
        evidence_id=f"extension:{row.id}:{version_id}:{tool_call_id}", observed_at=utcnow(),
        summary=f"Installed MCP tool {name} returned a validated result for device {binding['device_id']}.")]
