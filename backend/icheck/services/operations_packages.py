"""Guided portable recipes, recompiled against local capability contracts.

Import validates Artifacts but never publishes, registers MCP tools, runs a
workflow, enables a schedule or opens a source connection.
"""
from copy import deepcopy
import hashlib
import ipaddress
import json
import re

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..collector_schemas import ArtifactCreate, ArtifactVersionCreate
from ..config import get_settings
from ..database import validate_session_namespace
from ..extension_schemas import EXTENSION_FORMAT, GeneratedExtensionSpec
from ..models import (Artifact, ArtifactVersion, ArtifactVersionStatus, ArtifactTrustKey, AgentToolRegistration,
    MCPServer, MonitoringIntegrationConnection, OperationsPackageInstallation, new_id)
from ..operations_package_schemas import FORMAT, OperationComponent, OperationsPackage
from ..studio_schemas import GeneratedWorkflowSpec, GeneratedSkillSpec, GeneratedToolSpec
from .authorization_scope import namespace_clause
from .collectors import create_artifact, validate_artifact_version, assert_no_inline_secrets
from .audit import record_audit_event
from .artifact_portability import verify_trusted_digest_signature
from .artifact_lifecycle import lock_artifact_identities
from .workflow_templates import workflow_artifact_documents
from .tool_skills import skill_artifact_documents, tool_artifact_documents
from .mcp_extensions import extension_documents

MAX_BYTES = 2_000_000
LOCAL_KEYS = {"credential_profile_ref", "credential_ref", "secret_ref", "connection_id", "device_id",
              "tenant_id", "region_id", "site_id", "mcp_server_id", "deployment_id"}


def digest(document):
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                                     allow_nan=False).encode()).hexdigest()


def build_package(name, version, description, components):
    material = {"format_version": FORMAT, "name": name, "version": version,
                "description": description, "components": [c.model_dump(mode="json") for c in components]}
    return OperationsPackage(**material, digest_sha256=digest(material))


def guard(db, actor):
    if validate_session_namespace(db) != (actor.tenant_id, actor.region_id):
        raise PermissionError("Package workspace mismatch")


def portable(value, *, schema=False):
    """Reject nonportable authority, rather than silently exporting local values.

    Schema property names are not credentials. Fixture values still get scanned.
    Public documentation/example hosts and RFC documentation IPs are permitted.
    """
    if isinstance(value, dict):
        for key, child in value.items():
            in_schema = schema or key.endswith("_schema")
            if not in_schema and key in LOCAL_KEYS and child not in (None, "", {}, []):
                raise ValueError("Package contains environment-local bindings; remove them before export")
            portable(child, schema=in_schema)
    elif isinstance(value, list):
        for child in value:
            portable(child, schema=schema)
    elif isinstance(value, str):
        if re.search(r"(?:env|vault|managed-ai|managed-device)://|-----BEGIN .*PRIVATE KEY|(?:sk-|ghp_)[A-Za-z0-9_-]{16,}", value):
            raise ValueError("Package contains a secret or external secret reference")
        if not schema:
            for address in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", value):
                try:
                    ip = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if not any(ip in ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
                    raise ValueError("Package contains a real environment address; use runtime inputs or documentation fixtures")
        # Reject literal API endpoints in portable recipes. Source references
        # belong in documentation; local endpoints are bound after import.
        for host in re.findall(r"https?://([^/\s\"'<>]+)", value):
            if not (host.endswith(".example.test") or host in {"example.com", "example.org"}):
                raise ValueError("Package contains an endpoint; bind connections in the destination workspace")


def check_package(package):
    material = package.model_dump(mode="json", exclude={"digest_sha256"})
    if len(json.dumps(material).encode()) > MAX_BYTES or digest(material) != package.digest_sha256:
        raise ValueError("Package size or digest is invalid")
    portable(material)
    # Existing secret checks are applied to semantic specs by their compilers.
    # Do not run them on JSON schemas (where a property named token is metadata).


def semantic_contract(value, db=None):
    result = {key: child for key, child in value.items() if key != "id"}
    if result.get("transport") == "managed_mcp":
        result["handler"] = "managed_mcp:" + result["name"]
        if db is not None:
            parts = value["handler"].split(":")
            version = db.get(ArtifactVersion, parts[1]) if len(parts) == 3 else None
            if version is None or not version.content_hash:
                raise ValueError("Managed MCP dependency has no immutable source version")
            result["implementation_sha256"] = version.content_hash
    return result


def export(db, payload, actor):
    guard(db, actor)
    components = []
    for identifier in payload.artifact_version_ids:
        version = db.scalar(select(ArtifactVersion).where(ArtifactVersion.id == str(identifier),
                            namespace_clause(ArtifactVersion, actor)))
        if version is None or version.status not in {ArtifactVersionStatus.VALIDATED, ArtifactVersionStatus.PUBLISHED}:
            raise ValueError("Select validated or published versions in this workspace")
        artifact = db.get(Artifact, version.artifact_id)
        kind, spec, contracts = artifact.kind.value, deepcopy(version.definition.get("spec")), []
        if version.definition.get("format_version") == EXTENSION_FORMAT:
            kind = "mcp"
        elif kind == "workflow":
            contracts = version.definition["tool_dependencies"]
        elif kind == "skill":
            contracts = version.tests[0]["tool_dependencies"]
        elif kind == "collector":
            from .artifact_portability import export_artifact_bundle
            spec = export_artifact_bundle(version).version.model_dump(mode="json")
            # Credentials are acquired through onboarding in the destination.
            spec["collector_definition"]["credential_profile_ref"] = None
        if kind not in {"workflow", "skill", "tool", "mcp", "collector"} or spec is None:
            raise ValueError("This version does not have a supported portable recipe")
        components.append(OperationComponent(name=artifact.name, kind=kind, spec=spec,
                          tool_contracts=[semantic_contract(c, db) for c in contracts]))
    for provider in dict.fromkeys(payload.connector_providers):
        components.append(OperationComponent(name=provider.replace("_", "-") + "-connection",
                                              kind="connector", spec={"provider": provider}))
    result = build_package(payload.name, payload.version, payload.description, components)
    check_package(result)
    return result


def compile_component(db, component, mcp_servers):
    spec = deepcopy(component.spec)
    if component.kind == "collector":
        version = ArtifactVersionCreate(**spec, created_by="package-import")
        assert_no_inline_secrets(version.definition)
        return "collector", version
    if component.kind == "tool":
        spec["mcp_server_name"] = mcp_servers.get(component.name, spec.get("mcp_server_name"))
        parsed = GeneratedToolSpec.model_validate(spec)
        documents = tool_artifact_documents(parsed)
    elif component.kind == "mcp":
        parsed = GeneratedExtensionSpec.model_validate(spec)
        documents = extension_documents(parsed)
    elif component.kind == "workflow":
        parsed = GeneratedWorkflowSpec.model_validate(spec)
        documents = workflow_artifact_documents(db, parsed)
    elif component.kind == "skill":
        parsed = GeneratedSkillSpec.model_validate(spec)
        documents = skill_artifact_documents(db, parsed)
    else:
        raise ValueError("Unsupported executable component")
    if parsed.artifact_name != component.name:
        raise ValueError("Component name must match its artifact name")
    if component.kind in {"workflow", "skill"}:
        actual = documents[0]["tool_dependencies"] if component.kind == "workflow" else documents[2][0]["tool_dependencies"]
        if [semantic_contract(c, db) for c in actual] != component.tool_contracts:
            raise ValueError("Local tool contracts differ from this package; review and export a compatible version")
    return ("tool" if component.kind == "mcp" else component.kind), ArtifactVersionCreate(
        definition=documents[0], implementation=documents[1], tests=documents[2], created_by="package-import")


def installed(db, package, actor):
    return db.scalar(select(OperationsPackageInstallation).where(
        OperationsPackageInstallation.name == package.name, OperationsPackageInstallation.version == package.version,
        namespace_clause(OperationsPackageInstallation, actor)))


def retain_signature_authority(db, signature, actor):
    """Keep publisher trust current through the import/prepare transaction."""
    if signature is None:
        return
    from .trust_authority import lock_trust_keys
    identity = db.scalar(select(ArtifactTrustKey.id).where(namespace_clause(ArtifactTrustKey, actor),
        ArtifactTrustKey.fingerprint_sha256 == signature.key_fingerprint_sha256))
    if identity is None:
        raise ValueError("Package signer is not trusted in this workspace")
    lock_trust_keys(db, [identity], expected_purpose="capability_pack")


def review(db, payload, actor, *, builtin=False):
    guard(db, actor)
    package = payload.package
    check_package(package)
    blockers, requirements, pending = [], [], []
    if not builtin:
        if payload.signature:
            verify_trusted_digest_signature(db, payload.signature, expected_digest_sha256=package.digest_sha256,
                                            signed_format_version=FORMAT, expected_purpose="capability_pack")
        elif get_settings().artifact_signature_policy == "required":
            blockers.append("This installation requires a trusted package signature")
    existing = installed(db, package, actor)
    if existing and existing.digest_sha256 != package.digest_sha256:
        blockers.append("This package version already exists with different content")
    allowed_connections = {c.name for c in package.components if c.kind == "connector"}
    allowed_servers = {c.name for c in package.components if c.kind == "tool"}
    if set(payload.connections) - allowed_connections or set(payload.mcp_servers) - allowed_servers:
        raise ValueError("Unexpected local binding")
    for component in package.components:
        if component.kind == "connector":
            provider = component.spec.get("provider")
            if set(component.spec) != {"provider"} or provider not in {"zabbix", "solarwinds_orion", "rest_webhook"}:
                raise ValueError("Unsupported connector recipe")
            identifier = payload.connections.get(component.name)
            row = db.scalar(select(MonitoringIntegrationConnection).where(
                MonitoringIntegrationConnection.id == str(identifier),
                namespace_clause(MonitoringIntegrationConnection, actor))) if identifier else None
            ready = row is not None and row.provider == provider
            requirements.append({"component": component.name, "kind": "connection", "provider": provider, "ready": ready})
            if not ready:
                blockers.append(f"{component.name}: select a saved {provider} connection")
            continue
        if component.kind == "tool":
            name = payload.mcp_servers.get(component.name, component.spec.get("mcp_server_name"))
            server = db.scalar(select(MCPServer).where(MCPServer.name == name, namespace_clause(MCPServer, actor)))
            requirements.append({"component": component.name, "kind": "mcp_server", "ready": server is not None})
            if server is None:
                blockers.append(f"{component.name}: select a local MCP server")
        if not existing and db.scalar(select(Artifact.id).where(Artifact.name == component.name, namespace_clause(Artifact, actor))):
            blockers.append(f"{component.name}: an artifact with this name already exists; use its version lifecycle")
        try:
            compile_component(db, component, payload.mcp_servers)
        except ValueError:
            if internal_dependency_pending(db, package, component):
                pending.append(component.name)
            else:
                blockers.append(f"{component.name}: recipe or local tool contract is incompatible")
    return {"name": package.name, "version": package.version, "digest_sha256": package.digest_sha256,
            "already_imported": bool(existing and existing.digest_sha256 == package.digest_sha256),
            "installable": not blockers, "blockers": blockers, "requirements": requirements,
            "pending_components": pending,
            "components": [{"name": c.name, "kind": c.kind} for c in package.components],
            "activation": "Import validates only. Publishing, MCP installation and recurring execution remain separate."}


def internal_dependency_pending(db, package, component):
    if component.kind not in {"workflow", "skill"}:
        return False
    # Validate syntax even when this package's executable MCP tools are not yet
    # registered. Only declared in-package dependencies may be staged.
    parsed = (GeneratedWorkflowSpec if component.kind == "workflow" else GeneratedSkillSpec).model_validate(component.spec)
    if parsed.artifact_name != component.name:
        raise ValueError("Mismatched component name")
    names = set(parsed.allowed_tools) if component.kind == "skill" else {
        name for node in parsed.nodes for name in [node.tool_name, *node.allowed_tools] if name}
    supplied = {f"extensions.{c.name}.{tool['name']}" for c in package.components if c.kind == "mcp"
                for tool in GeneratedExtensionSpec.model_validate(c.spec).model_dump()["tools"]}
    present = set(db.scalars(select(AgentToolRegistration.name).where(AgentToolRegistration.name.in_(names),
                                                                 AgentToolRegistration.enabled.is_(True))))
    missing = names - present
    return bool(missing) and missing <= supplied


def install(db, payload, actor, *, builtin=False):
    guard(db, actor)
    if not builtin:
        retain_signature_authority(db, payload.signature, actor)
    # Names are serialized with all other Artifact mutations; validation and the
    # receipt commit together, including failure of a later component.
    lock_artifact_identities(db, writable=[("tool" if c.kind == "mcp" else c.kind, c.name)
                                         for c in payload.package.components if c.kind != "connector"])
    plan = review(db, payload, actor, builtin=builtin)
    if not plan["installable"]:
        raise ValueError("Package is not ready: " + "; ".join(plan["blockers"]))
    old = installed(db, payload.package, actor)
    if old:
        return receipt(old, db)
    ids = []
    for component in payload.package.components:
        if component.kind == "connector":
            continue
        pending = component.name in plan["pending_components"]
        if pending:
            kind = component.kind
            version = ArtifactVersionCreate(created_by=actor.subject,
                definition={"format_version": "icheck.operations-pending/v1", "component": component.model_dump(mode="json")},
                implementation={"runtime": "not_active"}, tests=[])
        else:
            kind, version = compile_component(db, component, payload.mcp_servers)
        version.created_by = actor.subject
        artifact = create_artifact(db, ArtifactCreate(name=component.name, kind=kind,
            description=component.spec.get("description", payload.package.description), owner=actor.subject,
            labels={"operations_package": payload.package.name, "operations_digest": payload.package.digest_sha256},
            initial_version=version), commit=False)
        version = artifact.versions[0]
        if not pending:
            version = validate_artifact_version(db, version, actor.subject, commit=False)
        ids.append(version.id)
    row = OperationsPackageInstallation(id=new_id(), tenant_id=actor.tenant_id, region_id=actor.region_id,
        name=payload.package.name, version=payload.package.version, digest_sha256=payload.package.digest_sha256,
        package=payload.package.model_dump(mode="json"),
        bindings={"connections": {key: str(value) for key, value in payload.connections.items()},
                  "mcp_servers": payload.mcp_servers, "builtin": builtin,
                  "signature": payload.signature.model_dump(mode="json") if payload.signature else None},
        artifact_version_ids=ids, installed_by=actor.subject)
    db.add(row)
    record_audit_event(db, event_type="operations_package.imported", actor_type=actor.principal_type,
        actor_id=actor.subject, entity_type=row.__tablename__, entity_id=row.id,
        details={"digest_sha256": row.digest_sha256, "artifact_count": len(ids), "built_in": builtin, "activated": False})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ValueError("Package changed concurrently; refresh before retrying") from None
    return receipt(row, db)


def receipt(row, db=None):
    states = []
    if db is not None:
        for identifier in row.artifact_version_ids:
            version = db.get(ArtifactVersion, identifier)
            if version:
                states.append({"id": version.id, "artifact_id": version.artifact_id, "name": version.artifact.name,
                    "kind": "mcp" if version.definition.get("format_version") == EXTENSION_FORMAT else version.artifact.kind.value,
                    "status": version.status.value, "pending": version.definition.get("format_version") == "icheck.operations-pending/v1"})
    return {"id": row.id, "name": row.name, "version": row.version, "digest_sha256": row.digest_sha256,
            "artifact_version_ids": row.artifact_version_ids, "bindings": row.bindings,
            "components": states, "pending": any(item["pending"] for item in states),
            "installed_at": row.installed_at, "status": "imported", "activated": False}


def listing(db, actor):
    guard(db, actor)
    return [receipt(row, db) for row in db.scalars(select(OperationsPackageInstallation)
        .where(namespace_clause(OperationsPackageInstallation, actor))
        .order_by(OperationsPackageInstallation.installed_at.desc()).limit(100))]


def prepare(db, identifier, actor):
    from ..operations_package_schemas import OperationsReview
    from .artifact_lifecycle import lock_artifact_version
    guard(db, actor)
    row = db.scalar(select(OperationsPackageInstallation).where(OperationsPackageInstallation.id == identifier,
                    namespace_clause(OperationsPackageInstallation, actor)))
    if row is None:
        raise LookupError("Package installation is unavailable")
    payload = OperationsReview(package=row.package, connections=row.bindings["connections"],
                               mcp_servers=row.bindings["mcp_servers"], signature=row.bindings.get("signature"))
    if not row.bindings.get("builtin", False):
        retain_signature_authority(db, payload.signature, actor)
    plan = review(db, payload, actor, builtin=row.bindings.get("builtin", False))
    if not plan["installable"] or plan["pending_components"]:
        raise ValueError("Install the required MCP servers, then prepare this package again")
    components = {component.name: component for component in payload.package.components}
    for identifier in row.artifact_version_ids:
        version = lock_artifact_version(db, identifier)
        if version.definition.get("format_version") != "icheck.operations-pending/v1":
            continue
        component = components[version.artifact.name]
        if version.status != ArtifactVersionStatus.DRAFT or version.definition["component"] != component.model_dump(mode="json"):
            raise ValueError("Pending version was changed; do not overwrite user edits")
        _, compiled = compile_component(db, component, payload.mcp_servers)
        version.definition, version.implementation, version.tests = compiled.definition, compiled.implementation, compiled.tests
        # Validation reacquires the version with populate_existing. Persist the
        # compiled draft inside this transaction before that refresh.
        db.flush()
        validate_artifact_version(db, version, actor.subject, commit=False)
    record_audit_event(db, event_type="operations_package.prepared", actor_type=actor.principal_type, actor_id=actor.subject,
                      entity_type=row.__tablename__, entity_id=row.id, details={"activated": False})
    db.commit()
    return receipt(row, db)


def choices(db, actor):
    guard(db, actor)
    versions = db.scalars(select(ArtifactVersion).where(namespace_clause(ArtifactVersion, actor),
        ArtifactVersion.status.in_([ArtifactVersionStatus.VALIDATED, ArtifactVersionStatus.PUBLISHED]))
        .order_by(ArtifactVersion.created_at.desc()).limit(200)).all()
    return {"versions": [{"id": v.id, "name": v.artifact.name, "kind": v.artifact.kind.value, "version": v.version}
                         for v in versions if v.artifact.kind.value in {"workflow", "skill", "tool", "collector"}],
            "connections": [{"id": c.id, "name": c.name, "provider": c.provider} for c in db.scalars(
                select(MonitoringIntegrationConnection).where(namespace_clause(MonitoringIntegrationConnection, actor)).limit(200))],
            "mcp_servers": [{"name": c.name} for c in db.scalars(select(MCPServer)
                .where(namespace_clause(MCPServer, actor)).limit(200))]}
