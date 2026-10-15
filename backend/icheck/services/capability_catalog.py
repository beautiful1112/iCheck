from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from ..capability_catalog_schemas import (
    CapabilityCatalogCounts,
    CapabilityCatalogItemRead,
    CapabilityCatalogRead,
    CapabilityProvenanceRead,
)
from ..models import (
    AgentToolRegistration,
    Artifact,
    ArtifactKind,
    ArtifactSignatureVerification,
    ArtifactVersion,
    ArtifactVersionStatus,
    CapabilityPackInstallation,
    CapabilityPackInstalledArtifact,
    CollectorDeployment,
    CredentialProfile,
    MCPServer,
    MCPToolActivation,
    WorkflowScheduleActivation,
    WorkflowTriggerActivation,
)
from ..config import get_settings
from ..mcp_schemas import MCP_PROTOCOL_VERSION
from ..studio_schemas import GeneratedToolSpec
from .tool_skills import (
    assert_skill_runtime_compatible,
    validate_tool_artifact_contract,
)
from .mcp_gateway import validate_mcp_endpoint
from .topology_views import published_topology_spec
from .service_indicator_visualizations import (
    published_visualization_spec,
    validate_visualization_selectors,
    visualization_indicator_catalog,
)
from .service_health_reports import (
    published_service_report_spec,
    validate_service_report_selectors,
)
from .workflow_runtime import assert_workflow_runtime_compatible


EXECUTABLE_KINDS = {
    ArtifactKind.COLLECTOR,
    ArtifactKind.TOOL,
    ArtifactKind.SKILL,
    ArtifactKind.WORKFLOW,
    ArtifactKind.TOPOLOGY,
    ArtifactKind.VISUALIZATION,
}
SENSITIVE_TAG_FRAGMENTS = ("secret", "token", "password", "credential", "key")
CATALOG_SCAN_LIMIT = 10_000


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _tags(labels: dict[str, Any] | None) -> list[str]:
    """Expose only the explicit, bounded tag allowlist from arbitrary labels."""

    if not isinstance(labels, dict):
        return []
    values = labels.get("tags", [])
    if not isinstance(values, list):
        return []
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        normalized = value.strip()
        lowered = normalized.casefold()
        if (
            not normalized
            or len(normalized) > 64
            or any(fragment in lowered for fragment in SENSITIVE_TAG_FRAGMENTS)
        ):
            continue
        result.append(normalized)
        if len(result) == 20:
            break
    return list(dict.fromkeys(result))


def _blocker_for_exception(exc: Exception) -> str:
    message = str(exc).casefold()
    if "drift" in message or "unavailable tool" in message:
        return "dependency_drift"
    return "contract_invalid"


def _collector_contract(
    version: ArtifactVersion,
) -> tuple[str, list[str], int, dict[str, Any]]:
    definition = version.collector_definition
    runtime = version.implementation.get("runtime")
    adapter = version.implementation.get("adapter")
    blockers: list[str] = []
    if definition is None:
        blockers.append("contract_invalid")
        return str(runtime or "unknown"), blockers, 0, {}
    if (
        runtime not in {"builtin", "python_sandbox_v1"}
        or adapter != definition.adapter_type
        or not definition.output_kinds
    ):
        blockers.append("contract_invalid")
    return (
        str(runtime or "unknown"),
        blockers,
        0,
        {
            "adapter_type": definition.adapter_type,
            "mode": definition.mode.value,
            "output_kinds": sorted(definition.output_kinds),
        },
    )


def _mcp_tool_blockers(
    version: ArtifactVersion,
    activation: MCPToolActivation | None,
    registrations: dict[str, AgentToolRegistration],
    servers: dict[str, MCPServer],
    credential_profiles: dict[str, CredentialProfile],
) -> tuple[list[str], list[str], int, dict[str, Any]]:
    blockers: list[str] = []
    permissions: list[str] = []
    summary: dict[str, Any] = {}
    dependency_count = 1
    try:
        report = validate_tool_artifact_contract(
            version.definition,
            version.implementation,
            version.tests,
        )
        spec = GeneratedToolSpec.model_validate(version.definition["spec"])
        permissions = sorted(spec.required_permissions)
        summary = {
            "tool_name": spec.tool_name,
            "transport": spec.transport,
            "risk_level": spec.risk_level,
            "read_only": spec.read_only,
            "requires_approval": spec.requires_approval,
            "fixture_count": report["fixture_count"],
            "reviewed_preapproval_contract": bool(
                spec.change_contract
                and spec.change_contract.risk_class == "low"
                and any(kind == "device_id" for kind in
                    spec.change_contract.authorization_target_paths.values())
                and spec.change_contract.semantic_expectations
            ),
        }
    except (KeyError, TypeError, ValueError) as exc:
        blockers.append(_blocker_for_exception(exc))
        return blockers, permissions, dependency_count, summary
    if activation is None:
        blockers.append("activation_required")
        return blockers, permissions, dependency_count, summary
    tool = registrations.get(activation.tool_registration_id)
    server = servers.get(activation.server_id)
    if tool is None:
        blockers.append("tool_registration_missing")
    elif not tool.enabled:
        blockers.append("tool_registration_disabled")
    if server is None:
        blockers.append("mcp_server_missing")
    elif not server.enabled:
        blockers.append("mcp_server_disabled")
    else:
        if server.protocol_version != MCP_PROTOCOL_VERSION:
            blockers.append("mcp_protocol_unsupported")
        try:
            validate_mcp_endpoint(
                server.endpoint_url,
                get_settings().mcp_allowed_host_list,
            )
        except ValueError:
            blockers.append("mcp_endpoint_invalid")
        if server.last_health_status == "unhealthy":
            blockers.append("mcp_server_unhealthy")
        if server.credential_profile_ref:
            profile = credential_profiles.get(server.credential_profile_ref)
            if profile is None:
                blockers.append("credential_profile_missing")
            elif not profile.enabled:
                blockers.append("credential_profile_disabled")
            elif not {
                "mcp",
                f"mcp:{server.name}",
            }.intersection(profile.allowed_adapters):
                blockers.append("credential_scope_mismatch")
    if tool is not None and server is not None:
        expected_handler = f"{server.name}/{activation.mcp_tool_name}"
        if (
            activation.tool_name != tool.name
            or tool.transport != "mcp"
            or tool.handler != expected_handler
            or activation.input_schema_sha256
            != _canonical_hash(tool.input_schema)
            or activation.output_schema_sha256
            != _canonical_hash(tool.output_schema)
        ):
            blockers.append("dependency_drift")
    return blockers, permissions, dependency_count, summary


def _base_item(
    version: ArtifactVersion,
    signature: ArtifactSignatureVerification | None,
    pack_installation: CapabilityPackInstallation | None,
    *,
    runtime: str,
    readiness: str,
    activation_state: str,
    activation_count: int,
    dependency_count: int,
    permissions: list[str],
    blockers: list[str],
    summary: dict[str, Any],
) -> CapabilityCatalogItemRead:
    return CapabilityCatalogItemRead(
        artifact_id=version.artifact_id,
        artifact_version_id=version.id,
        name=version.artifact.name,
        kind=version.artifact.kind,
        description=version.artifact.description,
        owner=version.artifact.owner,
        tags=_tags(version.artifact.labels),
        version=version.version,
        content_hash=version.content_hash or "",
        published_at=version.published_at,
        runtime=runtime,
        readiness=readiness,
        activation_state=activation_state,
        activation_count=activation_count,
        dependency_count=dependency_count,
        required_permissions=sorted(set(permissions)),
        blockers=list(dict.fromkeys(blockers)),
        provenance=(
            CapabilityProvenanceRead(
                source="artifact_bundle",
                signed=True,
                algorithm=signature.algorithm,
                key_fingerprint_sha256=signature.key_fingerprint_sha256,
                verified_at=signature.verified_at,
            )
            if signature is not None
            else CapabilityProvenanceRead(
                source=(
                    "capability_pack"
                    if pack_installation is not None
                    else "local"
                ),
                signed=pack_installation is not None,
                algorithm="ed25519" if pack_installation is not None else None,
                key_fingerprint_sha256=(
                    pack_installation.key_fingerprint_sha256
                    if pack_installation is not None
                    else None
                ),
                verified_at=(
                    pack_installation.installed_at
                    if pack_installation is not None
                    else None
                ),
                pack_name=(
                    pack_installation.pack_name
                    if pack_installation is not None
                    else None
                ),
                pack_version=(
                    pack_installation.pack_version
                    if pack_installation is not None
                    else None
                ),
                pack_digest_sha256=(
                    pack_installation.pack_digest_sha256
                    if pack_installation is not None
                    else None
                ),
            )
        ),
        summary=summary,
    )


def capability_catalog(
    db: Session,
    *,
    query: str | None = None,
    kind: ArtifactKind | None = None,
    readiness: str | None = None,
    preapproval_tool: bool = False,
    offset: int = 0,
    limit: int = 100,
) -> CapabilityCatalogRead:
    statement = (
        select(ArtifactVersion)
        .join(ArtifactVersion.artifact)
        .where(ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED)
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
        .order_by(Artifact.kind, Artifact.name, ArtifactVersion.version.desc())
    )
    normalized_query = (query or "").strip().casefold()
    if normalized_query:
        statement = statement.where(
            or_(
                func.lower(Artifact.name).contains(
                    normalized_query,
                    autoescape=True,
                ),
                func.lower(Artifact.description).contains(
                    normalized_query,
                    autoescape=True,
                ),
                func.lower(Artifact.owner).contains(
                    normalized_query,
                    autoescape=True,
                ),
            )
        )
    if kind is not None:
        statement = statement.where(Artifact.kind == kind)
    if preapproval_tool:
        statement = statement.where(Artifact.kind == ArtifactKind.TOOL)
    scanned_versions = list(
        db.scalars(statement.limit(CATALOG_SCAN_LIMIT + 1)).unique().all()
    )
    scan_truncated = len(scanned_versions) > CATALOG_SCAN_LIMIT
    versions = scanned_versions[:CATALOG_SCAN_LIMIT]
    version_ids = [version.id for version in versions]

    signatures = {
        item.artifact_version_id: item
        for item in db.scalars(
            select(ArtifactSignatureVerification).where(
                ArtifactSignatureVerification.artifact_version_id.in_(version_ids)
            )
        ).all()
    } if version_ids else {}
    pack_installations: dict[str, CapabilityPackInstallation] = {}
    if version_ids:
        pack_rows = db.execute(
            select(
                CapabilityPackInstalledArtifact.artifact_version_id,
                CapabilityPackInstallation,
            )
            .join(
                CapabilityPackInstallation,
                CapabilityPackInstallation.id
                == CapabilityPackInstalledArtifact.installation_id,
            )
            .where(
                CapabilityPackInstalledArtifact.artifact_version_id.in_(
                    version_ids
                )
            )
            .order_by(CapabilityPackInstallation.installed_at.desc())
        ).all()
        for artifact_version_id, installation in pack_rows:
            pack_installations.setdefault(artifact_version_id, installation)
    deployments: dict[str, list[CollectorDeployment]] = defaultdict(list)
    activations: dict[str, MCPToolActivation] = {}
    alert_activations: dict[str, list[WorkflowTriggerActivation]] = defaultdict(list)
    schedule_activations: dict[str, list[WorkflowScheduleActivation]] = defaultdict(list)
    if version_ids:
        for item in db.scalars(
            select(CollectorDeployment).where(
                CollectorDeployment.artifact_version_id.in_(version_ids)
            )
        ).all():
            deployments[item.artifact_version_id].append(item)
        for item in db.scalars(
            select(MCPToolActivation).where(
                MCPToolActivation.artifact_version_id.in_(version_ids),
                MCPToolActivation.status == "active",
            )
        ).all():
            activations[item.artifact_version_id] = item
        for item in db.scalars(
            select(WorkflowTriggerActivation).where(
                WorkflowTriggerActivation.artifact_version_id.in_(version_ids)
            )
        ).all():
            alert_activations[item.artifact_version_id].append(item)
        for item in db.scalars(
            select(WorkflowScheduleActivation).where(
                WorkflowScheduleActivation.artifact_version_id.in_(version_ids)
            )
        ).all():
            schedule_activations[item.artifact_version_id].append(item)
    registrations = {
        item.id: item for item in db.scalars(select(AgentToolRegistration)).all()
    }
    servers = {item.id: item for item in db.scalars(select(MCPServer)).all()}
    credential_profiles: dict[str, CredentialProfile] = {}
    for item in db.scalars(select(CredentialProfile)).all():
        credential_profiles[item.id] = item
        credential_profiles[item.name] = item

    items: list[CapabilityCatalogItemRead] = []
    for version in versions:
        blockers: list[str] = []
        permissions: list[str] = []
        dependency_count = 0
        activation_count = 0
        activation_state = "not_required"
        summary: dict[str, Any] = {}
        runtime = str(version.implementation.get("runtime") or "declarative")

        if not version.content_hash:
            blockers.append("content_hash_missing")

        if version.artifact.kind == ArtifactKind.COLLECTOR:
            runtime, contract_blockers, dependency_count, summary = (
                _collector_contract(version)
            )
            blockers.extend(contract_blockers)
            records = deployments.get(version.id, [])
            enabled = [item for item in records if item.enabled]
            activation_count = len(enabled)
            activation_state = "active" if enabled else "inactive"
            if not enabled:
                blockers.append("activation_required")
            summary.update(
                {
                    "deployment_count": len(records),
                    "enabled_deployment_count": len(enabled),
                }
            )
        elif version.artifact.kind == ArtifactKind.TOOL:
            activation = activations.get(version.id)
            activation_count = int(activation is not None)
            activation_state = "active" if activation else "inactive"
            tool_blockers, permissions, dependency_count, summary = (
                _mcp_tool_blockers(
                    version,
                    activation,
                    registrations,
                    servers,
                    credential_profiles,
                )
            )
            blockers.extend(tool_blockers)
        elif version.artifact.kind == ArtifactKind.SKILL:
            try:
                spec, report = assert_skill_runtime_compatible(db, version)
                permissions = sorted(report.get("required_permissions", []))
                dependency_count = len(spec.allowed_tools)
                summary = {
                    "skill_name": spec.skill_name,
                    "tool_count": len(spec.allowed_tools),
                    "max_iterations": spec.max_iterations,
                    "max_tool_calls": spec.max_tool_calls,
                    "read_only": True,
                }
            except (KeyError, TypeError, ValueError) as exc:
                blockers.append(_blocker_for_exception(exc))
                stored = version.validation_report or {}
                dependencies = stored.get("tool_dependencies", [])
                dependency_count = len(dependencies) if isinstance(dependencies, list) else 0
                permissions = list(stored.get("required_permissions", []))
        elif version.artifact.kind == ArtifactKind.WORKFLOW:
            trigger_type = "unknown"
            try:
                spec, report = assert_workflow_runtime_compatible(db, version)
                trigger_type = spec.trigger.trigger_type
                permissions = sorted(report.get("required_permissions", []))
                dependencies = version.definition.get("tool_dependencies", [])
                dependency_count = len(dependencies) if isinstance(dependencies, list) else 0
                summary = {
                    "trigger_type": trigger_type,
                    "node_count": len(spec.nodes),
                    "approval_required": any(
                        node.node_type == "approval" for node in spec.nodes
                    ),
                    "max_runtime_seconds": spec.max_runtime_seconds,
                    "max_total_tool_calls": spec.max_total_tool_calls,
                }
            except (KeyError, TypeError, ValueError) as exc:
                blockers.append(_blocker_for_exception(exc))
                report = version.validation_report or {}
                permissions = list(report.get("required_permissions", []))
                dependencies = version.definition.get("tool_dependencies", [])
                dependency_count = len(dependencies) if isinstance(dependencies, list) else 0
                raw_spec = version.definition.get("spec", {})
                if isinstance(raw_spec, dict):
                    raw_trigger = raw_spec.get("trigger", {})
                    if isinstance(raw_trigger, dict):
                        trigger_type = str(raw_trigger.get("trigger_type", "unknown"))
            if trigger_type == "alert":
                records = alert_activations.get(version.id, [])
                enabled = [item for item in records if item.enabled]
                activation_count = len(enabled)
                activation_state = "active" if enabled else "inactive"
            elif trigger_type == "schedule":
                records = schedule_activations.get(version.id, [])
                enabled = [item for item in records if item.enabled]
                activation_count = len(enabled)
                activation_state = "active" if enabled else "inactive"
            if activation_state == "inactive":
                blockers.append("activation_required")
        elif version.artifact.kind == ArtifactKind.TOPOLOGY:
            try:
                spec = published_topology_spec(
                    version.definition,
                    version.implementation,
                    version.tests,
                )
                summary = {
                    "layout": spec.layout,
                    "group_by": spec.group_by,
                    "node_types": list(spec.node_types),
                    "edge_types": list(spec.edge_types),
                    "max_nodes": spec.max_nodes,
                    "max_edges": spec.max_edges,
                }
            except (KeyError, TypeError, ValueError) as exc:
                blockers.append(_blocker_for_exception(exc))
        elif version.artifact.kind == ArtifactKind.VISUALIZATION:
            try:
                spec = published_visualization_spec(
                    version.definition,
                    version.implementation,
                    version.tests,
                )
                try:
                    validate_visualization_selectors(
                        spec,
                        visualization_indicator_catalog(db),
                    )
                except ValueError:
                    blockers.append("dependency_drift")
                permissions = ["services.read"]
                dependency_count = len(spec.panels)
                summary = {
                    "layout_columns": spec.layout_columns,
                    "refresh_seconds": spec.refresh_seconds,
                    "lookback_minutes": spec.lookback_minutes,
                    "panel_count": len(spec.panels),
                    "data_source": "service_indicator_observations",
                }
            except (KeyError, TypeError, ValueError) as exc:
                blockers.append(_blocker_for_exception(exc))
        elif version.artifact.kind == ArtifactKind.REPORT:
            if (
                version.definition.get("format_version")
                in {"icheck.service-health-report/v1", "icheck.service-health-report/v2"}
            ):
                try:
                    spec = published_service_report_spec(
                        version.definition,
                        version.implementation,
                        version.tests,
                    )
                    try:
                        validate_service_report_selectors(
                            spec,
                            visualization_indicator_catalog(db),
                        )
                    except ValueError:
                        blockers.append("dependency_drift")
                    permissions = ["services.read"]
                    retained_count = len(getattr(spec, "retained_proofs", []))
                    if retained_count:
                        permissions.append("alerts.read")
                        if any(item.reference_kind != "situation_closure_receipt" for item in spec.retained_proofs):
                            permissions.append("capabilities.read")
                    dependency_count = len(spec.indicators) + retained_count
                    summary = {
                        "report_type": "retained_control_plane_proof" if retained_count else "service_health_snapshot",
                        "report_title": spec.report_title,
                        "lookback_minutes": spec.lookback_minutes,
                        "section_count": dependency_count,
                        "data_source": "service_indicators_and_retained_domain_proofs" if retained_count else "service_indicator_observations",
                    }
                    if retained_count:
                        summary["retained_reference_count"] = retained_count
                except (KeyError, TypeError, ValueError) as exc:
                    blockers.append(_blocker_for_exception(exc))

        if (
            version.artifact.kind == ArtifactKind.REPORT
            and version.definition.get("format_version")
            in {"icheck.service-health-report/v1", "icheck.service-health-report/v2"}
        ):
            item_readiness = "blocked" if blockers else "ready"
        elif version.artifact.kind not in EXECUTABLE_KINDS:
            item_readiness = "declarative" if not blockers else "blocked"
        else:
            item_readiness = "blocked" if blockers else "ready"
        item = _base_item(
            version,
            signatures.get(version.id),
            pack_installations.get(version.id),
            runtime=runtime,
            readiness=item_readiness,
            activation_state=activation_state,
            activation_count=activation_count,
            dependency_count=dependency_count,
            permissions=permissions,
            blockers=blockers,
            summary=summary,
        )
        items.append(item)

    if readiness is not None:
        items = [item for item in items if item.readiness == readiness]
    if preapproval_tool:
        items = [item for item in items if item.readiness == "ready"
            and item.summary.get("reviewed_preapproval_contract") is True]

    counts = Counter(item.readiness for item in items)
    activation_counts = Counter(item.activation_state for item in items)
    total = len(items)
    page = items[offset : offset + limit]
    return CapabilityCatalogRead(
        items=page,
        total=total,
        offset=offset,
        limit=limit,
        truncated=offset + len(page) < total,
        scan_truncated=scan_truncated,
        counts=CapabilityCatalogCounts(
            ready=counts["ready"],
            blocked=counts["blocked"],
            declarative=counts["declarative"],
            active=activation_counts["active"],
            inactive=activation_counts["inactive"],
            not_required=activation_counts["not_required"],
        ),
    )
