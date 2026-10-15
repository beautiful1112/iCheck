from __future__ import annotations

import hashlib

from sqlalchemy import func, or_, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from ..capability_pack_schemas import (
    CapabilityPackInstallationRead,
    CapabilityPackUninstallCreate,
    CapabilityPackUninstallPreviewRead,
)
from ..database import require_locking_transaction, set_session_namespace
from ..models import (
    AgentExecution,
    AgentExecutionStatus,
    ArtifactVersion,
    ArtifactVersionStatus,
    CapabilityPackInstallation,
    CapabilityPackInstalledArtifact,
    CollectorCanaryRollout,
    CollectorDeployment,
    Investigation,
    MCPToolActivation,
    ServiceIndicatorArtifactBinding,
    SituationIntegrationBinding,
    WorkflowScheduleActivation,
    WorkflowTriggerActivation,
    utcnow,
)
from .audit import record_audit_event
from .capability_pack_revocations import quarantine_pack_versions
from .capability_packs import get_capability_pack_installation
from .capability_transparency import append_capability_transparency_record
from .trust_authority import lock_publisher_resource
from .trust_namespace import selected_trust_namespace
from .artifact_lifecycle import artifact_identities_for_versions, lock_artifact_identities


def _introduced_version_ids(
    db: Session,
    installation_id: str,
) -> list[str]:
    return list(
        dict.fromkeys(
            db.scalars(
                select(
                    CapabilityPackInstalledArtifact.artifact_version_id
                ).where(
                    CapabilityPackInstalledArtifact.installation_id
                    == installation_id,
                    CapabilityPackInstalledArtifact.install_action.in_(
                        ["installed", "upgraded"]
                    ),
                )
            ).all()
        )
    )


def _active_dependent_installation_ids(
    db: Session,
    *,
    installation_id: str,
    version_ids: list[str],
) -> list[str]:
    if not version_ids:
        return []
    dependent_ids = set(
        db.scalars(
            select(CapabilityPackInstalledArtifact.installation_id)
            .join(
                CapabilityPackInstallation,
                CapabilityPackInstallation.id
                == CapabilityPackInstalledArtifact.installation_id,
            )
            .where(
                CapabilityPackInstalledArtifact.artifact_version_id.in_(
                    version_ids
                ),
                CapabilityPackInstalledArtifact.installation_id
                != installation_id,
                CapabilityPackInstallation.lifecycle_status == "installed",
            )
        ).all()
    )
    active_installations = db.scalars(
        select(CapabilityPackInstallation).where(
            CapabilityPackInstallation.id != installation_id,
            CapabilityPackInstallation.lifecycle_status == "installed",
        )
    ).all()
    version_id_set = set(version_ids)
    for installation in active_installations:
        dependency_version_ids = {
            item.get("artifact_version_id")
            for item in (installation.dependency_snapshot or [])
            if isinstance(item, dict)
        }
        if dependency_version_ids & version_id_set:
            dependent_ids.add(installation.id)
    return sorted(dependent_ids)


def _count(db: Session, model: type, *criteria: object) -> int:
    return int(
        db.scalar(select(func.count()).select_from(model).where(*criteria)) or 0
    )


def _impact_summary(
    db: Session,
    version_ids: list[str],
) -> dict[str, int]:
    summary = {
        "installed_packs": 1,
        "artifact_versions": 0,
        "collector_deployments": 0,
        "collector_canaries": 0,
        "mcp_activations": 0,
        "workflow_triggers": 0,
        "workflow_schedules": 0,
        "investigations": 0,
        "agent_executions": 0,
        "indicator_bindings": 0,
        "integration_bindings": 0,
    }
    if not version_ids:
        return summary
    summary["artifact_versions"] = _count(
        db,
        ArtifactVersion,
        ArtifactVersion.id.in_(version_ids),
        ArtifactVersion.status.in_(
            [
                ArtifactVersionStatus.VALIDATED,
                ArtifactVersionStatus.PUBLISHED,
            ]
        ),
    )
    summary["collector_deployments"] = _count(
        db,
        CollectorDeployment,
        CollectorDeployment.artifact_version_id.in_(version_ids),
        CollectorDeployment.enabled.is_(True),
    )
    summary["collector_canaries"] = _count(
        db,
        CollectorCanaryRollout,
        or_(
            CollectorCanaryRollout.candidate_version_id.in_(version_ids),
            CollectorCanaryRollout.baseline_version_id.in_(version_ids),
        ),
        CollectorCanaryRollout.status.in_(["running", "passed"]),
    )
    summary["mcp_activations"] = _count(
        db,
        MCPToolActivation,
        MCPToolActivation.artifact_version_id.in_(version_ids),
        MCPToolActivation.status == "active",
    )
    summary["workflow_triggers"] = _count(
        db,
        WorkflowTriggerActivation,
        WorkflowTriggerActivation.artifact_version_id.in_(version_ids),
        WorkflowTriggerActivation.enabled.is_(True),
    )
    summary["workflow_schedules"] = _count(
        db,
        WorkflowScheduleActivation,
        or_(
            WorkflowScheduleActivation.artifact_version_id.in_(version_ids),
            WorkflowScheduleActivation.report_artifact_version_id.in_(
                version_ids
            ),
        ),
        WorkflowScheduleActivation.enabled.is_(True),
    )
    active_investigations = list(
        db.scalars(
            select(Investigation.id).where(
                or_(
                    Investigation.skill_artifact_version_id.in_(version_ids),
                    Investigation.workflow_artifact_version_id.in_(version_ids),
                ),
                Investigation.status.in_(
                    ["pending", "running", "waiting_approval"]
                ),
            )
        ).all()
    )
    summary["investigations"] = len(active_investigations)
    if active_investigations:
        summary["agent_executions"] = _count(
            db,
            AgentExecution,
            AgentExecution.investigation_id.in_(active_investigations),
            AgentExecution.status.in_(
                [
                    AgentExecutionStatus.QUEUED,
                    AgentExecutionStatus.RUNNING,
                    AgentExecutionStatus.WAITING_APPROVAL,
                ]
            ),
        )
    summary["indicator_bindings"] = _count(
        db,
        ServiceIndicatorArtifactBinding,
        ServiceIndicatorArtifactBinding.artifact_version_id.in_(version_ids),
        ServiceIndicatorArtifactBinding.enabled.is_(True),
    )
    summary["integration_bindings"] = _count(
        db,
        SituationIntegrationBinding,
        SituationIntegrationBinding.artifact_version_id.in_(version_ids),
        SituationIntegrationBinding.enabled.is_(True),
    )
    return summary


def preview_capability_pack_uninstall(
    db: Session,
    installation_id: str,
) -> CapabilityPackUninstallPreviewRead:
    installation = db.get(CapabilityPackInstallation, installation_id)
    if installation is None:
        raise LookupError("Capability pack installation not found")
    version_ids = _introduced_version_ids(db, installation.id)
    already_uninstalled = installation.lifecycle_status == "uninstalled"
    successor = db.scalar(
        select(CapabilityPackInstallation)
        .where(
            CapabilityPackInstallation.predecessor_installation_id
            == installation.id,
            CapabilityPackInstallation.lifecycle_status == "installed",
        )
        .order_by(
            CapabilityPackInstallation.installed_at.desc(),
            CapabilityPackInstallation.id.desc(),
        )
        .limit(1)
    )
    dependent_ids = (
        []
        if already_uninstalled
        else _active_dependent_installation_ids(
            db,
            installation_id=installation.id,
            version_ids=version_ids,
        )
    )
    blockers: list[str] = []
    if already_uninstalled:
        blockers.append("pack_already_uninstalled")
    if successor is not None:
        blockers.append("pack_has_active_successor")
    if dependent_ids:
        blockers.append("pack_has_active_dependents")
    return CapabilityPackUninstallPreviewRead(
        installation_id=installation.id,
        pack_name=installation.pack_name,
        pack_version=installation.pack_version,
        pack_digest_sha256=installation.pack_digest_sha256,
        lifecycle_status=installation.lifecycle_status,
        uninstallable=not blockers,
        already_uninstalled=already_uninstalled,
        blockers=blockers,
        active_successor_installation_id=(
            successor.id if successor is not None else None
        ),
        dependent_pack_installation_ids=dependent_ids,
        introduced_artifact_version_ids=version_ids,
        impact_summary=(
            {}
            if already_uninstalled
            else _impact_summary(db, version_ids)
        ),
    )


def uninstall_capability_pack(
    db: Session,
    installation_id: str,
    payload: CapabilityPackUninstallCreate,
    *,
    actor: str,
) -> CapabilityPackInstallationRead:
    require_locking_transaction(db, purpose="Capability pack uninstalls")
    set_session_namespace(db, *selected_trust_namespace(db))
    # Read immutable identity without retaining a row lock ahead of advisory
    # locks. Installation and upgrades acquire lineage, then digest, then rows.
    identity = db.execute(select(
        CapabilityPackInstallation.pack_name,
        CapabilityPackInstallation.pack_digest_sha256,
    ).where(CapabilityPackInstallation.id == installation_id)).one_or_none()
    if identity is None:
        raise LookupError("Capability pack installation not found")
    lock_publisher_resource(db, "pack-lineage", identity.pack_name)
    lock_publisher_resource(db, "pack-digest", identity.pack_digest_sha256)
    installation = db.scalar(
        select(CapabilityPackInstallation)
        .where(CapabilityPackInstallation.id == installation_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if installation is None:
        raise LookupError("Capability pack installation not found")
    if (
        installation.pack_digest_sha256
        != payload.expected_pack_digest_sha256
    ):
        raise ValueError("Capability pack digest changed before uninstall")
    if installation.lifecycle_status == "uninstalled":
        result = CapabilityPackInstallationRead.model_validate(
            get_capability_pack_installation(db, installation.id)
        )
        db.commit()
        return result
    lock_artifact_identities(db, writable=artifact_identities_for_versions(
        db, _introduced_version_ids(db, installation.id)))
    preview = preview_capability_pack_uninstall(db, installation.id)
    if not preview.uninstallable:
        raise ValueError(
            "Capability pack is not uninstallable: "
            + ", ".join(preview.blockers)
        )
    try:
        summary = quarantine_pack_versions(
            db,
            [installation.pack_digest_sha256],
            actor=actor,
            reason_text="Capability pack uninstalled",
            reason_code="capability_pack_uninstalled",
            execution_event_type="execution.capability_pack_uninstalled",
            deprecate_validated=True,
        )
        installation.lifecycle_status = "uninstalled"
        installation.uninstall_reason = payload.reason
        installation.uninstalled_by = actor
        installation.uninstalled_at = utcnow()
        installation.uninstall_summary = summary
        append_capability_transparency_record(
            db,
            event_type="capability.pack.uninstalled",
            entity_type="capability_pack_installation",
            entity_id=installation.id,
            subject_digest_sha256=installation.pack_digest_sha256,
            details={
                "pack_name": installation.pack_name,
                "pack_version": installation.pack_version,
                "deprecated_versions": summary.get(
                    "artifact_versions_deprecated",
                    0,
                ),
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        record_audit_event(
            db,
            event_type="capability.pack.uninstalled",
            actor_type="user",
            actor_id=actor,
            entity_type="capability_pack_installation",
            entity_id=installation.id,
            details={
                "pack_name": installation.pack_name,
                "pack_version": installation.pack_version,
                "pack_digest_sha256": installation.pack_digest_sha256,
                "predecessor_installation_id": (
                    installation.predecessor_installation_id
                ),
                "impact_summary": summary,
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        db.flush()
    except Exception:
        db.rollback()
        raise
    # An exception on the response path must not mask a committed tombstone.
    try:
        db.commit()
    except DBAPIError:
        db.rollback()
        raise
    return CapabilityPackInstallationRead.model_validate(
        get_capability_pack_installation(db, installation.id)
    )
