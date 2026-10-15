from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..capability_pack_revocation_schemas import (
    SIGNED_REVOCATION_FEED_FORMAT,
    CapabilityPackRevocationFeedRead,
    CapabilityPackRevocationIngestCreate,
)
from ..database import require_locking_transaction, set_session_namespace
from ..models import (
    ArtifactTrustKey,
    ArtifactVersion,
    ArtifactVersionStatus,
    AgentExecution,
    AgentExecutionStatus,
    CapabilityPackInstallation,
    CapabilityPackInstalledArtifact,
    CapabilityPackRevocation,
    CapabilityPackRevocationFeed,
    CollectorCanaryRollout,
    CollectorDeployment,
    CollectorRun,
    CollectorRunStatus,
    MCPToolActivation,
    Investigation,
    ServiceIndicatorArtifactBinding,
    SituationIntegrationBinding,
    WorkflowScheduleActivation,
    WorkflowScheduleEvent,
    WorkflowTriggerActivation,
    WorkflowTriggerEvent,
    utcnow,
)
from .agent_execution import append_execution_event
from .artifact_portability import verify_trusted_digest_signature
from .audit import record_audit_event
from .capability_transparency import append_capability_transparency_record
from .trust_namespace import assert_selected_trust_namespace, selected_trust_namespace
from .trust_authority import lock_publisher_resource, lock_trust_keys
from .artifact_lifecycle import artifact_identities_for_versions, lock_artifact_identities


REVOCATION_FEED_MAX_BYTES = 2_000_000
REVOCATION_CLOCK_SKEW = timedelta(minutes=5)
SYSTEM_ACTOR = "capability-pack.revocation"


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _feed_payload(feed: Any) -> dict[str, Any]:
    return feed.model_dump(mode="json", exclude={"digest_sha256"})


def _verified_feed(
    db: Session,
    payload: CapabilityPackRevocationIngestCreate,
) -> dict[str, str]:
    signed = payload.signed_feed
    feed = signed.feed
    material = _feed_payload(feed)
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(encoded) > REVOCATION_FEED_MAX_BYTES:
        raise ValueError(
            f"Capability pack revocation feed exceeds {REVOCATION_FEED_MAX_BYTES} bytes"
        )
    if _canonical_hash(material) != feed.digest_sha256:
        raise ValueError("Capability pack revocation feed digest does not match")
    now = utcnow()
    if _as_utc(feed.issued_at) > now + REVOCATION_CLOCK_SKEW:
        raise ValueError("Capability pack revocation feed is issued in the future")
    if any(_as_utc(item.effective_at) > now for item in feed.entries):
        raise ValueError("Future capability pack revocations are not supported")
    return verify_trusted_digest_signature(
        db,
        signed.signature,
        expected_digest_sha256=feed.digest_sha256,
        signed_format_version=SIGNED_REVOCATION_FEED_FORMAT,
        expected_purpose="capability_revocation",
    )


def _feed_query():
    return select(CapabilityPackRevocationFeed).options(
        selectinload(CapabilityPackRevocationFeed.entries)
    )


def get_revocation_feed(
    db: Session,
    feed_id: str,
) -> CapabilityPackRevocationFeed:
    feed = db.scalar(
        _feed_query().where(CapabilityPackRevocationFeed.id == feed_id)
    )
    if feed is None:
        raise LookupError("Capability pack revocation feed not found")
    assert_selected_trust_namespace(db, feed)
    return feed


def list_revocation_feeds(
    db: Session,
    *,
    limit: int,
) -> list[CapabilityPackRevocationFeed]:
    tenant_id, region_id = selected_trust_namespace(db)
    return list(
        db.scalars(
            _feed_query()
            .where(
                CapabilityPackRevocationFeed.tenant_id == tenant_id,
                CapabilityPackRevocationFeed.region_id == region_id,
            )
            .order_by(CapabilityPackRevocationFeed.ingested_at.desc())
            .limit(limit)
        ).unique().all()
    )


def active_pack_revocation(
    db: Session,
    pack_digest_sha256: str,
) -> CapabilityPackRevocation | None:
    tenant_id, region_id = selected_trust_namespace(db)
    return db.scalar(
        select(CapabilityPackRevocation)
        .where(
            CapabilityPackRevocation.tenant_id == tenant_id,
            CapabilityPackRevocation.region_id == region_id,
            CapabilityPackRevocation.pack_digest_sha256
            == pack_digest_sha256,
            CapabilityPackRevocation.effective_at <= utcnow(),
        )
        .order_by(CapabilityPackRevocation.effective_at.desc())
        .limit(1)
    )


def artifact_version_revocation(
    db: Session,
    artifact_version_id: str,
) -> CapabilityPackRevocation | None:
    tenant_id, region_id = selected_trust_namespace(db)
    return db.scalar(
        select(CapabilityPackRevocation)
        .join(
            CapabilityPackInstallation,
            CapabilityPackInstallation.pack_digest_sha256
            == CapabilityPackRevocation.pack_digest_sha256,
        )
        .join(
            CapabilityPackInstalledArtifact,
            CapabilityPackInstalledArtifact.installation_id
            == CapabilityPackInstallation.id,
        )
        .where(
            CapabilityPackRevocation.tenant_id == tenant_id,
            CapabilityPackRevocation.region_id == region_id,
            CapabilityPackInstallation.tenant_id == tenant_id,
            CapabilityPackInstallation.region_id == region_id,
            CapabilityPackInstalledArtifact.tenant_id == tenant_id,
            CapabilityPackInstalledArtifact.region_id == region_id,
            CapabilityPackInstalledArtifact.artifact_version_id
            == artifact_version_id,
            CapabilityPackInstalledArtifact.install_action.in_(
                ["installed", "upgraded"]
            ),
            CapabilityPackRevocation.effective_at <= utcnow(),
        )
        .order_by(CapabilityPackRevocation.effective_at.desc())
        .limit(1)
    )


def assert_artifact_version_not_revoked(
    db: Session,
    artifact_version_id: str,
) -> None:
    revocation = artifact_version_revocation(db, artifact_version_id)
    if revocation is not None:
        raise ValueError(
            "Artifact version was installed by a revoked capability pack "
            f"({revocation.reason_code})"
        )


def _installed_version_ids(
    db: Session,
    pack_digests: list[str],
) -> tuple[list[str], int]:
    installation_ids = list(
        db.scalars(
            select(CapabilityPackInstallation.id).where(
                CapabilityPackInstallation.pack_digest_sha256.in_(pack_digests)
            )
        ).all()
    )
    rows = db.execute(
        select(
            CapabilityPackInstalledArtifact.artifact_version_id,
            CapabilityPackInstallation.id,
        )
        .join(
            CapabilityPackInstallation,
            CapabilityPackInstallation.id
            == CapabilityPackInstalledArtifact.installation_id,
        )
        .where(
            CapabilityPackInstallation.pack_digest_sha256.in_(pack_digests),
            CapabilityPackInstalledArtifact.install_action.in_(
                ["installed", "upgraded"]
            ),
        )
    ).all()
    return (
        list(dict.fromkeys(row.artifact_version_id for row in rows)),
        len(installation_ids),
    )


def quarantine_pack_versions(
    db: Session,
    pack_digests: list[str],
    *,
    actor: str = SYSTEM_ACTOR,
    reason_text: str = "Capability pack revoked",
    reason_code: str = "capability_pack_revoked",
    execution_event_type: str = "execution.revoked",
    deprecate_validated: bool = False,
) -> dict[str, int]:
    version_ids, installed_pack_count = _installed_version_ids(db, pack_digests)
    lock_artifact_identities(db, writable=artifact_identities_for_versions(db, version_ids))
    summary = {
        "installed_packs": installed_pack_count,
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

    now = utcnow()
    versions = list(
        db.scalars(
            select(ArtifactVersion).where(ArtifactVersion.id.in_(version_ids))
            .order_by(ArtifactVersion.id).with_for_update()
            .execution_options(populate_existing=True)
        ).all()
    )
    for version in versions:
        removable_statuses = {ArtifactVersionStatus.PUBLISHED}
        if deprecate_validated:
            removable_statuses.add(ArtifactVersionStatus.VALIDATED)
        if version.status in removable_statuses:
            version.status = ArtifactVersionStatus.DEPRECATED
            summary["artifact_versions"] += 1

    deployments = list(
        db.scalars(
            select(CollectorDeployment).where(
                CollectorDeployment.artifact_version_id.in_(version_ids),
                CollectorDeployment.enabled.is_(True),
            )
        ).all()
    )
    deployment_ids = [item.id for item in deployments]
    for deployment in deployments:
        deployment.enabled = False
        deployment.next_run_at = None
        deployment.lease_worker_id = None
        deployment.lease_token_hash = None
        deployment.lease_expires_at = None
        deployment.updated_at = now
    summary["collector_deployments"] = len(deployments)
    if deployment_ids:
        for run in db.scalars(
            select(CollectorRun).where(
                CollectorRun.deployment_id.in_(deployment_ids),
                CollectorRun.status == CollectorRunStatus.RUNNING,
            )
        ).all():
            run.status = CollectorRunStatus.FAILED
            run.finished_at = now
            run.error = f"{reason_text} during execution"

    canaries = list(
        db.scalars(
            select(CollectorCanaryRollout).where(
                or_(
                    CollectorCanaryRollout.candidate_version_id.in_(version_ids),
                    CollectorCanaryRollout.baseline_version_id.in_(version_ids),
                ),
                CollectorCanaryRollout.status.in_(["running", "passed"]),
            )
        ).all()
    )
    for canary in canaries:
        canary.status = "aborted"
        canary.aborted_at = now
        canary.evaluated_at = now
        canary.abort_reason = reason_text
        canary.last_gate_result = reason_code
        canary.updated_at = now
    summary["collector_canaries"] = len(canaries)

    mcp_activations = list(
        db.scalars(
            select(MCPToolActivation).where(
                MCPToolActivation.artifact_version_id.in_(version_ids),
                MCPToolActivation.status == "active",
            )
        ).all()
    )
    for activation in mcp_activations:
        activation.status = "inactive"
        activation.deactivated_by = actor
        activation.deactivation_reason = reason_text
        activation.deactivated_at = now
        activation.updated_at = now
    summary["mcp_activations"] = len(mcp_activations)

    trigger_activations = list(
        db.scalars(
            select(WorkflowTriggerActivation).where(
                WorkflowTriggerActivation.artifact_version_id.in_(version_ids),
                WorkflowTriggerActivation.enabled.is_(True),
            )
        ).all()
    )
    trigger_ids = [item.id for item in trigger_activations]
    for activation in trigger_activations:
        activation.enabled = False
        activation.updated_at = now
    summary["workflow_triggers"] = len(trigger_activations)
    if trigger_ids:
        for event in db.scalars(
            select(WorkflowTriggerEvent).where(
                WorkflowTriggerEvent.activation_id.in_(trigger_ids),
                WorkflowTriggerEvent.status.in_(["pending", "processing", "failed"]),
            )
        ).all():
            event.status = "failed"
            event.attempt_count = max(event.attempt_count, 3)
            event.error_type = reason_code
            event.error_sha256 = hashlib.sha256(
                reason_text.encode("utf-8")
            ).hexdigest()
            event.updated_at = now

    schedule_activations = list(
        db.scalars(
            select(WorkflowScheduleActivation).where(
                or_(
                    WorkflowScheduleActivation.artifact_version_id.in_(
                        version_ids
                    ),
                    WorkflowScheduleActivation.report_artifact_version_id.in_(
                        version_ids
                    ),
                ),
                WorkflowScheduleActivation.enabled.is_(True),
            )
        ).all()
    )
    schedule_ids = [item.id for item in schedule_activations]
    for activation in schedule_activations:
        activation.enabled = False
        activation.updated_at = now
    summary["workflow_schedules"] = len(schedule_activations)
    if schedule_ids:
        for event in db.scalars(
            select(WorkflowScheduleEvent).where(
                WorkflowScheduleEvent.activation_id.in_(schedule_ids),
                WorkflowScheduleEvent.status.in_(["pending", "processing", "failed"]),
            )
        ).all():
            event.status = "failed"
            event.attempt_count = max(event.attempt_count, 3)
            event.error_type = reason_code
            event.error_sha256 = hashlib.sha256(
                reason_text.encode("utf-8")
            ).hexdigest()
            event.updated_at = now

    investigations = list(
        db.scalars(
            select(Investigation).where(
                or_(
                    Investigation.skill_artifact_version_id.in_(version_ids),
                    Investigation.workflow_artifact_version_id.in_(version_ids),
                ),
                Investigation.status.in_([
                    "pending",
                    "running",
                    "waiting_approval",
                ]),
            )
        ).all()
    )
    investigation_ids = [item.id for item in investigations]
    executions = []
    if investigation_ids:
        executions = list(
            db.scalars(
                select(AgentExecution).where(
                    AgentExecution.investigation_id.in_(investigation_ids),
                    AgentExecution.status.in_([
                        AgentExecutionStatus.QUEUED,
                        AgentExecutionStatus.RUNNING,
                        AgentExecutionStatus.WAITING_APPROVAL,
                    ]),
                )
            ).all()
        )
    for execution in executions:
        execution.status = AgentExecutionStatus.CANCELLED
        execution.cancellation_requested_at = now
        execution.cancellation_requested_by = actor
        execution.cancellation_reason = reason_text
        execution.worker_id = None
        execution.lease_token_hash = None
        execution.lease_expires_at = None
        execution.finished_at = now
        execution.error = reason_text
        execution.updated_at = now
        append_execution_event(
            db,
            execution,
            event_type=execution_event_type,
            payload={"reason": reason_code},
        )
    for investigation in investigations:
        investigation.status = "cancelled"
        investigation.escalation_reason = reason_text
        investigation.finished_at = now
        investigation.updated_at = now
    summary["investigations"] = len(investigations)
    summary["agent_executions"] = len(executions)

    indicator_bindings = list(
        db.scalars(
            select(ServiceIndicatorArtifactBinding).where(
                ServiceIndicatorArtifactBinding.artifact_version_id.in_(version_ids),
                ServiceIndicatorArtifactBinding.enabled.is_(True),
            )
        ).all()
    )
    for binding in indicator_bindings:
        binding.enabled = False
        binding.updated_by = actor
        binding.revision += 1
    summary["indicator_bindings"] = len(indicator_bindings)

    integration_bindings = list(
        db.scalars(
            select(SituationIntegrationBinding).where(
                SituationIntegrationBinding.artifact_version_id.in_(version_ids),
                SituationIntegrationBinding.enabled.is_(True),
            )
        ).all()
    )
    for binding in integration_bindings:
        binding.enabled = False
        binding.inbound_enabled = False
        binding.updated_at = now
    summary["integration_bindings"] = len(integration_bindings)
    return summary


def ingest_revocation_feed(
    db: Session,
    payload: CapabilityPackRevocationIngestCreate,
    *,
    actor: str,
) -> CapabilityPackRevocationFeedRead:
    require_locking_transaction(db, purpose="Publisher revocation feeds")
    # Quarantine touches many runtime consumers. Bind their whole transaction,
    # including new feed/entry rows, even for a non-enforcing service caller.
    set_session_namespace(db, *selected_trust_namespace(db))
    statement = payload.signed_feed.feed
    lock_publisher_resource(db, "revocation-stream", payload.signed_feed.signature.key_fingerprint_sha256)
    for digest in sorted({item.pack_digest_sha256 for item in statement.entries}):
        lock_publisher_resource(db, "pack-digest", digest)
    verification = _verified_feed(db, payload)
    lock_trust_keys(db, [verification["trust_key_id"]], expected_purpose="capability_revocation")
    verification = _verified_feed(db, payload)
    existing = db.scalar(
        _feed_query().where(
            CapabilityPackRevocationFeed.trust_key_id
            == verification["trust_key_id"],
            CapabilityPackRevocationFeed.sequence == statement.sequence,
        )
    )
    if existing is not None:
        if existing.feed_digest_sha256 != statement.digest_sha256:
            raise ValueError(
                "Revocation feed sequence already exists with different content"
            )
        result = CapabilityPackRevocationFeedRead.model_validate(existing)
        db.commit()
        return result
    latest_sequence = db.scalar(
        select(func.max(CapabilityPackRevocationFeed.sequence)).where(
            CapabilityPackRevocationFeed.trust_key_id
            == verification["trust_key_id"]
        )
    )
    if latest_sequence is not None and statement.sequence <= latest_sequence:
        raise ValueError(
            "Revocation feed sequence must be greater than the latest trusted sequence"
        )

    feed = CapabilityPackRevocationFeed(
        trust_key_id=verification["trust_key_id"],
        sequence=statement.sequence,
        issued_at=_as_utc(statement.issued_at),
        feed_digest_sha256=statement.digest_sha256,
        key_fingerprint_sha256=verification["key_fingerprint_sha256"],
        signature_sha256=verification["signature_sha256"],
        entry_count=len(statement.entries),
        quarantine_summary={},
        reason=payload.reason,
        ingested_by=actor,
    )
    db.add(feed)
    try:
        db.flush()
        for entry in statement.entries:
            db.add(
                CapabilityPackRevocation(
                    feed_id=feed.id,
                    pack_digest_sha256=entry.pack_digest_sha256,
                    reason_code=entry.reason_code,
                    effective_at=_as_utc(entry.effective_at),
                )
            )
        db.flush()
        feed.quarantine_summary = quarantine_pack_versions(
            db,
            [item.pack_digest_sha256 for item in statement.entries],
        )
        append_capability_transparency_record(
            db,
            event_type="capability.pack.revocation_feed.ingested",
            entity_type="capability_pack_revocation_feed",
            entity_id=feed.id,
            subject_digest_sha256=statement.digest_sha256,
            details={
                "sequence": statement.sequence,
                "key_fingerprint_sha256": verification[
                    "key_fingerprint_sha256"
                ],
                "entry_count": len(statement.entries),
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        record_audit_event(
            db,
            event_type="capability.pack.revocation_feed.ingested",
            actor_type="user",
            actor_id=actor,
            entity_type="capability_pack_revocation_feed",
            entity_id=feed.id,
            details={
                "sequence": statement.sequence,
                "feed_digest_sha256": statement.digest_sha256,
                "key_fingerprint_sha256": verification[
                    "key_fingerprint_sha256"
                ],
                "entry_count": len(statement.entries),
                "quarantine_summary": feed.quarantine_summary,
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        _verified_feed(db, payload)
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        existing = db.scalar(
            _feed_query().where(
                CapabilityPackRevocationFeed.trust_key_id
                == verification["trust_key_id"],
                CapabilityPackRevocationFeed.sequence == statement.sequence,
            )
        )
        if (
            existing is not None
            and existing.feed_digest_sha256 == statement.digest_sha256
        ):
            return CapabilityPackRevocationFeedRead.model_validate(existing)
        raise ValueError("Revocation feed sequence or digest already exists") from exc
    except Exception:
        db.rollback()
        raise
    try:
        db.commit()
    except DBAPIError:
        db.rollback()
        raise
    return CapabilityPackRevocationFeedRead.model_validate(
        get_revocation_feed(db, feed.id)
    )
