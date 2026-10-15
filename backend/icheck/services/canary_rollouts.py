from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..collector_schemas import CollectorDeploymentCreate
from ..models import (
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    CollectorCanaryRollout,
    CollectorDeployment,
    CollectorDeploymentMode,
    CollectorMode,
    CollectorRun,
    CollectorRunStatus,
    Device,
    utcnow,
)
from ..rollout_schemas import CollectorCanaryCreate
from .audit import record_audit_event
from .collectors import (
    _deployment_device_identity_current,
    create_deployment,
    publish_artifact_version,
)
from .capability_pack_revocations import assert_artifact_version_not_revoked


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _ownership_document(
    *,
    version_id: str,
    target: dict[str, Any],
    configuration: dict[str, Any],
    worker_selector: dict[str, Any],
    credential_profile_ref: str | None,
    schedule_seconds: int,
    target_classification: str | None,
    scope_device_id: str | None,
    scope_device_identity_revision: int | None,
    scope_site: str | None,
    external_source_reason: str | None,
    actor: str,
) -> dict[str, Any]:
    return {
        "candidate_version_id": version_id,
        "target": target,
        "configuration": configuration,
        "worker_selector": worker_selector,
        "credential_profile_ref": credential_profile_ref,
        "schedule_seconds": schedule_seconds,
        "target_classification": target_classification,
        "scope_device_id": scope_device_id,
        "scope_device_identity_revision": scope_device_identity_revision,
        "scope_site": scope_site,
        "external_source_reason": external_source_reason,
        "actor": actor,
    }


def _rollout_ownership_hash(rollout: CollectorCanaryRollout) -> str:
    return _hash(_ownership_document(
        version_id=rollout.candidate_version_id,
        target=rollout.target,
        configuration=rollout.configuration,
        worker_selector=rollout.worker_selector,
        credential_profile_ref=rollout.credential_profile_ref,
        schedule_seconds=rollout.schedule_seconds,
        target_classification=rollout.target_classification,
        scope_device_id=rollout.scope_device_id,
        scope_device_identity_revision=rollout.scope_device_identity_revision,
        scope_site=rollout.scope_site,
        external_source_reason=rollout.external_source_reason,
        actor=rollout.created_by,
    ))


def _deployment_ownership_hash(deployment: CollectorDeployment) -> str:
    return _hash(_ownership_document(
        version_id=deployment.artifact_version_id,
        target=deployment.target,
        configuration=deployment.configuration,
        worker_selector=deployment.worker_selector,
        credential_profile_ref=deployment.credential_profile_ref,
        schedule_seconds=deployment.schedule_seconds,
        target_classification=deployment.target_classification,
        scope_device_id=deployment.scope_device_id,
        scope_device_identity_revision=deployment.scope_device_identity_revision,
        scope_site=deployment.scope_site,
        external_source_reason=deployment.external_source_reason,
        actor=deployment.created_by,
    ))


def _version(db: Session, version_id: str) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == version_id)
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
    )
    if version is None:
        raise LookupError("Artifact version not found")
    return version


def _disable_deployment(
    db: Session,
    rollout: CollectorCanaryRollout,
) -> None:
    if rollout.deployment_id is None:
        return
    deployment = db.get(CollectorDeployment, rollout.deployment_id)
    if deployment is None:
        return
    deployment.enabled = False
    deployment.next_run_at = None
    deployment.updated_at = utcnow()


def _transition(
    db: Session,
    rollout: CollectorCanaryRollout,
    status: str,
    *,
    reason: str,
    actor_type: str = "system",
    actor_id: str = "collector.canary",
) -> None:
    previous = rollout.status
    now = utcnow()
    rollout.status = status
    rollout.evaluated_at = now
    rollout.updated_at = now
    if status == "passed":
        rollout.passed_at = now
    elif status == "aborted":
        rollout.aborted_at = now
        rollout.abort_reason = reason
    if status in {"passed", "aborted", "promoted"}:
        _disable_deployment(db, rollout)
    record_audit_event(
        db,
        event_type=f"collector.canary.{status}",
        actor_type=actor_type,
        actor_id=actor_id,
        entity_type="collector_canary_rollout",
        entity_id=rollout.id,
        outcome="success" if status in {"passed", "promoted"} else "failure",
        details={
            "from": previous,
            "to": status,
            "candidate_version_id": rollout.candidate_version_id,
            "qualifying_runs": rollout.qualifying_runs,
            "failed_runs": rollout.failed_runs,
            "reason": reason,
        },
    )


def create_canary_rollout(
    db: Session,
    payload: CollectorCanaryCreate,
    *,
    actor: str,
) -> CollectorCanaryRollout:
    candidate = _version(db, payload.artifact_version_id)
    assert_artifact_version_not_revoked(db, candidate.id)
    if candidate.artifact.kind != ArtifactKind.COLLECTOR:
        raise ValueError("Canary rollout supports only Collector Artifacts")
    if candidate.status != ArtifactVersionStatus.VALIDATED:
        raise ValueError("Canary candidate must be a validated version")
    definition = candidate.collector_definition
    if definition is None:
        raise ValueError("Collector definition is missing")
    if definition.mode != CollectorMode.POLL:
        raise ValueError("Initial canary runtime supports polling Collectors only")
    if definition.adapter_type == "psrp_cim":
        raise ValueError("Initial canary runtime does not support PSRP/CIM")
    active = db.scalar(
        select(CollectorCanaryRollout.id).where(
            CollectorCanaryRollout.artifact_id == candidate.artifact_id,
            CollectorCanaryRollout.status == "running",
        )
    )
    if active is not None:
        raise ValueError("Artifact already has an active canary rollout")
    baseline = db.scalar(
        select(ArtifactVersion).where(
            ArtifactVersion.artifact_id == candidate.artifact_id,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
        )
    )
    now = utcnow()
    rollout = CollectorCanaryRollout(
        name=payload.name,
        artifact_id=candidate.artifact_id,
        candidate_version_id=candidate.id,
        baseline_version_id=baseline.id if baseline else None,
        status="running",
        target=payload.target,
        configuration=payload.configuration,
        worker_selector=payload.worker_selector,
        credential_profile_ref=payload.credential_profile_ref,
        schedule_seconds=payload.schedule_seconds,
        min_successful_runs=payload.min_successful_runs,
        max_failed_runs=payload.max_failed_runs,
        min_records_per_run=payload.min_records_per_run,
        created_by=actor,
        started_at=now,
        deadline_at=now + timedelta(seconds=payload.timeout_seconds),
    )
    db.add(rollout)
    try:
        db.flush()
        deployment_payload = CollectorDeploymentCreate(
            name=f"canary:{candidate.artifact.name}:v{candidate.version}:{rollout.id[:8]}",
            artifact_version_id=candidate.id,
            scope_device_id=payload.scope_device_id,
            scope_device_identity_revision=payload.scope_device_identity_revision,
            target_classification=payload.target_classification,
            external_source_reason=payload.external_source_reason,
            scope_site=payload.scope_site,
            target=payload.target,
            configuration=payload.configuration,
            worker_selector=payload.worker_selector,
            execution_mode=CollectorDeploymentMode.SCHEDULED,
            credential_profile_ref=payload.credential_profile_ref,
            schedule_seconds=payload.schedule_seconds,
            enabled=True,
            created_by=actor,
            next_run_at=now,
        )
        deployment = create_deployment(
            db,
            deployment_payload,
            commit=False,
            allowed_statuses={ArtifactVersionStatus.VALIDATED},
        )
        rollout.deployment_id = deployment.id
        rollout.target = deployment.target
        rollout.configuration = deployment.configuration
        rollout.worker_selector = deployment.worker_selector
        rollout.credential_profile_ref = deployment.credential_profile_ref
        rollout.schedule_seconds = deployment.schedule_seconds
        rollout.target_classification = deployment.target_classification
        rollout.scope_device_id = deployment.scope_device_id
        rollout.scope_device_identity_revision = deployment.scope_device_identity_revision
        rollout.scope_site = deployment.scope_site
        rollout.external_source_reason = deployment.external_source_reason
        rollout.target_ownership_sha256 = _rollout_ownership_hash(rollout)
        if rollout.target_ownership_sha256 != _deployment_ownership_hash(deployment):
            raise ValueError("Canary ownership snapshot differs from its deployment")
        record_audit_event(
            db,
            event_type="collector.canary.started",
            actor_type="user",
            actor_id=actor,
            entity_type="collector_canary_rollout",
            entity_id=rollout.id,
            details={
                "artifact_id": rollout.artifact_id,
                "candidate_version_id": candidate.id,
                "baseline_version_id": rollout.baseline_version_id,
                "deployment_id": deployment.id,
                "target_classification": rollout.target_classification,
                "scope_device_id": rollout.scope_device_id,
                "scope_device_identity_revision": rollout.scope_device_identity_revision,
                "scope_site": rollout.scope_site,
                "target_ownership_sha256": rollout.target_ownership_sha256,
                "min_successful_runs": rollout.min_successful_runs,
                "max_failed_runs": rollout.max_failed_runs,
                "min_records_per_run": rollout.min_records_per_run,
                "deadline_at": rollout.deadline_at.isoformat(),
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Canary name exists or Artifact already has an active rollout") from exc
    db.refresh(rollout)
    return rollout


def active_rollout_for_deployment(
    db: Session,
    deployment_id: str,
) -> CollectorCanaryRollout | None:
    return db.scalar(
        select(CollectorCanaryRollout).where(
            CollectorCanaryRollout.deployment_id == deployment_id,
            CollectorCanaryRollout.status == "running",
        )
    )


def record_canary_envelope_batch(
    db: Session,
    run: CollectorRun,
    envelopes: list[Any],
) -> bool:
    rollout = active_rollout_for_deployment(db, run.deployment_id)
    if rollout is None:
        return False
    normalized = [
        item.model_dump(mode="json", exclude_none=True)
        if hasattr(item, "model_dump")
        else item
        for item in envelopes
    ]
    rollout.evidence_batches += 1
    rollout.last_evidence_sha256 = _hash(normalized)
    rollout.updated_at = utcnow()
    return True


def reconcile_canary_run(db: Session, run: CollectorRun) -> None:
    rollout = db.scalar(
        select(CollectorCanaryRollout).where(
            CollectorCanaryRollout.deployment_id == run.deployment_id
        )
    )
    if rollout is None:
        return
    if rollout.status != "running":
        _disable_deployment(db, rollout)
        return
    now = utcnow()
    rollout.last_run_id = run.id
    rollout.records_received += run.records_received
    rollout.evaluated_at = now
    rollout.updated_at = now
    if run.status == CollectorRunStatus.SUCCEEDED:
        rollout.successful_runs += 1
        if run.records_received >= rollout.min_records_per_run:
            rollout.qualifying_runs += 1
            rollout.last_gate_result = "qualified"
        else:
            rollout.failed_runs += 1
            rollout.last_gate_result = "insufficient_records"
    else:
        rollout.failed_runs += 1
        rollout.last_gate_result = run.status.value

    if rollout.failed_runs >= rollout.max_failed_runs:
        _transition(
            db,
            rollout,
            "aborted",
            reason="Canary failure threshold reached",
        )
    elif _as_utc(rollout.deadline_at) <= now:
        _transition(
            db,
            rollout,
            "aborted",
            reason="Canary deadline expired before health gates passed",
        )
    elif rollout.qualifying_runs >= rollout.min_successful_runs:
        _transition(
            db,
            rollout,
            "passed",
            reason="Canary health gates passed",
        )


def reconcile_timed_out_rollouts(db: Session, *, commit: bool = True) -> int:
    now = utcnow()
    rollouts = list(
        db.scalars(
            select(CollectorCanaryRollout).where(
                CollectorCanaryRollout.status == "running",
                CollectorCanaryRollout.deadline_at <= now,
            )
        ).all()
    )
    for rollout in rollouts:
        _transition(
            db,
            rollout,
            "aborted",
            reason="Canary deadline expired before health gates passed",
        )
    if rollouts and commit:
        db.commit()
    return len(rollouts)


def abort_canary_rollout(
    db: Session,
    rollout: CollectorCanaryRollout,
    *,
    actor: str,
    reason: str,
) -> CollectorCanaryRollout:
    if rollout.status != "running":
        raise ValueError("Only a running canary can be aborted")
    _transition(
        db,
        rollout,
        "aborted",
        reason=reason,
        actor_type="user",
        actor_id=actor,
    )
    db.commit()
    db.refresh(rollout)
    return rollout


def promote_canary_rollout(
    db: Session,
    rollout: CollectorCanaryRollout,
    *,
    actor: str,
    reason: str,
) -> CollectorCanaryRollout:
    from .artifact_lifecycle import lock_artifact_version, prepare_artifact_mutation
    prepare_artifact_mutation(db, purpose="Canary promotion")
    candidate = lock_artifact_version(db, rollout.candidate_version_id)
    rollout = db.scalar(select(CollectorCanaryRollout).where(CollectorCanaryRollout.id == rollout.id)
        .with_for_update().execution_options(populate_existing=True))
    if rollout is None:
        raise LookupError("Canary rollout not found")
    if rollout.status != "passed":
        raise ValueError("Only a passed canary can be promoted")
    if candidate.status != ArtifactVersionStatus.VALIDATED:
        raise ValueError("Canary candidate is no longer a validated version")
    if rollout.target_ownership_sha256 is None:
        raise ValueError("Canary has no reviewed ownership snapshot; start a new canary")
    else:
        if rollout.target_ownership_sha256 != _rollout_ownership_hash(rollout):
            raise ValueError("Canary ownership snapshot changed after review")
        if rollout.scope_device_id is not None:
            # Device identity correction locks the Device before its deployments.
            # Keep the same order and hold both rows through publication.
            db.scalar(
                select(Device.id).where(
                    Device.id == rollout.scope_device_id,
                    Device.tenant_id == rollout.tenant_id,
                    Device.region_id == rollout.region_id,
                ).with_for_update()
            )
        deployment = (
            db.scalar(
                select(CollectorDeployment)
                .where(CollectorDeployment.id == rollout.deployment_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if rollout.deployment_id is not None else None
        )
        if deployment is None or (
            rollout.target_ownership_sha256 != _deployment_ownership_hash(deployment)
        ):
            raise ValueError("Canary deployment differs from reviewed ownership snapshot")
        if not _deployment_device_identity_current(db, deployment):
            raise ValueError("Canary target ownership is no longer current")
    current = db.scalar(
        select(ArtifactVersion).where(
            ArtifactVersion.artifact_id == rollout.artifact_id,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
        )
    )
    current_id = current.id if current else None
    if current_id != rollout.baseline_version_id:
        raise ValueError("Published baseline changed after the canary started")
    publish_artifact_version(
        db,
        candidate,
        actor,
        commit=False,
        canary_promotion=True,
    )
    now = utcnow()
    rollout.status = "promoted"
    rollout.promoted_at = now
    rollout.promoted_by = actor
    rollout.promotion_reason = reason
    rollout.evaluated_at = now
    rollout.updated_at = now
    _disable_deployment(db, rollout)
    record_audit_event(
        db,
        event_type="collector.canary.promoted",
        actor_type="user",
        actor_id=actor,
        entity_type="collector_canary_rollout",
        entity_id=rollout.id,
        details={
            "candidate_version_id": rollout.candidate_version_id,
            "baseline_version_id": rollout.baseline_version_id,
            "reason": reason,
        },
    )
    db.commit()
    db.refresh(rollout)
    return rollout
