from __future__ import annotations

import hashlib
import hmac
import json
import math
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..collector_schemas import CollectorDeploymentCreate
from ..database import require_locking_transaction
from ..models import (
    Artifact,
    ArtifactVersion,
    ArtifactVersionStatus,
    CollectorCanaryRollout,
    CollectorDeployment,
    CollectorDeploymentMode,
    CollectorFleetRollout,
    CollectorFleetRolloutItem,
    CollectorFleetRolloutRing,
    CollectorRun,
    CollectorRunStatus,
    CredentialProfile,
    Device,
    DeviceConnectionActivation,
    utcnow,
)
from ..rollout_schemas import CollectorFleetPlanCreate
from .audit import record_audit_event
from .collectors import (CollectorTargetBusy, _deployment_device_identity_current,
    _lock_external_target_hosts, validate_deployment_payload)
from .artifact_lifecycle import lock_artifact_identities
from .capability_pack_revocations import assert_artifact_version_not_revoked


APPLY_ITEM_STATUSES = {"pending", "deferred"}
ROLLBACK_ITEM_STATUSES = {"migrated", "rollback_deferred"}


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _text_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def deployment_fingerprint(
    deployment: CollectorDeployment,
    *,
    artifact_version_id: str | None = None,
) -> str:
    execution_mode = deployment.execution_mode
    if hasattr(execution_mode, "value"):
        execution_mode = execution_mode.value
    return _canonical_hash(
        {
            "id": deployment.id,
            "name": deployment.name,
            "artifact_version_id": artifact_version_id
            or deployment.artifact_version_id,
            "scope_device_id": deployment.scope_device_id,
            "scope_device_identity_revision": deployment.scope_device_identity_revision,
            "target_classification": deployment.target_classification,
            "external_source_reason": deployment.external_source_reason,
            "scope_site": deployment.scope_site,
            "target": deployment.target,
            "configuration": deployment.configuration,
            "worker_selector": deployment.worker_selector,
            "execution_mode": execution_mode,
            "credential_profile_ref": deployment.credential_profile_ref,
            "schedule_seconds": deployment.schedule_seconds,
            "enabled": deployment.enabled,
        }
    )


def _deployment_payload(
    deployment: CollectorDeployment,
    artifact_version_id: str,
) -> CollectorDeploymentCreate:
    next_run_at = None
    if deployment.execution_mode == CollectorDeploymentMode.SCHEDULED:
        next_run_at = deployment.next_run_at or utcnow()
    return CollectorDeploymentCreate(
        name=deployment.name,
        artifact_version_id=artifact_version_id,
        scope_device_id=deployment.scope_device_id,
        scope_device_identity_revision=deployment.scope_device_identity_revision,
        target_classification=deployment.target_classification,
        external_source_reason=deployment.external_source_reason,
        scope_site=deployment.scope_site,
        target=deployment.target,
        configuration=deployment.configuration,
        worker_selector=deployment.worker_selector,
        execution_mode=deployment.execution_mode,
        credential_profile_ref=deployment.credential_profile_ref,
        schedule_seconds=deployment.schedule_seconds,
        enabled=deployment.enabled,
        created_by=deployment.created_by,
        next_run_at=next_run_at,
    )


def _version(db: Session, version_id: str) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == version_id)
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
        .execution_options(populate_existing=True)
    )
    if version is None:
        raise LookupError("Artifact version not found")
    return version


def _has_active_activation(db: Session, deployment_id: str) -> bool:
    return (
        db.scalar(
            select(DeviceConnectionActivation.id).where(
                DeviceConnectionActivation.deployment_id == deployment_id,
                DeviceConnectionActivation.status == "active",
            )
        )
        is not None
    )


def _is_busy(db: Session, deployment: CollectorDeployment, now: datetime) -> bool:
    if (
        deployment.lease_expires_at is not None
        and _as_utc(deployment.lease_expires_at) > now
    ):
        return True
    return (
        db.scalar(
            select(CollectorRun.id)
            .where(
                CollectorRun.deployment_id == deployment.id,
                CollectorRun.status == CollectorRunStatus.RUNNING,
            )
            .limit(1)
        )
        is not None
    )


def _error(item: CollectorFleetRolloutItem, code: str, exc: Exception | str) -> None:
    message = str(exc)
    item.last_error_code = code
    item.last_error_sha256 = _text_hash(f"{type(exc).__name__}:{message}")
    item.updated_at = utcnow()


def _items(db: Session, rollout_id: str) -> list[CollectorFleetRolloutItem]:
    return list(
        db.scalars(
            select(CollectorFleetRolloutItem)
            .where(CollectorFleetRolloutItem.rollout_id == rollout_id)
            .order_by(CollectorFleetRolloutItem.deployment_id)
        ).all()
    )


def _update_counts(db: Session, rollout: CollectorFleetRollout) -> None:
    db.flush()
    rows = db.execute(
        select(
            CollectorFleetRolloutItem.status,
            func.count(CollectorFleetRolloutItem.id),
        )
        .where(CollectorFleetRolloutItem.rollout_id == rollout.id)
        .group_by(CollectorFleetRolloutItem.status)
    ).all()
    counts = {status: count for status, count in rows}
    rollout.planned_count = sum(counts.values())
    rollout.pending_count = counts.get("pending", 0)
    rollout.blocked_count = counts.get("blocked", 0)
    rollout.deferred_count = counts.get("deferred", 0) + counts.get(
        "rollback_deferred", 0
    )
    rollout.migrated_count = counts.get("migrated", 0) + counts.get(
        "rollback_deferred", 0
    )
    rollout.failed_count = counts.get("failed", 0)
    rollout.rolled_back_count = counts.get("rolled_back", 0)
    rollout.rollback_failed_count = counts.get("rollback_failed", 0)
    rollout.updated_at = utcnow()


def _plan_material(
    rollout: CollectorFleetRollout,
    items: list[CollectorFleetRolloutItem],
) -> dict[str, Any]:
    return {
        "contract": "icheck.collector_fleet_rollout_plan.v1",
        "canary_rollout_id": rollout.canary_rollout_id,
        "artifact_id": rollout.artifact_id,
        "from_version_id": rollout.from_version_id,
        "to_version_id": rollout.to_version_id,
        "scope_site": rollout.scope_site,
        "include_disabled": rollout.include_disabled,
        "batch_size": rollout.batch_size,
        "max_failures": rollout.max_failures,
        "progression_mode": rollout.progression_mode,
        "ring_percentages": rollout.ring_percentages,
        "observation_seconds": rollout.observation_seconds,
        "min_successful_runs_per_deployment": (
            rollout.min_successful_runs_per_deployment
        ),
        "max_failed_runs_per_ring": rollout.max_failed_runs_per_ring,
        "items": [
            {
                "deployment_id": item.deployment_id,
                "pre_change_sha256": item.pre_change_sha256,
                "post_change_sha256": item.post_change_sha256,
                "status": item.status,
                "ring_index": item.ring_index,
                "block_reason_code": item.block_reason_code,
            }
            for item in sorted(items, key=lambda value: value.deployment_id)
        ],
    }


def _assert_plan_hash(rollout: CollectorFleetRollout, supplied: str) -> None:
    if not hmac.compare_digest(rollout.plan_sha256, supplied):
        raise ValueError("Fleet rollout plan hash does not match")


def create_fleet_rollout_plan(
    db: Session,
    payload: CollectorFleetPlanCreate,
    *,
    actor: str,
) -> CollectorFleetRollout:
    canary = db.get(CollectorCanaryRollout, payload.canary_rollout_id)
    if canary is None:
        raise LookupError("Collector canary rollout not found")
    if canary.status != "promoted":
        raise ValueError("Fleet replacement requires a promoted canary")
    if canary.baseline_version_id is None:
        raise ValueError("Fleet replacement requires a baseline version")
    candidate = _version(db, canary.candidate_version_id)
    baseline = _version(db, canary.baseline_version_id)
    if candidate.status != ArtifactVersionStatus.PUBLISHED:
        raise ValueError("Canary candidate is no longer the published version")
    if baseline.status != ArtifactVersionStatus.DEPRECATED:
        raise ValueError("Canary baseline is no longer a deprecated version")
    if candidate.artifact_id != baseline.artifact_id or candidate.artifact_id != canary.artifact_id:
        raise ValueError("Canary version lineage is inconsistent")
    current_published_id = db.scalar(
        select(ArtifactVersion.id).where(
            ArtifactVersion.artifact_id == canary.artifact_id,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
        )
    )
    if current_published_id != candidate.id:
        raise ValueError("Canary candidate is no longer the current published version")
    active = db.scalar(
        select(CollectorFleetRollout.id).where(
            CollectorFleetRollout.canary_rollout_id == canary.id,
            CollectorFleetRollout.status.in_(
                ("planned", "running", "rolling_back")
            ),
        )
    )
    if active is not None:
        raise ValueError("Canary already has an active fleet rollout")

    deployment_query = select(CollectorDeployment).where(
        CollectorDeployment.artifact_version_id == baseline.id
    )
    if payload.scope_site is not None:
        deployment_query = deployment_query.where(
            CollectorDeployment.scope_site == payload.scope_site
        )
    if not payload.include_disabled:
        deployment_query = deployment_query.where(CollectorDeployment.enabled.is_(True))
    deployments = list(
        db.scalars(
            deployment_query.order_by(CollectorDeployment.id).limit(
                payload.max_deployments + 1
            )
        ).all()
    )
    if len(deployments) > payload.max_deployments:
        raise ValueError(
            "Fleet impact exceeds max_deployments; narrow the rollout scope"
        )
    if not deployments:
        raise ValueError("No baseline deployments match the requested fleet scope")

    rollout = CollectorFleetRollout(
        canary_rollout_id=canary.id,
        artifact_id=canary.artifact_id,
        from_version_id=baseline.id,
        to_version_id=candidate.id,
        status="planned",
        scope_site=payload.scope_site,
        include_disabled=payload.include_disabled,
        batch_size=payload.batch_size,
        max_failures=payload.max_failures,
        progression_mode=payload.progression_mode,
        ring_percentages=(
            payload.ring_percentages
            if payload.progression_mode == "automatic"
            else []
        ),
        observation_seconds=payload.observation_seconds,
        min_successful_runs_per_deployment=(
            payload.min_successful_runs_per_deployment
        ),
        max_failed_runs_per_ring=payload.max_failed_runs_per_ring,
        automation_state=(
            "armed" if payload.progression_mode == "automatic" else "manual"
        ),
        automation_updated_at=(
            utcnow() if payload.progression_mode == "automatic" else None
        ),
        plan_sha256="0" * 64,
        created_by=actor,
        reason=payload.reason,
    )
    db.add(rollout)
    db.flush()
    items: list[CollectorFleetRolloutItem] = []
    for deployment in deployments:
        status = "pending"
        block_reason_code = None
        last_error_code = None
        last_error_sha256 = None
        if _has_active_activation(db, deployment.id):
            status = "blocked"
            block_reason_code = "activation_approval_required"
        else:
            try:
                validate_deployment_payload(
                    db,
                    _deployment_payload(deployment, candidate.id),
                )
            except (LookupError, ValueError) as exc:
                status = "blocked"
                block_reason_code = "candidate_incompatible"
                last_error_code = "candidate_incompatible"
                last_error_sha256 = _text_hash(
                    f"{type(exc).__name__}:{str(exc)}"
                )
        item = CollectorFleetRolloutItem(
            rollout_id=rollout.id,
            deployment_id=deployment.id,
            deployment_name=deployment.name,
            pre_change_sha256=deployment_fingerprint(deployment),
            post_change_sha256=deployment_fingerprint(
                deployment,
                artifact_version_id=candidate.id,
            ),
            status=status,
            block_reason_code=block_reason_code,
            last_error_code=last_error_code,
            last_error_sha256=last_error_sha256,
        )
        db.add(item)
        items.append(item)
    db.flush()
    if payload.progression_mode == "automatic":
        actionable = [item for item in items if item.status == "pending"]
        if not actionable:
            raise ValueError(
                "Automatic fleet rollout requires at least one actionable deployment"
            )
        ring_specs: list[tuple[int, int]] = []
        previous_target = 0
        for percent in payload.ring_percentages:
            target = math.ceil(len(actionable) * percent / 100)
            if target <= previous_target:
                if ring_specs and target == previous_target:
                    ring_specs[-1] = (percent, target)
                continue
            ring_specs.append((percent, target))
            previous_target = target
        for ring_index, (percent, target) in enumerate(ring_specs):
            prior_target = ring_specs[ring_index - 1][1] if ring_index else 0
            for item in actionable[prior_target:target]:
                item.ring_index = ring_index
            db.add(
                CollectorFleetRolloutRing(
                    rollout_id=rollout.id,
                    ring_index=ring_index,
                    target_percent=percent,
                    target_count=target,
                    cohort_count=target - prior_target,
                )
            )
        rollout.current_ring_index = 0
        db.flush()
    rollout.plan_sha256 = _canonical_hash(_plan_material(rollout, items))
    _update_counts(db, rollout)
    record_audit_event(
        db,
        event_type="collector.fleet_rollout.planned",
        actor_type="user",
        actor_id=actor,
        entity_type="collector_fleet_rollout",
        entity_id=rollout.id,
        details={
            "canary_rollout_id": canary.id,
            "from_version_id": baseline.id,
            "to_version_id": candidate.id,
            "plan_sha256": rollout.plan_sha256,
            "planned_count": rollout.planned_count,
            "pending_count": rollout.pending_count,
            "blocked_count": rollout.blocked_count,
            "progression_mode": rollout.progression_mode,
            "ring_percentages": rollout.ring_percentages,
            "reason_sha256": _text_hash(payload.reason),
        },
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Canary already has an active fleet rollout") from exc
    db.refresh(rollout)
    return rollout


def _locked_rollout(db: Session, rollout_id: str) -> CollectorFleetRollout:
    require_locking_transaction(db, purpose="Fleet rollout mutations")
    # Publication/revocation take the exclusive identity fence. Acquire our
    # shared fence before the rollout mutex, consistently for API and Worker
    # callers, and retain it through the batch/observation transaction.
    identity_query = (select(Artifact.kind, Artifact.name)
        .join(CollectorFleetRollout, CollectorFleetRollout.artifact_id == Artifact.id)
        .where(CollectorFleetRollout.id == rollout_id))
    identities = list(db.execute(identity_query))
    if not identities:
        raise LookupError("Collector fleet rollout not found")
    lock_artifact_identities(db, readable=identities)
    if list(db.execute(identity_query)) != identities:
        raise ValueError("Artifact identity changed during fleet rollout locking")
    rollout = db.scalar(
        select(CollectorFleetRollout)
        .where(CollectorFleetRollout.id == rollout_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if rollout is None:
        raise LookupError("Collector fleet rollout not found")
    return rollout


def _current_published_candidate(
    db: Session,
    rollout: CollectorFleetRollout,
) -> ArtifactVersion:
    candidate = _version(db, rollout.to_version_id)
    assert_artifact_version_not_revoked(db, candidate.id)
    if candidate.status != ArtifactVersionStatus.PUBLISHED:
        raise ValueError("Fleet candidate is no longer published")
    current_id = db.scalar(
        select(ArtifactVersion.id).where(
            ArtifactVersion.artifact_id == rollout.artifact_id,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
        )
    )
    if current_id != candidate.id:
        raise ValueError("Fleet candidate is no longer the current published version")
    return candidate


class RolloutReferenceBusy(RuntimeError):
    """Retry a busy identity/credential fence without failing the approved plan."""


def _validate_replacement(
    db: Session, deployment: CollectorDeployment, version: ArtifactVersion,
    *, allowed_statuses: set[ArtifactVersionStatus] | None = None,
) -> None:
    if allowed_statuses and ArtifactVersionStatus.DEPRECATED in allowed_statuses:
        assert_artifact_version_not_revoked(db, version.id)
    # Deployment is already locked. NOWAIT reference locks avoid cycles with
    # inventory correction/collector writers that hold the opposite order.
    # A savepoint keeps expected 55P03 from aborting the whole batch.
    try:
        with db.begin_nested():
            if deployment.scope_device_id:
                device = db.scalar(select(Device).where(Device.id == deployment.scope_device_id)
                    .with_for_update(read=True, nowait=True).execution_options(populate_existing=True))
                if device is None:
                    raise ValueError("Fleet target ownership is no longer current")
            if version.collector_definition is None:
                raise ValueError("Collector definition is missing")
            reference = deployment.credential_profile_ref or version.collector_definition.credential_profile_ref
            if reference:
                db.scalar(select(CredentialProfile).where(or_(
                    CredentialProfile.id == reference, CredentialProfile.name == reference))
                    .with_for_update(read=True, nowait=True).execution_options(populate_existing=True))
            _lock_external_target_hosts(db, deployment, nowait=True)
            if not _deployment_device_identity_current(db, deployment):
                raise ValueError("Fleet target ownership is no longer current")
            validate_deployment_payload(db, _deployment_payload(deployment, version.id),
                                        allowed_statuses=allowed_statuses)
    except CollectorTargetBusy as exc:
        raise RolloutReferenceBusy("Fleet external target identity is busy") from exc
    except DBAPIError as exc:
        if getattr(exc.orig, "sqlstate", None) == "55P03":
            raise RolloutReferenceBusy("Fleet target or credential reference is busy") from exc
        raise


def apply_next_fleet_batch(
    db: Session,
    rollout_id: str,
    *,
    actor: str,
    reason: str,
    plan_sha256: str,
    actor_type: str = "user",
    ring_index: int | None = None,
    batch_limit: int | None = None,
    commit: bool = True,
) -> CollectorFleetRollout:
    rollout = _locked_rollout(db, rollout_id)
    _assert_plan_hash(rollout, plan_sha256)
    if rollout.status not in {"planned", "running"}:
        raise ValueError("Fleet rollout is not available for replacement")
    if (
        rollout.progression_mode == "automatic"
        and rollout.automation_state not in {"aborted", "failed"}
        and ring_index is None
    ):
        raise ValueError(
            "Automatic fleet rollout batches are controlled by the rollout worker"
        )
    candidate = _current_published_candidate(db, rollout)
    now = utcnow()
    if rollout.started_at is None:
        rollout.started_at = now
    rollout.status = "running"
    batch_query = select(CollectorFleetRolloutItem).where(
        CollectorFleetRolloutItem.rollout_id == rollout.id,
        CollectorFleetRolloutItem.status.in_(APPLY_ITEM_STATUSES),
    )
    if ring_index is not None:
        batch_query = batch_query.where(
            CollectorFleetRolloutItem.ring_index == ring_index
        )
    limit = rollout.batch_size
    if batch_limit is not None:
        limit = min(limit, max(1, batch_limit))
    batch = list(
        db.scalars(
            batch_query.order_by(CollectorFleetRolloutItem.deployment_id)
            .limit(limit)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).all()
    )
    applied = deferred = failed = 0
    for item in batch:
        item.attempt_count += 1
        item.updated_at = now
        deployment = db.scalar(
            select(CollectorDeployment)
            .where(CollectorDeployment.id == item.deployment_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if deployment is None:
            item.status = "failed"
            _error(item, "deployment_missing", "deployment_missing")
            failed += 1
        elif _has_active_activation(db, deployment.id):
            item.status = "failed"
            _error(
                item,
                "activation_approval_required",
                "activation_approval_required",
            )
            failed += 1
        elif _is_busy(db, deployment, now):
            item.status = "deferred"
            item.last_error_code = "deployment_busy"
            item.last_error_sha256 = None
            deferred += 1
        elif deployment_fingerprint(deployment) != item.pre_change_sha256:
            item.status = "failed"
            _error(item, "deployment_drift", "deployment_drift")
            failed += 1
        else:
            try:
                _validate_replacement(db, deployment, candidate)
            except RolloutReferenceBusy:
                item.status = "deferred"
                item.last_error_code = "reference_busy"
                item.last_error_sha256 = None
                deferred += 1
            except (LookupError, ValueError) as exc:
                item.status = "failed"
                _error(item, "candidate_incompatible", exc)
                failed += 1
            else:
                deployment.artifact_version_id = candidate.id
                deployment.lease_worker_id = None
                deployment.lease_token_hash = None
                deployment.lease_expires_at = None
                deployment.next_run_at = (
                    now
                    if deployment.enabled
                    and deployment.execution_mode
                    == CollectorDeploymentMode.SCHEDULED
                    else None
                )
                deployment.updated_at = now
                if deployment_fingerprint(deployment) != item.post_change_sha256:
                    raise RuntimeError("post_change_fingerprint_mismatch")
                item.status = "migrated"
                item.migrated_at = now
                item.last_error_code = None
                item.last_error_sha256 = None
                applied += 1
        db.flush()
        _update_counts(db, rollout)
        if rollout.failed_count >= rollout.max_failures:
            break

    _update_counts(db, rollout)
    remaining = rollout.pending_count + counts_for_status(
        db, rollout.id, "deferred"
    )
    if rollout.failed_count >= rollout.max_failures:
        rollout.status = "failed"
    elif remaining == 0 and not (
        rollout.progression_mode == "automatic"
        and rollout.automation_state not in {"aborted", "failed"}
    ):
        rollout.status = (
            "failed"
            if rollout.failed_count or rollout.migrated_count == 0
            else "completed"
        )
        if rollout.status == "completed":
            rollout.completed_at = utcnow()
    rollout.last_batch_result = {
        "action": "apply",
        "attempted": applied + deferred + failed,
        "applied": applied,
        "deferred": deferred,
        "failed": failed,
        "remaining": remaining,
    }
    rollout.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="collector.fleet_rollout.batch_applied",
        actor_type=actor_type,
        actor_id=actor,
        entity_type="collector_fleet_rollout",
        entity_id=rollout.id,
        outcome="failure" if rollout.status == "failed" else "success",
        details={
            **rollout.last_batch_result,
            "status": rollout.status,
            "plan_sha256": rollout.plan_sha256,
            "ring_index": ring_index,
            "reason_sha256": _text_hash(reason),
        },
    )
    if commit:
        db.commit()
        db.refresh(rollout)
    return rollout


def counts_for_status(db: Session, rollout_id: str, status: str) -> int:
    return int(
        db.scalar(
            select(func.count(CollectorFleetRolloutItem.id)).where(
                CollectorFleetRolloutItem.rollout_id == rollout_id,
                CollectorFleetRolloutItem.status == status,
            )
        )
        or 0
    )


def rollback_next_fleet_batch(
    db: Session,
    rollout_id: str,
    *,
    actor: str,
    reason: str,
    plan_sha256: str,
) -> CollectorFleetRollout:
    rollout = _locked_rollout(db, rollout_id)
    _assert_plan_hash(rollout, plan_sha256)
    if rollout.status not in {"running", "completed", "failed", "rolling_back"}:
        raise ValueError("Fleet rollout is not available for rollback")
    if rollout.progression_mode == "automatic" and rollout.automation_state in {
        "armed",
        "observing",
        "paused",
    }:
        rollout.automation_state = "aborted"
        rollout.automation_updated_at = utcnow()
    baseline = _version(db, rollout.from_version_id)
    if baseline.status != ArtifactVersionStatus.DEPRECATED:
        raise ValueError("Fleet baseline is no longer deprecated")
    remaining_before = db.scalar(
        select(func.count(CollectorFleetRolloutItem.id)).where(
            CollectorFleetRolloutItem.rollout_id == rollout.id,
            CollectorFleetRolloutItem.status.in_(ROLLBACK_ITEM_STATUSES),
        )
    )
    if not remaining_before:
        raise ValueError("Fleet rollout has no migrated deployments to roll back")
    now = utcnow()
    if rollout.rollback_started_at is None:
        rollout.rollback_started_at = now
    rollout.status = "rolling_back"
    batch = list(
        db.scalars(
            select(CollectorFleetRolloutItem)
            .where(
                CollectorFleetRolloutItem.rollout_id == rollout.id,
                CollectorFleetRolloutItem.status.in_(ROLLBACK_ITEM_STATUSES),
            )
            .order_by(CollectorFleetRolloutItem.deployment_id)
            .limit(rollout.batch_size)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).all()
    )
    rolled_back = deferred = failed = 0
    for item in batch:
        item.attempt_count += 1
        item.updated_at = now
        deployment = db.scalar(
            select(CollectorDeployment)
            .where(CollectorDeployment.id == item.deployment_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if deployment is None:
            item.status = "rollback_failed"
            _error(item, "deployment_missing", "deployment_missing")
            failed += 1
        elif _has_active_activation(db, deployment.id):
            item.status = "rollback_failed"
            _error(
                item,
                "activation_approval_required",
                "activation_approval_required",
            )
            failed += 1
        elif _is_busy(db, deployment, now):
            item.status = "rollback_deferred"
            item.last_error_code = "deployment_busy"
            item.last_error_sha256 = None
            deferred += 1
        elif deployment_fingerprint(deployment) != item.post_change_sha256:
            item.status = "rollback_failed"
            _error(item, "deployment_drift", "deployment_drift")
            failed += 1
        else:
            try:
                _validate_replacement(db, deployment, baseline,
                    allowed_statuses={ArtifactVersionStatus.DEPRECATED})
            except RolloutReferenceBusy:
                item.status = "rollback_deferred"
                item.last_error_code = "reference_busy"
                item.last_error_sha256 = None
                deferred += 1
            except (LookupError, ValueError) as exc:
                item.status = "rollback_failed"
                _error(item, "baseline_incompatible", exc)
                failed += 1
            else:
                deployment.artifact_version_id = baseline.id
                deployment.lease_worker_id = None
                deployment.lease_token_hash = None
                deployment.lease_expires_at = None
                deployment.next_run_at = (
                    now
                    if deployment.enabled
                    and deployment.execution_mode
                    == CollectorDeploymentMode.SCHEDULED
                    else None
                )
                deployment.updated_at = now
                if deployment_fingerprint(deployment) != item.pre_change_sha256:
                    raise RuntimeError("pre_change_fingerprint_mismatch")
                item.status = "rolled_back"
                item.rolled_back_at = now
                item.last_error_code = None
                item.last_error_sha256 = None
                rolled_back += 1
        db.flush()
        if failed:
            break

    _update_counts(db, rollout)
    remaining = int(
        db.scalar(
            select(func.count(CollectorFleetRolloutItem.id)).where(
                CollectorFleetRolloutItem.rollout_id == rollout.id,
                CollectorFleetRolloutItem.status.in_(ROLLBACK_ITEM_STATUSES),
            )
        )
        or 0
    )
    if failed:
        rollout.status = "rollback_failed"
    elif remaining == 0:
        rollout.status = "rolled_back"
        rollout.rolled_back_at = utcnow()
    rollout.last_batch_result = {
        "action": "rollback",
        "attempted": rolled_back + deferred + failed,
        "rolled_back": rolled_back,
        "deferred": deferred,
        "failed": failed,
        "remaining": remaining,
    }
    rollout.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="collector.fleet_rollout.rollback_batch_applied",
        actor_type="user",
        actor_id=actor,
        entity_type="collector_fleet_rollout",
        entity_id=rollout.id,
        outcome="failure" if rollout.status == "rollback_failed" else "success",
        details={
            **rollout.last_batch_result,
            "status": rollout.status,
            "plan_sha256": rollout.plan_sha256,
            "reason_sha256": _text_hash(reason),
        },
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Another active fleet rollout prevents this rollback"
        ) from exc
    db.refresh(rollout)
    return rollout
