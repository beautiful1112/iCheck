from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from ..models import (
    CollectorFleetRollout,
    CollectorFleetRolloutItem,
    CollectorFleetRolloutRing,
    CollectorDeployment,
    CollectorRun,
    CollectorRunStatus,
    ArtifactVersion,
    utcnow,
)
from .audit import record_audit_event
from .fleet_rollouts import (
    APPLY_ITEM_STATUSES,
    _assert_plan_hash,
    _canonical_hash,
    _locked_rollout,
    _current_published_candidate,
    _validate_replacement,
    RolloutReferenceBusy,
    deployment_fingerprint,
    _text_hash,
    _update_counts,
    apply_next_fleet_batch,
)


ACTIVE_AUTOMATION_STATES = {"armed", "observing"}


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _current_ring(
    db: Session,
    rollout: CollectorFleetRollout,
) -> CollectorFleetRolloutRing | None:
    if rollout.current_ring_index is None:
        return None
    return db.scalar(
        select(CollectorFleetRolloutRing)
        .where(
            CollectorFleetRolloutRing.rollout_id == rollout.id,
            CollectorFleetRolloutRing.ring_index == rollout.current_ring_index,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def _ring_items(
    db: Session,
    rollout_id: str,
    ring_index: int,
) -> list[CollectorFleetRolloutItem]:
    return list(
        db.scalars(
            select(CollectorFleetRolloutItem)
            .where(
                CollectorFleetRolloutItem.rollout_id == rollout_id,
                CollectorFleetRolloutItem.ring_index == ring_index,
            )
            .order_by(CollectorFleetRolloutItem.deployment_id)
            .execution_options(populate_existing=True)
        ).all()
    )


def _record_transition(
    db: Session,
    rollout: CollectorFleetRollout,
    ring: CollectorFleetRolloutRing,
    *,
    event_type: str,
    actor_type: str,
    actor_id: str,
    outcome: str = "success",
    extra: dict[str, object] | None = None,
) -> None:
    record_audit_event(
        db,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        entity_type="collector_fleet_rollout",
        entity_id=rollout.id,
        outcome=outcome,
        details={
            "plan_sha256": rollout.plan_sha256,
            "ring_index": ring.ring_index,
            "target_percent": ring.target_percent,
            "target_count": ring.target_count,
            "ring_status": ring.status,
            "automation_state": rollout.automation_state,
            **(extra or {}),
        },
    )


def _fail_ring(
    db: Session,
    rollout: CollectorFleetRollout,
    ring: CollectorFleetRolloutRing,
    *,
    gate_result: str,
    actor: str,
) -> None:
    now = utcnow()
    ring.status = "failed"
    ring.last_gate_result = gate_result
    ring.evaluated_at = now
    ring.updated_at = now
    rollout.automation_state = "failed"
    rollout.automation_updated_at = now
    rollout.status = "failed"
    rollout.updated_at = now
    _record_transition(
        db,
        rollout,
        ring,
        event_type="collector.fleet_rollout.ring_failed",
        actor_type="service",
        actor_id=actor,
        outcome="failure",
        extra={"gate_result": gate_result},
    )


def _begin_observation(
    db: Session,
    rollout: CollectorFleetRollout,
    ring: CollectorFleetRolloutRing,
    *,
    now: datetime,
    actor: str,
) -> None:
    ring.status = "observing"
    ring.observation_started_at = now
    ring.last_gate_result = "waiting_for_observation_window"
    ring.updated_at = now
    rollout.automation_state = "observing"
    rollout.automation_updated_at = now
    _record_transition(
        db,
        rollout,
        ring,
        event_type="collector.fleet_rollout.ring_observing",
        actor_type="service",
        actor_id=actor,
    )


def _evaluate_health(
    db: Session,
    rollout: CollectorFleetRollout,
    ring: CollectorFleetRolloutRing,
    items: list[CollectorFleetRolloutItem],
    *,
    now: datetime,
    actor: str,
    candidate: ArtifactVersion,
) -> None:
    if ring.observation_started_at is None:
        _begin_observation(db, rollout, ring, now=now, actor=actor)
        return
    for item in items:
        deployment = db.scalar(select(CollectorDeployment).where(CollectorDeployment.id == item.deployment_id)
            .with_for_update().execution_options(populate_existing=True))
        if deployment is None or deployment_fingerprint(deployment) != item.post_change_sha256:
            _fail_ring(db, rollout, ring, gate_result="deployment_drift", actor=actor)
            return
        try:
            _validate_replacement(db, deployment, candidate)
        except RolloutReferenceBusy:
            ring.last_gate_result = "waiting_for_reference_fence"
            ring.evaluated_at = now
            ring.updated_at = now
            return
        except (LookupError, ValueError):
            _fail_ring(db, rollout, ring, gate_result="candidate_incompatible", actor=actor)
            return
    observation_started_at = _as_utc(ring.observation_started_at)
    deployment_ids = [item.deployment_id for item in items]
    run_groups = db.execute(
            select(
                CollectorRun.deployment_id,
                CollectorRun.status,
                func.count(CollectorRun.id),
                func.coalesce(func.sum(CollectorRun.records_received), 0),
                func.min(CollectorRun.started_at),
                func.max(CollectorRun.finished_at),
            )
            .where(
                CollectorRun.deployment_id.in_(deployment_ids),
                CollectorRun.artifact_version_id == rollout.to_version_id,
                or_(CollectorRun.status != CollectorRunStatus.SUCCEEDED, and_(
                    CollectorRun.execution_admitted_at >= CollectorRun.started_at,
                    CollectorRun.execution_admitted_at <= CollectorRun.finished_at,
                    CollectorRun.assignment_sha256.is_not(None))),
                CollectorRun.started_at >= observation_started_at,
                CollectorRun.finished_at >= CollectorRun.started_at,
                CollectorRun.finished_at <= now,
                CollectorRun.status.in_(
                    (
                        CollectorRunStatus.SUCCEEDED,
                        CollectorRunStatus.FAILED,
                        CollectorRunStatus.CANCELLED,
                    )
                ),
            )
            .group_by(CollectorRun.deployment_id, CollectorRun.status)
            .order_by(CollectorRun.deployment_id, CollectorRun.status)
        ).all()
    successful_by_deployment: dict[str, int] = defaultdict(int)
    successful_runs = 0
    failed_runs = 0
    evidence: list[dict[str, object]] = []
    for (
        deployment_id,
        run_status,
        run_count,
        records_received,
        first_started_at,
        last_finished_at,
    ) in run_groups:
        status = (
            run_status.value if hasattr(run_status, "value") else str(run_status)
        )
        count = int(run_count)
        if run_status == CollectorRunStatus.SUCCEEDED:
            successful_by_deployment[deployment_id] += count
            successful_runs += count
        else:
            failed_runs += count
        evidence.append(
            {
                "deployment_id": deployment_id,
                "status": status,
                "run_count": count,
                "records_received": int(records_received),
                "first_started_at": _as_utc(first_started_at).isoformat(),
                "last_finished_at": (
                    _as_utc(last_finished_at).isoformat()
                    if last_finished_at is not None
                    else None
                ),
            }
        )
    healthy = sum(
        1
        for deployment_id in deployment_ids
        if successful_by_deployment[deployment_id]
        >= rollout.min_successful_runs_per_deployment
    )
    missing = len(deployment_ids) - healthy
    ring.healthy_deployments = healthy
    ring.missing_evidence_deployments = missing
    ring.successful_runs = successful_runs
    ring.failed_runs = failed_runs
    ring.evidence_sha256 = _canonical_hash(
        {
            "contract": "icheck.collector_fleet_rollout_ring_evidence.v1",
            "rollout_id": rollout.id,
            "plan_sha256": rollout.plan_sha256,
            "artifact_version_id": rollout.to_version_id,
            "successful_run_basis": "candidate_execution_admitted_with_assignment",
            "ring_index": ring.ring_index,
            "observation_started_at": observation_started_at.isoformat(),
            "run_groups": evidence,
        }
    )
    ring.evaluated_at = now
    ring.updated_at = now
    rollout.automation_updated_at = now

    if failed_runs > rollout.max_failed_runs_per_ring:
        ring.status = "paused"
        ring.last_gate_result = "failed_run_limit_exceeded"
        rollout.automation_state = "paused"
        _record_transition(
            db,
            rollout,
            ring,
            event_type="collector.fleet_rollout.ring_paused",
            actor_type="service",
            actor_id=actor,
            outcome="failure",
            extra={
                "gate_result": ring.last_gate_result,
                "evidence_sha256": ring.evidence_sha256,
                "failed_runs": failed_runs,
            },
        )
        return

    elapsed = (now - observation_started_at).total_seconds()
    if elapsed < rollout.observation_seconds:
        ring.last_gate_result = "waiting_for_observation_window"
        return
    if missing:
        ring.last_gate_result = "waiting_for_healthy_runs"
        return

    ring.status = "passed"
    ring.last_gate_result = "passed"
    ring.passed_at = now
    _record_transition(
        db,
        rollout,
        ring,
        event_type="collector.fleet_rollout.ring_passed",
        actor_type="service",
        actor_id=actor,
        extra={
            "evidence_sha256": ring.evidence_sha256,
            "healthy_deployments": healthy,
            "successful_runs": successful_runs,
        },
    )
    next_ring = db.scalar(
        select(CollectorFleetRolloutRing)
        .where(
            CollectorFleetRolloutRing.rollout_id == rollout.id,
            CollectorFleetRolloutRing.ring_index > ring.ring_index,
        )
        .order_by(CollectorFleetRolloutRing.ring_index)
        .limit(1)
    )
    if next_ring is None:
        rollout.current_ring_index = None
        rollout.automation_state = "completed"
        rollout.status = "completed"
        rollout.completed_at = now
    else:
        rollout.current_ring_index = next_ring.ring_index
        rollout.automation_state = "armed"
    rollout.automation_updated_at = now
    rollout.updated_at = now


def reconcile_automatic_rollout(
    db: Session,
    rollout_id: str,
    *,
    actor: str = "system.rollout-controller",
    now: datetime | None = None,
    commit: bool = True,
) -> CollectorFleetRollout:
    rollout = _locked_rollout(db, rollout_id)
    if rollout.progression_mode != "automatic":
        raise ValueError("Fleet rollout does not use automatic progression")
    if rollout.automation_state not in ACTIVE_AUTOMATION_STATES:
        return rollout
    ring = _current_ring(db, rollout)
    if ring is None:
        raise RuntimeError("Automatic fleet rollout has no current ring")
    current_time = _as_utc(now or utcnow())
    try:
        candidate = _current_published_candidate(db, rollout)
    except (LookupError, ValueError):
        _fail_ring(db, rollout, ring, gate_result="candidate_unavailable", actor=actor)
        if commit:
            db.commit()
            db.refresh(rollout)
        return rollout
    items = _ring_items(db, rollout.id, ring.ring_index)
    if len(items) != ring.cohort_count:
        _fail_ring(
            db,
            rollout,
            ring,
            gate_result="ring_membership_mismatch",
            actor=actor,
        )
    elif ring.status in {"pending", "applying"}:
        if ring.started_at is None:
            ring.started_at = current_time
        ring.status = "applying"
        rollout.automation_state = "armed"
        rollout.automation_updated_at = current_time
        apply_next_fleet_batch(
            db,
            rollout.id,
            actor=actor,
            actor_type="service",
            reason=f"Automatic application of rollout ring {ring.ring_index}.",
            plan_sha256=rollout.plan_sha256,
            ring_index=ring.ring_index,
            batch_limit=rollout.batch_size,
            commit=False,
        )
        db.flush()
        _update_counts(db, rollout)
        items = _ring_items(db, rollout.id, ring.ring_index)
        if rollout.status == "failed" or any(item.status == "failed" for item in items):
            _fail_ring(
                db,
                rollout,
                ring,
                gate_result="ring_application_failed",
                actor=actor,
            )
        elif all(item.status == "migrated" for item in items):
            _begin_observation(
                db,
                rollout,
                ring,
                now=current_time,
                actor=actor,
            )
    elif ring.status == "observing":
        _evaluate_health(
            db,
            rollout,
            ring,
            items,
            now=current_time,
            actor=actor,
            candidate=candidate,
        )
    else:
        _fail_ring(
            db,
            rollout,
            ring,
            gate_result="invalid_ring_state",
            actor=actor,
        )
    if commit:
        db.commit()
        db.refresh(rollout)
    return rollout


def set_automatic_rollout_state(
    db: Session,
    rollout_id: str,
    *,
    action: str,
    actor: str,
    reason: str,
    plan_sha256: str,
) -> CollectorFleetRollout:
    rollout = _locked_rollout(db, rollout_id)
    _assert_plan_hash(rollout, plan_sha256)
    if rollout.progression_mode != "automatic":
        raise ValueError("Fleet rollout does not use automatic progression")
    if action not in {"pause", "resume", "abort"}:
        raise ValueError("Unsupported automatic rollout action")
    ring = _current_ring(db, rollout)
    now = utcnow()
    if action == "pause":
        if rollout.automation_state not in ACTIVE_AUTOMATION_STATES:
            raise ValueError("Automatic fleet rollout is not active")
        rollout.automation_state = "paused"
        if ring is not None:
            ring.status = "paused"
            ring.last_gate_result = "paused_by_operator"
    elif action == "resume":
        if rollout.automation_state != "paused" or ring is None:
            raise ValueError("Automatic fleet rollout is not paused")
        items = _ring_items(db, rollout.id, ring.ring_index)
        if all(item.status == "migrated" for item in items):
            ring.status = "observing"
            ring.observation_started_at = now
            ring.last_gate_result = "waiting_for_observation_window"
            ring.healthy_deployments = 0
            ring.missing_evidence_deployments = len(items)
            ring.successful_runs = 0
            ring.failed_runs = 0
            ring.evidence_sha256 = None
            rollout.automation_state = "observing"
        elif any(item.status in APPLY_ITEM_STATUSES for item in items):
            ring.status = "applying"
            ring.last_gate_result = None
            rollout.automation_state = "armed"
        else:
            raise ValueError("Paused ring cannot be safely resumed")
    else:
        if rollout.automation_state not in {"armed", "observing", "paused"}:
            raise ValueError("Automatic fleet rollout cannot be aborted")
        rollout.automation_state = "aborted"
        if ring is not None:
            ring.status = "aborted"
            ring.last_gate_result = "aborted_by_operator"
    rollout.automation_updated_at = now
    rollout.updated_at = now
    if ring is not None:
        ring.updated_at = now
        _record_transition(
            db,
            rollout,
            ring,
            event_type=f"collector.fleet_rollout.automation_{action}",
            actor_type="user",
            actor_id=actor,
            extra={"reason_sha256": _text_hash(reason)},
        )
    db.commit()
    db.refresh(rollout)
    return rollout
