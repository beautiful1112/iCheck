"""Finalize abandoned Collector runs after their lease can no longer be renewed."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..database import require_locking_transaction, session_namespace
from ..models import (
    CollectorDeployment,
    CollectorDeploymentMode,
    CollectorRun,
    CollectorRunStatus,
    utcnow,
)
from .audit import record_audit_event
from .canary_rollouts import reconcile_canary_run
from .runtime_health import reconcile_completed_run


MAX_LEASE_BATCH = 100


def cancel_abandoned_runs(
    db: Session, deployment: CollectorDeployment, *, now: datetime,
) -> int:
    """Call with the deployment row locked, before releasing or replacing its lease."""
    runs = list(db.scalars(
        select(CollectorRun)
        .where(
            CollectorRun.deployment_id == deployment.id,
            CollectorRun.status == CollectorRunStatus.RUNNING,
        )
        .order_by(CollectorRun.started_at, CollectorRun.id)
        .with_for_update()
    ).all())
    for run in runs:
        _cancel_run(db, run, deployment, now=now, orphan=False)
    return len(runs)


def _cancel_run(
    db: Session, run: CollectorRun, deployment: CollectorDeployment,
    *, now: datetime, orphan: bool,
) -> None:
    reason = "lease_owner_lost" if orphan else "lease_expired"
    run.status = CollectorRunStatus.CANCELLED
    run.finished_at = now
    run.error = (
        "Collector run no longer owns its deployment lease" if orphan
        else "Collector lease expired before the Worker completed the run"
    )
    run.stats = {**(run.stats or {}), "cancel_reason": reason}
    deployment.last_finished_at = now
    reconcile_completed_run(db, run)
    reconcile_canary_run(db, run)
    record_audit_event(
        db,
        event_type=(
            "collector.run.orphan_reconciled" if orphan
            else "collector.run.lease_expired"
        ),
        actor_type="service",
        actor_id="collector.lease_reconciler",
        entity_type="collector_run",
        entity_id=run.id,
        outcome="failure",
        details={
            "deployment_id": deployment.id,
            "worker_id": run.worker_id,
            "reason_code": reason,
        },
    )


def reconcile_expired_leases(
    db: Session, *, now: datetime | None = None, limit: int = MAX_LEASE_BATCH,
) -> int:
    """Cancel expired runs and release leases in one bounded transaction.

    PostgreSQL replicas skip deployment rows another replica or Worker owns.
    The caller commits after this function; a failed transaction rolls back all
    run, health, canary, and audit changes together.
    """
    if session_namespace(db) is None:
        raise ValueError("Collector lease reconciler requires a bound namespace")
    if not 1 <= limit <= MAX_LEASE_BATCH:
        raise ValueError(f"limit must be between 1 and {MAX_LEASE_BATCH}")
    require_locking_transaction(db, purpose="Collector lease reconciliation")
    now = now or utcnow()
    deployments = list(db.scalars(
        select(CollectorDeployment)
        .where(
            CollectorDeployment.lease_token_hash.is_not(None),
            or_(
                CollectorDeployment.lease_expires_at.is_(None),
                CollectorDeployment.lease_expires_at < now,
            ),
        )
        .order_by(CollectorDeployment.lease_expires_at, CollectorDeployment.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
        .execution_options(populate_existing=True)
    ).all())
    for deployment in deployments:
        cancelled = cancel_abandoned_runs(db, deployment, now=now)
        if not cancelled:
            record_audit_event(
                db,
                event_type="collector.deployment.orphan_lease_expired",
                actor_type="service",
                actor_id="collector.lease_reconciler",
                entity_type="collector_deployment",
                entity_id=deployment.id,
                outcome="failure",
                details={"worker_id": deployment.lease_worker_id},
            )
        deployment.lease_worker_id = None
        deployment.lease_token_hash = None
        deployment.lease_expires_at = None
        deployment.last_finished_at = now
        if deployment.execution_mode == CollectorDeploymentMode.ON_DEMAND:
            deployment.next_run_at = None
        elif deployment.enabled:
            deployment.next_run_at = now + timedelta(
                seconds=deployment.schedule_seconds
            )
        deployment.updated_at = now
    return len(deployments)


def reconcile_orphan_runs(
    db: Session, *, now: datetime | None = None, limit: int = MAX_LEASE_BATCH,
) -> int:
    """Close running rows whose lease vanished or belongs to a newer run.

    Candidate reads are advisory. The deployment and run are re-read under
    locks in that order, so a concurrent claim or Worker completion wins cleanly.
    A valid newer lease is never cleared by this legacy repair.
    """
    if session_namespace(db) is None:
        raise ValueError("Collector orphan reconciler requires a bound namespace")
    if not 1 <= limit <= MAX_LEASE_BATCH:
        raise ValueError(f"limit must be between 1 and {MAX_LEASE_BATCH}")
    require_locking_transaction(db, purpose="Collector orphan reconciliation")
    now = now or utcnow()
    candidates = list(db.execute(
        select(CollectorRun.id, CollectorRun.deployment_id)
        .join(CollectorDeployment, CollectorRun.deployment_id == CollectorDeployment.id)
        .where(
            CollectorRun.status == CollectorRunStatus.RUNNING,
            or_(
                CollectorDeployment.lease_token_hash.is_(None),
                CollectorDeployment.lease_worker_id.is_(None),
                CollectorDeployment.lease_token_hash != CollectorRun.lease_token_hash,
                CollectorDeployment.lease_worker_id != CollectorRun.worker_id,
            ),
        )
        .order_by(CollectorRun.started_at, CollectorRun.id)
        .limit(limit)
    ).all())
    cancelled = 0
    for run_id, deployment_id in candidates:
        deployment = db.scalar(
            select(CollectorDeployment)
            .where(CollectorDeployment.id == deployment_id)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
        if deployment is None:
            continue
        run = db.scalar(
            select(CollectorRun)
            .where(CollectorRun.id == run_id)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
        if run is None or run.status != CollectorRunStatus.RUNNING:
            continue
        if (
            deployment.lease_token_hash == run.lease_token_hash
            and deployment.lease_worker_id == run.worker_id
        ):
            continue
        _cancel_run(db, run, deployment, now=now, orphan=True)
        if deployment.lease_token_hash is None:
            if deployment.execution_mode == CollectorDeploymentMode.ON_DEMAND:
                deployment.next_run_at = None
            elif deployment.enabled:
                deployment.next_run_at = now + timedelta(
                    seconds=deployment.schedule_seconds
                )
        deployment.updated_at = now
        cancelled += 1
    return cancelled
