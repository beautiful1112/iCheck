"""Opt-in source inventory scheduling, fenced leases and bounded retry.

Trusted local controllers only. Browser authorization lives in read/update;
workers cannot enable schedules or change connection credentials and scopes.
"""
from dataclasses import dataclass
from datetime import UTC, timedelta
from types import SimpleNamespace

from sqlalchemy import String, cast, or_, select

from ..database import require_locking_transaction, validate_session_namespace
from ..integration_schemas import ScheduleRead
from ..models import (MonitoringIntegrationConnection as Connection, MonitoringIntegrationSync as Sync,
                      MonitoringIntegrationSchedule as Schedule, new_id, utcnow)
from . import monitoring_integrations as integrations
from .authorization_scope import namespace_clause

LEASE_SECONDS = 90  # Longer than the existing 30-second source transport budget.
TRANSIENT = {"source_timeout", "source_unavailable", "worker_interrupted"}


def aware(value):
    return value.replace(tzinfo=UTC) if value and value.tzinfo is None else value


def read(db, identifier, principal):
    row = integrations.connection(db, identifier, principal)
    schedule = db.scalar(select(Schedule).where(Schedule.connection_id == row.id, namespace_clause(Schedule, principal)))
    return schedule or ScheduleRead(connection_id=row.id, connection_revision=row.revision)


def update(db, identifier, payload, principal):
    integrations.guard(db, principal, manage=True)
    row = integrations.connection(db, identifier, principal, lock=True)
    integrations._revision(row, payload.expected_revision)
    schedule = db.scalar(select(Schedule).where(Schedule.connection_id == row.id, namespace_clause(Schedule, principal))
                         .with_for_update().execution_options(populate_existing=True))
    if (schedule.revision if schedule else 0) != payload.expected_schedule_revision:
        raise integrations.IntegrationConflict("Schedule changed; refresh before continuing")
    if payload.enabled and (not row.enabled or not row.group_ids):
        raise integrations.IntegrationConflict("Enable a connection with a saved group scope first")
    if schedule is None:
        schedule = Schedule(connection_id=row.id, tenant_id=row.tenant_id, region_id=row.region_id, revision=0)
        db.add(schedule)
    schedule.revision += 1
    schedule.connection_revision = row.revision
    schedule.enabled = payload.enabled
    schedule.interval_seconds, schedule.retention_days = payload.interval_seconds, payload.retention_days
    schedule.next_run_at = utcnow() if payload.enabled else None
    schedule.lease_token = schedule.lease_expires_at = None
    schedule.failures, schedule.last_error = 0, None
    schedule.updated_at, schedule.updated_by = utcnow(), principal.subject
    integrations.audit(db, row, principal, "schedule_updated", {"schedule_revision": schedule.revision,
        "connection_revision": row.revision, "enabled": schedule.enabled, "interval_seconds": schedule.interval_seconds,
        "manifest_retention_days": schedule.retention_days})
    db.commit()
    return schedule


def worker_actor(db):
    tenant, region = validate_session_namespace(db)
    return SimpleNamespace(tenant_id=tenant, region_id=region, principal_type="worker", subject="integration-sync-worker")


@dataclass(frozen=True)
class Claim:
    connection_id: str
    token: str
    revision: int
    tenant_id: str
    region_id: str


def _failure(schedule, code, now):
    schedule.failures += 1
    schedule.last_error = code
    # Two quick retries, then the normal interval. No catch-up storm after downtime.
    retry = code in TRANSIENT and schedule.failures < 3
    delay = 30 * 2 ** (schedule.failures - 1) if retry else schedule.interval_seconds
    schedule.next_run_at = now + timedelta(seconds=delay)
    schedule.lease_token = schedule.lease_expires_at = None


def claim_due(db):
    actor = worker_actor(db)
    require_locking_transaction(db, purpose="Integration scheduling")
    now = utcnow()
    # All paths lock connection before schedule. SKIP LOCKED shares different
    # connections across processes without racing a manual configuration change.
    row = db.scalar(select(Connection).join(Schedule, Schedule.connection_id == Connection.id).where(
        namespace_clause(Connection, actor), namespace_clause(Schedule, actor), Connection.enabled.is_(True),
        Schedule.enabled.is_(True), Schedule.connection_revision == Connection.revision,
        Schedule.next_run_at <= now, or_(Schedule.lease_expires_at.is_(None), Schedule.lease_expires_at <= now))
        .order_by(Schedule.next_run_at, Connection.id).limit(1).with_for_update(skip_locked=True, of=Connection)
        .execution_options(populate_existing=True))
    if row is None:
        db.rollback()
        return None
    schedule = db.scalar(select(Schedule).where(Schedule.connection_id == row.id, namespace_clause(Schedule, actor))
                         .with_for_update().execution_options(populate_existing=True))
    if (not schedule.enabled or not row.enabled or not row.group_ids or schedule.connection_revision != row.revision
        or not schedule.next_run_at or aware(schedule.next_run_at) > now
        or (schedule.lease_expires_at and aware(schedule.lease_expires_at) > now)):
        db.rollback()
        return None
    if schedule.lease_token:
        _failure(schedule, "worker_interrupted", now)
        integrations.audit(db, row, actor, "lease_recovered", {"failures": schedule.failures})
        db.commit()
        return None
    # An interval has elapsed after an exhausted/permanent failure: allow a new
    # bounded retry cycle, preserving the last error until actual success.
    if schedule.failures >= 3 or schedule.last_error not in TRANSIENT:
        schedule.failures = 0
    schedule.lease_token = new_id()
    schedule.lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
    schedule.last_attempt_at = now
    claim = Claim(row.id, schedule.lease_token, schedule.revision, actor.tenant_id, actor.region_id)
    db.commit()
    return claim


def _owned(db, claim):
    actor = worker_actor(db)
    if (actor.tenant_id, actor.region_id) != (claim.tenant_id, claim.region_id):
        raise PermissionError("Integration claim belongs to another workspace")
    require_locking_transaction(db, purpose="Integration lease fencing")
    row = db.scalar(select(Connection).where(Connection.id == claim.connection_id, namespace_clause(Connection, actor))
                    .with_for_update().execution_options(populate_existing=True))
    schedule = db.scalar(select(Schedule).where(Schedule.connection_id == claim.connection_id, namespace_clause(Schedule, actor))
                         .with_for_update().execution_options(populate_existing=True))
    if not row or not schedule or not row.enabled or not schedule.enabled or not row.group_ids:
        return None
    if (schedule.revision != claim.revision or schedule.lease_token != claim.token
        or schedule.connection_revision != row.revision or not schedule.lease_expires_at
        or aware(schedule.lease_expires_at) <= utcnow()):
        return None
    return row, schedule, actor


def _compact(db, schedule, actor, now):
    # Retain summaries, audit, resource observations and any resumable cursor.
    # Only bulky manifests from terminal scans expire; no DELETE authority needed.
    query = select(Sync).where(Sync.connection_id == schedule.connection_id, namespace_clause(Sync, actor),
        Sync.status.in_(["completed", "superseded"]), cast(Sync.host_ids, String) != "null",
        Sync.updated_at < now - timedelta(days=schedule.retention_days))
    if schedule.active_run_id:
        query = query.where(Sync.id != schedule.active_run_id)
    for run in db.scalars(query.order_by(Sync.updated_at, Sync.id).limit(100)):
        run.host_ids = None


def execute(db, claim):
    owned = _owned(db, claim)
    if owned is None:
        db.rollback()
        return False
    row, schedule, actor = owned
    run = db.scalar(select(Sync).where(Sync.id == schedule.active_run_id, Sync.connection_id == row.id,
        namespace_clause(Sync, actor))) if schedule.active_run_id else None
    if run and run.can_resume and run.connection_revision == row.revision:
        run = integrations._step_locked(db, row, run.id, run.cursor, actor)
    else:
        run = integrations._start_locked(db, row, actor)
    schedule.active_run_id = run.id
    now = utcnow()
    if aware(schedule.lease_expires_at) <= now:
        db.rollback()  # Even an unexpectedly slow transport cannot commit an expired claim.
        return False
    if run.status == "failed":
        _failure(schedule, run.error_code or "source_unavailable", now)
    else:
        schedule.failures, schedule.last_error = 0, None
        schedule.lease_token = schedule.lease_expires_at = None
        if run.status == "completed":
            schedule.last_success_at = now
            schedule.active_run_id = None
            schedule.next_run_at = now + timedelta(seconds=schedule.interval_seconds)
        else:
            schedule.next_run_at = now
    _compact(db, schedule, actor, now)
    db.commit()  # The page, cursor and schedule receipt have one atomic outcome.
    return True


def record_worker_failure(db, claim):
    owned = _owned(db, claim)
    if owned:
        row, schedule, actor = owned
        _failure(schedule, "worker_failed", utcnow())
        integrations.audit(db, row, actor, "worker_failed", {"error_code": "worker_failed"})
        db.commit()
    else:
        db.rollback()
