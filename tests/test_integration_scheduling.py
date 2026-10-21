"""Scheduled inventory uses synthetic transport only; no running services."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from icheck.auth import current_principal
from icheck.database import SessionLocal, set_session_namespace, DEFAULT_TENANT_ID, DEFAULT_REGION_ID
from icheck.main import app
from icheck.models import (MonitoringIntegrationSchedule as Schedule, MonitoringIntegrationSync as Sync,
                          MonitoringIntegrationResource as Resource, Device)
from icheck.services import integration_scheduling as scheduler, monitoring_integrations as integrations
from icheck.services.control_plane_auth import development_principal
from icheck import integration_sync_worker as worker
from icheck.worker_namespace import WorkerNamespace
from test_monitoring_integrations import protected_configuration, saved, BASE, TOKEN
from test_integration_discovery_sync import source, enabled, start, step


@pytest.fixture
def clock(monkeypatch):
    clock = SimpleNamespace(now=datetime(2026, 10, 20, 12, tzinfo=UTC))
    monkeypatch.setattr(scheduler, "utcnow", lambda: clock.now)
    return clock


def bound():
    db = SessionLocal()
    set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
    return db


def schedule_path(row):
    return f"{BASE}/{row['id']}/schedule"


def configure(client, row, **overrides):
    current = client.get(schedule_path(row)).json()
    return client.put(schedule_path(row), json={"expected_revision": row["revision"],
        "expected_schedule_revision": current["revision"], "enabled": True, "confirm": True,
        "interval_seconds": 300, "retention_days": 7, **overrides})


def claim():
    with bound() as db:
        return scheduler.claim_due(db)


def execute(claim):
    with bound() as db:
        return scheduler.execute(db, claim)


def tick():
    lease = claim()
    return execute(lease) if lease else False


def state(client, row):
    return client.get(schedule_path(row)).json()


def test_default_off_explicit_enable_no_network_and_redacted_status(client, source, clock):
    row = saved(client)
    assert state(client, row)["revision"] == 0
    assert configure(client, row).status_code == 409
    assert claim() is None
    row = client.put(f"{BASE}/{row['id']}", json={"expected_revision": 1, "enabled": True}).json()
    response = configure(client, row)
    assert response.status_code == 200, response.text
    assert response.json()["enabled"] and response.json()["revision"] == 1
    assert source.calls == []
    assert TOKEN not in response.text and "lease_token" not in response.text
    assert client.get(f"{BASE}/{row['id']}").json()["revision"] == row["revision"]
    assert client.post(f"{BASE}/{row['id']}/syncs", json={"expected_revision": row["revision"], "confirm": True}).status_code == 409


@pytest.mark.parametrize("overrides", [{"confirm": False}, {"interval_seconds": 299}, {"interval_seconds": 86401},
    {"interval_seconds": True}, {"retention_days": 6}, {"retention_days": 366}, {"enabled": "yes"},
    {"expected_schedule_revision": -1}, {"lease_token": "injected"}])
def test_schedule_input_bounds(client, source, overrides):
    row = enabled(client)
    assert configure(client, row, **overrides).status_code == 422
    assert not state(client, row)["enabled"] and not source.calls


def test_revision_guards_and_read_only_authority(client, source):
    row = enabled(client)
    assert configure(client, row).status_code == 200
    assert configure(client, row, expected_schedule_revision=0).status_code == 409
    assert configure(client, row, expected_revision=1).status_code == 409
    principal = replace(development_principal(), permissions=frozenset({"metrics.read"}))
    app.dependency_overrides[current_principal] = lambda: principal
    assert client.get(schedule_path(row)).status_code == 200
    assert configure(client, row).status_code == 403
    principal = replace(principal, authorization_scope={"sites": ["LAB"]})
    assert client.get(schedule_path(row)).status_code == 403
    assert not source.calls


def test_worker_batches_resume_across_sessions_and_next_interval(client, source, clock):
    row = enabled(client)
    configure(client, row)
    lease = claim()
    assert lease and claim() is None
    assert execute(lease)
    for expected in (250, 500, 501):
        assert tick()
        with bound() as db:
            run = db.scalar(select(Sync))
            assert run.cursor == expected
    saved_schedule = state(client, row)
    assert saved_schedule["last_success_at"] == clock.now.isoformat().replace("+00:00", "Z")
    assert saved_schedule["active_run_id"] is None and saved_schedule["last_error"] is None
    assert claim() is None
    with bound() as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 501
        assert db.scalar(select(func.count()).select_from(Device)) == 0
    clock.now += timedelta(seconds=300)
    assert tick()
    with bound() as db:
        assert db.scalar(select(func.count()).select_from(Sync)) == 2


def test_page_failure_bounded_backoff_keeps_cursor_and_later_resumes(client, source, clock):
    row = enabled(client)
    configure(client, row)
    assert tick() and tick()
    source.failing = True
    for attempt, delay in [(1, 30), (2, 60), (3, 300)]:
        assert tick()
        schedule = state(client, row)
        assert schedule["failures"] == attempt and schedule["last_error"] == "source_timeout"
        assert datetime.fromisoformat(schedule["next_run_at"]) == clock.now + timedelta(seconds=delay)
        assert claim() is None
        with bound() as db:
            assert db.scalar(select(Sync)).cursor == 250
            assert db.scalar(select(func.count()).select_from(Resource)) == 250
        clock.now += timedelta(seconds=delay)
    source.failing = False
    assert tick() and tick()
    assert state(client, row)["last_error"] is None
    with bound() as db:
        assert db.scalar(select(Sync)).cursor == 501


def test_manifest_failure_retries_without_creating_imported_rows(client, source, clock):
    row = enabled(client)
    configure(client, row)
    source.failing = True
    assert tick()
    assert state(client, row)["last_error"] == "source_timeout"
    source.failing = False
    clock.now += timedelta(seconds=30)
    assert tick() and tick()
    with bound() as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 250


def test_permanent_failure_waits_normal_interval_and_never_deletes(client, source, clock):
    row = enabled(client)
    configure(client, row)
    assert tick() and tick()
    source.outside_scope = True
    assert tick()
    schedule = state(client, row)
    assert schedule["last_error"] == "source_scope_mismatch"
    assert datetime.fromisoformat(schedule["next_run_at"]) == clock.now + timedelta(seconds=300)
    with bound() as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 250


def test_pause_and_connection_change_fence_claims_and_do_not_erase_inventory(client, source, clock):
    row = enabled(client)
    configure(client, row)
    assert tick() and tick()
    lease = claim()
    before = len(source.calls)
    assert configure(client, row, enabled=False).status_code == 200
    assert not execute(lease) and claim() is None and len(source.calls) == before
    assert configure(client, row).status_code == 200
    lease = claim()
    changed = client.put(f"{BASE}/{row['id']}", json={"expected_revision": row["revision"],
        "enabled": True, "group_ids": ["2"]}).json()
    assert not state(client, changed)["enabled"] and state(client, changed)["last_error"] == "connection_changed"
    assert not execute(lease) and claim() is None and len(source.calls) == before
    with bound() as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 250


def test_expired_lease_recovery_fences_old_worker_and_bounds_crash_retries(client, source, clock):
    row = enabled(client)
    configure(client, row)
    stale = claim()
    assert not execute(replace(stale, token="wrong")) and source.calls == []
    for attempt, delay in [(1, 30), (2, 60), (3, 300)]:
        clock.now += timedelta(seconds=91)
        assert not execute(stale)
        assert claim() is None  # Recovery schedules a delayed retry, not immediate I/O.
        assert state(client, row)["failures"] == attempt
        assert state(client, row)["last_error"] == "worker_interrupted"
        clock.now += timedelta(seconds=delay)
        fresh = claim()
        assert fresh.token != stale.token and not execute(stale)
        stale = fresh
    assert execute(fresh) and len(source.calls) == 2


def test_lease_expiring_during_source_read_rolls_back_progress(client, source, clock, monkeypatch):
    row = enabled(client)
    configure(client, row)
    lease = claim()
    original = integrations._start_locked
    def slow(*args):
        result = original(*args)
        clock.now += timedelta(seconds=91)
        return result
    monkeypatch.setattr(integrations, "_start_locked", slow)
    assert not execute(lease)
    with bound() as db:
        assert db.scalar(select(func.count()).select_from(Sync)) == 0
        assert db.scalar(select(Schedule)).lease_token == lease.token


def test_schedule_can_adopt_manual_progress_and_pause_back_to_manual(client, source, clock):
    row = enabled(client)
    run = step(client, row, start(client, row))
    configure(client, row)
    assert tick()  # Adopt the same scan, no duplicate manifest.
    assert tick()
    with bound() as db:
        assert db.scalar(select(Sync)).id == run["id"]
        assert db.scalar(select(Sync)).cursor == 500
    configure(client, row, enabled=False)
    manual = start(client, row)
    assert step(client, row, manual)["status"] == "completed"


def test_compaction_keeps_summaries_resources_and_resumable_manifests(client, source, clock):
    source.hosts = ["100"]
    row = enabled(client)
    old = step(client, row, start(client, row))
    with bound() as db:
        db.get(Sync, old["id"]).updated_at = clock.now - timedelta(days=8)
        db.commit()
    run = start(client, row)
    with bound() as db:
        db.get(Sync, run["id"]).updated_at = clock.now - timedelta(days=8)
        db.commit()
    configure(client, row)
    assert tick()
    with bound() as db:
        assert db.get(Sync, old["id"]).host_ids is None
        assert db.get(Sync, run["id"]).host_ids == ["100"]
        assert db.scalar(select(func.count()).select_from(Resource)) == 1
        assert db.scalar(select(func.count()).select_from(Sync)) == 2


def test_unexpected_worker_failure_rolls_back_page_and_records_safe_error(client, source, clock, monkeypatch):
    row = enabled(client)
    configure(client, row)
    assert tick()
    original = integrations._step_locked
    def broken(*args):
        original(*args)
        raise RuntimeError(TOKEN)
    monkeypatch.setattr(integrations, "_step_locked", broken)
    ns = WorkerNamespace(DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
    assert not worker.dispatch_once(ns)
    schedule = state(client, row)
    assert schedule["last_error"] == "worker_failed" and TOKEN not in str(schedule)
    with bound() as db:
        assert db.scalar(select(Sync)).cursor == 0
        assert db.scalar(select(func.count()).select_from(Resource)) == 0


def test_claim_cannot_be_moved_to_another_namespace(client, source, clock):
    row = enabled(client)
    configure(client, row)
    lease = claim()
    with pytest.raises(PermissionError):
        execute(replace(lease, region_id="foreign"))
    assert source.calls == []


def test_compaction_moves_past_previously_compacted_json_nulls(client, source, clock):
    row = enabled(client)
    configure(client, row)
    with bound() as db:
        for index in range(102):
            db.add(Sync(id=f"fixture-{index:03}", connection_id=row["id"], connection_revision=row["revision"],
                status="completed", host_ids=["100"], cursor=1, total=1, observed=1,
                created_by="fixture", updated_at=clock.now - timedelta(days=8)))
        db.commit()
    assert tick() and tick()
    with bound() as db:
        old = db.scalars(select(Sync).where(Sync.id.like("fixture-%"))).all()
        assert len(old) == 102 and all(run.host_ids is None for run in old)
