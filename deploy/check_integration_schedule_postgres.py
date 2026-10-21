"""Real PostgreSQL leases, atomicity and restricted grants; synthetic source only."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
from threading import Event
import time

from check_monitoring_integrations_postgres import main


def verify(engine, identifier, principal):
    from sqlalchemy import select, text, func
    from sqlalchemy.orm import Session
    from sqlalchemy.exc import DBAPIError
    from icheck.database import set_session_namespace
    from icheck.models import (MonitoringIntegrationSchedule as Schedule, MonitoringIntegrationSync as Sync,
                              MonitoringIntegrationResource as Resource, Device)
    from icheck.integration_schemas import ConnectionUpdate, ScheduleUpdate
    from icheck.services import monitoring_integrations as service, integration_scheduling as scheduler
    from icheck.worker_database_roles import inspect_worker_grants

    class Source:
        hosts = [str(i) for i in range(1, 1002)]
        calls = 0
        def __init__(self, endpoint, token, **bounds):
            assert token == "synthetic-integration-token"
        def request(self, payload, **bounds):
            Source.calls += 1
            if payload["method"] == "apiinfo.version":
                result = "7.4.2"
            elif payload["params"]["output"] == ["hostid"]:
                result = [{"hostid": host} for host in self.hosts]
            else:
                result = [{"hostid": host, "host": "fixture", "name": "Device " + host, "status": "0",
                           "hostgroups": [{"groupid": "2"}]} for host in payload["params"]["hostids"]]
            return {"jsonrpc": "2.0", "id": payload["id"], "result": result}
    service.TRANSPORT = Source

    with engine.begin() as db:
        db.exec_driver_sql("CREATE ROLE integration_scheduler LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION")
        db.exec_driver_sql("REVOKE TEMP ON DATABASE integration_acceptance FROM PUBLIC")
        db.exec_driver_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    grants = inspect_worker_grants(os.environ["ICHECK_DATABASE_URL"], profile="integration-sync-worker",
                                  role="integration_scheduler", apply=True)
    assert grants["complete"] and not grants["unrelated_table_or_column_access"]

    def bind(db, role="integration_scheduler"):
        db.execute(text("SET LOCAL ROLE " + role))
        set_session_namespace(db, principal.tenant_id, principal.region_id)

    with Session(engine, expire_on_commit=False) as db:
        bind(db, "integration_runtime")
        row = service.update_connection(db, identifier, ConnectionUpdate(expected_revision=2, enabled=True), principal)
        revision = row.revision
        bind(db, "integration_runtime")
        scheduler.update(db, identifier, ScheduleUpdate(expected_revision=revision, expected_schedule_revision=0,
            enabled=True, confirm=True, interval_seconds=300), principal)

    def claim():
        with Session(engine, expire_on_commit=False) as db:
            bind(db)
            return scheduler.claim_due(db)
    def execute(lease):
        with Session(engine, expire_on_commit=False) as db:
            bind(db)
            return scheduler.execute(db, lease)

    # A concurrent process sees SKIP LOCKED, not a second claim or a long wait.
    with ThreadPoolExecutor(max_workers=1) as pool:
        with Session(engine) as db:
            bind(db, "integration_runtime")
            service.connection(db, identifier, principal, lock=True)
            assert pool.submit(claim).result(timeout=5) is None
    lease = claim()
    assert lease and claim() is None
    assert not execute(replace(lease, token="wrong")) and Source.calls == 0
    assert execute(lease)
    # Duplicate execution waits for the connection mutex, then observes the
    # committed lease receipt and performs no second source call.
    lease = claim()
    waiting = Event()
    pid = []
    def duplicate():
        with Session(engine, expire_on_commit=False) as db:
            bind(db)
            pid.append(db.scalar(text("SELECT pg_backend_pid()")))
            waiting.set()
            return scheduler.execute(db, lease)
    calls = Source.calls
    with ThreadPoolExecutor(max_workers=1) as pool:
        with Session(engine, expire_on_commit=False) as db:
            bind(db)
            scheduler._owned(db, lease)
            pending = pool.submit(duplicate)
            assert waiting.wait(5)
            deadline = time.monotonic() + 5
            with engine.connect() as observer:
                while not observer.scalar(text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"), {"pid": pid[0]}):
                    assert not pending.done() and time.monotonic() < deadline
                    time.sleep(0.01)
            assert scheduler.execute(db, lease)
        assert pending.result(timeout=5) is False
    assert Source.calls == calls + 2
    while lease := claim():
        assert execute(lease)
    with Session(engine) as db:
        bind(db)
        assert db.scalar(select(Sync)).cursor == 1001
        assert db.scalar(select(Schedule)).last_success_at
        assert db.scalar(select(func.count()).select_from(Resource)) == 1001

    # Crash after claim: committed progress survives; expiration fences stale work.
    with engine.begin() as db:
        db.execute(text("UPDATE monitoring_integration_schedules SET next_run_at=now()-interval '1 second'"))
    stale = claim()
    with engine.begin() as db:
        db.execute(text("UPDATE monitoring_integration_schedules SET lease_expires_at=now()-interval '1 second'"))
    assert not execute(stale) and claim() is None
    with engine.begin() as db:
        assert db.scalar(text("SELECT last_error FROM monitoring_integration_schedules")) == "worker_interrupted"
        db.execute(text("UPDATE monitoring_integration_schedules SET next_run_at=now()-interval '1 second'"))
    fresh = claim()
    assert fresh.token != stale.token and not execute(stale)
    Source.hosts = []
    with engine.begin() as db:
        db.execute(text("UPDATE monitoring_integration_syncs SET updated_at=now()-interval '31 days' WHERE status='completed'"))
    assert execute(fresh)
    with engine.begin() as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 1001
        assert db.scalar(select(func.count()).select_from(Device)) == 0
        assert db.scalar(text("SELECT count(*) FROM monitoring_integration_syncs WHERE CAST(host_ids AS TEXT)='null'")) == 1
        # Worker cannot authorize a schedule, change scope or read other secrets.
        db.exec_driver_sql("SET LOCAL ROLE integration_scheduler")
        for statement in ("UPDATE monitoring_integration_schedules SET enabled=true",
                          "UPDATE monitoring_integration_connections SET group_ids='[]'",
                          "SELECT * FROM ai_managed_connections",
                          "DELETE FROM monitoring_integration_resources"):
            try:
                with db.begin_nested():
                    db.execute(text(statement))
            except DBAPIError:
                pass
            else:
                raise AssertionError("Worker acquired unrelated authority")
        assert db.scalar(text("SELECT row_security_active('monitoring_integration_schedules')"))
        assert db.scalar(text("SELECT count(*) FROM monitoring_integration_schedules")) == 0
        db.execute(text("SELECT set_config('icheck.tenant_id',:t,true),set_config('icheck.region_id',:r,true)"),
                   {"t": principal.tenant_id, "r": principal.region_id})
        assert db.scalar(text("SELECT count(*) FROM monitoring_integration_schedules")) == 1
        db.execute(text("SELECT set_config('icheck.region_id','foreign',true)"))
        assert db.scalar(text("SELECT count(*) FROM monitoring_integration_schedules")) == 0
    # A configuration change revokes already acquired execution authority.
    with engine.begin() as db:
        db.execute(text("UPDATE monitoring_integration_schedules SET next_run_at=now()-interval '1 second'"))
    stale = claim()
    calls = Source.calls
    with Session(engine) as db:
        bind(db, "integration_runtime")
        service.update_connection(db, identifier, ConnectionUpdate(expected_revision=revision, enabled=False), principal)
    assert not execute(stale) and claim() is None and Source.calls == calls
    return ["restricted_worker_grants", "skip_locked_claim", "duplicate_lease_fence", "1001_host_background_scan",
            "expired_lease_recovery", "empty_scan_retains_inventory", "no_native_enrollment",
            "schedule_nonowner_rls", "worker_cannot_enable_or_change_scope", "connection_change_revokes_claim",
            "manifest_compaction_preserves_inventory"]


if __name__ == "__main__":
    main(extra_checks=verify)
