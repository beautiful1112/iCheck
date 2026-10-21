"""Stage-3 PostgreSQL acceptance using only a temporary cluster and fake source."""
from concurrent.futures import ThreadPoolExecutor
import importlib
from threading import Event
import time

from check_monitoring_integrations_postgres import main


def verify(engine, identifier, principal):
    from sqlalchemy import select, text, func
    from sqlalchemy.orm import Session
    from sqlalchemy.exc import DBAPIError
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from icheck.database import set_session_namespace
    from icheck.integration_schemas import ConnectionUpdate, ConnectionTest, SyncStep
    from icheck.models import MonitoringIntegrationResource as Resource, MonitoringIntegrationSync as Sync, Device
    from icheck.services import monitoring_integrations as service

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
    with engine.begin() as connection:
        connection.exec_driver_sql("GRANT SELECT,INSERT,UPDATE,DELETE ON monitoring_integration_syncs,monitoring_integration_resources TO integration_runtime")

    def runtime(db):
        db.execute(text("SET LOCAL ROLE integration_runtime"))
        set_session_namespace(db, principal.tenant_id, principal.region_id)

    with Session(engine, expire_on_commit=False) as db:
        runtime(db)
        row = service.update_connection(db, identifier, ConnectionUpdate(expected_revision=2, enabled=True), principal)
        revision = row.revision
        runtime(db)
        run = service.start_sync(db, identifier, ConnectionTest(expected_revision=revision, confirm=True), principal)
        run_id = run.id
        assert run.total == 1001
    calls = Source.calls
    started = Event()
    pid = []
    payload = SyncStep(expected_revision=revision, expected_cursor=0, confirm=True)

    def competitor():
        with Session(engine) as db:
            runtime(db)
            db.execute(text("SET LOCAL lock_timeout='5s'"))
            pid.append(db.scalar(text("SELECT pg_backend_pid()")))
            started.set()
            try:
                service.sync_step(db, identifier, run_id, payload, principal)
            except service.IntegrationConflict:
                return "conflict"
            raise AssertionError("Two calls advanced the same cursor")

    with ThreadPoolExecutor(max_workers=1) as pool:
        with Session(engine, expire_on_commit=False) as db:
            runtime(db)
            service.connection(db, identifier, principal, lock=True)
            pending = pool.submit(competitor)
            assert started.wait(5)
            deadline = time.monotonic() + 4
            with engine.connect() as observer:
                while not observer.scalar(text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"), {"pid": pid[0]}):
                    assert not pending.done() and time.monotonic() < deadline
                    time.sleep(0.01)
            result = service.sync_step(db, identifier, run_id, payload, principal)
            assert result.cursor == 250
        assert pending.result(timeout=10) == "conflict"
    assert Source.calls == calls + 2
    cursor = 250
    while cursor < 1001:
        with Session(engine, expire_on_commit=False) as db:
            runtime(db)
            result = service.sync_step(db, identifier, run_id, SyncStep(expected_revision=revision,
                                      expected_cursor=cursor, confirm=True), principal)
            cursor = result.cursor
    assert result.status == "completed" and result.observed == 1001
    with engine.begin() as connection:
        assert connection.scalar(select(func.count()).select_from(Resource)) == 1001
        assert connection.scalar(select(func.count()).select_from(Device)) == 0
        connection.exec_driver_sql("SET LOCAL ROLE integration_runtime")
        for table in ("monitoring_integration_resources", "monitoring_integration_syncs"):
            assert connection.scalar(text(f"SELECT row_security_active('{table}')"))
            assert connection.scalar(text(f"SELECT count(*) FROM {table}")) == 0
            connection.execute(text("SELECT set_config('icheck.tenant_id',:t,true),set_config('icheck.region_id',:r,true)"),
                               {"t": principal.tenant_id, "r": principal.region_id})
            assert connection.scalar(text(f"SELECT count(*) FROM {table}")) > 0
            try:
                with connection.begin_nested():
                    connection.execute(text(f"UPDATE {table} SET tenant_id='foreign'"))
            except DBAPIError:
                pass
            else:
                raise AssertionError("Cross-namespace mutation allowed")
            connection.execute(text("SELECT set_config('icheck.region_id','foreign',true)"))
    Source.hosts = []
    with Session(engine, expire_on_commit=False) as db:
        runtime(db)
        empty = service.start_sync(db, identifier, ConnectionTest(expected_revision=revision, confirm=True), principal)
        assert empty.status == "completed" and empty.total == 0
        assert db.scalar(select(func.count()).select_from(Resource)) == 1001
        runtime(db)
        service.update_connection(db, identifier, ConnectionUpdate(expected_revision=revision, enabled=False), principal)
        runtime(db)
        assert service.resources(db, identifier, principal)["total"] == 0
        assert db.scalar(select(func.count()).select_from(Resource)) == 1001
    migration = importlib.import_module("migrations.versions.c6i8k0m2p4r7_integration_discovery_sync")
    with engine.begin() as connection, Operations.context(MigrationContext.configure(connection)):
        try:
            migration.downgrade()
        except RuntimeError:
            pass
        else:
            raise AssertionError("Destructive synchronization downgrade allowed")
    return ["sync_cursor_concurrency", "1001_host_resume", "no_native_device_enrollment", "sync_resource_nonowner_rls",
            "empty_scan_retains_inventory", "changed_scope_hides_old_evidence", "sync_history_downgrade_guard"]


if __name__ == "__main__":
    main(extra_checks=verify)
