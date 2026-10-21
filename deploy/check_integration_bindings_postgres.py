"""Real PostgreSQL transactions with synthetic source data; never production."""
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
    from icheck.integration_schemas import ConnectionUpdate, ConnectionTest, SyncStep, AssetBindingsUpdate
    from icheck.models import Device, DeviceMonitoringEnrollment, MonitoringIntegrationBinding as Binding
    from icheck.services import monitoring_integrations as integrations, integration_bindings as bindings
    from icheck.worker_database_roles import inspect_worker_grants

    class Source:
        calls = 0

        def __init__(self, endpoint, token, **bounds):
            assert token == "synthetic-integration-token"

        def request(self, payload, **bounds):
            Source.calls += 1
            if payload["method"] == "apiinfo.version":
                result = "7.4.2"
            elif payload["params"]["output"] == ["hostid"]:
                result = [{"hostid": str(i)} for i in range(1, 1002)]
            else:
                result = [{"hostid": host, "host": "fixture", "name": "Device " + host, "status": "0",
                           "hostgroups": [{"groupid": "2"}]} for host in payload["params"]["hostids"]]
            return {"jsonrpc": "2.0", "id": payload["id"], "result": result}

    integrations.TRANSPORT = Source
    with engine.begin() as db:
        db.exec_driver_sql("GRANT SELECT,INSERT,UPDATE ON monitoring_integration_bindings TO integration_runtime")
        db.exec_driver_sql("GRANT SELECT,UPDATE ON devices TO integration_runtime")
        db.exec_driver_sql("CREATE ROLE mapping_sync_worker LOGIN NOSUPERUSER NOBYPASSRLS")
        db.exec_driver_sql("REVOKE TEMP ON DATABASE integration_acceptance FROM PUBLIC")
        db.exec_driver_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    inspect_worker_grants(str(engine.url), profile="integration-sync-worker", role="mapping_sync_worker", apply=True)
    with Session(engine) as db:
        db.add_all([Device(name=f"Device {i}", kind="network", tenant_id=principal.tenant_id,
                           region_id=principal.region_id) for i in range(1, 1002)])
        db.commit()

    def runtime(db):
        db.execute(text("SET LOCAL ROLE integration_runtime"))
        set_session_namespace(db, principal.tenant_id, principal.region_id)

    with Session(engine, expire_on_commit=False) as db:
        runtime(db)
        row = integrations.update_connection(db, identifier, ConnectionUpdate(expected_revision=2, enabled=True), principal)
        revision = row.revision
        runtime(db)
        run = integrations.start_sync(db, identifier, ConnectionTest(expected_revision=revision, confirm=True), principal)
        while run.can_resume:
            runtime(db)
            run = integrations.sync_step(db, identifier, run.id,
                SyncStep(expected_revision=revision, expected_cursor=run.cursor, confirm=True), principal)
        runtime(db)
        view = bindings.listing(db, identifier, principal, limit=1000)
        second = bindings.listing(db, identifier, principal, limit=1000, offset=1000)
        assert view["total"] == 1001 and len(second["items"]) == 1
    calls = Source.calls

    def payload(view, items):
        return AssetBindingsUpdate(expected_revision=revision, expected_scan_id=view["scan_id"], confirm=True, items=[{
            "resource_id": item["resource_id"], "source_name": item["name"], "expected_binding_revision": item["binding_revision"],
            "device_id": item["suggestion"]["id"], "expected_device_revision": item["suggestion"]["revision"],
            "expected_device_identity_revision": item["suggestion"]["identity_revision"]} for item in items])

    first = payload(view, view["items"][:1])
    started, pid = Event(), []

    def compete():
        with Session(engine) as db:
            runtime(db)
            db.execute(text("SET LOCAL lock_timeout='5s'"))
            pid.append(db.scalar(text("SELECT pg_backend_pid()")))
            started.set()
            try:
                bindings.update(db, identifier, first, principal)
            except integrations.IntegrationConflict:
                return "conflict"
            raise AssertionError("Concurrent stale binding approval succeeded")

    def wait_blocked(pending):
        assert started.wait(5)
        deadline = time.monotonic() + 4
        with engine.connect() as observer:
            while not observer.scalar(text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"), {"pid": pid[0]}):
                assert not pending.done() and time.monotonic() < deadline, "Expected real PostgreSQL row-lock contention"
                time.sleep(0.01)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with Session(engine) as db:
            runtime(db)
            integrations.connection(db, identifier, principal, lock=True)
            pending = pool.submit(compete)
            wait_blocked(pending)
            assert bindings.update(db, identifier, first, principal)["linked"] == 1
        assert pending.result(timeout=10) == "conflict"
    with Session(engine) as db:
        runtime(db)
        assert bindings.update(db, identifier, payload(view, view["items"][1:] + second["items"]), principal)["linked"] == 1000
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Binding)) == 1001
        assert db.scalar(select(func.count()).select_from(Device)) == 1001
        assert db.scalar(select(func.count()).select_from(DeviceMonitoringEnrollment)) == 0
    assert Source.calls == calls

    # A selected asset identity correction must serialize with approval too.
    with Session(engine) as db:
        runtime(db)
        current = bindings.listing(db, identifier, principal, limit=1)
    item = current["items"][0]
    item["suggestion"] = item["device"]
    first = payload(current, [item])
    started.clear()
    pid.clear()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with Session(engine) as db:
            device = db.get(Device, item["device"]["id"], with_for_update=True)
            device.identity_revision += 1
            pending = pool.submit(compete)
            wait_blocked(pending)
            db.commit()
        assert pending.result(timeout=10) == "conflict"
    with Session(engine) as db:
        runtime(db)
        assert bindings.listing(db, identifier, principal, limit=1)["items"][0]["reason"] == "asset_identity_changed"

    with engine.begin() as db:
        db.exec_driver_sql("SET LOCAL ROLE integration_runtime")
        assert db.scalar(text("SELECT row_security_active('monitoring_integration_bindings')"))
        assert db.scalar(text("SELECT count(*) FROM monitoring_integration_bindings")) == 0
        db.execute(text("SELECT set_config('icheck.tenant_id',:t,true),set_config('icheck.region_id',:r,true)"),
                   {"t": principal.tenant_id, "r": principal.region_id})
        assert db.scalar(text("SELECT count(*) FROM monitoring_integration_bindings")) == 1001
        try:
            with db.begin_nested():
                db.execute(text("UPDATE monitoring_integration_bindings SET tenant_id='foreign'"))
        except DBAPIError:
            pass
        else:
            raise AssertionError("Cross-namespace write allowed")
        db.execute(text("SELECT set_config('icheck.region_id','foreign',true)"))
        assert db.scalar(text("SELECT count(*) FROM monitoring_integration_bindings")) == 0
    with engine.begin() as db:
        assert not db.scalar(text("SELECT has_table_privilege('mapping_sync_worker','monitoring_integration_bindings','INSERT')"))
        assert not db.scalar(text("SELECT has_table_privilege('mapping_sync_worker','monitoring_integration_bindings','UPDATE')"))
    migration = importlib.import_module("migrations.versions.e8k0m2p4r6t9_integration_bindings")
    with engine.begin() as db, Operations.context(MigrationContext.configure(db)):
        try:
            migration.downgrade()
        except RuntimeError:
            pass
        else:
            raise AssertionError("Lossy mapping downgrade allowed")
    return ["1001_imported_hosts", "1000_atomic_reviewed_links", "concurrent_binding_revision_guard",
            "asset_identity_correction_fence", "binding_nonowner_rls", "binding_cross_namespace_write_rejected",
            "mapping_creates_no_devices_or_polling", "sync_worker_cannot_approve_mappings", "binding_history_downgrade_guard"]


if __name__ == "__main__":
    main(extra_checks=verify)
