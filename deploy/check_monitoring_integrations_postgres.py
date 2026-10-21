"""Private full-chain migration, RLS and revision-lock checks; no live sources."""
from concurrent.futures import ThreadPoolExecutor
import getpass
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
from threading import Event
import time

from check_optional_location_postgres import PG, run


def main(*, target="f9l1n3q5s7u0", extra_checks=None):
    with tempfile.TemporaryDirectory(prefix="icheck-integrations-pg-") as directory:
        root = Path(directory)
        data = root / "data"
        run([str(PG / "initdb"), "-D", str(data), "--auth=trust", "--no-locale", "--encoding=UTF8"])
        run([str(PG / "pg_ctl"), "-D", str(data), "-l", str(root / "postgres.log"),
             "-o", f"-k {root} -c listen_addresses=''", "-w", "start"])
        try:
            run([str(PG / "createdb"), "-h", str(root), "integration_acceptance"])
            os.environ["ICHECK_DATABASE_URL"] = f"postgresql+psycopg://{getpass.getuser()}@/integration_acceptance?host={root}"
            os.environ["ICHECK_AUTO_CREATE_SCHEMA"] = "false"
            os.environ["ICHECK_CONTROL_PLANE_AUTH_MODE"] = "disabled"
            os.environ["ICHECK_MONITORING_INTEGRATION_ALLOWED_ORIGINS"] = "https://zabbix.example.test"

            def migrate(command, target):
                run([sys.executable, "-m", "alembic", "-c", "alembic.ini", command, target])

            migrate("upgrade", "a4g6i8k0m2p5")
            from sqlalchemy import text
            from sqlalchemy.orm import Session
            from sqlalchemy.exc import DBAPIError
            from alembic.migration import MigrationContext
            from alembic.operations import Operations
            from icheck.database import engine, set_session_namespace, DEFAULT_TENANT_ID, DEFAULT_REGION_ID
            from icheck import integration_custody as custody
            from icheck.integration_schemas import ConnectionCreate, ConnectionUpdate
            from icheck.services import monitoring_integrations as service
            from icheck.services.control_plane_auth import development_principal
            from icheck.services.tenancy import ensure_default_namespace

            # Synthetic custody only; never read an installed key or configuration.
            ephemeral_key = os.urandom(32)
            custody.key = lambda: ephemeral_key
            with engine.begin() as connection:
                connection.exec_driver_sql("CREATE TABLE integration_existing_fixture (value TEXT)")
                connection.exec_driver_sql("INSERT INTO integration_existing_fixture VALUES ('preserved')")
            migrate("upgrade", target)
            migrate("downgrade", "a4g6i8k0m2p5")
            migrate("upgrade", target)
            with engine.begin() as connection:
                assert connection.scalar(text("SELECT version_num FROM alembic_version")) == target
                assert connection.scalar(text("SELECT value FROM integration_existing_fixture")) == "preserved"
                connection.exec_driver_sql("CREATE ROLE integration_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS")
                connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO integration_runtime")
                connection.exec_driver_sql("GRANT SELECT,INSERT,UPDATE,DELETE ON monitoring_integration_connections,audit_events TO integration_runtime")
                connection.exec_driver_sql("GRANT SELECT,INSERT,UPDATE,DELETE ON monitoring_integration_syncs,monitoring_integration_resources TO integration_runtime")
                connection.exec_driver_sql("GRANT SELECT,INSERT,UPDATE ON monitoring_integration_schedules TO integration_runtime")
                connection.exec_driver_sql("GRANT SELECT,UPDATE ON monitoring_integration_alert_feeds TO integration_runtime")
                connection.exec_driver_sql("GRANT SELECT ON tenants,regions TO integration_runtime")
            principal = development_principal()
            with Session(engine, expire_on_commit=False) as db:
                ensure_default_namespace(db)
                set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
                row = service.create_connection(db, ConnectionCreate(name="Fixture", api_url="https://zabbix.example.test",
                     group_ids=["2"], token="synthetic-integration-token"), principal)
                identifier, original = row.id, row.encrypted_token
                assert custody.decrypt_token(row) == "synthetic-integration-token"

            def runtime(db):
                db.execute(text("SET LOCAL ROLE integration_runtime"))
                set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)

            with engine.begin() as connection:
                connection.exec_driver_sql("SET LOCAL ROLE integration_runtime")
                assert connection.scalar(text("SELECT row_security_active('monitoring_integration_connections')"))
                assert connection.scalar(text("SELECT count(*) FROM monitoring_integration_connections")) == 0
                connection.execute(text("SELECT set_config('icheck.tenant_id',:tenant,true),set_config('icheck.region_id',:region,true)"),
                                   {"tenant": DEFAULT_TENANT_ID, "region": DEFAULT_REGION_ID})
                assert connection.scalar(text("SELECT count(*) FROM monitoring_integration_connections")) == 1
                with connection.begin_nested():
                    try:
                        with connection.begin_nested():
                            connection.execute(text("UPDATE monitoring_integration_connections SET tenant_id='foreign'"))
                    except DBAPIError:
                        pass
                    else:
                        raise AssertionError("Cross-namespace write was allowed")
                connection.execute(text("SELECT set_config('icheck.region_id','foreign',true)"))
                assert connection.scalar(text("SELECT count(*) FROM monitoring_integration_connections")) == 0

            # Keep one revision locked while another transaction attempts the same
            # update. The waiter must observe the committed revision, not overwrite.
            started = Event()
            contender_pid = []
            def competing_update():
                with Session(engine) as db:
                    runtime(db)
                    db.execute(text("SET LOCAL lock_timeout='5s'"))
                    contender_pid.append(db.scalar(text("SELECT pg_backend_pid()")))
                    started.set()
                    try:
                        service.update_connection(db, identifier, ConnectionUpdate(expected_revision=1, enabled=True), principal)
                    except service.IntegrationConflict:
                        return "conflict"
                    raise AssertionError("Concurrent stale revision was accepted")

            with ThreadPoolExecutor(max_workers=1) as executor:
                with Session(engine) as db:
                    runtime(db)
                    service.connection(db, identifier, principal, lock=True)
                    pending = executor.submit(competing_update)
                    assert started.wait(5)
                    deadline = time.monotonic() + 4
                    with engine.connect() as observer:
                        while True:
                            blocked = observer.scalar(text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"),
                                                      {"pid": contender_pid[0]})
                            if blocked:
                                break
                            assert not pending.done() and time.monotonic() < deadline, "Revision update did not wait for the row lock"
                            time.sleep(0.01)
                    updated = service.update_connection(db, identifier, ConnectionUpdate(expected_revision=1, enabled=False), principal)
                    assert updated.revision == 2
                assert pending.result(timeout=10) == "conflict"
            with Session(engine) as db:
                runtime(db)
                row = service.connection(db, identifier, principal)
                assert row.encrypted_token == original and custody.decrypt_token(row) == "synthetic-integration-token"
                assert not row.enabled and row.revision == 2
            migration = importlib.import_module("migrations.versions.b5h7j9l1n3q6_monitoring_integrations")
            with engine.begin() as connection, Operations.context(MigrationContext.configure(connection)):
                try:
                    migration.downgrade()
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Lossy downgrade was allowed")
            extra = extra_checks(engine, identifier, principal) if extra_checks else []
            engine.dispose()
            print(json.dumps({"passed": True, "checks": ["full_chain_upgrade", "empty_safe_roundtrip",
                "existing_data_preserved", "nonowner_rls", "cross_namespace_write_rejected",
                "concurrent_revision_guard", "encrypted_custody_preserved", "lossy_downgrade_blocked", *extra],
                "live_database_changed": False, "source_calls": 0}))
        finally:
            run([str(PG / "pg_ctl"), "-D", str(data), "-m", "fast", "-w", "stop"])


if __name__ == "__main__":
    main()
