"""Disposable PostgreSQL acceptance for search custody, isolation and admission."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import importlib
import json
import os
from pathlib import Path
import tempfile

from check_optional_location_postgres import PG, run


def main():
    with tempfile.TemporaryDirectory(prefix="icheck-research-pg-") as directory:
        root = Path(directory); data = root / "data"
        run([str(PG / "initdb"), "-D", str(data), "--auth=trust", "--no-locale", "--encoding=UTF8"])
        run([str(PG / "pg_ctl"), "-D", str(data), "-l", str(root / "postgres.log"), "-o", f"-k {root} -c listen_addresses=''", "-w", "start"])
        try:
            run([str(PG / "createdb"), "-h", str(root), "research_acceptance"])
            from alembic.migration import MigrationContext
            from alembic.operations import Operations
            from sqlalchemy import create_engine, event, text
            from sqlalchemy.orm import Session
            from icheck.config import get_settings
            from icheck.database import Base, DEFAULT_TENANT_ID, DEFAULT_REGION_ID, set_session_namespace
            from icheck.models import AuditEvent, Tenant, Region
            from icheck.public_research_http import ResearchUnavailable
            from icheck.research_schemas import ResearchSettingsUpdate
            from icheck.services import research_settings as service
            from icheck.services.tenancy import ensure_default_namespace
            engine = create_engine("postgresql+psycopg://zhao@/research_acceptance?host=" + str(root))
            Base.metadata.create_all(engine, tables=[Tenant.__table__, Region.__table__, AuditEvent.__table__])
            revision = importlib.import_module("migrations.versions.y2e4g6i8k0m3_research_settings")
            with engine.begin() as conn, Operations.context(MigrationContext.configure(conn)):
                revision.upgrade()
                conn.exec_driver_sql("CREATE ROLE research_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS")
                conn.exec_driver_sql("GRANT USAGE ON SCHEMA public TO research_runtime")
                conn.exec_driver_sql("GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA public TO research_runtime")
            with Session(engine) as db:
                ensure_default_namespace(db)
            key = root / "encryption.key"
            key.write_bytes(os.urandom(32)); key.chmod(0o400)
            os.environ["ICHECK_AI_MANAGED_SECRET_KEY_FILE"] = str(key)
            get_settings.cache_clear()

            @contextmanager
            def session(tenant=DEFAULT_TENANT_ID, region=DEFAULT_REGION_ID):
                with Session(engine, expire_on_commit=False) as db:
                    event.listen(db, "after_begin", lambda s, t, c: c.exec_driver_sql("SET LOCAL ROLE research_runtime"))
                    set_session_namespace(db, tenant, region)
                    yield db

            payload = ResearchSettingsUpdate(expected_revision=0, provider="brave", enabled=True,
                api_key="synthetic-research-key-not-real", daily_limit=1)
            def save(_):
                with session() as db:
                    try:
                        service.save(db, payload, actor="synthetic-admin")
                        return "saved"
                    except service.ResearchSettingsConflict:
                        db.rollback(); return "stale"
            with ThreadPoolExecutor(max_workers=2) as pool:
                assert sorted(pool.map(save, range(2))) == ["saved", "stale"]

            def reserve(_):
                with session() as db:
                    try:
                        service.reserve(db, service.connection(db)); return "admitted"
                    except ResearchUnavailable:
                        return "denied"
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(reserve, range(6)))
            assert results.count("admitted") == 1 and results.count("denied") == 5
            with session() as db:
                assert service.setup_status(db).calls_today == 1
                assert service.decrypt(service.connection(db)) == "synthetic-research-key-not-real"
            with session("other-tenant", "other-region") as db:
                assert service.connection(db) is None
                # Raw SQL proves database RLS, not merely ORM filtering.
                assert db.scalar(text("SELECT count(*) FROM research_settings")) == 0
            engine.dispose()
            print(json.dumps({"passed": True, "checks": ["additive_postgresql_migration", "concurrent_save_one_winner",
                "six_concurrent_searches_one_admission", "encrypted_key_resolution", "nonowner_rls_isolation"],
                "live_database_changed": False, "provider_calls": 0, "device_calls": 0}))
        finally:
            run([str(PG / "pg_ctl"), "-D", str(data), "-m", "fast", "-w", "stop"])


if __name__ == "__main__":
    main()
