"""Isolated full-chain migration and custody checks; never uses the live database."""
import getpass
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile

from check_optional_location_postgres import PG, run


def main():
    with tempfile.TemporaryDirectory(prefix="icheck-providers-pg-") as directory:
        root = Path(directory)
        data = root / "data"
        run([str(PG / "initdb"), "-D", str(data), "--auth=trust", "--no-locale", "--encoding=UTF8"])
        run([str(PG / "pg_ctl"), "-D", str(data), "-l", str(root / "postgres.log"), "-o", f"-k {root} -c listen_addresses=''", "-w", "start"])
        try:
            run([str(PG / "createdb"), "-h", str(root), "provider_acceptance"])
            os.environ["ICHECK_DATABASE_URL"] = f"postgresql+psycopg://{getpass.getuser()}@/provider_acceptance?host={root}"
            os.environ["ICHECK_AUTO_CREATE_SCHEMA"] = "false"
            key = root / "encryption.key"
            key.write_bytes(os.urandom(32)); key.chmod(0o400)
            os.environ["ICHECK_AI_MANAGED_SECRET_KEY_FILE"] = str(key)
            def migrate(command, target):
                run([sys.executable, "-m", "alembic", "-c", "alembic.ini", command, target])
            migrate("upgrade", "z3f5h7j9l1n4")
            from sqlalchemy import text, select
            from sqlalchemy.orm import Session
            from sqlalchemy.exc import DBAPIError
            from alembic.migration import MigrationContext
            from alembic.operations import Operations
            from icheck.database import engine, set_session_namespace, DEFAULT_TENANT_ID, DEFAULT_REGION_ID
            from icheck.models import AIManagedConnection, AIProviderConfig
            from icheck.openrouter_schemas import OpenRouterConnect, ManagedAIConnect
            from icheck.ai_provider_presets import PRESETS
            from icheck.services import openrouter_setup as service
            from icheck.services.ai_settings import _models_request_headers
            from icheck.services.tenancy import ensure_default_namespace
            with Session(engine) as db:
                ensure_default_namespace(db)
                set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
                row = service.connect(db, OpenRouterConnect(api_key="synthetic-not-real-provider-key", approve_outbound=True), actor="fixture")
                custody = db.scalar(select(AIManagedConnection))
                original = (custody.id, custody.encrypted_secret, custody.revision, custody.credential_profile_id)
            migrate("upgrade", "head")
            migrate("downgrade", "z3f5h7j9l1n4")
            migrate("upgrade", "head")
            with Session(engine) as db:
                set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
                custody = db.scalar(select(AIManagedConnection))
                assert (custody.id, custody.encrypted_secret, custody.revision, custody.credential_profile_id) == original
                with _models_request_headers(db, db.get(AIProviderConfig, row.provider_id)) as headers:
                    assert headers["Authorization"] == "Bearer synthetic-not-real-provider-key"
                for preset in PRESETS:
                    if preset != "openrouter":
                        service.connect(db, ManagedAIConnect(preset=preset, name=preset,
                            api_key="synthetic-not-real-provider-key", approve_outbound=True), actor="fixture")
            with engine.begin() as c:
                c.exec_driver_sql("CREATE ROLE provider_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS")
                c.exec_driver_sql("GRANT USAGE ON SCHEMA public TO provider_runtime")
                c.exec_driver_sql("GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO provider_runtime")
            with engine.connect() as c:
                c.exec_driver_sql("SET LOCAL ROLE provider_runtime")
                c.execute(text("SELECT set_config('icheck.tenant_id', :v, true)"), {"v": DEFAULT_TENANT_ID})
                c.execute(text("SELECT set_config('icheck.region_id', :v, true)"), {"v": DEFAULT_REGION_ID})
                assert c.scalar(text("SELECT count(*) FROM ai_managed_connections")) == len(PRESETS)
                assert c.scalar(text("SELECT row_security_active('ai_managed_connections')"))
                c.execute(text("SELECT set_config('icheck.tenant_id', 'other-tenant', true)"))
                assert c.scalar(text("SELECT count(*) FROM ai_managed_connections")) == 0
            for sql in ("DELETE FROM ai_managed_connections", "UPDATE ai_managed_connections SET preset='openai', revision=revision+1 WHERE preset='openrouter'"):
                try:
                    with engine.begin() as c: c.execute(text(sql))
                except DBAPIError:
                    pass
                else:
                    raise AssertionError("Custody guard did not reject mutation")
            migration = importlib.import_module("migrations.versions.a4g6i8k0m2p5_managed_ai_provider_presets")
            with engine.begin() as c, Operations.context(MigrationContext.configure(c)):
                try: migration.downgrade()
                except RuntimeError: pass
                else: raise AssertionError("Lossy downgrade was allowed")
            engine.dispose()
            print(json.dumps({"passed": True, "checks": ["full_chain_upgrade", "old_cipher_preserved_and_decryptable",
                "safe_roundtrip", "all_presets_insertable", "nonowner_rls", "immutable_custody_guard", "lossy_downgrade_blocked"],
                "live_database_changed": False, "provider_calls": 0}))
        finally:
            run([str(PG / "pg_ctl"), "-D", str(data), "-m", "fast", "-w", "stop"])


if __name__ == "__main__":
    main()
