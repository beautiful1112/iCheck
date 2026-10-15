"""Opt-in migrated PostgreSQL RLS, custody guards and concurrent revision acceptance."""
from concurrent.futures import ThreadPoolExecutor
import os
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from icheck.database import DEFAULT_TENANT_ID, DEFAULT_REGION_ID, set_session_namespace
from icheck.openrouter_schemas import OpenRouterConnect, OpenRouterConnectionUpdate
from icheck.services import openrouter_setup as service
from icheck.services.tenancy import ensure_default_namespace
from test_openrouter_setup import managed_key, KEY

URL = os.getenv("ICHECK_OPENROUTER_POSTGRES_TEST_URL")
ACK = os.getenv("ICHECK_OPENROUTER_POSTGRES_ACK")


@pytest.mark.skipif(not URL or ACK != "private-openrouter-test-database", reason="Requires an acknowledged private migrated database")
def test_managed_ai_nonowner_rls_binding_guards_and_concurrent_revisions(managed_key):
    engine = create_engine(URL, pool_size=4)
    try:
        with engine.begin() as connection:
            assert connection.scalar(text("SELECT current_database()")) == "icheck_openrouter_test"
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "q4u6w8y0b2d5"
            assert connection.scalar(text("SELECT count(*) FROM ai_managed_connections")) == 0
            connection.exec_driver_sql("CREATE ROLE icheck_openrouter_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS")
            connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO icheck_openrouter_runtime")
            connection.exec_driver_sql("GRANT SELECT, INSERT, UPDATE, DELETE ON tenants,regions,ai_provider_configs,credential_profiles,ai_managed_connections,audit_events TO icheck_openrouter_runtime")
        with Session(engine) as db:
            ensure_default_namespace(db)

        def runtime(tenant=DEFAULT_TENANT_ID, region=DEFAULT_REGION_ID):
            db = Session(engine, expire_on_commit=False)
            event.listen(db, "after_begin", lambda session, transaction, connection: connection.exec_driver_sql("SET LOCAL ROLE icheck_openrouter_runtime"))
            set_session_namespace(db, tenant, region)
            return db

        with runtime() as db:
            assert db.scalar(text("SELECT current_user")) == "icheck_openrouter_runtime"
            created = service.connect(db, OpenRouterConnect(name="pg-openrouter", api_key=KEY, approve_outbound=True), actor="test-admin")
            assert service.setup_status(db).connections[0].revision == 1
        with runtime("other-tenant", "other-region") as db:
            assert db.scalar(text("SELECT count(*) FROM ai_managed_connections")) == 0
            assert service.connection_for(db, created.provider_id) is None
        for mutation in ["DELETE FROM ai_managed_connections", "UPDATE ai_managed_connections SET revision=revision+2",
                         "UPDATE ai_managed_connections SET provider_id='another-provider',revision=revision+1"]:
            with runtime() as db:
                with pytest.raises(DBAPIError): db.execute(text(mutation))

        def revoke(_):
            with runtime() as db:
                try:
                    service.update_connection(db, created.provider_id, OpenRouterConnectionUpdate(expected_revision=1, outbound_enabled=False), actor="test-admin")
                    return "updated"
                except service.ManagedAIConflict:
                    return "conflict"
        with ThreadPoolExecutor(max_workers=2) as workers:
            assert sorted(workers.map(revoke, range(2))) == ["conflict", "updated"]
        with runtime() as db:
            retained = service.connection_for(db, created.provider_id)
            assert retained.revision == 2 and retained.outbound_enabled is False
    finally:
        engine.dispose()
