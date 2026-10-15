"""Opt-in row-lock acceptance on a migrated private PostgreSQL test database."""
from concurrent.futures import ThreadPoolExecutor
import os

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session

from icheck.auth_schemas import BootstrapRequest
from icheck.database import set_session_namespace
from icheck.models import ControlPlanePrincipal
from icheck.services.control_plane_auth import bootstrap_admin, ControlPlaneAuthenticationError, principal_context
from icheck.services.local_password_auth import authenticate_password, set_principal_password

URL = os.getenv("ICHECK_PASSWORD_POSTGRES_TEST_URL")
ACK = os.getenv("ICHECK_PASSWORD_POSTGRES_ACK")
PASSWORD = "A private concurrent test passphrase!"


@pytest.mark.skipif(not URL or ACK != "private-password-test-database", reason="Requires an explicitly acknowledged private migrated database")
def test_migrated_non_owner_password_lockout_serializes_concurrent_workers():
    engine = create_engine(URL, pool_size=6)
    try:
        with engine.begin() as connection:
            assert connection.scalar(text("SELECT current_database()")) == "icheck_password_test"
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "p3t5v7x9z1c4"
            assert connection.scalar(text("SELECT count(*) FROM control_plane_principals")) == 0
            connection.exec_driver_sql("CREATE ROLE icheck_password_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS")
            connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO icheck_password_runtime")
            connection.exec_driver_sql("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO icheck_password_runtime")
        with Session(engine) as db:
            principal, _, _ = bootstrap_admin(db, BootstrapRequest(
                subject="parallel-admin", display_name="Parallel test administrator", password=PASSWORD,
            ), default_token_ttl_hours=24)
            principal_id = principal.id

        def runtime_session():
            db = Session(engine)
            event.listen(db, "after_begin", lambda session, transaction, connection:
                connection.exec_driver_sql("SET LOCAL ROLE icheck_password_runtime"))
            return db

        def fail_login(_):
            with runtime_session() as db:
                assert db.scalar(text("SELECT current_user")) == "icheck_password_runtime"
                with pytest.raises(ControlPlaneAuthenticationError, match="Invalid username or password"):
                    authenticate_password(db, username="parallel-admin", password="incorrect", tenant_selector="local")

        with ThreadPoolExecutor(max_workers=5) as workers:
            list(workers.map(fail_login, range(5)))
        with runtime_session() as db:
            stored = db.get(ControlPlanePrincipal, principal_id)
            assert stored.password_failed_attempts == 5
            assert stored.password_locked_until is not None
            with pytest.raises(ControlPlaneAuthenticationError):
                authenticate_password(db, username="parallel-admin", password=PASSWORD, tenant_selector="local")
        with runtime_session() as db:
            stored = db.get(ControlPlanePrincipal, principal_id)
            actor = principal_context(stored, db=db)
            set_session_namespace(db, actor.tenant_id, actor.region_id)
            set_principal_password(db, principal_id=principal_id, password=PASSWORD,
                actor=actor, reason="Concurrency fixture recovery")
            _, context = authenticate_password(db, username="parallel-admin", password=PASSWORD, tenant_selector="local")
            assert context.principal_id == principal_id
            db.commit()
            assert db.get(ControlPlanePrincipal, principal_id).password_failed_attempts == 0
    finally:
        engine.dispose()
