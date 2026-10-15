import importlib

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
from sqlalchemy import CheckConstraint, Column, MetaData, String, Table, create_engine, inspect, select


def test_password_migration_preserves_existing_identities_and_session_provenance():
    engine = create_engine("sqlite://")
    metadata = MetaData()
    principals = Table("control_plane_principals", metadata,
        Column("id", String(36), primary_key=True), Column("subject", String(255)))
    sessions = Table("control_plane_browser_sessions", metadata,
        Column("id", String(36), primary_key=True), Column("auth_source", String(32)),
        Column("federated_identity_id", String(36)), CheckConstraint(
            "(auth_source IN ('unknown','local_token') AND federated_identity_id IS NULL) OR "
            "(auth_source IN ('oidc','trusted_proxy') AND federated_identity_id IS NOT NULL)",
            name="ck_control_plane_browser_session_source"))
    metadata.create_all(engine)
    revision = importlib.import_module("migrations.versions.p3t5v7x9z1c4_local_password_login")
    with engine.begin() as connection:
        connection.execute(principals.insert(), {"id": "existing-admin", "subject": "admin"})
        connection.execute(sessions.insert(), {"id": "existing-session", "auth_source": "local_token"})
        with Operations.context(MigrationContext.configure(connection)):
            revision.upgrade()
        upgraded = Table("control_plane_principals", MetaData(), autoload_with=connection)
        account = connection.execute(select(upgraded)).mappings().one()
        assert account["subject"] == "admin" and account["password_hash"] is None
        assert account["password_failed_attempts"] == 0
        assert connection.execute(select(sessions.c.auth_source)).scalar_one() == "local_token"
        connection.execute(sessions.insert(), {"id": "password-session", "auth_source": "local_password"})
        with Operations.context(MigrationContext.configure(connection)):
            with pytest.raises(RuntimeError, match="session history"):
                revision.downgrade()
        connection.execute(sessions.delete().where(sessions.c.id == "password-session"))
        with Operations.context(MigrationContext.configure(connection)):
            revision.downgrade()
        assert "password_hash" not in {item["name"] for item in inspect(connection).get_columns(principals.name)}
        assert connection.execute(select(sessions.c.auth_source)).scalar_one() == "local_token"
    engine.dispose()
