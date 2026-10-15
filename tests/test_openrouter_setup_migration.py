import importlib
from datetime import datetime, UTC

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
from sqlalchemy import create_engine, text, inspect


def test_encrypted_ai_migration_preserves_existing_tables_and_refuses_discarding_keys():
    engine = create_engine("sqlite://")
    revision = importlib.import_module("migrations.versions.q4u6w8y0b2d5_managed_ai_connections")
    with engine.begin() as connection:
        for name in ("ai_provider_configs", "credential_profiles"):
            connection.execute(text(f"CREATE TABLE {name} (id VARCHAR(36) PRIMARY KEY)"))
            connection.execute(text(f"INSERT INTO {name} VALUES ('existing')"))
        with Operations.context(MigrationContext.configure(connection)):
            revision.upgrade()
        assert connection.scalar(text("SELECT id FROM ai_provider_configs")) == "existing"
        assert connection.scalar(text("SELECT id FROM credential_profiles")) == "existing"
        connection.execute(text("""INSERT INTO ai_managed_connections
            (id,provider_id,credential_profile_id,preset,encrypted_secret,outbound_enabled,revision,created_by,updated_by,created_at,updated_at)
            VALUES ('connection','existing','existing','openrouter',:cipher,1,1,'admin','admin',:now,:now)"""),
            {"cipher": b"encrypted-test-custody", "now": datetime.now(UTC)})
        with Operations.context(MigrationContext.configure(connection)):
            with pytest.raises(RuntimeError, match="custody"):
                revision.downgrade()
        connection.execute(text("DELETE FROM ai_managed_connections"))
        with Operations.context(MigrationContext.configure(connection)):
            revision.downgrade()
        assert "ai_managed_connections" not in inspect(connection).get_table_names()
    engine.dispose()
