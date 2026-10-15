import importlib
from datetime import UTC, datetime

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
from sqlalchemy import create_engine, inspect, text


def test_search_migration_is_additive_and_preserves_saved_custody():
    revision = importlib.import_module("migrations.versions.y2e4g6i8k0m3_research_settings")
    assert revision.down_revision == "x1d3f5h7j9l2"
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE existing_data (value TEXT)")
        connection.exec_driver_sql("INSERT INTO existing_data VALUES ('preserved')")
        with Operations.context(MigrationContext.configure(connection)):
            revision.upgrade()
        assert connection.scalar(text("SELECT value FROM existing_data")) == "preserved"
        connection.execute(text("""INSERT INTO research_settings
            (id,provider,enabled,revision,daily_limit,quota_day,calls_today,updated_by,updated_at,encrypted_secret)
            VALUES ('connection','brave',1,1,100,'',0,'admin',:now,:secret)"""),
            {"now": datetime.now(UTC), "secret": b"ciphertext-only"})
        with Operations.context(MigrationContext.configure(connection)):
            with pytest.raises(RuntimeError, match="custody"): revision.downgrade()
        connection.exec_driver_sql("DELETE FROM research_settings")
        with Operations.context(MigrationContext.configure(connection)):
            revision.downgrade()
        assert "research_settings" not in inspect(connection).get_table_names()
