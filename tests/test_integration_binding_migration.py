import importlib

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
from sqlalchemy import create_engine, inspect, text

from icheck.models import MonitoringIntegrationBinding


@pytest.fixture(autouse=True)
def clean_database():
    yield


def test_additive_binding_migration_and_lossy_downgrade_guard():
    migration = importlib.import_module("migrations.versions.e8k0m2p4r6t9_integration_bindings")
    assert migration.down_revision == "d7j9l1n3p5s8"
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as db, Operations.context(MigrationContext.configure(db)):
            migration.upgrade()
            table = MonitoringIntegrationBinding.__tablename__
            assert {c["name"] for c in inspect(db).get_columns(table)} == set(MonitoringIntegrationBinding.__table__.columns.keys())
            assert db.scalar(text(f"SELECT count(*) FROM {table}")) == 0
            db.execute(text(f"""INSERT INTO {table}
                (resource_id,connection_id,revision,connection_revision,source_name,reviewed_by,reviewed_at)
                VALUES ('fixture','connection',1,1,'Fixture','fixture','2026-10-20')"""))
            with pytest.raises(RuntimeError, match="reviewed integration bindings"):
                migration.downgrade()
            db.execute(text(f"DELETE FROM {table}"))
            migration.downgrade()
            assert table not in inspect(db).get_table_names()
    finally:
        engine.dispose()
