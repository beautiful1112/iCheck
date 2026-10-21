import importlib

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
from sqlalchemy import create_engine, inspect, text

from icheck.models import MonitoringIntegrationSchedule


@pytest.fixture(autouse=True)
def clean_database():
    yield


def test_additive_schedule_migration_defaults_to_no_recurring_work_and_guards_history():
    migration = importlib.import_module("migrations.versions.d7j9l1n3p5s8_integration_schedules")
    assert migration.down_revision == "c6i8k0m2p4r7"
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as db, Operations.context(MigrationContext.configure(db)):
            migration.upgrade()
            table = MonitoringIntegrationSchedule.__tablename__
            assert {c["name"] for c in inspect(db).get_columns(table)} == set(MonitoringIntegrationSchedule.__table__.columns.keys())
            assert db.scalar(text(f"SELECT count(*) FROM {table}")) == 0
            db.execute(text(f"""INSERT INTO {table}
                (connection_id,revision,connection_revision,enabled,interval_seconds,retention_days,failures,updated_by,updated_at)
                VALUES ('fixture',1,1,false,900,30,0,'fixture','2026-10-20')"""))
            with pytest.raises(RuntimeError, match="saved integration schedules"):
                migration.downgrade()
            db.execute(text(f"DELETE FROM {table}"))
            migration.downgrade()
            assert table not in inspect(db).get_table_names()
    finally:
        engine.dispose()
