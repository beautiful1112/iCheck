import importlib
from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
from sqlalchemy import create_engine, inspect, text
from icheck.models import MonitoringIntegrationAlertFeed, MonitoringIntegrationEvent


@pytest.fixture(autouse=True)
def clean_database():
    yield


def test_empty_additive_alert_migration_and_lossy_downgrade_guard():
    migration = importlib.import_module("migrations.versions.f9l1n3q5s7u0_integration_alerts")
    assert migration.down_revision == "e8k0m2p4r6t9"
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as db, Operations.context(MigrationContext.configure(db)):
            migration.upgrade()
            for model in (MonitoringIntegrationAlertFeed, MonitoringIntegrationEvent):
                assert {c["name"] for c in inspect(db).get_columns(model.__tablename__)} == set(model.__table__.columns.keys())
                assert db.scalar(text(f"SELECT count(*) FROM {model.__tablename__}")) == 0
            db.execute(text("""INSERT INTO monitoring_integration_alert_feeds
                (connection_id,revision,connection_revision,enabled,interval_seconds,started_at,cursor,phase,failures,updated_by)
                VALUES ('fixture',1,1,0,60,'2026-10-20','0','bootstrap',0,'fixture')"""))
            with pytest.raises(RuntimeError, match="external alert"):
                migration.downgrade()
            db.execute(text("DELETE FROM monitoring_integration_alert_feeds"))
            migration.downgrade()
            assert MonitoringIntegrationEvent.__tablename__ not in inspect(db).get_table_names()
    finally:
        engine.dispose()
