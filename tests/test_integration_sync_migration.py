import importlib

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
from sqlalchemy import create_engine, inspect, text

from icheck.models import MonitoringIntegrationResource, MonitoringIntegrationSync


@pytest.fixture(autouse=True)
def clean_database():
    yield


def test_sync_migration_matches_models_and_preserves_populated_history():
    previous = importlib.import_module("migrations.versions.b5h7j9l1n3q6_monitoring_integrations")
    current = importlib.import_module("migrations.versions.c6i8k0m2p4r7_integration_discovery_sync")
    assert current.down_revision == previous.revision
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as db:
            with Operations.context(MigrationContext.configure(db)):
                previous.upgrade()
                db.execute(text("""INSERT INTO monitoring_integration_connections
                    (id,name,provider,api_url,group_ids,encrypted_token,created_by,created_at,updated_at)
                    VALUES ('fixture','Fixture','zabbix','https://zabbix.example.test/api_jsonrpc.php','["1"]',:secret,'fixture','2026-01-01','2026-01-01')"""),
                    {"secret": b"fixture-ciphertext"})
                current.upgrade()
                assert db.scalar(text("SELECT encrypted_token FROM monitoring_integration_connections")) == b"fixture-ciphertext"
                for model in (MonitoringIntegrationResource, MonitoringIntegrationSync):
                    assert {c["name"] for c in inspect(db).get_columns(model.__tablename__)} == set(model.__table__.columns.keys())
                db.execute(text("""INSERT INTO monitoring_integration_syncs
                    (id,connection_id,connection_revision,status,cursor,total,observed,created_by,started_at,updated_at)
                    VALUES ('run','fixture',1,'failed',0,0,0,'fixture','2026-01-01','2026-01-01')"""))
                with pytest.raises(RuntimeError, match="history"):
                    current.downgrade()
                db.execute(text("DELETE FROM monitoring_integration_syncs"))
                current.downgrade()
                assert db.scalar(text("SELECT encrypted_token FROM monitoring_integration_connections")) == b"fixture-ciphertext"
    finally:
        engine.dispose()
