import importlib
from datetime import UTC, datetime

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
from sqlalchemy import create_engine, inspect, text

from icheck.models import MonitoringIntegrationConnection


@pytest.fixture(autouse=True)
def clean_database():
    yield


def test_integration_migration_is_additive_and_preserves_custody():
    revision = importlib.import_module("migrations.versions.b5h7j9l1n3q6_monitoring_integrations")
    assert revision.down_revision == "a4g6i8k0m2p5"
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE existing_data (value TEXT)")
            connection.exec_driver_sql("INSERT INTO existing_data VALUES ('preserved')")
            with Operations.context(MigrationContext.configure(connection)):
                revision.upgrade()
            assert connection.scalar(text("SELECT value FROM existing_data")) == "preserved"
            table = MonitoringIntegrationConnection.__table__
            columns = inspect(connection).get_columns(table.name)
            assert {column["name"] for column in columns} == set(table.columns.keys())
            assert {c["name"] for c in columns if c["nullable"]} == {c.name for c in table.columns if c.nullable}
            connection.execute(text("""INSERT INTO monitoring_integration_connections
                (id,name,provider,api_url,group_ids,encrypted_token,created_by,created_at,updated_at)
                VALUES ('fixture','Fixture','zabbix','https://zabbix.example.test/api_jsonrpc.php','["1"]',:secret,'fixture',:now,:now)"""),
                {"secret": b"encrypted-fixture-only", "now": datetime.now(UTC).isoformat()})
            assert connection.execute(text("SELECT enabled,revision FROM monitoring_integration_connections")).one() == (0, 1)
            with Operations.context(MigrationContext.configure(connection)):
                with pytest.raises(RuntimeError, match="custody"):
                    revision.downgrade()
            connection.exec_driver_sql("DELETE FROM monitoring_integration_connections")
            with Operations.context(MigrationContext.configure(connection)):
                revision.downgrade()
            assert table.name not in inspect(connection).get_table_names()
            assert connection.scalar(text("SELECT value FROM existing_data")) == "preserved"
    finally:
        engine.dispose()
