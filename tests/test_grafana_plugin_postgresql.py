"""Reusable opt-in migration custody checks on a private PostgreSQL database."""
import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from icheck.models import GrafanaChange, GrafanaConnection, new_id

URL = os.getenv("ICHECK_GRAFANA_POSTGRES_TEST_URL")
ACK = os.getenv("ICHECK_GRAFANA_POSTGRES_ACK")
TENANT = "00000000-0000-0000-0000-000000000001"
REGION = "00000000-0000-0000-0000-000000000002"


@pytest.mark.skipif(not URL or ACK != "private-grafana-plugin-database", reason="Requires an acknowledged private migrated database")
def test_non_owner_namespace_isolation_and_immutable_reviewed_history():
    engine = create_engine(URL)
    try:
        with engine.begin() as owner:
            assert owner.scalar(text("SELECT current_database()")) == "grafana_plugin_test"
            assert owner.scalar(text("SELECT version_num FROM alembic_version")) == "t7x9z1c3e5g8"
            owner.exec_driver_sql("DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='icheck_grafana_test') THEN CREATE ROLE icheck_grafana_test NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF; END $$")
            owner.exec_driver_sql("GRANT USAGE ON SCHEMA public TO icheck_grafana_test")
            owner.exec_driver_sql("GRANT SELECT,INSERT,UPDATE,DELETE ON grafana_connections,grafana_changes TO icheck_grafana_test")
        identifier, proposal = new_id(), new_id()
        with Session(engine) as owner:
            owner.add(GrafanaConnection(id=identifier, tenant_id=TENANT, region_id=REGION, name=identifier,
                api_url="http://127.0.0.1:3001/grafana", public_url="https://test.invalid/grafana",
                datasource_uid="icheck-prometheus", folder_uid="icheck", encrypted_token=b"opaque-fixture",
                enabled=True, shared_dataset_acknowledged=True, revision=1, created_by="test"))
            owner.commit()
            owner.add(GrafanaChange(id=proposal, tenant_id=TENANT, region_id=REGION, connection_id=identifier,
                connection_revision=1, connection_snapshot={}, resource_kind="dashboard", resource_uid="test",
                folder_uid="icheck", definition={"title": "Reviewed"}, plan_hash="a" * 64,
                status="proposed", created_by="test"))
            owner.commit()
        with engine.begin() as runtime:
            runtime.exec_driver_sql("SET LOCAL ROLE icheck_grafana_test")
            assert runtime.scalar(text("SELECT current_user")) == "icheck_grafana_test"
            assert runtime.scalar(text("SELECT count(*) FROM grafana_changes")) == 0
            runtime.execute(text("SELECT set_config('icheck.tenant_id', :tenant, true),set_config('icheck.region_id', :region, true)"), {"tenant": TENANT, "region": REGION})
            assert runtime.scalar(text("SELECT count(*) FROM grafana_changes WHERE id=:id"), {"id": proposal}) == 1
            for sql in ("UPDATE grafana_changes SET definition='{}' WHERE id=:id",
                        "DELETE FROM grafana_changes WHERE id=:id",
                        "UPDATE grafana_changes SET tenant_id='other' WHERE id=:id"):
                with pytest.raises(DBAPIError), runtime.begin_nested():
                    runtime.execute(text(sql), {"id": proposal})
            runtime.execute(text("UPDATE grafana_changes SET status='applying',approved_by='human' WHERE id=:id"), {"id": proposal})
            runtime.execute(text("UPDATE grafana_changes SET status='applied',applied_resource='{}',applied_at=now() WHERE id=:id"), {"id": proposal})
            with pytest.raises(DBAPIError), runtime.begin_nested():
                runtime.execute(text("UPDATE grafana_changes SET status='unknown' WHERE id=:id"), {"id": proposal})
            runtime.execute(text("SELECT set_config('icheck.tenant_id','other',true)"))
            assert runtime.scalar(text("SELECT count(*) FROM grafana_changes")) == 0
    finally:
        engine.dispose()
