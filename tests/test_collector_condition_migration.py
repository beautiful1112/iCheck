"""Actual SQLite migration/guards, not metadata.create_all substitutes."""
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import MetaData, Table, create_engine, inspect, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from icheck.database import DEFAULT_TENANT_ID, DEFAULT_REGION_ID, get_db, set_session_namespace
from icheck.main import app
from icheck.models import (Alert, AlertSeverity, AlertStatus, CollectorConditionAdmission,
    CollectorConditionSource, CollectorConditionReceipt)
import test_collector_conditions as shared
import test_knowledge_projection
from test_alert_condition_migration import migrate

HEAD = "y3a5c7e9g1i4"
PREVIOUS = "x2z4b6d8f0h3"


def test_empty_condition_migration_roundtrip(tmp_path):
    url = f"sqlite+pysqlite:///{tmp_path/'condition-empty.sqlite'}"
    migrate(url, HEAD)
    migrate(url, PREVIOUS, "downgrade")
    migrate(url, HEAD)
    engine = create_engine(url)
    with engine.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == HEAD
    engine.dispose()


def test_upgrade_refuses_legacy_reserved_source_without_erasing_history(tmp_path):
    url = f"sqlite+pysqlite:///{tmp_path/'condition-reserved.sqlite'}"
    migrate(url, PREVIOUS)
    engine = create_engine(url)
    # Use the actual historical schema, not today's ORM with later retirement
    # columns. The migration must preserve/refuse real legacy material.
    from icheck.models import utcnow
    alerts = Table("alerts", MetaData(), autoload_with=engine)
    with engine.begin() as db:
        db.execute(alerts.insert().values(id=str(uuid4()), tenant_id=DEFAULT_TENANT_ID,
            region_id=DEFAULT_REGION_ID, dedup_key="collector.condition:legacy", event_type="device.cpu.high",
            entity_type="device", entity_id="historical-device", severity=AlertSeverity.WARNING.name,
            status=AlertStatus.RESOLVED.name, title="Historical generic source", description="", details={},
            first_seen=utcnow(), last_seen=utcnow(), occurrence_count=1))
    result = migrate(url, HEAD, success=False)
    assert "Reconcile legacy reserved Collector condition keys" in result.stdout+result.stderr
    with engine.connect() as db:
        assert db.scalar(text("SELECT count(*) FROM alerts")) == 1
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == PREVIOUS
    engine.dispose()


@pytest.fixture
def migrated_condition_database(tmp_path, client, monkeypatch):
    url = f"sqlite+pysqlite:///{tmp_path/'condition-records.sqlite'}"
    # Runtime subjects use the current schema. Empty historical roundtrip and
    # populated legacy refusal above still exercise the exact original revision.
    migrate(url, "head")
    engine = create_engine(url, connect_args={"check_same_thread": False})
    def session():
        db = Session(engine, expire_on_commit=False)
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        return db
    def scoped_db():
        with session() as db:
            yield db
    monkeypatch.setitem(app.dependency_overrides, get_db, scoped_db)
    monkeypatch.setattr(shared, "session", session)
    monkeypatch.setattr(test_knowledge_projection, "SessionLocal", session)
    yield url, engine, session
    engine.dispose()


def test_actual_sqlite_condition_ingress_projection_and_guarded_downgrade(client, migrated_condition_database):
    url, engine, session = migrated_condition_database
    c = shared.fixture(client)
    active = shared.submit(client, c, 99)
    quiet = shared.submit(client, c, 10, at=c["at"]+timedelta(seconds=1))
    assert quiet["alert_status"] == "resolved" and active["source_id"] == quiet["source_id"]
    # Drain through the real completion API. Newer migrations also refuse live
    # ownership, which must not mask this historical provenance downgrade guard.
    assignment = c["assignment"]
    completed = client.post(f'/api/v1/collector-runs/{assignment["run_id"]}/complete',
        json={"lease_token": assignment["lease_token"], "status": "succeeded"}, headers=c["headers"])
    assert completed.status_code == 200, completed.text
    result = migrate(url, PREVIOUS, "downgrade", success=False)
    assert "Cannot downgrade recorded Collector condition provenance" in result.stdout+result.stderr
    with engine.connect() as db:
        assert db.scalar(text("SELECT count(*) FROM collector_condition_receipts")) == 2


@pytest.mark.parametrize("table", ["collector_condition_admissions", "collector_condition_sources", "collector_condition_receipts"])
@pytest.mark.parametrize("operation", ["update", "delete"])
def test_actual_sqlite_history_is_append_only(client, migrated_condition_database, table, operation):
    _url, engine, _session = migrated_condition_database
    c = shared.fixture(client)
    shared.submit(client, c, 99)
    sql = f"UPDATE {table} SET created_at=created_at" if operation == "update" else f"DELETE FROM {table}"
    with engine.connect() as db:
        with pytest.raises(DBAPIError, match="append-only"):
            db.execute(text(sql))
        db.rollback()
        assert db.scalar(text("SELECT count(*) FROM "+table)) == 1


@pytest.mark.parametrize("mutation", ["admission_worker", "admission_authority", "source_assignment",
    "source_extra_authority", "receipt_verdict", "receipt_authority"])
def test_actual_sqlite_insert_guards_reject_crossed_origin_or_authority(client, migrated_condition_database, mutation):
    _url, engine, _session = migrated_condition_database
    c = shared.fixture(client)
    shared.submit(client, c, 99)
    model = CollectorConditionAdmission if mutation.startswith("admission") else (
        CollectorConditionSource if mutation.startswith("source") else CollectorConditionReceipt)
    table = model.__table__
    with engine.connect() as db:
        values = dict(db.execute(table.select()).mappings().one())
        values["id"] = str(uuid4())
        if model is CollectorConditionSource:
            values["dedup_key"] = "collector.condition:"+values["id"]
        elif model is CollectorConditionReceipt:
            values["result"]["receipt_id"] = values["id"]
        if mutation == "admission_worker":
            values["worker_id"] = "wrong-worker"
        elif mutation == "admission_authority":
            values["context"]["pins"]["independently_verified"] = True
        elif mutation == "source_assignment":
            values["context"]["assignment_sha256"] = "wrong-assignment"
        elif mutation == "source_extra_authority":
            values["context"]["independently_verified"] = True
        elif mutation == "receipt_verdict":
            values["verdict"] = "quiet"
        else:
            values["result"]["independently_verified"] = True
        with pytest.raises(DBAPIError, match="Collector condition reference"):
            db.execute(table.insert().values(**values))
        db.rollback()
        assert db.scalar(text("SELECT count(*) FROM "+table.name)) == 1
