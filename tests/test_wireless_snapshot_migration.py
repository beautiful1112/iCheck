from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from icheck.models import Device, Endpoint, WirelessClientSession, WirelessSnapshotState, utcnow
from test_alert_condition_migration import migrate

HEAD = "x2z4b6d8f0h3"
PREVIOUS = "w1y3a5c7e9g2"


def test_empty_wireless_ordering_roundtrip(tmp_path):
    url = f"sqlite+pysqlite:///{tmp_path/'wireless-empty.sqlite'}"
    migrate(url, HEAD)
    migrate(url, PREVIOUS, "downgrade")
    migrate(url, HEAD)
    engine = create_engine(url)
    with engine.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == HEAD
        assert db.scalar(text("SELECT count(*) FROM wireless_snapshot_states")) == 0
    engine.dispose()


@pytest.fixture
def legacy_wireless(tmp_path):
    url = f"sqlite+pysqlite:///{tmp_path/'wireless-history.sqlite'}"
    migrate(url, PREVIOUS)
    engine = create_engine(url)
    now = utcnow()
    with Session(engine) as db:
        controller = Device(name="legacy-controller", kind="wireless_controller")
        endpoint = Endpoint(mac_address="00:1b:44:11:3a:b7")
        db.add_all([controller, endpoint])
        db.flush()
        db.add(WirelessClientSession(controller_id=controller.id, endpoint_id=endpoint.id,
            active=False, last_seen=now, observed_at=now, disconnected_at=now+timedelta(seconds=1), rssi=-55))
        db.commit()
    yield url, engine, now
    engine.dispose()


def test_legacy_backfill_is_unknown_body_and_preserves_history(legacy_wireless):
    url, engine, now = legacy_wireless
    migrate(url, HEAD)
    with Session(engine) as db:
        row = db.scalar(select(WirelessSnapshotState))
        assert row.state == "legacy_unknown" and row.payload == ""
        assert row.observed_at.replace(tzinfo=now.tzinfo) == now+timedelta(seconds=1)
        old = db.scalar(select(WirelessClientSession))
        assert not old.active and old.rssi == -55
    refused = migrate(url, PREVIOUS, "downgrade", success=False)
    assert "Cannot downgrade recorded wireless snapshot watermarks" in refused.stdout+refused.stderr


@pytest.mark.parametrize("mutation", ["delete", "time", "revision", "identity", "same_clock_body", "noncanonical"])
def test_actual_sqlite_wireless_watermark_guards(legacy_wireless, mutation):
    url, engine, now = legacy_wireless
    migrate(url, HEAD)
    with engine.begin() as db:
        db.execute(text("UPDATE wireless_snapshot_states SET observed_at=:at,state='accepted',payload='{}',revision=revision+1"),
            {"at": (now+timedelta(seconds=2)).strftime("%Y-%m-%d %H:%M:%S.%f")})
    sql = {"delete": "DELETE FROM wireless_snapshot_states",
        "time": "UPDATE wireless_snapshot_states SET observed_at='2020-01-01 00:00:00.000000',revision=revision+1",
        "revision": "UPDATE wireless_snapshot_states SET revision=revision+2",
        "identity": "UPDATE wireless_snapshot_states SET controller_id='different-controller',revision=revision+1",
        "same_clock_body": "UPDATE wireless_snapshot_states SET payload='other-body',state='conflict',revision=revision+1",
        "noncanonical": "UPDATE wireless_snapshot_states SET observed_at='2099-01-01T00:00:00Z',revision=revision+1"}[mutation]
    with engine.connect() as db:
        with pytest.raises(DBAPIError):
            db.execute(text(sql))
        db.rollback()
        assert db.scalar(text("SELECT revision FROM wireless_snapshot_states")) == 2


def test_actual_sqlite_allows_equal_clock_conflict_but_only_newer_resolution(legacy_wireless):
    url, engine, now = legacy_wireless
    migrate(url, HEAD)
    with engine.begin() as db:
        db.execute(text("UPDATE wireless_snapshot_states SET observed_at=:at,state='accepted',payload='{}',revision=revision+1"),
            {"at": (now+timedelta(seconds=2)).strftime("%Y-%m-%d %H:%M:%S.%f")})
        db.execute(text("UPDATE wireless_snapshot_states SET state='conflict',revision=revision+1"))
    with engine.connect() as db:
        with pytest.raises(DBAPIError):
            db.execute(text("UPDATE wireless_snapshot_states SET state='accepted',revision=revision+1"))
        db.rollback()
    with engine.begin() as db:
        db.execute(text("UPDATE wireless_snapshot_states SET observed_at=:at,state='accepted',payload='new-body',revision=revision+1"),
            {"at": (now+timedelta(seconds=2, microseconds=1)).strftime("%Y-%m-%d %H:%M:%S.%f")})


def test_cross_namespace_legacy_reference_refuses_upgrade_without_rewriting(legacy_wireless):
    url, engine, _now = legacy_wireless
    with engine.begin() as db:
        db.execute(text("UPDATE wireless_client_sessions SET tenant_id='other-tenant'"))
    refused = migrate(url, HEAD, success=False)
    assert "Reconcile legacy wireless controller namespace references" in refused.stdout+refused.stderr
    with engine.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == PREVIOUS
        assert db.scalar(text("SELECT tenant_id FROM wireless_client_sessions")) == "other-tenant"
