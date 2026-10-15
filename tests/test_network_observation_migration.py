from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from icheck.models import Device, Endpoint, EndpointAttachment, IPAddressObservation, NetworkObservationState, ObservationSource, utcnow
from test_alert_condition_migration import migrate

HEAD, PREVIOUS = "z4b6d8f0h2j5", "y3a5c7e9g1i4"


def test_empty_inventory_ordering_roundtrip(tmp_path):
    url = f"sqlite+pysqlite:///{tmp_path/'network-empty.sqlite'}"
    migrate(url, HEAD)
    migrate(url, PREVIOUS, "downgrade")
    migrate(url, HEAD)
    engine = create_engine(url)
    with engine.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == HEAD
    engine.dispose()


@pytest.fixture
def legacy_network(tmp_path):
    url = f"sqlite+pysqlite:///{tmp_path/'network-history.sqlite'}"
    migrate(url, PREVIOUS)
    engine = create_engine(url)
    now = utcnow()
    with Session(engine) as db:
        device = Device(name="legacy-observer", kind="switch")
        endpoint = Endpoint(mac_address="00:1b:44:11:3a:b7")
        db.add_all([device, endpoint])
        db.flush()
        db.add(IPAddressObservation(endpoint_id=endpoint.id, collector_device_id=device.id, source=ObservationSource.ARP,
            ip_address="192.0.2.10", active=False, first_seen=now, observed_at=now,
            last_seen=now+timedelta(seconds=1)))
        db.add(EndpointAttachment(endpoint_id=endpoint.id, collector_device_id=device.id, source=ObservationSource.ARP,
            interface_name="eth1", active=False, first_seen=now, observed_at=now, last_seen=now+timedelta(seconds=1)))
        db.commit()
    yield url, engine, now
    engine.dispose()


def test_backfill_retains_inactive_history_and_never_invents_payload_or_quiet(legacy_network):
    url, engine, now = legacy_network
    migrate(url, HEAD)
    with Session(engine) as db:
        rows = list(db.scalars(select(NetworkObservationState)))
        assert {row.dimension for row in rows} == {"ipv4", "attachment", "metadata"}
        assert all(row.state == "legacy_unknown" and row.payload == "" for row in rows)
        assert all(row.observed_at.replace(tzinfo=now.tzinfo) == now+timedelta(seconds=1) for row in rows)
        assert not db.scalar(select(IPAddressObservation)).active
    refused = migrate(url, PREVIOUS, "downgrade", success=False)
    assert "Cannot downgrade recorded network observation watermarks" in refused.stdout+refused.stderr


@pytest.mark.parametrize("mutation", ["delete", "time", "revision", "source", "collector", "endpoint", "same_clock", "noncanonical"])
def test_actual_sqlite_inventory_clock_guards(legacy_network, mutation):
    url, engine, now = legacy_network
    migrate(url, HEAD)
    stamp = (now+timedelta(seconds=2)).strftime("%Y-%m-%d %H:%M:%S.%f")
    with engine.begin() as db:
        db.execute(text("UPDATE network_observation_states SET state='accepted',payload='{}',observed_at=:at,revision=revision+1 WHERE dimension='ipv4'"), {"at": stamp})
    sql = {
        "delete": "DELETE FROM network_observation_states WHERE dimension='ipv4'",
        "time": "UPDATE network_observation_states SET observed_at='2020-01-01 00:00:00.000000',revision=revision+1 WHERE dimension='ipv4'",
        "revision": "UPDATE network_observation_states SET revision=revision+2 WHERE dimension='ipv4'",
        "source": "UPDATE network_observation_states SET source='DHCP',revision=revision+1 WHERE dimension='ipv4'",
        "collector": "UPDATE network_observation_states SET collector_device_id=NULL,collector_key='unbound',revision=revision+1 WHERE dimension='ipv4'",
        "endpoint": "UPDATE network_observation_states SET endpoint_id='another-endpoint',revision=revision+1 WHERE dimension='ipv4'",
        "same_clock": "UPDATE network_observation_states SET payload='other-body',revision=revision+1 WHERE dimension='ipv4'",
        "noncanonical": "UPDATE network_observation_states SET observed_at='2099-01-01T00:00:00Z',revision=revision+1 WHERE dimension='ipv4'",
    }[mutation]
    with engine.connect() as db:
        with pytest.raises(DBAPIError):
            db.execute(text(sql))
        db.rollback()
        assert db.scalar(text("SELECT state FROM network_observation_states WHERE dimension='ipv4'")) == "accepted"


@pytest.mark.parametrize("kind", ["namespace", "clock"])
def test_bad_legacy_references_or_clocks_refuse_upgrade_without_rewriting(legacy_network, kind):
    url, engine, _now = legacy_network
    with engine.begin() as db:
        db.execute(text("UPDATE ip_address_observations SET "+
            ("tenant_id='wrong-tenant'" if kind == "namespace" else "first_seen='2099-01-01 00:00:00.000000'")))
    result = migrate(url, HEAD, success=False)
    assert "Reconcile legacy network references/clocks" in result.stdout+result.stderr
    with engine.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == PREVIOUS
        assert db.scalar(text("SELECT count(*) FROM ip_address_observations")) == 1
