from datetime import timedelta

import pytest
from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from icheck.database import DEFAULT_TENANT_ID, SessionLocal, engine
from icheck.models import Alert, AlertConditionState, AlertRule, AlertSeverity, AlertStatus, Situation, utcnow
from icheck.services.alerts import acknowledge_alert, emit_for_rules, resolve_alert, resolve_by_dedup_key, upsert_alert
from test_situations import _device

session = SessionLocal


def emit(db, at, *, key="ordered:cpu", entity_id="device-source", **changes):
    args = dict(dedup_key=key, event_type="device.cpu.high", severity=AlertSeverity.WARNING,
        title="CPU condition", description="Controlled source", entity_type="device", entity_id=entity_id,
        details={"value": 80}, observed_at=at)
    args.update(changes)
    return upsert_alert(db, **args)


def cursor(db, key="ordered:cpu"):
    return db.scalar(select(AlertConditionState).where(AlertConditionState.dedup_key == key))


def test_duplicate_timestamp_does_not_add_occurrence_or_episode(client):
    now = utcnow()
    with session() as db:
        first = emit(db, now)
        db.commit()
        rev = cursor(db).revision
        again = emit(db, now, details={"value": 90})
        db.commit()
        assert again.id == first.id and again.occurrence_count == 1
        assert again.details == {"value": 80}
        assert cursor(db).revision == rev
        assert again._observation_disposition == "duplicate"


def test_older_positive_cannot_overwrite_newer_source(client):
    now = utcnow()
    with session() as db:
        row = emit(db, now)
        db.commit()
        stale = emit(db, now-timedelta(seconds=1), title="Stale title", details={"value": 99})
        db.commit()
        assert stale.id == row.id and stale.occurrence_count == 1
        assert stale.title == "CPU condition" and stale._observation_disposition == "stale"


def test_unbound_legacy_owner_caller_cannot_select_another_namespaces_active_key(client):
    from uuid import uuid4

    now = utcnow()
    foreign_id = str(uuid4())
    with engine.begin() as db:
        db.execute(insert(Alert).values(id=foreign_id,tenant_id=str(uuid4()),region_id=str(uuid4()),
            dedup_key="ordered:cpu",event_type="device.cpu.high",severity=AlertSeverity.WARNING,
            status=AlertStatus.OPEN,title="Foreign source",description="",entity_type="device",entity_id="foreign-device",
            occurrence_count=1,details={},first_seen=now,last_seen=now))
    with Session(bind=engine,autoflush=False,expire_on_commit=False) as db:
        assert not db.info.get("namespace_enforced")
        local = emit(db, now)
        db.commit()
        assert local.id != foreign_id and local.tenant_id == DEFAULT_TENANT_ID
        resolve_by_dedup_key(db,"ordered:cpu","fixture.source",now+timedelta(seconds=1))
        db.commit()
        assert db.get(Alert,local.id).status == AlertStatus.RESOLVED
        foreign = db.get(Alert,foreign_id)
        assert foreign.status == AlertStatus.OPEN and foreign.occurrence_count == 1
        assert foreign.entity_id == "foreign-device"


def test_future_network_alert_failure_returns_422_and_rolls_back_inventory(client):
    now = utcnow()
    item = {"mac_address":"00:1b:44:11:3a:b7","source":"arp","ip_address":"10.20.1.10","observed_at":now.isoformat()}
    route = "/api/v1/inventory/network-observations"
    first = client.post(route,json={"observations":[item]})
    assert first.status_code == 200,first.text
    response = client.post(route,json={"observations":[{**item,"ip_address":"10.20.1.11",
        "observed_at":(now+timedelta(hours=1)).isoformat()}]})
    assert response.status_code == 422 and "future clock bound" in response.text
    endpoint = client.get("/api/v1/endpoints").json()[0]
    assert [row["address"] for row in endpoint["current_ips"]] == ["10.20.1.10"]
    with session() as db:
        assert not list(db.scalars(select(AlertConditionState)))


@pytest.mark.parametrize("kind", ["alert", "condition"])
def test_pending_source_edits_cannot_be_flushed_or_overwritten_by_observation(client, kind):
    now = utcnow()
    with session() as db:
        row = emit(db, now)
        db.commit()
        if kind == "alert":
            row.title = "Pending local edit"
        else:
            cursor(db).state = "quiet"
        with pytest.raises(ValueError, match="pending Alert source edits"):
            emit(db, now + timedelta(seconds=1))
        db.rollback()
        assert db.get(Alert, row.id).title == "CPU condition"
        assert cursor(db).state == "active"


def test_deleting_rule_preserves_original_pin_and_allows_only_manual_history_resolution(client):
    now = utcnow()
    with session() as db:
        rule = AlertRule(name="retired-source-rule",event_type="device.cpu.high",
            severity=AlertSeverity.WARNING,conditions={})
        db.add(rule)
        db.commit()
        rule_id = rule.id
        row = emit(db,now,rule_id=rule_id)
        db.commit()
        db.delete(rule)
        db.commit()
        resolved = resolve_alert(db,row,"fixture.operator")
        db.commit()
        assert resolved.rule_id is None and resolved.status == AlertStatus.RESOLVED
        assert cursor(db).source_rule_id == rule_id and cursor(db).state == "active"
        with pytest.raises(ValueError,match="different source identity"):
            emit(db,now+timedelta(seconds=1),rule_id=None)
        db.rollback()


def test_older_recovery_cannot_resolve_current_active_condition(client):
    now = utcnow()
    with session() as db:
        row = emit(db, now)
        db.commit()
        resolve_by_dedup_key(db, "ordered:cpu", "fixture.source", now-timedelta(seconds=1))
        db.commit()
        assert row.status == AlertStatus.OPEN
        assert cursor(db).state == "active"
        assert db.scalar(select(Situation)).status == "open"


def test_quiet_watermark_before_first_positive_blocks_older_episode(client):
    now = utcnow()
    with session() as db:
        assert resolve_by_dedup_key(db, "ordered:cpu", "fixture.source", now) is None
        db.commit()
        assert emit(db, now-timedelta(seconds=1)) is None
        db.commit()
        assert not list(db.scalars(select(Alert)))
        assert cursor(db).state == "quiet" and cursor(db).entity_id is None
        assert emit(db, now+timedelta(seconds=1)).status == AlertStatus.OPEN
        db.commit()


def test_old_positive_after_quiet_returns_history_not_a_new_episode(client):
    now = utcnow()
    with session() as db:
        row = emit(db, now)
        db.commit()
        resolve_by_dedup_key(db, "ordered:cpu", "fixture.source", now+timedelta(seconds=1))
        db.commit()
        ignored = emit(db, now)
        db.commit()
        assert ignored.id == row.id and ignored.status == AlertStatus.RESOLVED
        assert cursor(db).state == "quiet"
        newer = emit(db, now+timedelta(seconds=2))
        db.commit()
        assert newer.id != row.id and newer.status == AlertStatus.OPEN


@pytest.mark.parametrize("quiet_first", [False, True])
def test_same_time_contradiction_keeps_active_and_conflict_until_newer_sample(client, quiet_first):
    now = utcnow()
    with session() as db:
        if quiet_first:
            resolve_by_dedup_key(db, "ordered:cpu", "fixture.source", now)
            db.commit()
        row = emit(db, now)
        db.commit()
        if not quiet_first:
            resolve_by_dedup_key(db, "ordered:cpu", "fixture.source", now)
            db.commit()
        assert row.status == AlertStatus.OPEN and cursor(db).state == "conflict"
        resolve_by_dedup_key(db, "ordered:cpu", "fixture.source", now)
        db.commit()
        assert row.status == AlertStatus.OPEN and cursor(db).state == "conflict"
        resolve_by_dedup_key(db, "ordered:cpu", "fixture.source", now+timedelta(seconds=1))
        db.commit()
        assert row.status == AlertStatus.RESOLVED and cursor(db).state == "quiet"


def test_source_key_cannot_be_rebound_to_another_target(client):
    now = utcnow()
    with session() as db:
        row = emit(db, now)
        db.commit()
        with pytest.raises(ValueError, match="different source identity"):
            emit(db, now+timedelta(seconds=1), entity_id="different-device")
        db.rollback()
        assert cursor(db).entity_id == row.entity_id


def test_manual_resolution_is_not_source_quiet_or_a_replay_permission(client):
    now = utcnow()
    with session() as db:
        row = emit(db, now)
        db.commit()
        resolve_alert(db, row, "fixture.operator")
        db.commit()
        assert cursor(db).state == "active"
        assert emit(db, now).id == row.id
        db.commit()
        assert row.status == AlertStatus.RESOLVED
        assert emit(db, now+timedelta(seconds=1)).id != row.id
        db.commit()


def test_stale_cached_active_alert_cannot_acknowledge_a_resolved_row(client):
    now = utcnow()
    with session() as db:
        row = emit(db, now)
        db.commit()
        with session() as other:
            resolve_alert(other, other.get(Alert, row.id), "fixture.resolver")
            other.commit()
        with pytest.raises(ValueError, match="resolved alert"):
            acknowledge_alert(db, row, "stale.operator")
        db.rollback()


@pytest.mark.parametrize("rssi", [None, True, False, "-80", 100])
def test_missing_or_invalid_rssi_is_unknown_not_quiet_and_blocks_older_recovery(client, rssi):
    _device(client)
    now = utcnow()
    with session() as db:
        rule = db.scalar(select(AlertRule).where(AlertRule.event_type == "wireless.rssi.low"))
        args = dict(event_type=rule.event_type, entity_type="endpoint", entity_id="wireless-source",
            title="Weak RSSI", description="Controlled radio source")
        first = emit_for_rules(db, **args, details={"rssi": -82}, observed_at=now)[0]
        db.commit()
        key = first.dedup_key
        emit_for_rules(db, **args, details={"rssi": rssi}, observed_at=now+timedelta(seconds=2))
        db.commit()
        assert cursor(db, key).state == "unknown" and first.status == AlertStatus.OPEN
        emit_for_rules(db, **args, details={"rssi": -50}, observed_at=now+timedelta(seconds=1))
        db.commit()
        assert first.status == AlertStatus.OPEN and cursor(db, key).state == "unknown"
        emit_for_rules(db, **args, details={"rssi": -50}, observed_at=now+timedelta(seconds=3))
        db.commit()
        assert first.status == AlertStatus.RESOLVED and cursor(db, key).state == "quiet"


def test_future_clock_poisoning_is_rejected_without_a_watermark(client):
    with session() as db:
        with pytest.raises(ValueError, match="five-minute future"):
            emit(db, utcnow()+timedelta(minutes=6))
        db.rollback()
        assert cursor(db) is None


@pytest.mark.parametrize("invalid_rssi", [False,True])
def test_boolean_wireless_rssi_cannot_be_coerced_to_quiet_or_change_telemetry(client,invalid_rssi):
    from icheck.models import WirelessClientSession
    from test_inventory import create_device

    controller = create_device(client,name="ordered-wlc",kind="wireless_controller")
    now = utcnow()
    client_row = {"mac_address":"00:1b:44:11:3a:b7","rssi":-85,"observed_at":now.isoformat()}
    route = "/api/v1/inventory/wireless-snapshots"
    first = client.post(route,json={"controller_id":controller["id"],"observed_at":now.isoformat(),"clients":[client_row]})
    assert first.status_code == 200,first.text
    response = client.post(route,json={"controller_id":controller["id"],"observed_at":(now+timedelta(seconds=1)).isoformat(),
        "clients":[{**client_row,"rssi":invalid_rssi,"observed_at":(now+timedelta(seconds=1)).isoformat()}]})
    assert response.status_code == 422 and "not a boolean" in response.text
    with session() as db:
        assert db.scalar(select(Alert)).status == AlertStatus.OPEN
        assert db.scalar(select(AlertConditionState)).state == "active"
        assert db.scalar(select(WirelessClientSession)).rssi == -85


def test_http_disposition_and_stale_without_episode_are_explicit(client):
    now = utcnow()
    payload = {"event_type": "device.cpu.high", "entity_type": "device", "entity_id": "device-source",
        "title": "CPU condition", "dedup_key": "ordered:cpu", "observed_at": now.isoformat()}
    first = client.post("/api/v1/alerts/events", json=payload)
    assert first.status_code == 201, first.text
    assert first.headers["X-Icheck-Alert-Observation"] == "accepted"
    again = client.post("/api/v1/alerts/events", json=payload)
    assert again.status_code == 201 and again.headers["X-Icheck-Alert-Observation"] == "duplicate"
    with session() as db:
        resolve_by_dedup_key(db, "empty:condition", "fixture.source", now)
        db.commit()
    stale = client.post("/api/v1/alerts/events", json={**payload, "dedup_key": "empty:condition",
        "observed_at": (now-timedelta(seconds=1)).isoformat()})
    assert stale.status_code == 409 and "no Alert episode" in stale.text
