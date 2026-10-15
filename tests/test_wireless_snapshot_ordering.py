from datetime import timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from icheck.database import SessionLocal
from icheck.models import Alert, AlertConditionState, AlertRule, AlertStatus, Endpoint, IPAddressObservation, ObservationSource, WirelessClientSession, WirelessSnapshotState, utcnow
from icheck.projection_schemas import WirelessSnapshotProjection
from icheck.schemas import WirelessSnapshot
from icheck.services.alert_conditions import as_utc
from icheck.services.alerts import emit_for_rules
from icheck.services.inventory import ingest_wireless_snapshot

session = SessionLocal
ROUTE = "/api/v1/inventory/wireless-snapshots"
MAC = "00:1b:44:11:3a:b7"


def controller(client, name="ordered-controller"):
    response = client.post("/api/v1/devices", json={"name": name, "kind": "wireless_controller", "site": "HQ"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def body(device, at, *, clients=None, complete=True):
    return {"controller_id": device, "observed_at": at.isoformat(), "complete_snapshot": complete,
        "clients": [{"mac_address": MAC, "ip_address": "10.30.1.54", "rssi": -85, "access_point": "ap-1"}] if clients is None else clients}


def post(client, payload, expected="accepted"):
    response = client.post(ROUTE, json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["snapshot_disposition"] == expected
    return response.json()


def signal(db):
    return db.scalar(select(AlertConditionState).where(AlertConditionState.event_type == "wireless.rssi.low"))


def test_complete_absence_is_unknown_and_blocks_late_recovery_without_resurrecting_client(client):
    device, now = controller(client), utcnow()
    first = post(client, body(device, now))
    alert_id = first["alert_ids"][0]
    assert client.post(f"/api/v1/alerts/{alert_id}/acknowledge", json={"actor": "operator"}).status_code == 200
    gone_at = now + timedelta(seconds=2)
    gone = post(client, body(device, gone_at, clients=[]))
    assert gone["sessions_closed"] == 1
    with session() as db:
        state = signal(db)
        assert state.state == "unknown" and as_utc(state.observed_at) == gone_at
        assert db.get(Alert, alert_id).status == AlertStatus.ACKNOWLEDGED
        assert not db.scalar(select(WirelessClientSession)).active
        assert not db.scalar(select(IPAddressObservation)).active
        endpoint_id = db.scalar(select(Endpoint.id))
        emit_for_rules(db, event_type="wireless.rssi.low", entity_type="endpoint", entity_id=endpoint_id,
            title="Delayed recovery", description="", details={"rssi": -50}, observed_at=now+timedelta(seconds=1),
            dedup_suffix=device)
        db.commit()
        assert signal(db).state == "unknown"
        assert db.get(Alert, alert_id).status == AlertStatus.ACKNOWLEDGED
    late = post(client, body(device, now+timedelta(seconds=1),
        clients=[{"mac_address": MAC, "rssi": -50, "access_point": "old-ap"}], complete=False), "stale")
    assert late["wireless_sessions_written"] == 0 and late["endpoints_updated"] == 0
    with session() as db:
        assert not db.scalar(select(WirelessClientSession)).active
    post(client, body(device, gone_at+timedelta(seconds=1)))
    with session() as db:
        assert signal(db).state == "active"
        assert db.get(Alert, alert_id).status == AlertStatus.ACKNOWLEDGED
        assert db.scalar(select(func.count()).select_from(WirelessClientSession)) == 2


def test_partial_absence_does_not_close_sessions_or_change_signal_truth(client):
    device, now = controller(client), utcnow()
    post(client, body(device, now))
    result = post(client, body(device, now+timedelta(seconds=1), clients=[], complete=False))
    assert result["sessions_closed"] == 0
    with session() as db:
        assert signal(db).state == "active" and as_utc(signal(db).observed_at) == now
        assert db.scalar(select(WirelessClientSession)).active
        assert db.scalar(select(IPAddressObservation)).active


def test_complete_empty_before_first_client_rejects_older_unknown_client(client):
    device, now = controller(client), utcnow()
    post(client, body(device, now, clients=[]))
    result = post(client, body(device, now-timedelta(seconds=1), complete=False), "stale")
    assert result["endpoints_created"] == 0 and result["alert_ids"] == []
    with session() as db:
        assert db.scalar(select(func.count()).select_from(Endpoint)) == 0
        assert db.scalar(select(func.count()).select_from(Alert)) == 0
        assert as_utc(db.scalar(select(WirelessSnapshotState)).observed_at) == now


def test_retry_normalizes_mac_client_order_and_timezone_without_new_occurrence(client):
    device, now = controller(client), utcnow()
    clients = [{"mac_address": MAC, "rssi": -85}, {"mac_address": "00:1b:44:11:3a:b8", "rssi": -55}]
    original = body(device, now, clients=clients)
    post(client, original)
    equivalent = {**original, "observed_at": now.isoformat().replace("+00:00", "Z"),
        "clients": [{**clients[1], "observed_at": now.isoformat()}, {**clients[0], "mac_address": "001B.4411.3AB7"}]}
    result = post(client, equivalent, "duplicate")
    assert result["wireless_sessions_written"] == 0
    with session() as db:
        assert db.scalar(select(Alert)).occurrence_count == 1
        assert db.scalar(select(func.count()).select_from(WirelessClientSession)) == 2
        assert db.scalar(select(WirelessSnapshotState)).revision == 2


@pytest.mark.parametrize("contradiction", ["quiet", "empty", "partial"])
def test_equal_time_contradiction_freezes_inventory_and_source_until_newer_sample(client, contradiction):
    device, now = controller(client), utcnow()
    original = body(device, now)
    post(client, original)
    conflicting = (body(device, now, clients=[{"mac_address": MAC, "rssi": -50}]) if contradiction == "quiet"
        else body(device, now, clients=[]) if contradiction == "empty" else {**original, "complete_snapshot": False})
    result = post(client, conflicting, "conflict")
    assert result["sessions_closed"] == 0 and result["alert_ids"] == []
    with session() as db:
        assert db.scalar(select(WirelessClientSession)).rssi == -85
        assert db.scalar(select(WirelessClientSession)).active
        assert db.scalar(select(Alert)).status == AlertStatus.OPEN
        assert signal(db).state == "conflict"
        assert db.scalar(select(WirelessSnapshotState)).revision == 3
    post(client, original, "conflict")
    with session() as db:
        assert db.scalar(select(WirelessSnapshotState)).revision == 3
    post(client, body(device, now+timedelta(seconds=1), clients=[{"mac_address": MAC, "rssi": -50}]))
    with session() as db:
        assert signal(db).state == "quiet"
        assert db.scalar(select(Alert)).status == AlertStatus.RESOLVED


def test_repeated_complete_absence_advances_even_for_already_inactive_client_and_disabled_rule(client):
    device, now = controller(client), utcnow()
    post(client, body(device, now))
    with session() as db:
        db.scalar(select(AlertRule).where(AlertRule.event_type == "wireless.rssi.low")).enabled = False
        db.commit()
    post(client, body(device, now+timedelta(seconds=1), clients=[]))
    second = post(client, body(device, now+timedelta(seconds=2), clients=[]))
    assert second["sessions_closed"] == 0
    with session() as db:
        assert signal(db).state == "unknown" and as_utc(signal(db).observed_at) == now+timedelta(seconds=2)
        assert db.scalar(select(Alert)).status == AlertStatus.OPEN


@pytest.mark.parametrize("invalid", ["duplicate_mac", "older_client", "newer_client", "connected_future", "boolean_complete", "future_empty"])
def test_invalid_snapshots_roll_back_without_poisoning_saved_state(client, invalid):
    device, now = controller(client), utcnow()
    post(client, body(device, now))
    next_at = now+timedelta(seconds=1)
    payload = body(device, next_at)
    if invalid == "duplicate_mac":
        payload["clients"] += [{"mac_address": "001b.4411.3ab7", "rssi": -55}]
    elif invalid in {"older_client", "newer_client"}:
        payload["clients"][0]["observed_at"] = (next_at+timedelta(seconds=-1 if invalid == "older_client" else 1)).isoformat()
    elif invalid == "connected_future":
        payload["clients"][0]["connected_at"] = (next_at+timedelta(seconds=1)).isoformat()
    elif invalid == "boolean_complete":
        payload["complete_snapshot"] = "false"
    else:
        payload = body(device, now+timedelta(minutes=6), clients=[])
    response = client.post(ROUTE, json=payload)
    assert response.status_code == 422, response.text
    with session() as db:
        assert as_utc(db.scalar(select(WirelessSnapshotState)).observed_at) == now
        assert signal(db).state == "active"
        assert db.scalar(select(WirelessClientSession)).rssi == -85
        assert db.scalar(select(Alert)).occurrence_count == 1


@pytest.mark.parametrize("value", [False, True])
def test_generated_projection_rejects_boolean_rssi_before_coercion(value):
    with pytest.raises(ValidationError, match="not a boolean"):
        WirelessSnapshotProjection.model_validate({"clients": [{"mac_address": MAC, "rssi": value}]})


def test_direct_wifi_observation_cannot_bypass_snapshot_contract(client):
    device = controller(client)
    response = client.post("/api/v1/inventory/network-observations", json={"observations": [
        {"mac_address": MAC, "source": "wifi_controller", "collector_device_id": device, "ip_address": "10.0.0.1"}]})
    assert response.status_code == 422 and "snapshot contract" in response.text
    with session() as db:
        assert db.scalar(select(func.count()).select_from(Endpoint)) == 0


def test_other_collectors_and_other_controller_associations_are_not_closed(client):
    device, other, now = controller(client), controller(client, "second-controller"), utcnow()
    post(client, body(device, now))
    post(client, body(other, now+timedelta(seconds=1),
        clients=[{"mac_address": MAC, "hostname": "newer-name", "rssi": -50, "ip_address": "10.0.2.1"}]))
    response = client.post("/api/v1/inventory/network-observations", json={"observations": [
        {"mac_address": MAC, "source": "arp", "collector_device_id": other, "ip_address": "10.0.3.1",
         "observed_at": (now+timedelta(seconds=2)).isoformat()}]})
    assert response.status_code == 200, response.text
    post(client, body(device, now+timedelta(seconds=3), clients=[]))
    with session() as db:
        assert db.scalar(select(WirelessClientSession).where(WirelessClientSession.controller_id == other)).active
        assert db.scalar(select(IPAddressObservation).where(IPAddressObservation.source == ObservationSource.ARP)).active
        assert db.scalar(select(Endpoint)).hostname == "newer-name"


def test_controller_local_clock_does_not_regress_shared_endpoint_metadata(client):
    device, other, now = controller(client), controller(client, "newer-controller"), utcnow()
    post(client, body(other, now, clients=[{"mac_address": MAC, "hostname": "current-name", "rssi": -55}]))
    post(client, body(device, now-timedelta(seconds=1),
        clients=[{"mac_address": MAC, "hostname": "old-name", "rssi": -85}]))
    with session() as db:
        row = db.scalar(select(Endpoint))
        assert row.hostname == "current-name" and as_utc(row.last_seen) == now
        assert as_utc(row.first_seen) == now-timedelta(seconds=1)


def test_service_revalidates_mutated_models_before_writing(client):
    device, now = controller(client), utcnow()
    payload = WirelessSnapshot.model_validate(body(device, now))
    payload.clients[0].rssi = False
    with session() as db:
        with pytest.raises(ValueError, match="not a boolean"):
            ingest_wireless_snapshot(db, payload)
        db.rollback()
        assert db.scalar(select(func.count()).select_from(WirelessSnapshotState)) == 0


@pytest.mark.parametrize("kind", ["controller", "snapshot", "endpoint"])
def test_pending_ingestion_objects_are_not_silently_overwritten(client, kind):
    from icheck.models import Device

    device, now = controller(client), utcnow()
    post(client, body(device, now))
    with session() as db:
        row = (db.get(Device, device) if kind == "controller" else
            db.scalar(select(WirelessSnapshotState)) if kind == "snapshot" else db.scalar(select(Endpoint)))
        attribute = "name" if kind == "controller" else "payload" if kind == "snapshot" else "hostname"
        setattr(row, attribute, "pending-user-edit")
        with pytest.raises(ValueError, match="Persist pending"):
            ingest_wireless_snapshot(db, WirelessSnapshot.model_validate(body(device, now+timedelta(seconds=1))))
        assert getattr(row, attribute) == "pending-user-edit"
        db.rollback()
        assert as_utc(db.scalar(select(WirelessSnapshotState)).observed_at) == now
        assert db.scalar(select(Alert)).occurrence_count == 1


@pytest.mark.parametrize("value", [False, True])
def test_generated_wireless_envelope_retains_failure_without_mutating_inventory(client, value):
    from icheck.models import KnowledgeProjection, KnowledgeProjectionStatus
    from icheck.projection_schemas import WIRELESS_SNAPSHOT_V1
    from test_knowledge_projection import _post_envelope, _project_one, _start_scoped_run

    _device, assignment, headers = _start_scoped_run(client, name="invalid-wireless", device_kind="wireless_controller")
    response = _post_envelope(client, assignment, headers, {"kind": "observation", "type": WIRELESS_SNAPSHOT_V1,
        "source": "wlc-api", "observed_at": utcnow().isoformat(), "idempotency_key": "invalid-wireless-bool",
        "payload": {"clients": [{"mac_address": MAC, "rssi": value}]}})
    assert response.status_code == 200, response.text
    projection_id, status = _project_one()
    assert status == KnowledgeProjectionStatus.DEAD_LETTER
    with session() as db:
        record = db.get(KnowledgeProjection, projection_id)
        assert record.error_type == "ValidationError" and record.error_sha256
        assert db.scalar(select(func.count()).select_from(Endpoint)) == 0
        assert db.scalar(select(func.count()).select_from(WirelessSnapshotState)) == 0


def test_controller_absence_cannot_claim_an_unrelated_manual_source_with_matching_suffix(client):
    device, now = controller(client), utcnow()
    post(client, body(device, now))
    with session() as db:
        endpoint_id = db.scalar(select(Endpoint.id))
    key = f"manual-source:{device}"
    response = client.post("/api/v1/alerts/events", json={"event_type": "wireless.rssi.low",
        "entity_type": "endpoint", "entity_id": endpoint_id, "title": "Independent manual signal",
        "dedup_key": key, "observed_at": now.isoformat()})
    assert response.status_code == 201, response.text
    post(client, body(device, now+timedelta(seconds=1), clients=[]))
    with session() as db:
        manual = db.scalar(select(AlertConditionState).where(AlertConditionState.dedup_key == key))
        assert manual.state == "active" and as_utc(manual.observed_at) == now
        owned = db.scalar(select(AlertConditionState).where(AlertConditionState.source_rule_id.is_not(None)))
        assert owned.state == "unknown"


def test_service_legacy_fallback_never_invents_a_snapshot_body_or_reapplies_equal_clock(client):
    device, now = controller(client), utcnow()
    with session() as db:
        endpoint = Endpoint(mac_address=MAC)
        db.add(endpoint)
        db.flush()
        db.add(WirelessClientSession(controller_id=device, endpoint_id=endpoint.id,
            rssi=-55, active=True, last_seen=now, observed_at=now))
        db.commit()
    post(client, body(device, now), "legacy_unknown")
    post(client, body(device, now-timedelta(seconds=1)), "stale")
    with session() as db:
        state = db.scalar(select(WirelessSnapshotState))
        assert state.state == "legacy_unknown" and state.payload == ""
        assert db.scalar(select(WirelessClientSession)).rssi == -55
    post(client, body(device, now+timedelta(seconds=1)))
    with session() as db:
        assert db.scalar(select(WirelessSnapshotState)).state == "accepted"
        assert db.scalar(select(Alert)).status == AlertStatus.OPEN
