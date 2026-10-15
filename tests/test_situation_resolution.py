"""Manual Alert-state checks are not independent remediation/closure proof."""
from __future__ import annotations

import pytest
from sqlalchemy import func, select, text

from icheck.database import SessionLocal, engine
from icheck.models import Alert, AlertStatus, Situation, SituationAlert, SituationEvent, utcnow
from icheck.services.alerts import resolve_alert
from icheck.services.situations import acknowledge_situation, correlate_alert, resolve_situation
from test_situations import _alert, _device


# Native acceptance replaces only the service sessions with a real RLS role.
session = SessionLocal


def case(client):
    device = _device(client)
    alert = _alert(client, device["id"], event_type="device.cpu.high",
        title="CPU condition", severity="warning", dedup_key="closure:cpu")
    situation = client.get("/api/v1/situations").json()[0]
    return {"device_id": device["id"], "alert_id": alert["id"], "situation_id": situation["id"]}


def set_alert_state(case, status):
    # Deliberately leave the projection behind the authoritative Alert row.
    with session() as db:
        row = db.get(Alert, case["alert_id"])
        row.status = status
        row.resolved_at = utcnow() if status == AlertStatus.RESOLVED else None
        db.commit()


def set_projection(case, *, active=0, status="open"):
    with session() as db:
        row = db.get(Situation, case["situation_id"])
        row.active_alert_count = active
        row.status = status
        row.resolved_at = utcnow() if status == "resolved" else None
        row.resolved_by = "fixture.old.resolver" if status == "resolved" else None
        db.commit()


def events(db, case, kind):
    return list(db.scalars(select(SituationEvent).where(
        SituationEvent.situation_id == case["situation_id"], SituationEvent.event_type == kind)).all())


@pytest.mark.parametrize("status", [AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED])
@pytest.mark.parametrize("projection_status", ["open", "resolved"])
def test_cached_zero_cannot_hide_current_active_alert(client, status, projection_status):
    c = case(client)
    set_alert_state(c, status)
    set_projection(c, status=projection_status)
    response = client.post(f"/api/v1/situations/{c['situation_id']}/resolve", json={"actor": "fixture.operator"})
    assert response.status_code == 409, response.text
    assert "Alerts remain active" in response.text
    with session() as db:
        assert not events(db, c, "situation.resolved")
        assert db.get(Alert, c["alert_id"]).status == status


def test_stale_high_count_resolves_from_alert_truth_and_retries_once(client):
    c = case(client)
    set_alert_state(c, AlertStatus.RESOLVED)
    first = client.post(f"/api/v1/situations/{c['situation_id']}/resolve", json={"actor": "fixture.operator"})
    assert first.status_code == 200, first.text
    assert first.json()["active_alert_count"] == 0
    assert first.json()["status"] == "resolved"
    assert first.json()["summary"].startswith("0 active of 1 correlated alerts;")
    second = client.post(f"/api/v1/situations/{c['situation_id']}/resolve", json={"actor": "different.retry"})
    assert second.status_code == 200, second.text
    assert second.json()["resolved_by"] == first.json()["resolved_by"]
    assert second.json() == first.json()
    with session() as db:
        history = events(db, c, "situation.resolved")
        assert len(history) == 1
        assert history[0].details == {
            "reason": "operator_resolution", "resolution_basis": "manual_alert_state_check/v1",
            "alert_count": 1, "active_alert_count": 0,
            "independently_verified": False, "authorizes_ai_closure": False,
        }
        assert db.scalar(text("SELECT count(*) FROM audit_events WHERE event_type='situation.resolved'")) == 1


def test_empty_membership_cannot_be_resolved(client):
    c = case(client)
    with session() as db:
        membership = db.scalar(select(SituationAlert).where(SituationAlert.situation_id == c["situation_id"]))
        db.delete(membership)
        db.commit()
    response = client.post(f"/api/v1/situations/{c['situation_id']}/resolve", json={"actor": "fixture.operator"})
    assert response.status_code == 409, response.text
    assert "every correlated Alert" in response.text
    with session() as db:
        assert not events(db, c, "situation.resolved")


def test_hidden_alert_cannot_be_treated_as_resolved(client):
    c = case(client)
    # Owner-only corruption drill: the runtime cannot see the referenced Alert.
    with engine.begin() as connection:
        connection.execute(text("UPDATE alerts SET tenant_id=:tenant WHERE id=:id"),
            {"tenant": "10000000-0000-0000-0000-000000000001", "id": c["alert_id"]})
    response = client.post(f"/api/v1/situations/{c['situation_id']}/resolve", json={"actor": "fixture.operator"})
    assert response.status_code == 409, response.text
    assert "every correlated Alert" in response.text
    with session() as db:
        assert not events(db, c, "situation.resolved")


def test_unflushed_alert_change_cannot_cross_the_resolution_check(client):
    c = case(client)
    set_alert_state(c, AlertStatus.RESOLVED)
    with session() as db:
        alert = db.get(Alert, c["alert_id"])
        situation = db.get(Situation, c["situation_id"])
        alert.status = AlertStatus.OPEN
        with pytest.raises(ValueError, match="Persist pending Alert"):
            resolve_situation(db, situation, actor="fixture.operator")
        db.rollback()
    with session() as db:
        assert db.get(Alert, c["alert_id"]).status == AlertStatus.RESOLVED
        assert not events(db, c, "situation.resolved")


@pytest.mark.parametrize("operation", [acknowledge_situation, resolve_situation])
def test_pending_situation_changes_are_not_silently_discarded(client, operation):
    c = case(client)
    with session() as db:
        row = db.get(Situation, c["situation_id"])
        row.title = "Unpersisted caller edit"
        with pytest.raises(ValueError, match="Persist pending Situation"):
            operation(db, row, actor="fixture.operator")
        assert row.title == "Unpersisted caller edit"
        db.rollback()


def test_stale_cached_parent_cannot_acknowledge_a_later_resolution(client):
    c = case(client)
    with session() as stale:
        cached = stale.get(Situation, c["situation_id"])
        assert cached.status == "open"
        response = client.post(f"/api/v1/alerts/{c['alert_id']}/resolve", json={"actor": "fixture.operator"})
        assert response.status_code == 200, response.text
        with pytest.raises(ValueError, match="resolved Situation"):
            acknowledge_situation(stale, cached, actor="stale.operator")
        stale.rollback()
    with session() as db:
        assert not events(db, c, "situation.acknowledged")
        assert len(events(db, c, "situation.resolved")) == 1


def test_projection_refreshes_other_cached_alerts_before_resolution(client):
    c = case(client)
    second = _alert(client, c["device_id"], event_type="device.memory.high",
        title="Memory condition", severity="warning", dedup_key="closure:memory")
    with session() as stale:
        first_alert = stale.get(Alert, c["alert_id"])
        other_alert = stale.get(Alert, second["id"])
        assert other_alert.status == AlertStatus.OPEN
        with session() as writer:
            row = writer.get(Alert, second["id"])
            row.status = AlertStatus.RESOLVED
            writer.commit()
        resolve_alert(stale, first_alert, "fixture.operator")
        stale.commit()
    with session() as db:
        current = db.get(Situation, c["situation_id"])
        assert current.status == "resolved"
        assert current.active_alert_count == 0
        proof = events(db, c, "situation.resolved")
        assert len(proof) == 1
        assert proof[0].details["resolution_basis"] == "correlated_alert_state_projection/v1"
        assert proof[0].details["independently_verified"] is False


def test_current_active_membership_reopens_a_resolved_projection(client):
    c = case(client)
    set_projection(c, status="resolved")
    with session() as db:
        # Existing membership may resume after a parent closure. Refreshing the
        # current sources must not leave the active Alert under a resolved row.
        correlate_alert(db, db.get(Alert, c["alert_id"]), actor="fixture.correlator")
        db.commit()
    with session() as db:
        current = db.get(Situation, c["situation_id"])
        assert current.status == "open"
        assert current.active_alert_count == 1
        assert current.resolved_at is None
        assert current.resolved_by is None
        assert len(events(db, c, "situation.reopened")) == 1
        assert db.scalar(select(func.count()).select_from(SituationAlert)) == 1
