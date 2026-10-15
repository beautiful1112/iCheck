"""Automatic stops use fake native status, never a provider or a lab device."""
from copy import deepcopy
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from icheck.database import SessionLocal
from icheck.models import (AgentExecution, AgentExecutionEvent, AgentExecutionStatus, Alert, AuditEvent,
    AlertRule, AlertStatus, Investigation, MetricRuleChange, utcnow)
from icheck.services import alert_investigation as dispatch
from icheck.services import alert_investigation_control as control
from icheck.services import alertmanager
from icheck.services.alerts import resolve_alert
from test_agent_execution import register_worker, bearer
from test_agent_runtime import configure_investigation_route
from test_investigation_autonomy import enable, new_alert


@pytest.fixture
def automatic(client):
    configure_investigation_route(client)
    enable(client)
    with SessionLocal() as db:
        alert = new_alert(db)
        dispatch.dispatch_alert_investigations(db)
        run = db.scalar(select(Investigation))
        execution = db.scalar(select(AgentExecution))
        return alert.id, run.id, execution.id


def claim(client):
    registration = register_worker(client, "automatic-stop-worker")
    headers = bearer(registration["access_token"])
    result = client.post(f"/api/v1/agent/workers/{registration['worker']['id']}/executions/claim",
        headers=headers, json={"max_assignments": 1, "lease_seconds": 60})
    assert result.status_code == 200, result.text
    return headers, result.json()


def metric_identity(db, alert):
    rule = AlertRule(name="Automatic stop fixture", event_type="metric.prometheus", enabled=True,
        severity="critical", conditions={"revision": 1})
    db.add(rule); db.flush()
    labels = {"icheck_tenant_id": alert.tenant_id, "icheck_region_id": alert.region_id,
              "icheck_metric_rule_id": rule.id, "icheck_metric_rule_revision": "1"}
    compiled = {"alert": "fixture_threshold", "labels": labels}
    db.add(MetricRuleChange(rule_id=rule.id, expected_revision=0, definition={"severity": "critical"},
        target_snapshot={}, backend_revision=1, compiled_rule=compiled, catalog_before={}, catalog_after={},
        runtime_before_hash="a" * 64, runtime_binding={}, plan_hash="b" * 64, status="applied", created_by="fixture"))
    alert.event_type = "metric.prometheus"; alert.rule_id = rule.id
    alert.details = {"metric_rule_revision": 1}; db.commit()
    return {"labels": {"alertname": "fixture_threshold", **labels},
            "status": {"state": "active", "silencedBy": [], "inhibitedBy": []}}


@pytest.fixture
def native(automatic, monkeypatch):
    with SessionLocal() as db:
        row = metric_identity(db, db.get(Alert, automatic[0]))
    class Fake:
        rows = [row]
        calls = 0
        unavailable = False
        def api(self, path):
            assert path == "/api/v2/alerts"
            self.calls += 1
            if self.unavailable:
                from icheck.alertmanager_runtime import AlertmanagerUnavailable
                raise AlertmanagerUnavailable("fixture unavailable")
            return deepcopy(self.rows)
    fake = Fake()
    monkeypatch.setattr(alertmanager, "CLIENT", lambda _: fake)
    return fake


def test_user_close_cancels_queue_atomically_and_preserves_alert_history(client, automatic):
    with SessionLocal() as db:
        alert = db.get(Alert, automatic[0])
        resolve_alert(db, alert, "operator")
        db.commit()
        assert db.get(AgentExecution, automatic[2]).status == AgentExecutionStatus.CANCELLED
        assert db.get(Investigation, automatic[1]).status == "cancelled"
        assert db.get(Alert, automatic[0]).status == AlertStatus.RESOLVED
    assert claim(client)[1] == []


def test_close_rollback_does_not_cancel_run(client, automatic):
    with SessionLocal() as db:
        resolve_alert(db, db.get(Alert, automatic[0]), "operator")
        db.rollback()
        assert db.get(Alert, automatic[0]).status == AlertStatus.OPEN
        assert db.get(AgentExecution, automatic[2]).status == AgentExecutionStatus.QUEUED


@pytest.mark.parametrize("status,assignments", [(AlertStatus.RESOLVED, 0), (AlertStatus.ACKNOWLEDGED, 1)])
def test_source_resolution_stops_before_claim_but_ack_does_not(client, automatic, status, assignments):
    with SessionLocal() as db:
        db.get(Alert, automatic[0]).status = status; db.commit()
    assert len(claim(client)[1]) == assignments


@pytest.mark.parametrize("case", ["silenced", "inhibited", "unavailable", "missing", "malformed", "unprocessed", "disabled", "foreign"])
def test_native_gate_handles_external_silences_without_reimplementing_matchers(client, automatic, native, case):
    if case == "silenced": native.rows[0]["status"].update(state="suppressed", silencedBy=[str(uuid4())])
    if case == "inhibited": native.rows[0]["status"].update(state="suppressed", inhibitedBy=["parent"])
    if case == "unavailable": native.unavailable = True
    if case == "missing": native.rows = []
    if case == "malformed": native.rows[0]["status"] = {}
    if case == "unprocessed": native.rows[0]["status"]["state"] = "unprocessed"
    if case == "disabled":
        with SessionLocal() as db:
            db.get(AlertRule, db.get(Alert, automatic[0]).rule_id).enabled = False; db.commit()
    if case == "foreign":
        foreign = deepcopy(native.rows[0]); foreign["labels"]["icheck_tenant_id"] = "other"
        foreign["status"]["silencedBy"] = [str(uuid4())]; native.rows.append(foreign)
    assignments = claim(client)[1]
    assert bool(assignments) == (case in {"inhibited", "foreign"})
    with SessionLocal() as db:
        assert db.get(Investigation, automatic[1]).tokens_used == 0
        assert db.get(Alert, automatic[0]).status == AlertStatus.OPEN  # silence is not fault recovery


@pytest.mark.parametrize("boundary", ["lease", "reason", "tool"])
def test_silence_during_run_stops_next_boundary_and_stays_stopped(client, automatic, native, boundary):
    headers, assignments = claim(client)
    assignment = assignments[0]
    base = f"/api/v1/agent/executions/{automatic[2]}"
    payload = {"protocol_version": "icheck.agent-runtime/v1", "lease_token": assignment["lease_token"]}
    bootstrap = client.post(base + "/runtime/bootstrap", headers=headers, json=payload)
    assert bootstrap.status_code == 200, bootstrap.text
    native.rows[0]["status"].update(state="suppressed", silencedBy=[str(uuid4())])
    if boundary == "lease":
        result = client.post(base + "/lease", headers=headers,
            json={"lease_token": assignment["lease_token"], "lease_seconds": 60})
        assert result.status_code == 200 and result.json()["cancellation_requested_at"]
    else:
        request = {**payload, "operation_id": "0" * 64, "state": bootstrap.json()["initial_state"]}
        if boundary == "tool": request["request"] = {"tool_name": "inventory.devices.list", "arguments": {}, "rationale": "Check inventory"}
        result = client.post(base + "/runtime/" + boundary, headers=headers, json=request)
        assert result.status_code == 409, result.text
        assert "cancellation" in result.text
    with SessionLocal() as db:
        execution = db.get(AgentExecution, automatic[2])
        assert execution.cancellation_requested_at
        assert not control.enforce_stop(db, execution)
        assert db.scalar(select(func.count()).select_from(AgentExecutionEvent).where(
            AgentExecutionEvent.execution_id == execution.id,
            AgentExecutionEvent.event_type == "execution.cancellation_requested")) == 1
    native.rows[0]["status"].update(state="active", silencedBy=[])
    complete = client.post(base + "/complete", headers=headers,
        json={"lease_token": assignment["lease_token"], "status": "failed", "error": "worker observed stop"})
    assert complete.status_code == 200, complete.text
    assert complete.json()["status"] == "cancelled"
    with SessionLocal() as db:
        assert dispatch.dispatch_alert_investigations(db) == 0
        assert db.get(Investigation, automatic[1]).status == "cancelled"


def test_confirmed_local_silence_stops_immediately_only_matching_revision(client, automatic, native):
    from icheck.services.control_plane_auth import development_principal
    with SessionLocal() as db:
        labels = native.rows[0]["labels"]
        silence = {"id": str(uuid4()), "startsAt": (utcnow() - timedelta(seconds=1)).isoformat(),
            "endsAt": (utcnow() + timedelta(minutes=30)).isoformat(), "matchers": [
                {"name": key, "value": value, "isRegex": False, "isEqual": True}
                for key, value in labels.items() if key != "alertname"]}
        other = deepcopy(silence); other["matchers"][-1]["value"] = "2"
        control.stop_for_silence(db, development_principal(), other); db.commit()
        assert db.get(AgentExecution, automatic[2]).status == AgentExecutionStatus.QUEUED
        request = AuditEvent(event_type=alertmanager.REQUEST, actor_type="user", actor_id="operator",
            entity_type="alertmanager_silence_request", entity_id=str(uuid4()),
            details={"action": "create", "rule_id": labels["icheck_metric_rule_id"]})
        db.add(request); db.flush()
        receipt = alertmanager.finish(db, development_principal(), request, silence)
        assert receipt["status"] == "confirmed"
        assert db.get(AgentExecution, automatic[2]).status == AgentExecutionStatus.CANCELLED
        assert native.calls == 0


def test_manual_conversation_cannot_be_cancelled_by_forged_alert_scope(client, automatic, native):
    created = client.post("/api/v1/agent/investigations", json={"title": "Manual question",
        "objective": "Explain the previous alert", "created_by": "operator", "scope": {"alert_id": automatic[0]}})
    assert created.status_code == 201, created.text
    native.rows[0]["status"]["silencedBy"] = [str(uuid4())]
    with SessionLocal() as db:
        assert control.stop_reason(db, db.get(Investigation, created.json()["id"])) is None
        assert native.calls == 0
