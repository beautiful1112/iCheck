from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from icheck.database import SessionLocal
from icheck.models import (
    Investigation,
    WorkflowScheduleActivation,
    WorkflowScheduleEvent,
    utcnow,
)
from icheck.services.cron_schedule import (
    next_cron_occurrence,
    parse_cron,
    validate_cron_schedule,
)
from icheck.services.workflow_runtime import (
    dispatch_workflow_schedule_events,
    enqueue_due_workflow_schedules,
)

from test_workflow_runtime import (
    WORKFLOW_SPEC,
    _configure_route,
    _publish_workflow,
)


SCHEDULE_WORKFLOW_SPEC = copy.deepcopy(WORKFLOW_SPEC)
SCHEDULE_WORKFLOW_SPEC["artifact_name"] = "scheduled-device-triage-runtime"
SCHEDULE_WORKFLOW_SPEC["trigger"] = {
    "trigger_type": "schedule",
    "event_type": None,
}


def _activate(client, version_id: str, **overrides):
    document = {
        "cron_expression": "*/5 * * * *",
        "timezone": "UTC",
        "route_purpose": "investigation",
        "authorization_scope": {},
        "workflow_input": {"device_id": "scheduled-device-01"},
        "misfire_grace_seconds": 300,
        "actor": "capability.publisher",
        **overrides,
    }
    return client.post(
        f"/api/v1/workflow-runtime/workflows/{version_id}/schedule-activation",
        json=document,
    )


def test_bounded_cron_parser_and_timezone_calculation():
    with pytest.raises(ValueError, match="exactly five"):
        parse_cron("0 1 * *")
    with pytest.raises(ValueError, match="minute"):
        parse_cron("61 1 * * *")
    with pytest.raises(ValueError, match="five minutes"):
        validate_cron_schedule(
            "* * * * *",
            "UTC",
            after=datetime(2026, 9, 25, 0, 0, tzinfo=UTC),
        )
    normalized, first = validate_cron_schedule(
        "*/5   * * * *",
        "UTC",
        after=datetime(2026, 9, 25, 0, 1, tzinfo=UTC),
    )
    assert normalized == "*/5 * * * *"
    assert first == datetime(2026, 9, 25, 0, 5, tzinfo=UTC)
    shanghai = next_cron_occurrence(
        "0 9 * * 1-5",
        "Asia/Shanghai",
        datetime(2026, 9, 25, 0, 30, tzinfo=UTC),
    )
    assert shanghai == datetime(2026, 9, 25, 1, 0, tzinfo=UTC)
    with pytest.raises(ValueError, match="timezone"):
        next_cron_occurrence(
            "0 9 * * *",
            "Not/A_Real_Zone",
            datetime(2026, 9, 25, 0, 0, tzinfo=UTC),
        )


def test_schedule_activation_enqueues_and_dispatches_once(client):
    _configure_route(client)
    version = _publish_workflow(client, SCHEDULE_WORKFLOW_SPEC)
    too_frequent = _activate(client, version["id"], cron_expression="* * * * *")
    assert too_frequent.status_code == 422
    assert "five minutes" in too_frequent.text
    invalid_timezone = _activate(
        client,
        version["id"],
        timezone="Not/A_Real_Zone",
    )
    assert invalid_timezone.status_code == 422

    activated = _activate(client, version["id"])
    assert activated.status_code == 201, activated.text
    activation = activated.json()
    assert activation["cron_expression"] == "*/5 * * * *"
    assert activation["timezone"] == "UTC"
    assert activation["workflow_input"] == {
        "device_id": "scheduled-device-01"
    }
    duplicate = _activate(client, version["id"])
    assert duplicate.status_code == 422
    assert "already has" in duplicate.text

    scan_time = utcnow().replace(second=5, microsecond=0)
    due = scan_time - timedelta(seconds=30)
    with SessionLocal() as db:
        record = db.get(WorkflowScheduleActivation, activation["id"])
        assert record is not None
        record.next_fire_at = due
        db.commit()
    with SessionLocal() as db:
        assert enqueue_due_workflow_schedules(db, now=scan_time) == 1
        assert enqueue_due_workflow_schedules(
            db,
            now=scan_time + timedelta(seconds=1),
        ) == 0
        events = list(db.scalars(select(WorkflowScheduleEvent)).all())
        assert len(events) == 1
        assert events[0].status == "pending"
        record = db.get(WorkflowScheduleActivation, activation["id"])
        assert record is not None
        assert record.next_fire_at > scan_time.replace(tzinfo=None)

    listed = client.get("/api/v1/workflow-runtime/schedule-events").json()
    assert len(listed) == 1
    assert listed[0]["activation_id"] == activation["id"]
    with SessionLocal() as db:
        assert dispatch_workflow_schedule_events(db) == 1
        event = db.get(WorkflowScheduleEvent, listed[0]["id"])
        assert event is not None
        assert event.status == "succeeded"
        investigations = list(
            db.scalars(
                select(Investigation).where(
                    Investigation.workflow_schedule_event_id == event.id
                )
            ).all()
        )
        assert len(investigations) == 1
        assert investigations[0].workflow_input == {
            "device_id": "scheduled-device-01"
        }
        assert investigations[0].status == "running"
        assert dispatch_workflow_schedule_events(db) == 0

    disabled = client.post(
        f"/api/v1/workflow-runtime/schedule-activations/{activation['id']}/disable",
        json={"actor": "capability.publisher"},
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["enabled"] is False
    with SessionLocal() as db:
        record = db.get(WorkflowScheduleActivation, activation["id"])
        assert record is not None
        record.next_fire_at = utcnow() - timedelta(seconds=10)
        db.commit()
    with SessionLocal() as db:
        assert enqueue_due_workflow_schedules(db, now=utcnow()) == 0

    audit_text = json.dumps(client.get("/api/v1/audit-events?limit=1000").json())
    assert "scheduled-device-01" not in audit_text


def test_schedule_misfire_is_skipped_and_observable(client):
    _configure_route(client)
    version = _publish_workflow(client, SCHEDULE_WORKFLOW_SPEC)
    activated = _activate(
        client,
        version["id"],
        misfire_grace_seconds=60,
    )
    assert activated.status_code == 201, activated.text
    activation = activated.json()
    current = utcnow()
    with SessionLocal() as db:
        record = db.get(WorkflowScheduleActivation, activation["id"])
        assert record is not None
        record.next_fire_at = current - timedelta(minutes=10)
        db.commit()
    with SessionLocal() as db:
        assert enqueue_due_workflow_schedules(db, now=current) == 0
        record = db.get(WorkflowScheduleActivation, activation["id"])
        assert record is not None
        assert record.missed_runs == 1
        assert record.last_misfire_at is not None
        assert record.next_fire_at > current.replace(tzinfo=None)
        assert db.scalar(select(func.count()).select_from(WorkflowScheduleEvent)) == 0
    audits = client.get("/api/v1/audit-events?limit=1000").json()
    assert "workflow.schedule.misfired" in {
        event["event_type"] for event in audits
    }


def test_schedule_calendar_exclusion_is_durable_and_never_dispatched(client):
    _configure_route(client)
    version = _publish_workflow(client, SCHEDULE_WORKFLOW_SPEC)
    current = utcnow().replace(microsecond=0)
    window = {
        "id": "quarterly-freeze",
        "name": "Quarterly change freeze",
        "starts_at": (current - timedelta(hours=1)).isoformat(),
        "ends_at": (current + timedelta(hours=1)).isoformat(),
    }
    overlapping = _activate(
        client,
        version["id"],
        exclusion_windows=[
            window,
            {
                "id": "overlap",
                "name": "Ambiguous overlap",
                "starts_at": (current - timedelta(minutes=30)).isoformat(),
                "ends_at": (current + timedelta(hours=2)).isoformat(),
            },
        ],
    )
    assert overlapping.status_code == 422
    assert "cannot overlap" in overlapping.text

    activated = _activate(
        client,
        version["id"],
        exclusion_windows=[window],
    )
    assert activated.status_code == 201, activated.text
    activation = activated.json()
    assert activation["revision"] == 1
    assert activation["excluded_runs"] == 0
    assert activation["exclusion_windows"][0]["id"] == "quarterly-freeze"

    due = current - timedelta(seconds=10)
    with SessionLocal() as db:
        record = db.get(WorkflowScheduleActivation, activation["id"])
        assert record is not None
        record.next_fire_at = due
        db.commit()
    with SessionLocal() as db:
        assert enqueue_due_workflow_schedules(db, now=current) == 0
        event = db.scalar(select(WorkflowScheduleEvent))
        assert event is not None
        assert event.status == "skipped"
        assert event.attempt_count == 0
        assert event.skip_reason == "calendar_exclusion"
        assert event.exclusion_window_id == "quarterly-freeze"
        record = db.get(WorkflowScheduleActivation, activation["id"])
        assert record is not None
        assert record.excluded_runs == 1
        assert record.last_excluded_at is not None
        assert record.next_fire_at > current.replace(tzinfo=None)
        assert dispatch_workflow_schedule_events(db) == 0
        assert (
            db.scalar(select(func.count()).select_from(Investigation))
            == 0
        )

    listed = client.get("/api/v1/workflow-runtime/schedule-events").json()
    assert listed[0]["status"] == "skipped"
    assert listed[0]["skip_reason"] == "calendar_exclusion"
    assert listed[0]["exclusion_window_id"] == "quarterly-freeze"
    audits = client.get("/api/v1/audit-events?limit=1000").json()
    assert "workflow.schedule.excluded" in {
        event["event_type"] for event in audits
    }
    assert "Quarterly change freeze" not in json.dumps(audits)


def test_schedule_exclusion_updates_are_revisioned_and_invalid_state_fails_closed(
    client,
):
    _configure_route(client)
    version = _publish_workflow(client, SCHEDULE_WORKFLOW_SPEC)
    activated = _activate(client, version["id"])
    assert activated.status_code == 201, activated.text
    activation = activated.json()
    current = utcnow().replace(microsecond=0)
    update_document = {
        "expected_revision": 1,
        "exclusion_windows": [
            {
                "id": "planned-maintenance",
                "name": "Planned maintenance",
                "starts_at": (current + timedelta(days=1)).isoformat(),
                "ends_at": (current + timedelta(days=1, hours=2)).isoformat(),
            }
        ],
        "reason": "Protect the approved maintenance window.",
        "actor": "capability.publisher",
    }
    updated = client.post(
        f"/api/v1/workflow-runtime/schedule-activations/{activation['id']}/exclusions",
        json=update_document,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["revision"] == 2
    assert updated.json()["exclusion_windows"][0]["id"] == "planned-maintenance"

    stale = client.post(
        f"/api/v1/workflow-runtime/schedule-activations/{activation['id']}/exclusions",
        json=update_document,
    )
    assert stale.status_code == 409
    assert "revision conflict" in stale.text

    with SessionLocal() as db:
        record = db.get(WorkflowScheduleActivation, activation["id"])
        assert record is not None
        record.exclusion_windows = [{"id": "corrupt"}]
        record.next_fire_at = current - timedelta(seconds=10)
        db.commit()
    with SessionLocal() as db:
        assert enqueue_due_workflow_schedules(db, now=current) == 0
        record = db.get(WorkflowScheduleActivation, activation["id"])
        assert record is not None
        assert record.enabled is False
        assert db.scalar(select(func.count()).select_from(WorkflowScheduleEvent)) == 0
    audits = client.get("/api/v1/audit-events?limit=1000").json()
    assert "workflow.schedule.exclusions.updated" in {
        event["event_type"] for event in audits
    }
    assert "workflow.schedule.exclusions.invalid" in {
        event["event_type"] for event in audits
    }


def test_schedule_event_fails_closed_after_version_is_superseded(client):
    _configure_route(client)
    version = _publish_workflow(client, SCHEDULE_WORKFLOW_SPEC)
    activated = _activate(client, version["id"])
    assert activated.status_code == 201, activated.text
    with SessionLocal() as db:
        record = db.get(WorkflowScheduleActivation, activated.json()["id"])
        assert record is not None
        record.next_fire_at = utcnow() - timedelta(seconds=10)
        db.commit()
    with SessionLocal() as db:
        assert enqueue_due_workflow_schedules(db, now=utcnow()) == 1

    with SessionLocal() as db:
        from icheck.services.workflow_templates import workflow_artifact_documents
        from icheck.studio_schemas import GeneratedWorkflowSpec

        definition, implementation, tests = workflow_artifact_documents(
            db,
            GeneratedWorkflowSpec.model_validate(SCHEDULE_WORKFLOW_SPEC),
        )
    created = client.post(
        f"/api/v1/artifacts/{version['artifact_id']}/versions",
        json={
            "definition": definition,
            "implementation": implementation,
            "tests": tests,
            "created_by": "capability.author",
        },
    )
    assert created.status_code == 201, created.text
    replacement = max(created.json()["versions"], key=lambda item: item["version"])
    assert client.post(
        f"/api/v1/artifact-versions/{replacement['id']}/validate",
        json={"actor": "capability.reviewer"},
    ).status_code == 200
    assert client.post(
        f"/api/v1/artifact-versions/{replacement['id']}/publish",
        json={"actor": "capability.publisher"},
    ).status_code == 200

    with SessionLocal() as db:
        assert dispatch_workflow_schedule_events(db) == 0
        event = db.scalar(select(WorkflowScheduleEvent))
        assert event is not None
        assert event.status == "failed"
        assert event.attempt_count == 3
        assert event.error_type == "ValueError"
        assert len(event.error_sha256 or "") == 64
        assert db.scalar(
            select(func.count()).select_from(Investigation).where(
                Investigation.workflow_schedule_event_id == event.id
            )
        ) == 0


@pytest.mark.parametrize("committed_investigation", [False, True])
def test_stale_schedule_third_attempt_reconciles_without_fourth_dispatch(
    client, committed_investigation,
):
    _configure_route(client)
    version = _publish_workflow(client, SCHEDULE_WORKFLOW_SPEC)
    activated = _activate(client, version["id"])
    assert activated.status_code == 201, activated.text
    with SessionLocal() as db:
        activation = db.get(WorkflowScheduleActivation, activated.json()["id"])
        assert activation is not None
        activation.next_fire_at = utcnow() - timedelta(seconds=10)
        db.commit()
        assert enqueue_due_workflow_schedules(db, now=utcnow()) == 1
        event = db.scalar(select(WorkflowScheduleEvent))
        assert event is not None
        event_id = event.id
        if committed_investigation:
            assert dispatch_workflow_schedule_events(db) == 1
        event = db.get(WorkflowScheduleEvent, event_id)
        event.status = "processing"
        event.attempt_count = 3
        event.updated_at = utcnow() - timedelta(minutes=6)
        db.commit()
        before = db.scalar(select(func.count()).select_from(Investigation).where(
            Investigation.workflow_schedule_event_id == event_id,
        ))
        assert before == int(committed_investigation)
        assert dispatch_workflow_schedule_events(db) == int(committed_investigation)
        event = db.get(WorkflowScheduleEvent, event_id)
        assert event.status == ("succeeded" if committed_investigation else "failed")
        assert event.attempt_count == 3
        assert event.error_type == (None if committed_investigation else "DispatchAttemptsExhausted")
        assert db.scalar(select(func.count()).select_from(Investigation).where(
            Investigation.workflow_schedule_event_id == event_id,
        )) == before
        assert dispatch_workflow_schedule_events(db) == 0
