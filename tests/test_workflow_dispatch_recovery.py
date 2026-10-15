"""Lost third dispatcher claims do not bypass the three-attempt boundary."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from icheck.database import SessionLocal
from icheck.models import Investigation, SituationIntegrationEvent, WorkflowTriggerEvent
from icheck.services.workflow_runtime import (
    dispatch_situation_integration_events,
    dispatch_workflow_trigger_events,
)
from test_situations import _alert, _device
from test_situation_integrations import (
    SITUATION_TICKET_WORKFLOW,
    _activate as activate_situation,
    _register_mcp_ticket_tools,
)
from test_workflow_runtime import (
    ALERT_WORKFLOW_SPEC,
    _configure_route,
    _publish_workflow,
)


@pytest.mark.parametrize("kind", ["alert", "situation"])
@pytest.mark.parametrize("committed_investigation", [False, True])
def test_lost_third_dispatch_claim_reconciles_without_fourth_attempt(
    client, kind, committed_investigation,
):
    _configure_route(client)
    if kind == "alert":
        version = _publish_workflow(client, ALERT_WORKFLOW_SPEC)
        activated = client.post(
            f"/api/v1/workflow-runtime/workflows/{version['id']}/trigger-activation",
            json={
                "authorization_scope": {},
                "input_mapping": {"severity": "alert.severity"},
                "actor": "capability.publisher",
            },
        )
        assert activated.status_code == 201, activated.text
        emitted = client.post(
            "/api/v1/alerts/events",
            json={
                "dedup_key": "lost-third-alert",
                "event_type": "device.unreachable",
                "entity_type": "device",
                "entity_id": "lost-third-router",
                "title": "Router unreachable",
                "severity": "critical",
                "details": {},
            },
        )
        assert emitted.status_code == 201, emitted.text
        event_type = WorkflowTriggerEvent
        link = Investigation.workflow_trigger_event_id
        dispatch = dispatch_workflow_trigger_events
    else:
        _register_mcp_ticket_tools()
        version = _publish_workflow(client, SITUATION_TICKET_WORKFLOW)
        activated = activate_situation(client, version["id"])
        assert activated.status_code == 201, activated.text
        device = _device(client, "lost-third-situation-router")
        _alert(
            client, device["id"], event_type="device.unreachable",
            title="Router unreachable", severity="critical",
            dedup_key="lost-third-situation",
        )
        event_type = SituationIntegrationEvent
        link = Investigation.situation_integration_event_id
        dispatch = dispatch_situation_integration_events

    with SessionLocal() as db:
        event = db.scalar(select(event_type))
        assert event is not None and event.status == "pending"
        event_id = event.id
        if committed_investigation:
            assert dispatch(db) == 1
        event = db.get(event_type, event_id)
        event.status = "processing"
        event.attempt_count = 3
        event.updated_at = datetime.now(UTC) - timedelta(minutes=6)
        db.commit()
        existing_count = db.scalar(select(func.count()).select_from(Investigation).where(
            link == event_id,
        ))
        assert existing_count == int(committed_investigation)
        assert dispatch(db) == int(committed_investigation)
        event = db.get(event_type, event_id)
        assert event.status == ("succeeded" if committed_investigation else "failed")
        assert event.attempt_count == 3
        assert event.error_type == (None if committed_investigation else "DispatchAttemptsExhausted")
        assert db.scalar(select(func.count()).select_from(Investigation).where(
            link == event_id,
        )) == existing_count
        assert dispatch(db) == 0
