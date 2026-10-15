from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

from icheck.agent_schemas import InvestigationCheckpointCreate, InvestigationState
from icheck.database import SessionLocal
from icheck.models import (
    AgentToolRegistration,
    Investigation,
    InvestigationToolCall,
    Situation,
    SituationIntegrationBinding,
    SituationIntegrationEvent,
    SituationIntegrationInboundEvent,
    SituationIntegrationRemoteReference,
)
from icheck.services.agent_runtime import append_investigation_checkpoint
from icheck.services.workflow_runtime import dispatch_situation_integration_events

from test_situations import _alert, _device
from test_workflow_runtime import _configure_route, _publish_workflow


SITUATION_TICKET_WORKFLOW = {
    "artifact_name": "situation-ticket-create",
    "description": "Create and verify an external incident for a new Situation.",
    "trigger": {
        "trigger_type": "situation",
        "event_type": "situation.created",
    },
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["situation_id", "title", "severity"],
        "properties": {
            "situation_id": {"type": "string"},
            "title": {"type": "string"},
            "severity": {
                "type": "string",
                "enum": ["critical", "warning", "info"],
            },
        },
    },
    "start_node": "approve",
    "nodes": [
        {
            "node_id": "approve",
            "title": "Approve external ticket creation",
            "node_type": "approval",
            "on_success": "create_ticket",
            "on_failure": "complete",
        },
        {
            "node_id": "create_ticket",
            "title": "Create external ticket",
            "node_type": "tool",
            "tool_name": "external.ticket.create",
            "input_bindings": [
                {"argument": "situation_id", "input_path": "situation_id"},
                {"argument": "title", "input_path": "title"},
                {"argument": "severity", "input_path": "severity"},
            ],
            "on_success": "verify_ticket",
            "on_failure": "rollback_ticket",
            "requires_approval": True,
            "rollback_node_id": "rollback_ticket",
        },
        {
            "node_id": "verify_ticket",
            "title": "Verify external ticket",
            "node_type": "post_check",
            "tool_name": "external.ticket.get",
            "input_bindings": [
                {"argument": "situation_id", "input_path": "situation_id"}
            ],
            "on_success": "complete",
            "on_failure": "rollback_ticket",
        },
        {
            "node_id": "rollback_ticket",
            "title": "Rollback external ticket",
            "node_type": "rollback",
            "tool_name": "external.ticket.delete",
            "input_bindings": [
                {"argument": "situation_id", "input_path": "situation_id"}
            ],
            "on_success": "complete",
            "on_failure": "complete",
            "requires_approval": True,
        },
        {
            "node_id": "complete",
            "title": "Complete external synchronization",
            "node_type": "end",
        },
    ],
    "max_runtime_seconds": 180,
    "max_total_tool_calls": 4,
    "max_total_tokens": 500,
}


def _register_mcp_ticket_tools():
    with SessionLocal() as db:
        create_schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["situation_id", "title", "severity"],
            "properties": {
                "situation_id": {"type": "string"},
                "title": {"type": "string"},
                "severity": {"type": "string"},
            },
        }
        identity_schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["situation_id"],
            "properties": {"situation_id": {"type": "string"}},
        }
        output_schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["external_id"],
            "properties": {"external_id": {"type": "string"}},
        }
        db.add_all(
            [
                AgentToolRegistration(
                    name="external.ticket.create",
                    description="Create an external incident ticket.",
                    transport="mcp",
                    handler="ticketing/ticket.create",
                    input_schema=create_schema,
                    output_schema=output_schema,
                    risk_level="change",
                    read_only=False,
                    required_permissions=["changes.execute"],
                    timeout_seconds=30,
                    max_result_bytes=100_000,
                    enabled=True,
                    created_by="test.setup",
                ),
                AgentToolRegistration(
                    name="external.ticket.get",
                    description="Read an external incident ticket.",
                    transport="mcp",
                    handler="ticketing/ticket.get",
                    input_schema=identity_schema,
                    output_schema=output_schema,
                    risk_level="observe",
                    read_only=True,
                    required_permissions=["alerts.read"],
                    timeout_seconds=30,
                    max_result_bytes=100_000,
                    enabled=True,
                    created_by="test.setup",
                ),
                AgentToolRegistration(
                    name="external.ticket.delete",
                    description="Delete a ticket created by a failed integration.",
                    transport="mcp",
                    handler="ticketing/ticket.delete",
                    input_schema=identity_schema,
                    output_schema=output_schema,
                    risk_level="change",
                    read_only=False,
                    required_permissions=["changes.execute"],
                    timeout_seconds=30,
                    max_result_bytes=100_000,
                    enabled=True,
                    created_by="test.setup",
                ),
            ]
        )
        db.commit()


def _activate(client, version_id: str, **overrides):
    document = {
        "channel_kind": "ticket",
        "route_purpose": "investigation",
        "authorization_scope": {},
        "input_mapping": {
            "situation_id": "situation.id",
            "title": "situation.title",
            "severity": "situation.severity",
        },
        "actor": "capability.publisher",
        **overrides,
    }
    return client.post(
        f"/api/v1/workflow-runtime/workflows/{version_id}/situation-integration",
        json=document,
    )


def test_situation_integration_enqueues_dispatches_once_and_disables(client):
    _configure_route(client)
    _register_mcp_ticket_tools()
    version = _publish_workflow(client, SITUATION_TICKET_WORKFLOW)

    invalid = _activate(
        client,
        version["id"],
        input_mapping={
            "situation_id": "situation.id",
            "title": "situation.title",
            "severity": "situation.not_allowed",
        },
    )
    assert invalid.status_code == 422
    assert "invalid Situation path" in invalid.text

    activated = _activate(client, version["id"])
    assert activated.status_code == 201, activated.text
    binding = activated.json()
    assert binding["event_type"] == "situation.created"
    assert binding["channel_kind"] == "ticket"

    device = _device(client, "integration-router-01")
    _alert(
        client,
        device["id"],
        event_type="device.unreachable",
        title="Integration router unreachable",
        severity="critical",
        dedup_key="integration-router-unreachable",
    )
    situation = client.get("/api/v1/situations").json()[0]
    deliveries = client.get(
        "/api/v1/workflow-runtime/situation-integration-events"
    )
    assert deliveries.status_code == 200, deliveries.text
    assert len(deliveries.json()) == 1
    delivery = deliveries.json()[0]
    assert delivery["status"] == "pending"
    assert delivery["situation_id"] == situation["id"]

    with SessionLocal() as db:
        assert dispatch_situation_integration_events(db) == 1
        record = db.get(SituationIntegrationEvent, delivery["id"])
        assert record is not None
        assert record.status == "succeeded"
        assert record.attempt_count == 1
        investigation = db.scalar(
            select(Investigation).where(
                Investigation.situation_integration_event_id == record.id
            )
        )
        assert investigation is not None
        assert investigation.situation_id == situation["id"]
        assert investigation.workflow_input == {
            "situation_id": situation["id"],
            "title": "Integration router unreachable",
            "severity": "critical",
        }
        assert investigation.status == "running"
        assert dispatch_situation_integration_events(db) == 0

    disabled = client.post(
        f"/api/v1/workflow-runtime/situation-integrations/{binding['id']}/disable",
        json={"actor": "capability.publisher"},
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["enabled"] is False
    with SessionLocal() as db:
        stored = db.get(SituationIntegrationBinding, binding["id"])
        assert stored is not None and stored.enabled is False

    another_response = client.post(
        "/api/v1/devices",
        json={
            "name": "integration-router-02",
            "kind": "router",
            "management_ip": "192.0.2.78",
            "site": "Lab",
        },
    )
    assert another_response.status_code == 201, another_response.text
    another = another_response.json()
    _alert(
        client,
        another["id"],
        event_type="device.unreachable",
        title="Second integration router unreachable",
        severity="warning",
        dedup_key="integration-router-02-unreachable",
    )
    with SessionLocal() as db:
        assert (
            db.scalar(select(func.count()).select_from(SituationIntegrationEvent))
            == 1
        )


def test_situation_integration_requires_an_mcp_backed_workflow(client):
    _configure_route(client)
    internal = {
        **SITUATION_TICKET_WORKFLOW,
        "artifact_name": "situation-internal-only",
        "start_node": "read_alerts",
        "nodes": [
            {
                "node_id": "read_alerts",
                "title": "Read alerts",
                "node_type": "tool",
                "tool_name": "alerts.list_open",
                "input_bindings": [
                    {"argument": "severity", "input_path": "severity"}
                ],
                "on_success": "complete",
            },
            {
                "node_id": "complete",
                "title": "Complete",
                "node_type": "end",
            },
        ],
    }
    version = _publish_workflow(client, internal)
    rejected = _activate(client, version["id"])
    assert rejected.status_code == 422
    assert "require an MCP tool dependency" in rejected.text


def _signed_webhook(private_key, event_id: str, payload: dict):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    timestamp = str(int(datetime.now(UTC).timestamp()))
    payload_hash = hashlib.sha256(raw).hexdigest()
    material = f"{timestamp}\n{event_id}\n{payload_hash}".encode()
    signature = base64.b64encode(private_key.sign(material)).decode()
    return raw, {
        "Content-Type": "application/json",
        "X-Icheck-Timestamp": timestamp,
        "X-Icheck-Event-Id": event_id,
        "X-Icheck-Key-Id": "lab-key-01",
        "X-Icheck-Signature": f"v1={signature}",
    }


def test_remote_reference_capture_and_signed_inbound_reconciliation(client):
    _configure_route(client)
    _register_mcp_ticket_tools()
    version = _publish_workflow(client, SITUATION_TICKET_WORKFLOW)
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    bad_path = _activate(
        client,
        version["id"],
        remote_reference_tool_name="external.ticket.create",
        remote_reference_mapping={"remote_id": "not_in_schema"},
    )
    assert bad_path.status_code == 422
    assert "absent from Tool output schema" in bad_path.text

    activated = _activate(
        client,
        version["id"],
        provider_key="lab-ticketing",
        remote_reference_tool_name="external.ticket.create",
        remote_reference_mapping={"remote_id": "external_id"},
        inbound_enabled=True,
        inbound_key_id="lab-key-01",
        inbound_public_key_pem=public_pem,
    )
    assert activated.status_code == 201, activated.text
    binding = activated.json()
    assert binding["provider_key"] == "lab-ticketing"
    assert binding["inbound_enabled"] is True
    assert len(binding["inbound_public_key_sha256"]) == 64
    assert "inbound_public_key_pem" not in binding

    device = _device(client, "reconciliation-router-01")
    _alert(
        client,
        device["id"],
        event_type="device.unreachable",
        title="Reconciliation router unreachable",
        severity="critical",
        dedup_key="reconciliation-router-unreachable",
    )
    situation = client.get("/api/v1/situations").json()[0]
    with SessionLocal() as db:
        assert dispatch_situation_integration_events(db) == 1
        investigation = db.scalar(
            select(Investigation).where(
                Investigation.situation_integration_event_id.is_not(None)
            )
        )
        assert investigation is not None
        tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "external.ticket.create"
            )
        )
        assert tool is not None
        now = datetime.now(UTC)
        call = InvestigationToolCall(
            investigation_id=investigation.id,
            tool_id=tool.id,
            iteration=1,
            call_hash="a" * 64,
            arguments={
                "situation_id": situation["id"],
                "title": situation["title"],
                "severity": situation["severity"],
            },
            status="succeeded",
            result={"external_id": "INC-4242"},
            result_hash=hashlib.sha256(b"INC-4242").hexdigest(),
            started_at=now,
            finished_at=now,
        )
        db.add(call)
        db.flush()
        append_investigation_checkpoint(
            db,
            investigation,
            InvestigationCheckpointCreate(
                node="reason",
                state=InvestigationState(
                    investigation_id=investigation.id,
                    objective=investigation.objective,
                    scope=investigation.scope,
                    status="completed",
                    iteration=1,
                    plan=["completed"],
                    hypotheses=[],
                    evidence_ids=[],
                    tool_call_ids=[call.id],
                    confidence=1,
                    conclusion="External ticket created and verified.",
                    uncertainty=[],
                    structured_output={"terminal_node": "complete"},
                ),
                actor="agent.worker.test",
            ),
        )
        reference = db.scalar(select(SituationIntegrationRemoteReference))
        assert reference is not None
        assert reference.remote_id == "INC-4242"
        assert reference.provider_key == "lab-ticketing"
        reference_id = reference.id
        reference_time = reference.remote_updated_at

    references = client.get(
        "/api/v1/workflow-runtime/situation-integration-references"
    )
    assert references.status_code == 200, references.text
    assert references.json()[0]["remote_id"] == "INC-4242"

    scoped_references = client.get(
        f"/api/v1/situations/{situation['id']}/external-references"
    )
    assert scoped_references.status_code == 200, scoped_references.text
    assert scoped_references.json()[0]["remote_id"] == "INC-4242"

    updated_at = datetime.now(UTC) + timedelta(seconds=30)
    accepted_payload = {
        "provider_event_id": "evt-closed-01",
        "event_type": "ticket.status_changed",
        "remote_id": "INC-4242",
        "remote_status": "closed",
        "remote_updated_at": updated_at.isoformat(),
    }
    raw, headers = _signed_webhook(
        private_key, "evt-closed-01", accepted_payload
    )
    accepted = client.post(
        f"/api/v1/workflow-runtime/situation-integrations/{binding['id']}/webhook",
        content=raw,
        headers=headers,
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["outcome"] == "accepted"
    assert accepted.json()["replayed"] is False

    replayed = client.post(
        f"/api/v1/workflow-runtime/situation-integrations/{binding['id']}/webhook",
        content=raw,
        headers=headers,
    )
    assert replayed.status_code == 200, replayed.text
    assert replayed.json()["replayed"] is True

    conflict_payload = {**accepted_payload, "remote_status": "reopened"}
    conflict_raw, conflict_headers = _signed_webhook(
        private_key, "evt-closed-01", conflict_payload
    )
    conflict = client.post(
        f"/api/v1/workflow-runtime/situation-integrations/{binding['id']}/webhook",
        content=conflict_raw,
        headers=conflict_headers,
    )
    assert conflict.status_code == 409

    stale_payload = {
        **accepted_payload,
        "provider_event_id": "evt-stale-01",
        "remote_status": "open",
        "remote_updated_at": reference_time.isoformat(),
    }
    stale_raw, stale_headers = _signed_webhook(
        private_key, "evt-stale-01", stale_payload
    )
    stale = client.post(
        f"/api/v1/workflow-runtime/situation-integrations/{binding['id']}/webhook",
        content=stale_raw,
        headers=stale_headers,
    )
    assert stale.status_code == 200, stale.text
    assert stale.json()["outcome"] == "ignored_stale"

    invalid_headers = {**headers, "X-Icheck-Signature": "v1=AAAA"}
    invalid = client.post(
        f"/api/v1/workflow-runtime/situation-integrations/{binding['id']}/webhook",
        content=raw,
        headers=invalid_headers,
    )
    assert invalid.status_code == 401
    assert invalid.json()["detail"] == "Webhook authentication failed"

    with SessionLocal() as db:
        stored_situation = db.get(Situation, situation["id"])
        assert stored_situation is not None
        assert stored_situation.status == "open"
        reference = db.get(SituationIntegrationRemoteReference, reference_id)
        assert reference is not None
        assert reference.remote_status == "closed"
        inbound = list(
            db.scalars(
                select(SituationIntegrationInboundEvent).order_by(
                    SituationIntegrationInboundEvent.received_at
                )
            ).all()
        )
        assert [item.outcome for item in inbound] == [
            "accepted",
            "ignored_stale",
        ]
        assert all(len(item.payload_sha256) == 64 for item in inbound)
        assert any(
            event.event_type == "situation.external_status_observed"
            and event.details["local_lifecycle_changed"] is False
            for event in stored_situation.events
        )

    inbound_response = client.get(
        "/api/v1/workflow-runtime/situation-integration-inbound-events"
    )
    assert inbound_response.status_code == 200, inbound_response.text
    assert len(inbound_response.json()) == 2

    disabled = client.post(
        f"/api/v1/workflow-runtime/situation-integrations/{binding['id']}/disable",
        json={"actor": "capability.publisher"},
    )
    assert disabled.status_code == 200, disabled.text
    disabled_payload = {
        **accepted_payload,
        "provider_event_id": "evt-disabled-01",
        "remote_updated_at": (updated_at + timedelta(seconds=30)).isoformat(),
    }
    disabled_raw, disabled_headers = _signed_webhook(
        private_key, "evt-disabled-01", disabled_payload
    )
    rejected = client.post(
        f"/api/v1/workflow-runtime/situation-integrations/{binding['id']}/webhook",
        content=disabled_raw,
        headers=disabled_headers,
    )
    assert rejected.status_code == 401
    assert rejected.json()["detail"] == "Webhook authentication failed"
