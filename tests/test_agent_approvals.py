from __future__ import annotations

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from sqlalchemy import select

from icheck.agent_schemas import AgentActionDecision
from icheck.database import SessionLocal
from icheck.langgraph_runtime import GraphDecision, GraphToolRequest
from icheck.models import (
    AgentActionProposal,
    AgentExecution,
    AgentExecutionStatus,
    AgentToolRegistration,
    Investigation,
    InvestigationToolCall,
)
from icheck.services.agent_approvals import (
    ActionOutcomeUnknown,
    action_plan_hash,
    decide_action_proposal,
    validate_resumed_action,
)
from icheck.services.agent_graph import (
    resume_database_investigation,
    run_database_investigation,
)
from icheck.services.agent_tools import INTERNAL_HANDLERS
from icheck.services.control_plane_auth import PrincipalContext


def _configure_route(client) -> None:
    provider = client.post(
        "/api/v1/ai/providers",
        json={
            "name": "approval-provider",
            "provider_type": "openai_compatible",
            "base_url": "https://models.example.test/v1",
            "auth_type": "none",
            "created_by": "platform.admin",
        },
    )
    model = client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": provider.json()["id"],
            "display_name": "Approval reasoner",
            "model_name": "approval-reasoner",
            "capabilities": ["chat", "tools", "json_schema"],
            "created_by": "platform.admin",
        },
    )
    route = client.post(
        "/api/v1/ai/routes",
        json={
            "purpose": "investigation",
            "primary_model_id": model.json()["id"],
            "max_iterations": 4,
            "max_tool_calls": 4,
            "timeout_seconds": 300,
            "token_budget": 2000,
            "created_by": "platform.admin",
        },
    )
    assert route.status_code == 201, route.text


def _start_investigation(client) -> str:
    created = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": "Governed interface change",
            "objective": "Apply one approved test change and verify its result.",
            "scope": {"device_ids": ["device-1"]},
            "route_purpose": "investigation",
            "created_by": "l1.operator",
        },
    )
    investigation_id = created.json()["id"]
    started = client.post(
        f"/api/v1/agent/investigations/{investigation_id}/start",
        json={"actor": "l1.operator"},
    )
    assert started.status_code == 200, started.text
    return investigation_id


def _principal(subject: str, *permissions: str) -> PrincipalContext:
    return PrincipalContext(
        principal_id=None,
        subject=subject,
        principal_type="user",
        permissions=frozenset(permissions),
        role_names=("test",),
        authorization_scope={"all": True},
        auth_method="bearer",
    )


class ApprovalReasoner:
    def __init__(self):
        self.calls = 0

    def __call__(self, state):
        self.calls += 1
        if self.calls == 1:
            return GraphDecision(
                action="continue",
                plan=["Request approval", "Apply bounded change", "Verify result"],
                tool_requests=[
                    GraphToolRequest(
                        tool_name="test.set_interface_description",
                        arguments={
                            "device_id": "device-1",
                            "interface": "Ethernet1",
                            "description": "approved-test",
                        },
                        purpose="Set the approved test interface description",
                    )
                ],
                token_usage=10,
            )
        assert state["tool_results"][0]["result"] == {
            "changed": True,
            "post_check": "approved-test",
        }
        return GraphDecision(
            action="complete",
            plan=state["plan"],
            confidence=0.99,
            conclusion="The approved change and post-check succeeded.",
            token_usage=5,
        )


def test_four_eyes_approval_resumes_same_langgraph_thread(client, monkeypatch):
    _configure_route(client)
    tool = client.post(
        "/api/v1/agent/tools",
        json={
            "name": "test.set_interface_description",
            "description": "Acceptance-only idempotent change handler.",
            "transport": "internal",
            "handler": "test.set_interface_description",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["device_id", "interface", "description"],
                "properties": {
                    "device_id": {"type": "string"},
                    "interface": {"type": "string"},
                    "description": {"type": "string"},
                },
            },
            "output_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["changed", "post_check"],
                "properties": {
                    "changed": {"type": "boolean"},
                    "post_check": {"type": "string"},
                },
            },
            "risk_level": "change",
            "read_only": False,
            "required_permissions": ["changes.execute"],
            "created_by": "platform.admin",
        },
    )
    assert tool.status_code == 201, tool.text
    investigation_id = _start_investigation(client)
    calls: list[dict[str, str]] = []

    def change_handler(_db, arguments):
        calls.append(arguments)
        return {
            "changed": True,
            "post_check": arguments["description"],
        }, []

    monkeypatch.setitem(
        INTERNAL_HANDLERS,
        "test.set_interface_description",
        change_handler,
    )
    saver = InMemorySaver()
    reasoner = ApprovalReasoner()

    with SessionLocal() as db:
        investigation = db.get(Investigation, investigation_id)
        assert investigation is not None
        first = run_database_investigation(
            db,
            investigation,
            reasoner=reasoner,
            checkpointer=saver,
        )
        assert first["status"] == "waiting_approval"
        assert first["__interrupt__"][0].value["kind"] == "action_approval"
        proposal = db.scalar(
            select(AgentActionProposal).where(
                AgentActionProposal.investigation_id == investigation_id
            )
        )
        execution = db.scalar(
            select(AgentExecution).where(
                AgentExecution.investigation_id == investigation_id
            )
        )
        assert proposal is not None
        assert execution is not None
        assert proposal.status == "pending"
        assert investigation.status == "waiting_approval"
        assert calls == []

        # The worker acknowledges its LangGraph interrupt before a human can
        # decide; this is normally done by execute_assignment.
        execution.status = AgentExecutionStatus.WAITING_APPROVAL
        db.commit()

        requester = _principal("l1.operator", "changes.approve")
        with pytest.raises(PermissionError, match="requester"):
            decide_action_proposal(
                db,
                proposal,
                AgentActionDecision(
                    decision="approve",
                    expected_plan_hash=proposal.plan_hash,
                    reason="Self approval must fail.",
                ),
                actor=requester,
            )
        with pytest.raises(ValueError, match="hash"):
            decide_action_proposal(
                db,
                proposal,
                AgentActionDecision(
                    decision="approve",
                    expected_plan_hash="0" * 64,
                    reason="Stale plan must fail.",
                ),
                actor=_principal("peer.approver", "changes.approve"),
            )

        approved = decide_action_proposal(
            db,
            proposal,
            AgentActionDecision(
                decision="approve",
                expected_plan_hash=proposal.plan_hash,
                reason="Exact plan reviewed for this controlled test.",
            ),
            actor=_principal("peer.approver", "changes.approve"),
        )
        assert approved.status == "approved"
        db.refresh(execution)
        db.refresh(investigation)
        assert execution.status == AgentExecutionStatus.QUEUED
        assert investigation.status == "running"

        result = resume_database_investigation(
            db,
            investigation,
            reasoner=reasoner,
            checkpointer=saver,
        )
        assert result["status"] == "completed"
        assert result["tokens_used"] == 15
        assert reasoner.calls == 2
        assert len(calls) == 1
        db.refresh(approved)
        assert approved.status == "succeeded"
        assert approved.tool_call_id is not None
        persisted_call = db.get(InvestigationToolCall, approved.tool_call_id)
        assert persisted_call is not None
        assert persisted_call.status == "succeeded"
        snapshot = saver.get_tuple(
            {"configurable": {"thread_id": investigation_id}}
        )
        assert snapshot is not None
        assert snapshot.checkpoint["channel_values"]["status"] == "completed"


def test_executing_action_is_not_automatically_replayed(client, monkeypatch):
    _configure_route(client)
    tool = client.post(
        "/api/v1/agent/tools",
        json={
            "name": "test.set_interface_description",
            "description": "Acceptance-only idempotent change handler.",
            "transport": "internal",
            "handler": "test.set_interface_description",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "risk_level": "change",
            "read_only": False,
            "created_by": "platform.admin",
        },
    )
    investigation_id = _start_investigation(client)
    monkeypatch.setitem(
        INTERNAL_HANDLERS,
        "test.set_interface_description",
        lambda _db, _arguments: ({}, []),
    )
    with SessionLocal() as db:
        investigation = db.get(Investigation, investigation_id)
        assert investigation is not None
        registered_tool_id = tool.json()["id"]
        proposal = AgentActionProposal(
            investigation_id=investigation_id,
            tool_id=registered_tool_id,
            iteration=1,
            arguments={},
            purpose="Ambiguous action",
            plan_hash=action_plan_hash(
                tool_id=registered_tool_id,
                arguments={},
                purpose="Ambiguous action",
            ),
            status="executing",
            requested_by="l1.operator",
        )
        db.add(proposal)
        db.commit()
        registered_tool = db.get(AgentToolRegistration, registered_tool_id)
        assert registered_tool is not None
        with pytest.raises(ActionOutcomeUnknown):
            validate_resumed_action(
                db,
                proposal.id,
                investigation=investigation,
                tool=registered_tool,
                arguments={},
                purpose="Ambiguous action",
            )
