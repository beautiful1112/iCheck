from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent_schemas import InvestigationCheckpointCreate
from ..models import (
    AgentActionProposal,
    AgentToolRegistration,
    GovernedChangePlan,
    Investigation,
    InvestigationToolCall,
)


def bound_node(investigation: Investigation, plan: list[str]) -> dict[str, Any]:
    from .workflow_runtime import workflow_plan_cursor

    cursor = workflow_plan_cursor(plan)
    nodes = investigation.workflow_snapshot.get("nodes", [])
    node = next(
        (item for item in nodes if cursor and item.get("node_id") == cursor[0]),
        None,
    )
    if node is None:
        raise ValueError("Workflow execution evidence has no bound node cursor")
    return node


def bound_arguments(investigation: Investigation, node: dict[str, Any]) -> dict:
    arguments = {}
    for binding in node.get("input_bindings", []):
        value: Any = investigation.workflow_input
        for part in binding["input_path"].split("."):
            if not isinstance(value, dict) or part not in value:
                raise ValueError("Workflow evidence input binding is unavailable")
            value = value[part]
        arguments[binding["argument"]] = value
    return arguments


def validate_workflow_execution_evidence(
    db: Session,
    investigation: Investigation,
    payload: InvestigationCheckpointCreate,
) -> None:
    from .workflow_runtime import workflow_plan_cursor

    outcomes = payload.state.workflow_tool_outcomes
    if not outcomes:
        return  # Additive: old checkpoints remain readable/resumable.
    if not investigation.workflow_snapshot or payload.node != "tools":
        raise ValueError("Workflow outcomes belong only to Workflow tools checkpoints")
    node = bound_node(investigation, payload.state.plan)
    cursor = workflow_plan_cursor(payload.state.plan)
    fixed = node["node_type"] in {"tool", "post_check", "rollback"}
    if cursor is None or (fixed and (cursor[1] != "fixed" or len(outcomes) != 1)) or (
        not fixed and (node["node_type"] != "agent_loop" or cursor[1] != "agent")
    ):
        raise ValueError("Workflow outcomes do not match the bound execution phase")
    if len({item.call_id for item in outcomes}) != len(outcomes):
        raise ValueError("Workflow execution evidence contains duplicate calls")
    for outcome in outcomes:
        call = db.get(InvestigationToolCall, outcome.call_id)
        tool = db.get(AgentToolRegistration, call.tool_id) if call else None
        if (
            call is None
            or tool is None
            or call.investigation_id != investigation.id
            or call.id not in payload.state.tool_call_ids
            or call.iteration != payload.state.iteration
            or call.finished_at is None
            or call.status not in {"succeeded", "failed"}
        ):
            raise ValueError("Workflow execution evidence references an invalid ToolCall")
        allowed = (
            tool.name == node.get("tool_name")
            if fixed
            else tool.read_only and tool.name in node.get("allowed_tools", [])
        )
        if not allowed or (
            fixed and call.arguments != bound_arguments(investigation, node)
        ):
            raise ValueError("Workflow execution evidence does not match its node")
        if outcome.status == "succeeded" and call.status != "succeeded":
            raise ValueError("Workflow success evidence references a failed ToolCall")
        if not tool.read_only and outcome.status == "succeeded":
            proposal = db.scalar(
                select(AgentActionProposal).where(
                    AgentActionProposal.tool_call_id == call.id,
                    AgentActionProposal.investigation_id == investigation.id,
                )
            )
            if proposal is None or proposal.status != "succeeded":
                raise ValueError("Workflow change success requires its approved action")
            plan = db.scalar(
                select(GovernedChangePlan).where(
                    GovernedChangePlan.action_proposal_id == proposal.id
                )
            )
            if plan is not None and plan.status != "verified":
                raise ValueError("Workflow change success requires its governed post-check")
