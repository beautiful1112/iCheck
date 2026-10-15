from __future__ import annotations

from typing import Any
from datetime import datetime

from sqlalchemy.orm import Session

from ..langgraph_runtime import (
    GraphDecision,
    GraphToolRequest,
    InvestigationGraphState,
)
from ..models import Investigation
from ..studio_schemas import GeneratedWorkflowSpec, WorkflowNode
from .model_reasoner import OpenAICompatibleReasoner
from .workflow_runtime import (
    assert_bound_workflow_runtime_compatible,
    workflow_plan_cursor,
    workflow_plan_marker,
    workflow_agent_input,
)


class WorkflowReasoner:
    """Interpret an immutable Workflow contract through the Agent graph.

    Fixed nodes are deterministic. Agent-loop nodes delegate only their bounded
    objective and allowlisted read-only tools to the configured model adapter.
    """

    def __init__(
        self,
        db: Session,
        investigation: Investigation,
        *,
        opener: Any | None = None,
        runtime_deadline: datetime | None = None,
    ):
        bound = assert_bound_workflow_runtime_compatible(db, investigation)
        if bound is None:
            raise ValueError("Investigation is not bound to a Workflow")
        self.db = db
        self.investigation = investigation
        self.spec: GeneratedWorkflowSpec = bound[0]
        self.nodes = {node.node_id: node for node in self.spec.nodes}
        model_input = (workflow_agent_input(db, investigation)
                       if any(node.node_type == "agent_loop" for node in self.spec.nodes) else {})
        self.agent_reasoners = {
            node.node_id: OpenAICompatibleReasoner(
                db,
                investigation,
                opener=opener,
                runtime_deadline=runtime_deadline,
                tool_allowlist=set(node.allowed_tools),
                runtime_context={
                    "workflow": investigation.workflow_snapshot.get("artifact_name"),
                    "node_id": node.node_id,
                    "objective": node.objective,
                    "input": model_input,
                    "allowed_tools": node.allowed_tools,
                    "max_iterations": node.max_iterations,
                },
            )
            for node in self.spec.nodes
            if node.node_type == "agent_loop"
        }

    def __call__(self, state: InvestigationGraphState) -> GraphDecision:
        cursor = workflow_plan_cursor(state["plan"])
        if cursor is None:
            return self._advance(self.spec.start_node, state)
        node_id, phase, turn = cursor
        node = self._node(node_id)
        if phase == "fixed":
            results = state["tool_results"]
            if len(results) != 1:
                raise ValueError("Workflow fixed node requires exactly one result")
            target = node.on_success if results[0].get("status") == "succeeded" else node.on_failure
            if not target:
                return GraphDecision(
                    action="escalate",
                    plan=[workflow_plan_marker(node.node_id, "failed")],
                    escalation_reason=(
                        f"Workflow node {node.node_id!r} failed without a failure path"
                    ),
                )
            return self._advance(target, state)
        if phase == "agent":
            return self._run_agent_loop(node, state, turn)
        raise ValueError("Workflow execution phase is invalid")

    def _node(self, node_id: str) -> WorkflowNode:
        node = self.nodes.get(node_id)
        if node is None:
            raise ValueError("Workflow execution references an unknown node")
        return node

    def _input_arguments(self, node: WorkflowNode) -> dict[str, Any]:
        arguments: dict[str, Any] = {}
        for binding in node.input_bindings:
            current: Any = self.investigation.workflow_input
            for part in binding.input_path.split("."):
                if not isinstance(current, dict) or part not in current:
                    raise ValueError(
                        f"Workflow input path {binding.input_path!r} is missing"
                    )
                current = current[part]
            arguments[binding.argument] = current
        return arguments

    def _advance(
        self,
        node_id: str,
        state: InvestigationGraphState,
        *,
        carry: GraphDecision | None = None,
    ) -> GraphDecision:
        traversed_approvals: list[str] = []
        for _ in range(len(self.nodes) + 1):
            node = self._node(node_id)
            if node.node_type == "approval":
                traversed_approvals.append(node.node_id)
                if node.on_success is None:
                    raise ValueError("Workflow approval node has no success path")
                node_id = node.on_success
                continue
            if node.node_type == "end":
                conclusion = (
                    carry.conclusion
                    if carry and carry.conclusion
                    else f"Workflow {self.investigation.workflow_snapshot.get('artifact_name')!r} completed."
                )
                return GraphDecision(
                    action="complete",
                    plan=[workflow_plan_marker(node.node_id, "end"), *traversed_approvals],
                    hypotheses=carry.hypotheses if carry else [],
                    confidence=carry.confidence if carry else None,
                    conclusion=conclusion,
                    uncertainty=carry.uncertainty if carry else [],
                    structured_output={
                        "workflow": self.investigation.workflow_snapshot.get("artifact_name"),
                        "version_id": self.investigation.workflow_artifact_version_id,
                        "terminal_node": node.node_id,
                        "evidence_ids": state["evidence_ids"],
                        "tool_call_ids": state["tool_call_ids"],
                    },
                    token_usage=carry.token_usage if carry else 0,
                )
            if node.node_type == "agent_loop":
                decision = self._run_agent_loop(node, state, 0)
                if carry:
                    decision = decision.model_copy(
                        update={"token_usage": decision.token_usage + carry.token_usage}
                    )
                return decision
            if node.node_type in {"tool", "post_check", "rollback"}:
                if node.tool_name is None:
                    raise ValueError("Workflow fixed node has no tool")
                return GraphDecision(
                    action="continue",
                    plan=[
                        workflow_plan_marker(node.node_id, "fixed"),
                        *traversed_approvals,
                        node.title,
                    ],
                    hypotheses=carry.hypotheses if carry else [],
                    tool_requests=[
                        GraphToolRequest(
                            tool_name=node.tool_name,
                            arguments=self._input_arguments(node),
                            purpose=(
                                f"Workflow {self.investigation.workflow_snapshot.get('artifact_name')!r} "
                                f"node {node.node_id!r}: {node.title}"
                            ),
                        )
                    ],
                    uncertainty=carry.uncertainty if carry else [],
                    token_usage=carry.token_usage if carry else 0,
                )
            raise ValueError(f"Unsupported Workflow node type {node.node_type!r}")
        raise ValueError("Workflow routing exceeded its deterministic bound")

    def _run_agent_loop(
        self,
        node: WorkflowNode,
        state: InvestigationGraphState,
        turn: int,
    ) -> GraphDecision:
        max_iterations = node.max_iterations or 0
        if turn >= max_iterations:
            if node.on_failure:
                return self._advance(node.on_failure, state)
            return GraphDecision(
                action="escalate",
                plan=[workflow_plan_marker(node.node_id, "agent", turn)],
                escalation_reason=(
                    f"Workflow agent-loop {node.node_id!r} exhausted its iteration budget"
                ),
            )
        model_state = dict(state)
        model_state["objective"] = node.objective or node.title
        self.agent_reasoners[node.node_id].runtime_context["input"] = workflow_agent_input(self.db, self.investigation)
        decision = self.agent_reasoners[node.node_id](model_state)  # type: ignore[arg-type]
        if decision.action == "continue":
            unexpected = sorted(
                {
                    request.tool_name
                    for request in decision.tool_requests
                    if request.tool_name not in node.allowed_tools
                }
            )
            if unexpected:
                raise ValueError(
                    f"Workflow agent-loop requested disallowed tools {unexpected}"
                )
            return decision.model_copy(
                update={
                    "plan": [
                        workflow_plan_marker(node.node_id, "agent", turn + 1),
                        *decision.plan,
                    ],
                    "structured_output": None,
                }
            )
        if decision.action == "complete":
            if node.on_success is None:
                raise ValueError("Workflow agent-loop has no success path")
            return self._advance(node.on_success, state, carry=decision)
        if node.on_failure:
            return self._advance(node.on_failure, state, carry=decision)
        return decision.model_copy(
            update={
                "plan": [workflow_plan_marker(node.node_id, "agent", turn + 1)],
                "structured_output": None,
            }
        )
