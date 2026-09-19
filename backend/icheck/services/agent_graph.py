from __future__ import annotations

from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver
from sqlalchemy.orm import Session

from ..agent_schemas import (
    HypothesisState,
    InvestigationCheckpointCreate,
    InvestigationState,
)
from ..langgraph_runtime import (
    CheckpointHook,
    InvestigationGraphState,
    Reasoner,
    build_investigation_graph,
    initial_graph_state,
    invoke_investigation_graph,
    resume_investigation_graph,
)
from ..models import Investigation
from .agent_runtime import append_investigation_checkpoint
from .agent_approvals import approval_resume_value
from .agent_tools import DatabaseToolExecutor


class DatabaseCheckpointHook:
    """Mirror graph-node state into iCheck's immutable audit checkpoints."""

    def __init__(
        self,
        db: Session,
        investigation: Investigation,
        *,
        actor: str = "agent.langgraph",
    ):
        self.db = db
        self.investigation = investigation
        self.actor = actor

    def __call__(self, node: str, state: InvestigationGraphState) -> None:
        self.db.refresh(self.investigation)

        # The terminal reason checkpoint already contains the full result. The
        # following finalize node is a graph-control detail, not new evidence.
        if self.investigation.status != "running":
            return
        if state["tokens_used"] < self.investigation.tokens_used:
            raise ValueError("Graph token usage cannot move backwards")
        if state["iteration"] < self.investigation.iterations_used:
            raise ValueError("Graph iteration cannot move backwards")
        if state["tool_calls_used"] != self.investigation.tool_calls_used:
            raise ValueError("Graph and database tool-call counters diverged")

        checkpoint_state = InvestigationState(
            investigation_id=state["investigation_id"],
            objective=state["objective"],
            scope=state["scope"],
            status=state["status"],
            iteration=state["iteration"],
            plan=state["plan"],
            hypotheses=[
                HypothesisState.model_validate(item)
                for item in state["hypotheses"]
            ],
            evidence_ids=state["evidence_ids"],
            tool_call_ids=state["tool_call_ids"],
            confidence=state["confidence"],
            conclusion=state["conclusion"],
            uncertainty=state["uncertainty"],
            escalation_reason=state["escalation_reason"],
        )
        append_investigation_checkpoint(
            self.db,
            self.investigation,
            InvestigationCheckpointCreate(
                node=node,
                state=checkpoint_state,
                token_usage=(
                    state["tokens_used"] - self.investigation.tokens_used
                ),
                actor=self.actor,
            ),
        )


def run_database_investigation(
    db: Session,
    investigation: Investigation,
    *,
    reasoner: Reasoner,
    checkpointer: BaseCheckpointSaver | None = None,
    actor: str = "agent.langgraph",
    interrupt_after: list[str] | None = None,
    checkpoint_hook: CheckpointHook | None = None,
) -> dict[str, Any]:
    """Run a newly started investigation through the bounded graph kernel.

    LangGraph owns execution resumption through its checkpointer. iCheck keeps a
    separate immutable, user-facing checkpoint and evidence trail for audit.
    This entry point intentionally rejects a partially consumed investigation;
    a resume worker must use the persisted LangGraph thread instead of replaying
    the initial state.
    """

    db.refresh(investigation)
    if investigation.status != "running":
        raise ValueError("Investigation must be running")
    if any(
        (
            investigation.iterations_used,
            investigation.tool_calls_used,
            investigation.tokens_used,
        )
    ):
        raise ValueError(
            "Partially consumed investigations must resume from their "
            "LangGraph checkpoint"
        )

    graph = build_investigation_graph(
        reasoner=reasoner,
        tool_executor=DatabaseToolExecutor(db, investigation),
        checkpointer=checkpointer,
        checkpoint_hook=(
            checkpoint_hook
            or DatabaseCheckpointHook(
                db,
                investigation,
                actor=actor,
            )
        ),
        interrupt_after=interrupt_after,
    )
    state = initial_graph_state(
        investigation_id=investigation.id,
        objective=investigation.objective,
        scope=investigation.scope,
        max_iterations=investigation.max_iterations,
        max_tool_calls=investigation.max_tool_calls,
        token_budget=investigation.token_budget,
    )
    result = dict(invoke_investigation_graph(graph, state))
    if result.get("__interrupt__"):
        result["status"] = "waiting_approval"
    return result


def resume_database_investigation(
    db: Session,
    investigation: Investigation,
    *,
    reasoner: Reasoner,
    checkpointer: BaseCheckpointSaver,
    actor: str = "agent.langgraph",
    checkpoint_hook: CheckpointHook | None = None,
) -> dict[str, Any]:
    """Continue a leased investigation from its LangGraph thread checkpoint."""

    db.refresh(investigation)
    if investigation.status != "running":
        raise ValueError("Only running investigations can resume")
    graph = build_investigation_graph(
        reasoner=reasoner,
        tool_executor=DatabaseToolExecutor(db, investigation),
        checkpointer=checkpointer,
        checkpoint_hook=(
            checkpoint_hook
            or DatabaseCheckpointHook(
                db,
                investigation,
                actor=actor,
            )
        ),
    )
    return dict(
        resume_investigation_graph(
            graph,
            investigation_id=investigation.id,
            max_iterations=investigation.max_iterations,
            resume_value=approval_resume_value(db, investigation.id),
        )
    )
