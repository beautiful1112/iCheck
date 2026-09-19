from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, Literal, Protocol, TypedDict

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.errors import GraphInterrupt
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .agent_schemas import HypothesisState


class GraphToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(min_length=1, max_length=255)
    arguments: dict[str, Any]
    purpose: str = Field(min_length=1, max_length=2000)


class GraphDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["continue", "complete", "escalate"]
    plan: list[str] = Field(default_factory=list, max_length=100)
    hypotheses: list[HypothesisState] = Field(default_factory=list, max_length=100)
    tool_requests: list[GraphToolRequest] = Field(default_factory=list, max_length=20)
    confidence: float | None = Field(default=None, ge=0, le=1)
    conclusion: str | None = Field(default=None, max_length=20_000)
    uncertainty: list[str] = Field(default_factory=list, max_length=100)
    escalation_reason: str | None = Field(default=None, max_length=4000)
    token_usage: int = Field(default=0, ge=0, le=10_000_000)

    @model_validator(mode="after")
    def validate_action(self) -> GraphDecision:
        if self.action == "continue" and not self.tool_requests:
            raise ValueError("continue decisions require at least one tool request")
        if self.action == "complete" and not self.conclusion:
            raise ValueError("complete decisions require a conclusion")
        if self.action == "escalate" and not self.escalation_reason:
            raise ValueError("escalate decisions require a reason")
        if self.action != "continue" and self.tool_requests:
            raise ValueError("terminal decisions cannot request tools")
        return self


class GraphToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    call_id: str
    tool_name: str
    arguments: dict[str, Any]
    status: Literal["succeeded", "failed"]
    result: dict[str, Any] | list[Any] | None = None
    error: str | None = None
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)


class InvestigationGraphState(TypedDict):
    investigation_id: str
    objective: str
    scope: dict[str, Any]
    status: str
    iteration: int
    max_iterations: int
    tool_calls_used: int
    max_tool_calls: int
    tokens_used: int
    token_budget: int
    plan: list[str]
    hypotheses: list[dict[str, Any]]
    evidence_ids: list[str]
    tool_call_ids: list[str]
    pending_tool_requests: list[dict[str, Any]]
    tool_results: list[dict[str, Any]]
    call_hashes: list[str]
    confidence: float | None
    conclusion: str | None
    uncertainty: list[str]
    escalation_reason: str | None
    current_node: str


class Reasoner(Protocol):
    def __call__(
        self,
        state: InvestigationGraphState,
    ) -> GraphDecision: ...


class ToolExecutor(Protocol):
    def __call__(
        self,
        request: GraphToolRequest,
        state: InvestigationGraphState,
    ) -> GraphToolResult: ...


CheckpointHook = Callable[[str, InvestigationGraphState], None]


def initial_graph_state(
    *,
    investigation_id: str,
    objective: str,
    scope: dict[str, Any],
    max_iterations: int,
    max_tool_calls: int,
    token_budget: int,
) -> InvestigationGraphState:
    return {
        "investigation_id": investigation_id,
        "objective": objective,
        "scope": scope,
        "status": "running",
        "iteration": 0,
        "max_iterations": max_iterations,
        "tool_calls_used": 0,
        "max_tool_calls": max_tool_calls,
        "tokens_used": 0,
        "token_budget": token_budget,
        "plan": [],
        "hypotheses": [],
        "evidence_ids": [],
        "tool_call_ids": [],
        "pending_tool_requests": [],
        "tool_results": [],
        "call_hashes": [],
        "confidence": None,
        "conclusion": None,
        "uncertainty": [],
        "escalation_reason": None,
        "current_node": "start",
    }


def _tool_call_hash(request: GraphToolRequest) -> str:
    encoded = json.dumps(
        {"tool_name": request.tool_name, "arguments": request.arguments},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_investigation_graph(
    *,
    reasoner: Reasoner,
    tool_executor: ToolExecutor,
    checkpointer: BaseCheckpointSaver | None = None,
    checkpoint_hook: CheckpointHook | None = None,
    interrupt_after: list[str] | None = None,
):
    def save(node: str, state: InvestigationGraphState) -> None:
        if checkpoint_hook is not None:
            checkpoint_hook(node, state)

    def reason_node(
        state: InvestigationGraphState,
    ) -> dict[str, Any]:
        if state["iteration"] >= state["max_iterations"]:
            update = {
                "status": "escalated",
                "escalation_reason": "Iteration budget exhausted",
                "pending_tool_requests": [],
                "current_node": "reason",
            }
            save("reason", {**state, **update})
            return update
        if state["tokens_used"] >= state["token_budget"]:
            update = {
                "status": "escalated",
                "escalation_reason": "Token budget exhausted",
                "pending_tool_requests": [],
                "current_node": "reason",
            }
            save("reason", {**state, **update})
            return update

        try:
            decision = reasoner(state)
        except Exception as exc:
            failure_token_usage = getattr(exc, "token_usage", 0)
            if (
                isinstance(failure_token_usage, bool)
                or not isinstance(failure_token_usage, int)
                or failure_token_usage < 0
            ):
                failure_token_usage = 0
            tokens_used = state["tokens_used"] + failure_token_usage
            update = {
                "status": "escalated",
                "tokens_used": tokens_used,
                "escalation_reason": (
                    "Token budget exhausted"
                    if tokens_used > state["token_budget"]
                    else f"Reasoner failed: {type(exc).__name__}"
                ),
                "pending_tool_requests": [],
                "current_node": "reason",
            }
            save("reason", {**state, **update})
            return update
        tokens_used = state["tokens_used"] + decision.token_usage
        status = {
            "continue": "running",
            "complete": "completed",
            "escalate": "escalated",
        }[decision.action]
        escalation_reason = decision.escalation_reason
        if tokens_used > state["token_budget"]:
            status = "escalated"
            escalation_reason = "Token budget exhausted"
        update = {
            "status": status,
            "iteration": state["iteration"] + 1,
            "tokens_used": tokens_used,
            "plan": decision.plan,
            "hypotheses": [
                hypothesis.model_dump(mode="json")
                for hypothesis in decision.hypotheses
            ],
            "pending_tool_requests": [
                item.model_dump(mode="json") for item in decision.tool_requests
            ] if status == "running" else [],
            "confidence": decision.confidence,
            "conclusion": decision.conclusion,
            "uncertainty": decision.uncertainty,
            "escalation_reason": escalation_reason,
            "current_node": "reason",
        }
        save("reason", {**state, **update})
        return update

    def route_after_reason(state: InvestigationGraphState) -> str:
        return "tools" if state["status"] == "running" else "finalize"

    def tools_node(
        state: InvestigationGraphState,
    ) -> dict[str, Any]:
        requests = [
            GraphToolRequest.model_validate(item)
            for item in state["pending_tool_requests"]
        ]
        remaining = state["max_tool_calls"] - state["tool_calls_used"]
        if len(requests) > remaining:
            update = {
                "status": "escalated",
                "escalation_reason": "Tool-call budget exhausted",
                "pending_tool_requests": [],
                "current_node": "tools",
            }
            save("tools", {**state, **update})
            return update

        existing_hashes = set(state["call_hashes"])
        new_hashes: list[str] = []
        for request in requests:
            call_hash = _tool_call_hash(request)
            if call_hash in existing_hashes or call_hash in new_hashes:
                update = {
                    "status": "escalated",
                    "escalation_reason": "Duplicate tool call blocked",
                    "pending_tool_requests": [],
                    "current_node": "tools",
                }
                save("tools", {**state, **update})
                return update
            new_hashes.append(call_hash)

        results: list[dict[str, Any]] = []
        evidence_ids = list(state["evidence_ids"])
        tool_call_ids = list(state["tool_call_ids"])
        for request in requests:
            try:
                result = tool_executor(request, state)
            except GraphInterrupt:
                raise
            except Exception as exc:
                update = {
                    "status": "escalated",
                    "escalation_reason": (
                        f"Tool execution failed for {request.tool_name!r}: "
                        f"{type(exc).__name__}"
                    )[:4000],
                    "pending_tool_requests": [],
                    "current_node": "tools",
                }
                save("tools", {**state, **update})
                return update
            results.append(result.model_dump(mode="json"))
            tool_call_ids.append(result.call_id)
            for evidence_id in result.evidence_ids:
                if evidence_id not in evidence_ids:
                    evidence_ids.append(evidence_id)
        update = {
            "tool_calls_used": state["tool_calls_used"] + len(results),
            "tool_results": results,
            "tool_call_ids": tool_call_ids,
            "evidence_ids": evidence_ids,
            "call_hashes": [*state["call_hashes"], *new_hashes],
            "pending_tool_requests": [],
            "current_node": "tools",
        }
        save("tools", {**state, **update})
        return update

    def route_after_tools(state: InvestigationGraphState) -> str:
        return "reason" if state["status"] == "running" else "finalize"

    def finalize_node(
        state: InvestigationGraphState,
    ) -> dict[str, Any]:
        update = {"current_node": "finalize"}
        save("finalize", {**state, **update})
        return update

    builder = StateGraph(InvestigationGraphState)
    builder.add_node("reason", reason_node)
    builder.add_node("tools", tools_node)
    builder.add_node("finalize", finalize_node)
    builder.add_edge(START, "reason")
    builder.add_conditional_edges(
        "reason",
        route_after_reason,
        {"tools": "tools", "finalize": "finalize"},
    )
    builder.add_conditional_edges(
        "tools",
        route_after_tools,
        {"reason": "reason", "finalize": "finalize"},
    )
    builder.add_edge("finalize", END)
    return builder.compile(
        checkpointer=checkpointer,
        interrupt_after=interrupt_after,
        name="icheck-investigation",
    )


def invoke_investigation_graph(graph, state: InvestigationGraphState):
    config = {
        "configurable": {"thread_id": state["investigation_id"]},
        "recursion_limit": max(10, state["max_iterations"] * 3 + 3),
    }
    return graph.invoke(state, config=config)


def resume_investigation_graph(
    graph,
    *,
    investigation_id: str,
    max_iterations: int,
    resume_value: dict[str, Any] | None = None,
):
    config = {
        "configurable": {"thread_id": investigation_id},
        "recursion_limit": max(10, max_iterations * 3 + 3),
    }
    snapshot = graph.get_state(config)
    if not snapshot.values:
        raise ValueError("LangGraph checkpoint does not exist")
    if not snapshot.next:
        raise ValueError("LangGraph checkpoint is already terminal")
    graph_input = Command(resume=resume_value) if resume_value is not None else None
    return graph.invoke(graph_input, config=config)


def _postgres_dsn(database_url: str) -> str:
    if database_url.startswith("postgresql+psycopg://"):
        return "postgresql://" + database_url.removeprefix(
            "postgresql+psycopg://"
        )
    if database_url.startswith(("postgresql://", "postgres://")):
        return database_url
    raise ValueError("LangGraph production checkpoints require PostgreSQL")


@contextmanager
def postgres_checkpointer(database_url: str) -> Iterator[PostgresSaver]:
    os.environ.setdefault("LANGGRAPH_STRICT_MSGPACK", "true")
    with PostgresSaver.from_conn_string(_postgres_dsn(database_url)) as saver:
        saver.setup()
        yield saver
