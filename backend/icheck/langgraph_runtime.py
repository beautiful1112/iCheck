from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, Literal, Protocol, TypedDict
from uuid import UUID

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.errors import GraphInterrupt
from langgraph.func import task
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .checkpoint_schema import verify_checkpoint_schema
from .config import get_settings
from .agent_schemas import HypothesisState


_CHECKPOINT_SETUP_LOCK = threading.Lock()
_CHECKPOINT_SETUP_DSNS: set[str] = set()
_CHECKPOINT_VERIFIED_DSNS: set[str] = set()


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
    structured_output: dict[str, Any] | None = None
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
        if self.action != "complete" and self.structured_output is not None:
            raise ValueError("structured_output is valid only for complete decisions")
        return self


class GrafanaPreviewCompletion(BaseModel):
    """Executor-owned completion receipt, never parsed from remote tool content."""

    model_config = ConfigDict(extra="forbid")
    task: Literal["grafana-dashboard"] = "grafana-dashboard"
    change_id: UUID


class GraphToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    call_id: str
    tool_name: str
    arguments: dict[str, Any]
    status: Literal["succeeded", "failed"]
    result: dict[str, Any] | list[Any] | None = None
    error: str | None = None
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    auxiliary_call_ids: list[str] = Field(default_factory=list, max_length=100)
    governance: dict[str, Any] | None = None
    task_completion: GrafanaPreviewCompletion | None = None

    @model_validator(mode="after")
    def validate_task_completion(self):
        if self.task_completion is not None and (self.status != "succeeded" or self.tool_name not in {
                "grafana.dashboard.preview", "grafana.dashboard.restore.preview"}):
            raise ValueError("Preview completion requires a successful native preview call")
        return self


class GraphToolExecutionFailure(RuntimeError):
    """A rejected request may have completed real read-only prerequisites."""
    def __init__(self, *, tool_call_ids: list[str], evidence_ids: list[str],
                 message: str = "Requested action rejected before execution"):
        super().__init__(message)
        self.tool_call_ids = list(tool_call_ids)
        self.evidence_ids = list(evidence_ids)


class GraphToolOutcomeUnknown(GraphToolExecutionFailure):
    """Count a started Tool call while escalating without a fabricated result."""
    def __init__(self, *, tool_call_ids: list[str], evidence_ids: list[str]):
        super().__init__(
            tool_call_ids=tool_call_ids, evidence_ids=evidence_ids,
            message="External write outcome unknown; independent provider reconciliation required",
        )


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
    structured_output: dict[str, Any] | None
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
        "structured_output": None,
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
            "structured_output": decision.structured_output,
            "current_node": "reason",
        }
        save("reason", {**state, **update})
        return update

    def route_after_reason(state: InvestigationGraphState) -> str:
        return "tools" if state["status"] == "running" else "finalize"

    @task(name="icheck-tool-request")
    def execute_tool_request(
        request: dict[str, Any], state: InvestigationGraphState,
    ) -> dict[str, Any]:
        # A request owns its interrupt positions and durable completed result.
        # Otherwise a completed earlier action skips its old interrupt when
        # the tools node replays, shifting a later action's human approval.
        # Inputs/results stay primitive for strict remote checkpoint encoding.
        # No task retry policy: unknown infrastructure writes must not repeat.
        result = tool_executor(GraphToolRequest.model_validate(request), state)
        return result.model_dump(mode="json")

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
        calls_used = 0
        for request in requests:
            try:
                # Await each Task before starting the next: shared database
                # executors and governed changes must remain sequential.
                result = GraphToolResult.model_validate(execute_tool_request(
                    request.model_dump(mode="json"), state,
                ).result())
            except GraphInterrupt:
                raise
            except Exception as exc:
                if isinstance(exc, GraphToolExecutionFailure):
                    for call_id in exc.tool_call_ids:
                        if call_id not in tool_call_ids:
                            tool_call_ids.append(call_id)
                            calls_used += 1
                    for evidence_id in exc.evidence_ids:
                        if evidence_id not in evidence_ids:
                            evidence_ids.append(evidence_id)
                update = {
                    "status": "escalated",
                    # Preserve earlier completed requests when a later exact
                    # approval is rejected or a Tool cannot execute. Do not
                    # invent a result/citation for the failing request.
                    "tool_calls_used": state["tool_calls_used"] + calls_used,
                    "tool_results": results,
                    "tool_call_ids": tool_call_ids,
                    "evidence_ids": evidence_ids,
                    "call_hashes": [*state["call_hashes"], *new_hashes[:len(results)]],
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
            result_call_ids = [result.call_id, *result.auxiliary_call_ids]
            if len(result_call_ids) != len(set(result_call_ids)):
                raise ValueError("Tool executor returned duplicate call identifiers")
            calls_used += len(result_call_ids)
            for call_id in result_call_ids:
                if call_id not in tool_call_ids:
                    tool_call_ids.append(call_id)
            for evidence_id in result.evidence_ids:
                if evidence_id not in evidence_ids:
                    evidence_ids.append(evidence_id)
        if state["tool_calls_used"] + calls_used > state["max_tool_calls"]:
            update = {
                "status": "escalated",
                "tool_calls_used": state["tool_calls_used"] + calls_used,
                "tool_results": results,
                "tool_call_ids": tool_call_ids,
                "evidence_ids": evidence_ids,
                "call_hashes": [*state["call_hashes"], *new_hashes],
                "escalation_reason": "Tool-call budget exhausted",
                "pending_tool_requests": [],
                "current_node": "tools",
            }
            save("tools", {**state, **update})
            return update
        update = {
            "tool_calls_used": state["tool_calls_used"] + calls_used,
            "tool_results": results,
            "tool_call_ids": tool_call_ids,
            "evidence_ids": evidence_ids,
            "call_hashes": [*state["call_hashes"], *new_hashes],
            "pending_tool_requests": [],
            "current_node": "tools",
        }
        # Known preview tasks finish on the native executor's accepted receipt.
        # The tool's result body is untrusted and cannot supply this metadata.
        # Finish only after the entire admitted batch has succeeded and budgets
        # have been checked; ordinary investigation/Skill/workflow loops remain.
        completions = [item["task_completion"] for item in results if item.get("task_completion")]
        if (state["scope"].get("capability_task") == "grafana-dashboard"
                and completions and all(item["status"] == "succeeded" for item in results)):
            changes = list(dict.fromkeys(str(item["change_id"]) for item in completions))
            links = [f"/dashboards?change={identifier}" for identifier in changes]
            update.update({
                "status": "completed",
                "conclusion": "Dashboard preview validated. " + " ".join(
                    f"[Review proposal]({link})." for link in links
                ) + " The proposed changes have not been applied; review and confirm them to save to Grafana.",
                "structured_output": {"contract": "icheck.grafana-preview-result/v1",
                    "change_ids": changes, "review_urls": links, "applied": False},
                "confidence": None,
                "uncertainty": ["A validated proposal does not establish fresh device measurements or device health."],
                "escalation_reason": None,
            })
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
    # A Tool may commit independently of this root graph. Its next-step
    # checkpoint must be acknowledged before the Tool RPC can begin, including
    # when checkpoint and Tool HTTP share a synchronized transport.
    durability = {"durability": "sync"} if getattr(graph, "checkpointer", None) else {}
    return graph.invoke(state, config=config, **durability)


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
    pending = [item for task in snapshot.tasks for item in getattr(task, "interrupts", ())]
    if not snapshot.next and not pending:
        raise ValueError("LangGraph checkpoint is already terminal")
    if resume_value is not None and pending:
        if len(pending) != 1:
            raise ValueError("Investigation requires one exact pending approval interrupt")
        graph_input = Command(resume={pending[0].id: resume_value})
    else:
        graph_input = Command(resume=resume_value) if resume_value is not None else None
    durability = {"durability": "sync"} if getattr(graph, "checkpointer", None) else {}
    return graph.invoke(graph_input, config=config, **durability)


def _postgres_dsn(database_url: str) -> str:
    if database_url.startswith("postgresql+psycopg://"):
        return "postgresql://" + database_url.removeprefix(
            "postgresql+psycopg://"
        )
    if database_url.startswith(("postgresql://", "postgres://")):
        return database_url
    raise ValueError("LangGraph production checkpoints require PostgreSQL")


@contextmanager
def postgres_checkpointer(
    database_url: str,
    *,
    setup_mode: Literal["automatic", "verify"] | None = None,
    tenant_id: str | None = None,
    region_id: str | None = None,
) -> Iterator[PostgresSaver]:
    if (tenant_id is None) != (region_id is None):
        raise ValueError("Checkpoint tenant and region must be supplied together")
    if tenant_id is not None and (
        not tenant_id.strip() or not region_id or not region_id.strip()
        or len(tenant_id) > 36 or len(region_id) > 36
    ):
        raise ValueError("Checkpoint tenant and region must be nonempty IDs")
    os.environ.setdefault("LANGGRAPH_STRICT_MSGPACK", "true")
    dsn = _postgres_dsn(database_url)
    mode = setup_mode or get_settings().effective_checkpoint_setup_mode
    with PostgresSaver.from_conn_string(dsn) as saver:
        if mode == "automatic" and dsn not in _CHECKPOINT_SETUP_DSNS:
            with _CHECKPOINT_SETUP_LOCK:
                if dsn not in _CHECKPOINT_SETUP_DSNS:
                    saver.setup()
                    _CHECKPOINT_SETUP_DSNS.add(dsn)
        elif mode == "verify" and dsn not in _CHECKPOINT_VERIFIED_DSNS:
            with _CHECKPOINT_SETUP_LOCK:
                if dsn not in _CHECKPOINT_VERIFIED_DSNS:
                    verify_checkpoint_schema(dsn)
                    _CHECKPOINT_VERIFIED_DSNS.add(dsn)
        if tenant_id is not None:
            # PostgresSaver.from_conn_string owns one autocommit connection for
            # this context. Session settings remain bound across its statements.
            with saver.conn.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config('icheck.tenant_id', %s, false), "
                    "set_config('icheck.region_id', %s, false)",
                    (tenant_id, region_id),
                )
        yield saver
