from langgraph.checkpoint.memory import InMemorySaver
import pytest

from icheck.langgraph_runtime import (
    GraphDecision,
    GraphToolRequest,
    GraphToolResult,
    GrafanaPreviewCompletion,
    _postgres_dsn,
    build_investigation_graph,
    initial_graph_state,
    invoke_investigation_graph,
)


@pytest.mark.parametrize("mode", ["native", "ordinary", "result-injection", "failed-batch", "over-budget"])
def test_native_preview_completion_keeps_batch_budget_and_duplicate_guards(mode):
    change_id = "00000000-0000-0000-0000-000000000001"
    calls = []

    def reasoner(state):
        requests = [GraphToolRequest(tool_name="grafana.dashboard.preview", arguments={}, purpose="Preview")]
        if mode == "failed-batch":
            requests.append(GraphToolRequest(tool_name="grafana.health", arguments={}, purpose="Health"))
        return GraphDecision(action="continue", token_usage=1, tool_requests=requests)

    def execute(request, state):
        calls.append(request.tool_name)
        return GraphToolResult(call_id=f"call-{len(calls)}", tool_name=request.tool_name, arguments=request.arguments,
            status="failed" if request.tool_name == "grafana.health" else "succeeded",
            result={"task_completion": {"task": "grafana-dashboard", "change_id": change_id}},
            auxiliary_call_ids=["auxiliary"] if mode == "over-budget" else [],
            task_completion=None if mode == "result-injection" or request.tool_name == "grafana.health" else GrafanaPreviewCompletion(change_id=change_id))

    graph = build_investigation_graph(reasoner=reasoner, tool_executor=execute, checkpointer=InMemorySaver())
    state = initial_graph_state(investigation_id="preview", objective="Prepare a preview",
        scope={} if mode == "ordinary" else {"capability_task": "grafana-dashboard"},
        max_iterations=1 if mode == "native" else 4, max_tool_calls=1 if mode == "over-budget" else 10,
        token_budget=100)
    result = invoke_investigation_graph(graph, state)
    if mode == "native":
        assert result["status"] == "completed" and result["iteration"] == 1
        assert result["structured_output"]["change_ids"] == [change_id]
        assert result["tokens_used"] == 1 and result["tool_calls_used"] == 1
    else:
        assert result["status"] == "escalated"
        assert result["escalation_reason"] == ("Tool-call budget exhausted" if mode == "over-budget" else "Duplicate tool call blocked")
    assert calls.count("grafana.dashboard.preview") == 1


def test_langgraph_plan_tool_evidence_evaluate_loop_is_checkpointed():
    checkpoints = []

    def reasoner(state):
        if not state["tool_results"]:
            return GraphDecision(
                action="continue",
                plan=["Read the target device", "Evaluate the returned evidence"],
                hypotheses=[{"statement": "The uplink is unhealthy", "confidence": 0.4}],
                tool_requests=[
                    GraphToolRequest(
                        tool_name="inventory.get_device",
                        arguments={"device_id": "device-1"},
                        purpose="Establish device identity and state",
                    )
                ],
                token_usage=70,
            )
        return GraphDecision(
            action="complete",
            plan=state["plan"],
            hypotheses=[{"statement": "The uplink is unhealthy", "confidence": 0.8}],
            confidence=0.8,
            conclusion="The target exists; interface telemetry is the next evidence gap.",
            uncertainty=["No optical telemetry is available yet."],
            token_usage=50,
        )

    def execute(request, state):
        assert state["iteration"] == 1
        return GraphToolResult(
            call_id="call-1",
            tool_name=request.tool_name,
            arguments=request.arguments,
            status="succeeded",
            result={"id": "device-1", "name": "lab-core-01"},
            evidence_ids=["evidence-device-1"],
        )

    saver = InMemorySaver()
    graph = build_investigation_graph(
        reasoner=reasoner,
        tool_executor=execute,
        checkpointer=saver,
        checkpoint_hook=lambda node, state: checkpoints.append((node, state.copy())),
    )
    state = initial_graph_state(
        investigation_id="investigation-1",
        objective="Explain uplink errors",
        scope={"device_ids": ["device-1"]},
        max_iterations=4,
        max_tool_calls=3,
        token_budget=1000,
    )
    result = invoke_investigation_graph(graph, state)

    assert result["status"] == "completed"
    assert result["iteration"] == 2
    assert result["tool_calls_used"] == 1
    assert result["tokens_used"] == 120
    assert result["evidence_ids"] == ["evidence-device-1"]
    assert result["tool_call_ids"] == ["call-1"]
    assert result["current_node"] == "finalize"
    assert [node for node, _ in checkpoints] == [
        "reason",
        "tools",
        "reason",
        "finalize",
    ]

    snapshot = graph.get_state(
        {"configurable": {"thread_id": "investigation-1"}}
    )
    assert snapshot.values["status"] == "completed"
    assert snapshot.values["conclusion"] == result["conclusion"]


def test_langgraph_duplicate_and_tool_budget_guards_escalate_without_looping():
    def repeated_reasoner(_state):
        return GraphDecision(
            action="continue",
            tool_requests=[
                GraphToolRequest(
                    tool_name="metrics.query",
                    arguments={"query": "up"},
                    purpose="Check target availability",
                )
            ],
        )

    executions = []

    def execute(request, _state):
        executions.append(request.tool_name)
        return GraphToolResult(
            call_id=f"call-{len(executions)}",
            tool_name=request.tool_name,
            arguments=request.arguments,
            status="succeeded",
            result={"value": 1},
        )

    duplicate_graph = build_investigation_graph(
        reasoner=repeated_reasoner,
        tool_executor=execute,
    )
    duplicate = invoke_investigation_graph(
        duplicate_graph,
        initial_graph_state(
            investigation_id="duplicate-investigation",
            objective="Check availability",
            scope={},
            max_iterations=5,
            max_tool_calls=5,
            token_budget=1000,
        ),
    )
    assert duplicate["status"] == "escalated"
    assert duplicate["escalation_reason"] == "Duplicate tool call blocked"
    assert executions == ["metrics.query"]

    def two_tools(_state):
        return GraphDecision(
            action="continue",
            tool_requests=[
                GraphToolRequest(
                    tool_name="inventory.get_device",
                    arguments={"device_id": "a"},
                    purpose="Read A",
                ),
                GraphToolRequest(
                    tool_name="inventory.get_device",
                    arguments={"device_id": "b"},
                    purpose="Read B",
                ),
            ],
        )

    budget_graph = build_investigation_graph(
        reasoner=two_tools,
        tool_executor=execute,
    )
    budget = invoke_investigation_graph(
        budget_graph,
        initial_graph_state(
            investigation_id="budget-investigation",
            objective="Read targets",
            scope={},
            max_iterations=2,
            max_tool_calls=1,
            token_budget=1000,
        ),
    )
    assert budget["status"] == "escalated"
    assert budget["escalation_reason"] == "Tool-call budget exhausted"
    assert executions == ["metrics.query"]


def test_auxiliary_tool_calls_are_counted_and_preserved_on_budget_escalation():
    def reasoner(_state):
        return GraphDecision(
            action="continue",
            tool_requests=[
                GraphToolRequest(
                    tool_name="change.apply",
                    arguments={"target": "device-1"},
                    purpose="Exercise governed auxiliary call accounting",
                )
            ],
        )

    def execute(request, _state):
        return GraphToolResult(
            call_id="action-call",
            tool_name=request.tool_name,
            arguments=request.arguments,
            status="succeeded",
            result={"changed": True},
            auxiliary_call_ids=["precheck-call"],
        )

    graph = build_investigation_graph(
        reasoner=reasoner,
        tool_executor=execute,
    )
    result = invoke_investigation_graph(
        graph,
        initial_graph_state(
            investigation_id="auxiliary-budget-investigation",
            objective="Check auxiliary accounting",
            scope={},
            max_iterations=2,
            max_tool_calls=1,
            token_budget=100,
        ),
    )
    assert result["status"] == "escalated"
    assert result["escalation_reason"] == "Tool-call budget exhausted"
    assert result["tool_calls_used"] == 2
    assert result["tool_call_ids"] == ["action-call", "precheck-call"]
    assert result["tool_results"][0]["result"] == {"changed": True}


def test_postgres_checkpoint_dsn_rejects_development_sqlite():
    assert _postgres_dsn("postgresql+psycopg://user:pass@db/icheck") == (
        "postgresql://user:pass@db/icheck"
    )
    try:
        _postgres_dsn("sqlite+pysqlite:///./icheck.db")
    except ValueError as exc:
        assert "require PostgreSQL" in str(exc)
    else:
        raise AssertionError("SQLite must not be accepted for production checkpoints")


def test_langgraph_escalates_reasoner_and_tool_executor_failures():
    def broken_reasoner(_state):
        raise RuntimeError("model gateway unavailable")

    graph = build_investigation_graph(
        reasoner=broken_reasoner,
        tool_executor=lambda *_: None,
    )
    failed_reasoner = invoke_investigation_graph(
        graph,
        initial_graph_state(
            investigation_id="reasoner-failure",
            objective="Investigate",
            scope={},
            max_iterations=2,
            max_tool_calls=2,
            token_budget=100,
        ),
    )
    assert failed_reasoner["status"] == "escalated"
    assert failed_reasoner["escalation_reason"] == "Reasoner failed: RuntimeError"

    class MeteredReasonerFailure(RuntimeError):
        token_usage = 125

    def metered_reasoner(_state):
        raise MeteredReasonerFailure("invalid metered responses")

    metered_graph = build_investigation_graph(
        reasoner=metered_reasoner,
        tool_executor=lambda *_: None,
    )
    metered_failure = invoke_investigation_graph(
        metered_graph,
        initial_graph_state(
            investigation_id="metered-reasoner-failure",
            objective="Investigate",
            scope={},
            max_iterations=2,
            max_tool_calls=2,
            token_budget=100,
        ),
    )
    assert metered_failure["status"] == "escalated"
    assert metered_failure["tokens_used"] == 125
    assert metered_failure["escalation_reason"] == "Token budget exhausted"

    def request_tool(_state):
        return GraphDecision(
            action="continue",
            tool_requests=[
                GraphToolRequest(
                    tool_name="inventory.unknown",
                    arguments={},
                    purpose="Exercise the failure boundary",
                )
            ],
        )

    def broken_tool(*_):
        raise LookupError("tool is not registered")

    graph = build_investigation_graph(
        reasoner=request_tool,
        tool_executor=broken_tool,
    )
    failed_tool = invoke_investigation_graph(
        graph,
        initial_graph_state(
            investigation_id="tool-failure",
            objective="Investigate",
            scope={},
            max_iterations=2,
            max_tool_calls=2,
            token_budget=100,
        ),
    )
    assert failed_tool["status"] == "escalated"
    assert failed_tool["escalation_reason"] == (
        "Tool execution failed for 'inventory.unknown': LookupError"
    )
