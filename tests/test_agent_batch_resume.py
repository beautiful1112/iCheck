"""Each sequential request owns its human interrupt and completed citations."""
import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import interrupt

from icheck.langgraph_runtime import (
    GraphDecision, GraphToolRequest, GraphToolResult, build_investigation_graph,
    initial_graph_state, invoke_investigation_graph, resume_investigation_graph,
)


def batch_state():
    return initial_graph_state(
        investigation_id="bounded-batch", objective="Read and review two exact changes",
        scope={}, max_iterations=3, max_tool_calls=4, token_budget=100,
    )


def batch_reasoner(state):
    if state["tool_results"]:
        return GraphDecision(action="complete", conclusion="The exact batch completed",
            token_usage=3)
    return GraphDecision(action="continue", token_usage=7, tool_requests=[
        GraphToolRequest(tool_name=name, arguments={}, purpose=f"Execute {name} exactly")
        for name in ("read", "change-one", "change-two")
    ])


class ControlledExecutor:
    def __init__(self):
        self.entered = []
        self.approvals = []
        self.completed = set()

    def __call__(self, request, state):
        name = request.tool_name
        self.entered.append(name)
        if name != "read" and name not in self.completed:
            value = interrupt({"kind": "action_approval", "proposal_id": name})
            self.approvals.append((name, value))
            if value != {"proposal_id": name, "decision": "approve"}:
                raise PermissionError("The exact action was not approved")
        self.completed.add(name)
        return GraphToolResult(call_id=f"call:{name}", tool_name=name, arguments={},
            status="succeeded", result={"ok": True}, evidence_ids=[f"evidence:{name}"])


def rebuild(saver, executor):
    return build_investigation_graph(reasoner=batch_reasoner, tool_executor=executor,
        checkpointer=saver)


def resume(saver, executor, name, decision="approve"):
    return resume_investigation_graph(rebuild(saver, executor),
        investigation_id="bounded-batch", max_iterations=3,
        resume_value={"proposal_id": name, "decision": decision})


def test_each_human_approval_stays_with_its_own_request_on_fresh_graph_resume():
    saver, executor = InMemorySaver(), ControlledExecutor()
    first = invoke_investigation_graph(rebuild(saver, executor), batch_state())
    assert first["__interrupt__"][0].value["proposal_id"] == "change-one"
    second = resume(saver, executor, "change-one")
    assert second["__interrupt__"][0].value["proposal_id"] == "change-two"
    completed = resume(saver, executor, "change-two")
    assert completed["status"] == "completed" and completed["tokens_used"] == 10
    assert executor.entered.count("read") == 1
    assert executor.entered.count("change-one") == 2  # suspend, then exact resume
    assert executor.entered.count("change-two") == 2
    assert executor.approvals == [
        (name, {"proposal_id": name, "decision": "approve"})
        for name in ("change-one", "change-two")
    ]
    assert completed["tool_calls_used"] == 3
    assert completed["tool_call_ids"] == ["call:read", "call:change-one", "call:change-two"]
    assert completed["evidence_ids"] == ["evidence:read", "evidence:change-one", "evidence:change-two"]
    with pytest.raises(ValueError, match="terminal"):
        resume(saver, executor, "change-two")


@pytest.mark.parametrize("approval", ["change-one", "change-two"])
def test_wrong_or_rejected_second_approval_preserves_only_completed_evidence(approval):
    saver, executor = InMemorySaver(), ControlledExecutor()
    invoke_investigation_graph(rebuild(saver, executor), batch_state())
    resume(saver, executor, "change-one")
    result = resume(saver, executor, approval, "reject" if approval == "change-two" else "approve")
    assert result["status"] == "escalated"
    assert "PermissionError" in result["escalation_reason"]
    assert executor.completed == {"read", "change-one"}
    assert result["tool_calls_used"] == 2
    assert result["tool_call_ids"] == ["call:read", "call:change-one"]
    assert result["evidence_ids"] == ["evidence:read", "evidence:change-one"]
    assert len(result["call_hashes"]) == len(result["tool_results"]) == 2


def test_completed_tasks_recover_without_calling_previous_executor_bindings():
    saver, original = InMemorySaver(), ControlledExecutor()
    invoke_investigation_graph(rebuild(saver, original), batch_state())
    resume(saver, original, "change-one")
    replacement = ControlledExecutor()
    def last_only(request, state):
        assert request.tool_name == "change-two", "A completed Task was replayed"
        return replacement(request, state)
    result = resume(saver, last_only, "change-two")
    assert result["status"] == "completed"
    assert result["tool_calls_used"] == len(result["evidence_ids"]) == 3
    assert replacement.completed == {"change-two"}


def test_no_task_retry_or_extra_budget_is_granted_after_an_executor_failure():
    calls = []
    def executor(request, state):
        calls.append(request.tool_name)
        if request.tool_name == "change-one":
            raise RuntimeError("Controlled unknown outcome")
        return GraphToolResult(call_id="read-call", tool_name=request.tool_name,
            arguments={}, status="succeeded", evidence_ids=["read-evidence"])
    result = invoke_investigation_graph(rebuild(InMemorySaver(), executor), batch_state())
    assert result["status"] == "escalated"
    assert calls == ["read", "change-one"]
    assert result["tool_calls_used"] == 1 and result["evidence_ids"] == ["read-evidence"]
    assert len(result["tool_results"]) == len(result["call_hashes"]) == 1
