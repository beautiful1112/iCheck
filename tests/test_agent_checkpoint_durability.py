"""Never start the next Tool while its root checkpoint is unacknowledged."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from langgraph.checkpoint.memory import InMemorySaver

from icheck.langgraph_runtime import (GraphDecision, GraphToolRequest, GraphToolResult,
    build_investigation_graph, initial_graph_state, invoke_investigation_graph, resume_investigation_graph)


@pytest.mark.parametrize("resumed", [False, True])
def test_next_tool_waits_for_durable_root_checkpoint_on_invoke_and_resume(resumed):
    entered, release, stored, tool_started = Event(), Event(), Event(), Event()
    class HeldSaver(InMemorySaver):
        enabled = False
        def put(self, config, checkpoint, metadata, new_versions):
            values = checkpoint.get("channel_values", {})
            hold = (self.enabled and values.get("pending_tool_requests")
                and values.get("tool_calls_used", 0) == int(resumed) and not entered.is_set())
            if hold:
                entered.set()
                if not release.wait(5): raise RuntimeError("Root checkpoint was not acknowledged")
            saved = super().put(config, checkpoint, metadata, new_versions)
            if hold: stored.set()
            return saved
    saver = HeldSaver()
    def reasoner(state):
        if state["tool_calls_used"] < 2:
            return GraphDecision(action="continue", plan=["Persist intent before every Tool"],
                tool_requests=[GraphToolRequest(tool_name="test.durable", arguments={"step":state["tool_calls_used"]},
                    purpose="Verify durable checkpoint ordering")])
        return GraphDecision(action="complete", conclusion="Both durably ordered Tools completed")
    def execute(request, state):
        if saver.enabled and state["tool_calls_used"] == int(resumed):
            tool_started.set()
            assert stored.is_set(), "A Tool started before its root checkpoint acknowledgement"
        return GraphToolResult(call_id=f'call-{state["tool_calls_used"]}', tool_name=request.tool_name,
            arguments=request.arguments, status="succeeded", result={"recorded":True})
    state = initial_graph_state(investigation_id="durable-root", objective="Persist before dispatch",
        scope={}, max_iterations=4, max_tool_calls=3, token_budget=100)
    if resumed:
        seed = build_investigation_graph(reasoner=reasoner, tool_executor=execute, checkpointer=saver,
            interrupt_after=["tools"])
        invoke_investigation_graph(seed, state)
    saver.enabled = True
    graph = build_investigation_graph(reasoner=reasoner, tool_executor=execute, checkpointer=saver)
    def run():
        if resumed:
            return resume_investigation_graph(graph, investigation_id=state["investigation_id"], max_iterations=4)
        return invoke_investigation_graph(graph, state)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run)
        try:
            assert entered.wait(3), "The controlled root checkpoint was not reached"
            assert not tool_started.wait(0.1), "An unacknowledged checkpoint allowed Tool dispatch"
        finally:
            release.set()
        result = future.result(timeout=5)
    assert stored.is_set() and tool_started.is_set()
    assert result["status"] == "completed" and result["tool_calls_used"] == 2, result.get("escalation_reason")
