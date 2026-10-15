"""Process-loss acceptance for the production LangGraph PostgreSQL saver.

This probe intentionally uses a new, disposable PostgreSQL database. It does
not run the Agent Worker or call external models or devices.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import psycopg

from .langgraph_runtime import (
    GraphDecision,
    GraphToolRequest,
    GraphToolResult,
    _postgres_dsn,
    build_investigation_graph,
    initial_graph_state,
    invoke_investigation_graph,
    postgres_checkpointer,
    resume_investigation_graph,
)


DATABASE_URL_ENV = "ICHECK_RECOVERY_DATABASE_URL"
INTERNAL_STAGE_TOKEN_ENV = "ICHECK_RECOVERY_STAGE_TOKEN"
REPORT_FORMAT = "icheck.langgraph-recovery-report/v1"
EVIDENCE_ID = "recovery-probe-evidence"
TOOL_CALL_ID = "recovery-probe-tool-call"


def _database_state(database_url: str) -> tuple[str, int]:
    dsn = _postgres_dsn(database_url)
    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database()")
            database_name = cursor.fetchone()[0]
            cursor.execute(
                """
                SELECT count(*) FROM pg_class AS relation
                JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                  AND namespace.nspname NOT IN ('pg_catalog', 'information_schema')
                  AND namespace.nspname NOT LIKE 'pg_toast%'
                """
            )
            relation_count = cursor.fetchone()[0]
    if not database_name.startswith("icheck_recovery_"):
        raise ValueError("Recovery probe requires an icheck_recovery_ database")
    return database_name, relation_count


def _validate_empty_database(database_url: str) -> str:
    database_name, relation_count = _database_state(database_url)
    if relation_count:
        raise ValueError("Recovery probe refuses a non-empty database")
    return database_name


def _stage_one(database_url: str, investigation_id: str) -> None:
    _validate_empty_database(database_url)

    def reasoner(_state: dict[str, Any]) -> GraphDecision:
        return GraphDecision(
            action="continue",
            plan=["Read one synthetic fact", "Conclude from persisted evidence"],
            tool_requests=[
                GraphToolRequest(
                    tool_name="recovery_probe.read",
                    arguments={"target": "synthetic"},
                    purpose="Test durable tool checkpoint recovery",
                )
            ],
            token_usage=7,
        )

    def execute(request: GraphToolRequest, _state: dict[str, Any]) -> GraphToolResult:
        return GraphToolResult(
            call_id=TOOL_CALL_ID,
            tool_name=request.tool_name,
            arguments=request.arguments,
            status="succeeded",
            result={"observation": "persisted"},
            evidence_ids=[EVIDENCE_ID],
        )

    with postgres_checkpointer(database_url) as saver:
        graph = build_investigation_graph(
            reasoner=reasoner,
            tool_executor=execute,
            checkpointer=saver,
            interrupt_after=["tools"],
        )
        state = initial_graph_state(
            investigation_id=investigation_id,
            objective="Prove PostgreSQL checkpoint recovery across process loss",
            scope={},
            max_iterations=3,
            max_tool_calls=2,
            token_budget=100,
        )
        interrupted = invoke_investigation_graph(graph, state)
        snapshot = graph.get_state(
            {"configurable": {"thread_id": investigation_id}}
        )
        if (
            interrupted["status"] != "running"
            or interrupted["tool_calls_used"] != 1
            or interrupted["evidence_ids"] != [EVIDENCE_ID]
            or tuple(snapshot.next) != ("reason",)
        ):
            raise RuntimeError("First process did not persist the tool checkpoint")
    print(json.dumps({"stage": "checkpoint_saved"}), flush=True)
    # Keep a pipe open until the parent sends SIGKILL. If the parent exits
    # unexpectedly, EOF also lets this child terminate without an orphan.
    sys.stdin.buffer.read(1)


def _stage_two(database_url: str, investigation_id: str) -> dict[str, Any]:
    _database_state(database_url)

    def reasoner(state: dict[str, Any]) -> GraphDecision:
        if (
            state["tool_calls_used"] != 1
            or state["evidence_ids"] != [EVIDENCE_ID]
            or state["tool_call_ids"] != [TOOL_CALL_ID]
        ):
            raise RuntimeError("Recovered state lost the completed tool evidence")
        return GraphDecision(
            action="complete",
            plan=state["plan"],
            confidence=0.9,
            conclusion="Recovered from the PostgreSQL checkpoint.",
            uncertainty=["Synthetic acceptance evidence only."],
            token_usage=5,
        )

    def refuse_replay(_request: GraphToolRequest, _state: dict[str, Any]):
        raise RuntimeError("Completed tool was replayed after process loss")

    with postgres_checkpointer(database_url) as saver:
        graph = build_investigation_graph(
            reasoner=reasoner,
            tool_executor=refuse_replay,
            checkpointer=saver,
        )
        result = resume_investigation_graph(
            graph,
            investigation_id=investigation_id,
            max_iterations=3,
        )
        snapshot = graph.get_state(
            {"configurable": {"thread_id": investigation_id}}
        )
        if (
            result["status"] != "completed"
            or result["iteration"] != 2
            or result["tool_calls_used"] != 1
            or result["tokens_used"] != 12
            or result["evidence_ids"] != [EVIDENCE_ID]
            or result["tool_call_ids"] != [TOOL_CALL_ID]
            or snapshot.next
            or snapshot.values["status"] != "completed"
        ):
            raise RuntimeError("Replacement process failed to resume exactly once")
        return {
            "status": result["status"],
            "iterations": result["iteration"],
            "tool_calls_used": result["tool_calls_used"],
            "tokens_used": result["tokens_used"],
            "evidence_ids": result["evidence_ids"],
            "tool_call_ids": result["tool_call_ids"],
            "terminal_checkpoint": not snapshot.next,
        }


def _wait_for_marker(process: subprocess.Popen[str], timeout_seconds: int) -> None:
    ready, _, _ = select.select([process.stdout], [], [], timeout_seconds)
    if not ready or process.stdout is None:
        raise TimeoutError("Checkpoint child did not signal readiness")
    line = process.stdout.readline()
    if not line or json.loads(line).get("stage") != "checkpoint_saved":
        raise RuntimeError("Checkpoint child failed before durable handoff")


def run_recovery_test(database_url: str, *, timeout_seconds: int = 60) -> dict[str, Any]:
    if timeout_seconds < 10 or timeout_seconds > 300:
        raise ValueError("timeout seconds must be between 10 and 300")
    database_name = _validate_empty_database(database_url)
    investigation_id = str(uuid.uuid4())
    child_env = {
        **os.environ,
        DATABASE_URL_ENV: database_url,
        INTERNAL_STAGE_TOKEN_ENV: str(uuid.uuid4()),
    }
    command = [sys.executable, "-m", "icheck.checkpoint_recovery_test"]
    started = time.monotonic()
    first = subprocess.Popen(
        [*command, "--stage", "checkpoint", "--investigation-id", investigation_id],
        env=child_env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        _wait_for_marker(first, timeout_seconds)
        first.kill()
        first.wait(timeout=10)
        if first.returncode != -signal.SIGKILL:
            raise RuntimeError("Checkpoint process was not killed by SIGKILL")
        second = subprocess.run(
            [*command, "--stage", "resume", "--investigation-id", investigation_id],
            env=child_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if second.returncode:
            raise RuntimeError("Replacement process failed to resume")
        result = json.loads(second.stdout)
    finally:
        if first.poll() is None:
            first.kill()
            first.wait(timeout=10)
    gates = {
        "process_was_killed": first.returncode == -signal.SIGKILL,
        "checkpoint_resumed": result["status"] == "completed",
        "tool_not_replayed": result["tool_calls_used"] == 1,
        "evidence_preserved": result["evidence_ids"] == [EVIDENCE_ID],
        "terminal_checkpoint_written": result["terminal_checkpoint"],
    }
    return {
        "format_version": REPORT_FORMAT,
        "database_backend": "postgresql",
        "schema_scope": "LangGraph PostgresSaver tables only",
        "database_name": database_name,
        "investigation_id": investigation_id,
        "first_process_exit_signal": "SIGKILL",
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "recovered": result,
        "gates": gates,
        "passed": all(gates.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-dedicated-database", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--stage", choices=["checkpoint", "resume"], help=argparse.SUPPRESS)
    parser.add_argument("--investigation-id", help=argparse.SUPPRESS)
    args = parser.parse_args()
    database_url = os.environ.get(DATABASE_URL_ENV)
    if not database_url:
        parser.error(f"{DATABASE_URL_ENV} is required; no application fallback exists")
    if args.stage:
        if not args.investigation_id:
            parser.error("internal stage requires investigation ID")
        if not os.environ.get(INTERNAL_STAGE_TOKEN_ENV):
            parser.error("internal stage requires a parent launch token")
        if args.stage == "checkpoint":
            _stage_one(database_url, args.investigation_id)
        else:
            print(json.dumps(_stage_two(database_url, args.investigation_id)))
        return 0
    if not args.acknowledge_dedicated_database:
        parser.error("--acknowledge-dedicated-database is required")
    try:
        report = run_recovery_test(database_url, timeout_seconds=args.timeout_seconds)
    except Exception as exc:
        detail = (
            f": {exc}"
            if isinstance(exc, ValueError)
            and str(exc).startswith("Recovery probe")
            else ""
        )
        parser.exit(2, f"recovery test failed: {type(exc).__name__}{detail}\n")
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
