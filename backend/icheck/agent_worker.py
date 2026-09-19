from __future__ import annotations

import argparse
import logging
import os
import time
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver
from sqlalchemy.orm import Session

from .agent_schemas import (
    AgentExecutionAssignment,
    AgentExecutionClaim,
    AgentExecutionComplete,
    AgentWorkerRegister,
)
from .builtin_agent_tools import ensure_builtin_agent_tools
from .config import get_settings
from .database import SessionLocal
from .langgraph_runtime import InvestigationGraphState, postgres_checkpointer
from .models import AgentExecution, AgentWorker, Investigation
from .services.agent_execution import (
    active_agent_execution,
    append_execution_event,
    claim_agent_executions,
    complete_agent_execution,
    register_agent_worker,
    renew_agent_execution_lease,
)
from .services.agent_graph import (
    DatabaseCheckpointHook,
    resume_database_investigation,
    run_database_investigation,
)
from .services.model_reasoner import OpenAICompatibleReasoner


LOGGER = logging.getLogger("icheck.agent_worker")


class ExecutionCancellationRequested(RuntimeError):
    pass


class LeasedCheckpointHook:
    """Validate/renew ownership and publish bounded graph progress events."""

    def __init__(
        self,
        db: Session,
        investigation: Investigation,
        execution: AgentExecution,
        worker: AgentWorker,
        *,
        lease_token: str,
        lease_seconds: int,
    ):
        self.db = db
        self.execution = execution
        self.worker = worker
        self.lease_token = lease_token
        self.lease_seconds = lease_seconds
        self.product_hook = DatabaseCheckpointHook(
            db,
            investigation,
            actor=f"agent.worker.{worker.id}",
        )

    def __call__(self, node: str, state: InvestigationGraphState) -> None:
        execution = active_agent_execution(
            self.db,
            self.execution.id,
            worker_id=self.worker.id,
            lease_token=self.lease_token,
        )
        if execution.cancellation_requested_at is not None:
            raise ExecutionCancellationRequested(
                "Agent execution cancellation was requested"
            )
        renew_agent_execution_lease(
            self.db,
            execution.id,
            worker=self.worker,
            lease_token=self.lease_token,
            lease_seconds=self.lease_seconds,
        )
        self.product_hook(node, state)
        event = append_execution_event(
            self.db,
            execution,
            event_type=f"graph.{node}",
            payload={
                "status": state["status"],
                "iteration": state["iteration"],
                "tokens_used": state["tokens_used"],
                "tool_calls_used": state["tool_calls_used"],
                "evidence_count": len(state["evidence_ids"]),
            },
        )
        self.db.commit()
        LOGGER.debug(
            "execution=%s event=%s sequence=%s",
            execution.id,
            event.event_type,
            event.sequence,
        )


def execute_assignment(
    db: Session,
    worker: AgentWorker,
    assignment: AgentExecutionAssignment,
    *,
    checkpointer: BaseCheckpointSaver,
    lease_seconds: int,
) -> AgentExecution:
    execution = active_agent_execution(
        db,
        assignment.execution_id,
        worker_id=worker.id,
        lease_token=assignment.lease_token,
    )
    investigation = db.get(Investigation, assignment.investigation_id)
    if investigation is None:
        raise LookupError("Investigation not found")
    reasoner = OpenAICompatibleReasoner(db, investigation)
    checkpoint_hook = LeasedCheckpointHook(
        db,
        investigation,
        execution,
        worker,
        lease_token=assignment.lease_token,
        lease_seconds=lease_seconds,
    )
    try:
        if assignment.resume_required:
            result = resume_database_investigation(
                db,
                investigation,
                reasoner=reasoner,
                checkpointer=checkpointer,
                actor=f"agent.worker.{worker.id}",
                checkpoint_hook=checkpoint_hook,
            )
        else:
            result = run_database_investigation(
                db,
                investigation,
                reasoner=reasoner,
                checkpointer=checkpointer,
                actor=f"agent.worker.{worker.id}",
                checkpoint_hook=checkpoint_hook,
            )
    except ExecutionCancellationRequested:
        return complete_agent_execution(
            db,
            execution.id,
            worker=worker,
            payload=AgentExecutionComplete(
                lease_token=assignment.lease_token,
                status="cancelled",
            ),
        )
    except Exception as exc:
        LOGGER.exception("Agent execution %s failed", execution.id)
        try:
            return complete_agent_execution(
                db,
                execution.id,
                worker=worker,
                payload=AgentExecutionComplete(
                    lease_token=assignment.lease_token,
                    status="failed",
                    error=f"Agent worker failed: {type(exc).__name__}",
                ),
            )
        except Exception:
            db.rollback()
            raise

    graph_status = result["status"]
    if graph_status == "completed":
        completion = AgentExecutionComplete(
            lease_token=assignment.lease_token,
            status="succeeded",
        )
    elif graph_status == "waiting_approval":
        completion = AgentExecutionComplete(
            lease_token=assignment.lease_token,
            status="waiting_approval",
        )
    else:
        completion = AgentExecutionComplete(
            lease_token=assignment.lease_token,
            status="failed",
            error="Investigation did not complete; inspect its checkpoint trace",
        )
    return complete_agent_execution(
        db,
        execution.id,
        worker=worker,
        payload=completion,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run an iCheck agent worker")
    parser.add_argument(
        "--name",
        default=os.environ.get("ICHECK_AGENT_WORKER_NAME"),
    )
    parser.add_argument(
        "--capabilities",
        default=os.environ.get(
            "ICHECK_AGENT_WORKER_CAPABILITIES",
            "openai_compatible",
        ),
        help="Comma-separated provider types",
    )
    parser.add_argument(
        "--lease-seconds",
        type=int,
        default=int(os.environ.get("ICHECK_AGENT_WORKER_LEASE_SECONDS", "300")),
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=float(os.environ.get("ICHECK_AGENT_WORKER_POLL_SECONDS", "2")),
    )
    parser.add_argument("--once", action="store_true")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: Any) -> list[str]:
    if not args.name:
        parser.error("--name or ICHECK_AGENT_WORKER_NAME is required")
    if args.lease_seconds < 15 or args.lease_seconds > 3600:
        parser.error("--lease-seconds must be between 15 and 3600")
    if args.poll_seconds <= 0 or args.poll_seconds > 60:
        parser.error("--poll-seconds must be greater than 0 and at most 60")
    capabilities = [
        item.strip() for item in args.capabilities.split(",") if item.strip()
    ]
    if not capabilities:
        parser.error("at least one worker capability is required")
    return capabilities


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("ICHECK_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = _parser()
    args = parser.parse_args()
    capabilities = _validate_args(parser, args)
    settings = get_settings()
    if not settings.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        parser.error("the agent worker requires PostgreSQL durable checkpoints")

    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        worker, _discarded_api_token = register_agent_worker(
            db,
            AgentWorkerRegister(
                name=args.name,
                capabilities=capabilities,
                labels={"runtime": "systemd"},
            ),
        )
        worker_id = worker.id

    with postgres_checkpointer(settings.database_url) as checkpointer:
        while True:
            with SessionLocal() as db:
                worker = db.get(AgentWorker, worker_id)
                if worker is None:
                    raise RuntimeError("Agent worker registration disappeared")
                assignments = claim_agent_executions(
                    db,
                    worker,
                    AgentExecutionClaim(
                        max_assignments=1,
                        lease_seconds=args.lease_seconds,
                    ),
                )
                for assignment in assignments:
                    execute_assignment(
                        db,
                        worker,
                        assignment,
                        checkpointer=checkpointer,
                        lease_seconds=args.lease_seconds,
                    )
            if args.once:
                return 0
            if not assignments:
                time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
