"""Private PostgreSQL acceptance for cancelling an in-flight Agent Worker.

Requires a fresh migrated icheck_agent_recovery_* database and an explicit
acknowledgement. The control plane and controlled model bind to loopback only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from sqlalchemy import make_url, select

from .agent_worker_recovery_test import (
    _ModelGateway,
    _api_request,
    _create_investigation,
    _start_control_plane,
    _verify_dedicated_database,
    _wait_for_expired_lease,
    _worker_command,
    _worker_environment,
)


DATABASE_URL_ENV = "ICHECK_AGENT_CANCELLATION_DATABASE_URL"
REPORT_FORMAT = "icheck.agent-worker-cancellation-report/v1"


def _assert_runtime_configuration(database_url: str, registration_token: str) -> None:
    from .config import get_settings
    from .database import engine

    settings = get_settings()
    if (
        settings.database_url != database_url
        or engine.url != make_url(database_url)
        or settings.agent_registration_token != registration_token
        or settings.environment != "development"
        or settings.control_plane_auth_mode != "disabled"
        or settings.auto_create_schema
    ):
        raise ValueError(
            "Agent cancellation requires a fresh process bound to the explicit "
            "probe database and registration token"
        )


def _result(
    execution_id: str,
    investigation_id: str,
    device_id: str,
    *,
    terminal_event: str = "execution.completed",
) -> dict[str, Any]:
    from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace
    from .models import (
        AgentExecution, AgentExecutionEvent, Investigation,
        InvestigationCheckpoint, InvestigationEvidence, InvestigationToolCall,
    )

    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        execution = db.get(AgentExecution, execution_id)
        investigation = db.get(Investigation, investigation_id)
        events = list(db.scalars(
            select(AgentExecutionEvent)
            .where(AgentExecutionEvent.execution_id == execution_id)
            .order_by(AgentExecutionEvent.sequence)
        ).all())
        checkpoints = list(db.scalars(
            select(InvestigationCheckpoint)
            .where(InvestigationCheckpoint.investigation_id == investigation_id)
            .order_by(InvestigationCheckpoint.sequence)
        ).all())
        calls = list(db.scalars(
            select(InvestigationToolCall)
            .where(InvestigationToolCall.investigation_id == investigation_id)
        ).all())
        evidence = list(db.scalars(
            select(InvestigationEvidence)
            .where(InvestigationEvidence.investigation_id == investigation_id)
        ).all())
        event_types = [item.event_type for item in events]
        gates = {
            "execution_cancelled": execution is not None and execution.status.value == "cancelled",
            "investigation_cancelled": investigation is not None and investigation.status == "cancelled",
            "one_claim_no_reassignment": (
                execution is not None
                and execution.attempt_count == 1
                and event_types.count("execution.claimed") == 1
                and "execution.reassigned" not in event_types
            ),
            (
                "cancellation_preceded_terminal_ack"
                if terminal_event == "execution.completed"
                else "cancellation_preceded_reconciliation"
            ): (
                "execution.cancellation_requested" in event_types
                and terminal_event in event_types
                and event_types.index("execution.cancellation_requested")
                < event_types.index(terminal_event)
            ),
            "prior_tool_evidence_preserved_once": (
                len(calls) == 1
                and calls[0].status == "succeeded"
                and len(evidence) == 1
                and evidence[0].evidence_id == device_id
            ),
            "no_post_cancel_product_checkpoint": (
                [item.node for item in checkpoints] == ["start", "reason", "tools"]
            ),
            "lease_cleared": (
                execution is not None
                and execution.worker_id is None
                and execution.lease_token_hash is None
                and execution.lease_expires_at is None
            ),
        }
        return {
            "execution_status": execution.status.value if execution else None,
            "investigation_status": investigation.status if investigation else None,
            "attempts": execution.attempt_count if execution else None,
            "event_types": event_types,
            "checkpoint_nodes": [item.node for item in checkpoints],
            "tool_call_count": len(calls),
            "evidence_count": len(evidence),
            "gates": gates,
        }


def run_agent_cancellation_test(
    database_url: str, *, kill_after_cancel: bool = False
) -> dict[str, Any]:
    database_name, _role_name = _verify_dedicated_database(database_url)
    registration_token = secrets.token_urlsafe(32)
    os.environ.update({
        "ICHECK_DATABASE_URL": database_url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "ICHECK_ENVIRONMENT": "development",
        "ICHECK_CONTROL_PLANE_AUTH_MODE": "disabled",
        "ICHECK_AGENT_REGISTRATION_TOKEN": registration_token,
        "ICHECK_AI_ALLOWED_HOSTS": "127.0.0.1",
    })
    _assert_runtime_configuration(database_url, registration_token)
    gateway = _ModelGateway()
    gateway.start()
    control_plane = None
    control_thread = None
    listener = None
    first = None
    started = time.monotonic()
    try:
        control_plane, control_thread, listener, port = _start_control_plane()
        device_id, investigation_id, execution_id = _create_investigation(port, gateway.port)
        gateway.device_id = device_id
        worker_env = _worker_environment(registration_token)
        first = subprocess.Popen(
            _worker_command(port, "agent-cancellation-in-flight"),
            cwd="/tmp",
            env=worker_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if not gateway.second_request.wait(45):
            if first.poll() is None:
                first.terminate()
            _, worker_error = first.communicate(timeout=10)
            digest = hashlib.sha256(worker_error.encode("utf-8")).hexdigest()
            raise RuntimeError(
                "Worker did not reach its in-flight second model request; "
                f"requests={gateway.requests}, exit={first.returncode}, stderr_sha256={digest}"
            )
        if first.poll() is not None:
            raise RuntimeError("Worker exited before in-flight cancellation")
        cancelled = _api_request(
            port, "POST", f"/api/v1/agent/executions/{execution_id}/cancel",
            {"actor": "acceptance.operator", "reason": "Operator cancelled in-flight reasoning"},
        )
        cancellation_was_pending = (
            cancelled["status"] == "running"
            and cancelled["cancellation_requested_at"] is not None
        )
        if kill_after_cancel:
            first.kill()
            first.wait(timeout=10)
            if first.returncode != -signal.SIGKILL:
                raise RuntimeError("Cancelled Worker did not die from SIGKILL")
            gateway.release_second.set()
            _wait_for_expired_lease(execution_id)
            pending = _api_request(
                port, "GET", f"/api/v1/agent/executions/{execution_id}"
            )
            pending_until_expiry = (
                pending["status"] == "running"
                and pending["cancellation_requested_at"] is not None
                and pending["attempt_count"] == 1
            )
        else:
            gateway.release_second.set()
            _, first_error = first.communicate(timeout=45)
            if first.returncode:
                digest = hashlib.sha256(first_error.encode("utf-8")).hexdigest()
                raise RuntimeError(f"Cancelled Worker failed; stderr_sha256={digest}")
            pending_until_expiry = False
        before_replacement = (
            None if kill_after_cancel
            else _result(execution_id, investigation_id, device_id)
        )
        replacement = subprocess.run(
            _worker_command(port, "agent-cancellation-after-terminal"),
            cwd="/tmp",
            env=worker_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if replacement.returncode:
            digest = hashlib.sha256(replacement.stderr.encode("utf-8")).hexdigest()
            raise RuntimeError(f"Idle replacement Worker failed; stderr_sha256={digest}")
        result = _result(
            execution_id, investigation_id, device_id,
            terminal_event=(
                "execution.reconciled" if kill_after_cancel else "execution.completed"
            ),
        )
        if kill_after_cancel:
            observer = subprocess.run(
                _worker_command(port, "agent-cancellation-after-reconciliation"),
                cwd="/tmp",
                env=worker_env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if observer.returncode:
                digest = hashlib.sha256(observer.stderr.encode("utf-8")).hexdigest()
                raise RuntimeError(f"Observer Worker failed; stderr_sha256={digest}")
            after_observer = _result(
                execution_id, investigation_id, device_id,
                terminal_event="execution.reconciled",
            )
        else:
            observer = None
            after_observer = None
        gates = {
            "cancel_accepted_while_model_request_in_flight": cancellation_was_pending,
            (
                "first_worker_sigkill" if kill_after_cancel
                else "first_worker_exited_cleanly"
            ): (
                first.returncode == -signal.SIGKILL if kill_after_cancel
                else first.returncode == 0
            ),
            "replacement_worker_exited_cleanly": replacement.returncode == 0,
            "terminal_state_not_reclaimed": (
                after_observer == result if kill_after_cancel
                else before_replacement == result
            ),
            "model_called_only_for_original_two_steps": gateway.requests == 2,
            **result.pop("gates"),
        }
        if kill_after_cancel:
            gates.update({
                "pending_cancel_survived_worker_loss_and_lease_expiry": pending_until_expiry,
                "observer_worker_exited_cleanly": observer.returncode == 0,
                "reconciled_without_worker_terminal_ack": (
                    "execution.reconciled" in result["event_types"]
                    and "execution.completed" not in result["event_types"]
                ),
            })
            after_observer.pop("gates")
        else:
            before_replacement.pop("gates")
        return {
            "format_version": REPORT_FORMAT,
            "scenario": (
                "cancel_then_worker_sigkill" if kill_after_cancel
                else "cancel_then_worker_ack"
            ),
            "database_backend": "postgresql",
            "database_name": database_name,
            "runtime_role_non_owner_non_bypass": True,
            "control_plane_transport": "loopback_http",
            "model_gateway": "controlled_loopback_http",
            "worker_database_credentials": False,
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "model_request_count": gateway.requests,
            "result": result,
            "gates": gates,
            "passed": all(gates.values()),
        }
    finally:
        gateway.release_second.set()
        if first is not None and first.poll() is None:
            first.kill()
            first.wait(timeout=10)
        if control_plane is not None:
            control_plane.should_exit = True
            control_thread.join(timeout=10)
        if listener is not None:
            listener.close()
        gateway.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-dedicated-database", action="store_true")
    parser.add_argument("--kill-after-cancel", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    database_url = os.environ.get(DATABASE_URL_ENV)
    if not database_url:
        parser.error(f"{DATABASE_URL_ENV} is required; no application fallback exists")
    if not args.acknowledge_dedicated_database:
        parser.error("--acknowledge-dedicated-database is required")
    try:
        report = run_agent_cancellation_test(
            database_url, kill_after_cancel=args.kill_after_cancel
        )
    except Exception as exc:
        parser.exit(2, f"agent cancellation test failed: {type(exc).__name__}\n")
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
