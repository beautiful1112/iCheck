"""Private PostgreSQL acceptance for a real Agent Worker process takeover.

Requires a fresh, migrated icheck_agent_recovery_* database and an explicit
acknowledgement. API and controlled model servers bind only to loopback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.request import ProxyHandler, Request, build_opener

import psycopg


DATABASE_URL_ENV = "ICHECK_AGENT_RECOVERY_DATABASE_URL"
REPORT_FORMAT = "icheck.agent-worker-recovery-report/v1"


def _verify_dedicated_database(database_url: str) -> tuple[str, str]:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    if database_url.startswith("postgresql+psycopg://"):
        dsn = "postgresql://" + database_url.removeprefix("postgresql+psycopg://")
    elif database_url.startswith("postgresql://"):
        dsn = database_url
    else:
        raise ValueError("Agent recovery requires PostgreSQL")
    migration_config = Config()
    migration_config.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[1] / "migrations")
    )
    heads = ScriptDirectory.from_config(migration_config).get_heads()
    if len(heads) != 1:
        raise ValueError("Agent recovery requires one Alembic head")

    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT current_database(), current_user,
                       role.rolsuper, role.rolbypassrls,
                       database.datdba = role.oid
                FROM pg_database AS database
                JOIN pg_roles AS role ON role.rolname = current_user
                WHERE database.datname = current_database()
                """
            )
            name, role_name, superuser, bypass_rls, database_owner = cursor.fetchone()
            if not name.startswith("icheck_agent_recovery_"):
                raise ValueError("Agent recovery requires an icheck_agent_recovery_ database")
            if superuser or bypass_rls or database_owner:
                raise ValueError("Agent recovery requires a non-owner, non-RLS-bypass role")
            cursor.execute("SELECT version_num FROM alembic_version")
            head = cursor.fetchone()[0]
            if head != heads[0]:
                raise ValueError("Agent recovery database is not at this checkout's Alembic head")
            cursor.execute(
                "SELECT count(*) FROM tenants WHERE id = %s AND slug = 'local'",
                ("00000000-0000-0000-0000-000000000001",),
            )
            default_tenant_count = cursor.fetchone()[0]
            cursor.execute(
                "SELECT count(*) FROM regions WHERE id = %s AND code = 'primary'",
                ("00000000-0000-0000-0000-000000000002",),
            )
            default_region_count = cursor.fetchone()[0]
            cursor.execute("SELECT count(*) FROM tenants")
            tenant_count = cursor.fetchone()[0]
            cursor.execute("SELECT count(*) FROM regions")
            region_count = cursor.fetchone()[0]
            if (default_tenant_count, default_region_count, tenant_count, region_count) != (1, 1, 1, 1):
                raise ValueError("Agent recovery requires only migration-seeded namespace rows")
            cursor.execute(
                "SELECT set_config('icheck.tenant_id', %s, true), "
                "set_config('icheck.region_id', %s, true)",
                (
                    "00000000-0000-0000-0000-000000000001",
                    "00000000-0000-0000-0000-000000000002",
                ),
            )
            for table in ("artifacts", "devices", "investigations", "agent_executions"):
                cursor.execute(f"SELECT count(*) FROM {table}")
                if cursor.fetchone()[0]:
                    raise ValueError("Agent recovery refuses a non-empty database")
    return name, role_name


class _ModelGateway:
    def __init__(self) -> None:
        self.device_id: str | None = None
        self.requests = 0
        self.lock = threading.Lock()
        self.second_request = threading.Event()
        self.release_second = threading.Event()

        gateway = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                return None

            def do_POST(self) -> None:
                if self.path != "/v1/chat/completions":
                    self.send_error(404)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 1_000_000:
                        raise ValueError("model request size is invalid")
                    document = json.loads(self.rfile.read(length))
                    prompt = json.loads(document["messages"][1]["content"])
                    with gateway.lock:
                        gateway.requests += 1
                        request_number = gateway.requests
                    if gateway.device_id is None:
                        raise ValueError("test device is not ready")
                    if request_number == 1:
                        if "inventory.get_device" not in {
                            item["name"] for item in prompt["available_tools"]
                        }:
                            raise ValueError("expected Tool is absent from model context")
                        decision = {
                            "action": "continue",
                            "plan": ["Read the device", "Evaluate the persisted evidence"],
                            "tool_requests": [{
                                "tool_name": "inventory.get_device",
                                "arguments": {"device_id": gateway.device_id},
                                "purpose": "Read the bounded device state",
                            }],
                        }
                        tokens = 30
                    else:
                        if request_number == 2:
                            gateway.second_request.set()
                            if not gateway.release_second.wait(45):
                                raise TimeoutError("first Worker was not killed")
                        state = prompt["investigation"]
                        results = state["tool_results"]
                        if (
                            len(results) != 1
                            or results[0]["result"]["id"] != gateway.device_id
                            or not state["evidence_ids"]
                        ):
                            raise ValueError("model did not receive persisted Tool evidence")
                        decision = {
                            "action": "complete",
                            "plan": state["plan"],
                            "confidence": 0.9,
                            "conclusion": "Device identity is known; live health is not yet verified.",
                            "uncertainty": ["No live device probe ran in this acceptance test."],
                        }
                        tokens = 20
                    body = json.dumps({
                        "choices": [{"message": {"content": json.dumps(decision)}}],
                        "usage": {"total_tokens": tokens},
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    return
                except Exception:
                    self.send_error(500)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.release_second.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _start_control_plane() -> tuple[Any, threading.Thread, socket.socket, int]:
    import uvicorn

    from .main import app

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.setblocking(False)
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [listener]},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        raise RuntimeError("private control plane failed to start")
    return server, thread, listener, port


def _api_request(port: int, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method=method,
    )
    with build_opener(ProxyHandler({})).open(request, timeout=15) as response:
        return json.loads(response.read(2_000_000))


def _create_investigation(port: int, model_port: int) -> tuple[str, str, str]:
    from .builtin_agent_tools import ensure_builtin_agent_tools
    from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace

    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        ensure_builtin_agent_tools(db)
    provider = _api_request(port, "POST", "/api/v1/ai/providers", {
        "name": "agent-recovery-controlled-provider",
        "provider_type": "openai_compatible",
        "base_url": f"http://127.0.0.1:{model_port}/v1",
        "auth_type": "none",
        "privacy_tier": "local",
        "data_residency": "local",
        "created_by": "acceptance.operator",
    })
    model = _api_request(port, "POST", "/api/v1/ai/models", {
        "provider_id": provider["id"],
        "display_name": "Controlled recovery reasoner",
        "model_name": "controlled-recovery-reasoner",
        "capabilities": ["chat", "tools", "json_schema"],
        "created_by": "acceptance.operator",
    })
    _api_request(port, "POST", "/api/v1/ai/routes", {
        "purpose": "investigation",
        "primary_model_id": model["id"],
        "max_iterations": 4,
        "max_tool_calls": 4,
        "timeout_seconds": 120,
        "token_budget": 2000,
        "created_by": "acceptance.operator",
    })
    device = _api_request(port, "POST", "/api/v1/assets/devices", {
        "name": "agent-recovery-switch",
        "kind": "switch",
        "management_ip": "192.0.2.88",
        "site": "LAB",
        "connections": [{
            "protocol": "icmp",
            "configuration": {"probe_timeout_seconds": 2},
        }],
        "created_by": "acceptance.operator",
    })
    investigation = _api_request(port, "POST", "/api/v1/agent/investigations", {
        "title": "Agent Worker process takeover",
        "objective": "Inspect the synthetic device without changing it.",
        "scope": {"device_ids": [device["id"]]},
        "route_purpose": "investigation",
        "created_by": "acceptance.operator",
    })
    _api_request(
        port, "POST",
        f"/api/v1/agent/investigations/{investigation['id']}/start",
        {"actor": "acceptance.operator"},
    )
    execution = _api_request(
        port, "GET",
        f"/api/v1/agent/investigations/{investigation['id']}/execution",
    )
    return device["id"], investigation["id"], execution["id"]


def _worker_environment(registration_token: str) -> dict[str, str]:
    from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID

    # Do not hand the Worker the control plane's PostgreSQL, provider, Vault,
    # cloud, or generic process credentials through inherited environment.
    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR")
        if key in os.environ
    }
    env.update({
        "ICHECK_ENVIRONMENT": "development",
        "ICHECK_CONTROL_PLANE_AUTH_MODE": "disabled",
        "ICHECK_AGENT_REGISTRATION_TOKEN": registration_token,
        "ICHECK_TENANT_ID": DEFAULT_TENANT_ID,
        "ICHECK_REGION_ID": DEFAULT_REGION_ID,
    })
    return env


def _worker_command(port: int, name: str) -> list[str]:
    return [
        sys.executable, "-m", "icheck.agent_worker",
        "--control-plane", f"http://127.0.0.1:{port}",
        "--name", name,
        "--capabilities", "openai_compatible",
        "--lease-seconds", "15",
        "--poll-seconds", "0.2",
        "--once",
    ]


def _wait_for_expired_lease(execution_id: str, timeout_seconds: int = 30) -> None:
    from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace
    from .models import AgentExecution

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        with SessionLocal() as db:
            set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
            execution = db.get(AgentExecution, execution_id)
            if execution is None or execution.lease_expires_at is None:
                raise RuntimeError("Agent execution lost its lease row")
            expiry = execution.lease_expires_at
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            if expiry < datetime.now(UTC):
                return
        time.sleep(0.2)
    raise TimeoutError("Agent lease did not expire after process loss")


def _result(execution_id: str, investigation_id: str, device_id: str) -> dict[str, Any]:
    from sqlalchemy import select

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
        gates = {
            "execution_succeeded": execution is not None and execution.status.value == "succeeded",
            "investigation_completed": investigation is not None and investigation.status == "completed",
            "two_distinct_claims": (
                execution is not None
                and execution.attempt_count == 2
                and len({
                    item.payload.get("worker_id")
                    for item in events
                    if item.event_type in {"execution.claimed", "execution.reassigned"}
                }) == 2
            ),
            "reassignment_recorded": any(item.event_type == "execution.reassigned" for item in events),
            "tool_not_replayed": len(calls) == 1 and calls[0].status == "succeeded",
            "device_evidence_preserved": len(evidence) == 1 and evidence[0].evidence_id == device_id,
            "product_checkpoints_continued": (
                [item.node for item in checkpoints] == ["start", "reason", "tools", "reason"]
            ),
        }
        return {
            "execution_status": execution.status.value if execution else None,
            "investigation_status": investigation.status if investigation else None,
            "attempts": execution.attempt_count if execution else None,
            "event_types": [item.event_type for item in events],
            "checkpoint_nodes": [item.node for item in checkpoints],
            "tool_call_count": len(calls),
            "evidence_count": len(evidence),
            "gates": gates,
        }


def run_agent_recovery_test(database_url: str) -> dict[str, Any]:
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
            _worker_command(port, "agent-recovery-before-kill"),
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
            fingerprint = hashlib.sha256(worker_error.encode("utf-8")).hexdigest()
            raise ValueError(
                "Agent recovery first Worker did not reach its second model "
                f"request; requests={gateway.requests}, exit={first.returncode}, "
                f"stderr_sha256={fingerprint}"
            )
        if first.poll() is not None:
            raise RuntimeError("First Worker exited before process kill")
        first.kill()
        first.wait(timeout=10)
        if first.returncode != -signal.SIGKILL:
            raise RuntimeError("First Worker was not killed by SIGKILL")
        gateway.release_second.set()
        _wait_for_expired_lease(execution_id)
        second = subprocess.run(
            _worker_command(port, "agent-recovery-after-kill"),
            cwd="/tmp",
            env=worker_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if second.returncode:
            digest = hashlib.sha256(second.stderr.encode("utf-8")).hexdigest()
            raise RuntimeError(f"Replacement Worker failed; stderr SHA-256 {digest}")
        result = _result(execution_id, investigation_id, device_id)
        gates = {
            "first_worker_sigkill": first.returncode == -signal.SIGKILL,
            "replacement_worker_exited_cleanly": second.returncode == 0,
            **result.pop("gates"),
        }
        return {
            "format_version": REPORT_FORMAT,
            "database_backend": "postgresql",
            "database_name": database_name,
            "runtime_role_non_owner_non_bypass": True,
            "control_plane_transport": "loopback_http",
            "model_gateway": "controlled_loopback_http",
            "worker_database_credentials": False,
            "lease_expiry": "natural_15_second_lease",
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
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    database_url = os.environ.get(DATABASE_URL_ENV)
    if not database_url:
        parser.error(f"{DATABASE_URL_ENV} is required; no application fallback exists")
    if not args.acknowledge_dedicated_database:
        parser.error("--acknowledge-dedicated-database is required")
    try:
        report = run_agent_recovery_test(database_url)
    except Exception as exc:
        detail = str(exc) if isinstance(exc, ValueError) and str(exc).startswith("Agent recovery") else ""
        parser.exit(2, f"agent recovery test failed: {type(exc).__name__}{': ' + detail if detail else ''}\n")
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
