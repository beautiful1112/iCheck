"""Private PostgreSQL acceptance for real Collector Worker process takeover.

Requires a fresh migrated icheck_collector_recovery_* database and an explicit
acknowledgement. The control plane and controlled HTTP target bind to loopback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import select
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

import psycopg


DATABASE_URL_ENV = "ICHECK_COLLECTOR_RECOVERY_DATABASE_URL"
REPORT_FORMAT = "icheck.collector-worker-recovery-report/v1"
FIRST_NAME = "collector-recovery-before-kill"
SECOND_NAME = "collector-recovery-after-kill"


def _dsn(database_url: str) -> str:
    if database_url.startswith("postgresql+psycopg://"):
        return "postgresql://" + database_url.removeprefix("postgresql+psycopg://")
    if database_url.startswith("postgresql://"):
        return database_url
    raise ValueError("Collector recovery requires PostgreSQL")


def _verify_dedicated_database(database_url: str) -> str:
    from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID
    from .scale_test import expected_schema_head

    with psycopg.connect(_dsn(database_url)) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT current_database(), role.rolsuper, role.rolbypassrls,
                          database.datdba = role.oid
                   FROM pg_database AS database
                   JOIN pg_roles AS role ON role.rolname = current_user
                   WHERE database.datname = current_database()"""
            )
            name, superuser, bypass_rls, database_owner = cursor.fetchone()
            if not name.startswith("icheck_collector_recovery_"):
                raise ValueError(
                    "Collector recovery requires an icheck_collector_recovery_ database"
                )
            if superuser or bypass_rls or database_owner:
                raise ValueError("Collector recovery requires a non-owner, non-RLS-bypass role")
            cursor.execute("SELECT version_num FROM alembic_version")
            if cursor.fetchone()[0] != expected_schema_head():
                raise ValueError("Collector recovery requires this checkout's Alembic head")
            cursor.execute("SELECT count(*) FROM tenants")
            if cursor.fetchone()[0] != 1:
                raise ValueError("Collector recovery requires only the migration-seeded tenant")
            cursor.execute("SELECT count(*) FROM regions")
            if cursor.fetchone()[0] != 1:
                raise ValueError("Collector recovery requires only the migration-seeded region")
            cursor.execute(
                "SELECT set_config('icheck.tenant_id', %s, true), "
                "set_config('icheck.region_id', %s, true)",
                (DEFAULT_TENANT_ID, DEFAULT_REGION_ID),
            )
            for table in (
                "artifacts", "devices", "collector_deployments", "collector_runs",
                "collection_envelopes", "knowledge_projections", "endpoints",
            ):
                cursor.execute(f"SELECT count(*) FROM {table}")
                if cursor.fetchone()[0]:
                    raise ValueError("Collector recovery refuses a non-empty database")
    return name


def _assert_runtime_configuration(database_url: str, registration_token: str) -> None:
    """Refuse a caller whose cached app engine/settings point elsewhere."""
    from sqlalchemy import make_url

    from .config import get_settings
    from .database import engine

    settings = get_settings()
    if (
        settings.database_url != database_url
        or engine.url != make_url(database_url)
        or settings.collector_registration_token != registration_token
        or settings.environment != "development"
        or settings.control_plane_auth_mode != "disabled"
        or settings.auto_create_schema
    ):
        raise ValueError(
            "Collector recovery requires a fresh process bound to the explicit "
            "probe database and registration token"
        )


class _ControlledTarget:
    def __init__(self) -> None:
        self.device_id: str | None = None
        self.first_request = threading.Event()
        self.first_disconnect = threading.Event()
        self.release_first = threading.Event()
        self.lock = threading.Lock()
        self.requests = 0
        target = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                return None

            def do_GET(self) -> None:
                if self.path != "/observation":
                    self.send_error(404)
                    return
                with target.lock:
                    target.requests += 1
                    request_number = target.requests
                if request_number == 1:
                    target.first_request.set()
                    deadline = time.monotonic() + 45
                    while not target.release_first.wait(0.05):
                        try:
                            readable, _, _ = select.select(
                                [self.connection], [], [], 0,
                            )
                            if readable and self.connection.recv(
                                1, socket.MSG_PEEK,
                            ) == b"":
                                target.first_disconnect.set()
                                return
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            target.first_disconnect.set()
                            return
                        if time.monotonic() >= deadline:
                            self.send_error(504)
                            return
                if target.device_id is None:
                    self.send_error(503)
                    return
                body = json.dumps({
                    "mac_address": "02:01:02:03:04:05",
                    "ip_address": "10.64.0.25",
                    "source": "arp",
                    "collector_device_id": target.device_id,
                    "interface_name": "Ethernet1/1",
                    "vlan_id": 25,
                    "hostname": "collector-recovery-terminal",
                }).encode("utf-8")
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.release_first.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _seed(target_port: int) -> str:
    from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace
    from .models import (
        Artifact, ArtifactKind, ArtifactVersion, ArtifactVersionStatus,
        CollectorDefinition, CollectorDeployment, CollectorMode, Device,
        EnvelopeKind, utcnow,
    )
    from .projection_schemas import NETWORK_OBSERVATION_V1

    now = utcnow()
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        device = Device(
            name="collector-recovery-switch", kind="switch", site="LAB",
            management_ip="127.0.0.1",
            created_by="acceptance.operator",
        )
        artifact = Artifact(
            name="collector-recovery-http-json", kind=ArtifactKind.COLLECTOR,
            description="Controlled process-loss acceptance fixture",
            owner="acceptance.operator", labels={"acceptance": "collector_recovery"},
        )
        version = ArtifactVersion(
            artifact=artifact, version=1, status=ArtifactVersionStatus.PUBLISHED,
            definition={"purpose": "Collector process-loss acceptance"},
            implementation={"runtime": "http_json"}, tests=[],
            validation_report={"controlled_fixture": True},
            content_hash=hashlib.sha256(b"collector-recovery-http-json-v1").hexdigest(),
            created_by="acceptance.operator", validated_at=now,
            validated_by="acceptance.operator", published_at=now,
            published_by="acceptance.operator",
        )
        db.add_all([device, artifact, version])
        db.flush()
        db.add(CollectorDefinition(
            artifact_version_id=version.id, adapter_type="http_json",
            mode=CollectorMode.POLL, output_kinds=[EnvelopeKind.OBSERVATION.value],
            target_schema={"type": "object"}, config_schema={"type": "object"},
            defaults={},
        ))
        db.add(CollectorDeployment(
            name="collector-recovery-deployment", artifact_version_id=version.id,
            scope_device_id=device.id, scope_site="LAB",
            scope_device_identity_revision=device.identity_revision,
            target_classification="registered_device",
            target={"url": f"http://127.0.0.1:{target_port}/observation"},
            configuration={
                "timeout_seconds": 8,
                "record_type": NETWORK_OBSERVATION_V1,
                "source": "collector-recovery-http-json",
                "subject_field": "mac_address",
                "idempotency_field": "mac_address",
            },
            worker_selector={"site": "LAB"}, schedule_seconds=3600,
            enabled=True, created_by="acceptance.operator", next_run_at=now,
        ))
        db.commit()
        return device.id


def _worker_environment(registration_token: str) -> dict[str, str]:
    from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID

    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR")
        if key in os.environ
    }
    env.update({
        "ICHECK_ENVIRONMENT": "development",
        "ICHECK_CONTROL_PLANE_AUTH_MODE": "disabled",
        "ICHECK_COLLECTOR_REGISTRATION_TOKEN": registration_token,
        "ICHECK_TENANT_ID": DEFAULT_TENANT_ID,
        "ICHECK_REGION_ID": DEFAULT_REGION_ID,
    })
    return env


def _worker_command(port: int, name: str) -> list[str]:
    return [
        sys.executable, "-m", "icheck.collector_worker",
        "--control-plane", f"http://127.0.0.1:{port}",
        "--name", name, "--site", "LAB", "--capability", "http_json",
        "--http-allowed-host", "127.0.0.1", "--lease-seconds", "15",
        "--preflight-timeout-seconds", "2", "--max-preflights", "1",
        "--max-assignments", "1", "--once",
    ]


def _observe_claims() -> tuple[dict[str, Any], dict[str, str], Any]:
    from . import collector_api

    assignments: dict[str, Any] = {}
    tokens: dict[str, str] = {}
    lock = threading.Lock()
    original_register = collector_api.register_worker
    original_claim = collector_api.claim_deployments

    def register(*args: Any, **kwargs: Any) -> Any:
        worker, token = original_register(*args, **kwargs)
        with lock:
            tokens[worker.name] = token
        return worker, token

    def claim(db: Any, worker: Any, payload: Any) -> Any:
        result = original_claim(db, worker, payload)
        if result:
            with lock:
                assignments[worker.name] = result[0]
        return result

    collector_api.register_worker = register
    collector_api.claim_deployments = claim

    def restore() -> None:
        collector_api.register_worker = original_register
        collector_api.claim_deployments = original_claim

    return assignments, tokens, restore


def _wait_for_first(target: _ControlledTarget, first: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if target.first_request.wait(0.1):
            if first.poll() is not None:
                raise RuntimeError("First Collector Worker exited before process kill")
            return
        if first.poll() is not None:
            raise RuntimeError("First Collector Worker exited before target request")
    raise TimeoutError("First Collector Worker never reached its HTTP target")


def _wait_for_expiry() -> None:
    from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace
    from .models import CollectorDeployment
    from sqlalchemy import select

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with SessionLocal() as db:
            set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
            deployment = db.scalar(select(CollectorDeployment))
            if deployment is None or deployment.lease_expires_at is None:
                raise RuntimeError("Collector deployment lost its lease row")
            expiry = deployment.lease_expires_at
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            if expiry < datetime.now(UTC):
                return
        time.sleep(0.2)
    raise TimeoutError("Collector lease did not expire after process loss")


def _stale_request(port: int, token: str, assignment: Any, operation: str) -> bool:
    from .collector_worker import ControlPlaneClient
    from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID

    client = ControlPlaneClient(
        f"http://127.0.0.1:{port}",
        tenant_id=DEFAULT_TENANT_ID,
        region_id=DEFAULT_REGION_ID,
    )
    client.access_token = token
    path = f"/api/v1/collector-runs/{assignment.run_id}/{operation}"
    if operation == "envelopes":
        payload = {
            "lease_token": assignment.lease_token,
            "envelopes": [{
                "kind": "observation",
                "type": "icheck.inventory.network-observation/v1",
                "source": "collector-recovery-stale-attempt",
                "observed_at": datetime.now(UTC).isoformat(),
                "payload": {"mac_address": "02:ff:ff:ff:ff:ff", "ip_address": "10.64.0.99"},
            }],
        }
    else:
        payload = {
            "lease_token": assignment.lease_token,
            "status": "succeeded",
            "stats": {"stale_attempt": True},
        }
    try:
        client.request("POST", path, payload)
    except RuntimeError as exc:
        return "HTTP 409" in str(exc)
    return False


def _project(database_url: str) -> None:
    from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID

    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR")
        if key in os.environ
    }
    env.update({
        "ICHECK_DATABASE_URL": database_url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "ICHECK_ENVIRONMENT": "development",
        "ICHECK_TENANT_ID": DEFAULT_TENANT_ID,
        "ICHECK_REGION_ID": DEFAULT_REGION_ID,
    })
    result = subprocess.run(
        [sys.executable, "-m", "icheck.projection_worker", "--name",
         "collector-recovery-projection", "--once"],
        cwd="/tmp", env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=45, check=False,
    )
    if result.returncode:
        digest = hashlib.sha256(result.stderr.encode("utf-8")).hexdigest()
        raise RuntimeError(f"Projection Worker failed; stderr SHA-256 {digest}")


def _result(first_id: str, second_id: str, target_requests: int) -> dict[str, Any]:
    from sqlalchemy import select
    from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace
    from .models import (
        CollectionEnvelope, CollectorDeployment, CollectorRun, CollectorRunStatus,
        CollectorWorker, Endpoint, IPAddressObservation, KnowledgeProjection,
        KnowledgeProjectionStatus,
    )

    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        workers = db.scalars(select(CollectorWorker)).all()
        runs = db.scalars(select(CollectorRun).order_by(CollectorRun.started_at)).all()
        runs_by_id = {run.id: run for run in runs}
        envelopes = db.scalars(select(CollectionEnvelope)).all()
        projections = db.scalars(select(KnowledgeProjection)).all()
        endpoints = db.scalars(select(Endpoint)).all()
        addresses = db.scalars(select(IPAddressObservation)).all()
        deployment = db.scalar(select(CollectorDeployment))
        gates = {
            "two_distinct_workers": (
                len(workers) == 2
                and first_id in runs_by_id
                and second_id in runs_by_id
                and runs_by_id[first_id].worker_id != runs_by_id[second_id].worker_id
            ),
            "target_requested_twice": target_requests == 2,
            "first_run_cancelled": (
                len(runs) == 2
                and first_id in runs_by_id
                and runs_by_id[first_id].status == CollectorRunStatus.CANCELLED
            ),
            "replacement_run_succeeded": (
                len(runs) == 2
                and second_id in runs_by_id
                and runs_by_id[second_id].status == CollectorRunStatus.SUCCEEDED
            ),
            "single_envelope": (
                len(envelopes) == 1
                and envelopes[0].run_id == second_id
            ),
            "single_projection_succeeded": (
                len(projections) == 1
                and projections[0].status == KnowledgeProjectionStatus.SUCCEEDED
            ),
            "single_endpoint": len(endpoints) == 1,
            "single_ip_observation": (
                len(addresses) == 1
                and len(endpoints) == 1
                and addresses[0].endpoint_id == endpoints[0].id
            ),
            "lease_released": deployment is not None and deployment.lease_worker_id is None,
        }
        return {
            "run_statuses": [run.status.value for run in runs],
            "worker_count": len(workers),
            "target_request_count": target_requests,
            "envelope_count": len(envelopes),
            "projection_count": len(projections),
            "endpoint_count": len(endpoints),
            "ip_observation_count": len(addresses),
            "gates": gates,
        }


def run_collector_recovery_test(database_url: str) -> dict[str, Any]:
    # config.py caches settings and database.py creates its engine at import.
    # Bind all control-plane settings before the verifier imports either module.
    # This changes process configuration only; the verifier still runs before
    # any fixture or Worker can write to the database.
    registration_token = secrets.token_urlsafe(32)
    os.environ.update({
        "ICHECK_DATABASE_URL": database_url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "ICHECK_ENVIRONMENT": "development",
        "ICHECK_CONTROL_PLANE_AUTH_MODE": "disabled",
        "ICHECK_COLLECTOR_REGISTRATION_TOKEN": registration_token,
    })
    database_name = _verify_dedicated_database(database_url)
    _assert_runtime_configuration(database_url, registration_token)
    from .agent_worker_recovery_test import _start_control_plane

    target = _ControlledTarget()
    target.start()
    control_plane = control_thread = listener = first = None
    restore = None
    started = time.monotonic()
    try:
        target.device_id = _seed(target.port)
        assignments, tokens, restore = _observe_claims()
        control_plane, control_thread, listener, port = _start_control_plane()
        worker_env = _worker_environment(registration_token)
        first = subprocess.Popen(
            _worker_command(port, FIRST_NAME), cwd="/tmp", env=worker_env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True,
        )
        _wait_for_first(target, first)
        first_assignment = assignments.get(FIRST_NAME)
        first_token = tokens.get(FIRST_NAME)
        if first_assignment is None or first_token is None:
            raise RuntimeError("First Collector claim observation was not recorded")
        first.kill()
        first.wait(timeout=10)
        if first.returncode != -signal.SIGKILL:
            raise RuntimeError("First Collector Worker was not killed by SIGKILL")
        first_adapter_io_stopped = target.first_disconnect.wait(5)
        target.release_first.set()
        _wait_for_expiry()
        second = subprocess.run(
            _worker_command(port, SECOND_NAME), cwd="/tmp", env=worker_env,
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=45, check=False,
        )
        if second.returncode:
            digest = hashlib.sha256(second.stderr.encode("utf-8")).hexdigest()
            raise RuntimeError(f"Replacement Collector Worker failed; stderr SHA-256 {digest}")
        second_assignment = assignments.get(SECOND_NAME)
        if second_assignment is None:
            raise RuntimeError("Replacement Collector never claimed the deployment")
        stale_ingest_denied = _stale_request(port, first_token, first_assignment, "envelopes")
        stale_complete_denied = _stale_request(port, first_token, first_assignment, "complete")
        _project(database_url)
        result = _result(
            first_assignment.run_id, second_assignment.run_id, target.requests
        )
        gates = {
            "first_worker_sigkill": first.returncode == -signal.SIGKILL,
            "first_adapter_io_stopped": first_adapter_io_stopped,
            "replacement_worker_exited_cleanly": second.returncode == 0,
            "stale_ingest_denied": stale_ingest_denied,
            "stale_completion_denied": stale_complete_denied,
            **result.pop("gates"),
        }
        return {
            "format_version": REPORT_FORMAT,
            "database_backend": "postgresql",
            "database_name": database_name,
            "runtime_role_non_owner_non_bypass": True,
            "control_plane_transport": "loopback_http",
            "collector_target": "controlled_loopback_http_json",
            "collector_worker_database_credentials": False,
            "lease_expiry": "natural_15_second_lease",
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "result": result,
            "gates": gates,
            "passed": all(gates.values()),
        }
    finally:
        target.release_first.set()
        if first is not None and first.poll() is None:
            first.kill()
            first.wait(timeout=10)
        if control_plane is not None:
            control_plane.should_exit = True
            control_thread.join(timeout=10)
        if listener is not None:
            listener.close()
        if restore is not None:
            restore()
        target.stop()


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
        report = run_collector_recovery_test(database_url)
    except Exception as exc:
        detail = (
            str(exc)
            if isinstance(exc, ValueError) and str(exc).startswith("Collector recovery")
            else ""
        )
        parser.exit(
            2,
            f"collector recovery test failed: {type(exc).__name__}"
            f"{': ' + detail if detail else ''}\n",
        )
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
