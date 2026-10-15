"""Private PostgreSQL acceptance for a lost Agent completion HTTP response.

Requires an empty, migrated icheck_agent_recovery_* database and an explicit
acknowledgement. All HTTP services bind to loopback. The fault proxy forwards
the first completion request, consumes the committed success response, and
closes the Worker connection without sending that response.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import secrets
import socket
import ssl
import stat
import subprocess
import tempfile
import time
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import make_url, select

from .agent_worker_recovery_test import (
    _ModelGateway,
    _create_investigation,
    _start_control_plane,
    _verify_dedicated_database,
    _worker_command,
    _worker_environment,
)


DATABASE_URL_ENV = "ICHECK_AGENT_COMPLETION_LOSS_DATABASE_URL"
REPORT_FORMAT = "icheck.agent-worker-completion-loss-report/v1"
MAX_PROXY_BODY_BYTES = 32_000_000
HOP_HEADERS = {
    "connection", "content-length", "host", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "transfer-encoding", "upgrade", "forwarded", "x-forwarded-for",
    "x-forwarded-host", "x-forwarded-proto", "x-real-ip",
}


@dataclass(frozen=True)
class _LocalMTLSMaterial:
    ca_file: Path
    server_cert_file: Path
    server_key_file: Path
    worker_cert_file: Path
    worker_key_file: Path
    worker_fingerprint_sha256: str


def _local_mtls_material(directory: Path) -> _LocalMTLSMaterial:
    """Issue short-lived, acceptance-only certificates into a private directory."""
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "iCheck acceptance Worker CA")
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def issue(name: str, *, server: bool) -> tuple[Path, Path, x509.Certificate]:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH if server
                    else ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=False,
            )
        )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
                ]),
                critical=False,
            )
        certificate = builder.sign(ca_key, hashes.SHA256())
        stem = "server" if server else "worker"
        cert_file = directory / f"{stem}.pem"
        key_file = directory / f"{stem}.key"
        cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        key_file.chmod(0o600)
        return cert_file, key_file, certificate

    ca_file = directory / "ca.pem"
    ca_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    server_cert, server_key, _ = issue("icheck-acceptance-proxy", server=True)
    worker_cert, worker_key, worker_identity = issue(
        "icheck-acceptance-agent-worker", server=False
    )
    return _LocalMTLSMaterial(
        ca_file=ca_file,
        server_cert_file=server_cert,
        server_key_file=server_key,
        worker_cert_file=worker_cert,
        worker_key_file=worker_key,
        worker_fingerprint_sha256=worker_identity.fingerprint(hashes.SHA256()).hex(),
    )


def _local_mtls_context(material: _LocalMTLSMaterial) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=str(material.server_cert_file),
        keyfile=str(material.server_key_file),
    )
    context.load_verify_locations(cafile=str(material.ca_file))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _missing_client_certificate_rejected(port: int, ca_file: Path) -> bool:
    context = ssl.create_default_context(cafile=str(ca_file))
    connection = http.client.HTTPSConnection(
        "127.0.0.1", port, context=context, timeout=5
    )
    try:
        connection.request("GET", "/api/v1/agent/workers/nonexistent")
        connection.getresponse()
        return False
    except (ssl.SSLError, ConnectionError, http.client.HTTPException):
        return True
    finally:
        connection.close()


class _CompletionLossProxy:
    def __init__(
        self,
        upstream_port: int,
        *,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self.completion_request_hashes: list[str] = []
        self.completion_upstream_statuses: list[int] = []
        self.peer_fingerprints: list[str] = []
        self.tls_versions: list[str] = []
        self.dropped_responses = 0
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:
                pass

            def do_GET(self) -> None:
                self._forward()

            def do_POST(self) -> None:
                self._forward()

            def _forward(self) -> None:
                if not self.path.startswith("/") or self.path.startswith("//"):
                    self.send_error(400)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    self.send_error(400)
                    return
                if length < 0 or length > MAX_PROXY_BODY_BYTES:
                    self.send_error(413)
                    return
                body = self.rfile.read(length) if length else None
                headers = {
                    key: value for key, value in self.headers.items()
                    if key.lower() not in HOP_HEADERS
                    and not key.lower().startswith("x-icheck-client-cert-")
                }
                if tls_context is not None:
                    peer_der = self.connection.getpeercert(binary_form=True)
                    if not peer_der:
                        self.send_error(401)
                        return
                    certificate = x509.load_der_x509_certificate(peer_der)
                    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
                    headers.update({
                        "X-iCheck-Client-Cert-Verified": "SUCCESS",
                        "X-iCheck-Client-Cert-SHA256": fingerprint,
                        "X-iCheck-Client-Cert-Subject": (
                            certificate.subject.rfc4514_string()
                        ),
                        "X-iCheck-Client-Cert-Serial": (
                            str(certificate.serial_number)
                        ),
                        "X-iCheck-Client-Cert-Not-After": (
                            certificate.not_valid_after_utc.isoformat()
                        ),
                    })
                    with proxy._lock:
                        proxy.peer_fingerprints.append(fingerprint)
                        proxy.tls_versions.append(self.connection.version())
                upstream = http.client.HTTPConnection(
                    "127.0.0.1", upstream_port, timeout=35
                )
                try:
                    upstream.request(self.command, self.path, body, headers)
                    response = upstream.getresponse()
                    response_body = response.read(MAX_PROXY_BODY_BYTES + 1)
                    if len(response_body) > MAX_PROXY_BODY_BYTES:
                        self.send_error(502)
                        return
                    is_completion = (
                        self.command == "POST"
                        and self.path.startswith("/api/v1/agent/executions/")
                        and self.path.endswith("/complete")
                    )
                    drop = False
                    if is_completion:
                        request_hash = hashlib.sha256(body or b"").hexdigest()
                        with proxy._lock:
                            proxy.completion_request_hashes.append(request_hash)
                            proxy.completion_upstream_statuses.append(response.status)
                            if response.status == 200 and proxy.dropped_responses == 0:
                                proxy.dropped_responses = 1
                                drop = True
                    if drop:
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in HOP_HEADERS:
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(response_body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if response_body:
                        self.wfile.write(response_body)
                    self.close_connection = True
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                except (OSError, http.client.HTTPException):
                    try:
                        self.send_error(502)
                    except OSError:
                        pass
                finally:
                    upstream.close()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        if tls_context is not None:
            self.server.socket = tls_context.wrap_socket(
                self.server.socket, server_side=True
            )
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _assert_runtime_configuration(
    database_url: str,
    registration_token: str,
    *,
    local_mtls: bool,
    owner_managed_checkpoints: bool,
) -> None:
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
        or settings.worker_mtls_mode != ("required" if local_mtls else "disabled")
        or settings.effective_checkpoint_setup_mode != (
            "verify" if owner_managed_checkpoints else "automatic"
        )
    ):
        raise ValueError(
            "Agent completion-loss acceptance requires a fresh process bound "
            "to the explicit probe database and registration token"
        )


def _result(
    execution_id: str,
    investigation_id: str,
    device_id: str,
    *,
    expected_worker_fingerprint: str | None = None,
) -> dict[str, Any]:
    from .database import (
        DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal,
        set_session_namespace,
    )
    from .models import (
        AgentExecution, AgentExecutionEvent, AgentWorker, AuditEvent, Investigation,
        InvestigationCheckpoint, InvestigationEvidence, InvestigationToolCall,
    )

    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        execution = db.get(AgentExecution, execution_id)
        worker = (
            db.get(AgentWorker, execution.completion_worker_id)
            if execution is not None and execution.completion_worker_id is not None
            else None
        )
        investigation = db.get(Investigation, investigation_id)
        events = list(db.scalars(
            select(AgentExecutionEvent)
            .where(AgentExecutionEvent.execution_id == execution_id)
            .order_by(AgentExecutionEvent.sequence)
        ).all())
        audits = list(db.scalars(
            select(AuditEvent).where(
                AuditEvent.entity_type == "agent_execution",
                AuditEvent.entity_id == execution_id,
                AuditEvent.event_type == "agent.execution.completed",
            )
        ).all())
        calls = list(db.scalars(
            select(InvestigationToolCall).where(
                InvestigationToolCall.investigation_id == investigation_id
            )
        ).all())
        evidence = list(db.scalars(
            select(InvestigationEvidence).where(
                InvestigationEvidence.investigation_id == investigation_id
            )
        ).all())
        checkpoints = list(db.scalars(
            select(InvestigationCheckpoint)
            .where(InvestigationCheckpoint.investigation_id == investigation_id)
            .order_by(InvestigationCheckpoint.sequence)
        ).all())
        event_types = [item.event_type for item in events]
        gates = {
            "execution_succeeded_once": (
                execution is not None and execution.status.value == "succeeded"
                and execution.attempt_count == 1
            ),
            "investigation_completed": (
                investigation is not None and investigation.status == "completed"
            ),
            "one_completion_event": event_types.count("execution.completed") == 1,
            "one_completion_audit": len(audits) == 1,
            "bound_receipt_persisted": (
                execution is not None
                and execution.worker_id is None
                and execution.lease_token_hash is None
                and execution.completion_worker_id is not None
                and execution.completion_token_hash is not None
                and execution.completion_request_hash is not None
            ),
            "tool_not_replayed": len(calls) == 1 and calls[0].status == "succeeded",
            "device_evidence_preserved": (
                len(evidence) == 1 and evidence[0].evidence_id == device_id
            ),
            "product_checkpoints_single": (
                [item.node for item in checkpoints]
                == ["start", "reason", "tools", "reason"]
            ),
        }
        if expected_worker_fingerprint is not None:
            gates["worker_bound_to_verified_client_certificate"] = (
                worker is not None
                and worker.mtls_fingerprint_sha256 == expected_worker_fingerprint
            )
        return {
            "execution_status": execution.status.value if execution else None,
            "investigation_status": investigation.status if investigation else None,
            "attempts": execution.attempt_count if execution else None,
            "event_types": event_types,
            "checkpoint_nodes": [item.node for item in checkpoints],
            "tool_call_count": len(calls),
            "evidence_count": len(evidence),
            "completion_audit_count": len(audits),
            "worker_mtls_fingerprint_sha256": (
                worker.mtls_fingerprint_sha256 if worker is not None else None
            ),
            "gates": gates,
        }


def run_agent_completion_loss_test(
    database_url: str,
    *,
    local_mtls: bool = False,
    owner_managed_checkpoints: bool = False,
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
        "ICHECK_WORKER_MTLS_MODE": "required" if local_mtls else "disabled",
        "ICHECK_WORKER_MTLS_TRUSTED_PROXIES": "127.0.0.1/32",
        "ICHECK_CHECKPOINT_SETUP_MODE": (
            "verify" if owner_managed_checkpoints else "automatic"
        ),
    })
    _assert_runtime_configuration(
        database_url,
        registration_token,
        local_mtls=local_mtls,
        owner_managed_checkpoints=owner_managed_checkpoints,
    )
    checkpoint_schema_report = None
    if owner_managed_checkpoints:
        from .checkpoint_schema import verify_checkpoint_schema

        checkpoint_schema_report = verify_checkpoint_schema(database_url)
    gateway = _ModelGateway()
    gateway.start()
    control_plane = None
    control_thread = None
    listener = None
    proxy = None
    temporary = None
    material = None
    missing_certificate_rejected = None
    started = time.monotonic()
    try:
        if local_mtls:
            temporary = tempfile.TemporaryDirectory(
                prefix="icheck-agent-mtls-", dir="/tmp"
            )
            material = _local_mtls_material(Path(temporary.name))
        control_plane, control_thread, listener, port = _start_control_plane()
        device_id, investigation_id, execution_id = _create_investigation(
            port, gateway.port
        )
        gateway.device_id = device_id
        gateway.release_second.set()
        proxy = _CompletionLossProxy(
            port,
            tls_context=_local_mtls_context(material) if material else None,
        )
        proxy.start()
        if material is not None:
            missing_certificate_rejected = _missing_client_certificate_rejected(
                proxy.port, material.ca_file
            )
        command = _worker_command(proxy.port, "agent-completion-response-loss")
        if material is not None:
            command[command.index("--control-plane") + 1] = (
                f"https://127.0.0.1:{proxy.port}"
            )
            command.extend([
                "--control-plane-tls-ca-file", str(material.ca_file),
                "--control-plane-tls-cert-file", str(material.worker_cert_file),
                "--control-plane-tls-key-file", str(material.worker_key_file),
            ])
        worker = subprocess.run(
            command,
            cwd="/tmp",
            env=_worker_environment(registration_token),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        result = _result(
            execution_id, investigation_id, device_id,
            expected_worker_fingerprint=(
                material.worker_fingerprint_sha256 if material else None
            ),
        )
        gates = {
            "worker_exited_cleanly": worker.returncode == 0,
            "one_response_dropped_after_commit": proxy.dropped_responses == 1,
            "two_identical_completion_posts": (
                len(proxy.completion_request_hashes) == 2
                and len(set(proxy.completion_request_hashes)) == 1
            ),
            "both_completion_posts_accepted": (
                proxy.completion_upstream_statuses == [200, 200]
            ),
            "model_did_not_replay": gateway.requests == 2,
            **result.pop("gates"),
        }
        if material is not None:
            gates["missing_client_certificate_rejected"] = (
                missing_certificate_rejected is True
            )
            gates["proxy_used_verified_worker_certificate"] = (
                len(proxy.peer_fingerprints) > 0
                and set(proxy.peer_fingerprints)
                == {material.worker_fingerprint_sha256}
            )
            gates["tls_version_at_least_1_2"] = (
                len(proxy.tls_versions) > 0
                and set(proxy.tls_versions) <= {"TLSv1.2", "TLSv1.3"}
            )
            gates["worker_key_private_permissions"] = (
                stat.S_IMODE(material.worker_key_file.stat().st_mode) == 0o600
            )
        if checkpoint_schema_report is not None:
            gates["checkpoint_runtime_has_no_schema_create"] = (
                checkpoint_schema_report["runtime_schema_create"] is False
            )
            gates["checkpoint_migrations_read_only"] = (
                checkpoint_schema_report["runtime_migration_history_write"] is False
            )
            gates["checkpoint_namespace_rls"] = (
                checkpoint_schema_report["namespace_rls"] is True
            )
        return {
            "format_version": REPORT_FORMAT,
            "database_backend": "postgresql",
            "database_name": database_name,
            "runtime_role_non_owner_non_bypass": True,
            "control_plane_transport": (
                "loopback_https_mtls_via_fault_proxy"
                if material else "loopback_http_via_fault_proxy"
            ),
            "worker_mtls_required": material is not None,
            "checkpoint_setup_mode": (
                "verify" if owner_managed_checkpoints else "automatic"
            ),
            "checkpoint_schema": checkpoint_schema_report,
            "missing_client_certificate_rejected": missing_certificate_rejected,
            "tls_versions": sorted(set(proxy.tls_versions)),
            "model_gateway": "controlled_loopback_http",
            "worker_database_credentials": False,
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "worker_exit_code": worker.returncode,
            "worker_stderr_sha256": hashlib.sha256(
                worker.stderr.encode("utf-8")
            ).hexdigest(),
            "completion_request_hashes": proxy.completion_request_hashes,
            "completion_upstream_statuses": proxy.completion_upstream_statuses,
            "dropped_completion_responses": proxy.dropped_responses,
            "model_request_count": gateway.requests,
            "result": result,
            "gates": gates,
            "passed": all(gates.values()),
        }
    finally:
        gateway.release_second.set()
        if proxy is not None:
            proxy.stop()
        if control_plane is not None:
            control_plane.should_exit = True
            control_thread.join(timeout=10)
        if listener is not None:
            listener.close()
        gateway.stop()
        if temporary is not None:
            temporary.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-dedicated-database", action="store_true")
    parser.add_argument(
        "--local-mtls",
        action="store_true",
        help="Use an ephemeral local CA and require the Worker client certificate",
    )
    parser.add_argument(
        "--owner-managed-checkpoints",
        action="store_true",
        help="Require preprovisioned LangGraph tables and no runtime schema CREATE",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    database_url = os.environ.get(DATABASE_URL_ENV)
    if not database_url:
        parser.error(f"{DATABASE_URL_ENV} is required; no application fallback exists")
    if not args.acknowledge_dedicated_database:
        parser.error("--acknowledge-dedicated-database is required")
    try:
        report = run_agent_completion_loss_test(
            database_url,
            local_mtls=args.local_mtls,
            owner_managed_checkpoints=args.owner_managed_checkpoints,
        )
    except Exception as exc:
        detail = str(exc) if isinstance(exc, ValueError) and str(exc).startswith("Agent") else ""
        parser.exit(2, f"agent completion-loss test failed: {type(exc).__name__}{': ' + detail if detail else ''}\n")
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
