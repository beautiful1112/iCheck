"""Bound and revoke built-in Collector adapter I/O in a disposable process."""

from __future__ import annotations

import ctypes
import json
import multiprocessing
import os
import signal
import sys
import threading
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from time import monotonic
from typing import Any, Callable


MAX_ADAPTER_RESULT_BYTES = 32_000_000
MAX_ADAPTER_ERROR_CHARS = 10_000
ADMISSION_POLL_SECONDS = 2.0
MAX_ADMISSION_REQUEST_SECONDS = 5.0
PROCESS_START_SECONDS = 10.0

ISOLATED_ADAPTERS = frozenset({
    "http_json",
    "http_json_sandbox",
    "psrp_cim",
    "snmp_exporter",
    "snmp_topology",
    "ssh_command_sandbox",
    "windows_exporter",
})


class AdapterExecutionRevoked(RuntimeError):
    pass


def _as_utc(value: str | datetime) -> datetime:
    parsed = (
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        if isinstance(value, str) else value
    )
    if parsed.tzinfo is None:
        raise ValueError("Collector execution deadline must include a time zone")
    return parsed.astimezone(UTC)


def _wall_budget(assignment: dict[str, Any], adapter_type: str) -> float:
    configuration = {
        **(assignment.get("defaults") or {}),
        **(assignment.get("configuration") or {}),
    }
    default = 30 if adapter_type == "psrp_cim" else 10 if adapter_type.startswith("http_json") else 15
    timeout = int(configuration.get("timeout_seconds", default))
    if not 1 <= timeout <= 120:
        raise ValueError("Collector adapter timeout must be between 1 and 120 seconds")
    operations = configuration.get("operations")
    calls = min(len(operations), 8) if adapter_type == "psrp_cim" and isinstance(operations, list) else 1
    sandbox = assignment.get("_runtime", {}).get("sandbox_executor")
    sandbox_seconds = int(getattr(sandbox, "timeout_seconds", 0)) if adapter_type in {"http_json_sandbox", "ssh_command_sandbox"} else 0
    return float(timeout * max(1, calls) + max(0, sandbox_seconds) + 5)


def _bind_child_lifetime(parent_pid: int) -> None:
    if os.name == "posix":
        os.setsid()
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "Unable to bind adapter child to Worker lifetime")
        if os.getppid() != parent_pid:
            os._exit(1)


def _adapter_child(
    sender: Connection, parent_pid: int, adapter_type: str,
    assignment: dict[str, Any],
) -> None:
    try:
        _bind_child_lifetime(parent_pid)
        sender.send_bytes(b"ready")
        from .collector_worker import ADAPTERS

        try:
            envelopes = ADAPTERS[adapter_type](assignment)
            packet = {"status": "ok", "envelopes": envelopes}
        except Exception as exc:
            packet = {
                "status": "error",
                "error": str(exc)[:MAX_ADAPTER_ERROR_CHARS],
            }
        encoded = json.dumps(packet, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_ADAPTER_RESULT_BYTES:
            encoded = b'{"status":"error","error":"Collector adapter result exceeded process boundary"}'
        sender.send_bytes(encoded)
    finally:
        sender.close()


def _terminate_process_group(process: multiprocessing.Process) -> None:
    if not process.is_alive():
        process.join(timeout=0)
        return
    if os.name == "posix":
        try:
            if os.getpgid(process.pid) == process.pid:
                os.killpg(process.pid, signal.SIGTERM)
        except OSError:
            pass
    if process.is_alive():
        process.terminate()
    process.join(timeout=0.5)
    if process.is_alive():
        if os.name == "posix":
            try:
                if os.getpgid(process.pid) == process.pid:
                    os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        process.kill()
        process.join(timeout=1)


def run_supervised_adapter(
    assignment: dict[str, Any], adapter_type: str,
    *, check_admission: Callable[[float], None],
    credential_expires_at: datetime | None = None,
) -> list[dict[str, Any]]:
    """Re-admit during I/O; kill the adapter tree on denial or wall deadline."""
    if adapter_type not in ISOLATED_ADAPTERS:
        raise ValueError("Only built-in Collector adapters can run in isolation")
    lease_expiry = _as_utc(assignment["lease_expires_at"])
    seconds_left = (lease_expiry - datetime.now(UTC)).total_seconds() - 3
    if credential_expires_at is not None:
        seconds_left = min(
            seconds_left,
            (_as_utc(credential_expires_at) - datetime.now(UTC)).total_seconds() - 1,
        )
    budget = min(seconds_left, _wall_budget(assignment, adapter_type))
    if budget <= 0:
        raise AdapterExecutionRevoked("Collector execution deadline has passed")
    deadline = monotonic() + budget

    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_adapter_child,
        args=(sender, os.getpid(), adapter_type, assignment),
        name=f"icheck-adapter-{adapter_type}",
        daemon=False,
    )
    try:
        process.start()
    except Exception:
        receiver.close()
        sender.close()
        raise
    sender.close()
    termination_lock = threading.Lock()
    deadline_expired = threading.Event()
    finished = False

    def stop_at_deadline() -> None:
        with termination_lock:
            if not finished:
                deadline_expired.set()
                _terminate_process_group(process)

    watchdog = threading.Timer(
        max(0, deadline - monotonic()), stop_at_deadline,
    )
    watchdog.daemon = True
    watchdog.start()
    try:
        if not receiver.poll(min(PROCESS_START_SECONDS, max(0, deadline - monotonic()))):
            raise AdapterExecutionRevoked("Collector adapter process did not start in time")
        try:
            ready = receiver.recv_bytes(32)
        except EOFError as exc:
            if deadline_expired.is_set():
                raise AdapterExecutionRevoked("Collector adapter wall deadline passed") from exc
            raise RuntimeError("Collector adapter process exited before isolation") from exc
        if ready != b"ready":
            raise AdapterExecutionRevoked("Collector adapter process did not establish isolation")
        while True:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise AdapterExecutionRevoked("Collector adapter wall deadline passed")
            if receiver.poll(min(ADMISSION_POLL_SECONDS, remaining)):
                try:
                    encoded = receiver.recv_bytes(MAX_ADAPTER_RESULT_BYTES)
                except EOFError as exc:
                    if deadline_expired.is_set():
                        raise AdapterExecutionRevoked("Collector adapter wall deadline passed") from exc
                    raise RuntimeError("Collector adapter process exited without a result") from exc
                packet = json.loads(encoded)
                if packet.get("status") == "error":
                    raise RuntimeError(packet.get("error", "Collector adapter failed"))
                if packet.get("status") != "ok" or not isinstance(packet.get("envelopes"), list):
                    raise RuntimeError("Collector adapter returned an invalid result")
                return packet["envelopes"]
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise AdapterExecutionRevoked("Collector adapter wall deadline passed")
            try:
                check_admission(min(MAX_ADMISSION_REQUEST_SECONDS, remaining))
            except Exception as exc:
                raise AdapterExecutionRevoked("Collector execution admission was lost during adapter I/O") from exc
    finally:
        receiver.close()
        with termination_lock:
            finished = True
            watchdog.cancel()
            _terminate_process_group(process)
