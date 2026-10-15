"""Built-in Collector I/O stops on revocation or a hard wall deadline."""

from __future__ import annotations

import multiprocessing
import select
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import monotonic, sleep

import pytest
from sqlalchemy import select as sql_select

from icheck.collector_adapter_supervisor import (
    AdapterExecutionRevoked,
    run_supervised_adapter,
)
from icheck.collector_worker import ADAPTERS, ControlPlaneHTTPError, run_assignment
from icheck.credentials import DisabledCredentialBroker
from icheck.database import SessionLocal
from icheck.models import CollectionEnvelope, CollectorRun, Device
from icheck.sandbox import HardenedProcessSandboxExecutor
from test_collector_execution_admission import _claimed_device


@contextmanager
def _json_server(*, blocked: bool = False):
    started = threading.Event()
    release = threading.Event()
    disconnected = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            started.set()
            if blocked:
                deadline = monotonic() + 20
                while not release.wait(0.05):
                    try:
                        readable, _, _ = select.select([self.connection], [], [], 0)
                        if readable and self.connection.recv(1, socket.MSG_PEEK) == b"":
                            disconnected.set()
                            return
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        disconnected.set()
                        return
                    if monotonic() >= deadline:
                        return
            body = b'{"asset":"test-host"}'
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/assets", started, disconnected
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _assignment(url: str, *, remaining_seconds: float = 60) -> dict:
    return {
        "lease_expires_at": (
            datetime.now(UTC) + timedelta(seconds=remaining_seconds)
        ).isoformat(),
        "artifact_name": "isolated-test",
        "target": {"url": url},
        "configuration": {"timeout_seconds": 10},
        "output_kinds": ["observation"],
        "_runtime": {
            "http_allowed_hosts": ["127.0.0.1"],
            "lease_seconds": 60,
        },
    }


def _adapter_children() -> list[multiprocessing.Process]:
    return [
        process for process in multiprocessing.active_children()
        if process.name.startswith("icheck-adapter-")
    ]


def test_every_builtin_adapter_requires_supervision():
    from icheck.collector_adapter_supervisor import ISOLATED_ADAPTERS

    assert set(ADAPTERS) == ISOLATED_ADAPTERS


def test_monitoring_preflight_capabilities_do_not_become_collection_adapters():
    from icheck.collector_worker import validate_worker_capabilities
    from icheck.device_preflight_worker import PREFLIGHT_ONLY_ADAPTERS
    approved = ["http_json", "icmp", "ssh", "node_exporter", "cadvisor", "vmware_exporter", "node_exporter"]
    assert validate_worker_capabilities(approved) == approved[:-1]
    assert not PREFLIGHT_ONLY_ADAPTERS.intersection(ADAPTERS)
    for unsupported in ([], ["arbitrary_code"], ["http_metrics"]):
        with pytest.raises(SystemExit):
            validate_worker_capabilities(unsupported)


def test_supervised_http_adapter_returns_normalized_result():
    with _json_server() as (url, started, _disconnected):
        envelopes = run_supervised_adapter(
            _assignment(url), "http_json",
            check_admission=lambda _timeout: None,
        )
    assert started.is_set()
    assert len(envelopes) == 1
    assert envelopes[0]["payload"]["asset"] == "test-host"
    assert _adapter_children() == []


def test_supervised_generated_http_adapter_runs_nested_sandbox():
    with _json_server() as (url, _started, _disconnected):
        assignment = _assignment(url)
        assignment["implementation"] = {
            "runtime": "python_sandbox_v1",
            "adapter": "http_json_sandbox",
            "entrypoint": "transform",
            "source": "def transform(records, configuration):\n return records",
        }
        assignment["_runtime"]["sandbox_executor"] = (
            HardenedProcessSandboxExecutor(python_path=sys.executable)
        )
        envelopes = run_supervised_adapter(
            assignment, "http_json_sandbox",
            check_admission=lambda _timeout: None,
        )
    assert len(envelopes) == 1
    assert envelopes[0]["payload"]["asset"] == "test-host"
    assert _adapter_children() == []


def test_revoked_admission_terminates_blocked_http_adapter():
    with _json_server(blocked=True) as (url, started, disconnected):
        checked = []

        def reject(timeout: float) -> None:
            checked.append(timeout)
            assert started.is_set()
            raise ValueError("target ownership changed")

        began = monotonic()
        with pytest.raises(AdapterExecutionRevoked, match="admission was lost"):
            run_supervised_adapter(
                _assignment(url), "http_json", check_admission=reject,
            )
        assert monotonic() - began < 8
        assert checked and max(checked) <= 5
        assert disconnected.wait(2)
        assert _adapter_children() == []


def test_wall_deadline_terminates_blocked_http_adapter():
    with _json_server(blocked=True) as (url, started, disconnected):
        began = monotonic()
        with pytest.raises(AdapterExecutionRevoked, match="wall deadline"):
            run_supervised_adapter(
                _assignment(url, remaining_seconds=4.5), "http_json",
                check_admission=lambda _timeout: None,
            )
        assert started.is_set()
        assert disconnected.wait(2)
        assert monotonic() - began < 5
        assert _adapter_children() == []


def test_watchdog_stops_io_while_control_plane_check_is_stalled():
    with _json_server(blocked=True) as (url, started, disconnected):
        checked = threading.Event()

        def slow_check(_timeout: float) -> None:
            checked.set()
            sleep(5)

        began = monotonic()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                run_supervised_adapter,
                _assignment(url, remaining_seconds=7), "http_json",
                check_admission=slow_check,
            )
            assert started.wait(5)
            assert checked.wait(5)
            assert disconnected.wait(4), "adapter I/O outlived its independent wall deadline"
            assert monotonic() - began < 6
            assert not future.done(), "the control-plane check did not remain stalled"
            with pytest.raises(AdapterExecutionRevoked, match="wall deadline"):
                future.result(timeout=6)
        assert _adapter_children() == []


def test_worker_aborts_envelopes_when_admission_is_revoked_during_io():
    class RevokingControlPlane:
        def __init__(self):
            self.calls = []
            self.admissions = 0

        def request(self, method, path, payload=None, **kwargs):
            self.calls.append((method, path, payload, kwargs))
            if path.endswith("/admit"):
                self.admissions += 1
                if self.admissions > 1:
                    raise ControlPlaneHTTPError(409, "target ownership changed")
            return {}

    with _json_server(blocked=True) as (url, started, _disconnected):
        client = RevokingControlPlane()
        assignment = {
            **_assignment(url),
            "run_id": "run-isolated-1",
            "deployment_id": "deployment-isolated-1",
            "lease_token": "lease-token-isolated-1",
            "assignment_sha256": "a" * 64,
            "adapter_type": "http_json",
            "_lease_seconds": 60,
        }
        assert run_assignment(
            client, "worker-isolated-1", assignment,
            http_allowed_hosts=["127.0.0.1"],
            exporter_allowed_hosts=[],
            snmp_allowed_targets=[],
            windows_exporter_allowed_hosts=[],
            windows_allowed_targets=[],
            credential_broker=DisabledCredentialBroker(),
        ) is False
        assert started.is_set()
        assert client.admissions >= 2
        assert not any(path.endswith("/envelopes") for _, path, _, _ in client.calls)
        failed = [
            payload for _, path, payload, _ in client.calls
            if path.endswith("/complete")
        ]
        assert len(failed) == 1 and failed[0]["status"] == "failed"
        assert _adapter_children() == []


def test_device_drift_during_supervised_http_io_revokes_socket(client):
    class LiveControlPlane:
        def __init__(self):
            self.calls = []

        def request(self, method, path, payload=None, **_kwargs):
            response = client.request(method, path, json=payload, headers=headers)
            self.calls.append((path, response.status_code))
            if response.status_code >= 400:
                raise ControlPlaneHTTPError(response.status_code, response.text)
            return response.json()

    with _json_server(blocked=True) as (url, started, disconnected):
        device, deployment, assignment, headers = _claimed_device(
            client, target_url=url, management_ip="127.0.0.1",
        )

        def change_device_after_io_starts():
            assert started.wait(8), "The supervised HTTP adapter never started"
            with SessionLocal() as db:
                target = db.get(Device, device["id"])
                target.identity_revision += 1
                db.commit()

        began = monotonic()
        control = LiveControlPlane()
        with ThreadPoolExecutor(max_workers=1) as pool:
            changed = pool.submit(change_device_after_io_starts)
            completed = run_assignment(
                control, "device-supervision-worker", assignment,
                http_allowed_hosts=["127.0.0.1"],
                exporter_allowed_hosts=[],
                snmp_allowed_targets=[],
                windows_exporter_allowed_hosts=[],
                windows_allowed_targets=[],
                credential_broker=DisabledCredentialBroker(),
            )
            changed.result(timeout=8)
        assert completed is False
        assert any(
            path.endswith("/admit") and status == 409
            for path, status in control.calls
        ), f"No mid-I/O admission revocation: {control.calls}"
        assert disconnected.wait(3), f"Revocation left Device adapter I/O open: {control.calls}"
        assert monotonic() - began < 9
        assert _adapter_children() == []
    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        assert run.status.value == "cancelled"
        assert run.stats["cancel_reason"] == "device_target_drift"
        assert run.deployment_id == deployment["id"]
        assert db.scalars(sql_select(CollectionEnvelope).where(
            CollectionEnvelope.run_id == run.id,
        )).all() == []


def test_worker_ingests_successful_isolated_adapter_result():
    class RecordingControlPlane:
        def __init__(self):
            self.calls = []

        def request(self, method, path, payload=None, **kwargs):
            self.calls.append((method, path, payload, kwargs))
            return {}

    with _json_server() as (url, _started, _disconnected):
        client = RecordingControlPlane()
        assignment = {
            **_assignment(url),
            "run_id": "run-isolated-2",
            "deployment_id": "deployment-isolated-2",
            "lease_token": "lease-token-isolated-2",
            "assignment_sha256": "b" * 64,
            "adapter_type": "http_json",
            "_lease_seconds": 60,
        }
        assert run_assignment(
            client, "worker-isolated-2", assignment,
            http_allowed_hosts=["127.0.0.1"],
            exporter_allowed_hosts=[],
            snmp_allowed_targets=[],
            windows_exporter_allowed_hosts=[],
            windows_allowed_targets=[],
            credential_broker=DisabledCredentialBroker(),
        ) is True
    envelopes = [
        payload for _, path, payload, _ in client.calls
        if path.endswith("/envelopes")
    ]
    assert len(envelopes) == 1
    assert envelopes[0]["envelopes"][0]["payload"]["asset"] == "test-host"
    completed = [
        payload for _, path, payload, _ in client.calls
        if path.endswith("/complete")
    ]
    assert len(completed) == 1 and completed[0]["status"] == "succeeded"
    assert _adapter_children() == []
