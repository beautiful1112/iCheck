from __future__ import annotations

from types import SimpleNamespace

from icheck import workflow_dispatch_worker
from icheck.worker_namespace import WorkerNamespace


class _SessionContext:
    def __init__(self, db: object) -> None:
        self.db = db

    def __enter__(self) -> object:
        return self.db

    def __exit__(self, *_args: object) -> None:
        return None


def test_dispatch_once_binds_namespace_and_runs_each_outbox(monkeypatch):
    db = object()
    namespace = WorkerNamespace(
        tenant_id="00000000-0000-0000-0000-000000000001",
        region_id="00000000-0000-0000-0000-000000000002",
    )
    calls: list[tuple[str, object, object]] = []

    monkeypatch.setattr(
        workflow_dispatch_worker,
        "SessionLocal",
        lambda: _SessionContext(db),
    )
    monkeypatch.setattr(
        workflow_dispatch_worker,
        "bind_worker_namespace",
        lambda session, bound: calls.append(("bind", session, bound)),
    )
    monkeypatch.setattr(
        workflow_dispatch_worker,
        "enqueue_due_workflow_schedules",
        lambda session, *, limit: (
            calls.append(("enqueue", session, limit)) or 2
        ),
    )
    monkeypatch.setattr(
        workflow_dispatch_worker,
        "dispatch_workflow_schedule_events",
        lambda session, *, limit: (
            calls.append(("schedule", session, limit)) or 3
        ),
    )
    monkeypatch.setattr(
        workflow_dispatch_worker,
        "dispatch_workflow_trigger_events",
        lambda session, *, limit: (
            calls.append(("trigger", session, limit)) or 5
        ),
    )
    monkeypatch.setattr(
        workflow_dispatch_worker,
        "dispatch_situation_integration_events",
        lambda session, *, limit: (
            calls.append(("situation", session, limit)) or 7
        ),
    )

    monkeypatch.setattr(workflow_dispatch_worker, "dispatch_alert_investigations",
        lambda session, *, limit: calls.append(("automatic", session, limit)) or 11)
    assert workflow_dispatch_worker.dispatch_once(
        batch_size=20,
        namespace=namespace,
    ) == 28
    assert calls == [
        ("bind", db, namespace),
        ("enqueue", db, 100),
        ("schedule", db, 20),
        ("trigger", db, 20),
        ("situation", db, 20),
        ("automatic", db, 20),
    ]


def test_dispatch_worker_argument_bounds():
    parser = workflow_dispatch_worker._parser()
    namespace_args = {
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "region_id": "00000000-0000-0000-0000-000000000002",
    }
    workflow_dispatch_worker._validate_args(
        parser,
        SimpleNamespace(batch_size=100, poll_seconds=60, **namespace_args),
    )

    for values in (
        {"batch_size": 0, "poll_seconds": 2},
        {"batch_size": 101, "poll_seconds": 2},
        {"batch_size": 20, "poll_seconds": 0},
        {"batch_size": 20, "poll_seconds": 61},
    ):
        try:
            workflow_dispatch_worker._validate_args(
                parser,
                SimpleNamespace(**values, **namespace_args),
            )
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError("invalid dispatch-worker arguments were accepted")
