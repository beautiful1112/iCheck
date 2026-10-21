import sys
from types import SimpleNamespace

import pytest

from icheck import integration_sync_worker as worker


NAMESPACE = ["--tenant-id", "00000000-0000-0000-0000-000000000001",
             "--region-id", "00000000-0000-0000-0000-000000000002"]


@pytest.mark.parametrize("poll", ["0", "-1", "61", "nan", "inf"])
def test_invalid_poll_interval_never_starts_worker(monkeypatch, poll):
    monkeypatch.setattr(sys, "argv", ["worker", *NAMESPACE, "--poll-seconds=" + poll])
    monkeypatch.setattr(worker, "dispatch_once", lambda *_: pytest.fail("Must not dispatch"))
    with pytest.raises(SystemExit) as error:
        worker.main()
    assert error.value.code == 2


def test_background_worker_requires_postgres_and_explicit_namespace(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["worker", *NAMESPACE, "--once"])
    monkeypatch.setattr(worker, "get_settings", lambda: SimpleNamespace(database_url="sqlite://"))
    with pytest.raises(SystemExit) as error:
        worker.main()
    assert error.value.code == 2
    monkeypatch.setattr(sys, "argv", ["worker", "--once"])
    monkeypatch.delenv("ICHECK_TENANT_ID", raising=False)
    monkeypatch.delenv("ICHECK_REGION_ID", raising=False)
    with pytest.raises(SystemExit):
        worker.main()


def test_once_dispatches_one_bounded_operation_without_sleep(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["worker", *NAMESPACE, "--once"])
    monkeypatch.setattr(worker, "get_settings", lambda: SimpleNamespace(database_url="postgresql+psycopg://fixture"))
    calls = []
    monkeypatch.setattr(worker, "dispatch_once", lambda namespace: calls.append(namespace))
    monkeypatch.setattr(worker.time, "sleep", lambda *_: pytest.fail("Must not sleep in once mode"))
    assert worker.main() == 0
    assert len(calls) == 1 and calls[0].tenant_id == NAMESPACE[1]
