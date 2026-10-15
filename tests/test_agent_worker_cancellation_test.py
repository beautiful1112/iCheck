import sys

import pytest

from icheck import agent_worker_cancellation_test as cancellation


def test_probe_does_not_fall_back_to_application_database(monkeypatch, capsys):
    monkeypatch.delenv(cancellation.DATABASE_URL_ENV, raising=False)
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://application/production")
    monkeypatch.setattr(
        sys, "argv", ["agent-cancellation-probe", "--acknowledge-dedicated-database"]
    )
    with pytest.raises(SystemExit) as exc:
        cancellation.main()
    assert exc.value.code == 2
    assert cancellation.DATABASE_URL_ENV in capsys.readouterr().err


def test_probe_requires_explicit_acknowledgement(monkeypatch, capsys):
    monkeypatch.setenv(cancellation.DATABASE_URL_ENV, "postgresql://private/test")
    monkeypatch.setattr(sys, "argv", ["agent-cancellation-probe"])
    with pytest.raises(SystemExit) as exc:
        cancellation.main()
    assert exc.value.code == 2
    assert "--acknowledge-dedicated-database" in capsys.readouterr().err


def test_probe_rejects_cached_application_engine(monkeypatch):
    from icheck.config import get_settings
    from icheck.database import engine

    monkeypatch.setenv(
        "ICHECK_DATABASE_URL", "postgresql+psycopg://private@/icheck_agent_recovery_test"
    )
    monkeypatch.setenv("ICHECK_AGENT_REGISTRATION_TOKEN", "registration-secret")
    get_settings.cache_clear()
    try:
        with pytest.raises(ValueError, match="fresh process"):
            cancellation._assert_runtime_configuration(
                str(engine.url), "registration-secret"
            )
    finally:
        get_settings.cache_clear()
