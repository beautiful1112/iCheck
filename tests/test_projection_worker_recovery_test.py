import sys

import pytest

from icheck import projection_worker_recovery_test as recovery


def test_probe_does_not_fallback_to_application_database(monkeypatch, capsys):
    monkeypatch.delenv(recovery.DATABASE_URL_ENV, raising=False)
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://application/production")
    monkeypatch.setattr(sys, "argv", ["projection-recovery", "--acknowledge-dedicated-database"])
    with pytest.raises(SystemExit) as exc:
        recovery.main()
    assert exc.value.code == 2
    assert recovery.DATABASE_URL_ENV in capsys.readouterr().err


def test_probe_requires_explicit_acknowledgement(monkeypatch, capsys):
    monkeypatch.setenv(recovery.DATABASE_URL_ENV, "postgresql://private/test")
    monkeypatch.setattr(sys, "argv", ["projection-recovery"])
    with pytest.raises(SystemExit) as exc:
        recovery.main()
    assert exc.value.code == 2
    assert "--acknowledge-dedicated-database" in capsys.readouterr().err


def test_worker_environment_only_receives_scoped_database_credentials(monkeypatch):
    monkeypatch.setenv("ICHECK_SERVER_SECRET_VAULT_TOKEN", "vault-secret")
    monkeypatch.setenv("PGPASSWORD", "postgres-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "cloud-secret")
    env = recovery._worker_environment(
        "postgresql://private/test", "projection-acceptance"
    )
    assert env["ICHECK_DATABASE_URL"] == "postgresql://private/test"
    assert env["ICHECK_TENANT_ID"]
    assert env["ICHECK_REGION_ID"]
    assert env["PGAPPNAME"] == "projection-acceptance"
    assert "ICHECK_SERVER_SECRET_VAULT_TOKEN" not in env
    assert "PGPASSWORD" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env


def test_probe_rejects_non_postgresql_database():
    with pytest.raises(ValueError, match="requires PostgreSQL"):
        recovery._dsn("sqlite:///tmp/local.db")
