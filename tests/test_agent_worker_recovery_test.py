import sys

import pytest

from icheck import agent_worker_recovery_test as recovery


def test_worker_recovery_probe_has_no_application_database_fallback(monkeypatch, capsys):
    monkeypatch.delenv(recovery.DATABASE_URL_ENV, raising=False)
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://application/production")
    monkeypatch.setattr(
        sys,
        "argv",
        ["agent-recovery-probe", "--acknowledge-dedicated-database"],
    )
    with pytest.raises(SystemExit) as exc:
        recovery.main()
    assert exc.value.code == 2
    assert recovery.DATABASE_URL_ENV in capsys.readouterr().err


def test_worker_recovery_probe_requires_explicit_acknowledgement(monkeypatch, capsys):
    monkeypatch.setenv(recovery.DATABASE_URL_ENV, "postgresql://private/test")
    monkeypatch.setattr(sys, "argv", ["agent-recovery-probe"])
    with pytest.raises(SystemExit) as exc:
        recovery.main()
    assert exc.value.code == 2
    assert "--acknowledge-dedicated-database" in capsys.readouterr().err


def test_replacement_worker_inherits_no_database_or_cloud_credentials(monkeypatch):
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://user:secret@private/db")
    monkeypatch.setenv("ICHECK_SERVER_SECRET_VAULT_TOKEN", "vault-secret")
    monkeypatch.setenv("PGPASSWORD", "postgres-secret")
    monkeypatch.setenv("DATABASE_URL", "postgresql://other:secret@private/db")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "cloud-secret")
    env = recovery._worker_environment("registration-secret")
    assert "ICHECK_DATABASE_URL" not in env
    assert "ICHECK_SERVER_SECRET_VAULT_TOKEN" not in env
    assert "PGPASSWORD" not in env
    assert "DATABASE_URL" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert env["ICHECK_AGENT_REGISTRATION_TOKEN"] == "registration-secret"
    assert env["ICHECK_TENANT_ID"]
    assert env["ICHECK_REGION_ID"]
