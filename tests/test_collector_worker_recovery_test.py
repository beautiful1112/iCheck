import os
import sys

import pytest

from icheck import collector_worker_recovery_test as recovery


def test_probe_does_not_fallback_to_application_database(monkeypatch, capsys):
    monkeypatch.delenv(recovery.DATABASE_URL_ENV, raising=False)
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://application/production")
    monkeypatch.setattr(sys, "argv", ["collector-recovery", "--acknowledge-dedicated-database"])
    with pytest.raises(SystemExit) as exc:
        recovery.main()
    assert exc.value.code == 2
    assert recovery.DATABASE_URL_ENV in capsys.readouterr().err


def test_probe_requires_explicit_acknowledgement(monkeypatch, capsys):
    monkeypatch.setenv(recovery.DATABASE_URL_ENV, "postgresql://private/test")
    monkeypatch.setattr(sys, "argv", ["collector-recovery"])
    with pytest.raises(SystemExit) as exc:
        recovery.main()
    assert exc.value.code == 2
    assert "--acknowledge-dedicated-database" in capsys.readouterr().err


def test_collector_process_receives_no_database_or_cloud_credentials(monkeypatch):
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://user:secret@private/db")
    monkeypatch.setenv("PGPASSWORD", "postgres-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "cloud-secret")
    monkeypatch.setenv("ICHECK_SERVER_SECRET_VAULT_TOKEN", "vault-secret")
    env = recovery._worker_environment("registration-secret")
    assert env["ICHECK_COLLECTOR_REGISTRATION_TOKEN"] == "registration-secret"
    assert env["ICHECK_TENANT_ID"]
    assert env["ICHECK_REGION_ID"]
    assert "ICHECK_DATABASE_URL" not in env
    assert "PGPASSWORD" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "ICHECK_SERVER_SECRET_VAULT_TOKEN" not in env


def test_probe_rejects_non_postgresql_database():
    with pytest.raises(ValueError, match="requires PostgreSQL"):
        recovery._dsn("sqlite:///tmp/local.db")


def test_control_plane_configuration_is_bound_before_verification(monkeypatch):
    class StopBeforeMutation(Exception):
        pass

    database_url = "postgresql://private/icheck_collector_recovery_fixture"
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://application/other")
    monkeypatch.setenv("ICHECK_COLLECTOR_REGISTRATION_TOKEN", "old-token")
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")

    def verify(url):
        assert url == database_url
        assert os.environ["ICHECK_DATABASE_URL"] == database_url
        assert os.environ["ICHECK_COLLECTOR_REGISTRATION_TOKEN"] != "old-token"
        assert os.environ["ICHECK_CONTROL_PLANE_AUTH_MODE"] == "disabled"
        raise StopBeforeMutation

    monkeypatch.setattr(recovery, "_verify_dedicated_database", verify)
    with pytest.raises(StopBeforeMutation):
        recovery.run_collector_recovery_test(database_url)


def test_probe_rejects_an_already_imported_application_engine():
    with pytest.raises(ValueError, match="requires a fresh process"):
        recovery._assert_runtime_configuration(
            "postgresql://private/icheck_collector_recovery_fixture",
            "probe-token",
        )
