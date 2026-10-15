from pathlib import Path

import pytest
from alembic.script import ScriptDirectory

from icheck import database_release as release


def test_installed_migration_config_does_not_depend_on_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = release.migration_config()
    scripts = Path(config.get_main_option("script_location"))
    assert scripts.is_absolute() and (scripts / "env.py").is_file()
    assert config.config_file_name is None
    assert len(ScriptDirectory.from_config(config).get_heads()) == 1


@pytest.mark.parametrize("argv", [["current"], ["upgrade", "--acknowledge-drained"]])
def test_database_commands_require_explicit_database_url(argv, monkeypatch):
    monkeypatch.delenv("ICHECK_DATABASE_URL", raising=False)
    with pytest.raises(SystemExit) as refused:
        release.main(argv)
    assert refused.value.code == 2


def test_upgrade_requires_operator_drain_acknowledgement(monkeypatch):
    monkeypatch.setenv("ICHECK_DATABASE_URL", "sqlite+pysqlite:///controlled.sqlite")
    with pytest.raises(SystemExit) as refused:
        release.main(["upgrade"])
    assert refused.value.code == 2


def test_heads_never_runs_the_database_environment(monkeypatch, capsys):
    monkeypatch.delenv("ICHECK_DATABASE_URL", raising=False)
    assert release.main(["heads"]) == 0
    assert "(head)" in capsys.readouterr().out


def test_upgrade_passes_the_requested_revision_to_original_alembic_guards(monkeypatch):
    monkeypatch.setenv("ICHECK_DATABASE_URL", "sqlite+pysqlite:///controlled.sqlite")
    calls = []
    monkeypatch.setattr(release.command, "upgrade", lambda config, revision: calls.append((config, revision)))
    assert release.main(["upgrade", "--revision", "reviewed-revision", "--acknowledge-drained"]) == 0
    assert calls[0][1] == "reviewed-revision"
    assert calls[0][0].get_main_option("script_location").endswith("migrations")


def test_driver_errors_never_print_connection_secrets(monkeypatch, capsys):
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql+psycopg://operator:private-password@db/icheck")
    def failure(config):
        raise RuntimeError("postgresql://operator:private-password@db/icheck; private-token")
    monkeypatch.setattr(release.command, "current", failure)
    assert release.main(["current"]) == 1
    captured = capsys.readouterr()
    assert "RuntimeError" in captured.err
    assert "private-password" not in captured.err + captured.out
    assert "private-token" not in captured.err + captured.out
