import sys

import pytest

from icheck import checkpoint_recovery_test as recovery


class _FakeCursor:
    def __init__(self, name, relation_count):
        self.values = iter([(name,), (relation_count,)])

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, _statement):
        return None

    def fetchone(self):
        return next(self.values)


class _FakeConnection:
    def __init__(self, name, relation_count):
        self.name = name
        self.relation_count = relation_count

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def cursor(self):
        return _FakeCursor(self.name, self.relation_count)


@pytest.mark.parametrize(
    ("name", "relation_count", "expected"),
    [
        ("icheck_recovery_empty", 0, "icheck_recovery_empty"),
        ("icheck", 0, "requires an icheck_recovery_ database"),
        ("icheck_recovery_used", 1, "refuses a non-empty database"),
    ],
)
def test_recovery_probe_requires_named_empty_database(
    monkeypatch, name, relation_count, expected
):
    monkeypatch.setattr(
        recovery.psycopg,
        "connect",
        lambda _dsn: _FakeConnection(name, relation_count),
    )
    if name == expected:
        assert recovery._validate_empty_database("postgresql://local/test") == expected
    else:
        with pytest.raises(ValueError, match=expected):
            recovery._validate_empty_database("postgresql://local/test")


def test_recovery_probe_has_no_application_database_fallback(monkeypatch, capsys):
    monkeypatch.delenv(recovery.DATABASE_URL_ENV, raising=False)
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://application/production")
    monkeypatch.setattr(sys, "argv", ["recovery-probe", "--acknowledge-dedicated-database"])
    with pytest.raises(SystemExit) as exc:
        recovery.main()
    assert exc.value.code == 2
    assert recovery.DATABASE_URL_ENV in capsys.readouterr().err


def test_recovery_probe_internal_stage_requires_parent_token(monkeypatch, capsys):
    monkeypatch.setenv(recovery.DATABASE_URL_ENV, "postgresql://local/test")
    monkeypatch.delenv(recovery.INTERNAL_STAGE_TOKEN_ENV, raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["recovery-probe", "--stage", "checkpoint", "--investigation-id", "probe"],
    )
    with pytest.raises(SystemExit) as exc:
        recovery.main()
    assert exc.value.code == 2
    assert "parent launch token" in capsys.readouterr().err
