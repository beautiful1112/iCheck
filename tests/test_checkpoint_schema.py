from contextlib import contextmanager
import sys
from types import SimpleNamespace

import pytest

from icheck import checkpoint_schema, langgraph_runtime
from icheck.config import Settings


PRODUCTION = {
    "environment": "production",
    "control_plane_auth_mode": "required",
    "control_plane_session_cookie_secure": True,
    "require_governed_change_contracts": True,
    "auto_create_schema": False,
}


def test_production_requires_owner_provisioned_checkpoint_verification():
    settings = Settings(_env_file=None, **PRODUCTION)
    assert settings.effective_checkpoint_setup_mode == "verify"
    with pytest.raises(ValueError, match="owner-provisioned verify mode"):
        Settings(
            _env_file=None,
            **PRODUCTION,
            checkpoint_setup_mode="automatic",
        )
    assert Settings(
        _env_file=None, checkpoint_setup_mode="automatic"
    ).effective_checkpoint_setup_mode == "automatic"


def test_schema_prepare_cli_never_falls_back_to_application_url(monkeypatch, capsys):
    monkeypatch.delenv(checkpoint_schema.OWNER_URL_ENV, raising=False)
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://production/app")
    monkeypatch.setattr(
        sys, "argv",
        [
            "checkpoint-schema-prepare", "--acknowledge-database-ddl",
            "--runtime-role", "icheck_runtime",
        ],
    )
    with pytest.raises(SystemExit) as failure:
        checkpoint_schema.main()
    assert failure.value.code == 2
    assert checkpoint_schema.OWNER_URL_ENV in capsys.readouterr().err


def test_schema_prepare_cli_requires_explicit_ddl_acknowledgement(
    monkeypatch, capsys,
):
    monkeypatch.setenv(
        checkpoint_schema.OWNER_URL_ENV, "postgresql://owner/private"
    )
    monkeypatch.setattr(
        sys, "argv", ["checkpoint-schema-prepare", "--runtime-role", "runtime"]
    )
    with pytest.raises(SystemExit) as failure:
        checkpoint_schema.main()
    assert failure.value.code == 2
    assert "--acknowledge-database-ddl" in capsys.readouterr().err


def test_orphan_audit_cli_requires_owner_url_and_lock_ack(monkeypatch, capsys):
    monkeypatch.delenv(checkpoint_schema.OWNER_URL_ENV, raising=False)
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://production/app")
    monkeypatch.setattr(sys, "argv", [
        "checkpoint-orphan-audit", "--acknowledge-schema-lock",
    ])
    with pytest.raises(SystemExit) as missing_owner:
        checkpoint_schema.audit_main()
    assert missing_owner.value.code == 2
    assert checkpoint_schema.OWNER_URL_ENV in capsys.readouterr().err

    monkeypatch.setenv(
        checkpoint_schema.OWNER_URL_ENV, "postgresql://owner/private"
    )
    monkeypatch.setattr(sys, "argv", ["checkpoint-orphan-audit"])
    with pytest.raises(SystemExit) as missing_ack:
        checkpoint_schema.audit_main()
    assert missing_ack.value.code == 2
    assert "--acknowledge-schema-lock" in capsys.readouterr().err


@pytest.mark.parametrize("value", (0, 99, 300001, True, "500"))
def test_checkpoint_owner_operations_reject_invalid_lock_timeout(value):
    with pytest.raises(ValueError, match="lock timeout"):
        checkpoint_schema.prepare_checkpoint_schema(
            "postgresql://owner/private", runtime_role="runtime",
            lock_timeout_ms=value,
        )
    with pytest.raises(ValueError, match="lock timeout"):
        checkpoint_schema.audit_checkpoint_orphans(
            "postgresql://owner/private", lock_timeout_ms=value,
        )


@pytest.mark.parametrize("mutation", ("new_migration", "same_count_sql_change"))
def test_checkpoint_owner_rejects_unreviewed_saver_before_database_access(
    monkeypatch, mutation,
):
    migrations = [*checkpoint_schema.PostgresSaver.MIGRATIONS]
    if mutation == "new_migration":
        migrations.append("SELECT 1")
    else:
        migrations[-1] += " /* changed without version increment */"
    monkeypatch.setattr(
        checkpoint_schema.PostgresSaver, "MIGRATIONS", migrations,
    )
    monkeypatch.setattr(
        checkpoint_schema.psycopg, "connect",
        lambda *_args, **_kwargs: pytest.fail("Owner connected before version guard"),
    )
    with pytest.raises(RuntimeError, match="migration contract changed"):
        checkpoint_schema.prepare_checkpoint_schema(
            "postgresql://owner/private", runtime_role="runtime"
        )


def test_checkpoint_owner_clis_forward_lock_timeout(monkeypatch, capsys):
    calls = []
    monkeypatch.setenv(
        checkpoint_schema.OWNER_URL_ENV, "postgresql://owner/private"
    )
    monkeypatch.setattr(
        checkpoint_schema, "prepare_checkpoint_schema",
        lambda url, **kwargs: calls.append(("prepare", url, kwargs)) or {},
    )
    monkeypatch.setattr(
        checkpoint_schema, "audit_checkpoint_orphans",
        lambda url, **kwargs: calls.append(("audit", url, kwargs)) or {},
    )
    monkeypatch.setattr(sys, "argv", [
        "checkpoint-schema-prepare", "--acknowledge-database-ddl",
        "--runtime-role", "runtime", "--lock-timeout-ms", "750",
    ])
    assert checkpoint_schema.main() == 0
    monkeypatch.setattr(sys, "argv", [
        "checkpoint-orphan-audit", "--acknowledge-schema-lock",
        "--lock-timeout-ms", "250",
    ])
    assert checkpoint_schema.audit_main() == 0
    assert calls == [
        (
            "prepare", "postgresql://owner/private",
            {"runtime_role": "runtime", "lock_timeout_ms": 750},
        ),
        (
            "audit", "postgresql://owner/private",
            {"lock_timeout_ms": 250},
        ),
    ]
    assert capsys.readouterr().out == "{}\n{}\n"


def test_verification_mode_does_not_invoke_saver_setup(monkeypatch):
    setup_calls = []
    verified = []

    class FakeSaver:
        @classmethod
        @contextmanager
        def from_conn_string(cls, _dsn):
            yield cls()

        def setup(self):
            setup_calls.append(True)

    monkeypatch.setattr(langgraph_runtime, "PostgresSaver", FakeSaver)
    monkeypatch.setattr(
        langgraph_runtime, "verify_checkpoint_schema", verified.append
    )
    dsn = "postgresql://unit/verify_checkpoint_schema_test"
    with langgraph_runtime.postgres_checkpointer(dsn, setup_mode="verify"):
        pass
    with langgraph_runtime.postgres_checkpointer(dsn, setup_mode="verify"):
        pass
    assert setup_calls == []
    assert verified == [dsn]


def test_scoped_checkpointer_binds_both_namespace_ids_on_saver_connection(
    monkeypatch,
):
    calls = []

    class FakeCursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, query, params):
            calls.append((query, params))

    class FakeSaver:
        conn = SimpleNamespace(cursor=FakeCursor)

        @classmethod
        @contextmanager
        def from_conn_string(cls, _dsn):
            yield cls()

    monkeypatch.setattr(langgraph_runtime, "PostgresSaver", FakeSaver)
    monkeypatch.setattr(
        langgraph_runtime, "verify_checkpoint_schema", lambda _dsn: None
    )
    with langgraph_runtime.postgres_checkpointer(
        "postgresql://unit/scoped_checkpoint_test", setup_mode="verify",
        tenant_id="tenant-a", region_id="region-a",
    ):
        pass
    assert calls == [(
        "SELECT set_config('icheck.tenant_id', %s, false), "
        "set_config('icheck.region_id', %s, false)",
        ("tenant-a", "region-a"),
    )]
    with pytest.raises(ValueError, match="supplied together"):
        with langgraph_runtime.postgres_checkpointer(
            "postgresql://unit/scoped_checkpoint_test", setup_mode="verify",
            tenant_id="tenant-a",
        ):
            pass


def test_runtime_role_identifier_is_restricted_before_connecting():
    with pytest.raises(ValueError, match="invalid identifier"):
        checkpoint_schema.prepare_checkpoint_schema(
            "postgresql://owner/private", runtime_role="runtime;drop schema"
        )


def test_unknown_saver_migration_contract_fails_closed(monkeypatch):
    monkeypatch.setattr(
        checkpoint_schema,
        "PostgresSaver",
        SimpleNamespace(MIGRATIONS=["SELECT 1"] * 11),
    )
    with pytest.raises(RuntimeError, match="migration contract changed"):
        checkpoint_schema._version()
