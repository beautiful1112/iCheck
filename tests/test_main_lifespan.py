import asyncio
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

import icheck.main as main_module


@pytest.mark.parametrize(
    ("database_url", "expected"),
    [
        ("postgresql+psycopg://local/icheck", ["saver", "session"]),
        ("sqlite+pysqlite:///:memory:", ["session"]),
    ],
)
def test_startup_initializes_postgres_saver_before_business_transaction(
    monkeypatch, database_url, expected
):
    observed = []

    @contextmanager
    def fake_saver(_database_url):
        observed.append("saver")
        yield object()

    class FakeSession:
        def __enter__(self):
            observed.append("session")
            return self

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(
        main_module,
        "settings",
        SimpleNamespace(
            database_url=database_url,
            auto_create_schema=False,
            environment="development",
        ),
    )
    monkeypatch.setattr(main_module, "build_server_credential_providers", lambda **_: None)
    monkeypatch.setattr(main_module, "postgres_checkpointer", fake_saver)
    monkeypatch.setattr(main_module, "SessionLocal", FakeSession)
    monkeypatch.setattr(
        main_module,
        "ensure_default_namespace",
        lambda _db: (SimpleNamespace(id="tenant"), SimpleNamespace(id="region")),
    )
    for name in (
        "set_session_namespace",
        "ensure_default_rules",
        "ensure_builtin_roles",
        "ensure_change_risk_policies",
        "ensure_default_agent_profiles",
    ):
        monkeypatch.setattr(main_module, name, lambda *_args: None)

    async def open_lifespan():
        async with main_module.lifespan(main_module.app):
            pass

    asyncio.run(open_lifespan())
    assert observed == expected
