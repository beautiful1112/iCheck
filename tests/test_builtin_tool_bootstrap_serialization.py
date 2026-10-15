from types import SimpleNamespace

import pytest

from icheck import builtin_agent_tools as builtin


class Session:
    def __init__(self, dialect="postgresql", namespace=True):
        self.info = {"tenant_id": "tenant", "region_id": "region"} if namespace else {}
        self.dialect = dialect
        self.events = []

    def get_bind(self): return SimpleNamespace(dialect=SimpleNamespace(name=self.dialect))
    def execute(self, sql, parameters): self.events.append(("mutex", str(sql), parameters))
    def scalar(self, query): self.events.append(("lookup",)); return None
    def commit(self): self.events.append(("commit",))


@pytest.mark.parametrize("commit", [True, False])
def test_postgres_bootstrap_locks_before_reads_and_never_commits_per_tool(monkeypatch, commit):
    monkeypatch.setattr(builtin, "BUILTIN_AGENT_TOOLS", builtin.BUILTIN_AGENT_TOOLS[:3])
    db = Session()
    def create(session, payload, *, commit):
        assert commit is False
        session.events.append(("create", payload.name))
        return SimpleNamespace(name=payload.name)
    monkeypatch.setattr(builtin, "create_agent_tool", create)
    tools = builtin.ensure_builtin_agent_tools(db, commit=commit)
    assert len(tools) == 3
    assert db.events[0] == ("mutex", "SELECT pg_advisory_xact_lock(hashtextextended(:namespace, 0))",
        {"namespace": "icheck.builtin-agent-tools:tenant:region"})
    assert [row for row in db.events if row[0] == "commit"] == ([("commit",)] if commit else [])
    if commit: assert db.events[-1] == ("commit",)


def test_postgres_bootstrap_refuses_missing_namespace_before_any_catalog_read(monkeypatch):
    db = Session(namespace=False)
    with pytest.raises(ValueError, match="explicit namespace"):
        builtin.ensure_builtin_agent_tools(db)
    assert db.events == []


def test_sqlite_bootstrap_does_not_issue_postgresql_lock_sql(monkeypatch):
    db = Session("sqlite", namespace=False)
    monkeypatch.setattr(builtin, "BUILTIN_AGENT_TOOLS", [])
    assert builtin.ensure_builtin_agent_tools(db) == []
    assert db.events == [("commit",)]
