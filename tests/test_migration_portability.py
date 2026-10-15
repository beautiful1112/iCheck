"""URL interpolation and cross-dialect migration naming regressions."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

from sqlalchemy import create_engine, inspect


def test_percent_url_and_empty_sqlite_migration_roundtrip(tmp_path):
    root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "migration%25.sqlite"
    url = f"sqlite+pysqlite:///{database_path}"
    environment = {**os.environ, "ICHECK_DATABASE_URL": url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false", "PYTHONPATH": str(root / "backend")}
    for command, target in (("upgrade", "head"), ("downgrade", "base"), ("upgrade", "head")):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"), command, target],
            cwd=root, env=environment, capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert database_path.exists()
        engine = create_engine(url)
        try:
            schema = inspect(engine)
            if command == "downgrade":
                assert schema.get_table_names() == ["alembic_version"]
            else:
                assert "change_preapproval_budget_claims" in schema.get_table_names()
                assert "activation_policy_proposals" in schema.get_table_names()
                proposal_constraints = {
                    item["name"] for item in schema.get_unique_constraints(
                        "activation_policy_proposals"
                    )
                }
                assert "uq_activation_policy_proposal_request" in proposal_constraints
                names = {item["name"] for item in schema.get_indexes("capability_studio_sessions")}
                assert "ix_capability_studio_sessions_revision_source_artifact_version_id" in names
        finally:
            engine.dispose()
