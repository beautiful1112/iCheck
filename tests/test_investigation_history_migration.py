"""The history index upgrades and downgrades without changing Investigation rows."""

import os
from pathlib import Path
import subprocess
import sys

from sqlalchemy import create_engine, inspect


def test_investigation_history_index_round_trip(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'history-index.sqlite'}"
    env = {
        **os.environ,
        "ICHECK_DATABASE_URL": url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "PYTHONPATH": str(root / "backend"),
    }

    def migrate(command: str, target: str):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"),
             command, target],
            cwd=root, env=env, capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    def index_present():
        engine = create_engine(url)
        try:
            indexes = inspect(engine).get_indexes("investigations")
            return any(
                index["name"] == "ix_investigations_history"
                and index["column_names"] == [
                    "tenant_id", "region_id", "created_at", "id",
                ]
                for index in indexes
            )
        finally:
            engine.dispose()

    migrate("upgrade", "q5s7u9w1y3a6")
    assert not index_present()
    migrate("upgrade", "head")
    assert index_present()
    migrate("downgrade", "q5s7u9w1y3a6")
    assert not index_present()
    migrate("upgrade", "head")
    assert index_present()
