"""Preflight target snapshots survive only safe migration rollbacks."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from sqlalchemy import MetaData, Table, create_engine, inspect

from icheck.models import utcnow


def test_preflight_target_snapshot_upgrade_and_downgrade_guard(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'preflight-target-snapshot.sqlite'}"
    env = {
        **os.environ,
        "ICHECK_DATABASE_URL": url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "PYTHONPATH": str(root / "backend"),
    }

    def migrate(command: str, target: str, *, succeeds: bool = True):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"), command, target],
            cwd=root, env=env, capture_output=True, text=True, timeout=120,
        )
        assert (result.returncode == 0) is succeeds, result.stdout + result.stderr
        return result

    migrate("upgrade", "i8k0m2p4r6t9")
    engine = create_engine(url)
    assert "target_host" not in {
        item["name"] for item in inspect(engine).get_columns("device_connection_preflights")
    }
    engine.dispose()
    migrate("upgrade", "head")
    engine = create_engine(url)
    columns = {item["name"] for item in inspect(engine).get_columns("device_connection_preflights")}
    assert {"target_host", "site_snapshot"} <= columns
    engine.dispose()
    migrate("downgrade", "i8k0m2p4r6t9")
    migrate("upgrade", "head")

    engine = create_engine(url)
    table = Table("device_connection_preflights", MetaData(), autoload_with=engine)
    with engine.begin() as connection:
        connection.execute(table.insert().values(
            id=str(uuid4()), connection_id=str(uuid4()), worker_id=str(uuid4()),
            status="verified", lease_token_hash="0" * 64,
            lease_expires_at=utcnow(), started_at=utcnow(),
            target_host="198.18.77.1", site_snapshot="LAB", evidence={},
        ))
    engine.dispose()
    refused = migrate("downgrade", "i8k0m2p4r6t9", succeeds=False)
    assert "Cannot discard preflight target history" in refused.stderr
