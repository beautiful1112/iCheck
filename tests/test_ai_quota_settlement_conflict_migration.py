"""Real migrated stores seal and retain contradictory model-call reports."""

import os
from datetime import UTC, date, datetime
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import MetaData, Table, create_engine, delete, update
from sqlalchemy.exc import DBAPIError


def test_migrated_settlement_conflict_is_append_only(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'quota-conflict.sqlite'}"
    env = {
        **os.environ,
        "ICHECK_DATABASE_URL": url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "PYTHONPATH": str(root / "backend"),
    }

    def migrate(command: str, target: str, *, succeeds: bool = True):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"),
             command, target],
            cwd=root, env=env, capture_output=True, text=True, timeout=120,
        )
        assert (result.returncode == 0) is succeeds, result.stdout + result.stderr
        return result

    migrate("upgrade", "head")
    engine = create_engine(url)
    metadata = MetaData()
    receipt = Table("ai_authoring_quota_reservations", metadata, autoload_with=engine)
    conflict = Table("ai_authoring_quota_settlement_conflicts", metadata, autoload_with=engine)
    receipt_id, conflict_id = str(uuid4()), str(uuid4())
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(receipt.insert().values(
            id=receipt_id, entity_type="investigation_step", entity_id=str(uuid4()),
            actor="l1.operator", period_start=date.today(), reserved_tokens=100,
            known_tokens=20, charged_tokens=100, status="settled",
            external_charge_unknown=True, created_at=now, settled_at=now,
        ))
        connection.execute(conflict.insert().values(
            id=conflict_id, reservation_id=receipt_id,
            reported_known_tokens=80, reported_external_charge_unknown=False,
            settled_known_tokens_snapshot=20,
            settled_external_charge_unknown_snapshot=True,
            settled_charged_tokens_snapshot=100, recorded_at=now,
        ))
    with pytest.raises(DBAPIError, match="append-only"):
        with engine.begin() as connection:
            connection.execute(update(conflict).where(conflict.c.id == conflict_id).values(
                reported_known_tokens=0,
            ))
    with pytest.raises(DBAPIError, match="append-only"):
        with engine.begin() as connection:
            connection.execute(delete(conflict).where(conflict.c.id == conflict_id))
    engine.dispose()
    refused = migrate("downgrade", "a0c2e4g6i8k1", succeeds=False)
    assert "Cannot discard AI quota settlement conflict history" in refused.stderr
