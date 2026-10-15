"""Quota source attribution backfills safely without unsealing receipts."""

import os
from datetime import UTC, date, datetime
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import MetaData, Table, create_engine, select, update
from sqlalchemy.exc import DBAPIError


def test_source_migration_preserves_legacy_agent_uncertainty(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'quota-sources.sqlite'}"
    env = {
        **os.environ,
        "ICHECK_DATABASE_URL": url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "PYTHONPATH": str(root / "backend"),
    }

    def migrate(target: str):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"),
             "upgrade", target],
            cwd=root, env=env, capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    migrate("y8a0c2e4g6i9")
    engine = create_engine(url)
    old = Table("ai_authoring_quota_reservations", MetaData(), autoload_with=engine)
    structured_id = str(uuid4())
    legacy_agent_id = str(uuid4())
    with engine.begin() as connection:
        for receipt_id, entity_type, entity_id, status in (
            (str(uuid4()), "device_activation_policy_proposal", structured_id, "settled"),
            (str(uuid4()), "investigation_step", legacy_agent_id, "reserved"),
        ):
            connection.execute(old.insert().values(
                id=receipt_id, entity_type=entity_type, entity_id=entity_id,
                actor="operator@example.test", period_start=date.today(),
                reserved_tokens=100, known_tokens=0, charged_tokens=100,
                status=status, external_charge_unknown=True,
                created_at=datetime.now(UTC),
                settled_at=datetime.now(UTC) if status == "settled" else None,
            ))
    engine.dispose()
    migrate("head")
    engine = create_engine(url)
    reservation = Table("ai_authoring_quota_reservations", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        rows = connection.execute(select(reservation)).mappings().all()
    structured = next(row for row in rows if row["entity_id"] == structured_id)
    legacy = next(row for row in rows if row["entity_id"] == legacy_agent_id)
    assert structured["source_entity_type"] == "device_activation_policy_proposal"
    assert structured["source_entity_id"] == structured_id
    assert legacy["source_entity_type"] is None
    assert legacy["source_entity_id"] is None
    with pytest.raises(DBAPIError, match="reservation is sealed"):
        with engine.begin() as connection:
            connection.execute(
                update(reservation).where(reservation.c.entity_id == legacy_agent_id)
                .values(source_entity_type="investigation", source_entity_id=str(uuid4()))
            )
    engine.dispose()


def test_empty_source_migration_can_downgrade_without_leaving_a_trigger(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'quota-source-empty.sqlite'}"
    env = {
        **os.environ,
        "ICHECK_DATABASE_URL": url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "PYTHONPATH": str(root / "backend"),
    }
    for command, target in (("upgrade", "head"), ("downgrade", "y8a0c2e4g6i9")):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"),
             command, target],
            cwd=root, env=env, capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    engine = create_engine(url)
    with engine.connect() as connection:
        trigger = connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='trigger' "
            "AND name='icheck_sealed_ai_authoring_quota_reservation_update'"
        ).scalar()
    assert trigger == "icheck_sealed_ai_authoring_quota_reservation_update"
    engine.dispose()
