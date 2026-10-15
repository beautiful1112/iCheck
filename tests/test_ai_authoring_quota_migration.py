"""Migrated authoring reservations cannot be rewritten or downgraded away."""

import os
from datetime import UTC, date, datetime
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import MetaData, Table, create_engine, delete, update
from sqlalchemy.exc import DBAPIError


def test_migrated_authoring_quota_receipt_is_sealed(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'authoring-quota.sqlite'}"
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

    migrate("upgrade", "head")
    engine = create_engine(url)
    reservation = Table(
        "ai_authoring_quota_reservations", MetaData(), autoload_with=engine,
    )
    now = datetime.now(UTC)
    receipt_id = str(uuid4())
    with engine.begin() as connection:
        connection.execute(reservation.insert().values(
            id=receipt_id, entity_type="device_activation_policy_proposal",
            entity_id=str(uuid4()), actor="operator@example.test",
            period_start=date.today(), reserved_tokens=100,
            known_tokens=0, charged_tokens=100, status="reserved",
            external_charge_unknown=True, created_at=now,
        ))
        connection.execute(
            update(reservation).where(reservation.c.id == receipt_id).values(
                known_tokens=42, charged_tokens=42, status="settled",
                external_charge_unknown=False, settled_at=now,
            )
        )
    with pytest.raises(DBAPIError, match="reservation is sealed"):
        with engine.begin() as connection:
            connection.execute(
                update(reservation).where(reservation.c.id == receipt_id).values(
                    charged_tokens=0,
                )
            )
    with pytest.raises(DBAPIError, match="reservation cannot be deleted"):
        with engine.begin() as connection:
            connection.execute(delete(reservation).where(reservation.c.id == receipt_id))
    engine.dispose()
    refused = migrate("downgrade", "x7z9b1d3f5h8", succeeds=False)
    assert "Cannot discard AI quota reservation source history" in refused.stderr
