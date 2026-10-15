"""Migration-level immutability for durable AI proposal receipts."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import MetaData, Table, create_engine, delete, update
from sqlalchemy.exc import DBAPIError

from icheck.models import utcnow


def test_activation_proposal_receipts_are_sealed_after_generation(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'activation-proposals.sqlite'}"
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
    table = Table("activation_policy_proposals", MetaData(), autoload_with=engine)
    proposal_id = str(uuid4())
    interrupted_id = str(uuid4())
    now = utcnow()
    with engine.begin() as connection:
        connection.execute(table.insert().values(
            id=proposal_id,
            artifact_version_id=str(uuid4()),
            protocol="https_api",
            actor="lab.operator",
            request_key=str(uuid4()),
            request_sha256="a" * 64,
            brief="Review this read-only API collector policy.",
            status="generating",
            result_snapshot={},
            tokens_used=0,
            external_charge_unknown=True,
            created_at=now,
            updated_at=now,
        ))
        connection.execute(
            update(table).where(table.c.id == proposal_id).values(
                status="succeeded", external_charge_unknown=False,
            )
        )
        connection.execute(table.insert().values(
            id=interrupted_id,
            artifact_version_id=str(uuid4()),
            protocol="https_api",
            actor="lab.operator",
            request_key=str(uuid4()),
            request_sha256="b" * 64,
            brief="Review a separate stale policy request.",
            status="generating",
            result_snapshot={},
            tokens_used=0,
            external_charge_unknown=True,
            created_at=now,
            updated_at=now,
        ))
        connection.execute(
            update(table).where(table.c.id == interrupted_id).values(
                status="failed", failure_code="Interrupted"
            )
        )
    with pytest.raises(DBAPIError, match="history is sealed"):
        with engine.begin() as connection:
            connection.execute(
                update(table).where(table.c.id == proposal_id).values(brief="tampered")
            )
    with pytest.raises(DBAPIError, match="history cannot be deleted"):
        with engine.begin() as connection:
            connection.execute(delete(table).where(table.c.id == proposal_id))
    with pytest.raises(DBAPIError, match="history is sealed"):
        with engine.begin() as connection:
            connection.execute(
                update(table).where(table.c.id == interrupted_id).values(
                    status="succeeded", result_snapshot={"forged": True}
                )
            )
    with pytest.raises(DBAPIError, match="history is sealed"):
        with engine.begin() as connection:
            connection.execute(
                update(table).where(table.c.id == proposal_id).values(
                    external_charge_unknown=True,
                )
            )
    engine.dispose()
    refused = migrate("downgrade", "w6y8a0c2e5g8", succeeds=False)
    assert "Cannot downgrade recorded proposal charge status" in refused.stderr
