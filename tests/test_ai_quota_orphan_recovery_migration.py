"""Real Alembic guards preserve independent orphan-closure history."""

import os
from datetime import UTC, date, datetime
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import MetaData, Table, create_engine, delete, update
from sqlalchemy.exc import DBAPIError


def test_migrated_orphan_closure_is_sealed(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'orphan-closure.sqlite'}"
    env = {
        **os.environ,
        "ICHECK_DATABASE_URL": url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "PYTHONPATH": str(root / "backend"),
    }

    def migrate(command: str, target: str, *, succeeds: bool = True):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"),
             command, target], cwd=root, env=env,
            capture_output=True, text=True, timeout=120,
        )
        assert (result.returncode == 0) is succeeds, result.stdout + result.stderr
        return result

    migrate("upgrade", "head")
    engine = create_engine(url)
    metadata = MetaData()
    receipt = Table("ai_authoring_quota_reservations", metadata, autoload_with=engine)
    case = Table("ai_authoring_quota_orphan_cases", metadata, autoload_with=engine)
    closure = Table("ai_authoring_quota_orphan_closures", metadata, autoload_with=engine)
    receipt_id, case_id, source_id = str(uuid4()), str(uuid4()), str(uuid4())
    proposer_id, reviewer_id = str(uuid4()), str(uuid4())
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(receipt.insert().values(
            id=receipt_id, entity_type="capability_studio_generation_attempt",
            entity_id=source_id, source_entity_type="capability_studio_generation_attempt",
            source_entity_id=source_id, actor="l1.operator", period_start=date.today(),
            reserved_tokens=100, known_tokens=0, charged_tokens=100,
            status="settled", external_charge_unknown=True,
            created_at=now, settled_at=now,
        ))
        connection.execute(case.insert().values(
            id=case_id, reservation_id=receipt_id, actor="l1.operator",
            period_start=date.today(),
            source_entity_type="capability_studio_generation_attempt",
            source_entity_id=source_id, source_status_snapshot="interrupted",
            source_terminal_at=now, reserved_tokens_snapshot=100,
            reason="Terminal source and expired ownership were reviewed.",
            proposed_by_principal_id=proposer_id,
            proposed_by="first-admin@example.test", proposed_at=now,
            status="proposed",
        ))
    with pytest.raises(DBAPIError, match="sealed"):
        with engine.begin() as connection:
            connection.execute(update(case).where(case.c.id == case_id).values(
                status="closed", reviewed_by_principal_id=proposer_id,
                reviewed_by="first-admin@example.test", reviewed_at=now,
                review_reason="Self-review must be refused.",
            ))
    with engine.begin() as connection:
        connection.execute(update(case).where(case.c.id == case_id).values(
            status="closed", reviewed_by_principal_id=reviewer_id,
            reviewed_by="second-admin@example.test", reviewed_at=now,
            review_reason="Independent source-state check accepted.",
        ))
        connection.execute(closure.insert().values(
            id=str(uuid4()), reservation_id=receipt_id, orphan_case_id=case_id,
            actor="l1.operator", period_start=date.today(), reserved_tokens=100,
            closed_by_principal_id=reviewer_id, closed_at=now,
        ))
    with pytest.raises(DBAPIError, match="sealed"):
        with engine.begin() as connection:
            connection.execute(update(case).where(case.c.id == case_id).values(
                reserved_tokens_snapshot=1,
            ))
    with pytest.raises(DBAPIError, match="append-only"):
        with engine.begin() as connection:
            connection.execute(update(closure).where(closure.c.orphan_case_id == case_id).values(
                reserved_tokens=1,
            ))
    with pytest.raises(DBAPIError, match="cannot be deleted"):
        with engine.begin() as connection:
            connection.execute(delete(case).where(case.c.id == case_id))
    engine.dispose()
    refused = migrate("downgrade", "b1d3f5h7j9l2", succeeds=False)
    assert "Cannot discard AI quota orphan recovery history" in refused.stderr
