"""Real migrated stores seal supplemental quota cases and ledger entries."""

import os
from datetime import UTC, date, datetime
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import MetaData, Table, create_engine, delete, update
from sqlalchemy.exc import DBAPIError


def test_migrated_supplement_ledger_is_append_only(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'quota-supplement.sqlite'}"
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
    case = Table("ai_authoring_quota_supplement_cases", metadata, autoload_with=engine)
    adjustment = Table("ai_authoring_quota_supplement_adjustments", metadata, autoload_with=engine)
    receipt_id, case_id, base_id = str(uuid4()), str(uuid4()), str(uuid4())
    proposer_id, reviewer_id = str(uuid4()), str(uuid4())
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(receipt.insert().values(
            id=receipt_id, entity_type="investigation_step", entity_id=str(uuid4()),
            actor="l1.operator", period_start=date.today(), reserved_tokens=100,
            known_tokens=37, charged_tokens=100, status="settled",
            external_charge_unknown=True, created_at=now, settled_at=now,
        ))
        connection.execute(case.insert().values(
            id=case_id, reservation_id=receipt_id, base_adjustment_id=base_id,
            sequence=1, actor="l1.operator", period_start=date.today(),
            previous_total_tokens=37, confirmed_total_tokens=80, delta_tokens=43,
            evidence_sha256="a" * 64,
            evidence_reference="corrected-provider-export-row-42",
            reason="Provider export shows a corrected eighty-token total.",
            proposed_by_principal_id=proposer_id,
            proposed_by="first-admin@example.test", proposed_at=now,
            status="proposed",
        ))
    with pytest.raises(DBAPIError, match="sealed"):
        with engine.begin() as connection:
            connection.execute(update(case).where(case.c.id == case_id).values(
                status="applied", reviewed_by_principal_id=proposer_id,
                reviewed_by="first-admin@example.test", reviewed_at=now,
                review_reason="Self-review must fail.",
            ))
    with engine.begin() as connection:
        connection.execute(update(case).where(case.c.id == case_id).values(
            status="applied", reviewed_by_principal_id=reviewer_id,
            reviewed_by="second-admin@example.test", reviewed_at=now,
            review_reason="Independent provider statement review accepted.",
        ))
        connection.execute(adjustment.insert().values(
            id=str(uuid4()), reservation_id=receipt_id,
            supplement_case_id=case_id, base_adjustment_id=base_id,
            sequence=1, actor="l1.operator", period_start=date.today(),
            previous_total_tokens=37, confirmed_total_tokens=80, delta_tokens=43,
            applied_by_principal_id=reviewer_id, applied_at=now,
        ))
    with pytest.raises(DBAPIError, match="sealed"):
        with engine.begin() as connection:
            connection.execute(update(case).where(case.c.id == case_id).values(
                evidence_sha256="b" * 64,
            ))
    with pytest.raises(DBAPIError, match="append-only"):
        with engine.begin() as connection:
            connection.execute(update(adjustment).where(
                adjustment.c.supplement_case_id == case_id,
            ).values(delta_tokens=0))
    with pytest.raises(DBAPIError, match="cannot be deleted"):
        with engine.begin() as connection:
            connection.execute(delete(case).where(case.c.id == case_id))
    engine.dispose()
    refused = migrate("downgrade", "c2e4g6i8k0m3", succeeds=False)
    assert "Cannot discard AI quota supplemental adjustment history" in refused.stderr
