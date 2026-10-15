"""Migrated orphan model-audit snapshots are append-only and cannot be dropped."""

import os
from datetime import UTC, date, datetime
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import MetaData, Table, create_engine, delete, update
from sqlalchemy.exc import DBAPIError


def test_migrated_orphan_audit_evidence_is_sealed(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'orphan-audit.sqlite'}"
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
    evidence = Table("ai_authoring_quota_orphan_audit_evidence", metadata, autoload_with=engine)
    receipt_id, case_id, source_id = str(uuid4()), str(uuid4()), str(uuid4())
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(receipt.insert().values(
            id=receipt_id, entity_type="capability_studio_generation_attempt",
            entity_id=source_id, source_entity_type="capability_studio_generation_attempt",
            source_entity_id=source_id, actor="l1.operator", period_start=date.today(),
            reserved_tokens=100, known_tokens=0, charged_tokens=100,
            status="reserved", external_charge_unknown=True, created_at=now,
        ))
        connection.execute(case.insert().values(
            id=case_id, reservation_id=receipt_id, actor="l1.operator",
            period_start=date.today(),
            source_entity_type="capability_studio_generation_attempt",
            source_entity_id=source_id, source_status_snapshot="interrupted",
            source_terminal_at=now, reserved_tokens_snapshot=100,
            reason="Terminal source and exact model audit were reviewed.",
            proposed_by_principal_id=str(uuid4()),
            proposed_by="first-admin@example.test", proposed_at=now,
            status="proposed",
        ))
        connection.execute(evidence.insert().values(
            id=str(uuid4()), reservation_id=receipt_id, orphan_case_id=case_id,
            known_tokens=42, event_count=2, audit_sha256="a" * 64,
            captured_at=now,
        ))
    with pytest.raises(DBAPIError, match="append-only"):
        with engine.begin() as connection:
            connection.execute(update(evidence).values(known_tokens=0))
    with pytest.raises(DBAPIError, match="append-only"):
        with engine.begin() as connection:
            connection.execute(delete(evidence))
    engine.dispose()
    refused = migrate("downgrade", "d3f5h7j9l1n4", succeeds=False)
    assert "Cannot discard AI quota orphan audit evidence history" in refused.stderr
