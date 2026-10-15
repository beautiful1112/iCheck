"""Populated migration preserves drafts and fences unowned legacy requests."""
import os
from pathlib import Path
import subprocess
import sys
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import MetaData, Table, create_engine, select, text
from sqlalchemy.exc import DBAPIError

from icheck.models import utcnow


def test_studio_ownership_upgrade_preserves_all_namespace_history(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'studio-ownership.sqlite'}"
    env = {**os.environ, "ICHECK_DATABASE_URL": url, "ICHECK_AUTO_CREATE_SCHEMA": "false", "PYTHONPATH": str(root / "backend")}
    def migrate(command, target, *, success=True):
        result = subprocess.run([sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"), command, target],
            cwd=root, env=env, capture_output=True, text=True, timeout=120)
        assert (result.returncode == 0) is success, result.stdout + result.stderr
        return result
    migrate("upgrade", "k3m5p7r9t1v4")
    db = create_engine(url)
    sessions = Table("capability_studio_sessions", MetaData(), autoload_with=db)
    artifacts = Table("artifacts", MetaData(), autoload_with=db)
    versions = Table("artifact_versions", MetaData(), autoload_with=db)
    now = utcnow()
    rows = []
    with db.begin() as connection:
        for status in ("generating", "validated"):
            namespace = {"tenant_id": str(uuid4()), "region_id": str(uuid4())}
            artifact_id, version_id, session_id = (str(uuid4()) for _ in range(3))
            connection.execute(artifacts.insert().values(id=artifact_id, **namespace,
                name=f"retained-{status}", kind="COLLECTOR", description="Retained draft", owner="legacy.author", labels={}, created_at=now, updated_at=now))
            connection.execute(versions.insert().values(id=version_id, **namespace, artifact_id=artifact_id,
                version=1, status="DRAFT", definition={"purpose": "Retained fixture"}, implementation={}, tests=[], validation_report={},
                created_by="legacy.author", created_at=now))
            row = dict(id=session_id, **namespace, title=f"Legacy {status}", artifact_kind="collector", status=status,
                route_purpose="capability.authoring", brief="Retained authoring intent", target_url="https://inventory.example.test/api",
                sample_document={"devices": []}, current_spec={"artifact_name": f"retained-{status}"},
                artifact_id=artifact_id, artifact_version_id=version_id, tokens_used=42, created_by="legacy.author", created_at=now, updated_at=now)
            connection.execute(sessions.insert().values(row))
            rows.append(row)
    db.dispose()
    migrate("upgrade", "head")
    db = create_engine(url)
    sessions = Table("capability_studio_sessions", MetaData(), autoload_with=db)
    attempts = Table("capability_studio_generation_attempts", MetaData(), autoload_with=db)
    audits = Table("audit_events", MetaData(), autoload_with=db)
    with db.connect() as connection:
        for original in rows:
            current = connection.execute(select(sessions).where(sessions.c.id == original["id"])).mappings().one()
            assert current["status"] == ("failed" if original["status"] == "generating" else "validated")
            assert current["generation_attempt_id"] is None
            for field in ("tenant_id", "region_id", "current_spec", "artifact_id", "artifact_version_id", "tokens_used"):
                assert current[field] == original[field]
        interrupted = connection.execute(select(audits).where(audits.c.event_type == "capability.studio.generation.legacy_interrupted")).mappings().one()
        assert interrupted["tenant_id"] == rows[0]["tenant_id"] and interrupted["region_id"] == rows[0]["region_id"]
        assert interrupted["details"]["artifact_version_id"] == rows[0]["artifact_version_id"]
    attempt_id = str(uuid4())
    with db.begin() as connection:
        connection.execute(attempts.insert().values(id=attempt_id,
            tenant_id=rows[0]["tenant_id"], region_id=rows[0]["region_id"], session_id=rows[0]["id"], request_key=str(uuid4()),
            request_sha256="a"*64, request_document={}, actor="legacy.author", status="generating", owner_sha256="b"*64,
            lease_expires_at=now+timedelta(minutes=30), model_document={}, tokens_used=0, result_snapshot={}, created_at=now, updated_at=now))
    for statement in ("UPDATE capability_studio_generation_attempts SET actor = 'forged.author' WHERE id = :id",
        "DELETE FROM capability_studio_generation_attempts WHERE id = :id"):
        with pytest.raises(DBAPIError, match="history"):
            with db.begin() as connection:
                connection.execute(text(statement), {"id": attempt_id})
    db.dispose()
    refused = migrate("downgrade", "k3m5p7r9t1v4", success=False)
    assert "Cannot downgrade recorded Studio generation history" in refused.stderr
