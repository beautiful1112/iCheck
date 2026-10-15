"""Database guards preserve activation policy history beyond API checks."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import MetaData, Table, create_engine, text
from sqlalchemy.exc import DBAPIError

from icheck.models import utcnow


def test_existing_policy_draft_can_advance_but_validated_history_is_sealed(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'activation-policy-guard.sqlite'}"
    env = {
        **os.environ,
        "ICHECK_DATABASE_URL": url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "PYTHONPATH": str(root / "backend"),
    }

    def migrate(command: str, target: str):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"), command, target],
            cwd=root, env=env, capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    migrate("upgrade", "g6j8l0n2p4r7")
    engine = create_engine(url)
    table = Table("device_activation_policies", MetaData(), autoload_with=engine)
    policy_id = str(uuid4())
    now = utcnow()
    with engine.begin() as connection:
        connection.execute(table.insert().values(
            id=policy_id, tenant_id=str(uuid4()), region_id=str(uuid4()),
            name="controller-readonly", version=1, status="DRAFT",
            protocol="https_api", adapter_type="http_json",
            artifact_version_id=str(uuid4()), target_template={},
            configuration_defaults={}, worker_selector={},
            execution_mode="SCHEDULED", schedule_seconds=300,
            created_by="migration.test", created_at=now,
        ))
    engine.dispose()

    migrate("upgrade", "head")
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE device_activation_policies SET schedule_seconds = 120, "
            "revision = 2, updated_by = 'editor', updated_at = :now WHERE id = :id"
        ), {"now": now, "id": policy_id})
    with pytest.raises(DBAPIError, match="lifecycle is sealed"):
        with engine.begin() as connection:
            connection.execute(text(
                "UPDATE device_activation_policies SET schedule_seconds = 150 WHERE id = :id"
            ), {"id": policy_id})
    with pytest.raises(DBAPIError, match="lifecycle is sealed"):
        with engine.begin() as connection:
            connection.execute(text(
                "UPDATE device_activation_policies SET name = 'renamed' WHERE id = :id"
            ), {"id": policy_id})
    with pytest.raises(DBAPIError, match="lifecycle is sealed"):
        with engine.begin() as connection:
            connection.execute(text(
                "UPDATE device_activation_policies SET status = 'PUBLISHED' WHERE id = :id"
            ), {"id": policy_id})
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE device_activation_policies SET status = 'VALIDATED', "
            "content_hash = :hash, validated_by = 'reviewer', "
            "validated_at = :now WHERE id = :id"
        ), {"hash": "a" * 64, "now": now, "id": policy_id})
    with pytest.raises(DBAPIError, match="lifecycle is sealed"):
        with engine.begin() as connection:
            connection.execute(text(
                "UPDATE device_activation_policies SET schedule_seconds = 150 WHERE id = :id"
            ), {"id": policy_id})
    with pytest.raises(DBAPIError, match="lifecycle is sealed"):
        with engine.begin() as connection:
            connection.execute(text(
                "UPDATE device_activation_policies SET status = 'DRAFT' WHERE id = :id"
            ), {"id": policy_id})
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE device_activation_policies SET status = 'PUBLISHED', "
            "published_by = 'publisher', published_at = :now WHERE id = :id"
        ), {"now": now, "id": policy_id})
    with pytest.raises(DBAPIError, match="lifecycle is sealed"):
        with engine.begin() as connection:
            connection.execute(text(
                "UPDATE device_activation_policies SET content_hash = :hash WHERE id = :id"
            ), {"hash": "b" * 64, "id": policy_id})
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE device_activation_policies SET status = 'DEPRECATED' WHERE id = :id"
        ), {"id": policy_id})
        assert connection.scalar(text(
            "SELECT revision FROM device_activation_policies WHERE id = :id"
        ), {"id": policy_id}) == 2
    with pytest.raises(DBAPIError, match="history cannot be deleted"):
        with engine.begin() as connection:
            connection.execute(text(
                "DELETE FROM device_activation_policies WHERE id = :id"
            ), {"id": policy_id})
    engine.dispose()
