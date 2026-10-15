"""Existing activation policies survive the editable-draft schema upgrade."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from sqlalchemy import MetaData, Table, create_engine, inspect, select, text

from icheck.models import utcnow


def test_activation_policy_draft_revision_upgrade_and_downgrade_guard(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'activation-policy-revisions.sqlite'}"
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

    migrate("upgrade", "e4g6i8k0m2n5")
    engine = create_engine(url)
    old = Table("device_activation_policies", MetaData(), autoload_with=engine)
    policy_id = str(uuid4())
    with engine.begin() as connection:
        connection.execute(old.insert().values(
            id=policy_id, name="legacy-controller-inventory", version=1,
            status="DRAFT", protocol="https_api", adapter_type="http_json",
            artifact_version_id=str(uuid4()), target_template={},
            configuration_defaults={}, worker_selector={},
            execution_mode="SCHEDULED", schedule_seconds=300,
            created_by="migration.test", created_at=utcnow(),
        ))
    engine.dispose()

    migrate("upgrade", "head")
    engine = create_engine(url)
    columns = {column["name"] for column in inspect(engine).get_columns("device_activation_policies")}
    assert {"revision", "updated_by", "updated_at"} <= columns
    policy = Table("device_activation_policies", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        row = connection.execute(select(policy).where(policy.c.id == policy_id)).one()
    assert row.revision == 1
    assert row.updated_by is None
    assert row.updated_at is None
    engine.dispose()
    migrate("downgrade", "e4g6i8k0m2n5")
    migrate("upgrade", "head")
    engine = create_engine(url)
    policy = Table("device_activation_policies", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        assert connection.execute(select(policy.c.revision).where(policy.c.id == policy_id)).scalar_one() == 1
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE device_activation_policies SET schedule_seconds = 120, "
            "revision = 2, updated_by = 'migration.test', updated_at = :now "
            "WHERE id = :id"
        ), {"id": policy_id, "now": utcnow()})
    engine.dispose()
    refused = migrate("downgrade", "e4g6i8k0m2n5", succeeds=False)
    assert "Cannot discard activation policy draft edit revisions" in refused.stderr
