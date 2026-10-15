"""Existing device rows gain an optimistic metadata revision."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from sqlalchemy import MetaData, Table, create_engine, inspect, select, text

from icheck.models import utcnow


def test_device_metadata_revision_upgrade_and_downgrade_guard(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'device-metadata.sqlite'}"
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

    migrate("upgrade", "h7k9m1p3r5t8")
    engine = create_engine(url)
    old = Table("devices", MetaData(), autoload_with=engine)
    device_id = str(uuid4())
    with engine.begin() as connection:
        connection.execute(old.insert().values(
            id=device_id, name="legacy-switch", kind="switch",
            management_ip="198.18.2.1", site="LAB",
            labels={"environment": "lab"}, onboarding_status="pending_verification",
            enabled=True, created_by="migration.test",
            created_at=utcnow(), updated_at=utcnow(),
        ))
    engine.dispose()

    migrate("upgrade", "head")
    engine = create_engine(url)
    assert "revision" in {item["name"] for item in inspect(engine).get_columns("devices")}
    device = Table("devices", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        assert connection.execute(select(device.c.revision).where(device.c.id == device_id)).scalar_one() == 1
    engine.dispose()

    migrate("downgrade", "h7k9m1p3r5t8")
    migrate("upgrade", "head")
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("UPDATE devices SET revision = 2 WHERE id = :id"), {"id": device_id})
    engine.dispose()
    refused = migrate("downgrade", "h7k9m1p3r5t8", succeeds=False)
    assert "Cannot discard edited device metadata revisions" in refused.stderr
