"""Legacy scoped deployments gain a binding, with a guarded rollback."""

from __future__ import annotations

from datetime import timedelta
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from sqlalchemy import MetaData, Table, create_engine, inspect, select, text

from icheck.models import utcnow


def test_collector_identity_binding_migration_preserves_legacy_rows(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'collector-identity.sqlite'}"
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

    migrate("upgrade", "j9l1n3p5r7t0")
    engine = create_engine(url)
    device = Table("devices", MetaData(), autoload_with=engine)
    deployment = Table("collector_deployments", MetaData(), autoload_with=engine)
    device_id, deployment_id = str(uuid4()), str(uuid4())
    now = utcnow()
    with engine.begin() as connection:
        connection.execute(device.insert().values(
            id=device_id, name="legacy-scoped-device", kind="switch",
            management_ip="198.18.42.1", site="LAB", labels={},
            onboarding_status="pending_verification", enabled=True,
            revision=1, created_by="migration.test", created_at=now, updated_at=now,
        ))
        connection.execute(deployment.insert().values(
            id=deployment_id, name="legacy-scoped-collector",
            artifact_version_id=str(uuid4()), scope_device_id=device_id,
            scope_site="LAB", target={"url": "https://example.test"},
            configuration={}, worker_selector={"site": "LAB"},
            execution_mode="scheduled", schedule_seconds=300,
            enabled=True, next_run_at=now,
            lease_expires_at=now + timedelta(hours=1),
            created_by="migration.test", created_at=now, updated_at=now,
        ))
    engine.dispose()

    refused = migrate("upgrade", "head", succeeds=False)
    assert "Drain active device-scoped Collector leases" in refused.stderr
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE collector_deployments "
            "SET lease_expires_at = :expired, lease_token_hash = :token "
            "WHERE id = :id"
        ), {
            "id": deployment_id,
            "expired": now - timedelta(hours=1),
            "token": "0" * 64,
        })
    engine.dispose()

    migrate("upgrade", "head")
    engine = create_engine(url)
    device = Table("devices", MetaData(), autoload_with=engine)
    deployment = Table("collector_deployments", MetaData(), autoload_with=engine)
    assert "identity_revision" in {col["name"] for col in inspect(engine).get_columns("devices")}
    assert "scope_device_identity_revision" in {
        col["name"] for col in inspect(engine).get_columns("collector_deployments")
    }
    with engine.connect() as connection:
        assert connection.execute(select(device.c.identity_revision)).scalar_one() == 1
        legacy_state = connection.execute(select(
            deployment.c.scope_device_identity_revision,
            deployment.c.enabled,
            deployment.c.next_run_at,
            deployment.c.lease_expires_at,
            deployment.c.lease_token_hash,
        )).one()
        assert legacy_state.scope_device_identity_revision == 0
        assert legacy_state.enabled is False
        assert legacy_state.next_run_at is None
        assert legacy_state.lease_expires_at is None
        assert legacy_state.lease_token_hash is None
    engine.dispose()

    refused = migrate("downgrade", "j9l1n3p5r7t0", succeeds=False)
    assert "Cannot discard reviewed Collector target classifications" in refused.stderr

    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(
            "DELETE FROM collector_deployments WHERE id = :id"
        ), {"id": deployment_id})
    engine.dispose()
    migrate("downgrade", "k0m2p4r6t8v1")
    migrate("downgrade", "j9l1n3p5r7t0")
    migrate("upgrade", "head")

    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE devices SET identity_revision = 2 WHERE id = :id"
        ), {"id": device_id})
    engine.dispose()
    migrate("downgrade", "k0m2p4r6t8v1")
    refused = migrate("downgrade", "j9l1n3p5r7t0", succeeds=False)
    assert "Cannot discard device collector identity bindings" in refused.stderr
