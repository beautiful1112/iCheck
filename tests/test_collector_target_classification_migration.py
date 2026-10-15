"""Legacy generated deployments need endpoint review before migration resumes them."""

from __future__ import annotations

from datetime import timedelta
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from sqlalchemy import MetaData, Table, create_engine, inspect, select, text

from icheck.models import utcnow


def test_legacy_generated_collector_is_disabled_until_target_review(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'target-classification.sqlite'}"
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

    migrate("upgrade", "k0m2p4r6t8v1")
    engine = create_engine(url)
    metadata = MetaData()
    artifacts = Table("artifacts", metadata, autoload_with=engine)
    versions = Table("artifact_versions", metadata, autoload_with=engine)
    deployments = Table("collector_deployments", metadata, autoload_with=engine)
    devices = Table("devices", metadata, autoload_with=engine)
    now = utcnow()
    generated_id = generated_version_id = ordinary_id = None
    direct_id, mismatched_id, device_id = str(uuid4()), str(uuid4()), str(uuid4())
    with engine.begin() as connection:
        for generated in (True, False):
            artifact_id, version_id, deployment_id = (
                str(uuid4()), str(uuid4()), str(uuid4())
            )
            connection.execute(artifacts.insert().values(
                id=artifact_id,
                name="studio-generated" if generated else "ordinary-collector",
                kind="COLLECTOR", description="migration fixture", owner="migration.test",
                labels={"generated": generated}, created_at=now, updated_at=now,
            ))
            connection.execute(versions.insert().values(
                id=version_id, artifact_id=artifact_id, version=1, status="PUBLISHED",
                definition={}, implementation={}, tests=[], validation_report={},
                created_by="migration.test", created_at=now,
            ))
            connection.execute(deployments.insert().values(
                id=deployment_id,
                name="generated-deployment" if generated else "ordinary-deployment",
                artifact_version_id=version_id, scope_device_id=None,
                scope_device_identity_revision=None,
                target={"url": "https://inventory.example.test/assets"},
                configuration={}, worker_selector={"site": "LAB"},
                execution_mode="SCHEDULED", schedule_seconds=300,
                enabled=True, next_run_at=now,
                lease_expires_at=(now + timedelta(hours=1)) if generated else None,
                created_by="migration.test", created_at=now, updated_at=now,
            ))
            if generated:
                generated_id = deployment_id
                generated_version_id = version_id
            else:
                ordinary_id = deployment_id
        connection.execute(devices.insert().values(
            id=device_id, name="legacy-studio-switch", kind="switch",
            management_ip="198.18.42.1", site="LAB", labels={},
            onboarding_status="pending_verification", enabled=True,
            revision=1, identity_revision=1,
            created_by="migration.test", created_at=now, updated_at=now,
        ))
        for deployment_id, name, endpoint_url, expires in (
            (direct_id, "generated-scoped-direct", "http://198.18.42.1/assets", None),
            (mismatched_id, "generated-scoped-proxy", "https://api.example.test/assets", now + timedelta(hours=1)),
        ):
            connection.execute(deployments.insert().values(
                id=deployment_id, name=name,
                artifact_version_id=generated_version_id,
                scope_device_id=device_id, scope_device_identity_revision=1,
                scope_site="LAB", target={"url": endpoint_url},
                configuration={}, worker_selector={"site": "LAB"},
                execution_mode="SCHEDULED", schedule_seconds=300,
                enabled=True, next_run_at=now, lease_expires_at=expires,
                created_by="migration.test", created_at=now, updated_at=now,
            ))
    engine.dispose()
    assert generated_id and generated_version_id and ordinary_id

    refused = migrate("upgrade", "head", succeeds=False)
    assert "Drain active unscoped Studio Collector leases" in refused.stderr
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE collector_deployments SET lease_expires_at = :expired, "
            "lease_token_hash = :token WHERE id = :id"
        ), {
            "id": generated_id,
            "expired": now - timedelta(hours=1),
            "token": "0" * 64,
        })
    engine.dispose()

    refused = migrate("upgrade", "head", succeeds=False)
    assert "Drain active scoped Studio Collector leases" in refused.stderr
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE collector_deployments SET lease_expires_at = :expired, "
            "lease_token_hash = :token WHERE id = :id"
        ), {
            "id": mismatched_id,
            "expired": now - timedelta(hours=1),
            "token": "1" * 64,
        })
    engine.dispose()

    migrate("upgrade", "head")
    engine = create_engine(url)
    deployments = Table("collector_deployments", MetaData(), autoload_with=engine)
    assert "target_classification" in {
        column["name"] for column in inspect(engine).get_columns("collector_deployments")
    }
    with engine.connect() as connection:
        generated = connection.execute(select(deployments).where(
            deployments.c.id == generated_id
        )).one()
        ordinary = connection.execute(select(deployments).where(
            deployments.c.id == ordinary_id
        )).one()
        direct = connection.execute(select(deployments).where(
            deployments.c.id == direct_id
        )).one()
        mismatched = connection.execute(select(deployments).where(
            deployments.c.id == mismatched_id
        )).one()
        assert generated.target_classification == "legacy_unreviewed"
        assert generated.enabled is False
        assert generated.next_run_at is None
        assert generated.lease_expires_at is None
        assert generated.lease_token_hash is None
        assert ordinary.target_classification is None
        assert ordinary.enabled is True
        assert direct.target_classification == "registered_device"
        assert direct.enabled is True
        assert mismatched.target_classification == "legacy_unreviewed"
        assert mismatched.enabled is False
        assert mismatched.next_run_at is None
        assert mismatched.lease_expires_at is None
        assert mismatched.lease_token_hash is None
    engine.dispose()

    refused = migrate("downgrade", "k0m2p4r6t8v1", succeeds=False)
    assert "Cannot discard reviewed Collector target classifications" in refused.stderr
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(
            "DELETE FROM collector_deployments WHERE id IN (:unscoped, :direct, :proxy)"
        ), {"unscoped": generated_id, "direct": direct_id, "proxy": mismatched_id})
    engine.dispose()
    migrate("downgrade", "k0m2p4r6t8v1")
