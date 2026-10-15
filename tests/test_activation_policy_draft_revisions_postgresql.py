"""Opt-in native PostgreSQL contention acceptance for editable policy drafts."""

from concurrent.futures import ThreadPoolExecutor
import os
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from icheck.activation_schemas import ActivationPolicyDraftUpdate, DeviceActivationPolicyCreate
from icheck.database import set_session_namespace
from icheck.models import AuditEvent, DeviceActivationPolicy
from icheck.services.activation import (
    ActivationPolicyRevisionConflict,
    create_activation_policy,
    publish_activation_policy,
    update_activation_policy_draft,
    validate_activation_policy,
)
from test_activation_catalog_pagination import _add_entry


URL = os.getenv("ICHECK_ACTIVATION_DRAFT_POSTGRES_TEST_URL")
ACK = os.getenv("ICHECK_ACTIVATION_DRAFT_POSTGRES_ACK")
RUNTIME_ROLE = "icheck_activation_draft_runtime"


@pytest.mark.skipif(
    not URL or ACK != "I_ACK_DISPOSABLE_ACTIVATION_DRAFT_DB",
    reason="Dedicated PostgreSQL activation-draft DB not acknowledged",
)
@pytest.mark.parametrize("_round_number", range(5))
def test_native_draft_revision_race_has_one_winner_and_one_audit(_round_number):
    engine = create_engine(URL, poolclass=NullPool, isolation_level="READ COMMITTED")
    try:
        with engine.begin() as connection:
            assert connection.scalar(text("SELECT current_database()")) == (
                "icheck_activation_draft_acceptance"
            )
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "h7k9m1p3r5t8"
            )
            connection.execute(text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
                "'icheck_activation_draft_runtime') THEN CREATE ROLE "
                "icheck_activation_draft_runtime NOLOGIN; END IF; END $$"
            ))
            connection.execute(text(
                "GRANT USAGE ON SCHEMA public TO icheck_activation_draft_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT ON artifacts, artifact_versions, collector_definitions "
                "TO icheck_activation_draft_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT, UPDATE ON device_activation_policies "
                "TO icheck_activation_draft_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT, INSERT ON audit_events "
                "TO icheck_activation_draft_runtime"
            ))
        tenant_id, region_id = str(uuid4()), str(uuid4())
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            version_id = _add_entry(
                db, 42, tenant_id=tenant_id, region_id=region_id,
            )
            db.flush()
            policy_id = db.scalar(select(DeviceActivationPolicy.id).where(
                DeviceActivationPolicy.artifact_version_id == version_id,
            ))
            assert policy_id is not None
            db.commit()

        barrier = Barrier(2)

        def revise(interval: int) -> tuple[str, int]:
            draft = DeviceActivationPolicyCreate(
                name="policy-042", protocol="https_api",
                artifact_version_id=version_id,
                target_template={"url": "https://${management_ip}:${port}/api/inventory"},
                configuration_defaults={}, worker_selector={},
                schedule_seconds=interval, created_by="test.operator",
            )
            payload = ActivationPolicyDraftUpdate(
                expected_revision=1, draft=draft, actor=f"editor.{interval}",
            )
            with Session(engine) as db:
                db.execute(text(f"SET ROLE {RUNTIME_ROLE}"))
                set_session_namespace(db, tenant_id, region_id)
                barrier.wait(timeout=20)
                try:
                    changed = update_activation_policy_draft(db, policy_id, payload)
                    return "updated", changed.schedule_seconds
                except ActivationPolicyRevisionConflict:
                    return "conflict", interval

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(revise, (120, 180)))
        assert sorted(status for status, _ in results) == ["conflict", "updated"]
        winner_interval = next(interval for status, interval in results if status == "updated")

        with Session(engine) as db:
            db.execute(text(f"SET ROLE {RUNTIME_ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            policy = db.scalar(select(DeviceActivationPolicy).where(
                DeviceActivationPolicy.id == policy_id,
            ))
            assert policy is not None
            assert (policy.version, policy.revision, policy.schedule_seconds) == (
                1, 2, winner_interval,
            )
            assert db.scalar(select(func.count()).select_from(AuditEvent).where(
                AuditEvent.event_type == "device.activation_policy.draft_updated",
                AuditEvent.entity_id == policy_id,
            )) == 1
            with pytest.raises(ActivationPolicyRevisionConflict):
                validate_activation_policy(db, policy, "test.reviewer", expected_revision=1)
            validated = validate_activation_policy(
                db, policy, "test.reviewer", expected_revision=2,
            )
            assert validated.content_hash is not None
            assert validated.status.value == "validated"
        for tampering in (
            "UPDATE device_activation_policies SET schedule_seconds = 60 WHERE id = :id",
            "UPDATE device_activation_policies SET status = 'DRAFT' WHERE id = :id",
        ):
            with pytest.raises(DBAPIError, match="lifecycle is sealed"):
                with Session(engine) as db:
                    db.execute(text(f"SET ROLE {RUNTIME_ROLE}"))
                    set_session_namespace(db, tenant_id, region_id)
                    db.execute(text(tampering), {"id": policy_id})
                    db.commit()
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {RUNTIME_ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            policy = db.get(DeviceActivationPolicy, policy_id)
            assert policy is not None
            published = publish_activation_policy(db, policy, "test.publisher")
            assert published.status.value == "published"
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            next_version = create_activation_policy(db, DeviceActivationPolicyCreate(
                name="policy-042", protocol="https_api",
                artifact_version_id=version_id,
                target_template={"url": "https://${management_ip}:${port}/api/inventory"},
                configuration_defaults={}, worker_selector={},
                schedule_seconds=300, created_by="test.operator",
            ))
            assert next_version.version == 2
            validate_activation_policy(
                db, next_version, "test.reviewer", expected_revision=1,
            )
            publish_activation_policy(db, next_version, "test.publisher")
            next_version_id = next_version.id
            previous = db.get(DeviceActivationPolicy, policy_id)
            assert previous is not None and previous.status.value == "deprecated"
        with pytest.raises(DBAPIError, match="lifecycle is sealed"):
            with Session(engine) as db:
                db.execute(text(f"SET ROLE {RUNTIME_ROLE}"))
                set_session_namespace(db, tenant_id, region_id)
                db.execute(text(
                    "UPDATE device_activation_policies SET schedule_seconds = 60 "
                    "WHERE id = :id"
                ), {"id": next_version_id})
                db.commit()
        for foreign_namespace in (
            (str(uuid4()), region_id),
            (tenant_id, str(uuid4())),
        ):
            with Session(engine) as db:
                db.execute(text(f"SET ROLE {RUNTIME_ROLE}"))
                set_session_namespace(db, *foreign_namespace)
                assert db.scalar(text(
                    "SELECT COUNT(*) FROM device_activation_policies WHERE id = :id"
                ), {"id": policy_id}) == 0
                assert db.execute(text(
                    "UPDATE device_activation_policies SET schedule_seconds = 60 "
                    "WHERE id = :id"
                ), {"id": policy_id}).rowcount == 0
                assert db.scalar(select(DeviceActivationPolicy.id).where(
                    DeviceActivationPolicy.id == policy_id,
                )) is None
                with pytest.raises(LookupError, match="not found"):
                    update_activation_policy_draft(db, policy_id, ActivationPolicyDraftUpdate(
                        expected_revision=2,
                        draft=DeviceActivationPolicyCreate(
                            name="policy-042", protocol="https_api",
                            artifact_version_id=version_id, created_by="foreign.operator",
                        ),
                        actor="foreign.operator",
                    ))
    finally:
        engine.dispose()
