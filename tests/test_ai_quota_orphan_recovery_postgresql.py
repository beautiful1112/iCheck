"""Opt-in PostgreSQL two-reviewer race and RLS for abandoned AI holds."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from icheck.database import set_session_namespace
from icheck.models import (
    AIAuthoringQuotaBucket,
    AIAuthoringQuotaOrphanAuditEvidence,
    AIAuthoringQuotaOrphanClosure,
    AIAuthoringQuotaReservation,
    CapabilityStudioGenerationAttempt,
    CapabilityStudioSession,
)
from icheck.services.ai_authoring_quota import AuthoringQuotaConflict
from icheck.services.ai_quota_orphan_recovery import (
    propose_orphan_closure, review_orphan_closure,
)
from icheck.services.control_plane_auth import PrincipalContext
from icheck.services.audit import record_audit_event


URL = os.getenv("ICHECK_QUOTA_POSTGRES_TEST_URL")
ACK = os.getenv("ICHECK_QUOTA_POSTGRES_ACK")


def _admin(subject: str) -> PrincipalContext:
    return PrincipalContext(
        principal_id=str(uuid4()), subject=subject, principal_type="user",
        permissions=frozenset({"ai.manage"}), role_names=("admin",),
        authorization_scope={"all": True}, auth_method="bearer",
    )


@pytest.mark.skipif(
    not URL or ACK != "I_ACK_DISPOSABLE_QUOTA_DB",
    reason="Dedicated PostgreSQL quota DB not acknowledged",
)
@pytest.mark.parametrize("_round_number", range(3))
def test_native_orphan_review_race_and_rls(_round_number):
    known_tokens = 120 if _round_number == 1 else 42
    charged_tokens = max(100, known_tokens)
    engine = create_engine(URL, poolclass=NullPool, isolation_level="READ COMMITTED")
    try:
        with engine.begin() as connection:
            assert connection.scalar(text("SELECT current_database()")).startswith("icheck_quota_acceptance")
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "e4g6i8k0m2n5"
            connection.execute(text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'icheck_quota_orphan_runtime') "
                "THEN CREATE ROLE icheck_quota_orphan_runtime NOLOGIN; END IF; END $$"
            ))
            connection.execute(text("GRANT USAGE ON SCHEMA public TO icheck_quota_orphan_runtime"))
            connection.execute(text(
                "GRANT SELECT, UPDATE ON ai_authoring_quota_reservations, "
                "ai_authoring_quota_orphan_cases TO icheck_quota_orphan_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT, INSERT ON ai_authoring_quota_orphan_closures, audit_events "
                "TO icheck_quota_orphan_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT ON ai_authoring_quota_orphan_audit_evidence "
                "TO icheck_quota_orphan_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT ON capability_studio_generation_attempts, "
                "ai_authoring_quota_adjustments "
                "TO icheck_quota_orphan_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT, UPDATE ON ai_authoring_quota_buckets "
                "TO icheck_quota_orphan_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT ON ai_authoring_quota_supplement_adjustments "
                "TO icheck_quota_orphan_runtime"
            ))
        tenant_id, region_id = str(uuid4()), str(uuid4())
        old = datetime.now(UTC) - timedelta(days=3)
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            session = CapabilityStudioSession(
                tenant_id=tenant_id, region_id=region_id,
                title="Native orphan race", artifact_kind="collector", status="failed",
                route_purpose="studio.default", brief="Test terminal model attempt",
                target_url="https://device.example.test/api", sample_document={},
                created_by="l1.operator",
            )
            db.add(session)
            db.flush()
            attempt = CapabilityStudioGenerationAttempt(
                tenant_id=tenant_id, region_id=region_id,
                session_id=session.id, request_key=str(uuid4()), request_sha256="a" * 64,
                request_document={}, actor="l1.operator", status="interrupted",
                owner_sha256="b" * 64, lease_expires_at=old,
                created_at=old, updated_at=old,
            )
            db.add(attempt)
            db.flush()
            receipt = AIAuthoringQuotaReservation(
                tenant_id=tenant_id, region_id=region_id,
                entity_type="capability_studio_generation_attempt", entity_id=attempt.id,
                source_entity_type="capability_studio_generation_attempt",
                source_entity_id=attempt.id, actor="l1.operator", period_start=old.date(),
                reserved_tokens=100, known_tokens=0, charged_tokens=100,
                status="reserved", external_charge_unknown=True, created_at=old,
            )
            db.add(receipt)
            for kind, key in (("namespace", "*"), ("actor", "l1.operator")):
                db.add(AIAuthoringQuotaBucket(
                    tenant_id=tenant_id, region_id=region_id,
                    period_start=old.date(), scope_kind=kind,
                    scope_key=key, used_tokens=100,
                ))
            db.commit()
            receipt_id = receipt.id
            record_audit_event(
                db, event_type="capability.model.failed", outcome="failure",
                actor_type="agent", actor_id="l1.operator",
                entity_type="capability_studio_generation_attempt", entity_id=attempt.id,
                details={
                    "route_id": str(uuid4()), "model_id": str(uuid4()),
                    "candidate_index": 0, "prompt_sha256": "c" * 64,
                    "fallback_used": False,
                    "token_usage": known_tokens,
                    "cumulative_token_usage": known_tokens,
                    "external_charge_unknown": True,
                },
            )
            db.commit()
            case = propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="The Studio attempt is terminal and its lease has been expired for days.",
                actor=_admin("first-admin@example.test"),
            )
            case_id = case.id

        def contend() -> str:
            reviewer = _admin(f"reviewer-{uuid4()}@example.test")
            with Session(engine) as db:
                db.execute(text("SET ROLE icheck_quota_orphan_runtime"))
                set_session_namespace(db, tenant_id, region_id)
                try:
                    review_orphan_closure(
                        db, case_id=case_id, decision="close",
                        reason="Independent terminal source and unchanged full hold confirmed.",
                        actor=reviewer,
                    )
                    return "closed"
                except AuthoringQuotaConflict:
                    return "conflict"

        with ThreadPoolExecutor(max_workers=2) as workers:
            outcomes = list(workers.map(lambda _: contend(), range(2)))
        assert sorted(outcomes) == ["closed", "conflict"]
        with Session(engine) as db:
            db.execute(text("SET ROLE icheck_quota_orphan_runtime"))
            set_session_namespace(db, tenant_id, region_id)
            closure_rows = db.scalars(select(AIAuthoringQuotaOrphanClosure)).all()
            assert len(closure_rows) == 1
            assert closure_rows[0].reserved_tokens == 100
            evidence_rows = db.scalars(select(AIAuthoringQuotaOrphanAuditEvidence)).all()
            assert len(evidence_rows) == 1
            assert evidence_rows[0].known_tokens == known_tokens
            assert evidence_rows[0].event_count == 1
            row = db.get(AIAuthoringQuotaReservation, receipt_id)
            assert row.status == "settled"
            assert row.known_tokens == known_tokens
            assert row.charged_tokens == charged_tokens
            assert row.external_charge_unknown is True
            assert db.scalar(text(
                "SELECT used_tokens FROM ai_authoring_quota_buckets "
                "WHERE scope_kind='namespace'"
            )) == charged_tokens
            assert db.scalar(text(
                "SELECT used_tokens FROM ai_authoring_quota_buckets "
                "WHERE scope_kind='actor'"
            )) == charged_tokens
        with Session(engine) as db:
            db.execute(text("SET ROLE icheck_quota_orphan_runtime"))
            set_session_namespace(db, str(uuid4()), str(uuid4()))
            assert db.scalar(text("SELECT COUNT(*) FROM ai_authoring_quota_orphan_cases")) == 0
            assert db.scalar(text("SELECT COUNT(*) FROM ai_authoring_quota_orphan_closures")) == 0
            assert db.scalar(text("SELECT COUNT(*) FROM ai_authoring_quota_orphan_audit_evidence")) == 0
        with pytest.raises(DBAPIError, match="append-only"):
            with Session(engine) as db:
                set_session_namespace(db, tenant_id, region_id)
                db.execute(text(
                    "UPDATE ai_authoring_quota_orphan_closures SET reserved_tokens=1 "
                    "WHERE orphan_case_id=:case_id"
                ), {"case_id": case_id})
                db.commit()
        with pytest.raises(DBAPIError, match="append-only"):
            with Session(engine) as db:
                set_session_namespace(db, tenant_id, region_id)
                db.execute(text(
                    "UPDATE ai_authoring_quota_orphan_audit_evidence SET known_tokens=0 "
                    "WHERE orphan_case_id=:case_id"
                ), {"case_id": case_id})
                db.commit()
    finally:
        engine.dispose()
