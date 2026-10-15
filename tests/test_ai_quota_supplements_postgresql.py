"""Opt-in native PostgreSQL supplement race, RLS and sealed-ledger acceptance."""

from concurrent.futures import ThreadPoolExecutor
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from icheck.database import set_session_namespace
from icheck.models import (
    AIAuthoringQuotaAdjustment,
    AIAuthoringQuotaReservation,
    AIAuthoringQuotaSupplementAdjustment,
)
from icheck.services.ai_authoring_quota import (
    AuthoringQuotaConflict, reserve_authoring_tokens, settle_authoring_tokens,
)
from icheck.services.ai_quota_reconciliation import (
    propose_quota_reconciliation, review_quota_reconciliation,
)
from icheck.services.ai_quota_supplements import propose_supplement, review_supplement
from icheck.services.control_plane_auth import PrincipalContext


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
def test_native_supplement_review_race_and_rls(_round_number):
    engine = create_engine(URL, poolclass=NullPool, isolation_level="READ COMMITTED")
    try:
        with engine.begin() as connection:
            assert connection.scalar(text("SELECT current_database()")).startswith("icheck_quota_acceptance")
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "e4g6i8k0m2n5"
            connection.execute(text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'icheck_quota_supplement_runtime') "
                "THEN CREATE ROLE icheck_quota_supplement_runtime NOLOGIN; END IF; END $$"
            ))
            connection.execute(text("GRANT USAGE ON SCHEMA public TO icheck_quota_supplement_runtime"))
            connection.execute(text(
                "GRANT SELECT, UPDATE ON ai_authoring_quota_reservations, "
                "ai_authoring_quota_supplement_cases, ai_authoring_quota_buckets "
                "TO icheck_quota_supplement_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT, INSERT ON ai_authoring_quota_supplement_adjustments, audit_events "
                "TO icheck_quota_supplement_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT ON ai_authoring_quota_adjustments, "
                "ai_authoring_quota_settlement_conflicts "
                "TO icheck_quota_supplement_runtime"
            ))
        tenant_id, region_id = str(uuid4()), str(uuid4())
        proposer, first_reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            receipt_id = reserve_authoring_tokens(
                db, actor="l1.operator", entity_type="investigation_step",
                entity_id=str(uuid4()), token_budget=100,
            )
            settle_authoring_tokens(db, receipt_id, known_tokens=37, external_charge_unknown=True)
            first_case = propose_quota_reconciliation(
                db, reservation_id=receipt_id, confirmed_total_tokens=37,
                evidence_sha256="a" * 64,
                evidence_reference="first-provider-export-row-42",
                reason="The first provider statement confirms a thirty-seven-token total.",
                actor=proposer,
            )
            review_quota_reconciliation(
                db, case_id=first_case.id, decision="approve",
                reason="I independently checked the first provider statement.",
                actor=first_reviewer,
            )
            first_id = db.scalar(select(AIAuthoringQuotaAdjustment).where(
                AIAuthoringQuotaAdjustment.reservation_id == receipt_id,
            )).id
            with pytest.raises(AuthoringQuotaConflict):
                settle_authoring_tokens(db, receipt_id, known_tokens=80, external_charge_unknown=False)
            case = propose_supplement(
                db, reservation_id=receipt_id, confirmed_total_tokens=80,
                evidence_sha256="b" * 64,
                evidence_reference="corrected-provider-export-row-42",
                reason="The corrected provider statement confirms the higher total.",
                actor=proposer,
            )
            case_id = case.id

        def contend() -> str:
            reviewer = _admin(f"supplement-reviewer-{uuid4()}@example.test")
            with Session(engine) as db:
                db.execute(text("SET ROLE icheck_quota_supplement_runtime"))
                set_session_namespace(db, tenant_id, region_id)
                try:
                    review_supplement(
                        db, case_id=case_id, decision="approve",
                        reason="Independent corrected statement and ledger head checked.",
                        actor=reviewer,
                    )
                    return "applied"
                except AuthoringQuotaConflict:
                    return "conflict"

        with ThreadPoolExecutor(max_workers=2) as workers:
            outcomes = list(workers.map(lambda _: contend(), range(2)))
        assert sorted(outcomes) == ["applied", "conflict"]
        with Session(engine) as db:
            db.execute(text("SET ROLE icheck_quota_supplement_runtime"))
            set_session_namespace(db, tenant_id, region_id)
            rows = db.scalars(select(AIAuthoringQuotaSupplementAdjustment)).all()
            assert len(rows) == 1
            assert rows[0].base_adjustment_id == first_id
            assert rows[0].sequence == 1
            assert rows[0].delta_tokens == 43
            receipt = db.get(AIAuthoringQuotaReservation, receipt_id)
            assert receipt.charged_tokens == 100
            assert receipt.effective_charged_tokens == 80
            assert db.scalar(text(
                "SELECT used_tokens FROM ai_authoring_quota_buckets "
                "WHERE scope_kind='namespace'"
            )) == 80
        with Session(engine) as db:
            db.execute(text("SET ROLE icheck_quota_supplement_runtime"))
            set_session_namespace(db, str(uuid4()), str(uuid4()))
            assert db.scalar(text("SELECT COUNT(*) FROM ai_authoring_quota_supplement_cases")) == 0
            assert db.scalar(text("SELECT COUNT(*) FROM ai_authoring_quota_supplement_adjustments")) == 0
        with pytest.raises(DBAPIError, match="append-only"):
            with Session(engine) as db:
                set_session_namespace(db, tenant_id, region_id)
                db.execute(text(
                    "UPDATE ai_authoring_quota_supplement_adjustments SET delta_tokens=0 "
                    "WHERE supplement_case_id=:case_id"
                ), {"case_id": case_id})
                db.commit()
    finally:
        engine.dispose()
