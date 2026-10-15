"""Opt-in native PostgreSQL race, RLS and trigger acceptance for late usage."""

from concurrent.futures import ThreadPoolExecutor
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from icheck.database import set_session_namespace
from icheck.models import AIAuthoringQuotaSettlementConflict
from icheck.services.ai_authoring_quota import (
    AuthoringQuotaConflict, reserve_authoring_tokens, settle_authoring_tokens,
)


URL = os.getenv("ICHECK_QUOTA_POSTGRES_TEST_URL")
ACK = os.getenv("ICHECK_QUOTA_POSTGRES_ACK")


@pytest.mark.skipif(
    not URL or ACK != "I_ACK_DISPOSABLE_QUOTA_DB",
    reason="Dedicated PostgreSQL quota DB not acknowledged",
)
@pytest.mark.parametrize("_round_number", range(3))
def test_native_late_settlement_race_and_rls(_round_number):
    engine = create_engine(URL, poolclass=NullPool, isolation_level="READ COMMITTED")
    try:
        with engine.begin() as connection:
            assert connection.scalar(text("SELECT current_database()")).startswith("icheck_quota_acceptance")
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "e4g6i8k0m2n5"
            connection.execute(text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'icheck_quota_conflict_runtime') "
                "THEN CREATE ROLE icheck_quota_conflict_runtime NOLOGIN; END IF; END $$"
            ))
            connection.execute(text("GRANT USAGE ON SCHEMA public TO icheck_quota_conflict_runtime"))
            connection.execute(text(
                "GRANT SELECT, UPDATE ON ai_authoring_quota_reservations "
                "TO icheck_quota_conflict_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT, INSERT ON ai_authoring_quota_settlement_conflicts, audit_events "
                "TO icheck_quota_conflict_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT ON ai_authoring_quota_adjustments "
                "TO icheck_quota_conflict_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT ON ai_authoring_quota_supplement_adjustments "
                "TO icheck_quota_conflict_runtime"
            ))
        tenant_id, region_id = str(uuid4()), str(uuid4())
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            receipt_id = reserve_authoring_tokens(
                db, actor="l1.operator", entity_type="investigation_step",
                entity_id=str(uuid4()), token_budget=100,
            )
            settle_authoring_tokens(
                db, receipt_id, known_tokens=20, external_charge_unknown=True,
            )

        def contend() -> str:
            with Session(engine) as db:
                db.execute(text("SET ROLE icheck_quota_conflict_runtime"))
                set_session_namespace(db, tenant_id, region_id)
                try:
                    settle_authoring_tokens(
                        db, receipt_id, known_tokens=80,
                        external_charge_unknown=False,
                    )
                except AuthoringQuotaConflict:
                    return "recorded_conflict"
                return "unexpected_success"

        with ThreadPoolExecutor(max_workers=2) as workers:
            outcomes = list(workers.map(lambda _: contend(), range(2)))
        assert outcomes == ["recorded_conflict", "recorded_conflict"]
        with Session(engine) as db:
            db.execute(text("SET ROLE icheck_quota_conflict_runtime"))
            set_session_namespace(db, tenant_id, region_id)
            rows = db.scalars(select(AIAuthoringQuotaSettlementConflict)).all()
            assert len(rows) == 1
            assert rows[0].reported_known_tokens == 80
        with Session(engine) as db:
            db.execute(text("SET ROLE icheck_quota_conflict_runtime"))
            set_session_namespace(db, str(uuid4()), str(uuid4()))
            assert db.scalar(text("SELECT COUNT(*) FROM ai_authoring_quota_settlement_conflicts")) == 0
        with pytest.raises(DBAPIError, match="append-only"):
            with Session(engine) as db:
                set_session_namespace(db, tenant_id, region_id)
                db.execute(text(
                    "UPDATE ai_authoring_quota_settlement_conflicts "
                    "SET reported_known_tokens=0 WHERE reservation_id=:receipt_id"
                ), {"receipt_id": receipt_id})
                db.commit()
    finally:
        engine.dispose()
