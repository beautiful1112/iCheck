"""Opt-in, destructive-only-to-dedicated-DB native quota contention acceptance."""

from concurrent.futures import ThreadPoolExecutor
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from icheck.database import set_session_namespace
from icheck.models import AIAuthoringQuotaBucket, AIAuthoringQuotaReservation
from icheck.services.ai_authoring_quota import (
    AuthoringQuotaExceeded,
    authoring_quota_snapshot,
    configure_authoring_quota,
    list_authoring_reservations,
    reserve_authoring_tokens,
    settle_authoring_tokens,
)


URL = os.getenv("ICHECK_QUOTA_POSTGRES_TEST_URL")
ACK = os.getenv("ICHECK_QUOTA_POSTGRES_ACK")


@pytest.mark.skipif(not URL or ACK != "I_ACK_DISPOSABLE_QUOTA_DB", reason="Dedicated PostgreSQL quota DB not acknowledged")
@pytest.mark.parametrize("_round_number", range(5))
def test_native_postgresql_quota_lock_and_rls(_round_number):
    engine = create_engine(URL, poolclass=NullPool, isolation_level="READ COMMITTED")
    try:
        with engine.begin() as connection:
            database_name = connection.scalar(text("SELECT current_database()"))
            assert database_name.startswith("icheck_quota_acceptance")
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "e4g6i8k0m2n5"
            connection.execute(text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'icheck_quota_runtime') "
                "THEN CREATE ROLE icheck_quota_runtime NOLOGIN; END IF; END $$"
            ))
            connection.execute(text(
                "GRANT USAGE ON SCHEMA public TO icheck_quota_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT, INSERT, UPDATE ON ai_authoring_quota_policies, "
                "ai_authoring_quota_buckets, ai_authoring_quota_reservations "
                "TO icheck_quota_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT ON ai_authoring_quota_adjustments TO icheck_quota_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT ON ai_authoring_quota_supplement_adjustments "
                "TO icheck_quota_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT, INSERT ON ai_authoring_quota_settlement_conflicts "
                "TO icheck_quota_runtime"
            ))
            connection.execute(text(
                "GRANT SELECT, INSERT ON audit_events TO icheck_quota_runtime"
            ))

        tenant_id, region_id = str(uuid4()), str(uuid4())
        other_tenant, other_region = str(uuid4()), str(uuid4())
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            configure_authoring_quota(
                db, actor="quota-admin", expected_revision=1,
                daily_token_limit=100, actor_daily_token_limit=100,
                reason="Verify independent PostgreSQL quota contenders.",
            )

        def contender() -> tuple[str, str | None]:
            with Session(engine) as db:
                db.execute(text("SET ROLE icheck_quota_runtime"))
                set_session_namespace(db, tenant_id, region_id)
                try:
                    receipt = reserve_authoring_tokens(
                        db, actor="operator@example.test",
                        entity_type="quota_acceptance", entity_id=str(uuid4()),
                        token_budget=100,
                    )
                    return "admitted", receipt
                except AuthoringQuotaExceeded:
                    return "denied", None

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: contender(), range(2)))
        assert sorted(result[0] for result in results) == ["admitted", "denied"]
        winning_receipt = next(value for status, value in results if status == "admitted")
        assert winning_receipt is not None

        with Session(engine) as db:
            db.execute(text("SET ROLE icheck_quota_runtime"))
            set_session_namespace(db, tenant_id, region_id)
            snapshot = authoring_quota_snapshot(db, actor="operator@example.test")
            assert snapshot["namespace_used"] == 100
            assert snapshot["actor_used"] == 100
            assert snapshot["pending_requests"] == 1
            settle_authoring_tokens(
                db, winning_receipt, known_tokens=42,
                external_charge_unknown=False,
            )
            settled = authoring_quota_snapshot(db, actor="operator@example.test")
            assert settled["namespace_used"] == 42
            assert settled["actor_used"] == 42
            assert settled["pending_requests"] == 0
            rows, cursor = list_authoring_reservations(
                db, actor="operator@example.test", state="all", limit=1,
            )
            assert cursor is None
            assert [row.id for row in rows] == [winning_receipt]

        with Session(engine) as db:
            db.execute(text("SET ROLE icheck_quota_runtime"))
            set_session_namespace(db, other_tenant, other_region)
            # Raw SQL bypasses ORM filtering and therefore tests actual RLS.
            assert db.scalar(text("SELECT COUNT(*) FROM ai_authoring_quota_reservations")) == 0
            assert db.scalar(text("SELECT COUNT(*) FROM ai_authoring_quota_buckets")) == 0
            assert authoring_quota_snapshot(db, actor="operator@example.test")["actor_used"] == 0
            assert list_authoring_reservations(
                db, actor="operator@example.test", state="all", limit=1,
            ) == ([], None)

        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            assert db.scalar(select(func.count()).select_from(AIAuthoringQuotaReservation)) == 1
            receipt = db.scalar(select(AIAuthoringQuotaReservation))
            assert receipt is not None
            assert receipt.source_entity_type == "quota_acceptance"
            assert receipt.source_entity_id == receipt.entity_id
            assert db.scalar(select(func.sum(AIAuthoringQuotaBucket.used_tokens)).where(
                AIAuthoringQuotaBucket.scope_kind == "namespace",
            )) == 42
        with pytest.raises(DBAPIError, match="AI quota reservation is sealed"):
            with Session(engine) as db:
                set_session_namespace(db, tenant_id, region_id)
                db.execute(text(
                    "UPDATE ai_authoring_quota_reservations "
                    "SET source_entity_id = :forged WHERE id = :receipt_id"
                ), {"forged": str(uuid4()), "receipt_id": winning_receipt})
                db.commit()
    finally:
        engine.dispose()
