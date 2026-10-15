"""Opt-in native PostgreSQL acceptance for proposal-sourced orphan holds."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from icheck.database import set_session_namespace
from icheck.models import (
    AIAuthoringQuotaBucket,
    AIAuthoringQuotaOrphanClosure,
    AIAuthoringQuotaReservation,
    ActivationPolicyProposal,
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
)
from icheck.services.ai_authoring_quota import AuthoringQuotaConflict
from icheck.services.ai_quota_orphan_recovery import (
    list_orphan_candidates,
    propose_orphan_closure,
    review_orphan_closure,
)
from icheck.services.audit import record_audit_event
from icheck.services.control_plane_auth import PrincipalContext


URL = os.getenv("ICHECK_QUOTA_PROPOSAL_POSTGRES_TEST_URL")
ACK = os.getenv("ICHECK_QUOTA_PROPOSAL_POSTGRES_ACK")
ROLE = "icheck_quota_proposal_runtime"


def _admin(subject: str) -> PrincipalContext:
    return PrincipalContext(
        principal_id=str(uuid4()), subject=subject, principal_type="user",
        permissions=frozenset({"ai.manage"}), role_names=("admin",),
        authorization_scope={"all": True}, auth_method="bearer",
    )


@pytest.mark.skipif(
    not URL or ACK != "I_ACK_DISPOSABLE_PROPOSAL_QUOTA_DB",
    reason="Dedicated PostgreSQL proposal quota DB not acknowledged",
)
def test_native_proposal_orphan_review_race_and_rls():
    engine = create_engine(URL, poolclass=NullPool, isolation_level="READ COMMITTED")
    try:
        with engine.begin() as connection:
            assert connection.scalar(text("SELECT current_database()")) == (
                "icheck_quota_proposal_acceptance"
            )
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "h7k9m1p3r5t8"
            )
            connection.execute(text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
                "'icheck_quota_proposal_runtime') THEN CREATE ROLE "
                "icheck_quota_proposal_runtime NOLOGIN NOBYPASSRLS; END IF; END $$"
            ))
            connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {ROLE}"))
            for privileges, tables in (
                ("SELECT", "activation_policy_proposals, ai_authoring_quota_adjustments, "
                 "ai_authoring_quota_supplement_adjustments"),
                ("SELECT, UPDATE", "ai_authoring_quota_reservations, ai_authoring_quota_buckets"),
                ("SELECT, INSERT, UPDATE", "ai_authoring_quota_orphan_cases"),
                ("SELECT, INSERT", "ai_authoring_quota_orphan_closures, "
                 "ai_authoring_quota_orphan_audit_evidence, audit_events"),
            ):
                connection.execute(text(f"GRANT {privileges} ON {tables} TO {ROLE}"))

        tenant_id, region_id = str(uuid4()), str(uuid4())
        old = datetime.now(UTC) - timedelta(days=3)
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            artifact = Artifact(
                tenant_id=tenant_id, region_id=region_id,
                name=f"proposal-source-{uuid4()}", kind=ArtifactKind.COLLECTOR,
                owner="acceptance",
            )
            db.add(artifact)
            db.flush()
            version = ArtifactVersion(
                tenant_id=tenant_id, region_id=region_id,
                artifact_id=artifact.id, version=1,
                status=ArtifactVersionStatus.PUBLISHED, created_by="acceptance",
            )
            db.add(version)
            db.flush()
            result = {"name": "proposal-acceptance", "tokens_used": 42}
            result_hash = hashlib.sha256(json.dumps(
                result, sort_keys=True, separators=(",", ":"),
            ).encode()).hexdigest()
            proposal = ActivationPolicyProposal(
                tenant_id=tenant_id, region_id=region_id,
                artifact_version_id=version.id, protocol="https_api",
                actor="l1.operator", request_key=str(uuid4()),
                request_sha256="a" * 64, brief="Read-only controller inventory",
                status="succeeded", result_snapshot=result,
                result_sha256=result_hash, route_id="acceptance-route",
                model_id="acceptance-model", tokens_used=42,
                external_charge_unknown=True, created_at=old, updated_at=old,
            )
            db.add(proposal)
            db.flush()
            receipt = AIAuthoringQuotaReservation(
                tenant_id=tenant_id, region_id=region_id,
                entity_type="device_activation_policy_proposal", entity_id=proposal.id,
                source_entity_type="device_activation_policy_proposal",
                source_entity_id=proposal.id, actor=proposal.actor,
                period_start=old.date(), reserved_tokens=100, known_tokens=0,
                charged_tokens=100, status="reserved", external_charge_unknown=True,
                created_at=old,
            )
            db.add(receipt)
            for kind, key in (("namespace", "*"), ("actor", proposal.actor)):
                db.add(AIAuthoringQuotaBucket(
                    tenant_id=tenant_id, region_id=region_id,
                    period_start=old.date(), scope_kind=kind,
                    scope_key=key, used_tokens=100,
                ))
            db.commit()
            receipt_id, proposal_id = receipt.id, proposal.id
            record_audit_event(
                db, event_type="capability.model.completed", outcome="success",
                actor_type="agent", actor_id="l1.operator",
                entity_type="device_activation_policy_proposal", entity_id=proposal_id,
                details={
                    "route_id": "acceptance-route", "model_id": "acceptance-model",
                    "candidate_index": 0, "fallback_used": False,
                    "prompt_sha256": "b" * 64, "token_usage": 42,
                    "candidate_token_usage": 42, "external_charge_unknown": True,
                },
            )
            db.commit()

        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            assert db.scalar(text("SELECT row_security_active('activation_policy_proposals')"))
            candidates, _ = list_orphan_candidates(
                db, limit=10, cursor=None, actor=_admin("queue-admin@example.test"),
            )
            candidate = next(item for item in candidates if item[0].id == receipt_id)
            assert candidate[1] is True
            assert candidate[3].audited_known_tokens == 42
            case = propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="The exact terminal proposal and model audit were checked.",
                actor=_admin("first-admin@example.test"),
            )
            case_id = case.id

        def contend() -> str:
            with Session(engine) as db:
                db.execute(text(f"SET ROLE {ROLE}"))
                set_session_namespace(db, tenant_id, region_id)
                try:
                    review_orphan_closure(
                        db, case_id=case_id, decision="close",
                        reason="Independent source and unchanged full hold confirmed.",
                        actor=_admin(f"reviewer-{uuid4()}@example.test"),
                    )
                    return "closed"
                except AuthoringQuotaConflict:
                    return "conflict"

        with ThreadPoolExecutor(max_workers=2) as workers:
            assert sorted(workers.map(lambda _: contend(), range(2))) == [
                "closed", "conflict",
            ]
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            row = db.get(AIAuthoringQuotaReservation, receipt_id)
            assert (row.status, row.known_tokens, row.charged_tokens) == (
                "settled", 42, 100,
            )
            assert row.external_charge_unknown is True
            assert len(db.scalars(select(AIAuthoringQuotaOrphanClosure)).all()) == 1
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, str(uuid4()), str(uuid4()))
            assert db.scalar(text("SELECT COUNT(*) FROM activation_policy_proposals")) == 0
            assert db.scalar(text("SELECT COUNT(*) FROM ai_authoring_quota_orphan_cases")) == 0
    finally:
        engine.dispose()
