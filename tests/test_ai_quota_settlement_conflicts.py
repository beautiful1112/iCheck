"""Late model usage is preserved without rewriting sealed quota receipts."""

from uuid import uuid4

import pytest
from sqlalchemy import func, select

from icheck.config import get_settings
from icheck.database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace
from icheck.models import AIAuthoringQuotaReservation, AIAuthoringQuotaSettlementConflict
from icheck.services.ai_authoring_quota import (
    AuthoringQuotaConflict, authoring_quota_snapshot,
    list_authoring_settlement_conflicts, reserve_authoring_tokens,
    settle_authoring_tokens,
)
from icheck.services.ai_quota_reconciliation import (
    propose_quota_reconciliation, review_quota_reconciliation,
)
from test_ai_quota_reconciliation import _admin


def _receipt(db) -> str:
    receipt_id = reserve_authoring_tokens(
        db, actor="l1.operator", entity_type="investigation_step",
        entity_id=str(uuid4()), token_budget=100,
    )
    settle_authoring_tokens(
        db, receipt_id, known_tokens=20, external_charge_unknown=True,
    )
    return receipt_id


def test_late_report_is_sealed_deduplicated_and_does_not_change_counters():
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id = _receipt(db)
        for _ in range(2):
            with pytest.raises(AuthoringQuotaConflict, match="settlement changed"):
                settle_authoring_tokens(
                    db, receipt_id, known_tokens=80,
                    external_charge_unknown=False,
                )
        rows, cursor = list_authoring_settlement_conflicts(db, limit=10)
        assert cursor is None
        assert len(rows) == 1
        conflict, receipt = rows[0]
        assert conflict.reported_known_tokens == 80
        assert conflict.reported_external_charge_unknown is False
        assert conflict.settled_known_tokens_snapshot == 20
        assert receipt.id == receipt_id
        assert receipt.known_tokens == 20
        assert receipt.charged_tokens == 100
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 100
        with pytest.raises(AuthoringQuotaConflict):
            settle_authoring_tokens(
                db, receipt_id, known_tokens=90,
                external_charge_unknown=False,
            )
        assert db.scalar(select(func.count()).select_from(AIAuthoringQuotaSettlementConflict)) == 2
        set_session_namespace(db, str(uuid4()), str(uuid4()))
        assert list_authoring_settlement_conflicts(db, limit=10) == ([], None)


def test_late_known_floor_blocks_understated_proposal_and_pending_review():
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id = _receipt(db)
        case = propose_quota_reconciliation(
            db, reservation_id=receipt_id, confirmed_total_tokens=30,
            evidence_sha256="a" * 64,
            evidence_reference="provider-billing-export-row-42",
            reason="Vendor export ties the call to a thirty-token total.",
            actor=proposer,
        )
        with pytest.raises(AuthoringQuotaConflict):
            settle_authoring_tokens(db, receipt_id, known_tokens=80, external_charge_unknown=False)
        with pytest.raises(AuthoringQuotaConflict, match="late settlement exceeds"):
            review_quota_reconciliation(
                db, case_id=case.id, decision="approve",
                reason="The older proposal is contradicted by a later model report.",
                actor=reviewer,
            )
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 100
        review_quota_reconciliation(
            db, case_id=case.id, decision="reject",
            reason="The older proposal is contradicted by a later model report.",
            actor=reviewer,
        )
        with pytest.raises(ValueError, match="below provider-reported"):
            propose_quota_reconciliation(
                db, reservation_id=receipt_id, confirmed_total_tokens=79,
                evidence_sha256="a" * 64,
                evidence_reference="provider-billing-export-row-42",
                reason="This understated amount must not pass validation.",
                actor=proposer,
            )
        corrected = propose_quota_reconciliation(
            db, reservation_id=receipt_id, confirmed_total_tokens=80,
            evidence_sha256="b" * 64,
            evidence_reference="corrected-provider-export-row-42",
            reason="Corrected vendor statement covers the late model result.",
            actor=proposer,
        )
        review_quota_reconciliation(
            db, case_id=corrected.id, decision="approve",
            reason="I independently checked the corrected provider statement.",
            actor=reviewer,
        )
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 80
        assert db.get(AIAuthoringQuotaReservation, receipt_id).charged_tokens == 100


def test_conflict_listing_requires_global_authenticated_ai_admin(client, monkeypatch):
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    try:
        boot = client.post(
            "/api/v1/auth/bootstrap",
            headers={"X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token"},
            json={"subject": "admin@example.test", "display_name": "Admin"},
        )
        assert boot.status_code == 201, boot.text
        admin = {"Authorization": f"Bearer {boot.json()['token']['access_token']}"}
        with SessionLocal() as db:
            set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
            receipt_id = _receipt(db)
            with pytest.raises(AuthoringQuotaConflict):
                settle_authoring_tokens(db, receipt_id, known_tokens=80, external_charge_unknown=False)
        page = client.get("/api/v1/ai/authoring-quota/settlement-conflicts", headers=admin)
        assert page.status_code == 200, page.text
        assert len(page.json()["items"]) == 1
        assert page.json()["items"][0]["reported_known_tokens"] == 80
        assert page.json()["items"][0]["reservation_id"] == receipt_id
        assert client.get(
            "/api/v1/ai/authoring-quota/settlement-conflicts",
        ).status_code == 401
        assert client.get(
            "/api/v1/ai/authoring-quota/settlement-conflicts",
            headers=admin, params={"cursor": str(uuid4())},
        ).status_code == 400
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()
