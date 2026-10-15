"""Independent supplementary corrections preserve the first sealed adjustment."""

from uuid import uuid4

import pytest
from sqlalchemy import select

from icheck.config import get_settings
from icheck.database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace
from icheck.models import (
    AIAuthoringQuotaAdjustment,
    AIAuthoringQuotaReservation,
    AIAuthoringQuotaSupplementAdjustment,
)
from icheck.services.ai_authoring_quota import (
    AuthoringQuotaConflict, authoring_quota_snapshot,
    settle_authoring_tokens,
)
from icheck.services.ai_quota_reconciliation import review_quota_reconciliation
from icheck.services.ai_quota_supplements import (
    list_supplement_candidates,
    propose_supplement,
    review_supplement,
)
from icheck.services.control_plane_auth import PrincipalContext
from test_ai_quota_reconciliation import _admin, _propose, _unknown_receipt


def _first_adjustment(db, proposer, reviewer) -> str:
    receipt_id = _unknown_receipt(db)
    first = _propose(db, receipt_id, proposer)
    review_quota_reconciliation(
        db, case_id=first.id, decision="approve",
        reason="I independently checked the exact first provider statement.",
        actor=reviewer,
    )
    return receipt_id


def _propose_supplement(db, receipt_id, proposer, total):
    return propose_supplement(
        db, reservation_id=receipt_id,
        confirmed_total_tokens=total, evidence_sha256="b" * 64,
        evidence_reference="corrected-provider-export-row-42",
        reason="A corrected vendor export proves the updated model-call total.",
        actor=proposer,
    )


def _approve(db, case_id, reviewer):
    return review_supplement(
        db, case_id=case_id, decision="approve",
        reason="I independently checked the exact corrected vendor statement.",
        actor=reviewer,
    )


def test_multiple_supplements_chain_positive_and_negative_deltas_without_rewriting_history():
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id = _first_adjustment(db, proposer, reviewer)
        first = db.scalar(select(AIAuthoringQuotaAdjustment))
        assert first.confirmed_total_tokens == 37
        with pytest.raises(AuthoringQuotaConflict):
            settle_authoring_tokens(
                db, receipt_id, known_tokens=80,
                external_charge_unknown=False,
            )
        expected = [(80, 43), (120, 40), (90, -30)]
        base_id = first.id
        for sequence, (total, delta) in enumerate(expected, start=1):
            case = _propose_supplement(db, receipt_id, proposer, total)
            assert case.sequence == sequence
            assert case.base_adjustment_id == base_id
            assert case.delta_tokens == delta
            with pytest.raises(PermissionError, match="independent"):
                _approve(db, case.id, proposer)
            assert _approve(db, case.id, reviewer).status == "applied"
            assert _approve(db, case.id, reviewer).id == case.id
            assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == total
            assert authoring_quota_snapshot(db, actor="l1.operator")["namespace_used"] == total
            db.expire_all()
            receipt = db.get(AIAuthoringQuotaReservation, receipt_id)
            assert receipt.effective_charged_tokens == total
            assert receipt.supplemental_adjustment_count == sequence
            base_id = receipt.latest_adjustment_id
            assert receipt.charged_tokens == 100
        assert db.get(AIAuthoringQuotaAdjustment, first.id).confirmed_total_tokens == 37
        supplements = list(db.scalars(select(AIAuthoringQuotaSupplementAdjustment)
            .order_by(AIAuthoringQuotaSupplementAdjustment.sequence)).all())
        assert [(row.sequence, row.previous_total_tokens, row.confirmed_total_tokens, row.delta_tokens)
                for row in supplements] == [(1, 37, 80, 43), (2, 80, 120, 40), (3, 120, 90, -30)]
        rows, cursor = list_supplement_candidates(db, limit=10, cursor=None, actor=proposer)
        assert cursor is None
        assert rows[0].id == receipt_id


def test_supplement_refuses_an_inconsistent_existing_ledger_chain():
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id = _first_adjustment(db, proposer, reviewer)
        for total in (80, 90):
            _approve(db, _propose_supplement(db, receipt_id, proposer, total).id, reviewer)
        second = db.scalar(select(AIAuthoringQuotaSupplementAdjustment).where(
            AIAuthoringQuotaSupplementAdjustment.reservation_id == receipt_id,
            AIAuthoringQuotaSupplementAdjustment.sequence == 2,
        ))
        assert second is not None
        # Direct mutation is possible only in this auto-schema fixture: the
        # migrated database's append-only trigger rejects it before this guard.
        second.base_adjustment_id = str(uuid4())
        db.commit()
        with pytest.raises(RuntimeError, match="ledger chain is inconsistent"):
            _propose_supplement(db, receipt_id, proposer, 100)


def test_new_late_report_blocks_stale_review_but_rejection_and_reproposal_work():
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id = _first_adjustment(db, proposer, reviewer)
        stale = _propose_supplement(db, receipt_id, proposer, 50)
        with pytest.raises(AuthoringQuotaConflict, match="awaiting review"):
            _propose_supplement(db, receipt_id, proposer, 60)
        with pytest.raises(AuthoringQuotaConflict):
            settle_authoring_tokens(db, receipt_id, known_tokens=80, external_charge_unknown=False)
        with pytest.raises(AuthoringQuotaConflict, match="late model report"):
            _approve(db, stale.id, reviewer)
        assert review_supplement(
            db, case_id=stale.id, decision="reject",
            reason="A higher late model result invalidated the first correction.",
            actor=reviewer,
        ).status == "rejected"
        with pytest.raises(ValueError, match="below provider-reported"):
            _propose_supplement(db, receipt_id, proposer, 79)
        corrected = _propose_supplement(db, receipt_id, proposer, 80)
        _approve(db, corrected.id, reviewer)
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 80
        set_session_namespace(db, str(uuid4()), str(uuid4()))
        with pytest.raises(LookupError):
            _propose_supplement(db, receipt_id, proposer, 80)


def test_supplement_requires_first_adjustment_and_human_global_admin():
    proposer = _admin("first-admin@example.test")
    service = PrincipalContext(
        principal_id=str(uuid4()), subject="billing-bot", principal_type="service",
        permissions=frozenset({"ai.manage"}), role_names=("admin",),
        authorization_scope={"all": True}, auth_method="bearer",
    )
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id = _unknown_receipt(db)
        with pytest.raises(AuthoringQuotaConflict, match="first adjustment"):
            _propose_supplement(db, receipt_id, proposer, 50)
        with pytest.raises(PermissionError, match="global AI administration"):
            _propose_supplement(db, receipt_id, service, 50)


def test_api_two_admin_supplement_review_and_candidate_listing(client, monkeypatch):
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    try:
        boot = client.post(
            "/api/v1/auth/bootstrap",
            headers={"X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token"},
            json={"subject": "first-admin@example.test", "display_name": "First admin"},
        )
        assert boot.status_code == 201, boot.text
        first = {"Authorization": f"Bearer {boot.json()['token']['access_token']}"}
        role = next(item for item in client.get(
            "/api/v1/auth/roles", headers=first,
        ).json() if item["name"] == "admin")
        created = client.post(
            "/api/v1/auth/principals", headers=first,
            json={"subject": "second-admin@example.test", "display_name": "Second admin"},
        )
        assert created.status_code == 201, created.text
        principal_id = created.json()["id"]
        assert client.post(
            f"/api/v1/auth/principals/{principal_id}/bindings", headers=first,
            json={"role_id": role["id"], "scope": {"all": True}},
        ).status_code == 201
        token = client.post(
            f"/api/v1/auth/principals/{principal_id}/tokens", headers=first,
            json={"name": "quota-supplement-reviewer", "expires_in_hours": 24},
        )
        assert token.status_code == 201, token.text
        second = {"Authorization": f"Bearer {token.json()['access_token']}"}
        with SessionLocal() as db:
            set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
            receipt_id = _first_adjustment(
                db, _admin("offline-proposer@example.test"),
                _admin("offline-reviewer@example.test"),
            )
        candidates = client.get(
            "/api/v1/ai/authoring-quota/supplement-candidates", headers=first,
        )
        assert candidates.status_code == 200, candidates.text
        assert candidates.json()["items"][0]["id"] == receipt_id
        assert candidates.json()["items"][0]["effective_charged_tokens"] == 37
        proposal = client.post(
            "/api/v1/ai/authoring-quota/supplements", headers=first,
            json={"reservation_id": receipt_id, "confirmed_total_tokens": 80,
                  "evidence_sha256": "b" * 64,
                  "evidence_reference": "corrected-provider-export-row-42",
                  "reason": "A corrected provider export proves the updated total."},
        )
        assert proposal.status_code == 201, proposal.text
        case_id = proposal.json()["id"]
        while_pending = client.get(
            "/api/v1/ai/authoring-quota/supplement-candidates", headers=first,
        )
        assert while_pending.status_code == 200, while_pending.text
        assert while_pending.json()["items"] == []
        assert client.post(
            f"/api/v1/ai/authoring-quota/supplements/{case_id}/review",
            headers=first,
            json={"decision": "approve", "reason": "Self-review must be refused."},
        ).status_code == 403
        assert client.get(
            "/api/v1/ai/authoring-quota/supplements", headers=second,
        ).json()["items"][0]["id"] == case_id
        approved = client.post(
            f"/api/v1/ai/authoring-quota/supplements/{case_id}/review",
            headers=second,
            json={"decision": "approve",
                  "reason": "I independently checked the exact corrected statement."},
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "applied"
        reread = client.get(
            "/api/v1/ai/authoring-quota/supplement-candidates", headers=first,
        ).json()["items"][0]
        assert reread["effective_charged_tokens"] == 80
        assert reread["supplemental_adjustment_count"] == 1
        assert reread["latest_adjustment_id"] != reread["adjustment_id"]
        assert client.get(
            "/api/v1/ai/authoring-quota/supplement-candidates",
        ).status_code == 401
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()
