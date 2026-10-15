"""Independent manual billing attestation adjusts counters, not sealed receipts."""

from uuid import uuid4

import pytest
from sqlalchemy import select

from icheck.config import get_settings
from icheck.database import (
    DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace,
)
from icheck.models import (
    AIAuthoringQuotaAdjustment,
    AIAuthoringQuotaReservation,
)
from icheck.services.ai_authoring_quota import (
    AuthoringQuotaConflict,
    authoring_quota_snapshot,
    list_authoring_reservations,
    reserve_authoring_tokens,
    settle_authoring_tokens,
)
from icheck.services.ai_quota_reconciliation import (
    propose_quota_reconciliation,
    review_quota_reconciliation,
)
from icheck.services.control_plane_auth import PrincipalContext


def _admin(subject: str) -> PrincipalContext:
    return PrincipalContext(
        principal_id=str(uuid4()), subject=subject, principal_type="user",
        permissions=frozenset({"ai.manage"}), role_names=("admin",),
        authorization_scope={"all": True}, auth_method="bearer",
    )


def _unknown_receipt(db, *, actor: str = "l1.operator", known: int = 37) -> str:
    receipt_id = reserve_authoring_tokens(
        db, actor=actor, entity_type="investigation_step",
        entity_id=str(uuid4()), token_budget=100,
    )
    settle_authoring_tokens(
        db, receipt_id, known_tokens=known, external_charge_unknown=True,
    )
    return receipt_id


def _propose(db, receipt_id: str, proposer: PrincipalContext, total: int = 37):
    return propose_quota_reconciliation(
        db, reservation_id=receipt_id, confirmed_total_tokens=total,
        evidence_sha256="a" * 64,
        evidence_reference="provider-billing-export-row-42",
        reason="Vendor billing export ties this model call to the stated total.",
        actor=proposer,
    )


def test_two_person_review_credits_unknown_hold_without_rewriting_receipt():
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id = _unknown_receipt(db)
        case = _propose(db, receipt_id, proposer)
        assert case.status == "proposed"
        assert case.delta_tokens == -63
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 100
        with pytest.raises(PermissionError):
            review_quota_reconciliation(
                db, case_id=case.id, decision="approve",
                reason="I independently checked the exact vendor export row.",
                actor=proposer,
            )
        reviewed = review_quota_reconciliation(
            db, case_id=case.id, decision="approve",
            reason="I independently checked the exact vendor export row.",
            actor=reviewer,
        )
        assert reviewed.status == "applied"
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 37
        assert authoring_quota_snapshot(db, actor="l1.operator")["namespace_used"] == 37
        assert authoring_quota_snapshot(db, actor="l1.operator")["unknown_charge_requests"] == 0
        assert list_authoring_reservations(
            db, actor="l1.operator", state="uncertain", limit=10,
        ) == ([], None)
        receipt = db.get(AIAuthoringQuotaReservation, receipt_id)
        assert receipt.charged_tokens == 100
        assert receipt.external_charge_unknown is True
        db.refresh(receipt)
        assert receipt.effective_charged_tokens == 37
        assert receipt.adjustment_id is not None
        adjustment = db.scalar(select(AIAuthoringQuotaAdjustment))
        assert adjustment is not None
        assert adjustment.delta_tokens == -63
        assert adjustment.confirmed_total_tokens == 37
        assert review_quota_reconciliation(
            db, case_id=case.id, decision="approve",
            reason="I independently checked the exact vendor export row.",
            actor=reviewer,
        ).id == case.id
        assert len(db.scalars(select(AIAuthoringQuotaAdjustment)).all()) == 1
        with pytest.raises(AuthoringQuotaConflict):
            _propose(db, receipt_id, proposer, total=40)


def test_positive_bill_delta_is_debited_and_rejected_case_can_be_reproposed():
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id = _unknown_receipt(db)
        first = _propose(db, receipt_id, proposer, total=150)
        rejected = review_quota_reconciliation(
            db, case_id=first.id, decision="reject",
            reason="The reference row did not match the provider request.",
            actor=reviewer,
        )
        assert rejected.status == "rejected"
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 100
        second = _propose(db, receipt_id, proposer, total=150)
        assert second.id != first.id
        assert review_quota_reconciliation(
            db, case_id=second.id, decision="approve",
            reason="A corrected provider export proves the higher total.",
            actor=reviewer,
        ).status == "applied"
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 150
        assert db.scalar(select(AIAuthoringQuotaAdjustment)).delta_tokens == 50


def test_manual_adjustment_refuses_pending_and_below_known_usage():
    proposer = _admin("first-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        pending = reserve_authoring_tokens(
            db, actor="l1.operator", entity_type="investigation_step",
            entity_id=str(uuid4()), token_budget=100,
        )
        with pytest.raises(AuthoringQuotaConflict, match="settled uncertain"):
            _propose(db, pending, proposer)
        settled = _unknown_receipt(db)
        with pytest.raises(ValueError, match="below provider-reported"):
            _propose(db, settled, proposer, total=36)


def test_service_identity_cannot_submit_a_human_billing_attestation():
    service_actor = PrincipalContext(
        principal_id=str(uuid4()), subject="billing-bot", principal_type="service",
        permissions=frozenset({"ai.manage"}), role_names=("admin",),
        authorization_scope={"all": True}, auth_method="bearer",
    )
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id = _unknown_receipt(db)
        with pytest.raises(PermissionError, match="global AI administration"):
            _propose(db, receipt_id, service_actor)


def test_originator_cannot_review_and_cases_are_namespace_local():
    proposer = _admin("first-admin@example.test")
    originator = _admin("l1.operator")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id = _unknown_receipt(db)
        case = _propose(db, receipt_id, proposer)
        with pytest.raises(PermissionError, match="independent"):
            review_quota_reconciliation(
                db, case_id=case.id, decision="approve",
                reason="I reviewed the provider export separately.",
                actor=originator,
            )
        set_session_namespace(db, str(uuid4()), str(uuid4()))
        with pytest.raises(LookupError):
            review_quota_reconciliation(
                db, case_id=case.id, decision="approve",
                reason="I reviewed the provider export separately.",
                actor=_admin("second-admin@example.test"),
            )


def test_api_requires_two_distinct_global_admin_principals(client, monkeypatch):
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
        admin_role = next(item for item in client.get(
            "/api/v1/auth/roles", headers=first,
        ).json() if item["name"] == "admin")
        created = client.post("/api/v1/auth/principals", headers=first, json={
            "subject": "second-admin@example.test", "display_name": "Second admin",
        })
        assert created.status_code == 201, created.text
        principal_id = created.json()["id"]
        binding = client.post(
            f"/api/v1/auth/principals/{principal_id}/bindings", headers=first,
            json={"role_id": admin_role["id"], "scope": {"all": True}},
        )
        assert binding.status_code == 201, binding.text
        token = client.post(
            f"/api/v1/auth/principals/{principal_id}/tokens", headers=first,
            json={"name": "quota-reviewer", "expires_in_hours": 24},
        )
        assert token.status_code == 201, token.text
        second = {"Authorization": f"Bearer {token.json()['access_token']}"}
        with SessionLocal() as db:
            set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
            receipt_id = _unknown_receipt(db)
        proposal = client.post(
            "/api/v1/ai/authoring-quota/reconciliations", headers=first,
            json={"reservation_id": receipt_id, "confirmed_total_tokens": 37,
                  "evidence_sha256": "a" * 64,
                  "evidence_reference": "provider-billing-export-row-42",
                  "reason": "Vendor billing export ties this model call to the stated total."},
        )
        assert proposal.status_code == 201, proposal.text
        case_id = proposal.json()["id"]
        assert client.post(
            f"/api/v1/ai/authoring-quota/reconciliations/{case_id}/review",
            headers=first,
            json={"decision": "approve", "reason": "Self-review must be refused by API."},
        ).status_code == 403
        queue = client.get(
            "/api/v1/ai/authoring-quota/reconciliations", headers=second,
        )
        assert queue.status_code == 200, queue.text
        assert [item["id"] for item in queue.json()["items"]] == [case_id]
        approved = client.post(
            f"/api/v1/ai/authoring-quota/reconciliations/{case_id}/review",
            headers=second,
            json={"decision": "approve",
                  "reason": "I independently checked the exact vendor export row."},
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "applied"
        snapshot = client.get("/api/v1/ai/authoring-quota", headers=first).json()
        assert snapshot["namespace_used"] == 37
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()
