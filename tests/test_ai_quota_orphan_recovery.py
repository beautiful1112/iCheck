"""Conservative two-person recovery of a source-proven abandoned AI hold."""

from datetime import UTC, datetime, timedelta
import hashlib
import json
from uuid import NAMESPACE_URL, uuid4, uuid5

import pytest
from sqlalchemy import select, text

from icheck.config import get_settings
from icheck.database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace
from icheck.models import (
    AIAuthoringQuotaOrphanClosure,
    AIAuthoringQuotaReservation,
    AIAuthoringQuotaSettlementConflict,
    ActivationPolicyProposal,
    AgentExecution,
    AgentExecutionStatus,
    CapabilityStudioGenerationAttempt,
    CapabilityStudioSession,
    Investigation,
)
from icheck.services import ai_quota_orphan_recovery as recovery
from icheck.services.ai_authoring_quota import (
    AuthoringQuotaConflict, authoring_quota_snapshot,
    reserve_authoring_tokens, settle_authoring_tokens,
)
from icheck.services.ai_quota_orphan_recovery import (
    list_orphan_candidates, propose_orphan_closure, review_orphan_closure,
)
from icheck.services.ai_quota_reconciliation import (
    propose_quota_reconciliation, review_quota_reconciliation,
)
from icheck.services.audit import record_audit_event
from test_ai_quota_reconciliation import _admin
from test_activation_policy_proposals import _published_http_artifact
from test_agent_execution import configure_execution_route, start_execution


def _studio_receipt(db, *, status: str = "interrupted") -> tuple[str, str]:
    old = datetime.now(UTC) - timedelta(days=3)
    session = CapabilityStudioSession(
        tenant_id=DEFAULT_TENANT_ID, region_id=DEFAULT_REGION_ID,
        title="Recovery test", artifact_kind="collector", status="failed",
        route_purpose="studio.default", brief="Test model call",
        target_url="https://device.example.test/api", sample_document={},
        created_by="l1.operator",
    )
    db.add(session)
    db.flush()
    attempt = CapabilityStudioGenerationAttempt(
        tenant_id=DEFAULT_TENANT_ID, region_id=DEFAULT_REGION_ID,
        session_id=session.id, request_key=str(uuid4()), request_sha256="a" * 64,
        request_document={}, actor="l1.operator", status=status,
        owner_sha256="b" * 64, lease_expires_at=old,
        created_at=old, updated_at=old,
    )
    db.add(attempt)
    db.commit()
    receipt_id = reserve_authoring_tokens(
        db, actor="l1.operator", entity_type="capability_studio_generation_attempt",
        entity_id=attempt.id, token_budget=100,
    )
    return receipt_id, attempt.id


def _age_clock(monkeypatch):
    monkeypatch.setattr(recovery, "_utc_now", lambda _db: datetime.now(UTC) + timedelta(days=2))


def _studio_model_audit(db, attempt_id, *, index, usage, cumulative, event_type="failed"):
    details = {
        "route_id": "studio-route-test", "model_id": str(uuid4()),
        "provider_id": str(uuid4()), "candidate_index": index,
        "fallback_used": index > 0, "prompt_sha256": "a" * 64,
        "token_usage": usage,
        "external_charge_unknown": True,
    }
    if event_type == "completed":
        details["candidate_token_usage"] = usage
        details["token_usage"] = cumulative
    else:
        details["cumulative_token_usage"] = cumulative
    record_audit_event(
        db, event_type=f"capability.model.{event_type}",
        outcome="success" if event_type == "completed" else "failure",
        actor_type="agent", actor_id="l1.operator",
        entity_type="capability_studio_generation_attempt", entity_id=attempt_id,
        details=details,
    )
    db.commit()


def _proposal_receipt(db, artifact_version_id, *, status="succeeded", tokens_used=42):
    old = datetime.now(UTC) - timedelta(days=3)
    proposal = ActivationPolicyProposal(
        tenant_id=DEFAULT_TENANT_ID, region_id=DEFAULT_REGION_ID,
        artifact_version_id=artifact_version_id, protocol="https_api",
        actor="l1.operator", request_key=str(uuid4()),
        request_sha256="a" * 64, brief="Draft a read-only inventory policy.",
        status=status, tokens_used=tokens_used,
        route_id="proposal-route" if status == "succeeded" else None,
        model_id="proposal-model" if status == "succeeded" else None,
        result_snapshot={"name": "lab-inventory", "tokens_used": tokens_used}
        if status == "succeeded" else {},
        failure_code="ValueError" if status == "failed" else None,
        external_charge_unknown=True, created_at=old, updated_at=old,
    )
    if status == "succeeded":
        proposal.result_sha256 = hashlib.sha256(json.dumps(
            proposal.result_snapshot, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
    db.add(proposal)
    db.commit()
    receipt_id = reserve_authoring_tokens(
        db, actor="l1.operator", entity_type="device_activation_policy_proposal",
        entity_id=proposal.id, token_budget=100,
    )
    return receipt_id, proposal.id


def _proposal_model_audit(db, proposal_id, *, index, usage, cumulative,
                          event_type="failed", route_id="proposal-route",
                          model_id="proposal-model"):
    details = {
        "route_id": route_id, "model_id": model_id,
        "provider_id": str(uuid4()), "candidate_index": index,
        "fallback_used": index > 0, "prompt_sha256": "b" * 64,
        "token_usage": cumulative if event_type == "completed" else usage,
        "external_charge_unknown": True,
    }
    if event_type == "completed":
        details["candidate_token_usage"] = usage
    else:
        details["cumulative_token_usage"] = cumulative
    record_audit_event(
        db, event_type=f"capability.model.{event_type}",
        outcome="success" if event_type == "completed" else "failure",
        actor_type="agent", actor_id="l1.operator",
        entity_type="device_activation_policy_proposal", entity_id=proposal_id,
        details=details,
    )
    db.commit()


def test_independent_recovery_retains_full_hold_and_late_result_is_recorded(monkeypatch):
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id, _ = _studio_receipt(db)
        assert authoring_quota_snapshot(db, actor="l1.operator")["pending_requests"] == 1
        _age_clock(monkeypatch)
        candidates, cursor = list_orphan_candidates(db, limit=10, cursor=None, actor=proposer)
        assert cursor is None
        assert candidates[0][0].id == receipt_id
        assert candidates[0][1] is True
        case = propose_orphan_closure(
            db, reservation_id=receipt_id,
            reason="The Studio generation is terminal and its lease has aged out.",
            actor=proposer,
        )
        with pytest.raises(PermissionError, match="independent"):
            review_orphan_closure(
                db, case_id=case.id, decision="close",
                reason="I independently checked the source and the preserved hold.",
                actor=proposer,
            )
        closed = review_orphan_closure(
            db, case_id=case.id, decision="close",
            reason="I independently checked the source and the preserved hold.",
            actor=reviewer,
        )
        assert closed.status == "closed"
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 100
        receipt = db.get(AIAuthoringQuotaReservation, receipt_id)
        assert receipt.status == "settled"
        assert receipt.known_tokens == 0
        assert receipt.charged_tokens == 100
        assert receipt.external_charge_unknown is True
        assert db.scalar(select(AIAuthoringQuotaOrphanClosure)).reservation_id == receipt_id
        assert review_orphan_closure(
            db, case_id=case.id, decision="close",
            reason="I independently checked the source and the preserved hold.",
            actor=reviewer,
        ).id == case.id
        with pytest.raises(AuthoringQuotaConflict, match="settlement changed"):
            settle_authoring_tokens(
                db, receipt_id, known_tokens=42,
                external_charge_unknown=False,
            )
        assert db.scalar(select(AIAuthoringQuotaSettlementConflict)).reported_known_tokens == 42
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 100
        adjustment = propose_quota_reconciliation(
            db, reservation_id=receipt_id, confirmed_total_tokens=42,
            evidence_sha256="c" * 64,
            evidence_reference="provider-billing-export-row-42",
            reason="The provider statement confirms forty-two tokens after recovery.",
            actor=proposer,
        )
        review_quota_reconciliation(
            db, case_id=adjustment.id, decision="approve",
            reason="I independently checked the exact provider statement.",
            actor=reviewer,
        )
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 42
        with pytest.raises(AuthoringQuotaConflict, match="settlement changed"):
            settle_authoring_tokens(
                db, receipt_id, known_tokens=90,
                external_charge_unknown=False,
            )
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 42
        assert [row.reported_known_tokens for row in db.scalars(
            select(AIAuthoringQuotaSettlementConflict).order_by(
                AIAuthoringQuotaSettlementConflict.reported_known_tokens,
            )
        ).all()] == [42, 90]


def test_terminal_activation_proposal_recovers_exact_audited_usage_without_credit(client, monkeypatch):
    version_id = _published_http_artifact(client)
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id, proposal_id = _proposal_receipt(db, version_id)
        _proposal_model_audit(db, proposal_id, index=0, usage=12, cumulative=12)
        _proposal_model_audit(db, proposal_id, index=1, usage=30, cumulative=42,
                              event_type="completed")
        _age_clock(monkeypatch)
        candidates, _ = list_orphan_candidates(db, limit=10, cursor=None, actor=proposer)
        candidate = next(item for item in candidates if item[0].id == receipt_id)
        assert candidate[1] is True
        assert candidate[3].audited_known_tokens == 42
        assert candidate[3].audit_event_count == 2
        case = propose_orphan_closure(
            db, reservation_id=receipt_id,
            reason="The exact terminal proposal and two-candidate model audit were checked.",
            actor=proposer,
        )
        assert case.source_status_snapshot == "succeeded"
        review_orphan_closure(
            db, case_id=case.id, decision="close",
            reason="I independently checked the terminal proposal and preserved hold.",
            actor=reviewer,
        )
        receipt = db.get(AIAuthoringQuotaReservation, receipt_id)
        assert (receipt.status, receipt.known_tokens, receipt.charged_tokens) == (
            "settled", 42, 100,
        )
        assert receipt.external_charge_unknown is True


def test_activation_proposal_recovery_rejects_live_interrupted_and_drifted_sources(client, monkeypatch):
    version_id = _published_http_artifact(client)
    admin = _admin("first-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id, proposal_id = _proposal_receipt(db, version_id)
        _proposal_model_audit(db, proposal_id, index=0, usage=42, cumulative=42,
                              event_type="completed")
        _age_clock(monkeypatch)
        proposal = db.get(ActivationPolicyProposal, proposal_id)
        proposal.status = "generating"
        db.commit()
        with pytest.raises(AuthoringQuotaConflict, match="terminal model result"):
            propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="A generating proposal must not release its pending hold.", actor=admin,
            )
        proposal.status = "failed"
        proposal.failure_code = "Interrupted"
        proposal.result_sha256 = None
        proposal.route_id = None
        proposal.model_id = None
        db.commit()
        with pytest.raises(AuthoringQuotaConflict, match="terminal model result"):
            propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="An interrupted model call may still return late.", actor=admin,
            )
        proposal.status = "succeeded"
        proposal.failure_code = None
        proposal.route_id = "proposal-route"
        proposal.model_id = "proposal-model"
        proposal.result_sha256 = "0" * 64
        db.commit()
        with pytest.raises(AuthoringQuotaConflict, match="result provenance"):
            propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="A changed result digest must not be accepted.", actor=admin,
            )
        proposal.result_sha256 = hashlib.sha256(json.dumps(
            proposal.result_snapshot, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        proposal.model_id = "different-model"
        db.commit()
        with pytest.raises(AuthoringQuotaConflict, match="route or model differs"):
            propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="The final audited model differs from the source result.", actor=admin,
            )
        proposal.model_id = "proposal-model"
        proposal.tokens_used = 41
        db.commit()
        with pytest.raises(AuthoringQuotaConflict, match="usage audit"):
            propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="The source usage disagrees with the complete audit chain.", actor=admin,
            )


def test_terminal_failed_activation_proposal_review_rechecks_source(client, monkeypatch):
    version_id = _published_http_artifact(client)
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id, proposal_id = _proposal_receipt(
            db, version_id, status="failed", tokens_used=0,
        )
        _age_clock(monkeypatch)
        case = propose_orphan_closure(
            db, reservation_id=receipt_id,
            reason="The failed proposal has no attributed model usage and remains fully held.",
            actor=proposer,
        )
        assert case.source_status_snapshot == "failed"
        db.execute(text(
            "UPDATE activation_policy_proposals SET failure_code = "
            "'StructuredModelUnavailable' WHERE id = :id"
        ), {"id": proposal_id})
        db.commit()
        with pytest.raises(AuthoringQuotaConflict, match="Model audit evidence changed"):
            review_orphan_closure(
                db, case_id=case.id, decision="close",
                reason="The source changed after the first review.", actor=reviewer,
            )
        assert review_orphan_closure(
            db, case_id=case.id, decision="reject",
            reason="The source status no longer matches the sealed proposal.", actor=reviewer,
        ).status == "rejected"
        fresh = propose_orphan_closure(
            db, reservation_id=receipt_id,
            reason="I checked the newly terminal source status and preserved hold.",
            actor=proposer,
        )
        review_orphan_closure(
            db, case_id=fresh.id, decision="close",
            reason="I independently checked the revised terminal source status.", actor=reviewer,
        )
        receipt = db.get(AIAuthoringQuotaReservation, receipt_id)
        assert (receipt.known_tokens, receipt.charged_tokens, receipt.external_charge_unknown) == (
            0, 100, True,
        )


def test_young_active_unattributed_and_known_usage_receipts_fail_closed(monkeypatch):
    admin = _admin("first-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        young, attempt_id = _studio_receipt(db)
        with pytest.raises(AuthoringQuotaConflict, match="24-hour"):
            propose_orphan_closure(
                db, reservation_id=young,
                reason="This request is too young and must stay pending.", actor=admin,
            )
        _age_clock(monkeypatch)
        attempt = db.get(CapabilityStudioGenerationAttempt, attempt_id)
        attempt.status = "generating"
        db.commit()
        with pytest.raises(AuthoringQuotaConflict, match="terminal attempt"):
            propose_orphan_closure(
                db, reservation_id=young,
                reason="An active source must never be classified as an orphan.", actor=admin,
            )
        attempt.status = "interrupted"
        db.commit()
        unsupported = reserve_authoring_tokens(
            db, actor="l1.operator", entity_type="test_authoring",
            entity_id=str(uuid4()), token_budget=50,
        )
        with pytest.raises(AuthoringQuotaConflict, match="no terminality verifier"):
            propose_orphan_closure(
                db, reservation_id=unsupported,
                reason="Unverified generic source must remain unresolved.", actor=admin,
            )
        set_session_namespace(db, str(uuid4()), str(uuid4()))
        with pytest.raises(LookupError):
            propose_orphan_closure(
                db, reservation_id=young,
                reason="Another namespace cannot recover this hold.", actor=admin,
            )


def test_changed_source_blocks_approval_but_rejection_and_reproposal_work(monkeypatch):
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id, attempt_id = _studio_receipt(db)
        _age_clock(monkeypatch)
        first = propose_orphan_closure(
            db, reservation_id=receipt_id,
            reason="The original Studio attempt appears terminal.", actor=proposer,
        )
        attempt = db.get(CapabilityStudioGenerationAttempt, attempt_id)
        attempt.status = "failed"
        db.commit()
        with pytest.raises(AuthoringQuotaConflict, match="Source terminal evidence changed"):
            review_orphan_closure(
                db, case_id=first.id, decision="close",
                reason="The original source state changed after proposal.", actor=reviewer,
            )
        assert review_orphan_closure(
            db, case_id=first.id, decision="reject",
            reason="The original source state changed after proposal.", actor=reviewer,
        ).status == "rejected"
        second = propose_orphan_closure(
            db, reservation_id=receipt_id,
            reason="The failed attempt still has no active ownership.", actor=proposer,
        )
        assert second.id != first.id


def test_unattributed_model_usage_audit_fails_closed(monkeypatch):
    admin = _admin("first-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id, attempt_id = _studio_receipt(db)
        record_audit_event(
            db, event_type="capability.model.failed", outcome="failure",
            actor_type="user", actor_id="l1.operator",
            entity_type="capability_studio_generation_attempt",
            entity_id=attempt_id,
            details={"token_usage": 12, "external_charge_unknown": True},
        )
        db.commit()
        _age_clock(monkeypatch)
        with pytest.raises(AuthoringQuotaConflict, match="known usage"):
            propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="A known-usage audit must not be ignored.", actor=admin,
            )


def test_valid_model_audit_restores_known_usage_without_releasing_unknown_hold(monkeypatch):
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id, attempt_id = _studio_receipt(db)
        _studio_model_audit(db, attempt_id, index=0, usage=12, cumulative=12)
        _studio_model_audit(db, attempt_id, index=1, usage=30, cumulative=42, event_type="completed")
        _age_clock(monkeypatch)
        candidates, _ = list_orphan_candidates(db, limit=10, cursor=None, actor=proposer)
        evidence = candidates[0][3]
        assert candidates[0][1] is True
        assert evidence.audited_known_tokens == 42
        assert evidence.audit_event_count == 2
        case = propose_orphan_closure(
            db, reservation_id=receipt_id,
            reason="The terminal Studio attempt has a valid two-candidate audit chain.",
            actor=proposer,
        )
        assert case.audited_known_tokens == 42
        assert case.audit_sha256 == evidence.audit_sha256
        review_orphan_closure(
            db, case_id=case.id, decision="close",
            reason="I independently checked the exact audit chain and preserved hold.",
            actor=reviewer,
        )
        receipt = db.get(AIAuthoringQuotaReservation, receipt_id)
        assert receipt.status == "settled"
        assert receipt.known_tokens == 42
        assert receipt.charged_tokens == 100
        assert receipt.external_charge_unknown is True
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 100
        with pytest.raises(ValueError, match="below provider-reported known usage"):
            propose_quota_reconciliation(
                db, reservation_id=receipt_id, confirmed_total_tokens=41,
                evidence_sha256="c" * 64,
                evidence_reference="provider-billing-export-row-42",
                reason="This provider statement undercuts the verified model audit.",
                actor=proposer,
            )


def test_new_audit_after_proposal_requires_rejection_and_fresh_snapshot(monkeypatch):
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id, attempt_id = _studio_receipt(db)
        _studio_model_audit(db, attempt_id, index=0, usage=12, cumulative=12)
        _age_clock(monkeypatch)
        old_case = propose_orphan_closure(
            db, reservation_id=receipt_id,
            reason="The first model audit recorded twelve known tokens.",
            actor=proposer,
        )
        _studio_model_audit(db, attempt_id, index=1, usage=8, cumulative=20, event_type="completed")
        with pytest.raises(AuthoringQuotaConflict, match="Model audit evidence changed"):
            review_orphan_closure(
                db, case_id=old_case.id, decision="close",
                reason="The earlier audit snapshot is now stale.", actor=reviewer,
            )
        assert review_orphan_closure(
            db, case_id=old_case.id, decision="reject",
            reason="The earlier audit snapshot is now stale.", actor=reviewer,
        ).status == "rejected"
        new_case = propose_orphan_closure(
            db, reservation_id=receipt_id,
            reason="The completed candidate adds eight more known tokens.",
            actor=proposer,
        )
        assert new_case.audited_known_tokens == 20
        review_orphan_closure(
            db, case_id=new_case.id, decision="close",
            reason="I independently checked the complete new audit chain.",
            actor=reviewer,
        )
        assert db.get(AIAuthoringQuotaReservation, receipt_id).known_tokens == 20


def test_audited_overrun_adds_only_the_positive_difference_to_counters(monkeypatch):
    proposer, reviewer = _admin("first-admin@example.test"), _admin("second-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id, attempt_id = _studio_receipt(db)
        _studio_model_audit(db, attempt_id, index=0, usage=120, cumulative=120)
        _age_clock(monkeypatch)
        case = propose_orphan_closure(
            db, reservation_id=receipt_id,
            reason="The audited model overrun exceeds the original reservation.",
            actor=proposer,
        )
        review_orphan_closure(
            db, case_id=case.id, decision="close",
            reason="I independently checked the 120-token audit and original hold.",
            actor=reviewer,
        )
        receipt = db.get(AIAuthoringQuotaReservation, receipt_id)
        assert (receipt.known_tokens, receipt.charged_tokens) == (120, 120)
        assert receipt.external_charge_unknown is True
        assert authoring_quota_snapshot(db, actor="l1.operator")["actor_used"] == 120
        assert authoring_quota_snapshot(db, actor="l1.operator")["namespace_used"] == 120


def test_duplicate_or_incomplete_model_audit_chain_fails_closed(monkeypatch):
    proposer = _admin("first-admin@example.test")
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        receipt_id, attempt_id = _studio_receipt(db)
        _studio_model_audit(db, attempt_id, index=1, usage=12, cumulative=12)
        _age_clock(monkeypatch)
        with pytest.raises(AuthoringQuotaConflict, match="candidate chain"):
            propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="An audit missing candidate zero must fail closed.", actor=proposer,
            )
        _studio_model_audit(db, attempt_id, index=0, usage=8, cumulative=8)
        with pytest.raises(AuthoringQuotaConflict, match="cumulative usage"):
            propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="The inconsistent cumulative usage must fail closed.", actor=proposer,
            )


def test_terminal_agent_step_requires_exact_identity_and_unowned_execution(client, monkeypatch):
    configure_execution_route(client)
    investigation_data, execution_data = start_execution(client)
    admin = _admin("first-admin@example.test")
    old = datetime.now(UTC) - timedelta(days=3)
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        investigation = db.get(Investigation, investigation_data["id"])
        execution = db.get(AgentExecution, execution_data["id"])
        investigation.status = "completed"
        investigation.finished_at = old
        execution.status = AgentExecutionStatus.SUCCEEDED
        execution.finished_at = old
        execution.worker_id = None
        execution.lease_token_hash = None
        execution.lease_expires_at = None
        db.commit()
        step = 0
        intent_id = str(uuid5(
            NAMESPACE_URL,
            f"icheck:investigation:{investigation.id}:iteration:{step}",
        ))
        receipt_id = reserve_authoring_tokens(
            db, actor="l1.operator", entity_type="investigation_step",
            entity_id=intent_id, token_budget=100,
            source_entity_type="investigation",
            source_entity_id=investigation.id, source_step=step,
        )
        for event_type, index, usage, cumulative in (
            ("failed", 0, 7, None),
            ("completed", 1, 11, 18),
        ):
            record_audit_event(
                db, event_type=f"investigation.model.{event_type}",
                outcome="success" if event_type == "completed" else "failure",
                actor_type="agent", actor_id="agent.langgraph",
                entity_type="investigation", entity_id=investigation.id,
                details={
                    "model_id": str(uuid4()), "iteration": 1,
                    "candidate_index": index, "fallback_used": index > 0,
                    "token_usage": usage,
                    **({"cumulative_token_usage": cumulative} if cumulative is not None else {}),
                },
            )
        record_audit_event(
            db, event_type="investigation.model.completed", outcome="success",
            actor_type="agent", actor_id="agent.langgraph",
            entity_type="investigation", entity_id=investigation.id,
            details={"model_id": str(uuid4()), "iteration": 2,
                     "candidate_index": 0, "fallback_used": False,
                     "token_usage": 50, "cumulative_token_usage": 50},
        )
        db.commit()
        _age_clock(monkeypatch)
        case = propose_orphan_closure(
            db, reservation_id=receipt_id,
            reason="The Investigation and execution are terminal without a live lease.",
            actor=admin,
        )
        assert case.source_status_snapshot == "completed:succeeded"
        assert case.source_step == 0
        assert case.audited_known_tokens == 18
        assert case.audit_event_count == 2
        review_orphan_closure(
            db, case_id=case.id, decision="close",
            reason="I independently verified the exact Investigation step audits.",
            actor=_admin("second-admin@example.test"),
        )
        assert db.get(AIAuthoringQuotaReservation, receipt_id).known_tokens == 18


def test_live_agent_lease_and_wrong_step_identity_fail_closed(client, monkeypatch):
    configure_execution_route(client)
    investigation_data, execution_data = start_execution(client)
    admin = _admin("first-admin@example.test")
    old = datetime.now(UTC) - timedelta(days=3)
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        investigation = db.get(Investigation, investigation_data["id"])
        execution = db.get(AgentExecution, execution_data["id"])
        investigation.status = "completed"
        investigation.finished_at = old
        execution.status = AgentExecutionStatus.SUCCEEDED
        execution.finished_at = old
        execution.lease_expires_at = datetime.now(UTC) + timedelta(minutes=30)
        db.commit()
        intent_id = str(uuid5(NAMESPACE_URL, f"icheck:investigation:{investigation.id}:iteration:0"))
        receipt_id = reserve_authoring_tokens(
            db, actor="l1.operator", entity_type="investigation_step",
            entity_id=intent_id, token_budget=100,
            source_entity_type="investigation",
            source_entity_id=investigation.id, source_step=0,
        )
        _age_clock(monkeypatch)
        with pytest.raises(AuthoringQuotaConflict, match="unowned execution"):
            propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="An execution with a live lease must remain pending.", actor=admin,
            )
        execution.lease_expires_at = None
        db.commit()
        receipt = db.get(AIAuthoringQuotaReservation, receipt_id)
        receipt.source_step = 1
        # Reservation provenance is sealed by migrated databases; the test DB
        # uses model metadata, so this simulates a malformed legacy identity.
        db.commit()
        with pytest.raises(AuthoringQuotaConflict, match="exact Investigation step"):
            propose_orphan_closure(
                db, reservation_id=receipt_id,
                reason="A step identity mismatch must fail closed.", actor=admin,
            )


def test_api_exposes_global_admin_recovery_queue(client, monkeypatch):
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
            receipt_id, attempt_id = _studio_receipt(db)
            _studio_model_audit(db, attempt_id, index=0, usage=12, cumulative=12)
        _age_clock(monkeypatch)
        queue = client.get("/api/v1/ai/authoring-quota/orphan-candidates", headers=admin)
        assert queue.status_code == 200, queue.text
        assert queue.json()["items"][0]["reservation_id"] == receipt_id
        assert queue.json()["items"][0]["eligible"] is True
        assert queue.json()["items"][0]["audited_known_tokens"] == 12
        assert queue.json()["items"][0]["audit_event_count"] == 1
        proposed = client.post(
            "/api/v1/ai/authoring-quota/orphan-cases", headers=admin,
            json={"reservation_id": receipt_id,
                  "reason": "The terminal source and expired lease were independently inspected."},
        )
        assert proposed.status_code == 201, proposed.text
        assert proposed.json()["audited_known_tokens"] == 12
        assert proposed.json()["audit_sha256"] == queue.json()["items"][0]["audit_sha256"]
        pending_review_queue = client.get(
            "/api/v1/ai/authoring-quota/orphan-candidates", headers=admin,
        )
        assert pending_review_queue.status_code == 200
        assert pending_review_queue.json()["items"][0]["eligible"] is False
        assert "awaiting independent review" in pending_review_queue.json()["items"][0]["eligibility_reason"]
        assert client.post(
            f"/api/v1/ai/authoring-quota/orphan-cases/{proposed.json()['id']}/review",
            headers=admin,
            json={"decision": "close", "reason": "Self-review must be denied here."},
        ).status_code == 403
        role = next(item for item in client.get(
            "/api/v1/auth/roles", headers=admin,
        ).json() if item["name"] == "admin")
        created = client.post(
            "/api/v1/auth/principals", headers=admin,
            json={"subject": "second-admin@example.test", "display_name": "Second admin"},
        )
        assert created.status_code == 201, created.text
        principal_id = created.json()["id"]
        assert client.post(
            f"/api/v1/auth/principals/{principal_id}/bindings", headers=admin,
            json={"role_id": role["id"], "scope": {"all": True}},
        ).status_code == 201
        token = client.post(
            f"/api/v1/auth/principals/{principal_id}/tokens", headers=admin,
            json={"name": "orphan-reviewer", "expires_in_hours": 24},
        )
        assert token.status_code == 201, token.text
        second = {"Authorization": f"Bearer {token.json()['access_token']}"}
        assert client.get(
            "/api/v1/ai/authoring-quota/orphan-cases", headers=admin,
        ).json()["items"][0]["id"] == proposed.json()["id"]
        approved = client.post(
            f"/api/v1/ai/authoring-quota/orphan-cases/{proposed.json()['id']}/review",
            headers=second,
            json={"decision": "close", "reason": "I independently verified the terminal attempt and unchanged hold."},
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "closed"
        with SessionLocal() as db:
            set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
            receipt = db.get(AIAuthoringQuotaReservation, receipt_id)
            assert receipt.status == "settled"
            assert receipt.known_tokens == 12
        assert client.get(
            "/api/v1/ai/authoring-quota/orphan-candidates",
        ).status_code == 401
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()
