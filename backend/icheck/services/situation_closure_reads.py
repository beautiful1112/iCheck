"""Authorize retained proof without replaying fresh execution qualification.

Today's correlation view and mutable Tool arguments are not historical read
scope. Retained identities, exact sources and immutable routing are. This code
does not acquire an execution lease, requalify peers or create a digest.
"""
from fastapi import HTTPException
from sqlalchemy import literal, select

from ..database import session_namespace
from ..models import (ActionTargetAdmission, AgentActionProposal, SituationClosureRequest,
    SituationClosureGrant, SituationRecoveryPolicyReview, SituationRecoveryPolicyRequest,
    CollectorConditionReceipt, CollectorSourceQualificationReview, CollectorSourceQualificationRequest)
from ..situation_closure_schemas import SituationClosureReceiptRead
from .authorization_scope import (has_global_scope, require_alert_access,
    require_device_access, require_endpoint_access, require_site_access)
from .collector_conditions import canonical
from .source_qualifications import _row


def _global(*actors):
    if not all(has_global_scope(actor) for actor in actors):
        raise PermissionError("Unbounded historical closure proof requires current and initiating global read scope")


def _entity_scope(db, kind, identity, *actors):
    if not isinstance(kind, str) or not kind:
        raise ValueError("Retained closure entity kind is invalid")
    if kind in {"device", "collector_device", "endpoint", "terminal"}:
        if not isinstance(identity, str) or not identity:
            raise ValueError("Retained closure entity identity is invalid")
        for actor in actors:
            if kind in {"device", "collector_device"}: require_device_access(db, actor, identity)
            else: require_endpoint_access(db, actor, identity)
    else:
        # The existing Alert/Situation ACL has no scoped permission for custom
        # or external entities. Never invent one from a current projection.
        _global(*actors)


def historical_identity_scope(db, identity, situation_id, *actors):
    from .situation_recovery import MAX_MEMBERS
    if not isinstance(identity, dict) or identity.get("situation_id") != situation_id:
        raise ValueError("Retained closure membership identity is unavailable")
    members = identity.get("members")
    if not isinstance(members, list) or not 1 <= len(members) <= MAX_MEMBERS:
        raise ValueError("Retained closure membership is incomplete or exceeds its bound")
    _entity_scope(db, identity.get("primary_entity_type"), identity.get("primary_entity_id"), *actors)
    seen = set()
    for member in members:
        if not isinstance(member, dict) or not isinstance(member.get("alert_id"), str) or member["alert_id"] in seen:
            raise ValueError("Retained closure membership is malformed or repeated")
        seen.add(member["alert_id"])
        _entity_scope(db, member.get("entity_type"), member.get("entity_id"), *actors)
        for actor in actors:
            # Check both retained entity pins and the still-retained Alert's
            # current ACL. Retargeting either cannot broaden a receipt read.
            require_alert_access(db, actor, member["alert_id"])


def historical_action_scope(db, proof, *actors):
    from .action_targets import routing_keys
    if not isinstance(proof, dict) or not isinstance(proof.get("proposal_id"), str):
        raise ValueError("Retained closure action identity is invalid")
    proposal_id = proof["proposal_id"]
    _row(db, AgentActionProposal, proposal_id)  # Namespace, not current args/status.
    namespace = session_namespace(db)
    if namespace is None:
        raise ValueError("Historical action proof requires a selected namespace")
    tenant_id, region_id = namespace
    row = db.scalar(select(ActionTargetAdmission).where(ActionTargetAdmission.id == proposal_id,
        ActionTargetAdmission.tenant_id == tenant_id, ActionTargetAdmission.region_id == region_id)
        .execution_options(populate_existing=True))
    if row is None:
        # Pre-catalog development history can be read only as unbounded.
        # Migrated production history has a native admission for every action.
        _global(*actors); return
    keys, unknown = routing_keys(row.contract_snapshot, row.target_snapshot)
    if (row.proposal_id != proposal_id or row.unknown_targets is not unknown
        or canonical(row.target_keys) != canonical(keys)
        or ("investigation_id" in proof and proof["investigation_id"] != row.investigation_id)
        or ("change_plan_id" in proof and proof["change_plan_id"] != row.routing_plan_id)):
        raise ValueError("Retained closure action routing is incomplete or differs from historical proof")
    if unknown: _global(*actors)
    for key in keys:
        for actor in actors:
            if key["kind"] == "device_id": require_device_access(db, actor, key["value"])
            else: require_site_access(actor, key["value"])


def historical_recovery_scope(db, report, policy, review_id, identity, *actors):
    """Check retained references and their scope, not current quiet/peer validity."""
    if policy.proof_version == 2:
        from .replacement_recovery_reads import historical_replacement_recovery_scope
        return historical_replacement_recovery_scope(db, report, policy, review_id, identity, *actors)
    from .situation_recovery import _bindings
    if (not isinstance(report, dict) or report.get("situation_id") != identity["situation_id"]
        or report.get("policy_review_id") != review_id):
        raise ValueError("Retained closure recovery lineage is invalid")
    members = report.get("membership")
    expected = identity["members"]
    if (not isinstance(members, list) or len(members) != len(expected)
        or report.get("member_count") != len(expected)
        or any(not isinstance(member, dict) for member in members)
        or canonical([{key: member.get(key) for key in expected[0]} for member in members]) != canonical(expected)):
        raise ValueError("Retained recovery membership differs from the closure request")
    bindings = {binding.source_id: binding.qualification_review_id for binding in _bindings(policy)}
    evidence = report.get("source_evidence")
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= len(bindings):
        raise ValueError("Retained recovery source evidence is incomplete or exceeds its bound")
    sources, covered = set(), set()
    namespace = session_namespace(db)
    if namespace is None:
        raise ValueError("Historical recovery proof requires a selected namespace")
    for item in evidence:
        if not isinstance(item, dict) or not isinstance(item.get("source_id"), str):
            raise ValueError("Retained recovery source identity is invalid")
        source_id = item["source_id"]
        if source_id in sources or bindings.get(source_id) != item.get("qualification_review_id"):
            raise ValueError("Retained recovery source is repeated or outside the reviewed policy")
        sources.add(source_id)
        accepted = _row(db, CollectorSourceQualificationReview, item["qualification_review_id"])
        request = _row(db, CollectorSourceQualificationRequest, accepted.request_id)
        if request.source_id != source_id or request.id != item.get("qualification_request_id"):
            raise ValueError("Retained recovery source qualification lineage is invalid")
        samples, active = item.get("quiet_sample_receipt_ids"), item.get("members")
        if (not isinstance(samples, list) or not 2 <= len(samples) <= 128
            or any(not isinstance(value, str) or not value for value in samples)
            or len(set(samples)) != len(samples) or item.get("quiet_receipt_id") not in samples
            or not isinstance(active, list) or not 1 <= len(active) <= len(expected)):
            raise ValueError("Retained recovery receipt references are incomplete or exceed their bound")
        receipt_ids = set(samples)
        for member in active:
            if (not isinstance(member, dict) or not isinstance(member.get("alert_id"), str)
                or member["alert_id"] in covered or not isinstance(member.get("active_receipt_id"), str)):
                raise ValueError("Retained recovery active membership is invalid or repeated")
            covered.add(member["alert_id"]); receipt_ids.add(member["active_receipt_id"])
            for actor in actors: require_alert_access(db, actor, member["alert_id"])
        current_alert = item.get("current_alert_id")
        if current_alert is not None:
            if not isinstance(current_alert, str): raise ValueError("Retained recovery Alert identity is invalid")
            for actor in actors: require_alert_access(db, actor, current_alert)
        # Batch immutable reference checks; never replay origin attestations,
        # live measurements or present-day expiry/approval checks on a read.
        rows = list(db.execute(select(CollectorConditionReceipt.id, CollectorConditionReceipt.source_id,
            CollectorConditionReceipt.admission_id).where(CollectorConditionReceipt.id.in_(receipt_ids),
            CollectorConditionReceipt.tenant_id == namespace[0], CollectorConditionReceipt.region_id == namespace[1])))
        if (len(rows) != len(receipt_ids) or any(row.source_id != source_id for row in rows)
            or next(row.admission_id for row in rows if row.id == item["quiet_receipt_id"]) != item.get("quiet_admission_id")):
            raise ValueError("Retained recovery receipts do not belong to their exact source")
    if covered != {member["alert_id"] for member in expected}:
        raise ValueError("Retained recovery source evidence does not cover the frozen membership")


def read_receipt(db, receipt, requested):
    """All full-proof responses share this boundary, including Agent retries."""
    from .situation_closure import MAX_ACTIONS, _authority, _policy_scope
    actor = _authority(db, requested, "alerts.read")
    request = _row(db, SituationClosureRequest, receipt.request_id)
    proof = receipt.proof
    if (not isinstance(proof, dict) or proof.get("contract") not in {"icheck.reviewed-situation-closure/v1", "icheck.reviewed-situation-closure/v2"}
        or (request.situation_id, request.grant_id) != (receipt.situation_id, receipt.grant_id)
        or canonical(proof.get("membership_identity")) != canonical(request.membership_identity)):
        raise ValueError("Retained closure receipt lineage is invalid")
    historical_identity_scope(db, request.membership_identity, receipt.situation_id, actor, requested)
    grant = _row(db, SituationClosureGrant, receipt.grant_id)
    review = _row(db, SituationRecoveryPolicyReview, grant.policy_review_id)
    policy = _row(db, SituationRecoveryPolicyRequest, review.request_id)
    if grant.proof_version != policy.proof_version or proof["contract"] != f"icheck.reviewed-situation-closure/v{grant.proof_version}":
        raise ValueError("Retained closure proof version differs from its exact grant and policy")
    if grant.proof_version == 2 and (set(proof) != set("contract proof_basis membership_identity recovery related_actions owner_principal_id owner_subject reviewer_principal_id reviewer_subject acceptance_reference evidence_environment remediation_causality_proven physical_truth_automatically_verified".split())
        or proof.get("remediation_causality_proven") is not False or proof.get("physical_truth_automatically_verified") is not False):
        raise ValueError("Retained replacement closure root shape or literal non-authorizing flags are invalid")
    _policy_scope(db, policy, actor, requested)
    historical_recovery_scope(db, proof.get("recovery"), policy, review.id, request.membership_identity, actor, requested)
    actions = proof.get("related_actions")
    if not isinstance(actions, list) or len(actions) > MAX_ACTIONS:
        raise ValueError("Retained closure action proof is incomplete or exceeds its bound")
    seen = set()
    for action in actions:
        historical_action_scope(db, action, actor, requested)
        if action["proposal_id"] in seen: raise ValueError("Retained closure action proof repeats a proposal")
        seen.add(action["proposal_id"])
        if policy.proof_version == 2 and action.get("finished_at"):
            from datetime import datetime
            from .alert_conditions import as_utc
            floor = as_utc(datetime.fromisoformat(action["finished_at"]))
            if any(as_utc(datetime.fromisoformat(item["quiet_after"])) < floor
                for item in proof["recovery"]["source_evidence"]):
                raise ValueError("Retained replacement quiet window predates a related terminal action")
    # No expiry/origin/peer requalification: these are historical reads, never
    # fresh authority. Current roles and all retained scopes are still required.
    return SituationClosureReceiptRead.model_validate(receipt)


def investigation_receipts_visible(db, investigation, requested):
    """Do not expose retained closure proof through a generic Agent history DTO.

    The immutable owned request key binds its original Tool journal even if the
    mutable Tool handler or Investigation history projection changes. Unrelated
    Investigations retain their existing read permissions. Read one proof at a
    time rather than bulk-loading up to 1000 full receipts.
    """
    from ..models import InvestigationToolCall, SituationClosureReceipt
    from .report_retained_proofs import investigation_proof_reports_visible
    if not investigation_proof_reports_visible(db, investigation, requested):
        return False
    from .source_replacement_runtime import investigation_replacements_visible
    if not investigation_replacements_visible(db, investigation, requested):
        return False
    namespace = session_namespace(db)
    if namespace is None:
        return False
    tenant_id, region_id = namespace
    receipt_calls = list(db.execute(select(SituationClosureReceipt.id, InvestigationToolCall.id)
        .join(SituationClosureRequest, SituationClosureRequest.id == SituationClosureReceipt.request_id)
        .join(InvestigationToolCall, SituationClosureRequest.request_key == literal("agent-closure:") + InvestigationToolCall.id)
        .where(InvestigationToolCall.investigation_id == investigation.id,
            SituationClosureReceipt.tenant_id == tenant_id, SituationClosureReceipt.region_id == region_id,
            SituationClosureRequest.tenant_id == tenant_id, SituationClosureRequest.region_id == region_id,
            InvestigationToolCall.tenant_id == tenant_id, InvestigationToolCall.region_id == region_id)
        .order_by(SituationClosureReceipt.id).limit(1001)))
    if len(receipt_calls) > 1000:
        return False
    try:
        from .tool_evidence_bindings import recorded_tool_evidence_ids
        from .situation_closure_runtime import assert_closure_citations
        for receipt_id, call_id in receipt_calls:
            receipt = read_receipt(db, _row(db, SituationClosureReceipt, receipt_id), requested)
            call = _row(db, InvestigationToolCall, call_id)
            # A commit-gap journal is legitimately still running. Terminal
            # history must retain its exact domain body and citation ledger.
            if call.status == "succeeded":
                if canonical(call.result) != canonical(receipt.model_dump(mode="json")):
                    raise ValueError("Retained closure journal differs from its immutable receipt")
                assert_closure_citations(db, call, receipt, recorded_tool_evidence_ids(db, call))
            elif call.status != "running":
                raise ValueError("Committed closure cannot be replaced by failed Tool history")
    except (LookupError, PermissionError, ValueError, HTTPException):
        return False
    return True
