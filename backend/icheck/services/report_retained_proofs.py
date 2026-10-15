"""Typed historical report material, never fresh cutover or closure authority."""
from __future__ import annotations

from fastapi import HTTPException

from ..database import session_namespace
from ..models import (CollectorConditionSource, CollectorSourceReplacementRequest,
    SituationClosureReceipt, SituationClosureGrant, SituationRecoveryPolicyReview, SituationRecoveryPolicyRequest)
from ..report_schemas import ReportInitiatingReader, ReportRetainedProofSection
from ..source_replacement_schemas import SourceReplacementRequestRead
from .collector_conditions import canonical
from .control_plane_auth import PrincipalContext
from .source_qualifications import _row


def initiating_reader(principal):
    if not principal.principal_id or principal.principal_type not in {"user", "service"}:
        raise PermissionError("Retained-proof reports require a persisted initiating identity")
    return ReportInitiatingReader(principal_id=principal.principal_id, subject=principal.subject,
        principal_type=principal.principal_type, permissions=sorted(
            permission for permission in ("services.read", "alerts.read", "capabilities.read") if principal.permits(permission)),
        authorization_scope=principal.authorization_scope)


def frozen_reader(value, principal):
    return PrincipalContext(principal_id=str(value.principal_id), subject=value.subject,
        principal_type=value.principal_type, permissions=frozenset(value.permissions), role_names=(),
        authorization_scope=value.authorization_scope, auth_method="retained-report-snapshot",
        tenant_id=principal.tenant_id, region_id=principal.region_id)


def retained_section(db, selector, principal, *, original=None):
    """Resolve exact immutable material and check current plus frozen read scope.

    Original-reader scope is a bound, not a fresh login or an old peer/origin
    attestation. Current persisted authority is checked by the domain reader.
    """
    if session_namespace(db) != (principal.tenant_id, principal.region_id):
        raise LookupError("Retained report proof is outside the selected namespace")
    identity = str(selector.reference_id)
    try:
        # Delegated Investigations hold a permission snapshot. It cannot retain
        # services.read after the initiating principal's live role is revoked.
        from .source_qualifications import _actor
        if not principal.permits("services.read"):
            raise PermissionError("Retained report reader lacks service read permission")
        _actor(db, principal, "services.read", human_only=False)
        if selector.reference_kind == "source_replacement_request":
            from .source_replacements import _authority, _scope
            row = _row(db, CollectorSourceReplacementRequest, identity)
            sources = [_row(db, CollectorConditionSource, value) for value in (row.old_source_id, row.new_source_id)]
            _authority(db, sources, principal, "alerts.read")
            if original is not None:
                if not original.permits("alerts.read", "capabilities.read"):
                    raise PermissionError("Initiating report reader lacks retained source permission")
                _scope(db, sources, original)
            recorded = SourceReplacementRequestRead.model_validate(row)
        elif selector.reference_kind == "source_retirement":
            from .source_retirements import read_source_retirement, retirement_reference_scope
            from ..models import CollectorSourceRetirement
            recorded = read_source_retirement(db, identity, principal)
            if original is not None:
                if not original.permits("capabilities.read"):
                    raise PermissionError("Initiating report reader lacks retained source material permission")
                retirement_reference_scope(db, _row(db, CollectorSourceRetirement, identity), original)
        elif selector.reference_kind == "situation_closure_receipt":
            from .situation_closure_reads import (read_receipt, historical_identity_scope,
                historical_recovery_scope, historical_action_scope)
            from .situation_closure import _policy_scope
            row = _row(db, SituationClosureReceipt, identity)
            recorded = read_receipt(db, row, principal)
            if original is not None:
                if not original.permits("alerts.read"):
                    raise PermissionError("Initiating report reader lacks retained closure permission")
                proof = row.proof
                membership = proof["membership_identity"]
                historical_identity_scope(db, membership, row.situation_id, original)
                grant = _row(db, SituationClosureGrant, row.grant_id)
                review = _row(db, SituationRecoveryPolicyReview, grant.policy_review_id)
                policy = _row(db, SituationRecoveryPolicyRequest, review.request_id)
                _policy_scope(db, policy, original)
                historical_recovery_scope(db, proof["recovery"], policy, review.id, membership, original)
                for action in proof["related_actions"]:
                    historical_action_scope(db, action, original)
        else:
            raise ValueError("Unsupported retained report proof kind")
    except (PermissionError, HTTPException) as exc:
        raise LookupError("Retained report proof is unavailable in the current and initiating scope") from exc
    return ReportRetainedProofSection(section_key=selector.section_key, title=selector.title,
        reference_kind=selector.reference_kind, reference_id=selector.reference_id, recorded=recorded)


def verify_retained_sections(db, snapshot, principal):
    original = frozen_reader(snapshot.initiating_reader, principal)
    if len(snapshot.retained_proofs) != len(snapshot.spec.retained_proofs):
        raise ValueError("Retained report proof membership is incomplete")
    for selector, recorded in zip(snapshot.spec.retained_proofs, snapshot.retained_proofs, strict=True):
        expected = retained_section(db, selector, principal, original=original)
        if canonical(expected.model_dump(mode="json")) != canonical(recorded.model_dump(mode="json")):
            raise ValueError("Retained report proof differs from its exact immutable domain material")
    return original


def investigation_proof_reports_visible(db, investigation, principal):
    """Immutable saved-evidence links, not editable Tool registrations, bind history."""
    from sqlalchemy import select
    from ..models import InvestigationEvidence, ServiceReportInstance
    from .report_instances import visible_report_instance
    namespace = (investigation.tenant_id, investigation.region_id)
    ids = list(db.scalars(select(ServiceReportInstance.id)
        .join(InvestigationEvidence, InvestigationEvidence.report_instance_id == ServiceReportInstance.id)
        .where(InvestigationEvidence.investigation_id == investigation.id,
            InvestigationEvidence.tenant_id == namespace[0], InvestigationEvidence.region_id == namespace[1],
            ServiceReportInstance.tenant_id == namespace[0], ServiceReportInstance.region_id == namespace[1],
            ServiceReportInstance.snapshot["format_version"].as_string() == "icheck.service-health-report-render/v2")
        .distinct().order_by(ServiceReportInstance.id).limit(1001)))
    if len(ids) > 1000:
        return False
    try:
        for identity in ids:
            visible_report_instance(db, identity, principal)
    except (LookupError, PermissionError, ValueError, HTTPException):
        return False
    return True
