"""Exact-generation peer governance. Acceptance is not cutover or closure.

Acquire the complete sorted deployment mutex prefix before origin locks.
Lower origin/source locks are NOWAIT, so overlapping multi-source operations
abort instead of waiting while retaining an earlier origin chain. Historical
qualification uses retained sealed provenance, never a retired Worker login.
"""
from __future__ import annotations

import json
from datetime import timedelta

from sqlalchemy import select

from ..collector_condition_schemas import CollectorConditionDefinition, CollectorConditionObservation, evaluate_condition
from ..database import session_namespace
from ..models import (CollectorConditionAdmission, CollectorConditionReceipt, CollectorConditionSource,
    CollectorDeployment, CollectorRun, CollectorSourceQualificationRequest,
    CollectorSourceQualificationReview, CollectorSourceQualificationRevocation,
    CollectorSourceReplacementRequest, CollectorSourceReplacementReview,
    CollectorSourceReplacementRevocation, CollectorSourceRetirement, utcnow)
from ..source_replacement_schemas import SourceReplacementDetailRead
from .alert_conditions import as_utc
from .audit import record_audit_event
from .authorization_scope import has_global_scope
from .collector_conditions import canonical
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext
from .source_qualifications import (MANAGE, QUALIFY, SOURCE_FIELDS, _actor, _human, _lock_origin,
    _row, _start, require_source_access)

REVIEW = "alerts.sources.replace.qualify"
PROTOCOL = "icheck.collector.source-replacement/v1"
SEMANTIC_FIELDS = ("event_type", "entity_type", "operator", "expected", "unit")


def _scope(db, sources, actor):
    for source in sources:
        require_source_access(db, source, actor)
        # Custom knowledge/external entities cannot inherit Device ownership
        # as an unsupported entity ACL. Fail closed until they have such ACLs.
        if source.entity_type not in {"device", "endpoint"} and not has_global_scope(actor):
            raise LookupError("Source replacement resource not found")


def _authority(db, sources, actor, permission, *, human_only=False, material=True, nowait=False):
    if not actor.permits(permission) or (material and not actor.permits("capabilities.read")):
        raise PermissionError("Source replacement requires initiating and current authority")
    _scope(db, sources, actor)
    current = _actor(db, actor, permission, human_only=human_only, material_access_required=material, nowait=nowait)
    _scope(db, sources, current)
    return current


def _namespace_query(db, model):
    namespace = session_namespace(db)
    if namespace is None:
        raise PermissionError("Source replacement requires a selected namespace")
    return select(model).where(model.tenant_id == namespace[0], model.region_id == namespace[1])


def _pair(db, value):
    old = _row(db, CollectorConditionSource, value.old_source_id)
    new = _row(db, CollectorConditionSource, value.new_source_id)
    if old.id == new.id:
        raise ValueError("Replacement requires distinct source generations")
    for deployment_id in sorted({old.deployment_id, new.deployment_id}):
        _row(db, CollectorDeployment, deployment_id, lock=True)
    return old, new


def _qualification(db, source, review_id):
    review = _row(db, CollectorSourceQualificationReview, review_id)
    request = _row(db, CollectorSourceQualificationRequest, review.request_id)
    if request.source_id != source.id:
        raise LookupError("Source replacement qualification not found")
    if db.scalar(_namespace_query(db, CollectorSourceQualificationRevocation).where(
        CollectorSourceQualificationRevocation.review_id == review.id)):
        raise ValueError("Source replacement cannot use revoked source acceptance")
    return request, review


def _historical(db, source, request):
    """Validate retained baseline meaning without refreshing old live origin."""
    receipt = _row(db, CollectorConditionReceipt, request.baseline_receipt_id)
    return historical_source_receipt(db, source, request, receipt, baseline=True)


def historical_source_receipt(db, source, request, receipt, *, baseline=False):
    """Exact accepted typed provenance; never require retired live ownership."""
    admission = _row(db, CollectorConditionAdmission, receipt.admission_id)
    run = _row(db, CollectorRun, admission.run_id)
    pins = request.snapshot.get("pins")
    if (request.source_id != source.id or not isinstance(pins, dict) or set(SOURCE_FIELDS) - pins.keys()
        or canonical({key: pins[key] for key in SOURCE_FIELDS}) != canonical(source.context)
        or canonical(pins) != canonical(admission.context.get("pins"))
        or request.snapshot.get("worker_auth_method") != admission.context.get("worker_auth_method")
        or receipt.source_id != source.id or receipt.disposition != "accepted"
        or receipt.verdict not in {"active", "quiet"}
        or source.deployment_id != admission.deployment_id or run.deployment_id != source.deployment_id
        or source.artifact_version_id != admission.artifact_version_id
        or run.artifact_version_id != source.artifact_version_id or run.worker_id != admission.worker_id
        or source.assignment_sha256 != pins.get("assignment_sha256")
        or as_utc(receipt.observed_at) != as_utc(admission.observed_at)
        or (baseline and as_utc(receipt.observed_at) > as_utc(request.created_at))
        or as_utc(receipt.observed_at) > utcnow()):
        raise ValueError("Historical source acceptance does not match sealed baseline provenance")
    definition = CollectorConditionDefinition.model_validate(source.context["definition"])
    observation = CollectorConditionObservation.model_validate(json.loads(admission.payload))
    verdict = evaluate_condition(definition, observation)
    entity = pins.get("entity", {})
    if (verdict is None or ("active" if verdict else "quiet") != receipt.verdict
        or observation.condition_key != source.condition_key or definition.key != source.condition_key
        or entity.get("id") != source.entity_id or entity.get("type") != source.entity_type
        or (observation.entity_id is not None and observation.entity_id != source.entity_id)):
        raise ValueError("Historical source baseline has incompatible typed condition identity")
    return definition


def _material(db, value, sources, *, applied_retirement=None, nonblocking_authority=False):
    old, new = sources
    # The current origin chain uses only nonblocking lower locks after the
    # complete deployment prefix. Both qualification checks are repeated AFTER
    # all source mutexes have been acquired, refreshing post-wait snapshots.
    new_request, _ = _qualification(db, new, value.new_qualification_review_id)
    new, new_snapshot, new_definition = _lock_origin(db, new.id, new_request.baseline_receipt_id, nowait=True)
    for source in sorted((old, new), key=lambda row: row.id):
        _row(db, CollectorConditionSource, source.id, lock=True, nowait=True)
    retirement = db.scalar(_namespace_query(db, CollectorSourceRetirement).where(
        CollectorSourceRetirement.old_source_id == old.id))
    applied = (applied_retirement is not None and retirement is not None
        and applied_retirement.id == retirement.id and retirement.request_id == value.id
        and retirement.old_source_id == old.id and retirement.new_source_id == new.id
        and value.prior_retirement_id is None)
    if (retirement.id if retirement else None) != value.prior_retirement_id and not applied:
        raise ValueError("Historical replacement must explicitly bind the original permanent retirement")
    old_request, old_review = _qualification(db, old, value.old_qualification_review_id)
    new_request, new_review = _qualification(db, new, value.new_qualification_review_id)
    old_definition = _historical(db, old, old_request)
    if (canonical(new_request.snapshot) != canonical(new_snapshot)
        or as_utc(new_request.expires_at) <= utcnow()
        or as_utc(value.expires_at) > as_utc(new_request.expires_at)):
        raise ValueError("Replacement new source acceptance changed, expired or is outlived")
    if old_request.evidence_environment != value.evidence_environment or new_request.evidence_environment != value.evidence_environment:
        raise ValueError("Replacement evidence environment must match both source acceptances")
    for principal_id, subject, permission in (
        (new_request.author_principal_id, new_request.author_subject, MANAGE),
        (new_review.reviewer_principal_id, new_review.reviewer_subject, QUALIFY)):
        peer = _human(db, principal_id, subject, permission, material_access_required=True, nowait=nonblocking_authority)
        _scope(db, [new], peer)
    old_semantics = {key: old_definition.model_dump(mode="json")[key] for key in SEMANTIC_FIELDS}
    new_semantics = {key: new_definition.model_dump(mode="json")[key] for key in SEMANTIC_FIELDS}
    if canonical(old_semantics) != canonical(new_semantics):
        raise ValueError("Source replacement cannot change normalized condition semantics")
    if (old.entity_type, old.entity_id) != (new.entity_type, new.entity_id):
        raise ValueError("Source replacement requires the same normalized entity identity")
    def pin(source, request, review):
        return {"source_id": source.id, "qualification_request_id": request.id,
            "qualification_review_id": review.id, "baseline_receipt_id": request.baseline_receipt_id,
            "qualification_snapshot": request.snapshot}
    return {"old": pin(old, old_request, old_review), "new": pin(new, new_request, new_review),
        "semantics": old_semantics, "entity": {"type": old.entity_type, "id": old.entity_id}}


def _audit(db, event_type, actor, row):
    record_audit_event(db, event_type=event_type, actor_type=actor.principal_type, actor_id=actor.subject,
        entity_type="collector_source_replacement", entity_id=row.id,
        details={"authorizes_incident_closure": False, "physical_truth_automatically_verified": False,
            "producer_cutover_performed": False})


def propose_source_replacement(db, payload, actor):
    _start(db)
    sources = _pair(db, payload)
    current = _authority(db, sources, actor, MANAGE)
    now = utcnow()
    if not now < as_utc(payload.expires_at) <= now + timedelta(days=30):
        raise ValueError("Source replacement expiry must be future and within thirty days")
    material = _material(db, payload, sources)
    snapshot = {"protocol": PROTOCOL, "material": material,
        "initiating_authority": {"permissions": sorted(actor.permissions), "scope": actor.authorization_scope},
        "verification_basis": "peer_reviewed_external_attestation",
        "physical_truth_automatically_verified": False, "authorizes_incident_closure": False}
    assert_no_inline_secrets({**payload.model_dump(mode="json"), "snapshot": snapshot})
    if len(canonical(snapshot)) > 524288:
        raise ValueError("Source replacement snapshot exceeds its bound")
    values = payload.model_dump(exclude={"expires_at"})
    previous = db.scalar(_namespace_query(db, CollectorSourceReplacementRequest).where(
        CollectorSourceReplacementRequest.request_key == payload.request_key))
    if previous:
        if (previous.author_principal_id != current.principal_id or previous.author_subject != current.subject
            or as_utc(previous.expires_at) != as_utc(payload.expires_at)
            or canonical(previous.snapshot) != canonical(snapshot)
            or any(getattr(previous, key) != value for key, value in values.items())):
            raise ValueError("Source replacement request key was reused with different material or author")
        return previous
    row = CollectorSourceReplacementRequest(**values, expires_at=as_utc(payload.expires_at), snapshot=snapshot,
        author_principal_id=current.principal_id, author_subject=current.subject)
    db.add(row); db.flush()
    _audit(db, "collector.source.replacement.proposed", current, row); db.flush()
    return row


def review_source_replacement(db, request_id, payload, actor):
    _start(db)
    request = _row(db, CollectorSourceReplacementRequest, request_id)
    sources = _pair(db, request)
    current = _authority(db, sources, actor, REVIEW, human_only=True)
    frozen = request.snapshot["initiating_authority"]
    namespace = session_namespace(db)
    author = PrincipalContext(principal_id=request.author_principal_id, subject=request.author_subject,
        principal_type="user", permissions=frozenset(frozen["permissions"]), role_names=(),
        authorization_scope=frozen["scope"], auth_method="source_replacement_request",
        tenant_id=namespace[0], region_id=namespace[1])
    author = _authority(db, sources, author, MANAGE)
    if author.principal_id == current.principal_id or author.subject == current.subject:
        raise PermissionError("Source replacement acceptance requires an independent human peer")
    material = _material(db, request, sources)
    if (as_utc(request.expires_at) <= utcnow() or request.snapshot.get("protocol") != PROTOCOL
        or canonical(material) != canonical(request.snapshot.get("material"))):
        raise ValueError("Source replacement proposal expired or its exact material changed")
    for side in ("old", "new"):
        actors = material[side]["qualification_snapshot"]["version_actors"]
        if current.subject in {actors.get(key) for key in ("created_by", "validated_by", "published_by")}:
            raise PermissionError("Replacement reviewer cannot be either Collector author, validator or publisher")
    request = _row(db, CollectorSourceReplacementRequest, request.id, lock=True, nowait=True)
    assert_no_inline_secrets(payload.model_dump())
    previous = db.scalar(_namespace_query(db, CollectorSourceReplacementReview).where(
        CollectorSourceReplacementReview.request_id == request.id))
    if previous:
        if db.scalar(_namespace_query(db, CollectorSourceReplacementRevocation).where(
            CollectorSourceReplacementRevocation.review_id == previous.id)):
            raise ValueError("Revoked replacement acceptance cannot be reactivated by retry")
        if (previous.reviewer_principal_id != current.principal_id or previous.reviewer_subject != current.subject
            or previous.acceptance_reference != payload.acceptance_reference or previous.reason != payload.reason):
            raise ValueError("Source replacement review retry differs from immutable history")
        return previous
    row = CollectorSourceReplacementReview(request_id=request.id, reviewer_principal_id=current.principal_id,
        reviewer_subject=current.subject, acceptance_reference=payload.acceptance_reference, reason=payload.reason)
    db.add(row); db.flush()
    _audit(db, "collector.source.replacement.accepted", current, row); db.flush()
    return row


def revoke_source_replacement(db, review_id, payload, actor):
    _start(db)
    review = _row(db, CollectorSourceReplacementReview, review_id)
    request = _row(db, CollectorSourceReplacementRequest, review.request_id)
    sources = _pair(db, request)
    current = _authority(db, sources, actor, REVIEW, human_only=True, material=False)
    for source in sorted(sources, key=lambda row: row.id):
        _row(db, CollectorConditionSource, source.id, lock=True, nowait=True)
    _row(db, CollectorSourceReplacementRequest, request.id, lock=True, nowait=True)
    assert_no_inline_secrets(payload.model_dump())
    previous = db.scalar(_namespace_query(db, CollectorSourceReplacementRevocation).where(
        CollectorSourceReplacementRevocation.review_id == review.id))
    if previous:
        if previous.principal_id != current.principal_id or previous.subject != current.subject or previous.reason != payload.reason:
            raise ValueError("Source replacement revocation retry differs from immutable history")
        return previous
    row = CollectorSourceReplacementRevocation(review_id=review.id, principal_id=current.principal_id,
        subject=current.subject, reason=payload.reason)
    db.add(row); db.flush()
    _audit(db, "collector.source.replacement.revoked", current, row); db.flush()
    return row


def source_replacement_detail(db, request_id, actor):
    """Unchanged retained proof, scoped on BOTH sources; no fresh attestation."""
    request = _row(db, CollectorSourceReplacementRequest, request_id)
    sources = [_row(db, CollectorConditionSource, request.old_source_id),
        _row(db, CollectorConditionSource, request.new_source_id)]
    _authority(db, sources, actor, "alerts.read")
    review = db.scalar(_namespace_query(db, CollectorSourceReplacementReview).where(
        CollectorSourceReplacementReview.request_id == request.id))
    revocation = db.scalar(_namespace_query(db, CollectorSourceReplacementRevocation).where(
        CollectorSourceReplacementRevocation.review_id == review.id)) if review else None
    applied = db.scalar(_namespace_query(db, CollectorSourceRetirement).where(CollectorSourceRetirement.request_id == request.id))
    return SourceReplacementDetailRead.model_validate({"request": request, "review": review, "revocation": revocation,
        "producer_cutover_performed": applied is not None, "retirement_id": applied.id if applied else None})
