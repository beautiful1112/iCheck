"""Reusable, revocable peer acceptance of ONE exact Collector source generation.

Human attestations are not automatic physical truth. Quiet checks cover one
Alert, never Situation membership or permission to close it. All supported
operations lock origin -> source -> proof rows, matching the Collector writer;
they never take a Situation lock or a reverse Alert row lock.
"""
from __future__ import annotations

import json
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..collector_condition_schemas import CollectorConditionObservation, evaluate_condition
from ..config import get_settings
from ..database import require_locking_transaction, session_namespace
from ..models import (Alert, AlertConditionState, AlertStatus, ArtifactVersion, CollectorConditionAdmission,
    CollectorConditionReceipt, CollectorConditionSource, CollectorRun, CollectorWorker,
    CollectorSourceQualificationRequest, CollectorSourceQualificationReview,
    CollectorSourceQualificationRevocation, ControlPlanePrincipal, ControlPlaneRole,
    ControlPlaneRoleBinding, utcnow)
from ..source_qualification_schemas import SourceQuietEvidenceRead
from .alert_conditions import as_utc
from .audit import record_audit_event
from .authorization_scope import (has_global_scope, require_alert_access,
    require_device_access, require_endpoint_access, require_site_access)
from .collector_conditions import _snapshot, canonical
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext, _merge_authorization_scopes

MANAGE = "alerts.manage"
QUALIFY = "alerts.sources.qualify"
SOURCE_FIELDS = ("definition", "version_content_hash", "version_material",
    "assignment_sha256", "deployment", "credential_profile", "entity")


def _row(db, model, row_id, *, lock=False, nowait=False):
    namespace = session_namespace(db)
    if namespace is None:
        raise PermissionError("Source qualification requires a selected namespace")
    query = select(model).where(model.id == row_id, model.tenant_id == namespace[0])
    if model is not ControlPlanePrincipal:
        query = query.where(model.region_id == namespace[1])
    if lock:
        query = query.with_for_update(nowait=nowait)
    row = db.scalar(query.execution_options(populate_existing=True))
    if row is None:
        raise LookupError("Source qualification resource not found")
    return row


def _start(db):
    require_locking_transaction(db, purpose="Collector source qualification")
    # Do not let uncommitted caller edits become a substitute for persisted
    # source material or fresh authority. Existing authenticated API calls have
    # no pending writes here; each service operation owns its explicit flush.
    if db.new or db.deleted or any(db.is_modified(row, include_collections=True) for row in db.dirty):
        raise ValueError("Commit pending edits before source qualification")


def _human(db, principal_id, subject, permission, *, human_only=True, material_access_required=False, nowait=False):
    person = _row(db, ControlPlanePrincipal, principal_id)
    # Shared locks prevent revocation during this transaction while allowing
    # distinct independent reviewers to operate concurrently.
    person = db.scalar(select(ControlPlanePrincipal).where(
        ControlPlanePrincipal.id == person.id, ControlPlanePrincipal.tenant_id == person.tenant_id)
        .with_for_update(read=True, nowait=nowait).execution_options(populate_existing=True))
    namespace = session_namespace(db)
    if (not person.enabled or person.subject != subject or (human_only and person.principal_type != "user")
        or (person.allowed_region_ids and namespace[1] not in person.allowed_region_ids)):
        raise PermissionError("Qualification requires a current persisted human identity")
    bindings = list(db.scalars(select(ControlPlaneRoleBinding).where(
        ControlPlaneRoleBinding.principal_id == person.id,
        ControlPlaneRoleBinding.tenant_id == namespace[0], ControlPlaneRoleBinding.region_id == namespace[1])
        .order_by(ControlPlaneRoleBinding.id).with_for_update(read=True, nowait=nowait)
        .execution_options(populate_existing=True)).all())
    roles = list(db.scalars(select(ControlPlaneRole).where(
        ControlPlaneRole.id.in_([row.role_id for row in bindings]),
        ControlPlaneRole.tenant_id == namespace[0], ControlPlaneRole.region_id == namespace[1])
        .order_by(ControlPlaneRole.id).with_for_update(read=True, nowait=nowait)
        .execution_options(populate_existing=True)).all())
    actor = PrincipalContext(principal_id=person.id, subject=person.subject, principal_type=person.principal_type,
        permissions=frozenset(item for role in roles for item in role.permissions),
        role_names=tuple(role.name for role in roles), authorization_scope=_merge_authorization_scopes(bindings),
        auth_method="source_qualification", tenant_id=namespace[0], region_id=namespace[1])
    if not actor.permits(permission):
        raise PermissionError("Source qualification role was revoked or is unavailable")
    if material_access_required and not actor.permits("capabilities.read"):
        raise PermissionError("Source qualification requires current Collector implementation read permission")
    return actor


def _actor(db, actor, permission, *, human_only=True, material_access_required=False, nowait=False):
    if not actor.principal_id or (actor.tenant_id, actor.region_id) != session_namespace(db):
        raise PermissionError("Source qualification requires a persisted human in the selected namespace")
    return _human(db, actor.principal_id, actor.subject, permission, human_only=human_only,
        material_access_required=material_access_required, nowait=nowait)


def require_source_access(db, source, actor):
    if (source.tenant_id, source.region_id) != (actor.tenant_id, actor.region_id):
        raise LookupError("Collector condition source not found")
    deployment = source.context["deployment"]
    if deployment.get("scope_device_id"):
        require_device_access(db, actor, deployment["scope_device_id"])
    elif deployment.get("scope_site"):
        require_site_access(actor, deployment["scope_site"])
    elif not has_global_scope(actor):
        raise LookupError("Collector condition source not found")
    if source.entity_type == "device":
        require_device_access(db, actor, source.entity_id)
    elif source.entity_type == "endpoint":
        require_endpoint_access(db, actor, source.entity_id)
    elif source.entity_type == "external" and not has_global_scope(actor):
        raise LookupError("Collector condition source not found")


def _origin(db, source, receipt, *, nowait=False):
    if receipt.source_id != source.id or receipt.disposition != "accepted" or receipt.verdict == "unknown":
        raise ValueError("Qualification baseline must be an accepted typed active or quiet receipt for this source")
    admission = _row(db, CollectorConditionAdmission, receipt.admission_id)
    if as_utc(receipt.observed_at) != as_utc(admission.observed_at) or as_utc(receipt.observed_at) > utcnow():
        raise ValueError("Qualification baseline clock is mismatched or in the future")
    run = _row(db, CollectorRun, admission.run_id)
    observation = CollectorConditionObservation.model_validate(json.loads(admission.payload))
    pins, definition, _grant = _snapshot(db, run, observation, accepted_context=admission.context, nowait=nowait)
    if (run.deployment_id != source.deployment_id or run.artifact_version_id != source.artifact_version_id
        or run.worker_id != admission.worker_id
        or canonical({key: pins[key] for key in SOURCE_FIELDS}) != canonical(source.context)):
        raise ValueError("Qualification baseline does not match its exact source generation")
    active = evaluate_condition(definition, observation)
    if active is None or ("active" if active else "quiet") != receipt.verdict:
        raise ValueError("Qualification baseline is not a valid typed predicate result")
    if admission.context.get("worker_auth_method") == "bearer+verified_proxy_mtls":
        worker = _row(db, CollectorWorker, admission.worker_id)
        if worker.mtls_not_after is None or as_utc(worker.mtls_not_after) <= utcnow():
            raise ValueError("Qualification Worker certificate is expired or unavailable")
    version = _row(db, ArtifactVersion, source.artifact_version_id)
    snapshot = {"pins": pins, "worker_auth_method": admission.context["worker_auth_method"],
        "worker_mtls_mode": get_settings().worker_mtls_mode,
        "version_actors": {key: getattr(version, key) for key in ("created_by", "validated_by", "published_by")},
        "verification_basis": "peer_reviewed_external_attestation",
        "physical_truth_automatically_verified": False, "authorizes_incident_closure": False}
    return snapshot, definition


def _lock_origin(db, source_id, receipt_id, *, nowait=False):
    source = _row(db, CollectorConditionSource, source_id)
    receipt = _row(db, CollectorConditionReceipt, receipt_id)
    snapshot, definition = _origin(db, source, receipt, nowait=nowait)
    # Source is immutable; lock AFTER deployment/run/worker/device. It also
    # serializes proposal, peer acceptance, revocation and single-source checks.
    source = _row(db, CollectorConditionSource, source.id, lock=True, nowait=nowait)
    from .source_retirements import retirement_for_source
    if retirement_for_source(db, source.id) is not None:
        raise ValueError("Retired Collector source cannot regain current qualification")
    return source, snapshot, definition


def _audit(db, event, actor, row):
    record_audit_event(db, event_type=event, actor_type="user", actor_id=actor.subject,
        entity_type="collector_source_qualification", entity_id=row.id,
        details={"authorizes_incident_closure": False, "physical_truth_automatically_verified": False})


def propose_source_qualification(db: Session, source_id, payload, actor):
    _start(db)
    source, snapshot, _definition = _lock_origin(db, source_id, payload.baseline_receipt_id)
    actor = _actor(db, actor, MANAGE, material_access_required=True)
    require_source_access(db, source, actor)
    now = utcnow()
    if not now < as_utc(payload.expires_at) <= now + timedelta(days=30):
        raise ValueError("Source qualification expiry must be future and within thirty days")
    if payload.evidence_environment == "production" and (
        snapshot["worker_auth_method"] != "bearer+verified_proxy_mtls" or snapshot["worker_mtls_mode"] == "disabled"):
        raise ValueError("Production source acceptance requires verified Worker mTLS under an enabled policy")
    assert_no_inline_secrets({"validation_reference": payload.validation_reference, "reason": payload.reason})
    if len(canonical(snapshot)) > 131072:
        raise ValueError("Source qualification snapshot exceeds its bound")
    existing = db.scalar(select(CollectorSourceQualificationRequest).where(
        CollectorSourceQualificationRequest.source_id == source.id,
        CollectorSourceQualificationRequest.request_key == payload.request_key))
    if existing is not None:
        exact = (existing.author_principal_id == actor.principal_id and existing.author_subject == actor.subject
            and as_utc(existing.expires_at) == as_utc(payload.expires_at)
            and canonical(existing.snapshot) == canonical(snapshot)
            and all(getattr(existing, key) == value for key, value in payload.model_dump(exclude={"expires_at"}).items()))
        if not exact:
            raise ValueError("Source qualification request key was reused with different material or author")
        return existing
    row = CollectorSourceQualificationRequest(source_id=source.id, snapshot=snapshot,
        author_principal_id=actor.principal_id, author_subject=actor.subject,
        expires_at=as_utc(payload.expires_at), **payload.model_dump(exclude={"expires_at"}))
    db.add(row); db.flush()
    _audit(db, "collector.source.qualification.proposed", actor, row)
    db.flush()
    return row


def review_source_qualification(db: Session, request_id, payload, actor):
    _start(db)
    request = _row(db, CollectorSourceQualificationRequest, request_id)
    source, snapshot, _definition = _lock_origin(db, request.source_id, request.baseline_receipt_id)
    request = _row(db, CollectorSourceQualificationRequest, request.id, lock=True)
    actor = _actor(db, actor, QUALIFY, material_access_required=True)
    author = _human(db, request.author_principal_id, request.author_subject, MANAGE, material_access_required=True)
    require_source_access(db, source, actor); require_source_access(db, source, author)
    if actor.principal_id == author.principal_id or actor.subject == author.subject:
        raise PermissionError("Source acceptance requires an independent human peer")
    material = snapshot["version_actors"]
    if actor.subject in {material.get("created_by"), material.get("published_by"), material.get("validated_by")}:
        raise PermissionError("Source acceptance reviewer cannot be the Collector author, validator or publisher")
    if as_utc(request.expires_at) <= utcnow() or canonical(request.snapshot) != canonical(snapshot):
        raise ValueError("Source qualification proposal expired or its exact origin changed")
    assert_no_inline_secrets({"acceptance_reference": payload.acceptance_reference, "reason": payload.reason})
    previous = db.scalar(select(CollectorSourceQualificationReview).where(
        CollectorSourceQualificationReview.request_id == request.id))
    if previous is not None:
        if db.scalar(select(CollectorSourceQualificationRevocation.id).where(
            CollectorSourceQualificationRevocation.review_id == previous.id)):
            raise ValueError("Revoked source acceptance cannot be reactivated by retry")
        if (previous.reviewer_principal_id != actor.principal_id or previous.reviewer_subject != actor.subject
            or previous.acceptance_reference != payload.acceptance_reference or previous.reason != payload.reason):
            raise ValueError("Source acceptance retry differs from its immutable review")
        return previous
    row = CollectorSourceQualificationReview(request_id=request.id,
        reviewer_principal_id=actor.principal_id, reviewer_subject=actor.subject,
        acceptance_reference=payload.acceptance_reference, reason=payload.reason)
    db.add(row); db.flush()
    _audit(db, "collector.source.qualification.accepted", actor, row); db.flush()
    return row


def revoke_source_qualification(db: Session, review_id, payload, actor):
    _start(db)
    review = _row(db, CollectorSourceQualificationReview, review_id)
    request = _row(db, CollectorSourceQualificationRequest, review.request_id)
    # Revocation must remain possible even when origin or original peers are
    # no longer usable. Take the same deployment -> source order without
    # demanding a fresh, still-valid attestation or Collector run.
    from ..models import CollectorDeployment
    source = _row(db, CollectorConditionSource, request.source_id)
    _row(db, CollectorDeployment, source.deployment_id, lock=True)
    source = _row(db, CollectorConditionSource, source.id, lock=True)
    actor = _actor(db, actor, QUALIFY)
    require_source_access(db, source, actor)
    assert_no_inline_secrets({"reason": payload.reason})
    previous = db.scalar(select(CollectorSourceQualificationRevocation).where(
        CollectorSourceQualificationRevocation.review_id == review.id))
    if previous:
        if previous.principal_id != actor.principal_id or previous.subject != actor.subject or previous.reason != payload.reason:
            raise ValueError("Source revocation retry differs from immutable history")
        return previous
    row = CollectorSourceQualificationRevocation(review_id=review.id, principal_id=actor.principal_id,
        subject=actor.subject, reason=payload.reason)
    db.add(row); db.flush()
    _audit(db, "collector.source.qualification.revoked", actor, row); db.flush()
    return row


def source_quiet_evidence(db: Session, source_id, review_id, alert_id, actor, *, nonblocking_origin=False):
    """Fresh single-Alert check. A changed/hidden origin fails closed, never closes."""
    _start(db)
    review = _row(db, CollectorSourceQualificationReview, review_id)
    request = _row(db, CollectorSourceQualificationRequest, review.request_id)
    if request.source_id != source_id:
        raise LookupError("Source qualification resource not found")
    source, snapshot, definition = _lock_origin(db, source_id, request.baseline_receipt_id, nowait=nonblocking_origin)
    if actor.principal_id:
        actor = _actor(db, actor, "alerts.read", human_only=False)
    require_source_access(db, source, actor)
    blockers = []
    if canonical(snapshot) != canonical(request.snapshot):
        blockers.append("qualified_origin_changed")
    if as_utc(request.expires_at) <= utcnow():
        blockers.append("qualification_expired")
    if db.scalar(select(CollectorSourceQualificationRevocation.id).where(
        CollectorSourceQualificationRevocation.review_id == review.id)):
        blockers.append("qualification_revoked")
    for person_id, subject, permission in (
        (request.author_principal_id, request.author_subject, MANAGE),
        (review.reviewer_principal_id, review.reviewer_subject, QUALIFY)):
        try:
            peer = _human(db, person_id, subject, permission, material_access_required=True)
            require_source_access(db, source, peer)
        except (PermissionError, LookupError, HTTPException):
            blockers.append("qualification_peer_authority_unavailable")
    state = db.scalar(select(AlertConditionState).where(AlertConditionState.dedup_key == source.dedup_key)
        .with_for_update(nowait=nonblocking_origin).execution_options(populate_existing=True))
    alert = _row(db, Alert, alert_id)
    require_alert_access(db, actor, alert.id)
    if alert.dedup_key != source.dedup_key or state is None or state.latest_alert_id != alert.id:
        raise ValueError("Quiet evidence must bind the current exact source Alert episode")
    if state.state != "quiet" or alert.status != AlertStatus.RESOLVED:
        blockers.append("source_or_alert_not_quiet")
    receipt = db.scalar(select(CollectorConditionReceipt).where(
        CollectorConditionReceipt.source_id == source.id, CollectorConditionReceipt.condition_state_id == state.id,
        CollectorConditionReceipt.alert_id == alert.id, CollectorConditionReceipt.observed_at == state.observed_at,
        CollectorConditionReceipt.verdict == "quiet", CollectorConditionReceipt.disposition == "accepted")
        .order_by(CollectorConditionReceipt.id).limit(1))
    now = utcnow()
    if receipt is None:
        blockers.append("no_accepted_quiet_at_current_clock")
    else:
        at = as_utc(receipt.observed_at)
        if at > now or now - at > timedelta(seconds=definition.max_age_seconds):
            blockers.append("quiet_measurement_future_or_stale")
        quiet_snapshot, _definition = _origin(db, source, receipt, nowait=nonblocking_origin)
        if canonical(quiet_snapshot) != canonical(request.snapshot):
            blockers.append("quiet_receipt_origin_unqualified")
        active = db.scalar(select(CollectorConditionReceipt).where(
            CollectorConditionReceipt.source_id == source.id, CollectorConditionReceipt.alert_id == alert.id,
            CollectorConditionReceipt.verdict == "active", CollectorConditionReceipt.disposition == "accepted")
            .order_by(CollectorConditionReceipt.observed_at.desc()).limit(1))
        if active is None or as_utc(active.observed_at) >= at or at <= as_utc(alert.first_seen):
            blockers.append("no_earlier_accepted_active_episode")
    return SourceQuietEvidenceRead(source_id=source.id, alert_id=alert.id,
        receipt_id=receipt.id if receipt else None, qualification_review_id=review.id,
        evaluated_at=utcnow(), qualified_quiet=not blockers,
        production_qualified=not blockers and request.evidence_environment == "production",
        evidence_environment=request.evidence_environment, blockers=sorted(set(blockers)),
        observed_at=receipt.observed_at if receipt else None, condition_revision=state.revision,
        qualification_expires_at=request.expires_at)
