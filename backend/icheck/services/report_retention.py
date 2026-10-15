"""Reviewed, namespace-local retention controls for saved Report snapshots."""
from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import (
    InvestigationEvidence, ReportArchiveAcknowledgement, ReportArchiveVerification, ReportAttachment, ReportDeliveryReceipt,
    ReportLegalHold, ReportPurgeRequest, ReportPurgeTombstone,
    ServiceReportInstance, new_id, utcnow,
)
from ..report_schemas import (
    ReportArchiveAcknowledgeCreate, ReportLegalHoldCreate, ReportLegalHoldRelease,
    ReportPurgeCreate, ReportPurgeExecute, ReportPurgeReview,
)
from .audit import record_audit_event
from .control_plane_auth import PrincipalContext
from .report_instances import visible_report_instance
from .report_attachments import attachment_manifest
from .report_storage import locked_report_storage_policy
from .report_archives import (
    ReportArchiveUnavailable, archive_binding, fetch_archive_evidence,
    record_archive_failure, validate_fetch_evidence,
)


def _reason_hash(reason: str) -> str:
    return hashlib.sha256(reason.encode("utf-8")).hexdigest()


def _identity(principal: PrincipalContext) -> str:
    return principal.principal_id or principal.subject


def _instance(db: Session, instance_id: str, principal: PrincipalContext) -> ServiceReportInstance:
    return visible_report_instance(db, instance_id, principal)


def _archive(
    db: Session, instance: ServiceReportInstance, acknowledgement_id: str,
) -> ReportArchiveAcknowledgement:
    acknowledgement = db.scalar(select(ReportArchiveAcknowledgement).where(
        ReportArchiveAcknowledgement.id == acknowledgement_id,
        ReportArchiveAcknowledgement.instance_id == instance.id,
        ReportArchiveAcknowledgement.tenant_id == instance.tenant_id,
        ReportArchiveAcknowledgement.region_id == instance.region_id,
    ))
    if (
        acknowledgement is None
        or acknowledgement.artifact_version_id != instance.artifact_version_id
        or acknowledgement.snapshot_sha256 != instance.content_sha256
        or acknowledgement.snapshot_size_bytes != instance.snapshot_size_bytes
    ):
        raise ValueError("Archive acknowledgement does not match the saved Report")
    return acknowledgement


def _blockers(db: Session, instance: ServiceReportInstance) -> list[str]:
    namespace = (instance.tenant_id, instance.region_id)
    blockers: list[str] = []
    hold = db.scalar(select(ReportLegalHold.id).where(
        ReportLegalHold.instance_id == instance.id,
        ReportLegalHold.tenant_id == namespace[0], ReportLegalHold.region_id == namespace[1],
        ReportLegalHold.released_at.is_(None),
    ).limit(1))
    if hold is not None:
        blockers.append("active_legal_hold")
    evidence = db.scalar(select(InvestigationEvidence.id).where(
        InvestigationEvidence.report_instance_id == instance.id,
        InvestigationEvidence.tenant_id == namespace[0],
        InvestigationEvidence.region_id == namespace[1],
    ).limit(1))
    if evidence is not None:
        blockers.append("investigation_evidence")
    receipt = db.scalar(select(ReportDeliveryReceipt.id).where(
        ReportDeliveryReceipt.report_instance_id == instance.id,
        ReportDeliveryReceipt.tenant_id == namespace[0],
        ReportDeliveryReceipt.region_id == namespace[1],
    ).limit(1))
    if receipt is not None:
        blockers.append("delivery_receipt")
    return blockers


def _assert_clear(db: Session, instance: ServiceReportInstance) -> None:
    blockers = _blockers(db, instance)
    if blockers:
        raise ValueError("Report cannot be purged: " + ", ".join(blockers))


def read_report_retention(db: Session, instance_id: str, principal: PrincipalContext) -> dict:
    instance = db.scalar(select(ServiceReportInstance).where(
        ServiceReportInstance.id == instance_id,
        ServiceReportInstance.tenant_id == principal.tenant_id,
        ServiceReportInstance.region_id == principal.region_id,
    ))
    tombstone = db.scalar(select(ReportPurgeTombstone).where(
        ReportPurgeTombstone.instance_id == instance_id,
        ReportPurgeTombstone.tenant_id == principal.tenant_id,
        ReportPurgeTombstone.region_id == principal.region_id,
    ))
    if instance is None and tombstone is None:
        raise LookupError("Report instance not found")
    if instance is not None:
        _instance(db, instance_id, principal)
    namespace = (
        ReportArchiveAcknowledgement.tenant_id == principal.tenant_id,
        ReportArchiveAcknowledgement.region_id == principal.region_id,
    )
    acknowledgements = list(db.scalars(select(ReportArchiveAcknowledgement).where(
        ReportArchiveAcknowledgement.instance_id == instance_id, *namespace,
    ).order_by(ReportArchiveAcknowledgement.acknowledged_at, ReportArchiveAcknowledgement.id)))
    verifications = list(db.scalars(select(ReportArchiveVerification).where(
        ReportArchiveVerification.instance_id == instance_id,
        ReportArchiveVerification.tenant_id == principal.tenant_id,
        ReportArchiveVerification.region_id == principal.region_id,
    ).order_by(ReportArchiveVerification.verified_at, ReportArchiveVerification.id)))
    holds = list(db.scalars(select(ReportLegalHold).where(
        ReportLegalHold.instance_id == instance_id,
        ReportLegalHold.tenant_id == principal.tenant_id,
        ReportLegalHold.region_id == principal.region_id,
    ).order_by(ReportLegalHold.placed_at, ReportLegalHold.id)))
    requests = list(db.scalars(select(ReportPurgeRequest).where(
        ReportPurgeRequest.instance_id == instance_id,
        ReportPurgeRequest.tenant_id == principal.tenant_id,
        ReportPurgeRequest.region_id == principal.region_id,
    ).order_by(ReportPurgeRequest.requested_at, ReportPurgeRequest.id)))
    return {
        "instance_id": instance_id, "status": "retained" if instance is not None else "purged",
        "snapshot_sha256": instance.content_sha256 if instance is not None else tombstone.snapshot_sha256,
        "archive_acknowledgements": acknowledgements,
        "archive_verifications": verifications,
        "legal_holds": holds, "purge_requests": requests,
        "tombstone": tombstone,
        "blockers": _blockers(db, instance) if instance is not None else [],
    }


def acknowledge_report_archive(
    db: Session, instance_id: str, payload: ReportArchiveAcknowledgeCreate,
    principal: PrincipalContext,
) -> ReportArchiveAcknowledgement:
    locked_report_storage_policy(db, principal, actor=principal.subject)
    instance = _instance(db, instance_id, principal)
    if payload.snapshot_sha256 != instance.content_sha256:
        raise ValueError("Archive acknowledgement must pin the current saved snapshot digest")
    existing = db.scalar(select(ReportArchiveAcknowledgement).where(
        ReportArchiveAcknowledgement.instance_id == instance.id,
        ReportArchiveAcknowledgement.archive_reference == payload.archive_reference,
        ReportArchiveAcknowledgement.tenant_id == principal.tenant_id,
        ReportArchiveAcknowledgement.region_id == principal.region_id,
    ).execution_options(populate_existing=True))
    if existing is not None:
        if existing.snapshot_sha256 != instance.content_sha256:
            raise ValueError("Archive reference is already bound to another digest")
        db.commit()
        return existing
    acknowledgement = ReportArchiveAcknowledgement(
        id=new_id(), instance_id=instance.id,
        tenant_id=principal.tenant_id, region_id=principal.region_id,
        artifact_version_id=instance.artifact_version_id,
        snapshot_sha256=instance.content_sha256,
        snapshot_size_bytes=instance.snapshot_size_bytes,
        archive_reference=payload.archive_reference,
        reason_sha256=_reason_hash(payload.reason), acknowledged_by=principal.subject,
    )
    db.add(acknowledgement)
    db.flush()
    record_audit_event(
        db, event_type="report.archive.acknowledged", actor_type=principal.principal_type,
        actor_id=principal.subject, entity_type="service_report_instance", entity_id=instance.id,
        details={"acknowledgement_id": acknowledgement.id, "snapshot_sha256": instance.content_sha256,
                 "verification_level": "operator_asserted", "reason_sha256": acknowledgement.reason_sha256},
    )
    db.commit()
    return acknowledgement


def place_report_legal_hold(
    db: Session, instance_id: str, payload: ReportLegalHoldCreate,
    principal: PrincipalContext,
) -> ReportLegalHold:
    locked_report_storage_policy(db, principal, actor=principal.subject)
    instance = _instance(db, instance_id, principal)
    existing = db.scalar(select(ReportLegalHold).where(
        ReportLegalHold.instance_id == instance.id,
        ReportLegalHold.hold_reference == payload.hold_reference,
        ReportLegalHold.tenant_id == principal.tenant_id,
        ReportLegalHold.region_id == principal.region_id,
    ).execution_options(populate_existing=True))
    if existing is not None:
        if existing.released_at is not None:
            raise ValueError("A released legal hold reference cannot be reused")
        db.commit()
        return existing
    hold = ReportLegalHold(
        id=new_id(), instance_id=instance.id, snapshot_sha256=instance.content_sha256,
        tenant_id=principal.tenant_id, region_id=principal.region_id,
        hold_reference=payload.hold_reference, reason_sha256=_reason_hash(payload.reason),
        placed_by=principal.subject,
    )
    db.add(hold)
    db.flush()
    record_audit_event(
        db, event_type="report.legal_hold.placed", actor_type=principal.principal_type,
        actor_id=principal.subject, entity_type="service_report_instance", entity_id=instance.id,
        details={"hold_id": hold.id, "snapshot_sha256": instance.content_sha256,
                 "reason_sha256": hold.reason_sha256},
    )
    db.commit()
    return hold


def release_report_legal_hold(
    db: Session, hold_id: str, payload: ReportLegalHoldRelease,
    principal: PrincipalContext,
) -> ReportLegalHold:
    locked_report_storage_policy(db, principal, actor=principal.subject)
    hold = db.scalar(select(ReportLegalHold).where(
        ReportLegalHold.id == hold_id,
        ReportLegalHold.tenant_id == principal.tenant_id,
        ReportLegalHold.region_id == principal.region_id,
    ).with_for_update().execution_options(populate_existing=True))
    if hold is None:
        raise LookupError("Legal hold not found")
    if hold.released_at is not None:
        db.commit()
        return hold
    if hold.placed_by == principal.subject:
        raise ValueError("A different principal must release the legal hold")
    hold.released_by = principal.subject
    hold.release_reason_sha256 = _reason_hash(payload.reason)
    hold.released_at = utcnow()
    record_audit_event(
        db, event_type="report.legal_hold.released", actor_type=principal.principal_type,
        actor_id=principal.subject, entity_type="service_report_instance", entity_id=hold.instance_id,
        details={"hold_id": hold.id, "snapshot_sha256": hold.snapshot_sha256,
                 "reason_sha256": hold.release_reason_sha256},
    )
    db.commit()
    return hold


def _purge_request(db: Session, request_id: str, principal: PrincipalContext, *, lock=True) -> ReportPurgeRequest:
    query = select(ReportPurgeRequest).where(
        ReportPurgeRequest.id == request_id,
        ReportPurgeRequest.tenant_id == principal.tenant_id,
        ReportPurgeRequest.region_id == principal.region_id,
    ).execution_options(populate_existing=True)
    request = db.scalar(query.with_for_update() if lock else query)
    if request is None:
        raise LookupError("Report purge request not found")
    return request


def request_report_purge(
    db: Session, instance_id: str, payload: ReportPurgeCreate,
    principal: PrincipalContext,
) -> ReportPurgeRequest:
    locked_report_storage_policy(db, principal, actor=principal.subject)
    request_sha256 = hashlib.sha256((
        f"{_identity(principal)}:{payload.request_key}"
    ).encode("utf-8")).hexdigest()
    previous = db.scalar(select(ReportPurgeRequest).where(
        ReportPurgeRequest.request_sha256 == request_sha256,
        ReportPurgeRequest.tenant_id == principal.tenant_id,
        ReportPurgeRequest.region_id == principal.region_id,
    ).execution_options(populate_existing=True))
    if previous is not None:
        if (previous.instance_id != instance_id or previous.archive_acknowledgement_id != str(payload.archive_acknowledgement_id)
            or previous.archive_verification_id != (str(payload.archive_verification_id) if payload.archive_verification_id else None)):
            raise ValueError("Purge request key is bound to a different Report or archive acknowledgement")
        db.commit()
        return previous
    instance = _instance(db, instance_id, principal)
    _archive(db, instance, str(payload.archive_acknowledgement_id))
    _assert_clear(db, instance)
    archive_binding(db, instance, str(payload.archive_acknowledgement_id),
                    str(payload.archive_verification_id) if payload.archive_verification_id else None, principal)
    active_request = db.scalar(select(ReportPurgeRequest.id).where(
        ReportPurgeRequest.instance_id == instance.id,
        ReportPurgeRequest.tenant_id == principal.tenant_id,
        ReportPurgeRequest.region_id == principal.region_id,
        ReportPurgeRequest.status.in_(["requested", "approved"]),
    ).limit(1))
    if active_request is not None:
        raise ValueError("Another purge request is already pending for this Report")
    request = ReportPurgeRequest(
        id=new_id(), tenant_id=principal.tenant_id, region_id=principal.region_id,
        instance_id=instance.id, artifact_version_id=instance.artifact_version_id,
        snapshot_sha256=instance.content_sha256,
        snapshot_size_bytes=instance.snapshot_size_bytes,
        archive_acknowledgement_id=str(payload.archive_acknowledgement_id),
        archive_verification_id=str(payload.archive_verification_id),
        request_sha256=request_sha256, request_reason_sha256=_reason_hash(payload.reason),
        status="requested", requested_by=principal.subject,
        requester_identity=_identity(principal),
    )
    db.add(request)
    db.flush()
    record_audit_event(
        db, event_type="report.purge.requested", actor_type=principal.principal_type,
        actor_id=principal.subject, entity_type="service_report_instance", entity_id=instance.id,
        details={"purge_request_id": request.id, "archive_acknowledgement_id": request.archive_acknowledgement_id,
                 "archive_verification_id": request.archive_verification_id,
                 "snapshot_sha256": request.snapshot_sha256, "reason_sha256": request.request_reason_sha256},
    )
    db.commit()
    return request


def review_report_purge(
    db: Session, request_id: str, payload: ReportPurgeReview,
    principal: PrincipalContext,
) -> ReportPurgeRequest:
    locked_report_storage_policy(db, principal, actor=principal.subject)
    request = _purge_request(db, request_id, principal)
    if request.status != "requested" and not (request.status == "approved" and payload.decision == "reject"):
        raise ValueError("Only a requested Report purge can be reviewed")
    if request.requester_identity == _identity(principal):
        raise ValueError("The purge requester cannot review their own request")
    if payload.decision == "approve":
        instance = _instance(db, request.instance_id, principal)
        if (instance.content_sha256 != request.snapshot_sha256
            or instance.snapshot_size_bytes != request.snapshot_size_bytes
            or instance.artifact_version_id != request.artifact_version_id):
            raise ValueError("Report snapshot changed after the purge request")
        _archive(db, instance, request.archive_acknowledgement_id)
        _assert_clear(db, instance)
        archive_binding(db, instance, request.archive_acknowledgement_id, request.archive_verification_id, principal)
    request.status = "approved" if payload.decision == "approve" else "rejected"
    request.reviewed_by = principal.subject
    request.reviewer_identity = _identity(principal)
    request.review_reason_sha256 = _reason_hash(payload.reason)
    request.reviewed_at = utcnow()
    record_audit_event(
        db, event_type=f"report.purge.{request.status}", actor_type=principal.principal_type,
        actor_id=principal.subject, entity_type="service_report_instance", entity_id=request.instance_id,
        details={"purge_request_id": request.id, "snapshot_sha256": request.snapshot_sha256,
                 "reason_sha256": request.review_reason_sha256},
    )
    db.commit()
    return request


def execute_report_purge(
    db: Session, request_id: str, payload: ReportPurgeExecute,
    principal: PrincipalContext,
) -> ReportPurgeTombstone:
    request = _purge_request(db, request_id, principal, lock=False)
    if request.status == "executed":
        tombstone = db.get(ReportPurgeTombstone, request.instance_id)
        if tombstone is None:
            raise ValueError("Executed Report purge has no tombstone")
        return tombstone
    if request.status != "approved" or request.reviewer_identity is None:
        raise ValueError("Report purge requires a separate completed review")
    instance = _instance(db, request.instance_id, principal)
    if (instance.content_sha256 != request.snapshot_sha256
        or instance.snapshot_size_bytes != request.snapshot_size_bytes
        or instance.artifact_version_id != request.artifact_version_id):
        raise ValueError("Report snapshot changed after purge approval")
    _archive(db, instance, request.archive_acknowledgement_id)
    _assert_clear(db, instance)
    instance_id = instance.id
    try:
        verification, acknowledgement, package = archive_binding(
            db, instance, request.archive_acknowledgement_id, request.archive_verification_id, principal,
        )
        evidence = fetch_archive_evidence(db, verification.source_id, acknowledgement.archive_reference, package, principal)
        db.expire_all()
        policy = locked_report_storage_policy(db, principal, actor=principal.subject)
        request = _purge_request(db, request_id, principal)
        if request.status == "executed":
            tombstone = db.get(ReportPurgeTombstone, request.instance_id)
            if tombstone is None:
                raise ValueError("Executed Report purge has no tombstone")
            db.commit()  # Release accounting/request locks on the concurrent retry.
            return tombstone
        if request.status != "approved" or request.reviewer_identity is None:
            raise ValueError("Report purge approval changed during archive retrieval")
        instance = _instance(db, request.instance_id, principal)
        if (instance.content_sha256 != request.snapshot_sha256
            or instance.snapshot_size_bytes != request.snapshot_size_bytes
            or instance.artifact_version_id != request.artifact_version_id):
            raise ValueError("Report snapshot changed during archive retrieval")
        _, _, package = archive_binding(db, instance, request.archive_acknowledgement_id, request.archive_verification_id, principal)
        validate_fetch_evidence(db, evidence, package, principal)
        _assert_clear(db, instance)
    except (LookupError, ValueError, ReportArchiveUnavailable) as exc:
        record_archive_failure(db, instance_id, principal, exc, revalidation=True)
        raise
    if policy.used_instances < 1 or policy.used_bytes < instance.snapshot_size_bytes:
        raise ValueError("Report storage accounting drift blocks purge")
    if db.get(ReportPurgeTombstone, instance.id) is not None:
        raise ValueError("Report already has a purge tombstone")
    attachments = list(db.scalars(select(ReportAttachment).where(
        ReportAttachment.instance_id == instance.id,
        ReportAttachment.tenant_id == principal.tenant_id,
        ReportAttachment.region_id == principal.region_id,
    )))
    attachment_bytes = sum(item.size_bytes for item in attachments)
    if policy.used_attachment_bytes < attachment_bytes:
        raise ValueError("Report attachment accounting drift blocks purge")
    tombstone = ReportPurgeTombstone(
        instance_id=instance.id, artifact_id=instance.artifact_id,
        artifact_version_id=instance.artifact_version_id,
        request_sha256=instance.request_sha256,
        snapshot_sha256=instance.content_sha256,
        snapshot_size_bytes=instance.snapshot_size_bytes,
        attachments=[attachment_manifest(item, instance).model_dump(mode="json") for item in attachments],
        archive_acknowledgement_id=request.archive_acknowledgement_id,
        archive_verification_id=request.archive_verification_id,
        archive_revalidated_at=evidence.fetched_at,
        purge_request_id=request.id,
        tenant_id=principal.tenant_id, region_id=principal.region_id,
        deleted_by=principal.subject,
    )
    db.add(tombstone)
    request.status = "executed"
    request.executed_by = principal.subject
    request.execution_reason_sha256 = _reason_hash(payload.reason)
    request.executed_at = utcnow()
    policy.used_instances -= 1
    policy.used_bytes -= instance.snapshot_size_bytes
    policy.used_attachment_bytes -= attachment_bytes
    for attachment in attachments:
        db.delete(attachment)
    db.delete(instance)
    record_audit_event(
        db, event_type="report.purge.executed", actor_type=principal.principal_type,
        actor_id=principal.subject, entity_type="service_report_instance", entity_id=tombstone.instance_id,
        details={"purge_request_id": request.id, "archive_acknowledgement_id": request.archive_acknowledgement_id,
                 "archive_verification_id": request.archive_verification_id,
                 "archive_package_sha256": evidence.package_sha256,
                 "snapshot_sha256": tombstone.snapshot_sha256,
                 "snapshot_size_bytes": tombstone.snapshot_size_bytes,
                 "attachment_count": len(attachments), "attachment_bytes": attachment_bytes,
                 "reason_sha256": request.execution_reason_sha256},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Report acquired a protected evidence or delivery reference") from exc
    return tombstone
