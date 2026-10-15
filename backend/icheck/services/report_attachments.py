"""Immutable rendered bytes, with small authenticated retrieval manifests."""
from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ReportAttachment, ServiceReportInstance, new_id
from ..report_schemas import ReportAttachmentManifest, ReportExportFormat, parse_report_render
from .audit import record_audit_event
from .control_plane_auth import PrincipalContext
from .report_exports import MAX_EXPORT_BYTES, render_report_export
from .report_instances import visible_report_instance
from .report_storage import ReportStorageQuotaExceeded, locked_report_storage_policy


def render_attachment(
    instance: ServiceReportInstance, export_format: ReportExportFormat,
    principal: PrincipalContext,
) -> ReportAttachment:
    document = render_report_export(
        instance, parse_report_render(instance.snapshot), export_format,
    )
    return ReportAttachment(
        id=new_id(), instance_id=instance.id, export_format=export_format,
        snapshot_sha256=instance.content_sha256, content_sha256=document.sha256,
        size_bytes=len(document.body), media_type=document.media_type,
        renderer=document.renderer, body=document.body,
        tenant_id=principal.tenant_id, region_id=principal.region_id,
        created_by=principal.subject,
    )


def attachment_manifest(
    attachment: ReportAttachment, instance: ServiceReportInstance,
) -> ReportAttachmentManifest:
    return ReportAttachmentManifest(
        attachment_id=attachment.id, instance_id=instance.id,
        artifact_id=instance.artifact_id, artifact_version_id=instance.artifact_version_id,
        content_hash=instance.snapshot["content_hash"],
        snapshot_sha256=instance.content_sha256, document_sha256=attachment.content_sha256,
        size_bytes=attachment.size_bytes, export_format=attachment.export_format,
        media_type=attachment.media_type, renderer=attachment.renderer,
        filename=f"report-{attachment.id}.{attachment.export_format}",
    )


def verified_report_attachment(
    db: Session, attachment_id: str, principal: PrincipalContext,
) -> tuple[ReportAttachment, ServiceReportInstance]:
    attachment = db.scalar(select(ReportAttachment).where(
        ReportAttachment.id == attachment_id,
        ReportAttachment.tenant_id == principal.tenant_id,
        ReportAttachment.region_id == principal.region_id,
    ))
    if attachment is None:
        raise LookupError("Report attachment not found")
    instance = visible_report_instance(db, attachment.instance_id, principal)
    if (
        attachment.snapshot_sha256 != instance.content_sha256
        or len(attachment.body) != attachment.size_bytes
        or not 0 < attachment.size_bytes <= MAX_EXPORT_BYTES
        or hashlib.sha256(attachment.body).hexdigest() != attachment.content_sha256
    ):
        raise ValueError("Stored Report attachment integrity check failed")
    return attachment, instance


def create_report_attachment(
    db: Session, instance_id: str, export_format: ReportExportFormat,
    principal: PrincipalContext, *, commit: bool = True,
) -> tuple[ReportAttachmentManifest, bool]:
    policy = locked_report_storage_policy(db, principal, actor=principal.subject)
    instance = visible_report_instance(db, instance_id, principal)
    existing = db.scalar(select(ReportAttachment).where(
        ReportAttachment.instance_id == instance.id,
        ReportAttachment.export_format == export_format,
        ReportAttachment.tenant_id == principal.tenant_id,
        ReportAttachment.region_id == principal.region_id,
    ))
    if existing is not None:
        verified_report_attachment(db, existing.id, principal)
        manifest = attachment_manifest(existing, instance)
        if commit:
            db.commit()  # Release the accounting lock on an exact retry too.
        return manifest, False
    attachment = render_attachment(instance, export_format, principal)
    if (policy.max_attachment_bytes is not None
        and policy.used_attachment_bytes + attachment.size_bytes > policy.max_attachment_bytes):
        raise ReportStorageQuotaExceeded("Report attachment byte quota exceeded")
    db.add(attachment)
    policy.used_attachment_bytes += attachment.size_bytes
    db.flush()
    record_audit_event(
        db, event_type="report.attachment.created", actor_type=principal.principal_type,
        actor_id=principal.subject, entity_type="report_attachment", entity_id=attachment.id,
        details={"instance_id": instance.id, "snapshot_sha256": instance.content_sha256,
                 "document_sha256": attachment.content_sha256,
                 "size_bytes": attachment.size_bytes, "export_format": export_format},
    )
    manifest = attachment_manifest(attachment, instance)
    if commit:
        db.commit()
    return manifest, True
