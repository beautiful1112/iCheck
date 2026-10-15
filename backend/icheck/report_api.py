from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .auth import require_global_permissions, require_permissions
from .database import get_db
from .models import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
)
from .report_schemas import (
    PublishedServiceReport, ReportExportFormat, ServiceReportRender,
    ServiceReportInstanceCreate, ServiceReportInstanceRead, ServiceReportInstancePage,
    ReportStoragePolicyRead, ReportStoragePolicyUpdate,
    ReportArchiveAcknowledgeCreate, ReportArchiveAcknowledgementRead,
    ReportLegalHoldCreate, ReportLegalHoldRelease, ReportLegalHoldRead,
    ReportPurgeCreate, ReportPurgeExecute, ReportPurgeReview,
    ReportPurgeRequestRead, ReportPurgeTombstoneRead, ReportRetentionRead,
    ReportAttachmentCreate, ReportAttachmentManifest,
    ReportArchiveSourceCreate, ReportArchiveSourceRead, ReportArchiveSourceState,
    ReportArchiveVerifyCreate, ReportArchiveVerificationRead,
)
from .report_schemas import RetainedProofReportRender
from .services.authorization_scope import has_global_scope, namespace_clause
from .services.audit import record_audit_event
from .services.report_exports import HTML_CSP, render_report_export
from .services.report_instances import (
    capture_report_instance, instance_read, list_report_instances,
    visible_report_instance, verified_instance_snapshot, ReportDiscoveryScanBudgetExceeded,
)
from .services.report_storage import (
    ReportStorageQuotaExceeded, configure_report_storage_policy,
    read_report_storage_policy,
)
from .services.report_retention import (
    acknowledge_report_archive, execute_report_purge, place_report_legal_hold,
    read_report_retention, release_report_legal_hold, request_report_purge,
    review_report_purge,
)
from .services.report_attachments import (
    attachment_manifest, create_report_attachment, verified_report_attachment,
)
from .services.control_plane_auth import PrincipalContext
from .services.report_archives import (
    ReportArchiveUnavailable, archive_package, create_archive_source, list_archive_sources,
    set_archive_source_state, verify_report_archive,
)
from .services.service_health_reports import (
    verified_service_report_version_spec,
    service_report_version_summary,
    service_report_is_fully_visible,
    service_report_runtime_generate,
)


router = APIRouter(prefix="/api/v1/reports", tags=["reports"])
DBSession = Annotated[Session, Depends(get_db)]


@router.get("/storage", response_model=ReportStoragePolicyRead)
def get_report_storage(
    db: DBSession, response: Response,
    principal: PrincipalContext = Depends(require_global_permissions("services.manage")),
):
    response.headers["Cache-Control"] = "no-store"
    return read_report_storage_policy(db, principal)


@router.put("/storage", response_model=ReportStoragePolicyRead)
def put_report_storage(
    payload: ReportStoragePolicyUpdate, db: DBSession, response: Response,
    principal: PrincipalContext = Depends(require_global_permissions("services.manage")),
):
    try:
        result = configure_report_storage_policy(db, principal, payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    response.headers["Cache-Control"] = "no-store"
    return result


def _retention_error(exc: Exception) -> HTTPException:
    return HTTPException(
        status_code=404 if isinstance(exc, LookupError) else 502 if isinstance(exc, ReportArchiveUnavailable) else 409,
        detail=str(exc),
    )


def _retention_reader(
    request: Request, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("services.read")),
) -> PrincipalContext:
    if principal.permits("services.manage") or principal.permits("changes.approve"):
        return principal
    record_audit_event(
        db, event_type="auth.permission.denied",
        actor_type=principal.principal_type, actor_id=principal.subject,
        entity_type="api_route", entity_id=request.url.path, outcome="denied",
        details={"method": request.method, "required_any_permission": ["services.manage", "changes.approve"]},
    )
    db.commit()
    raise HTTPException(status_code=403, detail="Required permission: services.manage or changes.approve")


@router.get("/archive-sources", response_model=list[ReportArchiveSourceRead])
def get_report_archive_sources(db: DBSession, response: Response,
                             principal: PrincipalContext = Depends(_retention_reader)):
    response.headers["Cache-Control"] = "no-store"
    return list_archive_sources(db, principal)


@router.post("/archive-sources", response_model=ReportArchiveSourceRead, status_code=201)
def post_report_archive_source(payload: ReportArchiveSourceCreate, db: DBSession, response: Response,
                              principal: PrincipalContext = Depends(require_global_permissions("auth.admin", "services.manage"))):
    try:
        result = create_archive_source(db, payload, principal)
    except (LookupError, ValueError) as exc:
        raise _retention_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/archive-sources/{source_id}/state", response_model=ReportArchiveSourceRead)
def post_report_archive_source_state(source_id: str, payload: ReportArchiveSourceState, db: DBSession, response: Response,
                                    principal: PrincipalContext = Depends(require_global_permissions("auth.admin", "services.manage"))):
    try:
        result = set_archive_source_state(db, source_id, payload, principal)
    except (LookupError, ValueError) as exc:
        raise _retention_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return result


@router.get("/instances/{instance_id}/archive-export")
def get_report_archive_export(instance_id: str, db: DBSession,
                             principal: PrincipalContext = Depends(require_global_permissions("services.manage", "services.read"))):
    try:
        package = archive_package(db, instance_id, principal)
    except (LookupError, ValueError) as exc:
        raise _retention_error(exc) from exc
    return Response(package.body, media_type="application/json", headers={
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "X-Icheck-Archive-SHA256": package.sha256,
        "X-Icheck-Content-SHA256": package.sha256,
        "X-Icheck-Snapshot-SHA256": visible_report_instance(db, instance_id, principal).content_sha256,
        "Content-Disposition": f'attachment; filename="report-archive-{instance_id}.json"',
    })


@router.post("/instances/{instance_id}/archive-verifications", response_model=ReportArchiveVerificationRead, status_code=201)
def post_report_archive_verification(instance_id: str, payload: ReportArchiveVerifyCreate, db: DBSession, response: Response,
                                    principal: PrincipalContext = Depends(require_global_permissions("services.manage", "services.read"))):
    try:
        result = verify_report_archive(db, instance_id, payload, principal)
    except (LookupError, ValueError, ReportArchiveUnavailable) as exc:
        raise _retention_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return result


@router.get("/instances/{instance_id}/retention", response_model=ReportRetentionRead)
def get_saved_report_retention(
    instance_id: str, db: DBSession, response: Response,
    principal: PrincipalContext = Depends(_retention_reader),
):
    try:
        result = read_report_retention(db, instance_id, principal)
    except (LookupError, TypeError, ValueError) as exc:
        raise _retention_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/instances/{instance_id}/archive-acknowledgements",
             response_model=ReportArchiveAcknowledgementRead, status_code=201)
def create_saved_report_archive_acknowledgement(
    instance_id: str, payload: ReportArchiveAcknowledgeCreate, db: DBSession, response: Response,
    principal: PrincipalContext = Depends(require_global_permissions("services.manage", "services.read")),
):
    try:
        result = acknowledge_report_archive(db, instance_id, payload, principal)
    except (LookupError, TypeError, ValueError) as exc:
        raise _retention_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/instances/{instance_id}/legal-holds",
             response_model=ReportLegalHoldRead, status_code=201)
def create_saved_report_legal_hold(
    instance_id: str, payload: ReportLegalHoldCreate, db: DBSession, response: Response,
    principal: PrincipalContext = Depends(require_global_permissions("services.manage", "services.read")),
):
    try:
        result = place_report_legal_hold(db, instance_id, payload, principal)
    except (LookupError, TypeError, ValueError) as exc:
        raise _retention_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/legal-holds/{hold_id}/release", response_model=ReportLegalHoldRead)
def release_saved_report_legal_hold(
    hold_id: str, payload: ReportLegalHoldRelease, db: DBSession, response: Response,
    principal: PrincipalContext = Depends(require_global_permissions("services.manage", "changes.approve")),
):
    try:
        result = release_report_legal_hold(db, hold_id, payload, principal)
    except (LookupError, TypeError, ValueError) as exc:
        raise _retention_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/instances/{instance_id}/purge-requests",
             response_model=ReportPurgeRequestRead, status_code=201)
def create_saved_report_purge_request(
    instance_id: str, payload: ReportPurgeCreate, db: DBSession, response: Response,
    principal: PrincipalContext = Depends(require_global_permissions("services.manage", "services.read")),
):
    try:
        result = request_report_purge(db, instance_id, payload, principal)
    except (LookupError, TypeError, ValueError) as exc:
        raise _retention_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/purge-requests/{request_id}/review", response_model=ReportPurgeRequestRead)
def review_saved_report_purge_request(
    request_id: str, payload: ReportPurgeReview, db: DBSession, response: Response,
    principal: PrincipalContext = Depends(require_global_permissions("changes.approve", "services.read")),
):
    try:
        result = review_report_purge(db, request_id, payload, principal)
    except (LookupError, TypeError, ValueError) as exc:
        raise _retention_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/purge-requests/{request_id}/execute", response_model=ReportPurgeTombstoneRead)
def execute_saved_report_purge_request(
    request_id: str, payload: ReportPurgeExecute, db: DBSession, response: Response,
    principal: PrincipalContext = Depends(require_global_permissions("services.manage", "services.read")),
):
    try:
        result = execute_report_purge(db, request_id, payload, principal)
    except (LookupError, TypeError, ValueError, ReportArchiveUnavailable) as exc:
        raise _retention_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return result


def _published_query(principal: PrincipalContext):
    return (
        select(ArtifactVersion)
        .join(Artifact, Artifact.id == ArtifactVersion.artifact_id)
        .options(joinedload(ArtifactVersion.artifact))
        .where(
            Artifact.kind == ArtifactKind.REPORT,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
            namespace_clause(Artifact, principal), namespace_clause(ArtifactVersion, principal),
        )
    )


def _spec(version: ArtifactVersion):
    try:
        return verified_service_report_version_spec(version)
    except (TypeError, ValueError, ValidationError) as exc:
        raise HTTPException(
            status_code=409,
            detail="Published service report contract is invalid",
        ) from exc


def _is_service_health_report(version: ArtifactVersion) -> bool:
    return (
        version.definition.get("format_version")
        in {"icheck.service-health-report/v1", "icheck.service-health-report/v2"}
    )


def _summary(version: ArtifactVersion, spec) -> dict[str, object]:
    if version.published_at is None or version.content_hash is None:
        raise HTTPException(
            status_code=409,
            detail="Published service report provenance is incomplete",
        )
    return service_report_version_summary(version, spec)


@router.get("", response_model=list[PublishedServiceReport])
def list_published_service_reports(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=500),
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> list[dict[str, object]]:
    versions = db.scalars(
        _published_query(principal)
        .order_by(Artifact.name, ArtifactVersion.version.desc())
        .limit(500)
    ).all()
    visible: list[dict[str, object]] = []
    for version in versions:
        if not _is_service_health_report(version):
            continue
        spec = _spec(version)
        if service_report_is_fully_visible(db, spec, principal):
            visible.append(_summary(version, spec))
        if len(visible) >= limit:
            break
    return visible


@router.get(
    "/{artifact_id}/generate",
    response_model=ServiceReportRender | RetainedProofReportRender,
)
def generate_published_service_report(
    artifact_id: str,
    db: DBSession,
    version: int | None = Query(default=None, ge=1),
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> dict[str, object]:
    query = _published_query(principal).where(ArtifactVersion.artifact_id == artifact_id)
    if version is not None:
        query = query.where(ArtifactVersion.version == version)
    else:
        query = query.order_by(ArtifactVersion.version.desc())
    artifact_version = db.scalar(query)
    if artifact_version is None or not _is_service_health_report(
        artifact_version
    ):
        raise HTTPException(status_code=404, detail="Published report not found")
    spec = _spec(artifact_version)
    if not service_report_is_fully_visible(db, spec, principal):
        raise HTTPException(status_code=404, detail="Published report not found")
    generated = service_report_runtime_generate(db, spec, principal)
    return {
        **_summary(artifact_version, spec),
        **generated,
        "scope_applied": not has_global_scope(principal),
        "spec": spec,
    }


def _instance_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ReportDiscoveryScanBudgetExceeded):
        return HTTPException(status_code=409, detail="Report discovery scan budget exhausted; narrow the report selection")
    if isinstance(exc, LookupError):
        return HTTPException(status_code=404, detail="Report instance or exact version not found")
    return HTTPException(status_code=409, detail="Report snapshot contract, integrity, or request key is invalid")


@router.post("/{artifact_id}/instances", response_model=ServiceReportInstanceRead, status_code=201)
def save_service_report_instance(
    artifact_id: str, payload: ServiceReportInstanceCreate, response: Response, db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
):
    try:
        instance, created = capture_report_instance(db, artifact_id, payload, principal)
        response.status_code = 201 if created else 200
        response.headers["Cache-Control"] = "no-store"
        return instance_read(instance)
    except ReportStorageQuotaExceeded as exc:
        raise HTTPException(status_code=507, detail=str(exc)) from exc
    except (LookupError, TypeError, ValueError) as exc:
        raise _instance_error(exc) from exc


@router.get("/{artifact_id}/instances", response_model=ServiceReportInstancePage)
def saved_service_report_instances(
    artifact_id: str, db: DBSession, response: Response,
    limit: int = Query(default=20, ge=1, le=100),
    after_id: str | None = Query(default=None, max_length=36),
    principal: PrincipalContext = Depends(require_permissions("services.read")),
):
    try:
        response.headers["Cache-Control"] = "no-store"
        return list_report_instances(db, artifact_id, principal, limit=limit, after_id=after_id)
    except (LookupError, TypeError, ValueError) as exc:
        raise _instance_error(exc) from exc


@router.get("/instances/{instance_id}", response_model=ServiceReportInstanceRead)
def read_service_report_instance(
    instance_id: str, db: DBSession, response: Response,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
):
    try:
        response.headers["Cache-Control"] = "no-store"
        return instance_read(visible_report_instance(db, instance_id, principal))
    except (LookupError, TypeError, ValueError) as exc:
        raise _instance_error(exc) from exc


@router.get("/instances/{instance_id}/export")
def export_service_report_instance(
    instance_id: str, db: DBSession,
    format: ReportExportFormat = Query(default="pdf"),
    principal: PrincipalContext = Depends(require_permissions("services.read")),
):
    try:
        instance = visible_report_instance(db, instance_id, principal)
        snapshot = verified_instance_snapshot(db, instance, principal)
        export = render_report_export(instance, snapshot, format)
    except (LookupError, TypeError, ValueError) as exc:
        raise _instance_error(exc) from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Report renderer asset is unavailable") from exc
    record_audit_event(
        db, event_type="report.instance.exported", actor_type="user", actor_id=principal.subject,
        entity_type="service_report_instance", entity_id=instance.id,
        details={"format": format, "snapshot_sha256": instance.content_sha256,
                 "export_sha256": export.sha256, "renderer": export.renderer,
                 "artifact_version_id": instance.artifact_version_id},
    )
    db.commit()
    return Response(
        content=export.body, media_type=export.media_type,
        headers={
            "Content-Disposition": f'attachment; filename="icheck-report-{instance.id}.{export.extension}"',
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": HTML_CSP,
            "X-Icheck-Snapshot-SHA256": instance.content_sha256,
            "X-Icheck-Content-SHA256": export.sha256,
            "X-Icheck-Artifact-Version-ID": instance.artifact_version_id,
            "X-Icheck-Renderer": export.renderer,
        },
    )


@router.post("/instances/{instance_id}/attachments", response_model=ReportAttachmentManifest, status_code=201)
def materialize_report_attachment(
    instance_id: str, payload: ReportAttachmentCreate, db: DBSession, response: Response,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
):
    try:
        manifest, created = create_report_attachment(db, instance_id, payload.export_format, principal)
    except ReportStorageQuotaExceeded as exc:
        raise HTTPException(status_code=507, detail=str(exc)) from exc
    except (LookupError, TypeError, ValueError) as exc:
        raise _instance_error(exc) from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Report renderer asset is unavailable") from exc
    response.status_code = 201 if created else 200
    response.headers["Cache-Control"] = "no-store"
    return manifest


@router.get("/attachments/{attachment_id}", response_model=ReportAttachmentManifest)
def read_report_attachment(
    attachment_id: str, db: DBSession, response: Response,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
):
    try:
        attachment, instance = verified_report_attachment(db, attachment_id, principal)
    except (LookupError, TypeError, ValueError) as exc:
        raise _instance_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return attachment_manifest(attachment, instance)


@router.get("/attachments/{attachment_id}/content")
def download_report_attachment(
    attachment_id: str, db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
):
    try:
        attachment, instance = verified_report_attachment(db, attachment_id, principal)
    except (LookupError, TypeError, ValueError) as exc:
        raise _instance_error(exc) from exc
    record_audit_event(
        db, event_type="report.attachment.downloaded", actor_type=principal.principal_type,
        actor_id=principal.subject, entity_type="report_attachment", entity_id=attachment.id,
        details={"instance_id": instance.id, "document_sha256": attachment.content_sha256,
                 "snapshot_sha256": instance.content_sha256},
    )
    db.commit()
    return Response(content=attachment.body, media_type=attachment.media_type, headers={
        "Content-Disposition": f'attachment; filename="report-{attachment.id}.{attachment.export_format}"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": HTML_CSP,
        "X-Icheck-Snapshot-SHA256": instance.content_sha256,
        "X-Icheck-Content-SHA256": attachment.content_sha256,
        "X-Icheck-Artifact-Version-ID": instance.artifact_version_id,
        "X-Icheck-Renderer": attachment.renderer,
    })
