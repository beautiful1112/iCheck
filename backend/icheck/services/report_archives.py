"""Independent HTTPS retrieval of complete, digest-pinned Report archives.

Export is data-only. The verifier never uploads data, follows redirects, accepts
caller URLs, or treats a remote digest header as proof of the returned bytes.
"""
from __future__ import annotations

import base64
import hashlib
import re
import ssl
import time
from http.client import HTTPException
from dataclasses import dataclass
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..credentials import CredentialUnavailable, resolved_server_secret
from ..models import (
    CredentialProfile, ReportArchiveAcknowledgement, ReportArchiveSource,
    ReportArchiveVerification, ReportAttachment, ServiceReportInstance, utcnow,
)
from ..report_schemas import ReportArchiveSourceCreate, ReportArchiveSourceState, ReportArchiveVerifyCreate
from .audit import record_audit_event
from .control_plane_auth import PrincipalContext
from .report_attachments import attachment_manifest, verified_report_attachment
from .report_instances import canonical_bytes, instance_material, visible_report_instance
from .report_storage import locked_report_storage_policy


ARCHIVE_FORMAT = "icheck.report.archive/v1"
ARCHIVE_ADAPTER = "report_archive"
MAX_ARCHIVE_BYTES = 22_000_000


class ReportArchiveUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class ArchivePackage:
    body: bytes
    attachments: list[dict]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


@dataclass(frozen=True)
class ArchiveFetchEvidence:
    source_id: str
    source_revision: int
    credential_revision: int
    source_binding_sha256: str
    package_sha256: str
    fetched_at: datetime


def archive_package(db: Session, instance_id: str, principal: PrincipalContext) -> ArchivePackage:
    instance = visible_report_instance(db, instance_id, principal)
    manifests, documents = [], []
    for attachment in db.scalars(select(ReportAttachment).where(
        ReportAttachment.instance_id == instance.id,
        ReportAttachment.tenant_id == principal.tenant_id,
        ReportAttachment.region_id == principal.region_id,
    ).order_by(ReportAttachment.id)).all():
        verified_report_attachment(db, attachment.id, principal)
        manifest = attachment_manifest(attachment, instance).model_dump(mode="json")
        manifests.append(manifest)
        documents.append({"manifest": manifest, "body_base64": base64.b64encode(attachment.body).decode("ascii")})
    body = canonical_bytes({
        "format_version": ARCHIVE_FORMAT, "instance": instance_material(instance),
        "snapshot_sha256": instance.content_sha256,
        "snapshot_size_bytes": instance.snapshot_size_bytes, "attachments": documents,
    })
    if not 0 < len(body) <= MAX_ARCHIVE_BYTES:
        raise ValueError("Complete Report archive exceeds the bounded package size")
    return ArchivePackage(body, manifests)


def validate_archive_origin(origin: str) -> str:
    if any(ord(char) <= 32 or ord(char) == 127 for char in origin):
        raise ValueError("Report archive origin must not contain whitespace or control characters")
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
        or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ValueError("Report archive source must be an HTTPS origin without credentials or a path")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Report archive origin has an invalid port") from exc
    if parsed.hostname.lower() not in get_settings().report_archive_allowed_host_list:
        raise ValueError("Report archive host is not in ICHECK_REPORT_ARCHIVE_ALLOWED_HOSTS")
    return origin.rstrip("/")


def _source(db: Session, source_id: str, principal: PrincipalContext, *, lock=False) -> ReportArchiveSource:
    query = select(ReportArchiveSource).where(
        ReportArchiveSource.id == source_id, ReportArchiveSource.tenant_id == principal.tenant_id,
        ReportArchiveSource.region_id == principal.region_id,
    )
    source = db.scalar(query.with_for_update() if lock else query)
    if source is None:
        raise LookupError("Report archive source not found")
    if not source.enabled:
        raise ValueError("Report archive source is disabled")
    validate_archive_origin(source.origin)
    return source


def _source_binding(source: ReportArchiveSource) -> str:
    return hashlib.sha256(canonical_bytes({
        "id": source.id, "origin": source.origin, "credential_profile_id": source.credential_profile_id,
        "tenant_id": source.tenant_id, "region_id": source.region_id,
    })).hexdigest()


def _credential(db: Session, profile_id: str, principal: PrincipalContext, *, lock=False) -> CredentialProfile:
    query = select(CredentialProfile).where(
        CredentialProfile.id == profile_id, CredentialProfile.tenant_id == principal.tenant_id,
        CredentialProfile.region_id == principal.region_id,
    )
    profile = db.scalar(query.with_for_update() if lock else query)
    if (profile is None or not profile.enabled or ARCHIVE_ADAPTER not in profile.allowed_adapters
        or profile.worker_selector):
        raise ValueError("Report archive requires a usable namespace-local server credential profile for report_archive")
    return profile


def list_archive_sources(db: Session, principal: PrincipalContext) -> list[ReportArchiveSource]:
    return list(db.scalars(select(ReportArchiveSource).where(
        ReportArchiveSource.tenant_id == principal.tenant_id, ReportArchiveSource.region_id == principal.region_id,
    ).order_by(ReportArchiveSource.name).limit(500)).all())


def create_archive_source(db: Session, payload: ReportArchiveSourceCreate, principal: PrincipalContext) -> ReportArchiveSource:
    source = ReportArchiveSource(
        name=payload.name, origin=validate_archive_origin(payload.origin),
        credential_profile_id=_credential(db, str(payload.credential_profile_id), principal).id,
        tenant_id=principal.tenant_id, region_id=principal.region_id, created_by=principal.subject,
    )
    db.add(source)
    try:
        db.flush()
        record_audit_event(db, event_type="report.archive_source.created", actor_type=principal.principal_type,
            actor_id=principal.subject, entity_type="report_archive_source", entity_id=source.id,
            details={"reason_sha256": hashlib.sha256(payload.reason.encode()).hexdigest()})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Report archive source name already exists in this namespace") from exc
    return source


def set_archive_source_state(db: Session, source_id: str, payload: ReportArchiveSourceState, principal: PrincipalContext):
    source = db.scalar(select(ReportArchiveSource).where(
        ReportArchiveSource.id == source_id, ReportArchiveSource.tenant_id == principal.tenant_id,
        ReportArchiveSource.region_id == principal.region_id,
    ).with_for_update())
    if source is None:
        raise LookupError("Report archive source not found")
    if source.revision != payload.expected_revision:
        raise ValueError("Report archive source revision changed")
    if payload.enabled:
        validate_archive_origin(source.origin)
        _credential(db, source.credential_profile_id, principal)
    if source.enabled != payload.enabled:
        source.enabled = payload.enabled
        source.revision += 1
        record_audit_event(db, event_type="report.archive_source.state_changed", actor_type=principal.principal_type,
            actor_id=principal.subject, entity_type="report_archive_source", entity_id=source.id,
            details={"enabled": source.enabled, "revision": source.revision,
                     "reason_sha256": hashlib.sha256(payload.reason.encode()).hexdigest()})
        db.commit()
    return source


def _acknowledgement(db: Session, instance: ServiceReportInstance, acknowledgement_id: str) -> ReportArchiveAcknowledgement:
    acknowledgement = db.scalar(select(ReportArchiveAcknowledgement).where(
        ReportArchiveAcknowledgement.id == acknowledgement_id,
        ReportArchiveAcknowledgement.instance_id == instance.id,
        ReportArchiveAcknowledgement.tenant_id == instance.tenant_id,
        ReportArchiveAcknowledgement.region_id == instance.region_id,
    ))
    if (acknowledgement is None or acknowledgement.snapshot_sha256 != instance.content_sha256
        or acknowledgement.artifact_version_id != instance.artifact_version_id
        or acknowledgement.snapshot_size_bytes != instance.snapshot_size_bytes):
        raise ValueError("Archive acknowledgement does not match the saved Report")
    return acknowledgement


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "Report archive redirects are prohibited", headers, fp)


def fetch_archive_evidence(
    db: Session, source_id: str, reference: str, package: ArchivePackage, principal: PrincipalContext,
) -> ArchiveFetchEvidence:
    source = _source(db, source_id, principal)
    profile = _credential(db, source.credential_profile_id, principal)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,254}", reference) is None:
        raise ValueError("Archive reference is not a bounded object identity")
    try:
        with resolved_server_secret(profile, adapter_type=ARCHIVE_ADAPTER) as token:
            _fetch_package(source.origin, reference, package, principal, token)
    except CredentialUnavailable as exc:
        raise ReportArchiveUnavailable("Report archive credential could not be resolved") from exc
    return ArchiveFetchEvidence(source.id, source.revision, profile.revision,
                                _source_binding(source), package.sha256, utcnow())


def _fetch_package(origin: str, reference: str, package: ArchivePackage, principal: PrincipalContext, token: str):
    if not token or any(ord(char) <= 32 or ord(char) > 126 for char in token):
        raise ValueError("Report archive credential is not a valid bearer value")
    url = origin + f"/v1/report-archives/{quote(reference, safe='')}/content"
    request = Request(url, method="GET", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/json", "Accept-Encoding": "identity",
        "X-Icheck-Tenant-ID": principal.tenant_id, "X-Icheck-Region-ID": principal.region_id,
    })
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
    deadline = time.monotonic() + 15
    digest, size = hashlib.sha256(), 0
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200 or response.geturl() != url:
                raise ValueError("Report archive retrieval did not return the pinned object")
            if (response.headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/json"
                or response.headers.get("Content-Encoding", "identity").lower() != "identity"):
                raise ValueError("Report archive requires uncompressed JSON bytes")
            declared = response.headers.get("Content-Length")
            if declared is not None and declared != str(len(package.body)):
                raise ValueError("Report archive declared size does not match the complete package")
            while True:
                if time.monotonic() > deadline:
                    raise ReportArchiveUnavailable("Report archive retrieval exceeded its total time budget")
                chunk = response.read1(64_000)
                if not chunk:
                    break
                size += len(chunk)
                if size > len(package.body):
                    raise ValueError("Report archive exceeded the approved complete package size")
                digest.update(chunk)
    except (HTTPError, URLError, OSError, HTTPException) as exc:
        raise ReportArchiveUnavailable("Report archive retrieval failed") from exc
    if size != len(package.body) or digest.hexdigest() != package.sha256:
        raise ValueError("Report archive bytes do not match the complete snapshot and attachments")


def validate_fetch_evidence(db: Session, evidence: ArchiveFetchEvidence, package: ArchivePackage, principal: PrincipalContext):
    source = _source(db, evidence.source_id, principal, lock=True)
    profile = _credential(db, source.credential_profile_id, principal, lock=True)
    if (source.revision != evidence.source_revision or profile.revision != evidence.credential_revision
        or _source_binding(source) != evidence.source_binding_sha256 or package.sha256 != evidence.package_sha256):
        raise ValueError("Report archive binding or retained bytes changed during retrieval")


def archive_binding(
    db: Session, instance: ServiceReportInstance, acknowledgement_id: str,
    verification_id: str | None, principal: PrincipalContext,
) -> tuple[ReportArchiveVerification, ReportArchiveAcknowledgement, ArchivePackage]:
    acknowledgement = _acknowledgement(db, instance, acknowledgement_id)
    verification = db.scalar(select(ReportArchiveVerification).where(
        ReportArchiveVerification.id == verification_id,
        ReportArchiveVerification.tenant_id == principal.tenant_id,
        ReportArchiveVerification.region_id == principal.region_id,
    )) if verification_id else None
    if (verification is None or verification.instance_id != instance.id
        or verification.acknowledgement_id != acknowledgement.id
        or verification.artifact_version_id != instance.artifact_version_id
        or verification.snapshot_sha256 != instance.content_sha256):
        raise ValueError("Report purge requires independent verification of the complete archive")
    source = _source(db, verification.source_id, principal)
    if _source_binding(source) != verification.source_binding_sha256:
        raise ValueError("Report archive source differs from its verified binding")
    package = archive_package(db, instance.id, principal)
    if (package.sha256 != verification.package_sha256 or len(package.body) != verification.package_size_bytes
        or package.attachments != verification.attachments):
        raise ValueError("Report archive verification does not cover the current complete package")
    return verification, acknowledgement, package


def record_archive_failure(db: Session, instance_id: str, principal: PrincipalContext, exc: Exception, *, revalidation=False):
    db.rollback()
    record_audit_event(db, event_type="report.archive.revalidation_failed" if revalidation else "report.archive.verification_failed",
        actor_type=principal.principal_type, actor_id=principal.subject,
        entity_type="service_report_instance", entity_id=instance_id, outcome="failed",
        details={"error_type": type(exc).__name__, "error_sha256": hashlib.sha256(str(exc).encode()).hexdigest()})
    db.commit()


def verify_report_archive(db: Session, instance_id: str, payload: ReportArchiveVerifyCreate, principal: PrincipalContext):
    instance = visible_report_instance(db, instance_id, principal)
    acknowledgement = _acknowledgement(db, instance, str(payload.acknowledgement_id))
    package = archive_package(db, instance.id, principal)
    try:
        evidence = fetch_archive_evidence(db, str(payload.source_id), acknowledgement.archive_reference, package, principal)
        # Network I/O runs before acquiring the namespace accounting or source
        # locks. Then discard cached ORM values and check all bindings again.
        db.expire_all()
        locked_report_storage_policy(db, principal, actor=principal.subject)
        instance = visible_report_instance(db, instance_id, principal)
        acknowledgement = _acknowledgement(db, instance, str(payload.acknowledgement_id))
        package = archive_package(db, instance.id, principal)
        validate_fetch_evidence(db, evidence, package, principal)
    except (LookupError, ValueError, ReportArchiveUnavailable) as exc:
        record_archive_failure(db, instance_id, principal, exc)
        raise
    verification = ReportArchiveVerification(
        tenant_id=principal.tenant_id, region_id=principal.region_id,
        instance_id=instance.id, acknowledgement_id=acknowledgement.id, source_id=evidence.source_id,
        artifact_version_id=instance.artifact_version_id, snapshot_sha256=instance.content_sha256,
        package_sha256=evidence.package_sha256, package_size_bytes=len(package.body),
        source_binding_sha256=evidence.source_binding_sha256,
        attachments=package.attachments, source_revision=evidence.source_revision,
        credential_revision=evidence.credential_revision, verified_at=evidence.fetched_at,
        verified_by=principal.subject, reason_sha256=hashlib.sha256(payload.reason.encode()).hexdigest(),
    )
    db.add(verification)
    db.flush()
    record_audit_event(db, event_type="report.archive.verified", actor_type=principal.principal_type,
        actor_id=principal.subject, entity_type="service_report_instance", entity_id=instance.id,
        details={"verification_id": verification.id, "source_id": verification.source_id,
                 "package_sha256": verification.package_sha256, "package_size_bytes": verification.package_size_bytes,
                 "reason_sha256": verification.reason_sha256, "verification_level": "https_exact_bytes"})
    db.commit()
    return verification
