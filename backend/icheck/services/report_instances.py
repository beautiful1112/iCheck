from __future__ import annotations

import hashlib
import json
from datetime import UTC
from typing import Any

from sqlalchemy import and_, exists, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload, selectinload

from ..models import (
    Artifact, ArtifactKind, ArtifactVersion, ArtifactVersionStatus,
    ReportPurgeTombstone, ServiceCatalogEntry, ServiceReportInstance,
    ServiceReportInstanceService, ReportProofAdmission, ReportInstanceProofReference, new_id,
)
from ..report_schemas import (
    ServiceReportInstanceCreate, ServiceReportInstancePage, ServiceReportInstanceRead,
    ServiceReportInstanceSummary, ServiceReportRender, RetainedProofReportRender, parse_report_render,
)
from .audit import record_audit_event
from .authorization_scope import has_global_scope, namespace_clause, service_scope_clause
from .control_plane_auth import PrincipalContext
from .service_health_reports import (
    service_report_is_fully_visible, service_report_runtime_generate,
    service_report_version_summary, verified_service_report_version_spec,
)
from .report_storage import (
    assert_report_storage_capacity, locked_report_storage_policy,
)


INSTANCE_FORMAT = "icheck.service-report-instance/v1"
MAX_SNAPSHOT_BYTES = 256_000
MAX_DISCOVERY_CANDIDATES = 256


class ReportDiscoveryScanBudgetExceeded(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")


def instance_material(instance: ServiceReportInstance) -> dict[str, Any]:
    return {
        "format_version": "icheck.service-report-instance/v2" if instance.snapshot.get("format_version") == "icheck.service-health-report-render/v2" else INSTANCE_FORMAT,
        "instance_id": instance.id,
        "tenant_id": instance.tenant_id, "region_id": instance.region_id,
        "artifact_version_id": instance.artifact_version_id, "snapshot": instance.snapshot,
    }


def _version(db: Session, version_id: str, principal: PrincipalContext, *, historical=False):
    statuses = [ArtifactVersionStatus.PUBLISHED]
    if historical:
        statuses.append(ArtifactVersionStatus.DEPRECATED)
    version = db.scalar(
        select(ArtifactVersion).join(Artifact, Artifact.id == ArtifactVersion.artifact_id)
        .options(joinedload(ArtifactVersion.artifact))
        .where(
            ArtifactVersion.id == version_id, Artifact.kind == ArtifactKind.REPORT,
            ArtifactVersion.status.in_(statuses), namespace_clause(ArtifactVersion, principal),
            namespace_clause(Artifact, principal),
        )
    )
    if version is None:
        raise LookupError("Report not found")
    return version


def _visible_clause(principal: PrincipalContext):
    namespace = namespace_clause(ServiceReportInstance, principal)
    if has_global_scope(principal):
        return namespace
    visible_services = select(ServiceCatalogEntry.service_key).where(service_scope_clause(principal))
    membership = [
        ServiceReportInstanceService.instance_id == ServiceReportInstance.id,
        namespace_clause(ServiceReportInstanceService, principal),
    ]
    return and_(
        namespace,
        or_(and_(
            exists(select(ServiceReportInstanceService.id).where(*membership)),
            ~exists(select(ServiceReportInstanceService.id).where(
                *membership, ServiceReportInstanceService.service_key.not_in(visible_services))),
        ), and_(ServiceReportInstance.snapshot["format_version"].as_string() == "icheck.service-health-report-render/v2",
            ~exists(select(ServiceReportInstanceService.id).where(*membership)))),
    )


def _query(principal: PrincipalContext):
    return select(ServiceReportInstance).where(_visible_clause(principal)).options(
        selectinload(ServiceReportInstance.service_refs)
    )


def _utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def verified_instance_snapshot(
    db: Session, instance: ServiceReportInstance, principal: PrincipalContext,
) -> ServiceReportRender:
    version = _version(db, instance.artifact_version_id, principal, historical=True)
    spec = verified_service_report_version_spec(version)
    if not service_report_is_fully_visible(db, spec, principal):
        raise LookupError("Report instance not found")
    payload = canonical_bytes(instance_material(instance))
    if (len(payload) > MAX_SNAPSHOT_BYTES
        or len(payload) != instance.snapshot_size_bytes
        or hashlib.sha256(payload).hexdigest() != instance.content_sha256):
        raise ValueError("Report instance integrity check failed")
    snapshot = parse_report_render(instance.snapshot)
    proof_count = len(snapshot.spec.retained_proofs) if isinstance(snapshot, RetainedProofReportRender) else 0
    expected_services = {item.service_key for item in spec.indicators}
    expected_sections = {item.section_key: item for item in spec.indicators}
    if (
        snapshot.artifact_id != instance.artifact_id or version.artifact_id != instance.artifact_id
        or snapshot.version_id != version.id or snapshot.version != version.version
        or snapshot.content_hash != version.content_hash or snapshot.spec != spec
        or snapshot.report_title != spec.report_title
        or snapshot.lookback_minutes != spec.lookback_minutes
        or _utc(snapshot.published_at) != _utc(version.published_at)
        or _utc(snapshot.generated_at) != _utc(instance.generated_at)
        or snapshot.section_count != len(snapshot.sections) + proof_count
        or len(snapshot.sections) != len(expected_sections)
        or {item.section_key for item in snapshot.sections} != set(expected_sections)
        or {item.service_key for item in instance.service_refs} != expected_services
    ):
        raise ValueError("Report instance provenance check failed")
    for section in snapshot.sections:
        expected = expected_sections[section.section_key]
        if (section.service_key, section.indicator_key, section.title) != (
            expected.service_key, expected.indicator_key, expected.title,
        ):
            raise ValueError("Report instance selector check failed")
    if isinstance(snapshot, RetainedProofReportRender):
        from .report_retained_proofs import verify_retained_sections
        from .collector_conditions import canonical
        admission = instance.proof_admission
        expected = snapshot.initiating_reader.model_dump(mode="json")
        reference_fields = {"source_replacement_request":"replacement_request_id",
            "source_retirement":"retirement_id", "situation_closure_receipt":"closure_receipt_id"}
        refs = {(row.section_key, field, getattr(row, field)) for row in instance.proof_refs
            for field in reference_fields.values() if getattr(row, field) is not None}
        selected = {(item.section_key, reference_fields[item.reference_kind], str(item.reference_id)) for item in snapshot.spec.retained_proofs}
        if (admission is None or admission.principal_id != str(snapshot.initiating_reader.principal_id)
            or canonical(admission.reader_snapshot) != canonical(expected)
            or snapshot.initiating_reader.subject != instance.created_by or refs != selected
            or len(instance.proof_refs) != len(selected)
            or any((row.tenant_id, row.region_id) != (instance.tenant_id, instance.region_id) for row in [admission, *instance.proof_refs])):
            raise ValueError("Retained report initiating admission or exact reference ledger differs from its snapshot")
        original = verify_retained_sections(db, snapshot, principal)
        from .service_health_reports import _visualization_spec
        from .service_indicator_visualizations import visualization_is_fully_visible
        if spec.indicators and not visualization_is_fully_visible(db, _visualization_spec(spec), original):
            raise LookupError("Report instance not found in its initiating scope")
    return snapshot


def visible_report_instance(db: Session, instance_id: str, principal: PrincipalContext):
    instance = db.scalar(_query(principal).where(ServiceReportInstance.id == instance_id))
    if instance is None:
        raise LookupError("Report instance not found")
    verified_instance_snapshot(db, instance, principal)
    return instance


def retained_workflow_input(instance: ServiceReportInstance) -> dict:
    from ..report_schemas import RetainedProofWorkflowInput
    snapshot = parse_report_render(instance.snapshot)
    if not isinstance(snapshot, RetainedProofReportRender):
        raise ValueError("Inline retained report requires a saved v2 proof snapshot")
    return RetainedProofWorkflowInput(instance_id=instance.id, artifact_id=instance.artifact_id,
        artifact_version_id=instance.artifact_version_id, artifact_version=snapshot.version,
        content_hash=snapshot.content_hash, published_at=snapshot.published_at,
        snapshot=snapshot).model_dump(mode="json")


def instance_summary(instance: ServiceReportInstance) -> ServiceReportInstanceSummary:
    snapshot = parse_report_render(instance.snapshot)
    return ServiceReportInstanceSummary(
        id=instance.id, artifact_id=instance.artifact_id, version_id=instance.artifact_version_id,
        version=snapshot.version, report_title=snapshot.report_title,
        overall_status=snapshot.overall_status, generated_at=instance.generated_at,
        created_at=instance.created_at, content_sha256=instance.content_sha256,
        snapshot_size_bytes=instance.snapshot_size_bytes,
        artifact_content_hash=snapshot.content_hash, section_count=snapshot.section_count,
        sample_count=snapshot.sample_count, drifted_section_count=snapshot.drifted_section_count,
    )


def instance_read(instance: ServiceReportInstance) -> ServiceReportInstanceRead:
    return ServiceReportInstanceRead(
        **instance_summary(instance).model_dump(), snapshot=instance.snapshot,
    )


def build_report_instance(
    db: Session, artifact_id: str, payload: ServiceReportInstanceCreate,
    principal: PrincipalContext,
) -> ServiceReportInstance:
    """Build an exact snapshot without writing; also used for activation validation."""
    request_sha256 = hashlib.sha256(canonical_bytes({
        "principal": principal.principal_id or principal.subject,
        "request_key": str(payload.request_key),
    })).hexdigest()
    version = _version(db, str(payload.version_id), principal)
    if version.artifact_id != artifact_id:
        raise LookupError("Report not found")
    spec = verified_service_report_version_spec(version)
    if not service_report_is_fully_visible(db, spec, principal):
        raise LookupError("Report not found")
    from .capability_pack_revocations import assert_artifact_version_not_revoked

    assert_artifact_version_not_revoked(db, version.id)
    snapshot = parse_report_render({
        **service_report_version_summary(version, spec),
        **service_report_runtime_generate(db, spec, principal),
        "scope_applied": not has_global_scope(principal), "spec": spec,
    })
    instance = ServiceReportInstance(
        id=new_id(), tenant_id=principal.tenant_id, region_id=principal.region_id,
        artifact_id=artifact_id, artifact_version_id=version.id, request_sha256=request_sha256,
        snapshot=snapshot.model_dump(mode="json"), generated_at=snapshot.generated_at,
        created_by=principal.subject,
        service_refs=[ServiceReportInstanceService(
            service_key=key, tenant_id=principal.tenant_id, region_id=principal.region_id,
        ) for key in sorted({
            item.service_key for item in spec.indicators
        })],
    )
    if isinstance(snapshot, RetainedProofReportRender):
        instance.proof_admission = ReportProofAdmission(principal_id=str(snapshot.initiating_reader.principal_id),
            reader_snapshot=snapshot.initiating_reader.model_dump(mode="json"),
            tenant_id=instance.tenant_id, region_id=instance.region_id)
        fields = {"source_replacement_request":"replacement_request_id", "source_retirement":"retirement_id",
            "situation_closure_receipt":"closure_receipt_id"}
        instance.proof_refs = [ReportInstanceProofReference(section_key=item.section_key,
            tenant_id=instance.tenant_id, region_id=instance.region_id,
            **{fields[item.reference_kind]:str(item.reference_id)}) for item in spec.retained_proofs]
    encoded = canonical_bytes(instance_material(instance))
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Report snapshot exceeds its bounded size limit")
    instance.snapshot_size_bytes = len(encoded)
    instance.content_sha256 = hashlib.sha256(encoded).hexdigest()
    return instance


def capture_report_instance(
    db: Session, artifact_id: str, payload: ServiceReportInstanceCreate,
    principal: PrincipalContext, *, commit: bool = True,
) -> tuple[ServiceReportInstance, bool]:
    request_sha256 = hashlib.sha256(canonical_bytes({
        "principal": principal.principal_id or principal.subject,
        "request_key": str(payload.request_key),
    })).hexdigest()
    existing_query = _query(principal).where(ServiceReportInstance.request_sha256 == request_sha256)

    def assert_not_purged():
        tombstone = db.scalar(select(ReportPurgeTombstone.instance_id).where(
            ReportPurgeTombstone.request_sha256 == request_sha256,
            ReportPurgeTombstone.tenant_id == principal.tenant_id,
            ReportPurgeTombstone.region_id == principal.region_id,
        ))
        if tombstone is not None:
            raise ValueError("Report snapshot request key has been permanently purged")

    def replay(existing):
        if existing.artifact_id != artifact_id or existing.artifact_version_id != str(payload.version_id):
            raise ValueError("Report snapshot request key is bound to another exact version")
        verified_instance_snapshot(db, existing, principal)
        if commit:
            db.commit()  # A post-lock retry must not retain the quota row lock.
        return existing, False

    existing = db.scalar(existing_query)
    if existing is not None:
        return replay(existing)
    assert_not_purged()
    instance = build_report_instance(db, artifact_id, payload, principal)
    policy = locked_report_storage_policy(db, principal, actor=principal.subject)
    existing = db.scalar(existing_query)
    if existing is not None:
        return replay(existing)
    assert_not_purged()
    assert_report_storage_capacity(policy, instance.snapshot_size_bytes)
    try:
        with db.begin_nested():
            db.add(instance)
            policy.used_instances += 1
            policy.used_bytes += instance.snapshot_size_bytes
            db.flush()
            record_audit_event(
                db, event_type="report.instance.captured", actor_type="user", actor_id=principal.subject,
                entity_type="service_report_instance", entity_id=instance.id,
                details={
                    "artifact_id": artifact_id, "artifact_version_id": instance.artifact_version_id,
                    "artifact_content_hash": instance.snapshot["content_hash"],
                    "snapshot_sha256": instance.content_sha256, "section_count": instance.snapshot["section_count"],
                    "sample_count": instance.snapshot["sample_count"],
                },
            )
    except IntegrityError as exc:
        existing = db.scalar(existing_query)
        if existing is not None:
            return replay(existing)
        raise ValueError("Report snapshot request cannot be committed") from exc
    if commit:
        db.commit()
        db.refresh(instance)
    return instance, True


def _visible_instance_page(db: Session, query, principal: PrincipalContext, limit: int):
    """Scan bounded metadata, then materialize and authorize one row at a time.

    SQL service membership is only a candidate filter for v2 proof-only reports.
    Hidden proof records must not poison the page or become public cursors.
    Budget exhaustion is explicit rather than silently claiming end-of-history.
    """
    candidates = db.execute(query.order_by(
        ServiceReportInstance.created_at.desc(), ServiceReportInstance.id.desc(),
    ).limit(MAX_DISCOVERY_CANDIDATES + 1)).all()
    visible = []
    for index, candidate in enumerate(candidates):
        if index == MAX_DISCOVERY_CANDIDATES:
            raise ReportDiscoveryScanBudgetExceeded("Report discovery scan budget exhausted; narrow the report selection")
        try:
            instance = visible_report_instance(db, candidate.id, principal)
        except (LookupError, PermissionError):
            continue
        visible.append(instance)
        if len(visible) > limit:
            break
    items = visible[:limit]
    return items, items[-1].id if len(visible) > limit else None


def list_report_instances(
    db: Session, artifact_id: str, principal: PrincipalContext,
    *, limit=20, after_id: str | None = None,
) -> ServiceReportInstancePage:
    if limit < 1 or limit > 100:
        raise ValueError("Report page limit must be between 1 and 100")
    query = select(ServiceReportInstance.id).where(
        _visible_clause(principal), ServiceReportInstance.artifact_id == artifact_id)
    if after_id:
        cursor = visible_report_instance(db, after_id, principal)
        if cursor.artifact_id != artifact_id:
            raise LookupError("Report cursor not found")
        query = query.where(or_(
            ServiceReportInstance.created_at < cursor.created_at,
            and_(ServiceReportInstance.created_at == cursor.created_at, ServiceReportInstance.id < cursor.id),
        ))
    rows, next_after_id = _visible_instance_page(db, query, principal, limit)
    if not rows and not after_id:
        current = db.scalars(select(ArtifactVersion).join(Artifact).options(joinedload(ArtifactVersion.artifact)).where(
            Artifact.id == artifact_id, Artifact.kind == ArtifactKind.REPORT,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
            namespace_clause(ArtifactVersion, principal), namespace_clause(Artifact, principal),
        )).first()
        if current is None or not service_report_is_fully_visible(
            db, verified_service_report_version_spec(current), principal,
        ):
            raise LookupError("Report not found")
    return ServiceReportInstancePage(
        items=[instance_summary(item) for item in rows], next_after_id=next_after_id,
    )


def list_visible_report_instances(
    db: Session, principal: PrincipalContext, *, limit: int = 10,
    after_id: str | None = None,
) -> tuple[list[ServiceReportInstance], str | None]:
    """Discover retained reports across artifacts within the current service scope."""
    if limit < 1 or limit > 10:
        raise ValueError("Report discovery limit must be between 1 and 10")
    query = select(ServiceReportInstance.id).where(_visible_clause(principal))
    if after_id is not None:
        cursor = visible_report_instance(db, after_id, principal)
        query = query.where(or_(
            ServiceReportInstance.created_at < cursor.created_at,
            and_(ServiceReportInstance.created_at == cursor.created_at,
                 ServiceReportInstance.id < cursor.id),
        ))
    return _visible_instance_page(db, query, principal, limit)
