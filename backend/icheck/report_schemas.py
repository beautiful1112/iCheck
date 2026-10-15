from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import ConfigDict, Field, FiniteFloat, field_validator

from .schemas import APIModel
from .studio_schemas import GeneratedServiceReportSpec, GeneratedRetainedProofReportSpec
from .source_replacement_schemas import SourceReplacementRequestRead, SourceRetirementRead
from .situation_closure_schemas import SituationClosureReceiptRead


class ReportAPIModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class PublishedServiceReport(ReportAPIModel):
    artifact_id: str
    name: str
    description: str
    version_id: str
    version: int
    published_at: datetime
    content_hash: str
    report_title: str
    lookback_minutes: int
    section_count: int


class ServiceReportSection(ReportAPIModel):
    section_key: str
    title: str
    service_key: str
    service_name: str | None
    indicator_key: str
    indicator_name: str | None
    kind: str | None
    unit: str | None
    state: Literal["ready", "no_data", "drifted"]
    drift_code: str | None
    current_status: str
    current_value: FiniteFloat | None
    sample_count: int
    minimum: FiniteFloat | None
    maximum: FiniteFloat | None
    average: FiniteFloat | None
    first_observed_at: datetime | None
    last_observed_at: datetime | None
    trend: Literal["improving", "degrading", "stable", "insufficient_data"]
    breach_direction: str | None
    warning_threshold: FiniteFloat | None
    critical_threshold: FiniteFloat | None
    samples_truncated: bool


class ServiceReportRender(PublishedServiceReport):
    generated_at: datetime
    overall_status: str
    sample_count: int
    drifted_section_count: int
    sections: list[ServiceReportSection] = Field(min_length=1, max_length=20)
    scope_applied: bool
    spec: GeneratedServiceReportSpec


class ReportInitiatingReader(ReportAPIModel):
    principal_id: UUID
    subject: str = Field(min_length=1, max_length=255)
    principal_type: Literal["user", "service"]
    permissions: list[str] = Field(min_length=1, max_length=500)
    authorization_scope: dict


class ReportRetainedProofSection(ReportAPIModel):
    section_key: str
    title: str
    reference_kind: Literal["source_replacement_request", "source_retirement", "situation_closure_receipt"]
    reference_id: UUID
    recorded: SourceReplacementRequestRead | SourceRetirementRead | SituationClosureReceiptRead
    historical: Literal[True] = True
    grants_future_authority: Literal[False] = False
    remediation_causality_proven: Literal[False] = False
    physical_truth_automatically_verified: Literal[False] = False


class RetainedProofReportRender(ServiceReportRender):
    format_version: Literal["icheck.service-health-report-render/v2"] = "icheck.service-health-report-render/v2"
    sections: list[ServiceReportSection] = Field(default_factory=list, max_length=20)
    spec: GeneratedRetainedProofReportSpec
    initiating_reader: ReportInitiatingReader
    retained_proofs: list[ReportRetainedProofSection] = Field(min_length=1, max_length=20)
    historical: Literal[True] = True
    grants_future_authority: Literal[False] = False


ReportRender = ServiceReportRender | RetainedProofReportRender


class RetainedProofWorkflowInput(ReportAPIModel):
    """Explicit inline delivery of one durable, scope-bound proof snapshot."""
    format_version: Literal["icheck.workflow-retained-report/v1"] = "icheck.workflow-retained-report/v1"
    instance_id: UUID
    artifact_id: UUID
    artifact_version_id: UUID
    artifact_version: int = Field(ge=1)
    content_hash: str = Field(min_length=1, max_length=64)
    published_at: datetime
    snapshot: RetainedProofReportRender


def parse_report_render(document: dict) -> ReportRender:
    model = RetainedProofReportRender if document.get("format_version") == "icheck.service-health-report-render/v2" else ServiceReportRender
    return model.model_validate(document)


ReportExportFormat = Literal["json", "html", "csv", "pdf"]


class ReportAttachmentCreate(ReportAPIModel):
    export_format: ReportExportFormat


class ReportAttachmentManifest(ReportAPIModel):
    format_version: Literal["icheck.report-attachment/v1"] = "icheck.report-attachment/v1"
    attachment_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    instance_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    artifact_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    artifact_version_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1, le=4_000_000)
    export_format: ReportExportFormat
    media_type: str = Field(min_length=1, max_length=128)
    renderer: str = Field(min_length=1, max_length=255)
    filename: str = Field(pattern=r"^report-[0-9a-f-]{36}\.(json|html|csv|pdf)$")


class ServiceReportInstanceCreate(ReportAPIModel):
    version_id: UUID
    request_key: UUID


class ServiceReportInstanceSummary(ReportAPIModel):
    id: str
    artifact_id: str
    version_id: str
    version: int
    report_title: str
    overall_status: str
    generated_at: datetime
    created_at: datetime
    content_sha256: str
    snapshot_size_bytes: int
    artifact_content_hash: str
    section_count: int
    sample_count: int
    drifted_section_count: int
    retention_state: Literal["retained"] = "retained"


class ServiceReportInstanceRead(ServiceReportInstanceSummary):
    snapshot: ReportRender
    export_formats: list[ReportExportFormat] = Field(default_factory=lambda: ["json", "html", "csv", "pdf"])


class ServiceReportInstancePage(ReportAPIModel):
    items: list[ServiceReportInstanceSummary]
    next_after_id: str | None


class ReportStoragePolicyRead(ReportAPIModel):
    tenant_id: str
    region_id: str
    max_instances: int | None
    max_bytes: int | None
    used_instances: int
    used_bytes: int
    max_attachment_bytes: int | None
    used_attachment_bytes: int
    revision: int


class ReportStoragePolicyUpdate(ReportAPIModel):
    max_instances: int | None = Field(default=None, ge=1, le=10_000_000)
    max_bytes: int | None = Field(default=None, ge=1, le=10_000_000_000_000)
    max_attachment_bytes: int | None = Field(default=None, ge=1, le=10_000_000_000_000)
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=512)


ArchiveReference = str
DigestSHA256 = str


class ReportArchiveAcknowledgeCreate(ReportAPIModel):
    archive_reference: ArchiveReference = Field(
        min_length=3, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]+$",
    )
    snapshot_sha256: DigestSHA256 = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=10, max_length=512)


class ReportArchiveAcknowledgementRead(ReportAPIModel):
    id: str
    instance_id: str
    artifact_version_id: str
    snapshot_sha256: str
    snapshot_size_bytes: int
    archive_reference: str
    acknowledged_by: str
    acknowledged_at: datetime
    verification_level: Literal["operator_asserted"] = "operator_asserted"


class ReportLegalHoldCreate(ReportAPIModel):
    hold_reference: str = Field(
        min_length=3, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]+$",
    )
    reason: str = Field(min_length=10, max_length=512)


class ReportArchiveSourceCreate(ReportAPIModel):
    name: str = Field(min_length=1, max_length=255)
    origin: str = Field(min_length=8, max_length=2048)
    credential_profile_id: UUID
    reason: str = Field(min_length=10, max_length=512)


class ReportArchiveSourceState(ReportAPIModel):
    enabled: bool
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=512)


class ReportArchiveSourceRead(ReportAPIModel):
    id: str
    name: str
    origin: str
    credential_profile_id: str
    enabled: bool
    revision: int
    created_by: str
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class ReportArchiveVerifyCreate(ReportAPIModel):
    acknowledgement_id: UUID
    source_id: UUID
    reason: str = Field(min_length=10, max_length=512)


class ReportArchiveVerificationRead(ReportAPIModel):
    id: str
    instance_id: str
    acknowledgement_id: str
    source_id: str
    artifact_version_id: str
    snapshot_sha256: str
    package_sha256: str
    package_size_bytes: int
    source_binding_sha256: str
    attachments: list[ReportAttachmentManifest]
    source_revision: int
    credential_revision: int
    verified_by: str
    verified_at: datetime
    verification_level: Literal["https_exact_bytes"] = "https_exact_bytes"

    @field_validator("verified_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class ReportLegalHoldRelease(ReportAPIModel):
    reason: str = Field(min_length=10, max_length=512)


class ReportLegalHoldRead(ReportAPIModel):
    id: str
    instance_id: str
    snapshot_sha256: str
    hold_reference: str
    placed_by: str
    placed_at: datetime
    released_by: str | None
    released_at: datetime | None


class ReportPurgeCreate(ReportAPIModel):
    archive_acknowledgement_id: UUID
    archive_verification_id: UUID | None = None
    request_key: UUID
    reason: str = Field(min_length=10, max_length=512)


class ReportPurgeReview(ReportAPIModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=10, max_length=512)


class ReportPurgeExecute(ReportAPIModel):
    reason: str = Field(min_length=10, max_length=512)


class ReportPurgeRequestRead(ReportAPIModel):
    id: str
    instance_id: str
    artifact_version_id: str
    snapshot_sha256: str
    snapshot_size_bytes: int
    archive_acknowledgement_id: str
    archive_verification_id: str | None
    status: Literal["requested", "approved", "rejected", "executed"]
    requested_by: str
    requested_at: datetime
    reviewed_by: str | None
    reviewed_at: datetime | None
    executed_by: str | None
    executed_at: datetime | None


class ReportPurgeTombstoneRead(ReportAPIModel):
    instance_id: str
    artifact_id: str
    artifact_version_id: str
    snapshot_sha256: str
    snapshot_size_bytes: int
    attachments: list[ReportAttachmentManifest] = Field(default_factory=list)
    archive_acknowledgement_id: str
    archive_verification_id: str | None
    archive_revalidated_at: datetime | None
    purge_request_id: str
    deleted_by: str
    deleted_at: datetime


class ReportRetentionRead(ReportAPIModel):
    instance_id: str
    status: Literal["retained", "purged"]
    snapshot_sha256: str
    archive_acknowledgements: list[ReportArchiveAcknowledgementRead]
    archive_verifications: list[ReportArchiveVerificationRead]
    legal_holds: list[ReportLegalHoldRead]
    purge_requests: list[ReportPurgeRequestRead]
    tombstone: ReportPurgeTombstoneRead | None
    blockers: list[str]
