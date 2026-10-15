from __future__ import annotations

import enum
import uuid
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    JSON,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    event,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class ObservationSource(str, enum.Enum):
    ARP = "arp"
    MAC_TABLE = "mac_table"
    DHCP = "dhcp"
    WIFI_CONTROLLER = "wifi_controller"
    MANUAL = "manual"


class AlertSeverity(str, enum.Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class SituationStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class ArtifactKind(str, enum.Enum):
    COLLECTOR = "collector"
    PARSER = "parser"
    TOPOLOGY = "topology"
    TOOL = "tool"
    SKILL = "skill"
    WORKFLOW = "workflow"
    VISUALIZATION = "visualization"
    REPORT = "report"


class ArtifactVersionStatus(str, enum.Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"


class CollectorMode(str, enum.Enum):
    POLL = "poll"
    EVENT = "event"
    STREAM = "stream"


class CollectorDeploymentMode(str, enum.Enum):
    SCHEDULED = "scheduled"
    ON_DEMAND = "on_demand"


class CollectorWorkerState(str, enum.Enum):
    ONLINE = "online"
    DRAINING = "draining"
    OFFLINE = "offline"


class CollectorRunStatus(str, enum.Enum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentWorkerState(str, enum.Enum):
    ONLINE = "online"
    DRAINING = "draining"
    OFFLINE = "offline"


class AgentExecutionStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EnvelopeKind(str, enum.Enum):
    ENTITY = "entity"
    RELATIONSHIP = "relationship"
    OBSERVATION = "observation"
    EVENT = "event"


class KnowledgeProjectionStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    RETRY = "retry"
    SUCCEEDED = "succeeded"
    IGNORED = "ignored"
    DEAD_LETTER = "dead_letter"


class KnowledgeProjectionWorkerState(str, enum.Enum):
    ONLINE = "online"
    DRAINING = "draining"
    OFFLINE = "offline"


class EcosystemTransportEndpointKind(str, enum.Enum):
    TRANSPARENCY_WITNESS = "transparency_witness"
    PROMOTION_TARGET = "promotion_target"
    GOSSIP_PEER = "gossip_peer"


class EcosystemTransportJobKind(str, enum.Enum):
    WITNESS_CHECKPOINT = "witness_checkpoint"
    PROMOTION_DELIVERY = "promotion_delivery"
    GOSSIP_DELIVERY = "gossip_delivery"


class EcosystemTransportJobStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    RETRY = "retry"
    SUCCEEDED = "succeeded"
    DEAD_LETTER = "dead_letter"
    CANCELLED = "cancelled"


class EcosystemTransportWorkerState(str, enum.Enum):
    ONLINE = "online"
    DRAINING = "draining"
    OFFLINE = "offline"


class IndicatorPollRunStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    RETRY = "retry"
    SUCCEEDED = "succeeded"
    DEAD_LETTER = "dead_letter"


class IndicatorWorkerState(str, enum.Enum):
    ONLINE = "online"
    DRAINING = "draining"
    OFFLINE = "offline"


class WorkerScalingPool(str, enum.Enum):
    COLLECTOR = "collector"
    AGENT = "agent"


class Tenant(Base):
    __tablename__ = "tenants"
    __namespace_exempt__ = True
    __table_args__ = (
        CheckConstraint("slug <> ''", name="ck_tenant_slug_nonempty"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(63), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    default_region_id: Mapped[str] = mapped_column(String(36), index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Region(Base):
    __tablename__ = "regions"
    __namespace_exempt__ = True
    __table_args__ = (
        UniqueConstraint("tenant_id", "code", name="uq_region_tenant_code"),
        CheckConstraint("code <> ''", name="ck_region_code_nonempty"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    code: Mapped[str] = mapped_column(String(63), index=True)
    name: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "name", name="uq_device_namespace_name"
        ),
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "management_ip",
            name="uq_device_namespace_management_ip",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    management_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    site: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    location: Mapped[dict] = mapped_column(JSON, default=dict, server_default="{}", nullable=False)
    labels: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    onboarding_status: Mapped[str] = mapped_column(
        String(32), default="pending_verification", index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    revision: Mapped[int] = mapped_column(
        Integer, default=1, server_default="1", nullable=False
    )
    identity_revision: Mapped[int] = mapped_column(
        Integer, default=1, server_default="1", nullable=False
    )
    created_by: Mapped[str] = mapped_column(String(255), default="api.user")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    ip_observations: Mapped[list[IPAddressObservation]] = relationship(
        back_populates="collector_device"
    )
    attachments: Mapped[list[EndpointAttachment]] = relationship(
        back_populates="collector_device"
    )
    wireless_sessions: Mapped[list[WirelessClientSession]] = relationship(
        back_populates="controller"
    )
    connections: Mapped[list[DeviceConnection]] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
        order_by="DeviceConnection.protocol",
    )

    @property
    def discovered_name(self) -> str | None:
        from .snmp_modules import safe_sysname
        for connection in self.connections:
            evidence = connection.last_verification_evidence or {}
            if (connection.protocol == "snmp" and connection.enabled
                and connection.verification_status == "verified"
                and evidence.get("target_host") == self.management_ip
                and evidence.get("identity_revision") == self.identity_revision):
                return safe_sysname(evidence.get("discovered_name"))
        return None


class DeviceConnection(Base):
    __tablename__ = "device_connections"
    __table_args__ = (
        UniqueConstraint(
            "device_id",
            "protocol",
            name="uq_device_connection_protocol",
        ),
        CheckConstraint(
            "port IS NULL OR (port > 0 AND port <= 65535)",
            name="ck_device_connection_port",
        ),
        Index(
            "ix_device_connection_verification",
            "verification_status",
            "updated_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    protocol: Mapped[str] = mapped_column(String(32), index=True)
    adapter_type: Mapped[str] = mapped_column(String(128), index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    worker_selector: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    verification_status: Mapped[str] = mapped_column(
        String(32), default="pending", index=True
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_verification_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    last_verification_worker_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    last_verification_latency_ms: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    last_verification_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )
    verification_worker_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    verification_lease_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    verification_lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    next_verification_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True, default=utcnow
    )
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    device: Mapped[Device] = relationship(back_populates="connections")
    preflights: Mapped[list[DeviceConnectionPreflight]] = relationship(
        back_populates="connection",
        cascade="all, delete-orphan",
        order_by="DeviceConnectionPreflight.started_at.desc()",
    )
    activations: Mapped[list[DeviceConnectionActivation]] = relationship(
        back_populates="connection",
        cascade="all, delete-orphan",
        order_by="DeviceConnectionActivation.created_at",
    )

    @property
    def activation(self) -> DeviceConnectionActivation | None:
        """Backward-compatible projection of the most relevant activation."""
        active = [item for item in self.activations if item.status == "active"]
        candidates = active or self.activations
        if not candidates:
            return None
        return max(candidates, key=lambda item: (item.activated_at, item.id))


class DeviceMonitoringEnrollment(Base):
    """Explicit, expiring continuous-scrape intent; never monitoring secrets."""
    __tablename__ = "device_monitoring_enrollments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "connection_id", name="uq_monitoring_connection"),
        CheckConstraint("revision >= 1", name="ck_monitoring_revision"),
        CheckConstraint("schedule_seconds BETWEEN 15 AND 3600", name="ck_monitoring_schedule"),
        CheckConstraint("timeout_seconds BETWEEN 1 AND 30 AND timeout_seconds < schedule_seconds", name="ck_monitoring_timeout"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    connection_id: Mapped[str] = mapped_column(ForeignKey("device_connections.id", ondelete="RESTRICT"), index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    device_identity_revision: Mapped[int] = mapped_column(Integer)
    connection_fingerprint: Mapped[str] = mapped_column(String(64))
    credential_profile_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    credential_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    gateway_profile: Mapped[str] = mapped_column(String(63))
    modules: Mapped[list[str]] = mapped_column(JSON, default=list)
    collectors: Mapped[list[str]] = mapped_column(JSON, default=list)
    schedule_seconds: Mapped[int] = mapped_column(Integer, default=30)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    approved_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    approved_by: Mapped[str] = mapped_column(String(255))
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class DeviceConnectionPreflight(Base):
    __tablename__ = "device_connection_preflights"
    __table_args__ = (
        CheckConstraint(
            "latency_ms IS NULL OR latency_ms >= 0",
            name="ck_device_preflight_latency_nonnegative",
        ),
        Index(
            "ix_device_preflight_connection_started",
            "connection_id",
            "started_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    connection_id: Mapped[str] = mapped_column(
        ForeignKey("device_connections.id", ondelete="CASCADE"), index=True
    )
    worker_id: Mapped[str] = mapped_column(
        ForeignKey("collector_workers.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    lease_token_hash: Mapped[str] = mapped_column(String(64))
    lease_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    target_host: Mapped[str | None] = mapped_column(String(45), nullable=True)
    site_snapshot: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    connection: Mapped[DeviceConnection] = relationship(back_populates="preflights")
    worker: Mapped[CollectorWorker] = relationship(back_populates="device_preflights")


class ActivationPolicyProposal(Base):
    """Review-only AI suggestion, one durable record per model request."""

    __tablename__ = "activation_policy_proposals"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "actor", "request_key",
            name="uq_activation_policy_proposal_request",
        ),
        CheckConstraint(
            "status IN ('generating', 'succeeded', 'failed')",
            name="ck_activation_policy_proposal_status",
        ),
        CheckConstraint(
            "tokens_used >= 0", name="ck_activation_policy_proposal_tokens",
        ),
        Index(
            "ix_activation_policy_proposal_device_created",
            "device_id", "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    parent_id: Mapped[str | None] = mapped_column(
        ForeignKey("activation_policy_proposals.id", ondelete="RESTRICT"),
        nullable=True, index=True,
    )
    device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="RESTRICT"), nullable=True, index=True,
    )
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True,
    )
    protocol: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(255), index=True)
    request_key: Mapped[str] = mapped_column(String(36))
    request_sha256: Mapped[str] = mapped_column(String(64))
    brief: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="generating", index=True)
    result_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    route_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    # NULL on pre-migration rows: historical provider charge is unverified.
    external_charge_unknown: Mapped[bool | None] = mapped_column(
        Boolean, nullable=True,
    )
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow,
    )


class DeviceActivationPolicy(Base):
    __tablename__ = "device_activation_policies"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "name", "version",
            name="uq_device_activation_policy_namespace_version",
        ),
        CheckConstraint("version > 0", name="ck_device_activation_policy_version_positive"),
        CheckConstraint("revision > 0", name="ck_device_activation_policy_revision_positive"),
        CheckConstraint(
            "schedule_seconds > 0",
            name="ck_device_activation_policy_schedule_positive",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[int] = mapped_column(Integer)
    revision: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    status: Mapped[ArtifactVersionStatus] = mapped_column(
        Enum(ArtifactVersionStatus, native_enum=False, length=16),
        default=ArtifactVersionStatus.DRAFT,
        index=True,
    )
    protocol: Mapped[str] = mapped_column(String(32), index=True)
    adapter_type: Mapped[str] = mapped_column(String(128), index=True)
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    target_template: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    configuration_defaults: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    worker_selector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    execution_mode: Mapped[CollectorDeploymentMode] = mapped_column(
        Enum(CollectorDeploymentMode, native_enum=False, length=16),
        default=CollectorDeploymentMode.SCHEDULED,
        index=True,
    )
    schedule_seconds: Mapped[int] = mapped_column(Integer, default=300)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    validated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    validated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    published_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class DeviceConnectionActivation(Base):
    __tablename__ = "device_connection_activations"
    __table_args__ = (
        UniqueConstraint(
            "connection_id",
            "capability_key",
            name="uq_device_connection_activation_capability",
        ),
        UniqueConstraint("deployment_id", name="uq_device_activation_deployment"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    connection_id: Mapped[str] = mapped_column(
        ForeignKey("device_connections.id", ondelete="CASCADE"), index=True
    )
    capability_key: Mapped[str] = mapped_column(String(255), index=True)
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("device_activation_policies.id", ondelete="RESTRICT"), index=True
    )
    deployment_id: Mapped[str | None] = mapped_column(
        ForeignKey("collector_deployments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    plan_hash: Mapped[str] = mapped_column(String(64))
    expected_deployment_hash: Mapped[str] = mapped_column(String(64))
    runtime_status: Mapped[str] = mapped_column(
        String(32), default="awaiting_first_run", index=True
    )
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("collector_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    last_run_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_run_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failure_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    health_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_by: Mapped[str] = mapped_column(String(255))
    approval_reason: Mapped[str] = mapped_column(Text)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    deactivated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deactivated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    deactivation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    connection: Mapped[DeviceConnection] = relationship(back_populates="activations")
    policy: Mapped[DeviceActivationPolicy] = relationship()
    deployment: Mapped[CollectorDeployment | None] = relationship()
    last_run: Mapped[CollectorRun | None] = relationship(
        foreign_keys=[last_run_id]
    )


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "mac_address",
            name="uq_endpoint_namespace_mac",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    mac_address: Mapped[str] = mapped_column(String(17), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    ip_observations: Mapped[list[IPAddressObservation]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan"
    )
    attachments: Mapped[list[EndpointAttachment]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan"
    )
    wireless_sessions: Mapped[list[WirelessClientSession]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan"
    )
    network_observation_states: Mapped[list[NetworkObservationState]] = relationship(viewonly=True, lazy="selectin")


class IPAddressObservation(Base):
    __tablename__ = "ip_address_observations"
    __table_args__ = (
        Index("ix_ip_observation_endpoint_active", "endpoint_id", "active"),
        Index("ix_ip_observation_address_last_seen", "ip_address", "last_seen"),
        Index("ix_ip_observation_source_history", "tenant_id", "region_id", "endpoint_id", "source",
            "collector_device_id", "ip_address", "vlan_id", "last_seen"),
        Index("ix_ip_observation_source_current", "tenant_id", "region_id", "endpoint_id", "source",
            "collector_device_id", postgresql_where=text("active"), sqlite_where=text("active")),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    source: Mapped[ObservationSource] = mapped_column(
        Enum(ObservationSource, native_enum=False, length=32), index=True
    )
    collector_device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), index=True, nullable=True
    )
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    endpoint: Mapped[Endpoint] = relationship(back_populates="ip_observations")
    collector_device: Mapped[Device | None] = relationship(back_populates="ip_observations")


class EndpointAttachment(Base):
    __tablename__ = "endpoint_attachments"
    __table_args__ = (
        Index("ix_attachment_endpoint_active", "endpoint_id", "active"),
        Index("ix_attachment_collector_interface", "collector_device_id", "interface_name"),
        Index("ix_attachment_source_current", "tenant_id", "region_id", "endpoint_id", "source",
            "collector_device_id", postgresql_where=text("active"), sqlite_where=text("active")),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), index=True
    )
    collector_device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), index=True, nullable=True
    )
    source: Mapped[ObservationSource] = mapped_column(
        Enum(ObservationSource, native_enum=False, length=32), index=True
    )
    interface_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    endpoint: Mapped[Endpoint] = relationship(back_populates="attachments")
    collector_device: Mapped[Device | None] = relationship(back_populates="attachments")


class NetworkObservationState(Base):
    """Source-local logical inventory clock, not causal or physical proof."""
    __tablename__ = "network_observation_states"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "endpoint_id", "source", "collector_key", "dimension",
            name="uq_network_observation_source_dimension"),
        CheckConstraint("revision>0", name="ck_network_observation_revision"),
        CheckConstraint("dimension IN ('metadata','ipv4','ipv6','attachment')", name="ck_network_observation_dimension"),
        CheckConstraint("state IN ('unobserved','accepted','conflict','legacy_unknown')", name="ck_network_observation_state"),
        CheckConstraint("(state='unobserved' AND observed_at IS NULL) OR (state<>'unobserved' AND observed_at IS NOT NULL)",
            name="ck_network_observation_time"),
        CheckConstraint("length(payload)<=65536", name="ck_network_observation_payload_bound"),
        CheckConstraint("(state IN ('accepted','conflict') AND length(payload)>0) OR (state IN ('unobserved','legacy_unknown') AND payload='')",
            name="ck_network_observation_payload_state"),
        CheckConstraint("(collector_device_id IS NULL AND collector_key='unbound') OR (collector_device_id IS NOT NULL AND collector_key=collector_device_id)",
            name="ck_network_observation_collector_key"),
        CheckConstraint("source IN ('ARP','MAC_TABLE','DHCP','MANUAL')", name="ck_network_observation_source"),
        Index("ix_network_observation_collector_source", "tenant_id", "region_id", "collector_key", "source"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id", ondelete="RESTRICT"), index=True)
    source: Mapped[ObservationSource] = mapped_column(Enum(ObservationSource, native_enum=False, length=32))
    collector_device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"), nullable=True)
    collector_key: Mapped[str] = mapped_column(String(36))
    dimension: Mapped[str] = mapped_column(String(16))
    state: Mapped[str] = mapped_column(String(32), default="unobserved")
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payload: Mapped[str] = mapped_column(Text, default="", deferred=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WirelessSnapshotState(Base):
    """Durable collection watermark, not independent remediation proof."""

    __tablename__ = "wireless_snapshot_states"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "controller_id", name="uq_wireless_snapshot_controller"),
        CheckConstraint("revision > 0", name="ck_wireless_snapshot_revision"),
        CheckConstraint("state IN ('unobserved','accepted','conflict','legacy_unknown')", name="ck_wireless_snapshot_state"),
        CheckConstraint("(state='unobserved' AND observed_at IS NULL) OR (state<>'unobserved' AND observed_at IS NOT NULL)", name="ck_wireless_snapshot_time"),
        CheckConstraint("length(payload) <= 8388608", name="ck_wireless_snapshot_payload_bound"),
        CheckConstraint("(state IN ('accepted','conflict') AND length(payload)>0) OR (state IN ('unobserved','legacy_unknown') AND payload='')", name="ck_wireless_snapshot_payload_state"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    controller_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"), index=True)
    state: Mapped[str] = mapped_column(String(32), default="unobserved")
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payload: Mapped[str] = mapped_column(Text, default="")
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WirelessClientSession(Base):
    __tablename__ = "wireless_client_sessions"
    __table_args__ = (
        Index("ix_wireless_endpoint_active", "endpoint_id", "active"),
        Index("ix_wireless_controller_active", "controller_id", "active"),
        Index("ix_wireless_ssid_last_seen", "ssid", "last_seen"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), index=True
    )
    controller_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    access_point: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    ssid: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    bssid: Mapped[str | None] = mapped_column(String(17), nullable=True)
    radio: Mapped[str | None] = mapped_column(String(64), nullable=True)
    band: Mapped[str | None] = mapped_column(String(32), nullable=True)
    channel: Mapped[int | None] = mapped_column(Integer, nullable=True)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rssi: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snr: Mapped[int | None] = mapped_column(Integer, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disconnected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    endpoint: Mapped[Endpoint] = relationship(back_populates="wireless_sessions")
    controller: Mapped[Device] = relationship(back_populates="wireless_sessions")


class KnowledgeEntity(Base):
    __tablename__ = "knowledge_entities"
    __table_args__ = (
        UniqueConstraint(
            "namespace",
            "scope_key",
            "entity_type",
            "external_key",
            name="uq_knowledge_entity_identity",
        ),
        Index(
            "ix_knowledge_entity_scope_type",
            "scope_key",
            "entity_type",
            "active",
        ),
        Index(
            "ix_knowledge_entity_site_type",
            "scope_site",
            "entity_type",
            "active",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    namespace: Mapped[str] = mapped_column(String(255), index=True)
    scope_key: Mapped[str] = mapped_column(String(255), index=True)
    scope_device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scope_site: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    external_key: Mapped[str] = mapped_column(String(512), index=True)
    display_name: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    last_envelope_id: Mapped[str | None] = mapped_column(
        ForeignKey("collection_envelopes.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class KnowledgeRelationship(Base):
    __tablename__ = "knowledge_relationships"
    __table_args__ = (
        UniqueConstraint(
            "namespace",
            "scope_key",
            "relationship_type",
            "source_entity_id",
            "target_entity_id",
            "directed",
            name="uq_knowledge_relationship_identity",
        ),
        Index(
            "ix_knowledge_relationship_scope_type",
            "scope_key",
            "relationship_type",
            "active",
        ),
        Index(
            "ix_knowledge_relationship_site_type",
            "scope_site",
            "relationship_type",
            "active",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    namespace: Mapped[str] = mapped_column(String(255), index=True)
    scope_key: Mapped[str] = mapped_column(String(255), index=True)
    scope_device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scope_site: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    relationship_type: Mapped[str] = mapped_column(String(64), index=True)
    source_entity_id: Mapped[str] = mapped_column(
        ForeignKey("knowledge_entities.id", ondelete="CASCADE"), index=True
    )
    target_entity_id: Mapped[str] = mapped_column(
        ForeignKey("knowledge_entities.id", ondelete="CASCADE"), index=True
    )
    directed: Mapped[bool] = mapped_column(Boolean, default=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    last_envelope_id: Mapped[str | None] = mapped_column(
        ForeignKey("collection_envelopes.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    source_entity: Mapped[KnowledgeEntity] = relationship(
        foreign_keys=[source_entity_id]
    )
    target_entity: Mapped[KnowledgeEntity] = relationship(
        foreign_keys=[target_entity_id]
    )


class ServiceCatalogEntry(Base):
    __tablename__ = "service_catalog_entries"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "service_key", name="uq_service_namespace_key",
        ),
        CheckConstraint(
            "status IN ('active', 'retired')",
            name="ck_service_catalog_status",
        ),
        CheckConstraint(
            "criticality IN ('tier_0', 'tier_1', 'tier_2', 'tier_3')",
            name="ck_service_catalog_criticality",
        ),
        CheckConstraint(
            "business_impact IN ('critical', 'high', 'moderate', 'low')",
            name="ck_service_catalog_business_impact",
        ),
        CheckConstraint(
            "slo_target_percent IS NULL OR (slo_target_percent >= 0 AND slo_target_percent <= 100)",
            name="ck_service_catalog_slo_target",
        ),
        CheckConstraint(
            "recovery_time_objective_minutes IS NULL OR recovery_time_objective_minutes >= 0",
            name="ck_service_catalog_rto",
        ),
        CheckConstraint(
            "recovery_point_objective_minutes IS NULL OR recovery_point_objective_minutes >= 0",
            name="ck_service_catalog_rpo",
        ),
        CheckConstraint("revision > 0", name="ck_service_catalog_revision"),
        Index(
            "ix_service_catalog_priority",
            "status",
            "criticality",
            "business_impact",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    service_key: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    owner_team: Mapped[str] = mapped_column(String(255), index=True)
    owner_contact: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )
    criticality: Mapped[str] = mapped_column(String(16), index=True)
    business_impact: Mapped[str] = mapped_column(String(16), index=True)
    business_impact_summary: Mapped[str] = mapped_column(Text, default="")
    slo_target_percent: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    recovery_time_objective_minutes: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    recovery_point_objective_minutes: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(16), default="active", index=True
    )
    tags: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255))
    updated_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    components: Mapped[list[ServiceCatalogComponent]] = relationship(
        back_populates="service",
        cascade="all, delete-orphan",
        order_by="ServiceCatalogComponent.node_id",
    )
    outgoing_dependencies: Mapped[list[ServiceCatalogDependency]] = relationship(
        back_populates="source_service",
        cascade="all, delete-orphan",
        foreign_keys="ServiceCatalogDependency.source_service_id",
    )
    incoming_dependencies: Mapped[list[ServiceCatalogDependency]] = relationship(
        back_populates="target_service",
        cascade="all, delete-orphan",
        foreign_keys="ServiceCatalogDependency.target_service_id",
    )
    indicators: Mapped[list[ServiceIndicatorDefinition]] = relationship(
        back_populates="service",
        cascade="all, delete-orphan",
        order_by="ServiceIndicatorDefinition.indicator_key",
    )


class ServiceCatalogComponent(Base):
    __tablename__ = "service_catalog_components"
    __table_args__ = (
        UniqueConstraint(
            "service_id",
            "node_id",
            name="uq_service_catalog_component_node",
        ),
        CheckConstraint(
            "node_type IN ('device', 'endpoint', 'knowledge_entity')",
            name="ck_service_catalog_component_node_type",
        ),
        CheckConstraint(
            "role IN ('entrypoint', 'dependency', 'compute', 'data', 'network', 'other')",
            name="ck_service_catalog_component_role",
        ),
        Index(
            "ix_service_catalog_component_entity",
            "node_type",
            "entity_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    service_id: Mapped[str] = mapped_column(
        ForeignKey("service_catalog_entries.id", ondelete="CASCADE"), index=True
    )
    node_id: Mapped[str] = mapped_column(String(255), index=True)
    node_type: Mapped[str] = mapped_column(String(32), index=True)
    entity_id: Mapped[str] = mapped_column(String(36), index=True)
    role: Mapped[str] = mapped_column(String(32), default="dependency")
    required: Mapped[bool] = mapped_column(Boolean, default=True)
    evidence_note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    service: Mapped[ServiceCatalogEntry] = relationship(
        back_populates="components"
    )


class ServiceCatalogDependency(Base):
    __tablename__ = "service_catalog_dependencies"
    __table_args__ = (
        UniqueConstraint(
            "source_service_id",
            "target_service_id",
            "dependency_type",
            name="uq_service_catalog_dependency",
        ),
        CheckConstraint(
            "source_service_id <> target_service_id",
            name="ck_service_catalog_dependency_not_self",
        ),
        CheckConstraint(
            "dependency_type IN ('synchronous', 'asynchronous', 'data', 'shared_infrastructure')",
            name="ck_service_catalog_dependency_type",
        ),
        Index(
            "ix_service_catalog_dependency_target_source",
            "target_service_id",
            "source_service_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_service_id: Mapped[str] = mapped_column(
        ForeignKey("service_catalog_entries.id", ondelete="CASCADE"), index=True
    )
    target_service_id: Mapped[str] = mapped_column(
        ForeignKey("service_catalog_entries.id", ondelete="CASCADE"), index=True
    )
    dependency_type: Mapped[str] = mapped_column(String(32), index=True)
    critical: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    evidence_note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    source_service: Mapped[ServiceCatalogEntry] = relationship(
        back_populates="outgoing_dependencies",
        foreign_keys=[source_service_id],
    )
    target_service: Mapped[ServiceCatalogEntry] = relationship(
        back_populates="incoming_dependencies",
        foreign_keys=[target_service_id],
    )


class ServiceIndicatorDefinition(Base):
    __tablename__ = "service_indicator_definitions"
    __table_args__ = (
        UniqueConstraint(
            "service_id",
            "indicator_key",
            name="uq_service_indicator_definition_key",
        ),
        CheckConstraint(
            "kind IN ('availability', 'latency', 'error_rate', 'throughput', "
            "'saturation', 'business', 'custom')",
            name="ck_service_indicator_kind",
        ),
        CheckConstraint(
            "source_type IN ('prometheus', 'api', 'collector', 'business_system', 'manual')",
            name="ck_service_indicator_source_type",
        ),
        CheckConstraint(
            "breach_direction IN ('above', 'below', 'none')",
            name="ck_service_indicator_breach_direction",
        ),
        CheckConstraint(
            "freshness_seconds >= 10 AND freshness_seconds <= 2592000",
            name="ck_service_indicator_freshness",
        ),
        CheckConstraint("revision > 0", name="ck_service_indicator_revision"),
        Index(
            "ix_service_indicator_definition_active",
            "service_id",
            "enabled",
            "indicator_key",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    service_id: Mapped[str] = mapped_column(
        ForeignKey("service_catalog_entries.id", ondelete="CASCADE"), index=True
    )
    indicator_key: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(32), index=True)
    unit: Mapped[str] = mapped_column(String(64))
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    source_ref: Mapped[str] = mapped_column(String(1024))
    breach_direction: Mapped[str] = mapped_column(String(16), default="none")
    warning_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    critical_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    freshness_seconds: Mapped[int] = mapped_column(Integer, default=300)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255))
    updated_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    service: Mapped[ServiceCatalogEntry] = relationship(back_populates="indicators")
    observations: Mapped[list[ServiceIndicatorObservation]] = relationship(
        back_populates="definition",
        cascade="all, delete-orphan",
        order_by="ServiceIndicatorObservation.observed_at.desc()",
    )
    prometheus_binding: Mapped[ServiceIndicatorPrometheusBinding | None] = (
        relationship(
            back_populates="definition",
            cascade="all, delete-orphan",
            uselist=False,
        )
    )
    artifact_binding: Mapped[ServiceIndicatorArtifactBinding | None] = relationship(
        back_populates="definition",
        cascade="all, delete-orphan",
        uselist=False,
    )


class ServiceIndicatorObservation(Base):
    __tablename__ = "service_indicator_observations"
    __table_args__ = (
        UniqueConstraint(
            "definition_id",
            "source_observation_id",
            name="uq_service_indicator_observation_source",
        ),
        CheckConstraint(
            "measurement_quality IN ('measured', 'estimated', 'manual')",
            name="ck_service_indicator_observation_quality",
        ),
        Index(
            "ix_service_indicator_observation_latest",
            "definition_id",
            "observed_at",
            "ingested_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    definition_id: Mapped[str] = mapped_column(
        ForeignKey("service_indicator_definitions.id", ondelete="CASCADE"),
        index=True,
    )
    source_observation_id: Mapped[str] = mapped_column(String(255), index=True)
    value: Mapped[float] = mapped_column(Float)
    measurement_quality: Mapped[str] = mapped_column(
        String(16), default="measured", index=True
    )
    dimensions: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    evidence_ref: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    created_by: Mapped[str] = mapped_column(String(255))

    definition: Mapped[ServiceIndicatorDefinition] = relationship(
        back_populates="observations"
    )


class ServiceIndicatorPrometheusBinding(Base):
    __tablename__ = "service_indicator_prometheus_bindings"
    __table_args__ = (
        CheckConstraint(
            "reduction IN ('single', 'sum', 'avg', 'min', 'max')",
            name="ck_indicator_prom_binding_reduction",
        ),
        CheckConstraint(
            "interval_seconds >= 60 AND interval_seconds <= 86400",
            name="ck_indicator_prom_binding_interval",
        ),
        CheckConstraint(
            "timeout_seconds >= 1 AND timeout_seconds <= 60",
            name="ck_indicator_prom_binding_timeout",
        ),
        CheckConstraint(
            "revision > 0 AND consecutive_failures >= 0",
            name="ck_indicator_prom_binding_revision_failures",
        ),
        Index(
            "ix_indicator_prom_binding_due",
            "enabled",
            "next_run_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    definition_id: Mapped[str] = mapped_column(
        ForeignKey("service_indicator_definitions.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    metric_backend_id: Mapped[str] = mapped_column(
        ForeignKey("metric_backends.id", ondelete="RESTRICT"),
        index=True,
    )
    query: Mapped[str] = mapped_column(Text)
    reduction: Mapped[str] = mapped_column(String(16), default="single")
    dimension_labels: Mapped[list[str]] = mapped_column(JSON, default=list)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=15)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    last_scheduled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_succeeded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_error_type: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    last_error_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    created_by: Mapped[str] = mapped_column(String(255))
    updated_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    definition: Mapped[ServiceIndicatorDefinition] = relationship(
        back_populates="prometheus_binding"
    )
    metric_backend: Mapped[MetricBackend] = relationship(
        back_populates="indicator_bindings"
    )
    runs: Mapped[list[ServiceIndicatorPollRun]] = relationship(
        back_populates="binding",
        cascade="all, delete-orphan",
        order_by="ServiceIndicatorPollRun.scheduled_for.desc()",
    )


class ServiceIndicatorArtifactBinding(Base):
    __tablename__ = "service_indicator_artifact_bindings"
    __table_args__ = (
        UniqueConstraint(
            "artifact_version_id",
            "producer_kind",
            "binding_key",
            name="uq_indicator_artifact_binding_key",
        ),
        CheckConstraint(
            "producer_kind IN ('collector', 'workflow')",
            name="ck_indicator_artifact_binding_kind",
        ),
        CheckConstraint(
            "revision > 0",
            name="ck_indicator_artifact_binding_revision",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    definition_id: Mapped[str] = mapped_column(
        ForeignKey("service_indicator_definitions.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    producer_kind: Mapped[str] = mapped_column(String(16), index=True)
    binding_key: Mapped[str] = mapped_column(String(128), index=True)
    producer_tool_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    output_mapping: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255))
    updated_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    definition: Mapped[ServiceIndicatorDefinition] = relationship(
        back_populates="artifact_binding"
    )
    artifact_version: Mapped[ArtifactVersion] = relationship()
    publications: Mapped[list[ServiceIndicatorArtifactPublication]] = relationship(
        back_populates="binding",
        cascade="all, delete-orphan",
        order_by="ServiceIndicatorArtifactPublication.created_at.desc()",
    )


class ServiceIndicatorArtifactPublication(Base):
    __tablename__ = "service_indicator_artifact_publications"
    __table_args__ = (
        UniqueConstraint(
            "observation_id",
            name="uq_indicator_artifact_publication_observation",
        ),
        UniqueConstraint(
            "binding_id",
            "collection_envelope_id",
            name="uq_indicator_artifact_publication_envelope",
        ),
        UniqueConstraint(
            "binding_id",
            "investigation_id",
            name="uq_indicator_artifact_publication_investigation",
        ),
        CheckConstraint(
            "producer_kind IN ('collector', 'workflow')",
            name="ck_indicator_artifact_publication_kind",
        ),
        CheckConstraint(
            "(producer_kind = 'collector' AND collection_envelope_id IS NOT NULL "
            "AND investigation_id IS NULL AND source_tool_call_id IS NULL) OR "
            "(producer_kind = 'workflow' AND collection_envelope_id IS NULL "
            "AND investigation_id IS NOT NULL AND source_tool_call_id IS NOT NULL)",
            name="ck_indicator_artifact_publication_source",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    binding_id: Mapped[str] = mapped_column(
        ForeignKey("service_indicator_artifact_bindings.id", ondelete="CASCADE"),
        index=True,
    )
    observation_id: Mapped[str] = mapped_column(
        ForeignKey("service_indicator_observations.id", ondelete="CASCADE"),
        index=True,
    )
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    binding_revision: Mapped[int] = mapped_column(Integer)
    producer_kind: Mapped[str] = mapped_column(String(16), index=True)
    collection_envelope_id: Mapped[str | None] = mapped_column(
        ForeignKey("collection_envelopes.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    investigation_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    source_tool_call_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    binding: Mapped[ServiceIndicatorArtifactBinding] = relationship(
        back_populates="publications"
    )
    observation: Mapped[ServiceIndicatorObservation] = relationship()


class ServiceIndicatorWorker(Base):
    __tablename__ = "service_indicator_workers"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_service_indicator_worker_namespace_name",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    state: Mapped[IndicatorWorkerState] = mapped_column(
        Enum(IndicatorWorkerState, native_enum=False, length=16),
        default=IndicatorWorkerState.ONLINE,
        index=True,
    )
    last_heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    runs: Mapped[list[ServiceIndicatorPollRun]] = relationship(
        back_populates="lease_worker"
    )


class ServiceIndicatorPollRun(Base):
    __tablename__ = "service_indicator_poll_runs"
    __table_args__ = (
        UniqueConstraint(
            "binding_id",
            "scheduled_for",
            name="uq_indicator_poll_run_schedule",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND max_attempts > 0",
            name="ck_indicator_poll_run_attempts",
        ),
        CheckConstraint(
            "series_count IS NULL OR series_count >= 0",
            name="ck_indicator_poll_run_series_count",
        ),
        Index(
            "ix_indicator_poll_run_queue",
            "status",
            "next_attempt_at",
            "lease_expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    binding_id: Mapped[str] = mapped_column(
        ForeignKey("service_indicator_prometheus_bindings.id", ondelete="CASCADE"),
        index=True,
    )
    scheduled_for: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    status: Mapped[IndicatorPollRunStatus] = mapped_column(
        Enum(IndicatorPollRunStatus, native_enum=False, length=16),
        default=IndicatorPollRunStatus.PENDING,
        index=True,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    lease_worker_id: Mapped[str | None] = mapped_column(
        ForeignKey("service_indicator_workers.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    lease_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    observation_id: Mapped[str | None] = mapped_column(
        ForeignKey("service_indicator_observations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    result_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    series_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    binding: Mapped[ServiceIndicatorPrometheusBinding] = relationship(
        back_populates="runs"
    )
    lease_worker: Mapped[ServiceIndicatorWorker | None] = relationship(
        back_populates="runs"
    )
    observation: Mapped[ServiceIndicatorObservation | None] = relationship()


class AlertRule(Base):
    __tablename__ = "alert_rules"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_alert_rule_namespace_name",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, native_enum=False, length=16)
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    conditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=300)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    alerts: Mapped[list[Alert]] = relationship(back_populates="rule")


class MetricRuleChange(Base):
    """Reviewed native rule versions and retained uncertain-write receipts."""
    __tablename__="metric_rule_changes"
    __table_args__=(CheckConstraint("status IN ('proposed','applying','applied','conflict','unknown','rejected')",name="ck_metric_rule_change_status"),
        CheckConstraint("expected_revision >= 0",name="ck_metric_rule_expected_revision"))
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=new_id)
    rule_id:Mapped[str]=mapped_column(ForeignKey("alert_rules.id",ondelete="RESTRICT"),index=True)
    expected_revision:Mapped[int]=mapped_column(Integer)
    definition:Mapped[dict[str,Any]]=mapped_column(JSON)
    target_snapshot:Mapped[dict[str,Any]]=mapped_column(JSON)
    backend_revision:Mapped[int]=mapped_column(Integer)
    compiled_rule:Mapped[dict[str,Any]]=mapped_column(JSON)
    catalog_before:Mapped[dict[str,Any]]=mapped_column(JSON)
    catalog_after:Mapped[dict[str,Any]]=mapped_column(JSON)
    runtime_before_hash:Mapped[str]=mapped_column(String(64))
    runtime_binding:Mapped[dict[str,Any]]=mapped_column(JSON)
    plan_hash:Mapped[str]=mapped_column(String(64),index=True)
    status:Mapped[str]=mapped_column(String(16),default="proposed",index=True)
    previous_definition:Mapped[dict[str,Any]|None]=mapped_column(JSON,nullable=True)
    restore_of_id:Mapped[str|None]=mapped_column(ForeignKey("metric_rule_changes.id",ondelete="RESTRICT"),nullable=True)
    approved_by:Mapped[str|None]=mapped_column(String(255),nullable=True)
    error_code:Mapped[str|None]=mapped_column(String(64),nullable=True)
    created_by:Mapped[str]=mapped_column(String(255))
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=utcnow)
    applied_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alert_status_severity_last_seen", "status", "severity", "last_seen"),
        Index("ix_alert_dedup_status", "dedup_key", "status"),
        Index("uq_alert_active_condition", "tenant_id", "region_id", "dedup_key", unique=True,
            postgresql_where=text("status IN ('OPEN','ACKNOWLEDGED')"),
            sqlite_where=text("status IN ('OPEN','ACKNOWLEDGED')")),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    rule_id: Mapped[str | None] = mapped_column(
        ForeignKey("alert_rules.id", ondelete="SET NULL"), index=True, nullable=True
    )
    dedup_key: Mapped[str] = mapped_column(String(512), index=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, native_enum=False, length=16), index=True
    )
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, native_enum=False, length=16), default=AlertStatus.OPEN, index=True
    )
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    entity_id: Mapped[str] = mapped_column(String(255), index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_retirement_id: Mapped[str | None] = mapped_column(ForeignKey(
        "collector_source_retirements.id", name="fk_alert_source_retirement", ondelete="RESTRICT", use_alter=True),
        nullable=True, index=True)

    rule: Mapped[AlertRule | None] = relationship(back_populates="alerts")
    situation_memberships: Mapped[list[SituationAlert]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
    )


class AlertConditionState(Base):
    """Per-source ordering watermark, not independent quiet-state proof."""
    __tablename__ = "alert_condition_states"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "dedup_key", name="uq_alert_condition_source"),
        CheckConstraint("state IN ('unobserved','active','quiet','conflict','unknown','legacy_unknown')", name="ck_alert_condition_state"),
        CheckConstraint("revision > 0", name="ck_alert_condition_revision"),
        CheckConstraint("(state = 'unobserved' AND observed_at IS NULL) OR (state != 'unobserved' AND observed_at IS NOT NULL)", name="ck_alert_condition_observation"),
        CheckConstraint("(event_type IS NULL AND entity_type IS NULL AND entity_id IS NULL AND source_rule_id IS NULL) OR (event_type IS NOT NULL AND entity_type IS NOT NULL AND entity_id IS NOT NULL)", name="ck_alert_condition_identity"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    dedup_key: Mapped[str] = mapped_column(String(512))
    event_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_rule_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    state: Mapped[str] = mapped_column(String(32), default="unobserved")
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    latest_alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectorConditionAdmission(Base):
    """Sealed acceptance context, not an independent truth attestation."""
    __tablename__ = "collector_condition_admissions"
    __table_args__ = (
        UniqueConstraint("envelope_id", name="uq_collector_condition_admission_envelope"),
        CheckConstraint("length(payload) <= 32768", name="ck_collector_condition_admission_payload"),
        Index("ix_condition_admission_generation_clock", "tenant_id", "region_id", "deployment_id", "artifact_version_id", "observed_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    envelope_id: Mapped[str] = mapped_column(ForeignKey("collection_envelopes.id", ondelete="RESTRICT"), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("collector_runs.id", ondelete="RESTRICT"), index=True)
    deployment_id: Mapped[str] = mapped_column(ForeignKey("collector_deployments.id", ondelete="RESTRICT"), index=True)
    artifact_version_id: Mapped[str] = mapped_column(ForeignKey("artifact_versions.id", ondelete="RESTRICT"))
    worker_id: Mapped[str] = mapped_column(ForeignKey("collector_workers.id", ondelete="RESTRICT"))
    credential_grant_audit_id: Mapped[str | None] = mapped_column(ForeignKey("audit_events.id", ondelete="RESTRICT"), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload: Mapped[str] = mapped_column(Text)
    context: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectorConditionSource(Base):
    """An immutable version/assignment/credential/entity source generation."""
    __tablename__ = "collector_condition_sources"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "deployment_id", "artifact_version_id",
            "assignment_sha256", "credential_identity", "condition_key", "entity_type", "entity_id",
            name="uq_collector_condition_source_generation"),
        UniqueConstraint("tenant_id", "region_id", "dedup_key", name="uq_collector_condition_source_key"),
        Index("ix_collector_condition_source_deployment", "tenant_id", "region_id", "deployment_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    deployment_id: Mapped[str] = mapped_column(ForeignKey("collector_deployments.id", ondelete="RESTRICT"))
    artifact_version_id: Mapped[str] = mapped_column(ForeignKey("artifact_versions.id", ondelete="RESTRICT"))
    assignment_sha256: Mapped[str] = mapped_column(String(64))
    credential_identity: Mapped[str] = mapped_column(String(64))
    condition_key: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str] = mapped_column(String(255))
    dedup_key: Mapped[str] = mapped_column(String(512))
    context: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectorConditionReceipt(Base):
    """Append-only interpretation/result of one sealed accepted observation."""
    __tablename__ = "collector_condition_receipts"
    __table_args__ = (
        UniqueConstraint("admission_id", name="uq_collector_condition_receipt_admission"),
        CheckConstraint("verdict IN ('active','quiet','unknown')", name="ck_collector_condition_receipt_verdict"),
        CheckConstraint("disposition IN ('accepted','stale','duplicate','conflict','retired')", name="ck_collector_condition_receipt_disposition"),
        Index("ix_collector_condition_receipt_source_time", "source_id", "observed_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    admission_id: Mapped[str] = mapped_column(ForeignKey("collector_condition_admissions.id", ondelete="RESTRICT"))
    source_id: Mapped[str] = mapped_column(ForeignKey("collector_condition_sources.id", ondelete="RESTRICT"))
    condition_state_id: Mapped[str] = mapped_column(ForeignKey("alert_condition_states.id", ondelete="RESTRICT"))
    alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    verdict: Mapped[str] = mapped_column(String(16))
    disposition: Mapped[str] = mapped_column(String(16))
    result: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectorSourceQualificationRequest(Base):
    """Exact source material proposed for external semantic/clock acceptance."""
    __tablename__ = "collector_source_qualification_requests"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "source_id", "request_key",
            name="uq_source_qualification_request_key"),
        CheckConstraint("expires_at > created_at", name="ck_source_qualification_request_lifetime"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("collector_condition_sources.id", ondelete="RESTRICT"), index=True)
    baseline_receipt_id: Mapped[str] = mapped_column(ForeignKey("collector_condition_receipts.id", ondelete="RESTRICT"))
    author_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    author_subject: Mapped[str] = mapped_column(String(255))
    request_key: Mapped[str] = mapped_column(String(128))
    evidence_environment: Mapped[str] = mapped_column(String(32))
    validation_reference: Mapped[str] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(String(512))
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectorSourceQualificationReview(Base):
    """Peer attestation, not automatic physical truth or closure permission."""
    __tablename__ = "collector_source_qualification_reviews"
    __table_args__ = (UniqueConstraint("request_id", name="uq_source_qualification_review_request"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(ForeignKey("collector_source_qualification_requests.id", ondelete="RESTRICT"), index=True)
    reviewer_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    reviewer_subject: Mapped[str] = mapped_column(String(255))
    acceptance_reference: Mapped[str] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectorSourceQualificationRevocation(Base):
    __tablename__ = "collector_source_qualification_revocations"
    __table_args__ = (UniqueConstraint("review_id", name="uq_source_qualification_revocation_review"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    review_id: Mapped[str] = mapped_column(ForeignKey("collector_source_qualification_reviews.id", ondelete="RESTRICT"), index=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    subject: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def _immutable_source_qualification(_mapper, _connection, _target):
    raise ValueError("Collector source qualification history is append-only")


for _qualification_model in (CollectorSourceQualificationRequest,
    CollectorSourceQualificationReview, CollectorSourceQualificationRevocation):
    event.listen(_qualification_model, "before_update", _immutable_source_qualification)
    event.listen(_qualification_model, "before_delete", _immutable_source_qualification)


class CollectorSourceReplacementRequest(Base):
    """Exact old/new source material; not a retirement or closure command."""
    __tablename__ = "collector_source_replacement_requests"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "request_key", name="uq_source_replacement_request_key"),
        CheckConstraint("old_source_id <> new_source_id", name="ck_source_replacement_distinct_sources"),
        CheckConstraint("expires_at > created_at", name="ck_source_replacement_request_lifetime"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    old_source_id: Mapped[str] = mapped_column(ForeignKey("collector_condition_sources.id", ondelete="RESTRICT"), index=True)
    new_source_id: Mapped[str] = mapped_column(ForeignKey("collector_condition_sources.id", ondelete="RESTRICT"), index=True)
    old_qualification_review_id: Mapped[str] = mapped_column(ForeignKey("collector_source_qualification_reviews.id", ondelete="RESTRICT"))
    new_qualification_review_id: Mapped[str] = mapped_column(ForeignKey("collector_source_qualification_reviews.id", ondelete="RESTRICT"))
    prior_retirement_id: Mapped[str | None] = mapped_column(ForeignKey(
        "collector_source_retirements.id", name="fk_replacement_prior_retirement", ondelete="RESTRICT", use_alter=True), nullable=True)
    author_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    author_subject: Mapped[str] = mapped_column(String(255))
    request_key: Mapped[str] = mapped_column(String(128))
    evidence_environment: Mapped[str] = mapped_column(String(32))
    validation_reference: Mapped[str] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(String(512))
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectorSourceReplacementReview(Base):
    __tablename__ = "collector_source_replacement_reviews"
    __table_args__ = (UniqueConstraint("request_id", name="uq_source_replacement_review_request"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(ForeignKey("collector_source_replacement_requests.id", ondelete="RESTRICT"), index=True)
    reviewer_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    reviewer_subject: Mapped[str] = mapped_column(String(255))
    acceptance_reference: Mapped[str] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectorSourceReplacementRevocation(Base):
    __tablename__ = "collector_source_replacement_revocations"
    __table_args__ = (UniqueConstraint("review_id", name="uq_source_replacement_revocation_review"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    review_id: Mapped[str] = mapped_column(ForeignKey("collector_source_replacement_reviews.id", ondelete="RESTRICT"), index=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    subject: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectorSourceRetirement(Base):
    """Permanent historical cutover fact; expiry/revocation never resurrect it."""
    __tablename__ = "collector_source_retirements"
    __table_args__ = (
        UniqueConstraint("old_source_id", name="uq_source_retirement_old_source"),
        UniqueConstraint("request_id", name="uq_source_retirement_request"),
        UniqueConstraint("tenant_id", "region_id", "execution_key", name="uq_source_retirement_execution_key"),
        CheckConstraint("old_source_id <> new_source_id", name="ck_source_retirement_distinct_sources"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(ForeignKey("collector_source_replacement_requests.id", ondelete="RESTRICT"))
    review_id: Mapped[str] = mapped_column(ForeignKey("collector_source_replacement_reviews.id", ondelete="RESTRICT"))
    old_source_id: Mapped[str] = mapped_column(ForeignKey("collector_condition_sources.id", ondelete="RESTRICT"), index=True)
    new_source_id: Mapped[str] = mapped_column(ForeignKey("collector_condition_sources.id", ondelete="RESTRICT"), index=True)
    old_watermark_receipt_id: Mapped[str] = mapped_column(ForeignKey("collector_condition_receipts.id", ondelete="RESTRICT"))
    new_receipt_id: Mapped[str] = mapped_column(ForeignKey("collector_condition_receipts.id", ondelete="RESTRICT"))
    superseded_alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=True)
    executor_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    executor_subject: Mapped[str] = mapped_column(String(255))
    executor_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    execution_key: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(String(512))
    old_state_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    new_state_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    result: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def _immutable_source_replacement(_mapper, _connection, _target):
    raise ValueError("Collector source replacement history is append-only")


for _replacement_model in (CollectorSourceReplacementRequest,
    CollectorSourceReplacementReview, CollectorSourceReplacementRevocation, CollectorSourceRetirement):
    event.listen(_replacement_model, "before_update", _immutable_source_replacement)
    event.listen(_replacement_model, "before_delete", _immutable_source_replacement)


class SituationRecoveryPolicyRequest(Base):
    """Reusable exact-source recovery criteria, not executable closure authority."""
    __tablename__ = "situation_recovery_policy_requests"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "request_key", name="uq_situation_recovery_policy_key"),
        CheckConstraint("expires_at > created_at", name="ck_situation_recovery_policy_lifetime"),
        CheckConstraint("min_quiet_samples BETWEEN 2 AND 128", name="ck_situation_recovery_policy_samples"),
        CheckConstraint("min_quiet_seconds BETWEEN 1 AND 86400", name="ck_situation_recovery_policy_duration"),
        CheckConstraint("max_sample_gap_seconds BETWEEN 1 AND 86400", name="ck_situation_recovery_policy_gap"),
        CheckConstraint("max_age_seconds BETWEEN 1 AND 86400", name="ck_situation_recovery_policy_age"),
        CheckConstraint("proof_version IN (1,2)", name="ck_situation_recovery_policy_proof_version"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_key: Mapped[str] = mapped_column(String(128))
    name: Mapped[str] = mapped_column(String(128))
    source_bindings: Mapped[list[dict[str, str]]] = mapped_column(JSON)
    proof_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    replacement_bindings: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list, server_default=text("'[]'"))
    evidence_environment: Mapped[str] = mapped_column(String(32))
    min_quiet_samples: Mapped[int] = mapped_column(Integer)
    min_quiet_seconds: Mapped[int] = mapped_column(Integer)
    max_sample_gap_seconds: Mapped[int] = mapped_column(Integer)
    max_age_seconds: Mapped[int] = mapped_column(Integer)
    author_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    author_subject: Mapped[str] = mapped_column(String(255))
    validation_reference: Mapped[str] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(String(512))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SituationRecoveryPolicyReview(Base):
    __tablename__ = "situation_recovery_policy_reviews"
    __table_args__ = (UniqueConstraint("request_id", name="uq_situation_recovery_policy_review"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(ForeignKey("situation_recovery_policy_requests.id", ondelete="RESTRICT"), index=True)
    reviewer_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    reviewer_subject: Mapped[str] = mapped_column(String(255))
    acceptance_reference: Mapped[str] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SituationRecoveryPolicyRevocation(Base):
    __tablename__ = "situation_recovery_policy_revocations"
    __table_args__ = (UniqueConstraint("review_id", name="uq_situation_recovery_policy_revocation"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    review_id: Mapped[str] = mapped_column(ForeignKey("situation_recovery_policy_reviews.id", ondelete="RESTRICT"), index=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    subject: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def _immutable_situation_recovery_policy(_mapper, _connection, _target):
    raise ValueError("Situation recovery policy history is append-only")


for _recovery_policy_model in (SituationRecoveryPolicyRequest, SituationRecoveryPolicyReview,
    SituationRecoveryPolicyRevocation):
    event.listen(_recovery_policy_model, "before_update", _immutable_situation_recovery_policy)
    event.listen(_recovery_policy_model, "before_delete", _immutable_situation_recovery_policy)


class SituationClosureGrant(Base):
    """Independent authority; a recovery-policy review alone is never a grant."""
    __tablename__ = "situation_closure_grants"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "request_key", name="uq_situation_closure_grant_key"),
        CheckConstraint("expires_at > created_at", name="ck_situation_closure_grant_lifetime"),
        CheckConstraint("max_lease_seconds BETWEEN 5 AND 120", name="ck_situation_closure_grant_lease"),
        CheckConstraint("proof_basis IN ('source_recovery','verified_remediation')", name="ck_situation_closure_grant_basis"),
        CheckConstraint("proof_version IN (1,2)", name="ck_situation_closure_grant_proof_version"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_key: Mapped[str] = mapped_column(String(128))
    policy_review_id: Mapped[str] = mapped_column(ForeignKey("situation_recovery_policy_reviews.id", ondelete="RESTRICT"), index=True)
    proof_basis: Mapped[str] = mapped_column(String(32))
    proof_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    remediation_version_id: Mapped[str | None] = mapped_column(ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=True)
    remediation_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    reviewer_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    reviewer_subject: Mapped[str] = mapped_column(String(255))
    acceptance_reference: Mapped[str] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(String(512))
    max_lease_seconds: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SituationClosureRevocation(Base):
    __tablename__ = "situation_closure_revocations"
    __table_args__ = (UniqueConstraint("grant_id", name="uq_situation_closure_revocation"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    grant_id: Mapped[str] = mapped_column(ForeignKey("situation_closure_grants.id", ondelete="RESTRICT"), index=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    subject: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SituationClosureRequest(Base):
    __tablename__ = "situation_closure_requests"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "situation_id", "request_key", name="uq_situation_closure_request_key"),
        CheckConstraint("lease_seconds BETWEEN 5 AND 120", name="ck_situation_closure_request_lease"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    situation_id: Mapped[str] = mapped_column(ForeignKey("situations.id", ondelete="RESTRICT"), index=True)
    grant_id: Mapped[str] = mapped_column(ForeignKey("situation_closure_grants.id", ondelete="RESTRICT"))
    request_key: Mapped[str] = mapped_column(String(128))
    owner_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    owner_subject: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(512))
    lease_seconds: Mapped[int] = mapped_column(Integer)
    membership_identity: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SituationClosureOwnership(Base):
    __tablename__ = "situation_closure_ownerships"
    __table_args__ = (
        UniqueConstraint("situation_id", name="uq_situation_closure_ownership"),
        CheckConstraint("epoch > 0", name="ck_situation_closure_ownership_epoch"),
        CheckConstraint("state IN ('claimed','released','committed')", name="ck_situation_closure_ownership_state"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    situation_id: Mapped[str] = mapped_column(ForeignKey("situations.id", ondelete="RESTRICT"), index=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("situation_closure_requests.id", ondelete="RESTRICT"))
    epoch: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(16))
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SituationClosureAttempt(Base):
    __tablename__ = "situation_closure_attempts"
    __table_args__ = (
        UniqueConstraint("ownership_id", "epoch", name="uq_situation_closure_attempt_epoch"),
        CheckConstraint("epoch > 0 AND expires_at > created_at", name="ck_situation_closure_attempt_lifetime"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(ForeignKey("situation_closure_requests.id", ondelete="RESTRICT"), index=True)
    ownership_id: Mapped[str] = mapped_column(ForeignKey("situation_closure_ownerships.id", ondelete="RESTRICT"))
    epoch: Mapped[int] = mapped_column(Integer)
    token_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SituationClosureReceipt(Base):
    __tablename__ = "situation_closure_receipts"
    __table_args__ = (
        UniqueConstraint("request_id", name="uq_situation_closure_receipt_request"),
        UniqueConstraint("attempt_id", name="uq_situation_closure_receipt_attempt"),
        UniqueConstraint("ownership_id", "epoch", name="uq_situation_closure_receipt_epoch"),
        UniqueConstraint("event_id", name="uq_situation_closure_receipt_event"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    situation_id: Mapped[str] = mapped_column(ForeignKey("situations.id", ondelete="RESTRICT"), index=True)
    grant_id: Mapped[str] = mapped_column(ForeignKey("situation_closure_grants.id", ondelete="RESTRICT"))
    request_id: Mapped[str] = mapped_column(ForeignKey("situation_closure_requests.id", ondelete="RESTRICT"))
    attempt_id: Mapped[str] = mapped_column(ForeignKey("situation_closure_attempts.id", ondelete="RESTRICT"))
    ownership_id: Mapped[str] = mapped_column(ForeignKey("situation_closure_ownerships.id", ondelete="RESTRICT"))
    epoch: Mapped[int] = mapped_column(Integer)
    event_id: Mapped[str] = mapped_column(ForeignKey("situation_events.id", ondelete="RESTRICT"))
    event_sequence: Mapped[int] = mapped_column(Integer)
    proof: Mapped[dict[str, Any]] = mapped_column(JSON)
    committed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def _immutable_situation_closure(_mapper, _connection, _target):
    raise ValueError("Situation closure history is append-only")


for _closure_model in (SituationClosureGrant, SituationClosureRevocation, SituationClosureRequest,
    SituationClosureAttempt, SituationClosureReceipt):
    event.listen(_closure_model, "before_update", _immutable_situation_closure)
    event.listen(_closure_model, "before_delete", _immutable_situation_closure)


class Situation(Base):
    __tablename__ = "situations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved')",
            name="ck_situation_status",
        ),
        CheckConstraint("alert_count > 0", name="ck_situation_alert_count"),
        CheckConstraint(
            "active_alert_count >= 0 AND active_alert_count <= alert_count",
            name="ck_situation_active_alert_count",
        ),
        CheckConstraint(
            "occurrence_count >= alert_count",
            name="ck_situation_occurrence_count",
        ),
        CheckConstraint(
            "priority_score >= 0",
            name="ck_situation_priority_score",
        ),
        CheckConstraint(
            "event_sequence >= 0",
            name="ck_situation_event_sequence",
        ),
        Index(
            "uq_situation_active_correlation_key",
            "correlation_key",
            unique=True,
            postgresql_where=text("status != 'resolved'"),
            sqlite_where=text("status != 'resolved'"),
        ),
        Index(
            "ix_situation_queue",
            "status",
            "priority_score",
            "last_seen",
        ),
        Index(
            "ix_situation_primary_entity",
            "primary_entity_type",
            "primary_entity_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    correlation_key: Mapped[str] = mapped_column(String(64))
    correlation_version: Mapped[str] = mapped_column(
        String(64), default="same_entity/v1"
    )
    status: Mapped[str] = mapped_column(String(16), default="open")
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, native_enum=False, length=16)
    )
    priority_score: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(Text, default="")
    primary_entity_type: Mapped[str] = mapped_column(String(64))
    primary_entity_id: Mapped[str] = mapped_column(String(255))
    alert_count: Mapped[int] = mapped_column(Integer, default=1)
    active_alert_count: Mapped[int] = mapped_column(Integer, default=1)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    correlation_confidence: Mapped[float] = mapped_column(Float, default=1.0)
    event_sequence: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    acknowledged_by: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_by: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    alert_memberships: Mapped[list[SituationAlert]] = relationship(
        back_populates="situation",
        cascade="all, delete-orphan",
    )
    events: Mapped[list[SituationEvent]] = relationship(
        back_populates="situation",
        cascade="all, delete-orphan",
        order_by="SituationEvent.sequence",
    )
    hypotheses: Mapped[list[SituationHypothesis]] = relationship(
        back_populates="situation",
        cascade="all, delete-orphan",
    )
    impact_assessments: Mapped[list[SituationImpactAssessment]] = relationship(
        back_populates="situation",
        cascade="all, delete-orphan",
    )


class SituationAlert(Base):
    __tablename__ = "situation_alerts"
    __table_args__ = (
        UniqueConstraint("alert_id", name="uq_situation_alert_alert"),
        CheckConstraint(
            "correlation_confidence >= 0 AND correlation_confidence <= 1",
            name="ck_situation_alert_correlation_confidence",
        ),
        Index(
            "ix_situation_alert_situation_added",
            "situation_id",
            "added_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    situation_id: Mapped[str] = mapped_column(
        ForeignKey("situations.id", ondelete="CASCADE"), index=True
    )
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(32), default="symptom")
    correlation_reason: Mapped[str] = mapped_column(
        String(64), default="same_entity"
    )
    correlation_confidence: Mapped[float] = mapped_column(Float, default=1.0)
    correlation_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )
    severity_snapshot: Mapped[str] = mapped_column(String(16))
    status_snapshot: Mapped[str] = mapped_column(String(16))
    occurrence_count_snapshot: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    situation: Mapped[Situation] = relationship(back_populates="alert_memberships")
    alert: Mapped[Alert] = relationship(back_populates="situation_memberships")


class SituationEvent(Base):
    __tablename__ = "situation_events"
    __table_args__ = (
        UniqueConstraint(
            "situation_id",
            "sequence",
            name="uq_situation_event_sequence",
        ),
        CheckConstraint("sequence > 0", name="ck_situation_event_sequence"),
        Index(
            "ix_situation_event_situation_created",
            "situation_id",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    situation_id: Mapped[str] = mapped_column(
        ForeignKey("situations.id", ondelete="CASCADE"), index=True
    )
    sequence: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(255))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    situation: Mapped[Situation] = relationship(back_populates="events")


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "kind", "name",
            name="uq_artifact_namespace_kind_name",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[ArtifactKind] = mapped_column(
        Enum(ArtifactKind, native_enum=False, length=32), index=True
    )
    description: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(255), index=True)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    versions: Mapped[list[ArtifactVersion]] = relationship(
        back_populates="artifact",
        cascade="all, delete-orphan",
        order_by="ArtifactVersion.version",
    )


class ArtifactVersion(Base):
    __tablename__ = "artifact_versions"
    __table_args__ = (
        UniqueConstraint("artifact_id", "version", name="uq_artifact_version"),
        CheckConstraint("version > 0", name="ck_artifact_version_positive"),
        Index("ix_artifact_version_status_created", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[int] = mapped_column(Integer)
    status: Mapped[ArtifactVersionStatus] = mapped_column(
        Enum(ArtifactVersionStatus, native_enum=False, length=16),
        default=ArtifactVersionStatus.DRAFT,
        index=True,
    )
    definition: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    implementation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tests: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    validation_report: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    validated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    validated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    published_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    artifact: Mapped[Artifact] = relationship(back_populates="versions")
    collector_definition: Mapped[CollectorDefinition | None] = relationship(
        back_populates="artifact_version",
        cascade="all, delete-orphan",
        uselist=False,
    )
    deployments: Mapped[list[CollectorDeployment]] = relationship(
        back_populates="artifact_version"
    )


class ManagedExtensionInstallation(Base):
    __tablename__ = "managed_extension_installations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "artifact_id", name="uq_managed_extension_artifact"),
        CheckConstraint("revision > 0", name="ck_managed_extension_revision"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id", ondelete="RESTRICT"), index=True)
    active_version_id: Mapped[str] = mapped_column(ForeignKey("artifact_versions.id", ondelete="RESTRICT"))
    previous_version_id: Mapped[str | None] = mapped_column(ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    bindings: Mapped[list[dict]] = mapped_column(JSON, default=list)
    previous_bindings: Mapped[list[dict]] = mapped_column(JSON, default=list)
    # Null preserves the explicit, target-bound authority of older installations.
    target_policy: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    previous_target_policy: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    tool_ids: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    last_health_status: Mapped[str] = mapped_column(String(32), default="discovered")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ManagedExtensionTest(Base):
    __tablename__ = "managed_extension_tests"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "request_key", name="uq_managed_extension_test_request"),
        CheckConstraint("status IN ('running','succeeded','failed')", name="ck_managed_extension_test_status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_key: Mapped[str] = mapped_column(String(36))
    artifact_version_id: Mapped[str] = mapped_column(ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True)
    version_hash: Mapped[str] = mapped_column(String(64))
    tool_name: Mapped[str] = mapped_column(String(64))
    binding: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="running")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExtensionConfigurationBackup(Base):
    __tablename__ = "extension_configuration_backups"
    __table_args__ = (
        CheckConstraint("byte_count BETWEEN 1 AND 1000000", name="ck_extension_backup_size"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_version_id: Mapped[str] = mapped_column(ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"), index=True)
    connection_id: Mapped[str] = mapped_column(ForeignKey("device_connections.id", ondelete="RESTRICT"), index=True)
    tool_name: Mapped[str] = mapped_column(String(64))
    sha256: Mapped[str] = mapped_column(String(64))
    byte_count: Mapped[int] = mapped_column(Integer)
    encrypted_body: Mapped[bytes] = mapped_column(LargeBinary)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CapabilityQualityPolicy(Base):
    __tablename__ = "capability_quality_policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "artifact_version_id", name="uq_quality_policy_namespace_version"),
        CheckConstraint("revision > 0", name="ck_quality_policy_revision"),
        CheckConstraint("window_minutes BETWEEN 5 AND 10080", name="ck_quality_policy_window"),
        CheckConstraint("min_samples BETWEEN 1 AND 2000", name="ck_quality_policy_samples"),
        CheckConstraint("max_failure_ppm BETWEEN 0 AND 1000000", name="ck_quality_policy_failure_ppm"),
        CheckConstraint("max_p95_ms BETWEEN 1 AND 3600000", name="ck_quality_policy_latency"),
        CheckConstraint("max_sample_age_seconds BETWEEN 60 AND 604800", name="ck_quality_policy_freshness"),
        CheckConstraint("evaluation_interval_seconds BETWEEN 60 AND 86400", name="ck_quality_policy_interval"),
        CheckConstraint("min_records_per_run BETWEEN 0 AND 1000000", name="ck_quality_policy_records"),
        CheckConstraint("evidence_mode IN ('execution_health', 'remediation_outcome')", name="ck_quality_policy_mode"),
        Index("ix_quality_policy_due", "tenant_id", "region_id", "next_evaluation_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_version_id: Mapped[str] = mapped_column(ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    evidence_mode: Mapped[str] = mapped_column(String(32), default="execution_health", server_default="execution_health")
    window_minutes: Mapped[int] = mapped_column(Integer, default=60)
    min_samples: Mapped[int] = mapped_column(Integer, default=5)
    max_failure_ppm: Mapped[int] = mapped_column(Integer, default=100000)
    max_p95_ms: Mapped[int] = mapped_column(Integer, default=30000)
    max_sample_age_seconds: Mapped[int] = mapped_column(Integer, default=900)
    evaluation_interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    min_records_per_run: Mapped[int] = mapped_column(Integer, default=0)
    alert_on_degradation: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    last_assessment_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    next_evaluation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255))
    updated_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class CapabilityQualityAssessment(Base):
    __tablename__ = "capability_quality_assessments"
    __table_args__ = (
        CheckConstraint("policy_revision > 0", name="ck_quality_assessment_revision"),
        CheckConstraint("status IN ('healthy', 'degraded', 'insufficient_data', 'disabled')", name="ck_quality_assessment_status"),
        CheckConstraint("sample_count BETWEEN 0 AND 2000 AND failed_count BETWEEN 0 AND sample_count", name="ck_quality_assessment_counts"),
        CheckConstraint("failure_ppm IS NULL OR failure_ppm BETWEEN 0 AND 1000000", name="ck_quality_assessment_failure_ppm"),
        CheckConstraint("evidence_scope IN ('execution_health_not_correctness', 'remediation_outcome_not_authority')", name="ck_quality_assessment_scope"),
        Index("ix_quality_assessment_policy_time", "policy_id", "evaluated_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    policy_id: Mapped[str] = mapped_column(ForeignKey("capability_quality_policies.id", ondelete="RESTRICT"), index=True)
    artifact_version_id: Mapped[str] = mapped_column(ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True)
    policy_revision: Mapped[int] = mapped_column(Integer)
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    evidence_scope: Mapped[str] = mapped_column(String(64), default="execution_health_not_correctness", server_default="execution_health_not_correctness")
    policy_sha256: Mapped[str] = mapped_column(String(64))
    content_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    sample_count: Mapped[int] = mapped_column(Integer)
    failed_count: Mapped[int] = mapped_column(Integer)
    failure_ppm: Mapped[int | None] = mapped_column(Integer, nullable=True)
    p95_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latest_sample_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scan_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence_manifest: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    evidence_sha256: Mapped[str] = mapped_column(String(64))
    assessment_sha256: Mapped[str] = mapped_column(String(64))
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    evaluated_by: Mapped[str] = mapped_column(String(255))


class SNMPExporterAttestation(Base):
    __tablename__ = "snmp_exporter_attestations"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "deployable_version_id",
            name="uq_snmp_attestation_namespace_deployable",
        ),
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "digest_sha256",
            name="uq_snmp_attestation_namespace_digest",
        ),
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "nonce",
            name="uq_snmp_attestation_namespace_nonce",
        ),
        Index(
            "ix_snmp_exporter_attestation_proposal",
            "proposal_version_id",
            "verified_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    proposal_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    deployable_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"), index=True
    )
    key_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    digest_sha256: Mapped[str] = mapped_column(String(64))
    signature_sha256: Mapped[str] = mapped_column(String(64))
    nonce: Mapped[str] = mapped_column(String(128))
    statement: Mapped[dict[str, Any]] = mapped_column(JSON)
    verified_by: Mapped[str] = mapped_column(String(255))
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ArtifactTrustKey(Base):
    __tablename__ = "artifact_trust_keys"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "name", name="uq_trust_key_namespace_name"),
        UniqueConstraint(
            "tenant_id", "region_id", "fingerprint_sha256",
            name="uq_trust_key_namespace_fingerprint",
        ),
        Index("ix_artifact_trust_keys_name", "name"),
        Index(
            "ix_artifact_trust_keys_fingerprint_sha256",
            "fingerprint_sha256",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    algorithm: Mapped[str] = mapped_column(String(32), default="ed25519")
    public_key_pem: Mapped[str] = mapped_column(Text)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    purposes: Mapped[list[str]] = mapped_column(
        JSON,
        default=lambda: [
            "artifact_bundle",
            "capability_pack",
            "capability_revocation",
            "remote_catalog",
            "trust_bundle",
        ],
    )
    trust_source: Mapped[str] = mapped_column(
        String(32),
        default="local",
        index=True,
    )
    trust_domain_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True,
    )
    managed_bundle_sequence: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    valid_from: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class OrganizationTrustDomain(Base):
    __tablename__ = "organization_trust_domains"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "organization_id",
            name="uq_trust_domain_namespace_organization",
        ),
        UniqueConstraint("tenant_id", "region_id", "name", name="uq_trust_domain_namespace_name"),
        CheckConstraint(
            "latest_sequence >= 0",
            name="ck_organization_trust_domain_sequence_nonnegative",
        ),
        CheckConstraint(
            "max_bundle_lifetime_days BETWEEN 1 AND 366",
            name="ck_organization_trust_bundle_lifetime",
        ),
        CheckConstraint(
            "max_key_lifetime_days BETWEEN 1 AND 3650",
            name="ck_organization_trust_key_lifetime",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    organization_id: Mapped[str] = mapped_column(String(255), index=True)
    authority_trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    authority_key_fingerprint_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    allowed_purposes: Mapped[list[str]] = mapped_column(JSON, default=list)
    max_bundle_lifetime_days: Mapped[int] = mapped_column(Integer, default=30)
    max_key_lifetime_days: Mapped[int] = mapped_column(Integer, default=730)
    latest_sequence: Mapped[int] = mapped_column(Integer, default=0)
    latest_bundle_digest_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
    )


class OrganizationTrustDomainCreationReceipt(Base):
    __tablename__ = "organization_trust_domain_creation_receipts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "idempotency_key_sha256",
            name="uq_trust_domain_creation_namespace_key",
        ),
        UniqueConstraint(
            "trust_domain_id", name="uq_trust_domain_creation_receipt_domain",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    trust_domain_id: Mapped[str] = mapped_column(
        ForeignKey("organization_trust_domains.id", ondelete="RESTRICT"),
        index=True,
    )
    idempotency_key_sha256: Mapped[str] = mapped_column(String(64))
    request_digest_sha256: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OrganizationTrustBundleImport(Base):
    __tablename__ = "organization_trust_bundle_imports"
    __table_args__ = (
        UniqueConstraint(
            "trust_domain_id",
            "sequence",
            name="uq_organization_trust_bundle_sequence",
        ),
        UniqueConstraint(
            "trust_domain_id",
            "bundle_digest_sha256",
            name="uq_organization_trust_bundle_digest",
        ),
        CheckConstraint(
            "sequence > 0",
            name="ck_organization_trust_bundle_sequence_positive",
        ),
        CheckConstraint(
            "key_count > 0",
            name="ck_organization_trust_bundle_key_count_positive",
        ),
        Index(
            "ix_organization_trust_bundle_imported",
            "trust_domain_id",
            "imported_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    trust_domain_id: Mapped[str] = mapped_column(
        ForeignKey("organization_trust_domains.id", ondelete="RESTRICT"),
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer)
    bundle_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    authority_key_fingerprint_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    signature_sha256: Mapped[str] = mapped_column(String(64))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    key_count: Mapped[int] = mapped_column(Integer)
    active_key_count: Mapped[int] = mapped_column(Integer)
    revoked_key_count: Mapped[int] = mapped_column(Integer)
    signed_bundle_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(Text)
    imported_by: Mapped[str] = mapped_column(String(255))
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class OrganizationTrustRootRotation(Base):
    __tablename__ = "organization_trust_root_rotations"
    __table_args__ = (
        UniqueConstraint(
            "trust_domain_id",
            "statement_digest_sha256",
            name="uq_organization_trust_root_rotation_statement",
        ),
        CheckConstraint(
            "bundle_sequence >= 0",
            name="ck_organization_trust_root_rotation_sequence_nonnegative",
        ),
        Index(
            "ix_organization_trust_root_rotation_time",
            "trust_domain_id",
            "rotated_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    trust_domain_id: Mapped[str] = mapped_column(
        ForeignKey("organization_trust_domains.id", ondelete="RESTRICT"),
        index=True,
    )
    from_trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    to_trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    from_key_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    to_key_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    bundle_sequence: Mapped[int] = mapped_column(Integer)
    bundle_digest_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    statement_digest_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    current_signature_sha256: Mapped[str] = mapped_column(String(64))
    next_signature_sha256: Mapped[str] = mapped_column(String(64))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
    rotated_by: Mapped[str] = mapped_column(String(255))
    rotated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class TrustRecoverySigningProvider(Base):
    __tablename__ = "trust_recovery_signing_providers"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_trust_recovery_signing_provider_name",
        ),
        CheckConstraint(
            "provider_kind IN ('hsm_gateway', 'kms_gateway')",
            name="ck_trust_recovery_signing_provider_kind",
        ),
        CheckConstraint(
            "request_timeout_seconds BETWEEN 1 AND 30",
            name="ck_trust_recovery_signing_provider_timeout",
        ),
        CheckConstraint(
            "max_response_bytes BETWEEN 1024 AND 65536",
            name="ck_trust_recovery_signing_provider_response_limit",
        ),
        CheckConstraint(
            "tls_mode IN ('server_auth', 'mutual_tls')",
            name="ck_trust_recovery_signing_provider_tls_mode",
        ),
        CheckConstraint(
            "(tls_mode = 'server_auth' "
            "AND tls_client_certificate_ref IS NULL "
            "AND tls_client_private_key_ref IS NULL "
            "AND tls_client_private_key_password_ref IS NULL) OR "
            "(tls_mode = 'mutual_tls' "
            "AND tls_client_certificate_ref IS NOT NULL "
            "AND tls_client_private_key_ref IS NOT NULL)",
            name="ck_trust_recovery_signing_provider_tls_binding",
        ),
        CheckConstraint(
            "tls_revision > 0",
            name="ck_trust_recovery_signing_provider_tls_revision",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    provider_kind: Mapped[str] = mapped_column(String(32), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    signing_key_ref: Mapped[str] = mapped_column(String(1024))
    trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    key_fingerprint_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    tls_mode: Mapped[str] = mapped_column(
        String(16),
        default="server_auth",
        index=True,
    )
    tls_ca_certificate_ref: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    tls_client_certificate_ref: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    tls_client_private_key_ref: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    tls_client_private_key_password_ref: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    tls_revision: Mapped[int] = mapped_column(Integer, default=1)
    request_timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    max_response_bytes: Mapped[int] = mapped_column(Integer, default=65536)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
    )


class TrustRecoverySigningEvent(Base):
    __tablename__ = "trust_recovery_signing_events"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "request_digest_sha256",
            name="uq_trust_recovery_signing_event_request",
        ),
        CheckConstraint(
            "document_type IN ('recovery_policy', 'root_reanchor')",
            name="ck_trust_recovery_signing_event_document_type",
        ),
        Index(
            "ix_trust_recovery_signing_event_time",
            "provider_id",
            "requested_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider_id: Mapped[str] = mapped_column(
        ForeignKey("trust_recovery_signing_providers.id", ondelete="RESTRICT"),
        index=True,
    )
    document_type: Mapped[str] = mapped_column(String(32), index=True)
    signed_format_version: Mapped[str] = mapped_column(String(128))
    statement_digest_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    request_digest_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    key_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    signature_sha256: Mapped[str] = mapped_column(String(64))
    signature_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    response_digest_sha256: Mapped[str] = mapped_column(String(64))
    tls_evidence: Mapped[dict[str, Any]] = mapped_column(JSON)
    requested_by: Mapped[str] = mapped_column(String(255))
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class OrganizationTrustRecoveryPolicy(Base):
    __tablename__ = "organization_trust_recovery_policies"
    __table_args__ = (
        UniqueConstraint(
            "trust_domain_id",
            "version",
            name="uq_organization_trust_recovery_policy_version",
        ),
        UniqueConstraint(
            "statement_digest_sha256",
            name="uq_organization_trust_recovery_policy_statement",
        ),
        CheckConstraint(
            "version > 0",
            name="ck_organization_trust_recovery_policy_version_positive",
        ),
        CheckConstraint(
            "required_approvals BETWEEN 2 AND 8",
            name="ck_organization_trust_recovery_policy_quorum",
        ),
        CheckConstraint(
            "delay_hours BETWEEN 1 AND 72",
            name="ck_organization_trust_recovery_policy_delay",
        ),
        Index(
            "ix_organization_trust_recovery_policy_active",
            "trust_domain_id",
            "active",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    trust_domain_id: Mapped[str] = mapped_column(
        ForeignKey("organization_trust_domains.id", ondelete="RESTRICT"),
        index=True,
    )
    version: Mapped[int] = mapped_column(Integer)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    authority_trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    authority_key_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    trustee_key_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    trustee_key_fingerprints_sha256: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
    )
    required_approvals: Mapped[int] = mapped_column(Integer)
    delay_hours: Mapped[int] = mapped_column(Integer)
    bundle_sequence: Mapped[int] = mapped_column(Integer)
    bundle_digest_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    statement_digest_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    authority_signature_sha256: Mapped[str] = mapped_column(String(64))
    signed_policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    transparency_sequence: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    superseded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class OrganizationTrustRootReanchor(Base):
    __tablename__ = "organization_trust_root_reanchors"
    __table_args__ = (
        UniqueConstraint(
            "statement_digest_sha256",
            name="uq_organization_trust_root_reanchor_statement",
        ),
        UniqueConstraint(
            "trust_domain_id",
            "ceremony_id",
            name="uq_organization_trust_root_reanchor_ceremony",
        ),
        CheckConstraint(
            "status IN ('pending', 'executed', 'cancelled')",
            name="ck_organization_trust_root_reanchor_status",
        ),
        CheckConstraint(
            "trustee_approval_count BETWEEN 2 AND 8",
            name="ck_organization_trust_root_reanchor_approvals",
        ),
        Index(
            "ix_organization_trust_root_reanchor_status_time",
            "status",
            "proposed_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    trust_domain_id: Mapped[str] = mapped_column(
        ForeignKey("organization_trust_domains.id", ondelete="RESTRICT"),
        index=True,
    )
    recovery_policy_id: Mapped[str] = mapped_column(
        ForeignKey(
            "organization_trust_recovery_policies.id",
            ondelete="RESTRICT",
        ),
        index=True,
    )
    from_trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    to_trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    ceremony_id: Mapped[str] = mapped_column(String(36), index=True)
    from_key_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    to_key_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    bundle_sequence: Mapped[int] = mapped_column(Integer)
    bundle_digest_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    witness_checkpoint_offer_id: Mapped[str] = mapped_column(
        ForeignKey(
            "capability_transparency_checkpoint_offers.id",
            ondelete="RESTRICT",
        ),
        index=True,
    )
    witness_log_id: Mapped[str] = mapped_column(String(36))
    witness_epoch: Mapped[int] = mapped_column(Integer)
    witness_sequence: Mapped[int] = mapped_column(Integer)
    witness_head_digest_sha256: Mapped[str] = mapped_column(String(64))
    statement_digest_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    next_signature_sha256: Mapped[str] = mapped_column(String(64))
    trustee_approval_count: Mapped[int] = mapped_column(Integer)
    trustee_signature_evidence: Mapped[list[dict[str, str]]] = mapped_column(
        JSON,
        default=list,
    )
    signed_reanchor_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    execute_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    proposal_transparency_sequence: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    execution_checkpoint_offer_id: Mapped[str | None] = mapped_column(
        ForeignKey(
            "capability_transparency_checkpoint_offers.id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    execution_transparency_sequence: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    reason: Mapped[str] = mapped_column(Text)
    proposed_by: Mapped[str] = mapped_column(String(255))
    proposed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    execution_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    cancelled_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class ArtifactSignatureVerification(Base):
    __tablename__ = "artifact_signature_verifications"
    __table_args__ = (
        UniqueConstraint(
            "artifact_version_id",
            name="uq_artifact_signature_verification_version",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="CASCADE"), index=True
    )
    trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"), index=True
    )
    algorithm: Mapped[str] = mapped_column(String(32))
    key_fingerprint_sha256: Mapped[str] = mapped_column(String(64), index=True)
    bundle_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    signature_sha256: Mapped[str] = mapped_column(String(64))
    verified_by: Mapped[str] = mapped_column(String(255))
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class CapabilityPackInstallation(Base):
    __tablename__ = "capability_pack_installations"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "pack_name", "pack_version",
            name="uq_capability_pack_namespace_name_version",
        ),
        UniqueConstraint(
            "tenant_id", "region_id", "pack_digest_sha256",
            name="uq_capability_pack_namespace_digest",
        ),
        Index(
            "ix_capability_pack_installed_at",
            "installed_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    pack_name: Mapped[str] = mapped_column(String(255), index=True)
    pack_version: Mapped[str] = mapped_column(String(64))
    platform_api: Mapped[str] = mapped_column(String(64))
    pack_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"), index=True
    )
    key_fingerprint_sha256: Mapped[str] = mapped_column(String(64), index=True)
    signature_sha256: Mapped[str] = mapped_column(String(64))
    operation: Mapped[str] = mapped_column(String(32), default="install")
    lifecycle_status: Mapped[str] = mapped_column(
        String(32),
        default="installed",
        index=True,
    )
    predecessor_installation_id: Mapped[str | None] = mapped_column(
        ForeignKey("capability_pack_installations.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    dependency_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        default=list,
    )
    distribution_channel: Mapped[str] = mapped_column(
        String(32),
        default="upload",
        index=True,
    )
    distribution_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
    )
    signer_rotation_snapshot: Mapped[dict[str, str]] = mapped_column(
        JSON,
        default=dict,
    )
    reason: Mapped[str] = mapped_column(Text)
    installed_by: Mapped[str] = mapped_column(String(255))
    installed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    uninstall_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    uninstalled_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    uninstalled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    uninstall_summary: Mapped[dict[str, int]] = mapped_column(
        JSON,
        default=dict,
    )

    artifacts: Mapped[list[CapabilityPackInstalledArtifact]] = relationship(
        back_populates="installation",
        cascade="all, delete-orphan",
        order_by="CapabilityPackInstalledArtifact.source_name",
    )


class CapabilityPackInstalledArtifact(Base):
    __tablename__ = "capability_pack_installed_artifacts"
    __table_args__ = (
        UniqueConstraint(
            "installation_id",
            "artifact_version_id",
            name="uq_capability_pack_installed_version",
        ),
        Index(
            "ix_capability_pack_artifact_version",
            "artifact_version_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(
        ForeignKey("capability_pack_installations.id", ondelete="CASCADE"),
        index=True,
    )
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"), index=True
    )
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT")
    )
    source_name: Mapped[str] = mapped_column(String(255))
    source_kind: Mapped[str] = mapped_column(String(32))
    source_content_hash: Mapped[str] = mapped_column(String(64))
    source_bundle_digest_sha256: Mapped[str] = mapped_column(String(64))
    install_action: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    installation: Mapped[CapabilityPackInstallation] = relationship(
        back_populates="artifacts"
    )


class CapabilityPromotionPolicy(Base):
    __tablename__ = "capability_promotion_policy"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", name="uq_promotion_policy_namespace"),
        UniqueConstraint(
            "tenant_id", "region_id",
            "local_environment_id",
            name="uq_promotion_policy_namespace_environment",
        ),
        CheckConstraint(
            "local_stage IN ('development', 'test', 'staging', 'production')",
            name="ck_capability_promotion_local_stage",
        ),
        CheckConstraint(
            "required_source_stage IN "
            "('development', 'test', 'staging', 'production')",
            name="ck_capability_promotion_required_source_stage",
        ),
        CheckConstraint(
            "max_attestation_age_hours BETWEEN 1 AND 168",
            name="ck_capability_promotion_attestation_age",
        ),
        CheckConstraint(
            "publication_mode IN ('disabled', 'manual')",
            name="ck_capability_promotion_publication_mode",
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    local_environment_id: Mapped[str] = mapped_column(String(255))
    local_stage: Mapped[str] = mapped_column(String(32))
    required_source_stage: Mapped[str] = mapped_column(String(32))
    max_attestation_age_hours: Mapped[int] = mapped_column(Integer, default=24)
    publication_mode: Mapped[str] = mapped_column(
        String(32),
        default="disabled",
    )
    require_distinct_publisher: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )
    updated_by: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
    )


class CapabilityPromotionSourceWitnessPolicy(Base):
    __tablename__ = "capability_promotion_source_witness_policy"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", name="uq_promotion_source_witness_policy_namespace"),
        CheckConstraint("required_quorum BETWEEN 0 AND 16", name="ck_promotion_source_witness_quorum"),
        CheckConstraint("max_attestation_age_hours BETWEEN 1 AND 720", name="ck_promotion_source_witness_age"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    required_quorum: Mapped[int] = mapped_column(Integer, default=0)
    witness_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    max_attestation_age_hours: Mapped[int] = mapped_column(Integer, default=168)
    updated_by: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CapabilityPromotionSourceCheckpointBinding(Base):
    __tablename__ = "capability_promotion_source_checkpoint_bindings"
    __table_args__ = (CheckConstraint("epoch > 0", name="ck_promotion_source_checkpoint_epoch"),)
    source_id: Mapped[str] = mapped_column(ForeignKey("capability_promotion_sources.id", ondelete="RESTRICT"), primary_key=True)
    log_id: Mapped[str] = mapped_column(String(36))
    epoch: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    updated_by: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CapabilityPromotionSourceWitnessDecision(Base):
    __tablename__ = "capability_promotion_source_witness_decisions"
    __table_args__ = (UniqueConstraint("receipt_id", name="uq_promotion_source_witness_decision_receipt"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    receipt_id: Mapped[str] = mapped_column(ForeignKey("capability_promotion_receipts.id", ondelete="RESTRICT"), index=True)
    checkpoint_statement_digest_sha256: Mapped[str] = mapped_column(String(64))
    evidence_digest_sha256: Mapped[str] = mapped_column(String(64))
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    witness_evidence: Mapped[list[dict[str, str]]] = mapped_column(JSON)
    accepted_by: Mapped[str] = mapped_column(String(255))
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PromotionRecoveryPolicy(Base):
    __tablename__ = "promotion_recovery_policies"
    __table_args__ = (
        UniqueConstraint("source_id", "version", name="uq_promotion_recovery_policy_version"),
        UniqueConstraint("source_id", "statement_digest_sha256", name="uq_promotion_recovery_policy_statement"),
        CheckConstraint("version > 0", name="ck_promotion_recovery_policy_version"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("capability_promotion_sources.id", ondelete="RESTRICT"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    trustee_key_ids: Mapped[list[str]] = mapped_column(JSON)
    witness_ids: Mapped[list[str]] = mapped_column(JSON)
    authority_public_key_pem: Mapped[str] = mapped_column(Text)
    statement_digest_sha256: Mapped[str] = mapped_column(String(64))
    authority_signature_sha256: Mapped[str] = mapped_column(String(64))
    signed_policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    transparency_sequence: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    accepted_by: Mapped[str] = mapped_column(String(255))
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PromotionKeyRecovery(Base):
    __tablename__ = "promotion_key_recoveries"
    __table_args__ = (
        UniqueConstraint("source_id", "statement_digest_sha256", name="uq_promotion_key_recovery_statement"),
        UniqueConstraint("source_id", "ceremony_uuid", name="uq_promotion_key_recovery_ceremony"),
        CheckConstraint("execute_after > proposed_at", name="ck_promotion_key_recovery_delay"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("capability_promotion_sources.id", ondelete="RESTRICT"), index=True)
    recovery_policy_id: Mapped[str] = mapped_column(ForeignKey("promotion_recovery_policies.id", ondelete="RESTRICT"))
    to_trust_key_id: Mapped[str] = mapped_column(ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"))
    ceremony_uuid: Mapped[str] = mapped_column(String(36))
    statement_digest_sha256: Mapped[str] = mapped_column(String(64))
    signed_recovery_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    checkpoint_evidence_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    verified_evidence: Mapped[dict[str, Any]] = mapped_column(JSON)
    execute_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    proposal_transparency_sequence: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    proposed_by: Mapped[str] = mapped_column(String(255))
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PromotionRecoveryEvent(Base):
    __tablename__ = "promotion_recovery_events"
    __table_args__ = (
        CheckConstraint("event_type IN ('policy_retired', 'executed', 'cancelled', 'restored')", name="ck_promotion_recovery_event_type"),
        CheckConstraint("(event_type = 'policy_retired' AND ceremony_id IS NULL) OR (event_type <> 'policy_retired' AND ceremony_id IS NOT NULL)", name="ck_promotion_recovery_event_subject"),
        UniqueConstraint("ceremony_id", "event_type", name="uq_promotion_recovery_ceremony_event"),
        Index("uq_promotion_recovery_terminal", "ceremony_id", unique=True,
            postgresql_where=text("event_type IN ('executed', 'cancelled')"), sqlite_where=text("event_type IN ('executed', 'cancelled')")),
        Index("uq_promotion_recovery_retired_policy", "recovery_policy_id", unique=True,
            postgresql_where=text("event_type = 'policy_retired'"), sqlite_where=text("event_type = 'policy_retired'")),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("capability_promotion_sources.id", ondelete="RESTRICT"), index=True)
    recovery_policy_id: Mapped[str] = mapped_column(ForeignKey("promotion_recovery_policies.id", ondelete="RESTRICT"))
    ceremony_id: Mapped[str | None] = mapped_column(ForeignKey("promotion_key_recoveries.id", ondelete="RESTRICT"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(32))
    checkpoint_evidence_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    verified_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    transparency_sequence: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(255))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CapabilityPromotionSource(Base):
    __tablename__ = "capability_promotion_sources"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id",
            "name",
            name="uq_promotion_source_namespace_name",
        ),
        UniqueConstraint(
            "tenant_id", "region_id",
            "environment_id",
            name="uq_promotion_source_namespace_environment",
        ),
        CheckConstraint(
            "source_stage IN "
            "('development', 'test', 'staging', 'production')",
            name="ck_capability_promotion_source_stage",
        ),
        CheckConstraint(
            "latest_sequence >= 0",
            name="ck_capability_promotion_source_sequence_nonnegative",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    organization_id: Mapped[str] = mapped_column(String(255), index=True)
    environment_id: Mapped[str] = mapped_column(String(255), index=True)
    source_stage: Mapped[str] = mapped_column(String(32), index=True)
    trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    key_fingerprint_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    latest_sequence: Mapped[int] = mapped_column(Integer, default=0)
    latest_statement_digest_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
    )


class CapabilityPromotionKeyRotation(Base):
    __tablename__ = "capability_promotion_key_rotations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "statement_digest_sha256", name="uq_promotion_rotation_namespace_statement"),
        CheckConstraint("promotion_sequence >= 0", name="ck_promotion_rotation_sequence"),
        CheckConstraint("from_trust_key_id <> to_trust_key_id", name="ck_promotion_rotation_distinct_keys"),
        CheckConstraint("expires_at > issued_at", name="ck_promotion_rotation_lifetime"),
        CheckConstraint("(promotion_sequence = 0 AND latest_statement_digest_sha256 IS NULL) OR "
            "(promotion_sequence > 0 AND latest_statement_digest_sha256 IS NOT NULL)", name="ck_promotion_rotation_head"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("capability_promotion_sources.id", ondelete="RESTRICT"), index=True)
    from_trust_key_id: Mapped[str] = mapped_column(ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"))
    to_trust_key_id: Mapped[str] = mapped_column(ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"))
    from_key_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    to_key_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    promotion_sequence: Mapped[int] = mapped_column(Integer)
    latest_statement_digest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    statement_digest_sha256: Mapped[str] = mapped_column(String(64))
    current_signature_sha256: Mapped[str] = mapped_column(String(64))
    next_signature_sha256: Mapped[str] = mapped_column(String(64))
    signed_rotation_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
    rotated_by: Mapped[str] = mapped_column(String(255))
    rotated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class CapabilityPromotionReceipt(Base):
    __tablename__ = "capability_promotion_receipts"
    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "promotion_sequence",
            name="uq_capability_promotion_source_sequence",
        ),
        UniqueConstraint(
            "tenant_id", "region_id",
            "statement_digest_sha256",
            name="uq_promotion_receipt_namespace_statement",
        ),
        UniqueConstraint(
            "tenant_id", "region_id",
            "target_environment_id",
            "pack_digest_sha256",
            name="uq_promotion_receipt_namespace_target_pack",
        ),
        CheckConstraint(
            "promotion_sequence > 0",
            name="ck_capability_promotion_sequence_positive",
        ),
        CheckConstraint(
            "artifact_count > 0",
            name="ck_capability_promotion_artifact_count_positive",
        ),
        Index(
            "ix_capability_promotion_accepted_at",
            "accepted_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(
        ForeignKey("capability_promotion_sources.id", ondelete="RESTRICT"),
        index=True,
    )
    installation_id: Mapped[str] = mapped_column(
        ForeignKey("capability_pack_installations.id", ondelete="RESTRICT"),
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(255), index=True)
    source_environment_id: Mapped[str] = mapped_column(String(255), index=True)
    source_stage: Mapped[str] = mapped_column(String(32))
    target_environment_id: Mapped[str] = mapped_column(String(255), index=True)
    target_stage: Mapped[str] = mapped_column(String(32))
    promotion_sequence: Mapped[int] = mapped_column(Integer)
    pack_name: Mapped[str] = mapped_column(String(255), index=True)
    pack_version: Mapped[str] = mapped_column(String(64))
    pack_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    pack_signer_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    artifact_count: Mapped[int] = mapped_column(Integer)
    artifact_set_digest_sha256: Mapped[str] = mapped_column(String(64))
    source_transparency_log_id: Mapped[str] = mapped_column(String(36))
    source_transparency_epoch: Mapped[int] = mapped_column(Integer)
    source_transparency_sequence: Mapped[int] = mapped_column(Integer)
    source_transparency_head_sha256: Mapped[str] = mapped_column(String(64))
    validation_evidence_digest_sha256: Mapped[str] = mapped_column(String(64))
    statement_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    key_fingerprint_sha256: Mapped[str] = mapped_column(String(64), index=True)
    signature_sha256: Mapped[str] = mapped_column(String(64))
    signed_attestation_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
    accepted_by: Mapped[str] = mapped_column(String(255))
    accepted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class CapabilityPromotionPublication(Base):
    __tablename__ = "capability_promotion_publications"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "receipt_id",
            name="uq_capability_promotion_publication_receipt",
        ),
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "publication_digest_sha256",
            name="uq_capability_promotion_publication_digest",
        ),
        CheckConstraint(
            "artifact_count > 0",
            name="ck_capability_promotion_publication_artifact_count",
        ),
        CheckConstraint(
            "newly_published_count >= 0",
            name="ck_capability_promotion_publication_new_count",
        ),
        Index(
            "ix_capability_promotion_publication_time",
            "published_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    receipt_id: Mapped[str] = mapped_column(
        ForeignKey("capability_promotion_receipts.id", ondelete="RESTRICT"),
    )
    installation_id: Mapped[str] = mapped_column(
        ForeignKey("capability_pack_installations.id", ondelete="RESTRICT"),
        index=True,
    )
    publication_digest_sha256: Mapped[str] = mapped_column(
        String(64),
    )
    artifact_count: Mapped[int] = mapped_column(Integer)
    newly_published_count: Mapped[int] = mapped_column(Integer)
    artifact_version_ids: Mapped[list[str]] = mapped_column(JSON)
    newly_published_version_ids: Mapped[list[str]] = mapped_column(JSON)
    already_published_version_ids: Mapped[list[str]] = mapped_column(JSON)
    reused_version_ids: Mapped[list[str]] = mapped_column(JSON)
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(Text)
    published_by: Mapped[str] = mapped_column(String(255))
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class CapabilityPackRevocationFeed(Base):
    __tablename__ = "capability_pack_revocation_feeds"
    __table_args__ = (
        UniqueConstraint(
            "trust_key_id",
            "sequence",
            name="uq_capability_pack_revocation_key_sequence",
        ),
        CheckConstraint(
            "sequence > 0",
            name="ck_capability_pack_revocation_sequence_positive",
        ),
        CheckConstraint(
            "entry_count > 0",
            name="ck_capability_pack_revocation_entries_positive",
        ),
        Index(
            "ix_capability_pack_revocation_feed_ingested_at",
            "ingested_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"), index=True
    )
    sequence: Mapped[int] = mapped_column(Integer)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    feed_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    key_fingerprint_sha256: Mapped[str] = mapped_column(String(64), index=True)
    signature_sha256: Mapped[str] = mapped_column(String(64))
    entry_count: Mapped[int] = mapped_column(Integer)
    quarantine_summary: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    reason: Mapped[str] = mapped_column(Text)
    ingested_by: Mapped[str] = mapped_column(String(255))
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    entries: Mapped[list[CapabilityPackRevocation]] = relationship(
        back_populates="feed",
        cascade="all, delete-orphan",
        order_by="CapabilityPackRevocation.pack_digest_sha256",
    )


class CapabilityPackRevocation(Base):
    __tablename__ = "capability_pack_revocations"
    __table_args__ = (
        UniqueConstraint(
            "feed_id",
            "pack_digest_sha256",
            name="uq_capability_pack_revocation_feed_pack",
        ),
        Index(
            "ix_capability_pack_revocation_pack_effective",
            "pack_digest_sha256",
            "effective_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    feed_id: Mapped[str] = mapped_column(
        ForeignKey("capability_pack_revocation_feeds.id", ondelete="CASCADE"),
        index=True,
    )
    pack_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    reason_code: Mapped[str] = mapped_column(String(64), index=True)
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    feed: Mapped[CapabilityPackRevocationFeed] = relationship(
        back_populates="entries"
    )


class RemoteCapabilityCatalogSource(Base):
    __tablename__ = "remote_capability_catalog_sources"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "name", name="uq_remote_catalog_namespace_name"),
        UniqueConstraint(
            "tenant_id", "region_id", "index_url",
            name="uq_remote_catalog_namespace_url",
        ),
        Index(
            "ix_remote_capability_catalog_status",
            "enabled",
            "last_refresh_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    catalog_id: Mapped[str] = mapped_column(String(255), index=True)
    index_url: Mapped[str] = mapped_column(String(2048))
    trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    latest_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latest_index_digest_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    last_refresh_status: Mapped[str] = mapped_column(
        String(32),
        default="never",
    )
    last_refresh_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_error_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
    )


class RemoteCapabilityCatalogSnapshot(Base):
    __tablename__ = "remote_capability_catalog_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "sequence",
            name="uq_remote_capability_catalog_source_sequence",
        ),
        UniqueConstraint(
            "source_id",
            "index_digest_sha256",
            name="uq_remote_capability_catalog_source_digest",
        ),
        CheckConstraint(
            "sequence > 0",
            name="ck_remote_capability_catalog_sequence_positive",
        ),
        CheckConstraint(
            "entry_count > 0",
            name="ck_remote_capability_catalog_entry_count_positive",
        ),
        Index(
            "ix_remote_capability_catalog_snapshot_refreshed",
            "source_id",
            "refreshed_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(
        ForeignKey(
            "remote_capability_catalog_sources.id",
            ondelete="CASCADE",
        ),
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    index_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    key_fingerprint_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    signature_sha256: Mapped[str] = mapped_column(String(64))
    entry_count: Mapped[int] = mapped_column(Integer)
    refresh_reason: Mapped[str] = mapped_column(Text)
    refreshed_by: Mapped[str] = mapped_column(String(255))
    refreshed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class RemoteCapabilityCatalogEntry(Base):
    __tablename__ = "remote_capability_catalog_entries"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "pack_name",
            "pack_version",
            name="uq_remote_capability_catalog_entry_version",
        ),
        UniqueConstraint(
            "snapshot_id",
            "pack_digest_sha256",
            name="uq_remote_capability_catalog_entry_digest",
        ),
        CheckConstraint(
            "artifact_count > 0",
            name="ck_remote_capability_catalog_artifact_count_positive",
        ),
        CheckConstraint(
            "dependency_count >= 0",
            name="ck_remote_capability_catalog_dependency_count_nonnegative",
        ),
        Index(
            "ix_remote_capability_catalog_entry_lookup",
            "source_id",
            "pack_name",
            "pack_version",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(
        ForeignKey(
            "remote_capability_catalog_sources.id",
            ondelete="CASCADE",
        ),
        index=True,
    )
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey(
            "remote_capability_catalog_snapshots.id",
            ondelete="CASCADE",
        ),
        index=True,
    )
    pack_name: Mapped[str] = mapped_column(String(255), index=True)
    pack_version: Mapped[str] = mapped_column(String(64))
    platform_api: Mapped[str] = mapped_column(String(64))
    pack_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    pack_key_fingerprint_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    predecessor_digest_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    download_url: Mapped[str] = mapped_column(String(2048))
    artifact_count: Mapped[int] = mapped_column(Integer)
    dependency_count: Mapped[int] = mapped_column(Integer)


class RemoteCapabilityCatalogKeyRotation(Base):
    __tablename__ = "remote_capability_catalog_key_rotations"
    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "statement_digest_sha256",
            name="uq_remote_catalog_key_rotation_statement",
        ),
        CheckConstraint(
            "catalog_sequence >= 0",
            name="ck_remote_catalog_key_rotation_sequence_nonnegative",
        ),
        Index(
            "ix_remote_catalog_key_rotation_source_time",
            "source_id",
            "rotated_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(
        ForeignKey(
            "remote_capability_catalog_sources.id",
            ondelete="RESTRICT",
        ),
        index=True,
    )
    from_trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    to_trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    from_key_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    to_key_fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    catalog_sequence: Mapped[int] = mapped_column(Integer)
    index_digest_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    statement_digest_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    current_signature_sha256: Mapped[str] = mapped_column(String(64))
    next_signature_sha256: Mapped[str] = mapped_column(String(64))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
    rotated_by: Mapped[str] = mapped_column(String(255))
    rotated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class CapabilityTransparencyState(Base):
    __tablename__ = "capability_transparency_state"
    __table_args__ = (
        UniqueConstraint(
            "log_id",
            name="uq_capability_transparency_state_log_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    log_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        default=new_id,
    )
    epoch: Mapped[int] = mapped_column(Integer, default=1)
    last_sequence: Mapped[int] = mapped_column(Integer, default=0)
    head_digest_sha256: Mapped[str] = mapped_column(
        String(64),
        default="0" * 64,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
    )


class CapabilityTransparencyRecord(Base):
    __tablename__ = "capability_transparency_records"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "sequence",
            name="uq_transparency_record_namespace_sequence",
        ),
        UniqueConstraint(
            "tenant_id", "region_id", "record_digest_sha256",
            name="uq_transparency_record_namespace_digest",
        ),
        CheckConstraint(
            "sequence > 0",
            name="ck_capability_transparency_sequence_positive",
        ),
        Index(
            "ix_capability_transparency_event_time",
            "event_type",
            "occurred_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sequence: Mapped[int] = mapped_column(Integer, index=True)
    previous_digest_sha256: Mapped[str] = mapped_column(String(64))
    record_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    entity_type: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str] = mapped_column(String(255))
    subject_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class CapabilityTransparencyWitnessPolicy(Base):
    __tablename__ = "capability_transparency_witness_policy"
    __table_args__ = (
        CheckConstraint(
            "required_quorum BETWEEN 1 AND 16",
            name="ck_transparency_witness_policy_quorum",
        ),
        CheckConstraint(
            "max_attestation_age_hours BETWEEN 1 AND 720",
            name="ck_transparency_witness_policy_age",
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    required_quorum: Mapped[int] = mapped_column(Integer, default=2)
    max_attestation_age_hours: Mapped[int] = mapped_column(
        Integer,
        default=168,
    )
    updated_by: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
    )


class CapabilityTransparencyWitness(Base):
    __tablename__ = "capability_transparency_witnesses"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "witness_id",
            name="uq_transparency_witness_namespace_identity",
        ),
        UniqueConstraint(
            "tenant_id", "region_id", "name",
            name="uq_transparency_witness_namespace_name",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    witness_id: Mapped[str] = mapped_column(String(255), index=True)
    region: Mapped[str] = mapped_column(String(128), index=True)
    trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    key_fingerprint_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
    )


class CapabilityTransparencyCheckpointOffer(Base):
    __tablename__ = "capability_transparency_checkpoint_offers"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "statement_digest_sha256",
            name="uq_transparency_offer_namespace_digest",
        ),
        CheckConstraint(
            "sequence > 0",
            name="ck_transparency_checkpoint_offer_sequence_positive",
        ),
        Index(
            "ix_transparency_checkpoint_offer_sequence",
            "log_id",
            "epoch",
            "sequence",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    log_id: Mapped[str] = mapped_column(String(36), index=True)
    epoch: Mapped[int] = mapped_column(Integer)
    sequence: Mapped[int] = mapped_column(Integer)
    head_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    statement_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    statement_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class CapabilityTransparencyWitnessAttestation(Base):
    __tablename__ = "capability_transparency_witness_attestations"
    __table_args__ = (
        UniqueConstraint(
            "checkpoint_offer_id",
            "witness_id",
            name="uq_transparency_offer_witness",
        ),
        UniqueConstraint(
            "tenant_id", "region_id", "attestation_digest_sha256",
            name="uq_transparency_attestation_namespace_digest",
        ),
        Index(
            "ix_transparency_witness_attestation_sequence",
            "witness_id",
            "log_id",
            "epoch",
            "sequence",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    checkpoint_offer_id: Mapped[str] = mapped_column(
        ForeignKey(
            "capability_transparency_checkpoint_offers.id",
            ondelete="RESTRICT",
        ),
        index=True,
    )
    witness_id: Mapped[str] = mapped_column(
        ForeignKey(
            "capability_transparency_witnesses.id",
            ondelete="RESTRICT",
        ),
        index=True,
    )
    external_witness_id: Mapped[str] = mapped_column(String(255), index=True)
    trust_key_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"),
        index=True,
    )
    key_fingerprint_sha256: Mapped[str] = mapped_column(String(64), index=True)
    log_id: Mapped[str] = mapped_column(String(36), index=True)
    epoch: Mapped[int] = mapped_column(Integer)
    sequence: Mapped[int] = mapped_column(Integer)
    head_digest_sha256: Mapped[str] = mapped_column(String(64))
    checkpoint_statement_digest_sha256: Mapped[str] = mapped_column(String(64))
    attestation_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    signature_sha256: Mapped[str] = mapped_column(String(64))
    signed_attestation_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    witnessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_by: Mapped[str] = mapped_column(String(255))
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class CapabilityTransparencyGossipObservation(Base):
    __tablename__ = "capability_transparency_gossip_observations"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "document_digest_sha256",
            name="uq_transparency_gossip_namespace_document",
        ),
        Index(
            "ix_transparency_gossip_checkpoint",
            "log_id",
            "epoch",
            "sequence",
        ),
        Index(
            "ix_transparency_gossip_status_time",
            "initial_status",
            "received_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_region: Mapped[str] = mapped_column(String(128), index=True)
    log_id: Mapped[str] = mapped_column(String(36), index=True)
    epoch: Mapped[int] = mapped_column(Integer)
    sequence: Mapped[int] = mapped_column(Integer)
    head_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    checkpoint_statement_digest_sha256: Mapped[str] = mapped_column(String(64))
    document_digest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    witness_count: Mapped[int] = mapped_column(Integer)
    witness_evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    initial_status: Mapped[str] = mapped_column(String(32), index=True)
    gossip_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    alert_id: Mapped[str | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    reason: Mapped[str] = mapped_column(Text)
    received_by: Mapped[str] = mapped_column(String(255))
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    alert: Mapped[Alert | None] = relationship()


class EcosystemTransportEndpoint(Base):
    __tablename__ = "ecosystem_transport_endpoints"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_ecosystem_transport_endpoint_name",
        ),
        CheckConstraint(
            "kind IN ('transparency_witness', 'promotion_target', "
            "'gossip_peer')",
            name="ck_ecosystem_transport_endpoint_kind",
        ),
        CheckConstraint(
            "(kind = 'transparency_witness' AND witness_id IS NOT NULL "
            "AND target_environment_id IS NULL AND target_stage IS NULL "
            "AND target_region_id IS NULL) OR "
            "(kind = 'promotion_target' AND witness_id IS NULL "
            "AND target_environment_id IS NOT NULL AND target_stage IS NOT NULL "
            "AND target_region_id IS NULL) OR "
            "(kind = 'gossip_peer' AND witness_id IS NULL "
            "AND target_environment_id IS NULL AND target_stage IS NULL "
            "AND target_region_id IS NOT NULL)",
            name="ck_ecosystem_transport_endpoint_binding",
        ),
        CheckConstraint(
            "target_stage IS NULL OR target_stage IN "
            "('development', 'test', 'staging', 'production')",
            name="ck_ecosystem_transport_endpoint_stage",
        ),
        CheckConstraint(
            "kind != 'promotion_target' OR auto_dispatch = false",
            name="ck_ecosystem_transport_endpoint_promotion_explicit",
        ),
        CheckConstraint(
            "request_timeout_seconds BETWEEN 1 AND 30",
            name="ck_ecosystem_transport_endpoint_timeout",
        ),
        CheckConstraint(
            "max_response_bytes BETWEEN 1024 AND 5000000",
            name="ck_ecosystem_transport_endpoint_response_limit",
        ),
        CheckConstraint(
            "tls_mode IN ('server_auth', 'mutual_tls')",
            name="ck_ecosystem_transport_endpoint_tls_mode",
        ),
        CheckConstraint(
            "(tls_mode = 'server_auth' "
            "AND tls_client_certificate_ref IS NULL "
            "AND tls_client_private_key_ref IS NULL "
            "AND tls_client_private_key_password_ref IS NULL) OR "
            "(tls_mode = 'mutual_tls' "
            "AND tls_client_certificate_ref IS NOT NULL "
            "AND tls_client_private_key_ref IS NOT NULL)",
            name="ck_ecosystem_transport_endpoint_tls_binding",
        ),
        CheckConstraint(
            "tls_revision > 0",
            name="ck_ecosystem_transport_endpoint_tls_revision",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[EcosystemTransportEndpointKind] = mapped_column(
        Enum(
            EcosystemTransportEndpointKind,
            native_enum=False,
            length=32,
            values_callable=lambda items: [item.value for item in items],
        ),
        index=True,
    )
    url: Mapped[str] = mapped_column(String(2048))
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    tls_mode: Mapped[str] = mapped_column(
        String(16), default="server_auth", index=True
    )
    tls_ca_certificate_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    tls_client_certificate_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    tls_client_private_key_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    tls_client_private_key_password_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    tls_revision: Mapped[int] = mapped_column(Integer, default=1)
    witness_id: Mapped[str | None] = mapped_column(
        ForeignKey(
            "capability_transparency_witnesses.id",
            ondelete="RESTRICT",
        ),
        nullable=True,
        index=True,
    )
    target_environment_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    target_stage: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    target_region_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    auto_dispatch: Mapped[bool] = mapped_column(
        Boolean, default=False, index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    request_timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    max_response_bytes: Mapped[int] = mapped_column(Integer, default=1_000_000)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    jobs: Mapped[list[EcosystemTransportJob]] = relationship(
        back_populates="endpoint"
    )


class EcosystemTransportWorker(Base):
    __tablename__ = "ecosystem_transport_workers"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_ecosystem_transport_worker_name",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    state: Mapped[EcosystemTransportWorkerState] = mapped_column(
        Enum(
            EcosystemTransportWorkerState,
            native_enum=False,
            length=16,
            values_callable=lambda items: [item.value for item in items],
        ),
        default=EcosystemTransportWorkerState.ONLINE,
        index=True,
    )
    last_heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    jobs: Mapped[list[EcosystemTransportJob]] = relationship(
        back_populates="lease_worker"
    )


class EcosystemTransportJob(Base):
    __tablename__ = "ecosystem_transport_jobs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "dedupe_key",
            name="uq_ecosystem_transport_job_dedupe",
        ),
        CheckConstraint(
            "kind IN ('witness_checkpoint', 'promotion_delivery', "
            "'gossip_delivery')",
            name="ck_ecosystem_transport_job_kind",
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'retry', 'succeeded', "
            "'dead_letter', 'cancelled')",
            name="ck_ecosystem_transport_job_status",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 20",
            name="ck_ecosystem_transport_job_attempts",
        ),
        CheckConstraint(
            "(kind IN ('witness_checkpoint', 'gossip_delivery') "
            "AND checkpoint_offer_id IS NOT NULL) "
            "OR (kind = 'promotion_delivery' AND checkpoint_offer_id IS NULL)",
            name="ck_ecosystem_transport_job_binding",
        ),
        Index(
            "ix_ecosystem_transport_job_queue",
            "status",
            "next_attempt_at",
            "lease_expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("ecosystem_transport_endpoints.id", ondelete="RESTRICT"),
        index=True,
    )
    kind: Mapped[EcosystemTransportJobKind] = mapped_column(
        Enum(
            EcosystemTransportJobKind,
            native_enum=False,
            length=32,
            values_callable=lambda items: [item.value for item in items],
        ),
        index=True,
    )
    checkpoint_offer_id: Mapped[str | None] = mapped_column(
        ForeignKey(
            "capability_transparency_checkpoint_offers.id",
            ondelete="RESTRICT",
        ),
        nullable=True,
        index=True,
    )
    dedupe_key: Mapped[str] = mapped_column(String(128), index=True)
    payload_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[EcosystemTransportJobStatus] = mapped_column(
        Enum(
            EcosystemTransportJobStatus,
            native_enum=False,
            length=16,
            values_callable=lambda items: [item.value for item in items],
        ),
        default=EcosystemTransportJobStatus.PENDING,
        index=True,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    lease_worker_id: Mapped[str | None] = mapped_column(
        ForeignKey("ecosystem_transport_workers.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    lease_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    response_digest_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255))
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    endpoint: Mapped[EcosystemTransportEndpoint] = relationship(
        back_populates="jobs"
    )
    lease_worker: Mapped[EcosystemTransportWorker | None] = relationship(
        back_populates="jobs"
    )


class ArtifactReplayCase(Base):
    __tablename__ = "artifact_replay_cases"
    __table_args__ = (
        UniqueConstraint(
            "artifact_id",
            "name",
            name="uq_artifact_replay_case_name",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255), index=True)
    source_label: Mapped[str] = mapped_column(String(255))
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    input_envelopes: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    expected_envelopes: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    input_sha256: Mapped[str] = mapped_column(String(64))
    expected_sha256: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ArtifactReplayRun(Base):
    __tablename__ = "artifact_replay_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('passed', 'failed', 'error')",
            name="ck_artifact_replay_run_status",
        ),
        Index(
            "ix_artifact_replay_run_case_created",
            "case_id",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_replay_cases.id", ondelete="CASCADE"), index=True
    )
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[str] = mapped_column(String(16), index=True)
    actual_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mismatch_count: Mapped[int] = mapped_column(Integer, default=0)
    report: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    executed_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class WorkflowTriggerActivation(Base):
    __tablename__ = "workflow_trigger_activations"
    __table_args__ = (
        UniqueConstraint(
            "artifact_version_id",
            name="uq_workflow_trigger_activation_version",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    route_purpose: Mapped[str] = mapped_column(String(128), default="investigation")
    run_as_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    authorization_scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    input_mapping: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class WorkflowTriggerEvent(Base):
    __tablename__ = "workflow_trigger_events"
    __table_args__ = (
        UniqueConstraint(
            "activation_id",
            "alert_id",
            name="uq_workflow_trigger_event_activation_alert",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_workflow_trigger_event_attempts",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    activation_id: Mapped[str] = mapped_column(
        ForeignKey("workflow_trigger_activations.id", ondelete="CASCADE"), index=True
    )
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    error_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class SituationIntegrationBinding(Base):
    __tablename__ = "situation_integration_bindings"
    __table_args__ = (
        UniqueConstraint(
            "artifact_version_id",
            name="uq_situation_integration_binding_version",
        ),
        CheckConstraint(
            "channel_kind IN ('ticket', 'collaboration')",
            name="ck_situation_integration_binding_channel",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="CASCADE"), index=True
    )
    channel_kind: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    route_purpose: Mapped[str] = mapped_column(
        String(128), default="investigation"
    )
    run_as_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    authorization_scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    input_mapping: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    provider_key: Mapped[str] = mapped_column(
        String(64), default="generic", index=True
    )
    remote_reference_tool_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    remote_reference_mapping: Mapped[dict[str, str]] = mapped_column(
        JSON, default=dict
    )
    inbound_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, index=True
    )
    inbound_key_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    inbound_public_key_pem: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    inbound_public_key_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class SituationIntegrationEvent(Base):
    __tablename__ = "situation_integration_events"
    __table_args__ = (
        UniqueConstraint(
            "binding_id",
            "situation_event_id",
            name="uq_situation_integration_event_delivery",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_situation_integration_event_attempts",
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'succeeded', 'failed')",
            name="ck_situation_integration_event_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    binding_id: Mapped[str] = mapped_column(
        ForeignKey("situation_integration_bindings.id", ondelete="CASCADE"),
        index=True,
    )
    situation_id: Mapped[str] = mapped_column(
        ForeignKey("situations.id", ondelete="CASCADE"), index=True
    )
    situation_event_id: Mapped[str] = mapped_column(
        ForeignKey("situation_events.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    error_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class SituationIntegrationRemoteReference(Base):
    __tablename__ = "situation_integration_remote_references"
    __table_args__ = (
        UniqueConstraint(
            "integration_event_id",
            name="uq_situation_remote_ref_event",
        ),
        UniqueConstraint(
            "binding_id",
            "remote_id",
            name="uq_situation_remote_ref_binding_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    integration_event_id: Mapped[str] = mapped_column(
        ForeignKey("situation_integration_events.id", ondelete="CASCADE"),
        index=True,
    )
    binding_id: Mapped[str] = mapped_column(
        ForeignKey("situation_integration_bindings.id", ondelete="CASCADE"),
        index=True,
    )
    situation_id: Mapped[str] = mapped_column(
        ForeignKey("situations.id", ondelete="CASCADE"), index=True
    )
    investigation_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    provider_key: Mapped[str] = mapped_column(String(64), index=True)
    remote_id: Mapped[str] = mapped_column(String(255), index=True)
    remote_url: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )
    remote_status: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    remote_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    source_tool_call_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class SituationIntegrationInboundEvent(Base):
    __tablename__ = "situation_integration_inbound_events"
    __table_args__ = (
        UniqueConstraint(
            "binding_id",
            "provider_event_id",
            name="uq_situation_inbound_provider_event",
        ),
        CheckConstraint(
            "outcome IN ('accepted', 'ignored_stale')",
            name="ck_situation_inbound_outcome",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    binding_id: Mapped[str] = mapped_column(
        ForeignKey("situation_integration_bindings.id", ondelete="CASCADE"),
        index=True,
    )
    reference_id: Mapped[str] = mapped_column(
        ForeignKey("situation_integration_remote_references.id", ondelete="CASCADE"),
        index=True,
    )
    provider_event_id: Mapped[str] = mapped_column(String(255), index=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    remote_status: Mapped[str] = mapped_column(String(128), index=True)
    remote_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    payload_sha256: Mapped[str] = mapped_column(String(64))
    signature_sha256: Mapped[str] = mapped_column(String(64))
    signature_key_id: Mapped[str] = mapped_column(String(128))
    outcome: Mapped[str] = mapped_column(String(32), index=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class WorkflowScheduleActivation(Base):
    __tablename__ = "workflow_schedule_activations"
    __table_args__ = (
        UniqueConstraint(
            "artifact_version_id",
            name="uq_workflow_schedule_activation_version",
        ),
        CheckConstraint(
            "misfire_grace_seconds >= 60 AND misfire_grace_seconds <= 86400",
            name="ck_workflow_schedule_misfire_grace",
        ),
        CheckConstraint(
            "missed_runs >= 0",
            name="ck_workflow_schedule_missed_runs",
        ),
        CheckConstraint(
            "excluded_runs >= 0 AND revision > 0",
            name="ck_workflow_schedule_exclusion_counters",
        ),
        CheckConstraint(
            "(report_artifact_version_id IS NULL AND report_input_key IS NULL) OR "
            "(report_artifact_version_id IS NOT NULL AND report_input_key IS NOT NULL)",
            name="ck_workflow_schedule_report_binding_complete",
        ),
        CheckConstraint(
            "report_attachment_format IS NULL OR (report_artifact_version_id IS NOT NULL "
            "AND report_attachment_format IN ('json', 'html', 'csv', 'pdf'))",
            name="ck_workflow_schedule_attachment_binding",
        ),
        CheckConstraint(
            "(report_delivery_tool_name IS NULL "
            "AND report_delivery_tool_argument IS NULL "
            "AND report_delivery_provider_key IS NULL) OR "
            "(report_delivery_tool_name IS NOT NULL "
            "AND report_delivery_tool_argument IS NOT NULL "
            "AND report_delivery_provider_key IS NOT NULL)",
            name="ck_workflow_schedule_delivery_receipt_complete",
        ),
        Index(
            "ix_workflow_schedule_due",
            "enabled",
            "next_fire_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="CASCADE"), index=True
    )
    cron_expression: Mapped[str] = mapped_column(String(255))
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    route_purpose: Mapped[str] = mapped_column(String(128), default="investigation")
    run_as_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    authorization_scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    workflow_input: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    report_artifact_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    report_input_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    report_attachment_format: Mapped[str | None] = mapped_column(String(8), nullable=True)
    report_delivery_tool_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    report_delivery_tool_argument: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    report_delivery_provider_key: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    report_delivery_receipt_mapping: Mapped[dict[str, str]] = mapped_column(
        JSON, default=dict
    )
    misfire_grace_seconds: Mapped[int] = mapped_column(Integer, default=300)
    exclusion_windows: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list
    )
    excluded_runs: Mapped[int] = mapped_column(Integer, default=0)
    last_excluded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_fire_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    last_fire_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_misfire_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    missed_runs: Mapped[int] = mapped_column(Integer, default=0)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class WorkflowScheduleEvent(Base):
    __tablename__ = "workflow_schedule_events"
    __table_args__ = (
        UniqueConstraint(
            "activation_id",
            "scheduled_for",
            name="uq_workflow_schedule_event_occurrence",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_workflow_schedule_event_attempts",
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'succeeded', 'failed', 'skipped')",
            name="ck_workflow_schedule_event_status",
        ),
        CheckConstraint(
            "(status = 'skipped' AND skip_reason = 'calendar_exclusion' "
            "AND exclusion_window_id IS NOT NULL) OR "
            "(status <> 'skipped' AND skip_reason IS NULL "
            "AND exclusion_window_id IS NULL)",
            name="ck_workflow_schedule_event_skip_metadata",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    activation_id: Mapped[str] = mapped_column(
        ForeignKey("workflow_schedule_activations.id", ondelete="CASCADE"),
        index=True,
    )
    scheduled_for: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    skip_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exclusion_window_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    error_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ServiceReportInstance(Base):
    __tablename__ = "service_report_instances"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "request_sha256", name="uq_report_instance_request"),
        CheckConstraint("snapshot_size_bytes > 0", name="ck_report_instance_snapshot_size_positive"),
        Index("ix_report_instance_artifact_created", "artifact_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id", ondelete="RESTRICT"), index=True)
    artifact_version_id: Mapped[str] = mapped_column(ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True)
    request_sha256: Mapped[str] = mapped_column(String(64))
    content_sha256: Mapped[str] = mapped_column(String(64))
    snapshot_size_bytes: Mapped[int] = mapped_column(Integer)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str] = mapped_column(String(255))
    service_refs: Mapped[list[ServiceReportInstanceService]] = relationship(
        cascade="all, delete-orphan", order_by="ServiceReportInstanceService.service_key",
    )
    proof_admission: Mapped[ReportProofAdmission | None] = relationship(passive_deletes="all")
    proof_refs: Mapped[list[ReportInstanceProofReference]] = relationship(
        passive_deletes="all", order_by="ReportInstanceProofReference.section_key")


class ReportProofAdmission(Base):
    __tablename__ = "report_proof_admissions"
    instance_id: Mapped[str] = mapped_column(ForeignKey("service_report_instances.id", ondelete="CASCADE"), primary_key=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), index=True)
    reader_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)


class ReportInstanceProofReference(Base):
    __tablename__ = "report_instance_proof_references"
    __table_args__ = (
        UniqueConstraint("instance_id", "section_key", name="uq_report_proof_section"),
        CheckConstraint("(replacement_request_id IS NOT NULL AND retirement_id IS NULL AND closure_receipt_id IS NULL) OR "
            "(replacement_request_id IS NULL AND retirement_id IS NOT NULL AND closure_receipt_id IS NULL) OR "
            "(replacement_request_id IS NULL AND retirement_id IS NULL AND closure_receipt_id IS NOT NULL)", name="ck_report_proof_one_reference"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    instance_id: Mapped[str] = mapped_column(ForeignKey("service_report_instances.id", ondelete="CASCADE"), index=True)
    section_key: Mapped[str] = mapped_column(String(128))
    replacement_request_id: Mapped[str | None] = mapped_column(ForeignKey("collector_source_replacement_requests.id", ondelete="RESTRICT"), nullable=True, index=True)
    retirement_id: Mapped[str | None] = mapped_column(ForeignKey("collector_source_retirements.id", ondelete="RESTRICT"), nullable=True, index=True)
    closure_receipt_id: Mapped[str | None] = mapped_column(ForeignKey("situation_closure_receipts.id", ondelete="RESTRICT"), nullable=True, index=True)


class ReportStoragePolicy(Base):
    __tablename__ = "report_storage_policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", name="uq_report_storage_policy_namespace"),
        CheckConstraint("max_instances IS NULL OR max_instances > 0", name="ck_report_storage_max_instances"),
        CheckConstraint("max_bytes IS NULL OR max_bytes > 0", name="ck_report_storage_max_bytes"),
        CheckConstraint("used_instances >= 0 AND used_bytes >= 0", name="ck_report_storage_usage_nonnegative"),
        CheckConstraint("revision > 0", name="ck_report_storage_policy_revision"),
        CheckConstraint("max_attachment_bytes IS NULL OR max_attachment_bytes > 0", name="ck_report_storage_max_attachment_bytes"),
        CheckConstraint("used_attachment_bytes >= 0", name="ck_report_storage_attachment_usage"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    max_instances: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    used_instances: Mapped[int] = mapped_column(Integer, default=0)
    used_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    max_attachment_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    used_attachment_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255))
    updated_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ReportAttachment(Base):
    __tablename__ = "report_attachments"
    __table_args__ = (
        UniqueConstraint("instance_id", "export_format", name="uq_report_attachment_instance_format"),
        CheckConstraint("size_bytes > 0 AND size_bytes <= 4000000", name="ck_report_attachment_size"),
        CheckConstraint("export_format IN ('json', 'html', 'csv', 'pdf')", name="ck_report_attachment_format"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    instance_id: Mapped[str] = mapped_column(ForeignKey("service_report_instances.id", ondelete="CASCADE"), index=True)
    export_format: Mapped[str] = mapped_column(String(8))
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    content_sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    media_type: Mapped[str] = mapped_column(String(128))
    renderer: Mapped[str] = mapped_column(String(255))
    body: Mapped[bytes] = mapped_column(LargeBinary)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReportArchiveAcknowledgement(Base):
    __tablename__ = "report_archive_acknowledgements"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "instance_id", "archive_reference",
            name="uq_report_archive_namespace_instance_reference",
        ),
        CheckConstraint("snapshot_size_bytes > 0", name="ck_report_archive_snapshot_size_positive"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    instance_id: Mapped[str] = mapped_column(String(36), index=True)
    artifact_version_id: Mapped[str] = mapped_column(String(36), index=True)
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    snapshot_size_bytes: Mapped[int] = mapped_column(Integer)
    archive_reference: Mapped[str] = mapped_column(String(255))
    reason_sha256: Mapped[str] = mapped_column(String(64))
    acknowledged_by: Mapped[str] = mapped_column(String(255))
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReportArchiveSource(Base):
    __tablename__ = "report_archive_sources"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "name", name="uq_report_archive_source_namespace_name"),
        CheckConstraint("revision > 0", name="ck_report_archive_source_revision"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    origin: Mapped[str] = mapped_column(String(2048))
    credential_profile_id: Mapped[str] = mapped_column(ForeignKey("credential_profiles.id", ondelete="RESTRICT"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReportArchiveVerification(Base):
    __tablename__ = "report_archive_verifications"
    __table_args__ = (
        CheckConstraint("package_size_bytes > 0 AND package_size_bytes <= 22000000", name="ck_report_archive_package_size"),
        CheckConstraint("source_revision > 0 AND credential_revision >= 0", name="ck_report_archive_verification_revisions"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    instance_id: Mapped[str] = mapped_column(String(36), index=True)
    acknowledgement_id: Mapped[str] = mapped_column(ForeignKey("report_archive_acknowledgements.id", ondelete="RESTRICT"), index=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("report_archive_sources.id", ondelete="RESTRICT"), index=True)
    artifact_version_id: Mapped[str] = mapped_column(String(36))
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    package_sha256: Mapped[str] = mapped_column(String(64))
    package_size_bytes: Mapped[int] = mapped_column(Integer)
    source_binding_sha256: Mapped[str] = mapped_column(String(64))
    attachments: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    source_revision: Mapped[int] = mapped_column(Integer)
    credential_revision: Mapped[int] = mapped_column(Integer)
    reason_sha256: Mapped[str] = mapped_column(String(64))
    verified_by: Mapped[str] = mapped_column(String(255))
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReportLegalHold(Base):
    __tablename__ = "report_legal_holds"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "instance_id", "hold_reference",
            name="uq_report_hold_namespace_instance_reference",
        ),
        CheckConstraint(
            "(released_at IS NULL AND released_by IS NULL AND release_reason_sha256 IS NULL) "
            "OR (released_at IS NOT NULL AND released_by IS NOT NULL "
            "AND release_reason_sha256 IS NOT NULL)",
            name="ck_report_hold_release_complete",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    instance_id: Mapped[str] = mapped_column(String(36), index=True)
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    hold_reference: Mapped[str] = mapped_column(String(255))
    reason_sha256: Mapped[str] = mapped_column(String(64))
    placed_by: Mapped[str] = mapped_column(String(255))
    placed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    released_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    release_reason_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReportPurgeRequest(Base):
    __tablename__ = "report_purge_requests"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "request_sha256",
            name="uq_report_purge_namespace_request",
        ),
        CheckConstraint(
            "status IN ('requested', 'approved', 'rejected', 'executed')",
            name="ck_report_purge_request_status",
        ),
        CheckConstraint("snapshot_size_bytes > 0", name="ck_report_purge_snapshot_size_positive"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    instance_id: Mapped[str] = mapped_column(String(36), index=True)
    artifact_version_id: Mapped[str] = mapped_column(String(36))
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    snapshot_size_bytes: Mapped[int] = mapped_column(Integer)
    archive_acknowledgement_id: Mapped[str] = mapped_column(
        ForeignKey("report_archive_acknowledgements.id", ondelete="RESTRICT"), index=True,
    )
    archive_verification_id: Mapped[str | None] = mapped_column(
        ForeignKey("report_archive_verifications.id", ondelete="RESTRICT"), nullable=True,
    )
    request_sha256: Mapped[str] = mapped_column(String(64))
    request_reason_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="requested", index=True)
    requested_by: Mapped[str] = mapped_column(String(255))
    requester_identity: Mapped[str] = mapped_column(String(255))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewer_identity: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_reason_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    execution_reason_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReportPurgeTombstone(Base):
    __tablename__ = "report_purge_tombstones"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "request_sha256",
            name="uq_report_tombstone_namespace_capture_request",
        ),
        UniqueConstraint("purge_request_id", name="uq_report_tombstone_purge_request"),
        CheckConstraint("snapshot_size_bytes > 0", name="ck_report_tombstone_snapshot_size_positive"),
        CheckConstraint(
            "(archive_verification_id IS NULL AND archive_revalidated_at IS NULL) OR "
            "(archive_verification_id IS NOT NULL AND archive_revalidated_at IS NOT NULL)",
            name="ck_report_tombstone_archive_revalidation",
        ),
    )

    instance_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    artifact_id: Mapped[str] = mapped_column(String(36))
    artifact_version_id: Mapped[str] = mapped_column(String(36))
    request_sha256: Mapped[str] = mapped_column(String(64))
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    snapshot_size_bytes: Mapped[int] = mapped_column(Integer)
    attachments: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    archive_acknowledgement_id: Mapped[str] = mapped_column(
        ForeignKey("report_archive_acknowledgements.id", ondelete="RESTRICT"), index=True,
    )
    archive_verification_id: Mapped[str | None] = mapped_column(
        ForeignKey("report_archive_verifications.id", ondelete="RESTRICT"), nullable=True,
    )
    archive_revalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    purge_request_id: Mapped[str] = mapped_column(
        ForeignKey("report_purge_requests.id", ondelete="RESTRICT"), index=True,
    )
    deleted_by: Mapped[str] = mapped_column(String(255))
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceReportInstanceService(Base):
    __tablename__ = "service_report_instance_services"
    __table_args__ = (UniqueConstraint("instance_id", "service_key", name="uq_report_instance_service"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    instance_id: Mapped[str] = mapped_column(ForeignKey("service_report_instances.id", ondelete="CASCADE"), index=True)
    service_key: Mapped[str] = mapped_column(String(128), index=True)


class ReportDeliveryReceipt(Base):
    __tablename__ = "report_delivery_receipts"
    __table_args__ = (
        UniqueConstraint(
            "schedule_event_id",
            name="uq_report_delivery_receipt_schedule_event",
        ),
        UniqueConstraint(
            "activation_id",
            "provider_key",
            "delivery_id",
            name="uq_report_delivery_receipt_provider_id",
        ),
        UniqueConstraint(
            "source_tool_call_id",
            name="uq_report_delivery_receipt_tool_call",
        ),
        CheckConstraint(
            "(verification_tool_call_id IS NULL AND verified_at IS NULL) OR "
            "(verification_tool_call_id IS NOT NULL AND verified_at IS NOT NULL)",
            name="ck_report_delivery_receipt_verification_complete",
        ),
        CheckConstraint(
            "(report_attachment_id IS NULL AND report_attachment_sha256 IS NULL) OR "
            "(report_attachment_id IS NOT NULL AND report_attachment_sha256 IS NOT NULL AND report_instance_id IS NOT NULL)",
            name="ck_report_receipt_attachment_complete",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    schedule_event_id: Mapped[str] = mapped_column(
        ForeignKey("workflow_schedule_events.id", ondelete="CASCADE"),
        index=True,
    )
    activation_id: Mapped[str] = mapped_column(
        ForeignKey("workflow_schedule_activations.id", ondelete="CASCADE"),
        index=True,
    )
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT"), index=True
    )
    workflow_artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    workflow_content_hash: Mapped[str] = mapped_column(String(64))
    report_artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    report_instance_id: Mapped[str | None] = mapped_column(
        ForeignKey("service_report_instances.id", ondelete="RESTRICT"),
        nullable=True, index=True,
    )
    report_content_hash: Mapped[str] = mapped_column(String(64))
    report_attachment_id: Mapped[str | None] = mapped_column(
        ForeignKey("report_attachments.id", ondelete="RESTRICT"), nullable=True, index=True,
    )
    report_attachment_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_key: Mapped[str] = mapped_column(String(64), index=True)
    delivery_tool_name: Mapped[str] = mapped_column(String(255), index=True)
    delivery_id: Mapped[str] = mapped_column(String(255), index=True)
    delivery_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    delivery_status: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    source_tool_call_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"),
        index=True,
    )
    verification_tool_call_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    delivered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class CapabilityStudioSession(Base):
    __tablename__ = "capability_studio_sessions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "revision_source_type",
            "revision_source_id",
            name="uq_capability_studio_revision_source",
        ),
        CheckConstraint(
            "revision_source_type IS NULL OR revision_source_type IN "
            "('collector_run', 'artifact_replay_run', 'agent_execution')",
            name="ck_capability_studio_revision_source_type",
        ),
        CheckConstraint(
            "(revision_source_type IS NULL AND revision_source_id IS NULL AND "
            "revision_source_artifact_version_id IS NULL AND "
            "revision_evidence_sha256 IS NULL) OR "
            "(revision_source_type IS NOT NULL AND revision_source_id IS NOT NULL "
            "AND revision_source_artifact_version_id IS NOT NULL AND "
            "revision_evidence_sha256 IS NOT NULL)",
            name="ck_capability_studio_revision_source_complete",
        ),
        CheckConstraint(
            "(source_context IS NULL AND source_document_name IS NULL AND "
            "source_document_media_type IS NULL AND source_document_sha256 IS NULL "
            "AND source_document_bytes IS NULL AND source_context_bytes IS NULL "
            "AND source_document_redaction_count IS NULL) OR "
            "(source_context IS NOT NULL AND source_document_name IS NOT NULL AND "
            "source_document_media_type IS NOT NULL AND source_document_sha256 IS NOT NULL "
            "AND source_document_bytes > 0 AND source_context_bytes > 0 "
            "AND source_document_redaction_count >= 0)",
            name="ck_capability_studio_source_document_complete",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(255), index=True)
    artifact_kind: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="draft", index=True)
    route_purpose: Mapped[str] = mapped_column(String(128), index=True)
    route_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    brief: Mapped[str] = mapped_column(Text)
    target_url: Mapped[str] = mapped_column(String(2048))
    sample_document: Mapped[dict[str, Any] | list[Any]] = mapped_column(JSON)
    source_context: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_document_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    source_document_media_type: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    source_document_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    source_document_bytes: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    source_context_bytes: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    source_document_redaction_count: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    current_spec: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    generation_attempt_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    artifact_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    revision_source_type: Mapped[str | None] = mapped_column(
        String(32), nullable=True, index=True
    )
    revision_source_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    revision_source_artifact_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    revision_evidence_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(255), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    messages: Mapped[list[CapabilityStudioMessage]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="CapabilityStudioMessage.created_at",
    )


class CapabilityStudioGenerationAttempt(Base):
    """Durable authoring intent and its exact, inspectable candidate outcome."""

    __tablename__ = "capability_studio_generation_attempts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "session_id", "request_key",
            name="uq_studio_generation_request"),
        CheckConstraint("status IN ('generating', 'generated', 'draft', 'validated', 'failed', 'interrupted')",
            name="ck_studio_generation_status"),
        CheckConstraint("tokens_used >= 0", name="ck_studio_generation_tokens"),
        CheckConstraint("(artifact_id IS NULL AND artifact_version_id IS NULL AND candidate_sha256 IS NULL) OR "
            "(artifact_id IS NOT NULL AND artifact_version_id IS NOT NULL AND candidate_sha256 IS NOT NULL)",
            name="ck_studio_generation_candidate"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("capability_studio_sessions.id", ondelete="RESTRICT"), index=True)
    request_key: Mapped[str] = mapped_column(String(36))
    request_sha256: Mapped[str] = mapped_column(String(64))
    request_document: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    actor: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="generating", index=True)
    owner_sha256: Mapped[str] = mapped_column(String(64))
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    model_schema: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model_document: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    model_document_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    usage_recorded: Mapped[bool] = mapped_column(Boolean, default=False)
    route_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=True, index=True)
    artifact_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=True, index=True)
    candidate_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class CapabilityStudioMessage(Base):
    __tablename__ = "capability_studio_messages"
    __table_args__ = (
        Index("ix_capability_studio_message_session_created", "session_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("capability_studio_sessions.id", ondelete="CASCADE"),
        index=True,
    )
    role: Mapped[str] = mapped_column(String(16), index=True)
    content: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64))
    structured_content: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    session: Mapped[CapabilityStudioSession] = relationship(
        back_populates="messages"
    )


class CollectorDefinition(Base):
    __tablename__ = "collector_definitions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    adapter_type: Mapped[str] = mapped_column(String(128), index=True)
    mode: Mapped[CollectorMode] = mapped_column(
        Enum(CollectorMode, native_enum=False, length=16), index=True
    )
    output_kinds: Mapped[list[str]] = mapped_column(JSON, default=list)
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    config_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    target_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    defaults: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    artifact_version: Mapped[ArtifactVersion] = relationship(
        back_populates="collector_definition"
    )


class CredentialProfile(Base):
    __tablename__ = "credential_profiles"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_credential_profile_namespace_name",
        ),
        CheckConstraint(
            "revision >= 0",
            name="ck_credential_profile_revision",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    provider: Mapped[str] = mapped_column(String(64), index=True)
    secret_ref: Mapped[str] = mapped_column(String(1024))
    allowed_adapters: Mapped[list[str]] = mapped_column(JSON, default=list)
    worker_selector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    revision: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class MetricBackend(Base):
    __tablename__ = "metric_backends"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_metric_backend_namespace_name",
        ),
        CheckConstraint(
            "auth_type IN ('none', 'bearer', 'basic', 'header')",
            name="ck_metric_backend_auth_type",
        ),
        CheckConstraint(
            "revision >= 0",
            name="ck_metric_backend_revision",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    provider: Mapped[str] = mapped_column(String(64), index=True)
    query_base_url: Mapped[str] = mapped_column(String(2048))
    remote_write_url: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )
    auth_type: Mapped[str] = mapped_column(
        String(32), default="none", server_default="none"
    )
    auth_header_name: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    external_labels: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    revision: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_by: Mapped[str] = mapped_column(String(255))
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_health_status: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    last_health_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    indicator_bindings: Mapped[list[ServiceIndicatorPrometheusBinding]] = (
        relationship(back_populates="metric_backend")
    )


class LogBackend(Base):
    __tablename__ = "log_backends"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_log_backend_namespace_name",
        ),
        CheckConstraint(
            "auth_type IN ('none', 'bearer', 'basic', 'header')",
            name="ck_log_backend_auth_type",
        ),
        CheckConstraint(
            "revision >= 0",
            name="ck_log_backend_revision",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    provider: Mapped[str] = mapped_column(String(64), index=True)
    query_base_url: Mapped[str] = mapped_column(String(2048))
    auth_type: Mapped[str] = mapped_column(
        String(32), default="none", server_default="none"
    )
    auth_header_name: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    device_label: Mapped[str] = mapped_column(String(128), default="instance")
    allowed_labels: Mapped[list[str]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    revision: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_by: Mapped[str] = mapped_column(String(255))
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_health_status: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    last_health_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AIProviderConfig(Base):
    __tablename__ = "ai_provider_configs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_ai_provider_namespace_name",
        ),
        CheckConstraint(
            "request_timeout_seconds > 0",
            name="ck_ai_provider_timeout_positive",
        ),
        CheckConstraint(
            "privacy_tier IN ('external', 'private', 'local')",
            name="ck_ai_provider_privacy_tier",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    provider_type: Mapped[str] = mapped_column(String(64), index=True)
    base_url: Mapped[str] = mapped_column(String(2048))
    auth_type: Mapped[str] = mapped_column(String(32), default="bearer")
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    request_timeout_seconds: Mapped[int] = mapped_column(Integer, default=20)
    privacy_tier: Mapped[str] = mapped_column(String(16), default="external")
    data_residency: Mapped[str] = mapped_column(String(64), default="unspecified")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_health_status: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    last_health_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ManagedDeviceCredential(Base):
    """Namespace-local, write-only device credential custody."""
    __tablename__ = "managed_device_credentials"
    __table_args__ = (UniqueConstraint("credential_profile_id", name="uq_managed_device_profile"),
                      CheckConstraint("revision > 0", name="ck_managed_device_revision"))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    credential_profile_id: Mapped[str] = mapped_column(ForeignKey("credential_profiles.id", ondelete="RESTRICT"))
    kind: Mapped[str] = mapped_column(String(32))
    site: Mapped[str] = mapped_column(String(128))
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DeviceOnboardingReceipt(Base):
    __tablename__ = "device_onboarding_receipts"
    __table_args__ = (UniqueConstraint("tenant_id", "region_id", "preview_hash", name="uq_device_onboarding_receipt"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    preview_hash: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(255))
    device_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ResearchSettings(Base):
    """One write-only search connection per workspace; no device credentials."""
    __tablename__ = "research_settings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", name="uq_research_namespace"),
        CheckConstraint("provider IN ('brave', 'searxng')", name="ck_research_provider"),
        CheckConstraint("revision > 0", name="ck_research_revision"),
        CheckConstraint("daily_limit BETWEEN 1 AND 10000 AND calls_today >= 0", name="ck_research_limit"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    searxng_url: Mapped[str | None] = mapped_column(String(2048))
    encrypted_secret: Mapped[bytes | None] = mapped_column(LargeBinary)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    daily_limit: Mapped[int] = mapped_column(Integer, default=100)
    quota_day: Mapped[str] = mapped_column(String(10), default="")
    calls_today: Mapped[int] = mapped_column(Integer, default=0)
    last_test_status: Mapped[str | None] = mapped_column(String(32))
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AIManagedConnection(Base):
    """Write-only AI credential custody and provider-bound outbound approval."""

    __tablename__ = "ai_managed_connections"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "provider_id", name="uq_ai_managed_provider"),
        UniqueConstraint("credential_profile_id", name="uq_ai_managed_credential"),
        CheckConstraint("revision > 0", name="ck_ai_managed_revision"),
        CheckConstraint("preset IN ('openrouter', 'openai', 'anthropic', 'gemini', 'deepseek', 'qwen_cn', 'qwen_sg')", name="ck_ai_managed_preset"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider_id: Mapped[str] = mapped_column(ForeignKey("ai_provider_configs.id", ondelete="RESTRICT"))
    credential_profile_id: Mapped[str] = mapped_column(ForeignKey("credential_profiles.id", ondelete="RESTRICT"))
    preset: Mapped[str] = mapped_column(String(32), default="openrouter")
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary)
    outbound_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255))
    updated_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AIModelConfig(Base):
    __tablename__ = "ai_model_configs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "display_name",
            name="uq_ai_model_namespace_display_name",
        ),
        UniqueConstraint(
            "provider_id",
            "model_name",
            name="uq_ai_model_provider_name",
        ),
        CheckConstraint(
            "context_window IS NULL OR context_window > 0",
            name="ck_ai_model_context_positive",
        ),
        CheckConstraint(
            "max_output_tokens IS NULL OR max_output_tokens > 0",
            name="ck_ai_model_output_positive",
        ),
        CheckConstraint(
            "cost_class IN ('low', 'standard', 'premium')",
            name="ck_ai_model_cost_class",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider_id: Mapped[str] = mapped_column(
        ForeignKey("ai_provider_configs.id", ondelete="CASCADE"), index=True
    )
    display_name: Mapped[str] = mapped_column(String(255), index=True)
    model_name: Mapped[str] = mapped_column(String(255), index=True)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    context_window: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_class: Mapped[str] = mapped_column(String(16), default="standard")
    default_parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AIModelRoute(Base):
    __tablename__ = "ai_model_routes"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "purpose",
            name="uq_ai_model_route_namespace_purpose",
        ),
        CheckConstraint("max_iterations > 0", name="ck_ai_route_iterations_positive"),
        CheckConstraint("max_tool_calls > 0", name="ck_ai_route_tools_positive"),
        CheckConstraint("timeout_seconds > 0", name="ck_ai_route_timeout_positive"),
        CheckConstraint("token_budget > 0", name="ck_ai_route_tokens_positive"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    purpose: Mapped[str] = mapped_column(String(128), index=True)
    primary_model_id: Mapped[str] = mapped_column(
        ForeignKey("ai_model_configs.id", ondelete="RESTRICT"), index=True
    )
    fallback_model_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    max_iterations: Mapped[int] = mapped_column(Integer, default=8)
    max_tool_calls: Mapped[int] = mapped_column(Integer, default=20)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)
    token_budget: Mapped[int] = mapped_column(Integer, default=50000)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AIAuthoringQuotaPolicy(Base):
    """Namespace-wide UTC-day admission limits for structured authoring."""

    __tablename__ = "ai_authoring_quota_policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", name="uq_ai_authoring_quota_namespace"),
        CheckConstraint("revision > 0", name="ck_ai_authoring_quota_revision"),
        CheckConstraint(
            "daily_token_limit IS NULL OR daily_token_limit > 0",
            name="ck_ai_authoring_quota_daily_limit",
        ),
        CheckConstraint(
            "actor_daily_token_limit IS NULL OR actor_daily_token_limit > 0",
            name="ck_ai_authoring_quota_actor_limit",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    daily_token_limit: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    actor_daily_token_limit: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AIAuthoringQuotaBucket(Base):
    """Row-locked daily usage: held reservations plus settled reported usage."""

    __tablename__ = "ai_authoring_quota_buckets"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "period_start", "scope_kind", "scope_key",
            name="uq_ai_authoring_quota_bucket",
        ),
        CheckConstraint(
            "scope_kind IN ('namespace', 'actor')",
            name="ck_ai_authoring_quota_scope_kind",
        ),
        CheckConstraint("used_tokens >= 0", name="ck_ai_authoring_quota_used"),
        Index(
            "ix_ai_authoring_quota_period",
            "tenant_id", "region_id", "period_start",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    period_start: Mapped[date] = mapped_column(Date)
    scope_kind: Mapped[str] = mapped_column(String(16))
    scope_key: Mapped[str] = mapped_column(String(255))
    used_tokens: Mapped[int] = mapped_column(BigInteger, default=0)


class AIAuthoringQuotaReservation(Base):
    """One durable model-call admission, with its operator-facing source."""

    __tablename__ = "ai_authoring_quota_reservations"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "entity_type", "entity_id",
            name="uq_ai_authoring_quota_entity",
        ),
        CheckConstraint(
            "status IN ('reserved', 'settled')",
            name="ck_ai_authoring_quota_reservation_status",
        ),
        CheckConstraint(
            "reserved_tokens > 0 AND known_tokens >= 0 AND charged_tokens >= 0",
            name="ck_ai_authoring_quota_reservation_tokens",
        ),
        Index(
            "ix_ai_authoring_quota_reservation_period",
            "tenant_id", "region_id", "period_start", "status",
        ),
        Index(
            "ix_ai_authoring_quota_reservation_source",
            "tenant_id", "region_id", "source_entity_type", "source_entity_id",
        ),
        Index(
            "ix_ai_authoring_quota_reservation_created",
            "tenant_id", "region_id", "created_at", "id",
        ),
        Index(
            "ix_ai_authoring_quota_reservation_actor_created",
            "tenant_id", "region_id", "actor", "created_at", "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    entity_type: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str] = mapped_column(String(36))
    source_entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_entity_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    source_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor: Mapped[str] = mapped_column(String(255))
    period_start: Mapped[date] = mapped_column(Date)
    reserved_tokens: Mapped[int] = mapped_column(BigInteger)
    known_tokens: Mapped[int] = mapped_column(BigInteger, default=0)
    charged_tokens: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(16), default="reserved")
    external_charge_unknown: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    adjustment: Mapped[AIAuthoringQuotaAdjustment | None] = relationship(
        "AIAuthoringQuotaAdjustment", uselist=False, viewonly=True, lazy="selectin",
    )
    supplemental_adjustments: Mapped[list[AIAuthoringQuotaSupplementAdjustment]] = relationship(
        "AIAuthoringQuotaSupplementAdjustment", viewonly=True, lazy="selectin",
        order_by="AIAuthoringQuotaSupplementAdjustment.sequence",
    )

    @property
    def effective_charged_tokens(self) -> int:
        if self.supplemental_adjustments:
            return self.supplemental_adjustments[-1].confirmed_total_tokens
        return (
            self.adjustment.confirmed_total_tokens
            if self.adjustment is not None else self.charged_tokens
        )

    @property
    def adjustment_id(self) -> str | None:
        return self.adjustment.id if self.adjustment is not None else None

    @property
    def latest_adjustment_id(self) -> str | None:
        if self.supplemental_adjustments:
            return self.supplemental_adjustments[-1].id
        return self.adjustment_id

    @property
    def supplemental_adjustment_count(self) -> int:
        return len(self.supplemental_adjustments)


class AIAuthoringQuotaReconciliationCase(Base):
    """One immutable, independently reviewed manual billing attestation."""

    __tablename__ = "ai_authoring_quota_reconciliation_cases"
    __table_args__ = (
        CheckConstraint("status IN ('proposed', 'applied', 'rejected')", name="ck_ai_quota_reconciliation_status"),
        CheckConstraint(
            "known_tokens_snapshot >= 0 AND original_charged_tokens >= 0 "
            "AND confirmed_total_tokens >= known_tokens_snapshot",
            name="ck_ai_quota_reconciliation_tokens",
        ),
        CheckConstraint(
            "delta_tokens = confirmed_total_tokens - original_charged_tokens",
            name="ck_ai_quota_reconciliation_delta",
        ),
        CheckConstraint(
            "(status = 'proposed' AND reviewed_by_principal_id IS NULL AND reviewed_at IS NULL) "
            "OR (status != 'proposed' AND reviewed_by_principal_id IS NOT NULL AND reviewed_at IS NOT NULL)",
            name="ck_ai_quota_reconciliation_review",
        ),
        Index("ix_ai_quota_reconciliation_reservation", "tenant_id", "region_id", "reservation_id"),
        Index("ix_ai_quota_reconciliation_status", "tenant_id", "region_id", "status", "proposed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    reservation_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_reservations.id", ondelete="RESTRICT"),
    )
    actor: Mapped[str] = mapped_column(String(255))
    period_start: Mapped[date] = mapped_column(Date)
    source_entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_entity_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    source_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    known_tokens_snapshot: Mapped[int] = mapped_column(BigInteger)
    original_charged_tokens: Mapped[int] = mapped_column(BigInteger)
    confirmed_total_tokens: Mapped[int] = mapped_column(BigInteger)
    delta_tokens: Mapped[int] = mapped_column(BigInteger)
    evidence_sha256: Mapped[str] = mapped_column(String(64))
    evidence_reference: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(1000))
    proposed_by_principal_id: Mapped[str] = mapped_column(String(36))
    proposed_by: Mapped[str] = mapped_column(String(255))
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="proposed")
    reviewed_by_principal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AIAuthoringQuotaAdjustment(Base):
    """Append-only counter delta; original model-call receipt stays sealed."""

    __tablename__ = "ai_authoring_quota_adjustments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "reservation_id", name="uq_ai_quota_adjustment_receipt"),
        UniqueConstraint("tenant_id", "region_id", "reconciliation_case_id", name="uq_ai_quota_adjustment_case"),
        CheckConstraint(
            "confirmed_total_tokens >= 0 AND delta_tokens = confirmed_total_tokens - original_charged_tokens",
            name="ck_ai_quota_adjustment_delta",
        ),
        Index("ix_ai_quota_adjustment_period", "tenant_id", "region_id", "period_start"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    reservation_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_reservations.id", ondelete="RESTRICT"),
    )
    reconciliation_case_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_reconciliation_cases.id", ondelete="RESTRICT"),
    )
    actor: Mapped[str] = mapped_column(String(255))
    period_start: Mapped[date] = mapped_column(Date)
    original_charged_tokens: Mapped[int] = mapped_column(BigInteger)
    confirmed_total_tokens: Mapped[int] = mapped_column(BigInteger)
    delta_tokens: Mapped[int] = mapped_column(BigInteger)
    applied_by_principal_id: Mapped[str] = mapped_column(String(36))
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AIAuthoringQuotaSupplementCase(Base):
    """Independently reviewed correction to an already adjusted call."""

    __tablename__ = "ai_authoring_quota_supplement_cases"
    __table_args__ = (
        CheckConstraint("status IN ('proposed', 'applied', 'rejected')", name="ck_ai_quota_supplement_case_status"),
        CheckConstraint(
            "sequence > 0 AND previous_total_tokens >= 0 AND "
            "confirmed_total_tokens >= 0 AND delta_tokens = confirmed_total_tokens - previous_total_tokens",
            name="ck_ai_quota_supplement_case_tokens",
        ),
        CheckConstraint(
            "(status = 'proposed' AND reviewed_by_principal_id IS NULL AND reviewed_at IS NULL) "
            "OR (status != 'proposed' AND reviewed_by_principal_id IS NOT NULL AND reviewed_at IS NOT NULL)",
            name="ck_ai_quota_supplement_case_review",
        ),
        Index("ix_ai_quota_supplement_case_receipt", "tenant_id", "region_id", "reservation_id"),
        Index("ix_ai_quota_supplement_case_status", "tenant_id", "region_id", "status", "proposed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    reservation_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_reservations.id", ondelete="RESTRICT"),
    )
    base_adjustment_id: Mapped[str] = mapped_column(String(36))
    sequence: Mapped[int] = mapped_column(Integer)
    actor: Mapped[str] = mapped_column(String(255))
    period_start: Mapped[date] = mapped_column(Date)
    source_entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_entity_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    source_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    previous_total_tokens: Mapped[int] = mapped_column(BigInteger)
    confirmed_total_tokens: Mapped[int] = mapped_column(BigInteger)
    delta_tokens: Mapped[int] = mapped_column(BigInteger)
    evidence_sha256: Mapped[str] = mapped_column(String(64))
    evidence_reference: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(1000))
    proposed_by_principal_id: Mapped[str] = mapped_column(String(36))
    proposed_by: Mapped[str] = mapped_column(String(255))
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="proposed")
    reviewed_by_principal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AIAuthoringQuotaSupplementAdjustment(Base):
    """Append-only signed delta in the per-receipt correction chain."""

    __tablename__ = "ai_authoring_quota_supplement_adjustments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "reservation_id", "sequence",
                         name="uq_ai_quota_supplement_sequence"),
        UniqueConstraint("tenant_id", "region_id", "supplement_case_id",
                         name="uq_ai_quota_supplement_case"),
        CheckConstraint(
            "sequence > 0 AND previous_total_tokens >= 0 AND "
            "confirmed_total_tokens >= 0 AND delta_tokens = confirmed_total_tokens - previous_total_tokens",
            name="ck_ai_quota_supplement_adjustment_tokens",
        ),
        Index("ix_ai_quota_supplement_period", "tenant_id", "region_id", "period_start"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    reservation_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_reservations.id", ondelete="RESTRICT"),
    )
    supplement_case_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_supplement_cases.id", ondelete="RESTRICT"),
    )
    base_adjustment_id: Mapped[str] = mapped_column(String(36))
    sequence: Mapped[int] = mapped_column(Integer)
    actor: Mapped[str] = mapped_column(String(255))
    period_start: Mapped[date] = mapped_column(Date)
    previous_total_tokens: Mapped[int] = mapped_column(BigInteger)
    confirmed_total_tokens: Mapped[int] = mapped_column(BigInteger)
    delta_tokens: Mapped[int] = mapped_column(BigInteger)
    applied_by_principal_id: Mapped[str] = mapped_column(String(36))
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AIAuthoringQuotaSettlementConflict(Base):
    """One distinct late or contradictory settlement report, never a credit."""

    __tablename__ = "ai_authoring_quota_settlement_conflicts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "region_id", "reservation_id", "reported_known_tokens",
            "reported_external_charge_unknown", name="uq_ai_quota_settlement_conflict_report",
        ),
        CheckConstraint(
            "reported_known_tokens >= 0 AND settled_known_tokens_snapshot >= 0 "
            "AND settled_charged_tokens_snapshot >= 0",
            name="ck_ai_quota_settlement_conflict_tokens",
        ),
        Index(
            "ix_ai_quota_settlement_conflict_recorded",
            "tenant_id", "region_id", "recorded_at", "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    reservation_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_reservations.id", ondelete="RESTRICT"),
    )
    reported_known_tokens: Mapped[int] = mapped_column(BigInteger)
    reported_external_charge_unknown: Mapped[bool] = mapped_column(Boolean)
    settled_known_tokens_snapshot: Mapped[int] = mapped_column(BigInteger)
    settled_external_charge_unknown_snapshot: Mapped[bool] = mapped_column(Boolean)
    settled_charged_tokens_snapshot: Mapped[int] = mapped_column(BigInteger)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AIAuthoringQuotaOrphanCase(Base):
    """Two-person request to conservatively close an abandoned quota hold."""

    __tablename__ = "ai_authoring_quota_orphan_cases"
    __table_args__ = (
        CheckConstraint("status IN ('proposed', 'closed', 'rejected')", name="ck_ai_quota_orphan_case_status"),
        CheckConstraint("reserved_tokens_snapshot > 0", name="ck_ai_quota_orphan_case_tokens"),
        CheckConstraint(
            "(status = 'proposed' AND reviewed_by_principal_id IS NULL AND reviewed_at IS NULL) "
            "OR (status != 'proposed' AND reviewed_by_principal_id IS NOT NULL AND reviewed_at IS NOT NULL)",
            name="ck_ai_quota_orphan_case_review",
        ),
        Index("ix_ai_quota_orphan_case_receipt", "tenant_id", "region_id", "reservation_id"),
        Index("ix_ai_quota_orphan_case_status", "tenant_id", "region_id", "status", "proposed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    reservation_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_reservations.id", ondelete="RESTRICT"),
    )
    actor: Mapped[str] = mapped_column(String(255))
    period_start: Mapped[date] = mapped_column(Date)
    source_entity_type: Mapped[str] = mapped_column(String(64))
    source_entity_id: Mapped[str] = mapped_column(String(36))
    source_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_status_snapshot: Mapped[str] = mapped_column(String(32))
    source_terminal_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reserved_tokens_snapshot: Mapped[int] = mapped_column(BigInteger)
    reason: Mapped[str] = mapped_column(String(1000))
    proposed_by_principal_id: Mapped[str] = mapped_column(String(36))
    proposed_by: Mapped[str] = mapped_column(String(255))
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="proposed")
    reviewed_by_principal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    audit_evidence: Mapped[AIAuthoringQuotaOrphanAuditEvidence | None] = relationship(
        "AIAuthoringQuotaOrphanAuditEvidence", uselist=False, viewonly=True, lazy="selectin",
    )

    @property
    def audited_known_tokens(self) -> int | None:
        return self.audit_evidence.known_tokens if self.audit_evidence is not None else None

    @property
    def audit_event_count(self) -> int | None:
        return self.audit_evidence.event_count if self.audit_evidence is not None else None

    @property
    def audit_sha256(self) -> str | None:
        return self.audit_evidence.audit_sha256 if self.audit_evidence is not None else None


class AIAuthoringQuotaOrphanAuditEvidence(Base):
    """Sealed exact model-audit snapshot for one orphan recovery proposal."""

    __tablename__ = "ai_authoring_quota_orphan_audit_evidence"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "orphan_case_id",
                         name="uq_ai_quota_orphan_audit_case"),
        CheckConstraint("known_tokens >= 0 AND known_tokens <= 1000000000 "
                        "AND event_count >= 0 AND event_count <= 500",
                        name="ck_ai_quota_orphan_audit_usage"),
        CheckConstraint("length(audit_sha256) = 64",
                        name="ck_ai_quota_orphan_audit_digest"),
        Index("ix_ai_quota_orphan_audit_receipt", "tenant_id", "region_id", "reservation_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    reservation_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_reservations.id", ondelete="RESTRICT"),
    )
    orphan_case_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_orphan_cases.id", ondelete="RESTRICT"),
    )
    known_tokens: Mapped[int] = mapped_column(BigInteger)
    event_count: Mapped[int] = mapped_column(Integer)
    audit_sha256: Mapped[str] = mapped_column(String(64))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AIAuthoringQuotaOrphanClosure(Base):
    """Append-only proof that a pending hold became settled-unknown, with no credit."""

    __tablename__ = "ai_authoring_quota_orphan_closures"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "reservation_id", name="uq_ai_quota_orphan_closure_receipt"),
        UniqueConstraint("tenant_id", "region_id", "orphan_case_id", name="uq_ai_quota_orphan_closure_case"),
        CheckConstraint("reserved_tokens > 0", name="ck_ai_quota_orphan_closure_tokens"),
        Index("ix_ai_quota_orphan_closure_period", "tenant_id", "region_id", "period_start"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    reservation_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_reservations.id", ondelete="RESTRICT"),
    )
    orphan_case_id: Mapped[str] = mapped_column(
        ForeignKey("ai_authoring_quota_orphan_cases.id", ondelete="RESTRICT"),
    )
    actor: Mapped[str] = mapped_column(String(255))
    period_start: Mapped[date] = mapped_column(Date)
    reserved_tokens: Mapped[int] = mapped_column(BigInteger)
    closed_by_principal_id: Mapped[str] = mapped_column(String(36))
    closed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AgentProfile(Base):
    __tablename__ = "agent_profiles"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_agent_profile_namespace_name",
        ),
        CheckConstraint(
            "tool_policy IN ('permission_scoped', 'allowlist')",
            name="ck_agent_profile_tool_policy",
        ),
        CheckConstraint(
            "minimum_provider_privacy IN ('external', 'private', 'local')",
            name="ck_agent_profile_provider_privacy",
        ),
        CheckConstraint("max_iterations > 0", name="ck_agent_profile_iterations"),
        CheckConstraint("max_tool_calls > 0", name="ck_agent_profile_tools"),
        CheckConstraint("timeout_seconds > 0", name="ck_agent_profile_timeout"),
        CheckConstraint("token_budget > 0", name="ck_agent_profile_tokens"),
        CheckConstraint("revision > 0", name="ck_agent_profile_revision"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    role_instructions: Mapped[str] = mapped_column(Text)
    escalation_instructions: Mapped[str] = mapped_column(Text, default="")
    route_purpose: Mapped[str] = mapped_column(String(128), index=True)
    tool_policy: Mapped[str] = mapped_column(
        String(32), default="permission_scoped"
    )
    allowed_tool_names: Mapped[list[str]] = mapped_column(JSON, default=list)
    minimum_provider_privacy: Mapped[str] = mapped_column(
        String(16), default="external"
    )
    allowed_data_residencies: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_model_cost_classes: Mapped[list[str]] = mapped_column(
        JSON,
        default=lambda: ["low", "standard", "premium"],
    )
    max_iterations: Mapped[int] = mapped_column(Integer, default=8)
    max_tool_calls: Mapped[int] = mapped_column(Integer, default=20)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)
    token_budget: Mapped[int] = mapped_column(Integer, default=50000)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255))
    updated_by: Mapped[str] = mapped_column(String(255))
    update_reason: Mapped[str] = mapped_column(String(4000))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AgentToolRegistration(Base):
    __tablename__ = "agent_tool_registrations"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_agent_tool_namespace_name",
        ),
        CheckConstraint("timeout_seconds > 0", name="ck_agent_tool_timeout_positive"),
        CheckConstraint(
            "max_result_bytes > 0",
            name="ck_agent_tool_result_bytes_positive",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(Text)
    transport: Mapped[str] = mapped_column(String(32), index=True)
    handler: Mapped[str] = mapped_column(String(512))
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    output_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    risk_level: Mapped[str] = mapped_column(String(32), index=True)
    read_only: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    change_contract: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )
    required_permissions: Mapped[list[str]] = mapped_column(JSON, default=list)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    max_result_bytes: Mapped[int] = mapped_column(Integer, default=1_000_000)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class MCPServer(Base):
    __tablename__ = "mcp_servers"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_mcp_server_namespace_name",
        ),
        CheckConstraint(
            "auth_mode IN ('none', 'credential_profile', 'oauth_authorization_code')",
            name="ck_mcp_server_auth_mode",
        ),
        CheckConstraint(
            "oauth_status IN ('not_configured', 'disconnected', 'connected', "
            "'expired', 'revoked', 'revocation_pending')",
            name="ck_mcp_server_oauth_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128), index=True)
    endpoint_url: Mapped[str] = mapped_column(String(2048))
    protocol_version: Mapped[str] = mapped_column(
        String(32), default="2026-07-28"
    )
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    auth_mode: Mapped[str] = mapped_column(
        String(32), default="none", server_default="none", index=True
    )
    oauth_client_id: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )
    oauth_client_secret_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    oauth_authorization_server: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )
    oauth_requested_scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    oauth_status: Mapped[str] = mapped_column(
        String(32), default="not_configured", server_default="not_configured", index=True
    )
    oauth_issuer: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    oauth_resource: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    oauth_granted_scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    oauth_metadata_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    oauth_access_token_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    oauth_refresh_token_present: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )
    oauth_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    oauth_generation: Mapped[str | None] = mapped_column(String(32), nullable=True)
    oauth_bundle_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    oauth_credential_observation: Mapped[dict | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    oauth_revocation_intent: Mapped[dict | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    oauth_recovery_custody: Mapped[dict | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    oauth_connected_by: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    oauth_connected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    oauth_revoked_by: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    oauth_revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_health_status: Mapped[str | None] = mapped_column(
        String(32), nullable=True, index=True
    )
    last_health_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_tool_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class MCPOAuthTransaction(Base):
    __tablename__ = "mcp_oauth_transactions"
    __namespace_exempt__ = True

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    server_id: Mapped[str] = mapped_column(String(36), index=True)
    oauth_generation: Mapped[str | None] = mapped_column(String(32), nullable=True)
    consent_snapshot: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    browser_token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True
    )
    code_verifier_ciphertext: Mapped[str] = mapped_column(Text)
    issuer: Mapped[str] = mapped_column(String(2048))
    resource: Mapped[str] = mapped_column(String(2048))
    metadata_sha256: Mapped[str] = mapped_column(String(64))
    requested_scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    resource_metadata_url: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )
    scope_challenge_id: Mapped[str | None] = mapped_column(
        ForeignKey("mcp_oauth_scope_challenges.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    return_to: Mapped[str] = mapped_column(String(2048))
    actor_id: Mapped[str] = mapped_column(String(255))
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class MCPOAuthConsentAttempt(Base):
    """One durable code-redemption attempt; never store access/refresh tokens."""
    __tablename__ = "mcp_oauth_consent_attempts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "transaction_id", name="uq_mcp_oauth_consent_transaction"),
        UniqueConstraint("tenant_id", "region_id", "server_id", "generation", name="uq_mcp_oauth_consent_generation"),
        CheckConstraint("status IN ('redemption_admitted','storage_admitted','connected','superseded','outcome_unknown','compensation_pending','compensation_acknowledged','stored_unpublished','revoked')", name="ck_mcp_oauth_consent_status"),
        CheckConstraint("target_version >= 0 AND (stored_version IS NULL OR stored_version = target_version + 1)", name="ck_mcp_oauth_consent_version"),
        CheckConstraint("status NOT IN ('connected','superseded','revoked','stored_unpublished') OR stored_version IS NOT NULL", name="ck_mcp_oauth_consent_receipt"),
        Index("ix_mcp_oauth_consent_history", "tenant_id", "region_id", "server_id", "admitted_at", "id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    # No cascading FK: transaction expiry/server deletion must not erase custody.
    server_id: Mapped[str] = mapped_column(String(36))
    transaction_id: Mapped[str] = mapped_column(String(36))
    generation: Mapped[str] = mapped_column(String(32))
    previous_generation: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32))
    issuer: Mapped[str] = mapped_column(String(2048))
    client_id: Mapped[str] = mapped_column(String(2048))
    resource: Mapped[str] = mapped_column(String(2048))
    snapshot: Mapped[dict] = mapped_column(JSON)
    target: Mapped[dict] = mapped_column(JSON)
    target_version: Mapped[int] = mapped_column(Integer)
    stored_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor_id: Mapped[str] = mapped_column(String(255))
    admitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    refresh_token_received: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    family_recovery_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    family_contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MCPOAuthFamilyRecovery(Base):
    """Retained exact-transaction issuer proof, not local Vault cleanup authority."""
    __tablename__ = "mcp_oauth_family_recoveries"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "attempt_id", name="uq_mcp_family_recovery_attempt"),
        CheckConstraint("status IN ('awaiting_evidence','issuer_verified')", name="ck_mcp_family_recovery_status"),
        CheckConstraint("(status='awaiting_evidence' AND proof IS NULL AND reviewed_by IS NULL AND reviewed_at IS NULL AND proposal_id IS NULL AND verification_tool_call_id IS NULL) OR (status='issuer_verified' AND proof IS NOT NULL AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL AND proposal_id IS NOT NULL AND verification_tool_call_id IS NOT NULL AND reviewed_by<>initiated_by AND reviewed_at>=initiated_at)", name="ck_mcp_family_recovery_review"),
        Index("ix_mcp_family_recovery_history", "tenant_id", "region_id", "server_id", "initiated_at", "id"),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    attempt_id: Mapped[str] = mapped_column(ForeignKey("mcp_oauth_consent_attempts.id", ondelete="RESTRICT"))
    server_id: Mapped[str] = mapped_column(String(36))
    generation: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="awaiting_evidence")
    snapshot: Mapped[dict] = mapped_column(JSON)
    initiated_by: Mapped[str] = mapped_column(String(36))
    initiated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reviewed_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    proposal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    verification_tool_call_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    proof: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), nullable=True)


class MCPOAuthFamilyLocalExecution(Base):
    """Original issuer proof and local plan with monotonic, secret-free receipts."""
    __tablename__ = "mcp_oauth_family_local_executions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "recovery_id", name="uq_mcp_family_local_recovery"),
        CheckConstraint("status IN ('admitted','fenced','complete')", name="ck_mcp_family_local_status"),
        CheckConstraint("(status='admitted' AND receipt IS NULL AND completion IS NULL AND completed_at IS NULL) OR (status='fenced' AND receipt IS NOT NULL AND completion IS NULL AND completed_at IS NULL) OR (status='complete' AND receipt IS NOT NULL AND completion IS NOT NULL AND completed_at IS NOT NULL)", name="ck_mcp_family_local_receipts"),
        CheckConstraint("auth_method IN ('bearer','browser_session')", name="ck_mcp_family_local_human"),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    recovery_id: Mapped[str] = mapped_column(ForeignKey("mcp_oauth_family_recoveries.id", ondelete="RESTRICT"))
    plan: Mapped[dict] = mapped_column(JSON)
    proof: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="admitted")
    admitted_by: Mapped[str] = mapped_column(String(36))
    auth_method: Mapped[str] = mapped_column(String(32))
    credential_id: Mapped[str] = mapped_column(String(36))
    admitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    receipt: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    deleted_versions: Mapped[list] = mapped_column(JSON, default=list)
    completion: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MCPOAuthFamilyLocalMutation(Base):
    """Append-only current-human decision committed before external mutation I/O."""
    __tablename__ = "mcp_oauth_family_local_mutations"
    __table_args__ = (
        CheckConstraint("phase IN ('reserve','delete_version','restore','delete_reservation')", name="ck_mcp_family_mutation_phase"),
        CheckConstraint("version BETWEEN 0 AND 2147483647", name="ck_mcp_family_mutation_version"),
        CheckConstraint("auth_method IN ('bearer','browser_session')", name="ck_mcp_family_mutation_human"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(ForeignKey("mcp_oauth_family_local_executions.id", ondelete="RESTRICT"), index=True)
    phase: Mapped[str] = mapped_column(String(24))
    version: Mapped[int] = mapped_column(Integer)
    authorized_by: Mapped[str] = mapped_column(String(36))
    auth_method: Mapped[str] = mapped_column(String(32))
    credential_id: Mapped[str] = mapped_column(String(36))
    admitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MCPOAuthScopeChallenge(Base):
    __tablename__ = "mcp_oauth_scope_challenges"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'authorizing', 'resolved')",
            name="ck_mcp_oauth_scope_challenge_status",
        ),
        CheckConstraint(
            "occurrence_count > 0 AND revision > 0",
            name="ck_mcp_oauth_scope_challenge_counters",
        ),
        Index(
            "uq_mcp_oauth_scope_challenge_active_tool",
            "tenant_id",
            "region_id",
            "server_id",
            "tool_name",
            unique=True,
            postgresql_where=text("status IN ('pending', 'authorizing')"),
            sqlite_where=text("status IN ('pending', 'authorizing')"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    server_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_servers.id", ondelete="CASCADE"), index=True
    )
    activation_id: Mapped[str | None] = mapped_column(
        ForeignKey("mcp_tool_activations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    investigation_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(String(255), index=True)
    challenged_scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    requested_scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    resource_metadata_url: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(16), default="pending", server_default="pending", index=True
    )
    occurrence_count: Mapped[int] = mapped_column(
        Integer, default=1, server_default="1"
    )
    revision: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approval_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    allowlist_expanded: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class MCPToolAttestation(Base):
    __tablename__ = "mcp_tool_attestations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'processing', 'passed', 'failed', "
            "'dead_letter', 'consumed')",
            name="ck_mcp_tool_attestation_status",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND max_attempts > 0",
            name="ck_mcp_tool_attestation_attempts",
        ),
        Index(
            "ix_mcp_tool_attestation_queue",
            "status",
            "next_attempt_at",
            "lease_expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    server_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_servers.id", ondelete="RESTRICT"), index=True
    )
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[str] = mapped_column(
        String(24), default="pending", server_default="pending", index=True
    )
    tool_name: Mapped[str] = mapped_column(String(255), index=True)
    mcp_tool_name: Mapped[str] = mapped_column(String(255))
    expected_server_config_sha256: Mapped[str] = mapped_column(String(64))
    expected_artifact_content_hash: Mapped[str] = mapped_column(String(64))
    expected_contract_sha256: Mapped[str] = mapped_column(String(64))
    expected_input_schema_sha256: Mapped[str] = mapped_column(String(64))
    expected_output_schema_sha256: Mapped[str] = mapped_column(String(64))
    credential_profile_id: Mapped[str | None] = mapped_column(
        ForeignKey("credential_profiles.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    credential_profile_revision: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    requested_by: Mapped[str] = mapped_column(String(255))
    request_reason: Mapped[str] = mapped_column(Text)
    worker_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_workers.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    lease_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    advertised_tool_count: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    catalog_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    remote_contract_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    failure_code: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    failure_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    attested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    consumed_by_activation_id: Mapped[str | None] = mapped_column(
        ForeignKey("mcp_tool_activations.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class MCPToolActivation(Base):
    __tablename__ = "mcp_tool_activations"
    __table_args__ = (
        UniqueConstraint(
            "artifact_version_id",
            name="uq_mcp_tool_activation_artifact_version",
        ),
        CheckConstraint(
            "status IN ('active', 'inactive')",
            name="ck_mcp_tool_activation_status",
        ),
        CheckConstraint(
            "rollout_state IN ('canary', 'full', 'blocked')",
            name="ck_mcp_tool_activation_rollout_state",
        ),
        CheckConstraint(
            "circuit_state IN ('closed', 'open')",
            name="ck_mcp_tool_activation_circuit_state",
        ),
        CheckConstraint(
            "traffic_percent > 0 AND traffic_percent <= 100",
            name="ck_mcp_tool_activation_traffic_percent",
        ),
        CheckConstraint(
            "minimum_successful_calls > 0 AND maximum_failed_calls >= 0 "
            "AND circuit_failure_threshold > 0",
            name="ck_mcp_tool_activation_health_thresholds",
        ),
        CheckConstraint(
            "successful_calls >= 0 AND failed_calls >= 0 "
            "AND consecutive_failures >= 0 AND revision > 0",
            name="ck_mcp_tool_activation_health_counters",
        ),
        Index(
            "uq_mcp_tool_active_name",
            "tenant_id",
            "region_id",
            "tool_name",
            unique=True,
            postgresql_where=text("status = 'active'"),
            sqlite_where=text("status = 'active'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    server_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_servers.id", ondelete="RESTRICT"), index=True
    )
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    tool_registration_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tool_registrations.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    tool_name: Mapped[str] = mapped_column(String(255), index=True)
    mcp_tool_name: Mapped[str] = mapped_column(String(255))
    contract_sha256: Mapped[str] = mapped_column(String(64))
    input_schema_sha256: Mapped[str] = mapped_column(String(64))
    output_schema_sha256: Mapped[str] = mapped_column(String(64))
    rollout_state: Mapped[str] = mapped_column(
        String(16), default="full", server_default="full", index=True
    )
    traffic_percent: Mapped[int] = mapped_column(
        Integer, default=100, server_default="100"
    )
    minimum_successful_calls: Mapped[int] = mapped_column(
        Integer, default=3, server_default="3"
    )
    maximum_failed_calls: Mapped[int] = mapped_column(
        Integer, default=1, server_default="1"
    )
    circuit_failure_threshold: Mapped[int] = mapped_column(
        Integer, default=3, server_default="3"
    )
    successful_calls: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0"
    )
    failed_calls: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0"
    )
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0"
    )
    circuit_state: Mapped[str] = mapped_column(
        String(16), default="closed", server_default="closed", index=True
    )
    last_call_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failure_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failure_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    circuit_opened_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    promoted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    promoted_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    promotion_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    revision: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    activated_by: Mapped[str] = mapped_column(String(255))
    activation_reason: Mapped[str] = mapped_column(Text)
    attested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    deactivated_by: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    deactivation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    deactivated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        Index(
            "ix_investigations_history",
            "tenant_id", "region_id", "created_at", "id",
        ),
        CheckConstraint("max_iterations > 0", name="ck_investigation_iterations_positive"),
        CheckConstraint("max_tool_calls > 0", name="ck_investigation_tools_positive"),
        CheckConstraint("timeout_seconds > 0", name="ck_investigation_timeout_positive"),
        CheckConstraint("token_budget > 0", name="ck_investigation_tokens_positive"),
        CheckConstraint("iterations_used >= 0", name="ck_investigation_iterations_used"),
        CheckConstraint("tool_calls_used >= 0", name="ck_investigation_tools_used"),
        CheckConstraint("tokens_used >= 0", name="ck_investigation_tokens_used"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(255))
    objective: Mapped[str] = mapped_column(Text)
    execution_mode: Mapped[str] = mapped_column(String(24), default="standard", server_default="standard")
    parent_investigation_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT"), nullable=True, index=True)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    route_id: Mapped[str] = mapped_column(
        ForeignKey("ai_model_routes.id", ondelete="RESTRICT"), index=True
    )
    model_id: Mapped[str] = mapped_column(
        ForeignKey("ai_model_configs.id", ondelete="RESTRICT"), index=True
    )
    fallback_model_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    agent_profile_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_profiles.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    agent_profile_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
    )
    max_iterations: Mapped[int] = mapped_column(Integer)
    max_tool_calls: Mapped[int] = mapped_column(Integer)
    timeout_seconds: Mapped[int] = mapped_column(Integer)
    token_budget: Mapped[int] = mapped_column(Integer)
    iterations_used: Mapped[int] = mapped_column(Integer, default=0)
    tool_calls_used: Mapped[int] = mapped_column(Integer, default=0)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    conclusion: Mapped[str | None] = mapped_column(Text, nullable=True)
    uncertainty: Mapped[list[str]] = mapped_column(JSON, default=list)
    escalation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    situation_id: Mapped[str | None] = mapped_column(
        ForeignKey("situations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    skill_artifact_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    skill_input: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    skill_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    structured_output: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    workflow_artifact_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    workflow_input: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    workflow_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    workflow_trigger_event_id: Mapped[str | None] = mapped_column(
        ForeignKey("workflow_trigger_events.id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
        index=True,
    )
    workflow_schedule_event_id: Mapped[str | None] = mapped_column(
        ForeignKey("workflow_schedule_events.id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
        index=True,
    )
    situation_integration_event_id: Mapped[str | None] = mapped_column(
        ForeignKey("situation_integration_events.id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
        index=True,
    )
    requested_by_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    permission_snapshot: Mapped[list[str]] = mapped_column(JSON, default=list)
    authorization_scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(255))
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AlertInvestigationPolicy(Base):
    """One standing, read-only investigation policy per security namespace."""
    __tablename__ = "alert_investigation_policies"
    __table_args__ = (UniqueConstraint("tenant_id", "region_id", name="uq_alert_investigation_policy_namespace"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    severities: Mapped[list[str]] = mapped_column(JSON, default=list)
    daily_limit: Mapped[int] = mapped_column(Integer, default=20)
    max_concurrent: Mapped[int] = mapped_column(Integer, default=2)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=1800)
    max_alert_age_seconds: Mapped[int] = mapped_column(Integer, default=900)
    paused_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    authorized_by_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), nullable=True)
    updated_by: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    dispatcher_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dispatcher_status: Mapped[str] = mapped_column(String(32), default="not_seen")


class AlertInvestigationEvent(Base):
    __tablename__ = "alert_investigation_events"
    __table_args__ = (UniqueConstraint("tenant_id", "region_id", "alert_id", name="uq_alert_investigation_event"),
        Index("ix_alert_investigation_group", "tenant_id", "region_id", "group_key", "created_at"),
        Index("ix_alert_investigation_run", "tenant_id", "region_id", "investigation_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    policy_id: Mapped[str] = mapped_column(ForeignKey("alert_investigation_policies.id", ondelete="RESTRICT"))
    policy_revision: Mapped[int] = mapped_column(Integer)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="RESTRICT"))
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id", ondelete="RESTRICT"), nullable=True)
    group_key: Mapped[str] = mapped_column(String(600))
    status: Mapped[str] = mapped_column(String(24))
    reason: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InvestigationCapabilityRequest(Base):
    __tablename__ = "investigation_capability_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="RESTRICT"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    suggested_tools: Mapped[list[str]] = mapped_column(JSON, default=list)
    studio_session_id: Mapped[str | None] = mapped_column(ForeignKey("capability_studio_sessions.id", ondelete="RESTRICT"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InvestigationCheckpoint(Base):
    __tablename__ = "investigation_checkpoints"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "sequence",
            name="uq_investigation_checkpoint_sequence",
        ),
        CheckConstraint("sequence > 0", name="ck_investigation_checkpoint_sequence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    sequence: Mapped[int] = mapped_column(Integer)
    node: Mapped[str] = mapped_column(String(128), index=True)
    state: Mapped[dict[str, Any]] = mapped_column(JSON)
    state_hash: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InvestigationEvidence(Base):
    __tablename__ = "investigation_evidence"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "evidence_type",
            "evidence_id",
            name="uq_investigation_evidence_reference",
        ),
        CheckConstraint(
            "(evidence_type = 'service_report_instance' AND report_instance_id IS NOT NULL "
            "AND report_instance_id = evidence_id) "
            "OR (evidence_type <> 'service_report_instance' AND report_instance_id IS NULL)",
            name="ck_investigation_evidence_report_instance_ref",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    evidence_type: Mapped[str] = mapped_column(String(64), index=True)
    evidence_id: Mapped[str] = mapped_column(String(512), index=True)
    report_instance_id: Mapped[str | None] = mapped_column(
        ForeignKey("service_report_instances.id", ondelete="RESTRICT"),
        nullable=True, index=True,
    )
    summary: Mapped[str] = mapped_column(Text)
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InvestigationTopologyProposal(Base):
    __tablename__ = "investigation_topology_proposals"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            name="uq_investigation_topology_proposal_investigation",
        ),
        CheckConstraint(
            "status IN ('proposed', 'published', 'rejected')",
            name="ck_investigation_topology_proposal_status",
        ),
        Index(
            "ix_investigation_topology_proposal_queue",
            "status",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    checkpoint_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_checkpoints.id", ondelete="CASCADE"),
        index=True,
    )
    contract_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="proposed", index=True)
    rationale: Mapped[str] = mapped_column(Text)
    spec: Mapped[dict[str, Any]] = mapped_column(JSON)
    validation_report: Mapped[dict[str, Any]] = mapped_column(JSON)
    uncertainty: Mapped[list[str]] = mapped_column(JSON, default=list)
    authorization_scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_model_id: Mapped[str] = mapped_column(String(36))
    created_by: Mapped[str] = mapped_column(String(255))
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    artifact_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    evidence_links: Mapped[list[InvestigationTopologyProposalEvidence]] = relationship(
        back_populates="proposal",
        cascade="all, delete-orphan",
        order_by="InvestigationTopologyProposalEvidence.created_at",
    )


class InvestigationTopologyProposalEvidence(Base):
    __tablename__ = "investigation_topology_proposal_evidence"
    __table_args__ = (
        UniqueConstraint(
            "proposal_id",
            "investigation_evidence_id",
            name="uq_investigation_topology_proposal_evidence",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    proposal_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_topology_proposals.id", ondelete="CASCADE"),
        index=True,
    )
    investigation_evidence_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_evidence.id", ondelete="CASCADE"),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    proposal: Mapped[InvestigationTopologyProposal] = relationship(
        back_populates="evidence_links"
    )
    evidence: Mapped[InvestigationEvidence] = relationship()


class InvestigationVisualizationProposal(Base):
    __tablename__ = "investigation_visualization_proposals"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            name="uq_investigation_visualization_proposal_investigation",
        ),
        CheckConstraint(
            "status IN ('proposed', 'published', 'rejected')",
            name="ck_investigation_visualization_proposal_status",
        ),
        Index(
            "ix_investigation_visualization_proposal_queue",
            "status",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    checkpoint_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_checkpoints.id", ondelete="CASCADE"),
        index=True,
    )
    contract_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="proposed", index=True)
    rationale: Mapped[str] = mapped_column(Text)
    spec: Mapped[dict[str, Any]] = mapped_column(JSON)
    validation_report: Mapped[dict[str, Any]] = mapped_column(JSON)
    uncertainty: Mapped[list[str]] = mapped_column(JSON, default=list)
    authorization_scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_model_id: Mapped[str] = mapped_column(String(36))
    created_by: Mapped[str] = mapped_column(String(255))
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    artifact_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    evidence_links: Mapped[list[InvestigationVisualizationProposalEvidence]] = (
        relationship(
            back_populates="proposal",
            cascade="all, delete-orphan",
            order_by="InvestigationVisualizationProposalEvidence.created_at",
        )
    )


class InvestigationVisualizationProposalEvidence(Base):
    __tablename__ = "investigation_visualization_proposal_evidence"
    __table_args__ = (
        UniqueConstraint(
            "proposal_id",
            "investigation_evidence_id",
            name="uq_investigation_visualization_proposal_evidence",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    proposal_id: Mapped[str] = mapped_column(
        ForeignKey(
            "investigation_visualization_proposals.id",
            ondelete="CASCADE",
        ),
        index=True,
    )
    investigation_evidence_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_evidence.id", ondelete="CASCADE"),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    proposal: Mapped[InvestigationVisualizationProposal] = relationship(
        back_populates="evidence_links"
    )
    evidence: Mapped[InvestigationEvidence] = relationship()


class SituationHypothesis(Base):
    __tablename__ = "situation_hypotheses"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "statement_hash",
            name="uq_situation_hypothesis_investigation_statement",
        ),
        CheckConstraint(
            "status IN ('candidate', 'proposed', 'accepted', 'rejected', 'superseded')",
            name="ck_situation_hypothesis_status",
        ),
        CheckConstraint(
            "current_confidence >= 0 AND current_confidence <= 1",
            name="ck_situation_hypothesis_confidence",
        ),
        CheckConstraint(
            "revision_count >= 0",
            name="ck_situation_hypothesis_revision_count",
        ),
        Index(
            "ix_situation_hypothesis_queue",
            "situation_id",
            "status",
            "current_confidence",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    situation_id: Mapped[str] = mapped_column(
        ForeignKey("situations.id", ondelete="CASCADE"), index=True
    )
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    statement_hash: Mapped[str] = mapped_column(String(64), index=True)
    statement: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(16), default="candidate", index=True
    )
    current_confidence: Mapped[float] = mapped_column(Float)
    revision_count: Mapped[int] = mapped_column(Integer, default=0)
    source_model_id: Mapped[str] = mapped_column(String(36))
    created_by: Mapped[str] = mapped_column(String(255))
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    situation: Mapped[Situation] = relationship(back_populates="hypotheses")
    revisions: Mapped[list[SituationHypothesisRevision]] = relationship(
        back_populates="hypothesis",
        cascade="all, delete-orphan",
        order_by="SituationHypothesisRevision.revision",
    )


class SituationHypothesisRevision(Base):
    __tablename__ = "situation_hypothesis_revisions"
    __table_args__ = (
        UniqueConstraint(
            "hypothesis_id",
            "checkpoint_id",
            name="uq_situation_hypothesis_checkpoint",
        ),
        UniqueConstraint(
            "hypothesis_id",
            "revision",
            name="uq_situation_hypothesis_revision",
        ),
        CheckConstraint("revision > 0", name="ck_situation_hypothesis_revision"),
        CheckConstraint("iteration >= 0", name="ck_situation_hypothesis_iteration"),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_situation_hypothesis_revision_confidence",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    hypothesis_id: Mapped[str] = mapped_column(
        ForeignKey("situation_hypotheses.id", ondelete="CASCADE"), index=True
    )
    checkpoint_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_checkpoints.id", ondelete="CASCADE"), index=True
    )
    revision: Mapped[int] = mapped_column(Integer)
    iteration: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    hypothesis: Mapped[SituationHypothesis] = relationship(
        back_populates="revisions"
    )
    evidence_links: Mapped[list[SituationHypothesisEvidence]] = relationship(
        back_populates="revision",
        cascade="all, delete-orphan",
    )


class SituationHypothesisEvidence(Base):
    __tablename__ = "situation_hypothesis_evidence"
    __table_args__ = (
        UniqueConstraint(
            "revision_id",
            "investigation_evidence_id",
            name="uq_situation_hypothesis_evidence",
        ),
        CheckConstraint(
            "stance IN ('supporting', 'contradicting')",
            name="ck_situation_hypothesis_evidence_stance",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    revision_id: Mapped[str] = mapped_column(
        ForeignKey("situation_hypothesis_revisions.id", ondelete="CASCADE"),
        index=True,
    )
    investigation_evidence_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_evidence.id", ondelete="CASCADE"), index=True
    )
    stance: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    revision: Mapped[SituationHypothesisRevision] = relationship(
        back_populates="evidence_links"
    )
    evidence: Mapped[InvestigationEvidence] = relationship()


class SituationImpactAssessment(Base):
    __tablename__ = "situation_impact_assessments"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            name="uq_situation_impact_assessment_investigation",
        ),
        CheckConstraint(
            "status IN ('proposed', 'accepted', 'rejected')",
            name="ck_situation_impact_assessment_status",
        ),
        CheckConstraint(
            "impact_level IN ('unknown', 'none', 'low', 'medium', 'high', 'critical')",
            name="ck_situation_impact_assessment_level",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_situation_impact_assessment_confidence",
        ),
        Index(
            "ix_situation_impact_assessment_queue",
            "situation_id",
            "status",
            "impact_level",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    situation_id: Mapped[str] = mapped_column(
        ForeignKey("situations.id", ondelete="CASCADE"), index=True
    )
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        index=True,
    )
    checkpoint_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_checkpoints.id", ondelete="CASCADE"), index=True
    )
    contract_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="proposed", index=True)
    impact_level: Mapped[str] = mapped_column(String(16), index=True)
    summary: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    affected_node_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    uncertainty: Mapped[list[str]] = mapped_column(JSON, default=list)
    service_context_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list
    )
    dependency_context_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list
    )
    indicator_context_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list
    )
    source_model_id: Mapped[str] = mapped_column(String(36))
    created_by: Mapped[str] = mapped_column(String(255))
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    situation: Mapped[Situation] = relationship(back_populates="impact_assessments")
    evidence_links: Mapped[list[SituationImpactAssessmentEvidence]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
    )


class SituationImpactAssessmentEvidence(Base):
    __tablename__ = "situation_impact_assessment_evidence"
    __table_args__ = (
        UniqueConstraint(
            "assessment_id",
            "investigation_evidence_id",
            name="uq_situation_impact_assessment_evidence",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("situation_impact_assessments.id", ondelete="CASCADE"),
        index=True,
    )
    investigation_evidence_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_evidence.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    assessment: Mapped[SituationImpactAssessment] = relationship(
        back_populates="evidence_links"
    )
    evidence: Mapped[InvestigationEvidence] = relationship()


class InvestigationToolCall(Base):
    __tablename__ = "investigation_tool_calls"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "call_hash",
            name="uq_investigation_tool_call_hash",
        ),
        CheckConstraint("iteration > 0", name="ck_investigation_tool_iteration"),
        CheckConstraint(
            "(artifact_version_id IS NULL AND artifact_content_hash IS NULL AND artifact_activation_id IS NULL AND artifact_activation_sha256 IS NULL) OR "
            "(artifact_version_id IS NOT NULL AND artifact_content_hash IS NOT NULL AND artifact_activation_id IS NOT NULL AND artifact_activation_sha256 IS NOT NULL)",
            name="ck_tool_call_artifact_provenance",
        ),
        CheckConstraint("(governed_change_plan_id IS NULL AND governed_stage IS NULL) OR (governed_change_plan_id IS NOT NULL AND governed_stage IS NOT NULL AND governed_stage IN ('precheck', 'dry_run', 'postcheck', 'rollback_check'))", name="ck_tool_call_governed_stage"),
        UniqueConstraint("governed_change_plan_id", "governed_stage", name="uq_tool_call_governed_stage"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    tool_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tool_registrations.id", ondelete="RESTRICT"), index=True
    )
    # Captured before execution, never reconstructed from today's mutable registry.
    artifact_version_id: Mapped[str | None] = mapped_column(ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=True, index=True)
    artifact_content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    artifact_activation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    artifact_activation_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    governed_change_plan_id: Mapped[str | None] = mapped_column(ForeignKey("governed_change_plans.id", ondelete="RESTRICT", use_alter=True, name="fk_tool_call_governed_plan"), nullable=True, index=True)
    governed_stage: Mapped[str | None] = mapped_column(String(16), nullable=True)
    iteration: Mapped[int] = mapped_column(Integer)
    call_hash: Mapped[str] = mapped_column(String(64))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(32), default="proposed", index=True)
    result: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(
        JSON, nullable=True
    )
    result_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InvestigationToolEvidenceBinding(Base):
    """An exact terminal result's immutable, minimized citation association."""
    __tablename__ = "investigation_tool_evidence_bindings"
    __table_args__ = (
        UniqueConstraint("tool_call_id", name="uq_tool_evidence_binding_call"),
        CheckConstraint("length(CAST(call_snapshot AS TEXT)) <= 4096", name="ck_tool_binding_call_size"),
        CheckConstraint("length(CAST(reference_snapshot AS TEXT)) <= 1048576", name="ck_tool_binding_reference_size"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT"), index=True)
    tool_call_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), index=True)
    call_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    reference_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentActionProposal(Base):
    __tablename__ = "agent_action_proposals"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "plan_hash",
            name="uq_agent_action_proposal_plan",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    tool_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tool_registrations.id", ondelete="RESTRICT"), index=True
    )
    tool_call_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
    )
    rollback_of_change_plan_id: Mapped[str | None] = mapped_column(
        ForeignKey(
            "governed_change_plans.id",
            name="fk_agent_action_proposal_rollback_change_plan",
            ondelete="SET NULL",
            use_alter=True,
        ),
        nullable=True,
        index=True,
    )
    iteration: Mapped[int] = mapped_column(Integer)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON)
    purpose: Mapped[str] = mapped_column(Text)
    plan_hash: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    requested_by_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    requested_by: Mapped[str] = mapped_column(String(255))
    approved_by_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    execution_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    execution_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class MCPWriteReconciliationObservation(Base):
    """Append-only lookup evidence; it never changes the original Tool outcome."""

    __tablename__ = "mcp_write_reconciliation_observations"
    __table_args__ = (
        UniqueConstraint("lookup_tool_call_id", name="uq_mcp_write_recon_lookup_call"),
        CheckConstraint(
            "provider_outcome IN ('applied', 'not_applied', 'unknown')",
            name="ck_mcp_write_recon_outcome",
        ),
        CheckConstraint("length(reason) BETWEEN 10 AND 1000", name="ck_mcp_write_recon_reason"),
        Index("ix_mcp_write_recon_proposal", "tenant_id", "region_id", "proposal_id", "created_at"),
        Index("ix_mcp_write_recon_recorded_by", "recorded_by_principal_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    proposal_id: Mapped[str] = mapped_column(
        ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), index=True
    )
    original_tool_call_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), index=True
    )
    lookup_tool_call_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), index=True
    )
    provider_outcome: Mapped[str] = mapped_column(String(16))
    provider_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lookup_result_hash: Mapped[str] = mapped_column(String(64))
    recorded_by_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), nullable=True
    )
    recorded_by: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MCPWriteReconciliationReview(Base):
    """Independent review of lookup evidence, not a decision on the original write."""

    __tablename__ = "mcp_write_reconciliation_reviews"
    __table_args__ = (
        UniqueConstraint("observation_id", name="uq_mcp_write_recon_review_observation"),
        CheckConstraint(
            "decision IN ('accept', 'reject', 'inconclusive')",
            name="ck_mcp_write_recon_review_decision",
        ),
        CheckConstraint(
            "length(reason) BETWEEN 10 AND 1000",
            name="ck_mcp_write_recon_review_reason",
        ),
        Index("ix_mcp_write_recon_review_proposal", "tenant_id", "region_id", "proposal_id", "reviewed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    proposal_id: Mapped[str] = mapped_column(
        ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), index=True
    )
    observation_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_write_reconciliation_observations.id", ondelete="RESTRICT"), index=True
    )
    decision: Mapped[str] = mapped_column(String(16))
    reviewed_by_principal_id: Mapped[str] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), index=True
    )
    reviewed_by: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(1000))
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MCPWriteIndependentObservation(Base):
    """Append-only target evidence; the original MCP write stays unresolved."""

    __tablename__ = "mcp_write_independent_observations"
    __table_args__ = (
        UniqueConstraint("verification_tool_call_id", name="uq_mcp_write_independent_call"),
        CheckConstraint(
            "verification_kind IN ('target_state', 'recipient_receipt')",
            name="ck_mcp_write_independent_kind",
        ),
        CheckConstraint(
            "observed_target_state IN ('present', 'absent', 'unknown')",
            name="ck_mcp_write_independent_state",
        ),
        CheckConstraint("bound_value_count BETWEEN 1 AND 16", name="ck_mcp_write_independent_bindings"),
        CheckConstraint("length(reason) BETWEEN 10 AND 1000", name="ck_mcp_write_independent_reason"),
        Index("ix_mcp_write_independent_proposal", "tenant_id", "region_id", "proposal_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    proposal_id: Mapped[str] = mapped_column(
        ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), index=True
    )
    original_tool_call_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), index=True
    )
    verification_tool_call_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), index=True
    )
    verification_kind: Mapped[str] = mapped_column(String(32))
    observed_target_state: Mapped[str] = mapped_column(String(16))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    evidence_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    bound_value_count: Mapped[int] = mapped_column(Integer)
    verification_result_hash: Mapped[str] = mapped_column(String(64))
    recorded_by_principal_id: Mapped[str] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), index=True
    )
    recorded_by: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MCPWriteIndependentReview(Base):
    """A second person's decision on evidence admissibility, not write outcome."""

    __tablename__ = "mcp_write_independent_reviews"
    __table_args__ = (
        UniqueConstraint("observation_id", name="uq_mcp_write_independent_review_observation"),
        CheckConstraint(
            "decision IN ('accept', 'reject', 'inconclusive')",
            name="ck_mcp_write_independent_review_decision",
        ),
        CheckConstraint("length(reason) BETWEEN 10 AND 1000", name="ck_mcp_write_independent_review_reason"),
        Index("ix_mcp_write_independent_review_proposal", "tenant_id", "region_id", "proposal_id", "reviewed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    proposal_id: Mapped[str] = mapped_column(
        ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), index=True
    )
    observation_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_write_independent_observations.id", ondelete="RESTRICT"), index=True
    )
    decision: Mapped[str] = mapped_column(String(16))
    reviewed_by_principal_id: Mapped[str] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), index=True
    )
    reviewed_by: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(1000))
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MCPWriteDisposition(Base):
    """Append-only unresolved-write custody; never alters the original Tool result."""

    __tablename__ = "mcp_write_dispositions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "request_id", name="uq_mcp_write_disposition_request"),
        CheckConstraint("decision = 'unresolved'", name="ck_mcp_write_disposition_unresolved"),
        CheckConstraint("length(reason) BETWEEN 10 AND 1000", name="ck_mcp_write_disposition_reason"),
        Index("ix_mcp_write_disposition_proposal", "tenant_id", "region_id", "proposal_id", "recorded_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(String(36))
    proposal_id: Mapped[str] = mapped_column(
        ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), index=True
    )
    original_tool_call_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), index=True
    )
    decision: Mapped[str] = mapped_column(String(24), default="unresolved")
    plan_hash: Mapped[str] = mapped_column(String(64))
    evidence_refs: Mapped[dict[str, Any]] = mapped_column(JSON)
    reviewed_by_principal_id: Mapped[str] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), index=True
    )
    reviewed_by: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(1000))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def _immutable_mcp_write_disposition(_mapper, _connection, _target):
    raise ValueError("MCP write dispositions are append-only")


event.listen(MCPWriteDisposition, "before_update", _immutable_mcp_write_disposition)
event.listen(MCPWriteDisposition, "before_delete", _immutable_mcp_write_disposition)


class ChangeRiskPolicy(Base):
    __tablename__ = "change_risk_policies"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "risk_class",
            name="uq_change_risk_policy_namespace_class",
        ),
        CheckConstraint(
            "risk_class IN ('low', 'medium', 'high', 'critical')",
            name="ck_change_risk_policy_risk_class",
        ),
        CheckConstraint("revision > 0", name="ck_change_risk_policy_revision"),
        CheckConstraint(
            "max_window_minutes >= 5 AND max_window_minutes <= 480",
            name="ck_change_risk_policy_max_window",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    risk_class: Mapped[str] = mapped_column(String(16), index=True)
    execution_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    maintenance_window_required: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )
    max_window_minutes: Mapped[int] = mapped_column(Integer, default=120)
    require_evidence_summary: Mapped[bool] = mapped_column(Boolean, default=False)
    require_authorization_binding: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )
    revision: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str] = mapped_column(String(255))
    update_reason: Mapped[str] = mapped_column(String(4000))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ChangePreapprovalPolicy(Base):
    """Reviewed, exact-scope automation envelope; review alone grants no execution."""

    __tablename__ = "change_preapproval_policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "name", name="uq_change_preapproval_namespace_name"),
        CheckConstraint("status IN ('draft', 'reviewed', 'revoked')", name="ck_change_preapproval_status"),
        CheckConstraint("revision > 0", name="ck_change_preapproval_revision"),
        CheckConstraint("max_alert_age_seconds BETWEEN 60 AND 3600", name="ck_change_preapproval_alert_age"),
        CheckConstraint("max_evidence_age_seconds BETWEEN 60 AND 3600", name="ck_change_preapproval_evidence_age"),
        CheckConstraint("max_actions_per_alert BETWEEN 1 AND 3", name="ck_change_preapproval_action_limit"),
        Index("ix_change_preapproval_lookup", "tenant_id", "region_id", "tool_artifact_version_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="draft", server_default="draft")
    tool_artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    tool_content_hash: Mapped[str] = mapped_column(String(64))
    target_device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"), index=True)
    target_site: Mapped[str] = mapped_column(String(128))
    alert_event_type: Mapped[str] = mapped_column(String(128))
    arguments_template: Mapped[dict[str, Any]] = mapped_column(JSON)
    max_alert_age_seconds: Mapped[int] = mapped_column(Integer, default=300)
    max_evidence_age_seconds: Mapped[int] = mapped_column(Integer, default=300, server_default="300")
    max_actions_per_alert: Mapped[int] = mapped_column(Integer, default=1)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255))
    created_by_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="SET NULL"), nullable=True
    )
    updated_by: Mapped[str] = mapped_column(String(255))
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_by_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ChangePreapprovalBudgetClaim(Base):
    """Append-only capacity claim for one Alert and governed change plan."""

    __tablename__ = "change_preapproval_budget_claims"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "change_plan_id", name="uq_change_preapproval_budget_plan"),
        CheckConstraint("policy_limit_snapshot BETWEEN 1 AND 3", name="ck_change_preapproval_budget_limit"),
        Index("ix_change_preapproval_budget_alert", "tenant_id", "region_id", "alert_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    policy_id: Mapped[str] = mapped_column(ForeignKey("change_preapproval_policies.id", ondelete="RESTRICT"), index=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="RESTRICT"), index=True)
    change_plan_id: Mapped[str] = mapped_column(ForeignKey("governed_change_plans.id", ondelete="RESTRICT"), index=True)
    policy_review_sha256: Mapped[str] = mapped_column(String(64))
    plan_hash: Mapped[str] = mapped_column(String(64))
    policy_limit_snapshot: Mapped[int] = mapped_column(Integer)
    claimed_by: Mapped[str] = mapped_column(String(255))
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ChangePreapprovalExecutionGrant(Base):
    """Immutable, independently reviewed permission to use one policy revision."""

    __tablename__ = "change_preapproval_execution_grants"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "policy_id", "policy_review_sha256",
            name="uq_preapproval_execution_grant_review"),
        CheckConstraint("expires_at > granted_at", name="ck_preapproval_execution_grant_expiry"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    policy_id: Mapped[str] = mapped_column(ForeignKey("change_preapproval_policies.id", ondelete="RESTRICT"), index=True)
    policy_review_sha256: Mapped[str] = mapped_column(String(64))
    quality_policy_id: Mapped[str] = mapped_column(ForeignKey("capability_quality_policies.id", ondelete="RESTRICT"), index=True)
    quality_policy_sha256: Mapped[str] = mapped_column(String(64))
    qualification_assessment_id: Mapped[str] = mapped_column(ForeignKey("capability_quality_assessments.id", ondelete="RESTRICT"))
    qualification_assessment_sha256: Mapped[str] = mapped_column(String(64))
    acceptance_reference: Mapped[str] = mapped_column(String(1024))
    granted_by_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    granted_by: Mapped[str] = mapped_column(String(255))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ChangePreapprovalAuthorization(Base):
    """Immutable decision connecting an Alert debit to one approved action."""

    __tablename__ = "change_preapproval_authorizations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "action_proposal_id", name="uq_preapproval_authorization_proposal"),
        UniqueConstraint("tenant_id", "region_id", "budget_claim_id", name="uq_preapproval_authorization_claim"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    grant_id: Mapped[str] = mapped_column(ForeignKey("change_preapproval_execution_grants.id", ondelete="RESTRICT"), index=True)
    budget_claim_id: Mapped[str] = mapped_column(ForeignKey("change_preapproval_budget_claims.id", ondelete="RESTRICT"))
    action_proposal_id: Mapped[str] = mapped_column(ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), index=True)
    action_plan_hash: Mapped[str] = mapped_column(String(64))
    change_plan_hash: Mapped[str] = mapped_column(String(64))
    assessment_id: Mapped[str] = mapped_column(ForeignKey("capability_quality_assessments.id", ondelete="RESTRICT"))
    assessment_sha256: Mapped[str] = mapped_column(String(64))
    authorized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ChangeRollbackExecutionGrant(Base):
    __tablename__ = "change_rollback_execution_grants"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "primary_grant_id", name="uq_rollback_execution_primary_grant"),
        CheckConstraint("expires_at > granted_at", name="ck_rollback_execution_grant_expiry"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    primary_grant_id: Mapped[str] = mapped_column(ForeignKey("change_preapproval_execution_grants.id", ondelete="RESTRICT"), index=True)
    settings_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    dependency_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    qualification_manifest: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    qualification_sha256: Mapped[str] = mapped_column(String(64))
    acceptance_reference: Mapped[str] = mapped_column(String(1024))
    granted_by_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    granted_by: Mapped[str] = mapped_column(String(255))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ChangeRollbackGrantRevocation(Base):
    __tablename__ = "change_rollback_grant_revocations"
    __table_args__ = (UniqueConstraint("tenant_id", "region_id", "grant_id", name="uq_rollback_grant_revocation"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    grant_id: Mapped[str] = mapped_column(ForeignKey("change_rollback_execution_grants.id", ondelete="RESTRICT"), index=True)
    revoked_by: Mapped[str] = mapped_column(String(255))
    revoked_by_principal_id: Mapped[str] = mapped_column(ForeignKey("control_plane_principals.id", ondelete="RESTRICT"))
    reason: Mapped[str] = mapped_column(String(512))
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ChangeRollbackAuthorization(Base):
    """Immutable one-slot parent budget; primary Alert debit is never refunded."""
    __tablename__ = "change_rollback_authorizations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "parent_change_plan_id", name="uq_rollback_authorization_parent"),
        UniqueConstraint("tenant_id", "region_id", "rollback_proposal_id", name="uq_rollback_authorization_proposal"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    grant_id: Mapped[str] = mapped_column(ForeignKey("change_rollback_execution_grants.id", ondelete="RESTRICT"), index=True)
    primary_authorization_id: Mapped[str] = mapped_column(ForeignKey("change_preapproval_authorizations.id", ondelete="RESTRICT"))
    parent_change_plan_id: Mapped[str] = mapped_column(ForeignKey("governed_change_plans.id", ondelete="RESTRICT"), index=True)
    rollback_proposal_id: Mapped[str] = mapped_column(ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), index=True)
    action_plan_hash: Mapped[str] = mapped_column(String(64))
    failure_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    evidence_manifest: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    evidence_sha256: Mapped[str] = mapped_column(String(64))
    authorized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionTargetAdmission(Base):
    """Immutable routing provenance, not execution or semantic authority."""
    __tablename__ = "action_target_admissions"
    __table_args__ = (
        CheckConstraint("id = proposal_id", name="ck_action_target_admission_identity"),
        CheckConstraint("origin IN ('frozen_plan','frozen_rollback_plan','legacy_unknown')", name="ck_action_target_admission_origin"),
        Index("ix_action_target_admission_situation", "tenant_id", "region_id", "situation_id", "id"),
        Index("ix_action_target_admission_unknown", "tenant_id", "region_id", "unknown_targets", "id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    proposal_id: Mapped[str] = mapped_column(ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), unique=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="RESTRICT"), index=True)
    situation_id: Mapped[str | None] = mapped_column(ForeignKey("situations.id", ondelete="RESTRICT"), nullable=True)
    tool_id: Mapped[str] = mapped_column(ForeignKey("agent_tool_registrations.id", ondelete="RESTRICT"))
    change_plan_id: Mapped[str | None] = mapped_column(ForeignKey("governed_change_plans.id", ondelete="RESTRICT"), nullable=True)
    routing_plan_id: Mapped[str | None] = mapped_column(ForeignKey("governed_change_plans.id", ondelete="RESTRICT"), nullable=True)
    rollback_of_change_plan_id: Mapped[str | None] = mapped_column(ForeignKey("governed_change_plans.id", ondelete="RESTRICT"), nullable=True)
    origin: Mapped[str] = mapped_column(String(32))
    unknown_targets: Mapped[bool] = mapped_column(Boolean)
    contract_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    target_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    target_keys: Mapped[list[dict[str, str]]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionTargetKey(Base):
    __tablename__ = "action_target_keys"
    __table_args__ = (
        CheckConstraint("target_kind IN ('device_id','site')", name="ck_action_target_key_kind"),
        UniqueConstraint("admission_id", "target_kind", "target_id", name="uq_action_target_key"),
        Index("ix_action_target_key_lookup", "tenant_id", "region_id", "target_kind", "target_id", "admission_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    admission_id: Mapped[str] = mapped_column(ForeignKey("action_target_admissions.id", ondelete="RESTRICT"))
    target_kind: Mapped[str] = mapped_column(String(16))
    target_id: Mapped[str] = mapped_column(String(255))


def _immutable_action_targets(_mapper, _connection, _target):
    raise ValueError("Action target admission history is append-only")


for _action_target_model in (ActionTargetAdmission, ActionTargetKey):
    event.listen(_action_target_model, "before_update", _immutable_action_targets)
    event.listen(_action_target_model, "before_delete", _immutable_action_targets)


class GovernedChangePlan(Base):
    __tablename__ = "governed_change_plans"
    __table_args__ = (
        CheckConstraint("revision > 0", name="ck_governed_change_plan_revision"),
        CheckConstraint(
            "risk_class IN ('low', 'medium', 'high', 'critical')",
            name="ck_governed_change_plan_risk_class",
        ),
        CheckConstraint(
            "status IN ('awaiting_evidence', 'ready_for_approval', 'approved', "
            "'rejected', 'executing', 'awaiting_postcheck', 'verified', "
            "'rollback_required', 'awaiting_rollback_check', 'rolled_back', 'rollback_failed')",
            name="ck_governed_change_plan_status",
        ),
        CheckConstraint(
            "maintenance_window_end IS NULL OR maintenance_window_start IS NOT NULL",
            name="ck_governed_change_plan_window_start",
        ),
        CheckConstraint(
            "maintenance_window_end IS NULL OR "
            "maintenance_window_end > maintenance_window_start",
            name="ck_governed_change_plan_window_order",
        ),
        Index(
            "ix_governed_change_plan_queue",
            "status",
            "maintenance_window_start",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    action_proposal_id: Mapped[str] = mapped_column(
        ForeignKey("agent_action_proposals.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    contract_version: Mapped[str] = mapped_column(
        String(64), default="icheck.change-plan/v1"
    )
    revision: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(
        String(32), default="awaiting_evidence", index=True
    )
    risk_class: Mapped[str] = mapped_column(String(16), index=True)
    tool_contract_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    target_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    authorization_scope_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    idempotency_key_hash: Mapped[str] = mapped_column(String(64))
    maintenance_window_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    maintenance_window_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    plan_hash: Mapped[str] = mapped_column(String(64), index=True)
    approved_plan_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    policy_evaluation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(255))
    updated_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    evidence: Mapped[list[GovernedChangeEvidence]] = relationship(
        back_populates="plan",
        cascade="all, delete-orphan",
        order_by="GovernedChangeEvidence.created_at",
    )


class GovernedChangeEvidence(Base):
    __tablename__ = "governed_change_evidence"
    __table_args__ = (
        CheckConstraint(
            "stage IN ('precheck', 'dry_run', 'postcheck', 'rollback', 'rollback_check')",
            name="ck_governed_change_evidence_stage",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    change_plan_id: Mapped[str] = mapped_column(
        ForeignKey("governed_change_plans.id", ondelete="CASCADE"), index=True
    )
    stage: Mapped[str] = mapped_column(String(16), index=True)
    tool_call_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"),
        unique=True,
        index=True,
    )
    tool_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tool_registrations.id", ondelete="RESTRICT"),
        index=True,
    )
    arguments_hash: Mapped[str] = mapped_column(String(64))
    result_hash: Mapped[str] = mapped_column(String(64))
    passed: Mapped[bool] = mapped_column(Boolean)
    evidence_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    recorded_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    plan: Mapped[GovernedChangePlan] = relationship(back_populates="evidence")


class AgentWorker(Base):
    __tablename__ = "agent_workers"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_agent_worker_namespace_name",
        ),
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "mtls_fingerprint_sha256",
            name="uq_agent_worker_namespace_mtls_fingerprint",
        ),
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "mtls_next_fingerprint_sha256",
            name="uq_agent_worker_namespace_mtls_next_fingerprint",
        ),
        CheckConstraint("mtls_revision >= 0", name="ck_agent_worker_mtls_revision"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    auth_token_hash: Mapped[str] = mapped_column(String(64))
    token_issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    mtls_fingerprint_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    mtls_subject_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mtls_serial_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mtls_not_after: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mtls_activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mtls_next_fingerprint_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    mtls_next_subject_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    mtls_next_serial_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    mtls_next_not_before: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mtls_next_not_after: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mtls_revision: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[AgentWorkerState] = mapped_column(
        Enum(AgentWorkerState, native_enum=False, length=16),
        default=AgentWorkerState.ONLINE,
        index=True,
    )
    last_heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class WorkerScalingPolicy(Base):
    __tablename__ = "worker_scaling_policies"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "pool",
            "name",
            name="uq_worker_scaling_policy_namespace_pool_name",
        ),
        CheckConstraint(
            "min_replicas >= 0 AND max_replicas >= min_replicas",
            name="ck_worker_scaling_policy_replica_bounds",
        ),
        CheckConstraint(
            "target_queue_per_replica > 0",
            name="ck_worker_scaling_policy_queue_target",
        ),
        CheckConstraint(
            "scale_out_step > 0 AND scale_in_step > 0",
            name="ck_worker_scaling_policy_steps",
        ),
        CheckConstraint(
            "queue_age_target_seconds > 0 AND heartbeat_timeout_seconds > 0 "
            "AND cooldown_seconds >= 0",
            name="ck_worker_scaling_policy_time_bounds",
        ),
        CheckConstraint(
            "revision > 0",
            name="ck_worker_scaling_policy_revision",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128), index=True)
    pool: Mapped[WorkerScalingPool] = mapped_column(
        Enum(
            WorkerScalingPool,
            native_enum=False,
            length=16,
            values_callable=lambda items: [item.value for item in items],
        ),
        index=True,
    )
    selector: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    required_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    min_replicas: Mapped[int] = mapped_column(Integer, default=1)
    max_replicas: Mapped[int] = mapped_column(Integer, default=20)
    target_queue_per_replica: Mapped[int] = mapped_column(Integer, default=4)
    scale_out_step: Mapped[int] = mapped_column(Integer, default=2)
    scale_in_step: Mapped[int] = mapped_column(Integer, default=1)
    queue_age_target_seconds: Mapped[int] = mapped_column(Integer, default=30)
    heartbeat_timeout_seconds: Mapped[int] = mapped_column(Integer, default=60)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=120)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255))
    updated_by: Mapped[str] = mapped_column(String(255))
    update_reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    decisions: Mapped[list[WorkerScalingDecision]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="WorkerScalingDecision.observed_at.desc()",
    )


class WorkerScalingDecision(Base):
    __tablename__ = "worker_scaling_decisions"
    __table_args__ = (
        CheckConstraint(
            "queue_depth >= 0 AND current_replicas >= 0 "
            "AND ready_replicas >= 0 AND busy_replicas >= 0 "
            "AND stale_replicas >= 0 AND desired_replicas >= 0",
            name="ck_worker_scaling_decision_counts",
        ),
        CheckConstraint(
            "direction IN ('scale_out', 'scale_in', 'hold')",
            name="ck_worker_scaling_decision_direction",
        ),
        Index(
            "ix_worker_scaling_decision_policy_time",
            "policy_id",
            "observed_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("worker_scaling_policies.id", ondelete="CASCADE"),
        index=True,
    )
    policy_revision: Mapped[int] = mapped_column(Integer)
    queue_depth: Mapped[int] = mapped_column(Integer)
    oldest_queue_age_seconds: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    current_replicas: Mapped[int] = mapped_column(Integer)
    ready_replicas: Mapped[int] = mapped_column(Integer)
    busy_replicas: Mapped[int] = mapped_column(Integer)
    stale_replicas: Mapped[int] = mapped_column(Integer)
    desired_replicas: Mapped[int] = mapped_column(Integer)
    direction: Mapped[str] = mapped_column(String(16), index=True)
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    created_by: Mapped[str] = mapped_column(String(255))

    policy: Mapped[WorkerScalingPolicy] = relationship(
        back_populates="decisions"
    )
    application_events: Mapped[list[WorkerScalingApplicationEvent]] = relationship(
        back_populates="decision",
        cascade="all, delete-orphan",
        order_by="WorkerScalingApplicationEvent.created_at.desc()",
    )


class WorkerScalingApplicationEvent(Base):
    __tablename__ = "worker_scaling_application_events"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "provider_subject",
            "idempotency_key",
            name="uq_scaling_application_event_namespace_provider_key",
        ),
        CheckConstraint(
            "status IN ('accepted', 'applying', 'applied', 'failed', 'rejected')",
            name="ck_scaling_application_event_status",
        ),
        CheckConstraint(
            "observed_replicas >= 0",
            name="ck_scaling_application_event_observed_replicas",
        ),
        Index(
            "ix_scaling_application_event_decision_provider_time",
            "decision_id",
            "provider_subject",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    decision_id: Mapped[str] = mapped_column(
        ForeignKey("worker_scaling_decisions.id", ondelete="CASCADE"),
        index=True,
    )
    provider_subject: Mapped[str] = mapped_column(String(255), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), index=True)
    observed_replicas: Mapped[int] = mapped_column(Integer)
    detail_code: Mapped[str] = mapped_column(String(128))
    error_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    decision: Mapped[WorkerScalingDecision] = relationship(
        back_populates="application_events"
    )


class AgentExecution(Base):
    __tablename__ = "agent_executions"
    __table_args__ = (
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_agent_execution_attempt_count",
        ),
        Index(
            "ix_agent_execution_claim",
            "status",
            "lease_expires_at",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    status: Mapped[AgentExecutionStatus] = mapped_column(
        Enum(AgentExecutionStatus, native_enum=False, length=24),
        default=AgentExecutionStatus.QUEUED,
        index=True,
    )
    worker_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_workers.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    lease_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    completion_worker_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    completion_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    completion_request_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    cancellation_requested_by: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    cancellation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AgentExecutionEvent(Base):
    __tablename__ = "agent_execution_events"
    __table_args__ = (
        UniqueConstraint(
            "execution_id",
            "sequence",
            name="uq_agent_execution_event_sequence",
        ),
        CheckConstraint(
            "sequence > 0",
            name="ck_agent_execution_event_sequence",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("agent_executions.id", ondelete="CASCADE"), index=True
    )
    sequence: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class CollectorWorker(Base):
    __tablename__ = "collector_workers"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_collector_worker_namespace_name",
        ),
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "mtls_fingerprint_sha256",
            name="uq_collector_worker_namespace_mtls_fingerprint",
        ),
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "mtls_next_fingerprint_sha256",
            name="uq_collector_worker_namespace_mtls_next_fingerprint",
        ),
        CheckConstraint(
            "mtls_revision >= 0",
            name="ck_collector_worker_mtls_revision",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    site: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    auth_token_hash: Mapped[str] = mapped_column(String(64))
    token_issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    mtls_fingerprint_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    mtls_subject_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mtls_serial_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mtls_not_after: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mtls_activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mtls_next_fingerprint_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    mtls_next_subject_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    mtls_next_serial_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    mtls_next_not_before: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mtls_next_not_after: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mtls_revision: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[CollectorWorkerState] = mapped_column(
        Enum(CollectorWorkerState, native_enum=False, length=16),
        default=CollectorWorkerState.ONLINE,
        index=True,
    )
    last_heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    deployments: Mapped[list[CollectorDeployment]] = relationship(
        back_populates="lease_worker"
    )
    runs: Mapped[list[CollectorRun]] = relationship(back_populates="worker")
    device_preflights: Mapped[list[DeviceConnectionPreflight]] = relationship(
        back_populates="worker"
    )


class KnowledgeProjectionWorker(Base):
    __tablename__ = "knowledge_projection_workers"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_knowledge_projection_worker_namespace_name",
        ),
        Index("ix_knowledge_projection_workers_name", "name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    state: Mapped[KnowledgeProjectionWorkerState] = mapped_column(
        Enum(KnowledgeProjectionWorkerState, native_enum=False, length=16),
        default=KnowledgeProjectionWorkerState.ONLINE,
        index=True,
    )
    last_heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    projections: Mapped[list[KnowledgeProjection]] = relationship(
        back_populates="lease_worker"
    )


class CollectorDeployment(Base):
    __tablename__ = "collector_deployments"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_collector_deployment_namespace_name",
        ),
        CheckConstraint("schedule_seconds > 0", name="ck_collector_schedule_positive"),
        CheckConstraint(
            "(scope_device_id IS NULL AND scope_device_identity_revision IS NULL) "
            "OR (scope_device_id IS NOT NULL AND scope_device_identity_revision >= 0)",
            name="ck_collector_deployment_identity_binding",
        ),
        CheckConstraint(
            "CASE "
            "WHEN target_classification IS NULL THEN external_source_reason IS NULL "
            "WHEN target_classification = 'registered_device' THEN "
            "scope_device_id IS NOT NULL AND external_source_reason IS NULL "
            "WHEN target_classification = 'external_source' THEN "
            "scope_device_id IS NULL AND external_source_reason IS NOT NULL "
            "AND length(trim(external_source_reason)) >= 10 "
            "WHEN target_classification = 'legacy_unreviewed' THEN "
            "external_source_reason IS NULL "
            "ELSE false END",
            name="ck_collector_deployment_target_classification",
        ),
        Index(
            "ix_collector_deployment_due",
            "enabled",
            "next_run_at",
            "lease_expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    scope_device_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    scope_device_identity_revision: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    target_classification: Mapped[str | None] = mapped_column(
        String(32), nullable=True, index=True
    )
    external_source_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    scope_site: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    target: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    worker_selector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    execution_mode: Mapped[CollectorDeploymentMode] = mapped_column(
        Enum(CollectorDeploymentMode, native_enum=False, length=16),
        default=CollectorDeploymentMode.SCHEDULED,
        index=True,
    )
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    schedule_seconds: Mapped[int] = mapped_column(Integer, default=300)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )
    lease_worker_id: Mapped[str | None] = mapped_column(
        ForeignKey("collector_workers.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    lease_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )
    last_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    artifact_version: Mapped[ArtifactVersion] = relationship(
        back_populates="deployments"
    )
    lease_worker: Mapped[CollectorWorker | None] = relationship(
        back_populates="deployments"
    )
    runs: Mapped[list[CollectorRun]] = relationship(
        back_populates="deployment", cascade="all, delete-orphan"
    )


class CollectorRun(Base):
    __tablename__ = "collector_runs"
    __table_args__ = (
        Index("ix_collector_run_status_started", "status", "started_at"),
        CheckConstraint(
            "assignment_sha256 IS NULL OR length(assignment_sha256) = 64",
            name="ck_collector_run_assignment_hash",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    deployment_id: Mapped[str] = mapped_column(
        ForeignKey("collector_deployments.id", ondelete="CASCADE"), index=True
    )
    artifact_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    worker_id: Mapped[str] = mapped_column(
        ForeignKey("collector_workers.id", ondelete="RESTRICT"), index=True
    )
    lease_token_hash: Mapped[str] = mapped_column(String(64))
    assignment_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_classification_snapshot: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    execution_admitted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[CollectorRunStatus] = mapped_column(
        Enum(CollectorRunStatus, native_enum=False, length=16),
        default=CollectorRunStatus.RUNNING,
        index=True,
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    records_received: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    deployment: Mapped[CollectorDeployment] = relationship(back_populates="runs")
    worker: Mapped[CollectorWorker] = relationship(back_populates="runs")
    envelopes: Mapped[list[CollectionEnvelope]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class CollectorCanaryRollout(Base):
    __tablename__ = "collector_canary_rollouts"
    __table_args__ = (
        UniqueConstraint("name"),
        UniqueConstraint("deployment_id"),
        Index("ix_collector_canary_rollouts_name", "name"),
        Index("ix_collector_canary_rollouts_deployment_id", "deployment_id"),
        CheckConstraint(
            "status IN ('running', 'passed', 'aborted', 'promoted')",
            name="ck_collector_canary_status",
        ),
        CheckConstraint(
            "min_successful_runs > 0",
            name="ck_collector_canary_min_success_positive",
        ),
        CheckConstraint(
            "max_failed_runs > 0",
            name="ck_collector_canary_max_failures_positive",
        ),
        CheckConstraint(
            "min_records_per_run >= 0",
            name="ck_collector_canary_min_records_nonnegative",
        ),
        CheckConstraint(
            "target_ownership_sha256 IS NULL OR length(target_ownership_sha256) = 64",
            name="ck_collector_canary_target_ownership_hash",
        ),
        Index(
            "uq_collector_canary_active_artifact",
            "artifact_id",
            unique=True,
            sqlite_where=text("status = 'running'"),
            postgresql_where=text("status = 'running'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    candidate_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    baseline_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    deployment_id: Mapped[str | None] = mapped_column(
        ForeignKey("collector_deployments.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(16), default="running", index=True)
    target_classification: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    scope_device_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    scope_device_identity_revision: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    scope_site: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    external_source_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    target_ownership_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    target: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    worker_selector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    schedule_seconds: Mapped[int] = mapped_column(Integer, default=30)
    min_successful_runs: Mapped[int] = mapped_column(Integer, default=3)
    max_failed_runs: Mapped[int] = mapped_column(Integer, default=1)
    min_records_per_run: Mapped[int] = mapped_column(Integer, default=1)
    successful_runs: Mapped[int] = mapped_column(Integer, default=0)
    qualifying_runs: Mapped[int] = mapped_column(Integer, default=0)
    failed_runs: Mapped[int] = mapped_column(Integer, default=0)
    records_received: Mapped[int] = mapped_column(Integer, default=0)
    evidence_batches: Mapped[int] = mapped_column(Integer, default=0)
    last_evidence_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    last_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("collector_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    last_gate_result: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    created_by: Mapped[str] = mapped_column(String(255))
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    passed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    aborted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    abort_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    promoted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    promoted_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    promotion_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class CollectorFleetRollout(Base):
    __tablename__ = "collector_fleet_rollouts"
    __table_args__ = (
        CheckConstraint(
            "status IN ('planned', 'running', 'completed', 'failed', "
            "'rolling_back', 'rolled_back', 'rollback_failed')",
            name="ck_collector_fleet_rollout_status",
        ),
        CheckConstraint(
            "batch_size > 0 AND batch_size <= 500",
            name="ck_collector_fleet_rollout_batch_size",
        ),
        CheckConstraint(
            "max_failures > 0",
            name="ck_collector_fleet_rollout_max_failures",
        ),
        CheckConstraint(
            "progression_mode IN ('manual', 'automatic')",
            name="ck_collector_fleet_rollout_progression_mode",
        ),
        CheckConstraint(
            "automation_state IN ('manual', 'armed', 'observing', 'paused', "
            "'aborted', 'completed', 'failed')",
            name="ck_collector_fleet_rollout_automation_state",
        ),
        CheckConstraint(
            "observation_seconds >= 30 AND observation_seconds <= 86400",
            name="ck_collector_fleet_rollout_observation_seconds",
        ),
        CheckConstraint(
            "min_successful_runs_per_deployment > 0 AND "
            "min_successful_runs_per_deployment <= 20",
            name="ck_collector_fleet_rollout_min_successful_runs",
        ),
        CheckConstraint(
            "max_failed_runs_per_ring >= 0 AND max_failed_runs_per_ring <= 500",
            name="ck_collector_fleet_rollout_max_failed_runs",
        ),
        Index(
            "uq_collector_fleet_active_canary",
            "canary_rollout_id",
            unique=True,
            sqlite_where=text(
                "status IN ('planned', 'running', 'rolling_back')"
            ),
            postgresql_where=text(
                "status IN ('planned', 'running', 'rolling_back')"
            ),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    canary_rollout_id: Mapped[str] = mapped_column(
        ForeignKey("collector_canary_rollouts.id", ondelete="RESTRICT"),
        index=True,
    )
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"), index=True
    )
    from_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    to_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[str] = mapped_column(String(24), default="planned", index=True)
    scope_site: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    include_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    batch_size: Mapped[int] = mapped_column(Integer, default=25)
    max_failures: Mapped[int] = mapped_column(Integer, default=1)
    progression_mode: Mapped[str] = mapped_column(
        String(16), default="manual", index=True
    )
    ring_percentages: Mapped[list[int]] = mapped_column(JSON, default=list)
    observation_seconds: Mapped[int] = mapped_column(Integer, default=300)
    min_successful_runs_per_deployment: Mapped[int] = mapped_column(
        Integer, default=1
    )
    max_failed_runs_per_ring: Mapped[int] = mapped_column(Integer, default=0)
    automation_state: Mapped[str] = mapped_column(
        String(16), default="manual", index=True
    )
    current_ring_index: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    automation_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    plan_sha256: Mapped[str] = mapped_column(String(64), index=True)
    planned_count: Mapped[int] = mapped_column(Integer, default=0)
    pending_count: Mapped[int] = mapped_column(Integer, default=0)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0)
    deferred_count: Mapped[int] = mapped_column(Integer, default=0)
    migrated_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    rolled_back_count: Mapped[int] = mapped_column(Integer, default=0)
    rollback_failed_count: Mapped[int] = mapped_column(Integer, default=0)
    last_batch_result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rollback_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rolled_back_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    items: Mapped[list[CollectorFleetRolloutItem]] = relationship(
        back_populates="rollout",
        cascade="all, delete-orphan",
        order_by="CollectorFleetRolloutItem.deployment_id",
    )
    rings: Mapped[list[CollectorFleetRolloutRing]] = relationship(
        back_populates="rollout",
        cascade="all, delete-orphan",
        order_by="CollectorFleetRolloutRing.ring_index",
    )


class CollectorFleetRolloutItem(Base):
    __tablename__ = "collector_fleet_rollout_items"
    __table_args__ = (
        UniqueConstraint(
            "rollout_id",
            "deployment_id",
            name="uq_collector_fleet_rollout_deployment",
        ),
        CheckConstraint(
            "status IN ('pending', 'blocked', 'deferred', 'migrated', "
            "'failed', 'rollback_deferred', 'rolled_back', 'rollback_failed')",
            name="ck_collector_fleet_rollout_item_status",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_collector_fleet_rollout_item_attempts",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    rollout_id: Mapped[str] = mapped_column(
        ForeignKey("collector_fleet_rollouts.id", ondelete="CASCADE"), index=True
    )
    deployment_id: Mapped[str] = mapped_column(
        ForeignKey("collector_deployments.id", ondelete="RESTRICT"), index=True
    )
    deployment_name: Mapped[str] = mapped_column(String(255))
    pre_change_sha256: Mapped[str] = mapped_column(String(64))
    post_change_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    ring_index: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    block_reason_code: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    migrated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rolled_back_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    rollout: Mapped[CollectorFleetRollout] = relationship(back_populates="items")


class CollectorFleetRolloutRing(Base):
    __tablename__ = "collector_fleet_rollout_rings"
    __table_args__ = (
        UniqueConstraint(
            "rollout_id",
            "ring_index",
            name="uq_collector_fleet_rollout_ring_index",
        ),
        CheckConstraint(
            "status IN ('pending', 'applying', 'observing', 'passed', "
            "'paused', 'aborted', 'failed')",
            name="ck_collector_fleet_rollout_ring_status",
        ),
        CheckConstraint(
            "ring_index >= 0",
            name="ck_collector_fleet_rollout_ring_index",
        ),
        CheckConstraint(
            "target_percent > 0 AND target_percent <= 100",
            name="ck_collector_fleet_rollout_ring_percent",
        ),
        CheckConstraint(
            "target_count > 0",
            name="ck_collector_fleet_rollout_ring_target_count",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    rollout_id: Mapped[str] = mapped_column(
        ForeignKey("collector_fleet_rollouts.id", ondelete="CASCADE"), index=True
    )
    ring_index: Mapped[int] = mapped_column(Integer)
    target_percent: Mapped[int] = mapped_column(Integer)
    target_count: Mapped[int] = mapped_column(Integer)
    cohort_count: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    healthy_deployments: Mapped[int] = mapped_column(Integer, default=0)
    missing_evidence_deployments: Mapped[int] = mapped_column(Integer, default=0)
    successful_runs: Mapped[int] = mapped_column(Integer, default=0)
    failed_runs: Mapped[int] = mapped_column(Integer, default=0)
    last_gate_result: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    evidence_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    observation_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    passed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    rollout: Mapped[CollectorFleetRollout] = relationship(back_populates="rings")


class CollectionEnvelope(Base):
    __tablename__ = "collection_envelopes"
    __table_args__ = (
        UniqueConstraint(
            "source", "idempotency_key", name="uq_collection_source_idempotency"
        ),
        Index("ix_collection_envelope_kind_observed", "kind", "observed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("collector_runs.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[EnvelopeKind] = mapped_column(
        Enum(EnvelopeKind, native_enum=False, length=16), index=True
    )
    type: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(255), index=True)
    subject: Mapped[str | None] = mapped_column(String(512), index=True, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    idempotency_key: Mapped[str | None] = mapped_column(
        String(512), index=True, nullable=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    run: Mapped[CollectorRun] = relationship(back_populates="envelopes")
    projection: Mapped[KnowledgeProjection | None] = relationship(
        back_populates="envelope",
        cascade="all, delete-orphan",
        uselist=False,
    )


class KnowledgeProjection(Base):
    __tablename__ = "knowledge_projections"
    __table_args__ = (
        CheckConstraint(
            "attempt_count >= 0 AND max_attempts > 0",
            name="ck_knowledge_projection_attempts",
        ),
        Index(
            "ix_knowledge_projection_queue",
            "status",
            "next_attempt_at",
            "lease_expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    envelope_id: Mapped[str] = mapped_column(
        ForeignKey("collection_envelopes.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    status: Mapped[KnowledgeProjectionStatus] = mapped_column(
        Enum(KnowledgeProjectionStatus, native_enum=False, length=16),
        default=KnowledgeProjectionStatus.PENDING,
        index=True,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    lease_worker_id: Mapped[str | None] = mapped_column(
        ForeignKey("knowledge_projection_workers.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    lease_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    envelope: Mapped[CollectionEnvelope] = relationship(back_populates="projection")
    lease_worker: Mapped[KnowledgeProjectionWorker | None] = relationship(
        back_populates="projections"
    )


class ControlPlanePrincipal(Base):
    __tablename__ = "control_plane_principals"
    __namespace_exempt__ = True
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "subject",
            name="uq_control_plane_principal_tenant_subject",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    subject: Mapped[str] = mapped_column(String(255), index=True)
    display_name: Mapped[str] = mapped_column(String(255))
    principal_type: Mapped[str] = mapped_column(
        String(32), default="user", index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    allowed_region_ids: Mapped[list[str]] = mapped_column(
        JSON, default=list, server_default=text("'[]'")
    )
    platform_admin: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"), index=True
    )
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password_failed_attempts: Mapped[int] = mapped_column(
        Integer, default=0, server_default=text("0")
    )
    password_locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    role_bindings: Mapped[list[ControlPlaneRoleBinding]] = relationship(
        back_populates="principal", cascade="all, delete-orphan"
    )
    access_tokens: Mapped[list[ControlPlaneAccessToken]] = relationship(
        back_populates="principal", cascade="all, delete-orphan"
    )
    browser_sessions: Mapped[list[ControlPlaneBrowserSession]] = relationship(
        back_populates="principal", cascade="all, delete-orphan"
    )
    oidc_identities: Mapped[list[ControlPlaneOIDCIdentity]] = relationship(
        back_populates="principal", cascade="all, delete-orphan"
    )
    trusted_proxy_identities: Mapped[list[ControlPlaneTrustedProxyIdentity]] = (
        relationship(
            back_populates="principal",
            cascade="all, delete-orphan",
        )
    )
    workload_identities: Mapped[list[ControlPlaneWorkloadIdentity]] = relationship(
        back_populates="principal",
        cascade="all, delete-orphan",
    )

    @property
    def password_login_configured(self) -> bool:
        return self.principal_type == "user" and self.password_hash is not None


class ControlPlaneRole(Base):
    __tablename__ = "control_plane_roles"
    __namespace_exempt__ = True
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_control_plane_role_namespace_name",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list)
    system: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    bindings: Mapped[list[ControlPlaneRoleBinding]] = relationship(
        back_populates="role"
    )


class ControlPlaneRoleBinding(Base):
    __tablename__ = "control_plane_role_bindings"
    __namespace_exempt__ = True
    __table_args__ = (
        UniqueConstraint(
            "principal_id",
            "role_id",
            "region_id",
            name="uq_control_plane_role_binding",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    principal_id: Mapped[str] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="CASCADE"), index=True
    )
    role_id: Mapped[str] = mapped_column(
        ForeignKey("control_plane_roles.id", ondelete="RESTRICT"), index=True
    )
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    principal: Mapped[ControlPlanePrincipal] = relationship(
        back_populates="role_bindings"
    )
    role: Mapped[ControlPlaneRole] = relationship(back_populates="bindings")


class ControlPlaneAccessToken(Base):
    __tablename__ = "control_plane_access_tokens"
    __namespace_exempt__ = True

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    principal_id: Mapped[str] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="CASCADE"), index=True
    )
    workload_identity_id: Mapped[str | None] = mapped_column(
        ForeignKey(
            "control_plane_workload_identities.id",
            ondelete="CASCADE",
        ),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255))
    token_prefix: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    revoked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    principal: Mapped[ControlPlanePrincipal] = relationship(
        back_populates="access_tokens"
    )


class ControlPlaneBrowserSession(Base):
    __tablename__ = "control_plane_browser_sessions"
    __namespace_exempt__ = True
    __table_args__ = (
        CheckConstraint(
            "(auth_source IN ('unknown', 'local_token', 'local_password') "
            "AND federated_identity_id IS NULL) OR "
            "(auth_source IN ('oidc', 'trusted_proxy') "
            "AND federated_identity_id IS NOT NULL)",
            name="ck_control_plane_browser_session_source",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    principal_id: Mapped[str] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="CASCADE"), index=True
    )
    token_prefix: Mapped[str] = mapped_column(
        String(32), unique=True, index=True
    )
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True
    )
    csrf_token_hash: Mapped[str] = mapped_column(String(64))
    auth_source: Mapped[str] = mapped_column(
        String(32), default="local_token", index=True
    )
    federated_identity_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    revoked_by: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    revocation_reason_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    principal: Mapped[ControlPlanePrincipal] = relationship(
        back_populates="browser_sessions"
    )


class ControlPlaneOIDCIdentity(Base):
    __tablename__ = "control_plane_oidc_identities"
    __namespace_exempt__ = True
    __table_args__ = (
        UniqueConstraint(
            "issuer_sha256",
            "subject_sha256",
            name="uq_control_plane_oidc_external_identity",
        ),
        UniqueConstraint(
            "principal_id",
            "issuer_sha256",
            name="uq_control_plane_oidc_principal_issuer",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    principal_id: Mapped[str] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="CASCADE"), index=True
    )
    issuer: Mapped[str] = mapped_column(String(2048))
    issuer_sha256: Mapped[str] = mapped_column(String(64), index=True)
    subject_sha256: Mapped[str] = mapped_column(String(64), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_claims_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    principal: Mapped[ControlPlanePrincipal] = relationship(
        back_populates="oidc_identities"
    )


class ControlPlaneOIDCTransaction(Base):
    __tablename__ = "control_plane_oidc_transactions"
    __namespace_exempt__ = True

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    browser_token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True
    )
    nonce_hash: Mapped[str] = mapped_column(String(64))
    code_verifier_ciphertext: Mapped[str] = mapped_column(Text)
    metadata_sha256: Mapped[str] = mapped_column(String(64))
    return_to: Mapped[str] = mapped_column(String(2048))
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class ControlPlaneTrustedProxyIdentity(Base):
    __tablename__ = "control_plane_trusted_proxy_identities"
    __namespace_exempt__ = True
    __table_args__ = (
        UniqueConstraint(
            "issuer_sha256",
            "subject_sha256",
            name="uq_control_plane_trusted_proxy_external_identity",
        ),
        UniqueConstraint(
            "principal_id",
            "issuer_sha256",
            name="uq_control_plane_trusted_proxy_principal_issuer",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    principal_id: Mapped[str] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="CASCADE"), index=True
    )
    issuer: Mapped[str] = mapped_column(String(255))
    issuer_sha256: Mapped[str] = mapped_column(String(64), index=True)
    subject_sha256: Mapped[str] = mapped_column(String(64), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    principal: Mapped[ControlPlanePrincipal] = relationship(
        back_populates="trusted_proxy_identities"
    )


class ControlPlaneTrustedProxyLoginAttempt(Base):
    __tablename__ = "control_plane_trusted_proxy_login_attempts"
    __namespace_exempt__ = True
    __table_args__ = (
        CheckConstraint(
            "(outcome = 'succeeded' AND failure_code IS NULL "
            "AND identity_id IS NOT NULL AND principal_id IS NOT NULL "
            "AND session_id IS NOT NULL) OR "
            "(outcome = 'denied' AND failure_code IS NOT NULL "
            "AND session_id IS NULL)",
            name="ck_control_plane_trusted_proxy_attempt_outcome",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    identity_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True,
    )
    principal_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True,
    )
    session_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True,
    )
    issuer_sha256: Mapped[str] = mapped_column(String(64), index=True)
    subject_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    source_address_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    outcome: Mapped[str] = mapped_column(String(16), index=True)
    failure_code: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class ControlPlaneWorkloadIdentity(Base):
    __tablename__ = "control_plane_workload_identities"
    __namespace_exempt__ = True
    __table_args__ = (
        UniqueConstraint(
            "issuer_sha256",
            "subject_sha256",
            name="uq_control_plane_workload_external_identity",
        ),
        UniqueConstraint(
            "principal_id",
            "issuer_sha256",
            name="uq_control_plane_workload_principal_issuer",
        ),
        CheckConstraint(
            "max_token_ttl_minutes >= 1 AND max_token_ttl_minutes <= 60",
            name="ck_control_plane_workload_identity_ttl",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    principal_id: Mapped[str] = mapped_column(
        ForeignKey("control_plane_principals.id", ondelete="CASCADE"), index=True
    )
    issuer: Mapped[str] = mapped_column(String(2048))
    issuer_sha256: Mapped[str] = mapped_column(String(64), index=True)
    subject_sha256: Mapped[str] = mapped_column(String(64), index=True)
    audience_sha256: Mapped[str] = mapped_column(String(64), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    max_token_ttl_minutes: Mapped[int] = mapped_column(Integer, default=15)
    last_exchange_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    principal: Mapped[ControlPlanePrincipal] = relationship(
        back_populates="workload_identities"
    )


class ControlPlaneWorkloadExchange(Base):
    __tablename__ = "control_plane_workload_exchanges"
    __namespace_exempt__ = True
    __table_args__ = (
        CheckConstraint(
            "(outcome = 'succeeded' AND failure_code IS NULL "
            "AND identity_id IS NOT NULL AND principal_id IS NOT NULL "
            "AND issued_token_id IS NOT NULL "
            "AND issued_token_prefix IS NOT NULL "
            "AND issued_token_expires_at IS NOT NULL) OR "
            "(outcome = 'denied' AND failure_code IS NOT NULL "
            "AND issued_token_id IS NULL AND issued_token_prefix IS NULL "
            "AND issued_token_expires_at IS NULL)",
            name="ck_control_plane_workload_exchange_outcome",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    identity_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    principal_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    assertion_jti_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True, index=True
    )
    issuer_sha256: Mapped[str] = mapped_column(String(64), index=True)
    subject_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    audience_sha256: Mapped[str] = mapped_column(String(64), index=True)
    claims_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    source_address_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    assertion_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    issued_token_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    issued_token_prefix: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    issued_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    outcome: Mapped[str] = mapped_column(String(16), index=True)
    failure_code: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class GrafanaConnection(Base):
    __tablename__ = "grafana_connections"
    __table_args__ = (
        UniqueConstraint("tenant_id", "region_id", "name", name="uq_grafana_connection_name"),
        CheckConstraint("revision > 0", name="ck_grafana_connection_revision"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    api_url: Mapped[str] = mapped_column(String(2048))
    public_url: Mapped[str] = mapped_column(String(2048))
    datasource_uid: Mapped[str] = mapped_column(String(64))
    folder_uid: Mapped[str] = mapped_column(String(64))
    encrypted_token: Mapped[bytes] = mapped_column(LargeBinary)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    shared_dataset_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    @property
    def token_configured(self):
        return bool(self.encrypted_token)


class GrafanaChange(Base):
    __tablename__ = "grafana_changes"
    __table_args__ = (
        CheckConstraint("resource_kind IN ('dashboard','folder')", name="ck_grafana_change_kind"),
        CheckConstraint("status IN ('proposed','applying','applied','conflict','unknown','rejected')", name="ck_grafana_change_status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    connection_id: Mapped[str] = mapped_column(ForeignKey("grafana_connections.id", ondelete="RESTRICT"))
    connection_revision: Mapped[int] = mapped_column(Integer)
    connection_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    resource_kind: Mapped[str] = mapped_column(String(16))
    resource_uid: Mapped[str] = mapped_column(String(64))
    folder_uid: Mapped[str] = mapped_column(String(64))
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    previous_resource: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    expected_resource_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    plan_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="proposed")
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    applied_resource: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    restore_of_id: Mapped[str | None] = mapped_column(ForeignKey("grafana_changes.id", ondelete="RESTRICT"), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_event_entity", "entity_type", "entity_id"),
        Index("ix_audit_event_type_occurred", "event_type", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    actor_type: Mapped[str] = mapped_column(String(32), index=True)
    actor_id: Mapped[str] = mapped_column(String(255), index=True)
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    entity_id: Mapped[str] = mapped_column(String(255), index=True)
    outcome: Mapped[str] = mapped_column(String(32), default="success", index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
