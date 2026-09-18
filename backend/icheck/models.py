from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
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


class EnvelopeKind(str, enum.Enum):
    ENTITY = "entity"
    RELATIONSHIP = "relationship"
    OBSERVATION = "observation"
    EVENT = "event"


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    management_ip: Mapped[str | None] = mapped_column(String(45), unique=True, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    site: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
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


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    mac_address: Mapped[str] = mapped_column(String(17), unique=True, index=True)
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


class IPAddressObservation(Base):
    __tablename__ = "ip_address_observations"
    __table_args__ = (
        Index("ix_ip_observation_endpoint_active", "endpoint_id", "active"),
        Index("ix_ip_observation_address_last_seen", "ip_address", "last_seen"),
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


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), unique=True)
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


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alert_status_severity_last_seen", "status", "severity", "last_seen"),
        Index("ix_alert_dedup_status", "dedup_key", "status"),
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

    rule: Mapped[AlertRule | None] = relationship(back_populates="alerts")


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint("kind", "name", name="uq_artifact_kind_name"),
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

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(64), index=True)
    secret_ref: Mapped[str] = mapped_column(String(1024))
    allowed_adapters: Mapped[list[str]] = mapped_column(JSON, default=list)
    worker_selector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class MetricBackend(Base):
    __tablename__ = "metric_backends"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(64), index=True)
    query_base_url: Mapped[str] = mapped_column(String(2048))
    remote_write_url: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    external_labels: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
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


class AIProviderConfig(Base):
    __tablename__ = "ai_provider_configs"
    __table_args__ = (
        CheckConstraint(
            "request_timeout_seconds > 0",
            name="ck_ai_provider_timeout_positive",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    provider_type: Mapped[str] = mapped_column(String(64), index=True)
    base_url: Mapped[str] = mapped_column(String(2048))
    auth_type: Mapped[str] = mapped_column(String(32), default="bearer")
    credential_profile_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    request_timeout_seconds: Mapped[int] = mapped_column(Integer, default=20)
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


class AIModelConfig(Base):
    __tablename__ = "ai_model_configs"
    __table_args__ = (
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
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider_id: Mapped[str] = mapped_column(
        ForeignKey("ai_provider_configs.id", ondelete="CASCADE"), index=True
    )
    display_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    model_name: Mapped[str] = mapped_column(String(255), index=True)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    context_window: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
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
        CheckConstraint("max_iterations > 0", name="ck_ai_route_iterations_positive"),
        CheckConstraint("max_tool_calls > 0", name="ck_ai_route_tools_positive"),
        CheckConstraint("timeout_seconds > 0", name="ck_ai_route_timeout_positive"),
        CheckConstraint("token_budget > 0", name="ck_ai_route_tokens_positive"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    purpose: Mapped[str] = mapped_column(String(128), unique=True, index=True)
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


class CollectorWorker(Base):
    __tablename__ = "collector_workers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    site: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    auth_token_hash: Mapped[str] = mapped_column(String(64))
    token_issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
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


class CollectorDeployment(Base):
    __tablename__ = "collector_deployments"
    __table_args__ = (
        CheckConstraint("schedule_seconds > 0", name="ck_collector_schedule_positive"),
        Index(
            "ix_collector_deployment_due",
            "enabled",
            "next_run_at",
            "lease_expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    artifact_version_id: Mapped[str] = mapped_column(
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"), index=True
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
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    deployment_id: Mapped[str] = mapped_column(
        ForeignKey("collector_deployments.id", ondelete="CASCADE"), index=True
    )
    worker_id: Mapped[str] = mapped_column(
        ForeignKey("collector_workers.id", ondelete="RESTRICT"), index=True
    )
    lease_token_hash: Mapped[str] = mapped_column(String(64))
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
