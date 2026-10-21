"""Bounded read contracts shared by external monitoring connectors.

These models carry observations, not inventory enrollment or action authority.
The caller must authorize a connection and resolve its current resource scope.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Generic, Literal, Protocol, TypeVar
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


ExternalID = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]


class ConnectorModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class SourceIdentity(ConnectorModel):
    tenant_id: UUID
    region_id: UUID
    connection_id: UUID
    provider: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]


class RemoteRef(ConnectorModel):
    source: SourceIdentity
    object_type: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
    remote_id: ExternalID


class ReadScope(ConnectorModel):
    # An empty group list must never accidentally become an unrestricted query.
    group_ids: tuple[ExternalID, ...] = Field(min_length=1, max_length=100)
    limit: int = Field(default=100, ge=1, le=500, strict=True)
    timeout_seconds: int = Field(default=15, ge=1, le=30, strict=True)


class ResourceObservation(ConnectorModel):
    ref: RemoteRef
    name: str = Field(min_length=1, max_length=255)
    monitoring_enabled: bool
    # Zabbix host status is configuration, not proof of device health.
    health: Literal["unknown"] = "unknown"


class AlertObservation(ConnectorModel):
    ref: RemoteRef
    subject: RemoteRef
    title: str = Field(min_length=1, max_length=1024)
    native_severity: str = Field(min_length=1, max_length=64)
    state: Literal["open", "resolved"]
    acknowledged: bool
    suppressed: bool
    occurred_at: AwareDatetime
    resolved_at: AwareDatetime | None = None
    recovery_ref: RemoteRef | None = None
    resources: tuple[ResourceObservation, ...] = Field(default=(), max_length=250)

    @property
    def investigation_stop_required(self) -> bool:
        """Stop signal only: False is never permission to start an investigation."""
        return self.suppressed or self.state == "resolved"

    @model_validator(mode="after")
    def consistent_recovery(self) -> AlertObservation:
        if self.subject.source != self.ref.source or (
            self.recovery_ref is not None and self.recovery_ref.source != self.ref.source
        ):
            raise ValueError("Alert evidence must belong to one source")
        if any(resource.ref.source != self.ref.source for resource in self.resources):
            raise ValueError("Affected resources must belong to the alert source")
        recovered = self.resolved_at is not None and self.recovery_ref is not None
        if (self.state == "resolved") != recovered:
            raise ValueError("Recovery state requires both time and source evidence")
        if self.state == "open" and (self.resolved_at or self.recovery_ref):
            raise ValueError("Open alert cannot contain recovery evidence")
        if self.resolved_at is not None and self.resolved_at < self.occurred_at:
            raise ValueError("Recovery cannot precede the problem")
        return self


class HistoryQuery(ConnectorModel):
    resource_id: ExternalID
    metric_id: ExternalID
    value_type: Literal["float", "uint"]
    start: AwareDatetime
    end: AwareDatetime
    limit: int = Field(default=500, ge=1, le=2000, strict=True)

    @model_validator(mode="after")
    def bounded_window(self) -> HistoryQuery:
        if not timedelta(0) < self.end - self.start <= timedelta(days=31):
            raise ValueError("History window must be positive and at most 31 days")
        if self.start < datetime(1970, 1, 1, tzinfo=UTC):
            raise ValueError("History window must not precede the Unix epoch")
        return self


class MetricSample(ConnectorModel):
    metric: RemoteRef
    resource: RemoteRef
    timestamp: AwareDatetime
    nanoseconds: int = Field(ge=0, lt=1_000_000_000, strict=True)
    value: Annotated[int, Field(strict=True)] | Annotated[float, Field(strict=True)]
    unit: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def same_source(self) -> MetricSample:
        if self.metric.source != self.resource.source:
            raise ValueError("Metric and resource must belong to one source")
        return self


T = TypeVar("T", ResourceObservation, AlertObservation, MetricSample)


class ObservationBatch(ConnectorModel, Generic[T]):
    source: SourceIdentity
    fetched_at: AwareDatetime
    items: tuple[T, ...] = Field(max_length=2000)
    truncated: bool
    # Neither bounded discovery nor recent problems can authorize deletion/closure.
    authoritative_snapshot: Literal[False] = False

    @model_validator(mode="after")
    def same_source(self) -> ObservationBatch[T]:
        for item in self.items:
            ref = item.metric if isinstance(item, MetricSample) else item.ref
            if ref.source != self.source:
                raise ValueError("Batch observations must belong to the declared source")
        return self


class ProviderDescriptor(ConnectorModel):
    provider: str
    display_name: str
    development_stage: Literal["adapter_only", "connection_api", "guided_sync", "planned"]
    implemented_operations: tuple[str, ...]
    protocol_targets: tuple[str, ...]
    configurable: bool = False
    live_qualified: Literal[False] = False
    requires_prometheus: Literal[False] = False


class MonitoringConnector(Protocol):
    """A source reader, not a transport, scheduler, or unrestricted MCP server."""

    def discover_resources(self, scope: ReadScope) -> ObservationBatch[ResourceObservation]: ...

    def read_alerts(self, scope: ReadScope) -> ObservationBatch[AlertObservation]: ...

    def query_history(self, scope: ReadScope, query: HistoryQuery) -> ObservationBatch[MetricSample]: ...
