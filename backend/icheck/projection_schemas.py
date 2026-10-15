from __future__ import annotations

import json
import ipaddress
from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .collector_condition_schemas import (
    COLLECTOR_CONDITION_V1,
    CollectorConditionObservation,
)
from .models import (
    AlertSeverity,
    EnvelopeKind,
    KnowledgeProjectionStatus,
    KnowledgeProjectionWorkerState,
    ObservationSource,
)
from .schemas import (
    APIModel,
    AlertEvent,
    NetworkObservation,
    WirelessClientObservation,
    WirelessSnapshot,
)
from .service_indicator_schemas import (
    ARTIFACT_INDICATOR_CONTRACT,
    ArtifactIndicatorEnvelope,
)
from .network_binding_schemas import NETWORK_OBSERVATION_V2, NetworkObservationFieldsV2, NetworkObservationV2


NETWORK_OBSERVATION_V1 = "icheck.inventory.network-observation/v1"
WIRELESS_SNAPSHOT_V1 = "icheck.inventory.wireless-snapshot/v1"
ALERT_EVENT_V1 = "icheck.alert.event/v1"
KNOWLEDGE_ENTITY_V1 = "icheck.knowledge.entity/v1"
KNOWLEDGE_RELATIONSHIP_V1 = "icheck.knowledge.relationship/v1"
DEVICE_ADJACENCY_SNAPSHOT_V1 = "icheck.network.device-adjacency-snapshot/v1"

MAX_KNOWLEDGE_ATTRIBUTES = 64
MAX_KNOWLEDGE_ATTRIBUTES_BYTES = 32 * 1024
MAX_KNOWLEDGE_ATTRIBUTE_DEPTH = 6
RESERVED_KNOWLEDGE_ATTRIBUTE_KEYS = {
    "payload",
    "raw",
    "raw_data",
    "raw_payload",
    "vendor_blob",
    "vendor_payload",
}


class StrictProjectionModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


def _json_depth(value: Any, *, depth: int = 0) -> int:
    if depth > MAX_KNOWLEDGE_ATTRIBUTE_DEPTH:
        return depth
    if isinstance(value, dict):
        return max(
            [depth, *(_json_depth(item, depth=depth + 1) for item in value.values())]
        )
    if isinstance(value, list):
        return max(
            [depth, *(_json_depth(item, depth=depth + 1) for item in value)]
        )
    return depth


def _bounded_attributes(value: dict[str, Any]) -> dict[str, Any]:
    if len(value) > MAX_KNOWLEDGE_ATTRIBUTES:
        raise ValueError(
            f"knowledge attributes cannot exceed {MAX_KNOWLEDGE_ATTRIBUTES} keys"
        )
    def validate_keys(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if not key or len(key) > 128:
                    raise ValueError(
                        "knowledge attribute keys must contain 1 to 128 characters"
                    )
                if key.strip().lower() in RESERVED_KNOWLEDGE_ATTRIBUTE_KEYS:
                    raise ValueError(
                        f"knowledge attribute key {key!r} is reserved for raw "
                        "source data"
                    )
                validate_keys(child)
        elif isinstance(item, list):
            for child in item:
                validate_keys(child)

    validate_keys(value)
    if _json_depth(value) > MAX_KNOWLEDGE_ATTRIBUTE_DEPTH:
        raise ValueError(
            f"knowledge attributes cannot exceed depth {MAX_KNOWLEDGE_ATTRIBUTE_DEPTH}"
        )
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("knowledge attributes must be finite JSON values") from exc
    if len(encoded) > MAX_KNOWLEDGE_ATTRIBUTES_BYTES:
        raise ValueError(
            "knowledge attributes exceed the 32768-byte serialized limit"
        )
    return value


class KnowledgeEntityReference(StrictProjectionModel):
    entity_type: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    external_key: str = Field(min_length=1, max_length=512)
    display_name: str | None = Field(default=None, min_length=1, max_length=255)


class KnowledgeEntityProjection(KnowledgeEntityReference):
    status: str | None = Field(default=None, min_length=1, max_length=64)
    active: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("attributes")
    @classmethod
    def validate_attributes(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_attributes(value)


class KnowledgeRelationshipProjection(StrictProjectionModel):
    relationship_type: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    source: KnowledgeEntityReference
    target: KnowledgeEntityReference
    directed: bool = True
    active: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("attributes")
    @classmethod
    def validate_attributes(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_attributes(value)


class DeviceAdjacencyNeighborProjection(StrictProjectionModel):
    remote_device_key: str = Field(min_length=1, max_length=512)
    remote_system_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )
    local_port: str = Field(min_length=1, max_length=255)
    remote_port: str = Field(min_length=1, max_length=255)
    management_ip: str | None = Field(default=None, max_length=64)

    @field_validator(
        "remote_device_key",
        "remote_system_name",
        "local_port",
        "remote_port",
    )
    @classmethod
    def strip_non_empty_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("adjacency text fields cannot be blank")
        return normalized

    @field_validator("management_ip")
    @classmethod
    def normalize_management_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("management_ip must be an IPv4 or IPv6 address") from exc


class DeviceAdjacencySnapshotProjection(StrictProjectionModel):
    local_device_key: str = Field(min_length=1, max_length=512)
    local_display_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )
    protocol: Literal["lldp", "cdp"]
    complete_snapshot: bool = True
    neighbors: list[DeviceAdjacencyNeighborProjection] = Field(max_length=2000)

    @field_validator("local_device_key", "local_display_name")
    @classmethod
    def strip_local_identity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("local device identity cannot be blank")
        return normalized

    @model_validator(mode="after")
    def require_unique_links(self) -> "DeviceAdjacencySnapshotProjection":
        identities: set[tuple[str, str, str]] = set()
        remote_metadata: dict[str, tuple[str | None, str | None]] = {}
        parallel_links: dict[str, int] = {}
        for neighbor in self.neighbors:
            if neighbor.remote_device_key == self.local_device_key:
                raise ValueError("adjacency snapshots cannot contain self-links")
            identity = (
                neighbor.remote_device_key,
                neighbor.local_port,
                neighbor.remote_port,
            )
            if identity in identities:
                raise ValueError("adjacency snapshots cannot contain duplicate links")
            identities.add(identity)
            metadata = (neighbor.remote_system_name, neighbor.management_ip)
            current_metadata = remote_metadata.setdefault(
                neighbor.remote_device_key,
                metadata,
            )
            if current_metadata != metadata:
                raise ValueError(
                    "adjacency snapshots require consistent metadata per remote device"
                )
            parallel_links[neighbor.remote_device_key] = (
                parallel_links.get(neighbor.remote_device_key, 0) + 1
            )
            if parallel_links[neighbor.remote_device_key] > 128:
                raise ValueError(
                    "adjacency snapshots cannot exceed 128 links per remote device"
                )
        return self


class NetworkObservationProjection(StrictProjectionModel):
    mac_address: str
    ip_address: str | None = None
    ip_addresses: list[str] | None = Field(default=None, max_length=256)
    source: ObservationSource
    collector_device_id: str | None = None
    interface_name: str | None = Field(default=None, max_length=255)
    attachment_present: bool | None = Field(default=None, strict=True)
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    vendor: str | None = Field(default=None, max_length=128)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("vlan_id", mode="before")
    @classmethod
    def reject_boolean_vlan(cls, value):
        return NetworkObservation.reject_boolean_vlan(value)

    def to_domain(
        self,
        *,
        observed_at: datetime,
        collector_device_id: str | None,
    ) -> NetworkObservation:
        values = self.model_dump()
        values["collector_device_id"] = collector_device_id
        values["observed_at"] = observed_at
        return NetworkObservation.model_validate(values)


class NetworkObservationProjectionV2(NetworkObservationFieldsV2):
    def to_domain(self, *, observed_at: datetime, collector_device_id: str | None) -> NetworkObservationV2:
        return NetworkObservationV2.model_validate({**self.model_dump(),
            "observed_at": observed_at, "collector_device_id": collector_device_id})


class WirelessClientProjection(StrictProjectionModel):
    mac_address: str
    ip_address: str | None = None
    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    vendor: str | None = Field(default=None, max_length=128)
    access_point: str | None = Field(default=None, max_length=255)
    ssid: str | None = Field(default=None, max_length=255)
    bssid: str | None = None
    radio: str | None = Field(default=None, max_length=64)
    band: str | None = Field(default=None, max_length=32)
    channel: int | None = Field(default=None, ge=1, le=233)
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    rssi: int | None = Field(default=None, ge=-150, le=0)
    snr: int | None = Field(default=None, ge=-50, le=100)
    connected_at: datetime | None = None
    observed_at: datetime | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("rssi", mode="before")
    @classmethod
    def reject_boolean_rssi(cls, value: object) -> object:
        return WirelessClientObservation.reject_boolean_rssi(value)

    def to_domain(self, *, snapshot_observed_at: datetime) -> WirelessClientObservation:
        values = self.model_dump()
        values["observed_at"] = self.observed_at or snapshot_observed_at
        return WirelessClientObservation.model_validate(values)


class WirelessSnapshotProjection(StrictProjectionModel):
    controller_id: str | None = None
    complete_snapshot: bool = Field(default=True, strict=True)
    clients: list[WirelessClientProjection] = Field(max_length=10000)

    def to_domain(
        self,
        *,
        observed_at: datetime,
        controller_id: str,
    ) -> WirelessSnapshot:
        return WirelessSnapshot(
            controller_id=controller_id,
            observed_at=observed_at,
            complete_snapshot=self.complete_snapshot,
            clients=[
                client.to_domain(snapshot_observed_at=observed_at)
                for client in self.clients
            ],
        )


class AlertEventProjection(StrictProjectionModel):
    event_type: str = Field(min_length=1, max_length=128)
    entity_type: str = Field(min_length=1, max_length=64)
    entity_id: str | None = Field(default=None, min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    severity: AlertSeverity = AlertSeverity.WARNING
    details: dict[str, Any] = Field(default_factory=dict)
    dedup_key: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def require_entity(self) -> "AlertEventProjection":
        if self.entity_id is not None and not self.entity_id.strip():
            raise ValueError("entity_id cannot be blank")
        return self

    def to_domain(
        self,
        *,
        observed_at: datetime,
        subject: str | None,
    ) -> AlertEvent:
        entity_id = self.entity_id or subject
        if not entity_id:
            raise ValueError("alert projection requires entity_id or envelope subject")
        values = self.model_dump()
        values["entity_id"] = entity_id
        values["observed_at"] = observed_at
        return AlertEvent.model_validate(values)


# One authoritative catalog for projection dispatch, authoring and fixture
# validation. Registration is structural support, never collection permission
# or independent semantic qualification.
PROJECTION_CONTRACT_MODELS: dict[str, tuple[EnvelopeKind, type[APIModel]]] = {
    COLLECTOR_CONDITION_V1: (EnvelopeKind.OBSERVATION, CollectorConditionObservation),
    KNOWLEDGE_ENTITY_V1: (EnvelopeKind.ENTITY, KnowledgeEntityProjection),
    KNOWLEDGE_RELATIONSHIP_V1: (EnvelopeKind.RELATIONSHIP, KnowledgeRelationshipProjection),
    DEVICE_ADJACENCY_SNAPSHOT_V1: (EnvelopeKind.RELATIONSHIP, DeviceAdjacencySnapshotProjection),
    NETWORK_OBSERVATION_V1: (EnvelopeKind.OBSERVATION, NetworkObservationProjection),
    NETWORK_OBSERVATION_V2: (EnvelopeKind.OBSERVATION, NetworkObservationProjectionV2),
    WIRELESS_SNAPSHOT_V1: (EnvelopeKind.OBSERVATION, WirelessSnapshotProjection),
    ARTIFACT_INDICATOR_CONTRACT: (EnvelopeKind.OBSERVATION, ArtifactIndicatorEnvelope),
    ALERT_EVENT_V1: (EnvelopeKind.EVENT, AlertEventProjection),
}
SUPPORTED_PROJECTION_CONTRACTS = frozenset(
    (kind, name) for name, (kind, _model) in PROJECTION_CONTRACT_MODELS.items()
)


def projection_contract_catalog() -> list[dict[str, Any]]:
    return [
        {
            "record_type": name,
            "envelope_kind": kind.value,
            "payload_schema": model.model_json_schema(),
            "qualification": "structural_only",
            "independently_verified": False,
            "authorizes_incident_closure": False,
        }
        for name, (kind, model) in sorted(PROJECTION_CONTRACT_MODELS.items())
    ]


class ProjectionAssignment(APIModel):
    projection_id: str
    envelope_id: str
    lease_token: str
    lease_expires_at: datetime


class ProjectionWorkerRead(APIModel):
    id: str
    name: str
    state: KnowledgeProjectionWorkerState
    last_heartbeat_at: datetime
    created_at: datetime
    updated_at: datetime


class KnowledgeEntityRead(APIModel):
    id: str
    namespace: str
    scope_key: str
    scope_device_id: str | None
    scope_site: str | None
    entity_type: str
    external_key: str
    display_name: str
    status: str | None
    active: bool
    attributes: dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    observed_at: datetime
    last_envelope_id: str | None
    created_at: datetime
    updated_at: datetime


class KnowledgeRelationshipRead(APIModel):
    id: str
    namespace: str
    scope_key: str
    scope_device_id: str | None
    scope_site: str | None
    relationship_type: str
    source_entity_id: str
    target_entity_id: str
    directed: bool
    active: bool
    attributes: dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    observed_at: datetime
    last_envelope_id: str | None
    created_at: datetime
    updated_at: datetime


class ProjectionRead(APIModel):
    id: str
    envelope_id: str
    envelope_kind: EnvelopeKind
    envelope_type: str
    envelope_source: str
    envelope_subject: str | None
    envelope_observed_at: datetime
    status: KnowledgeProjectionStatus
    attempt_count: int
    max_attempts: int
    next_attempt_at: datetime
    lease_worker_id: str | None
    lease_expires_at: datetime | None
    result_summary: dict[str, Any]
    error_type: str | None
    error_sha256: str | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ProjectionHealth(APIModel):
    workers_total: int
    workers_online: int
    workers_stale: int
    pending: int
    processing: int
    retry: int
    succeeded: int
    ignored: int
    dead_letter: int
    oldest_ready_age_seconds: float | None
    completed_last_hour: int


class ProjectionRetry(APIModel):
    actor: str = Field(default="projection.operator", min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)
