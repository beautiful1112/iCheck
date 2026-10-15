from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import AlertSeverity, AlertStatus, ObservationSource


MAC_PATTERN = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9a-f]", "", value.lower())
    if not MAC_PATTERN.fullmatch(compact):
        raise ValueError("MAC address must contain exactly 12 hexadecimal digits")
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def normalize_ip(value: str) -> str:
    normalized = str(ipaddress.ip_address(value))
    if len(normalized) > 45:
        raise ValueError("Normalized IP address exceeds the storage bound")
    return normalized


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class DeviceCreate(APIModel):
    name: str = Field(min_length=1, max_length=255)
    kind: str = Field(min_length=1, max_length=64)
    management_ip: str | None = None
    vendor: str | None = Field(default=None, max_length=128)
    model: str | None = Field(default=None, max_length=128)
    site: str | None = Field(default=None, max_length=128)
    labels: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    created_by: str = Field(default="api.user", min_length=1, max_length=255)

    @field_validator("management_ip")
    @classmethod
    def validate_management_ip(cls, value: str | None) -> str | None:
        return normalize_ip(value) if value else value


class DeviceRead(DeviceCreate):
    id: str
    onboarding_status: str
    revision: int
    identity_revision: int
    created_at: datetime
    updated_at: datetime


class NetworkObservation(APIModel):
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
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def reject_v2_sets_on_legacy_contract(cls, value):
        if isinstance(value, dict) and any(key in value for key in ("ip_bindings", "ip_family_scope", "attachments")):
            raise ValueError("Explicit binding sets require the v2 network observation contract")
        return value

    @field_validator("vlan_id", mode="before")
    @classmethod
    def reject_boolean_vlan(cls, value):
        if isinstance(value, bool):
            raise ValueError("VLAN ID must be an integer, not a boolean")
        return value

    @field_validator("ip_addresses")
    @classmethod
    def normalized_address_set(cls, value):
        if value is None:
            return None
        normalized = [normalize_ip(item) for item in value]
        if len(set(normalized)) != len(normalized):
            raise ValueError("Address sets cannot repeat a normalized IP")
        return sorted(normalized, key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item)), item))

    @model_validator(mode="after")
    def coherent_network_observation(self):
        if self.ip_address is not None and self.ip_addresses is not None:
            raise ValueError("Choose ip_address or the explicit complete ip_addresses set")
        if self.attachment_present is False and self.interface_name is not None:
            raise ValueError("A detached observation cannot also assert an interface")
        if self.attachment_present is True and self.collector_device_id is None and self.interface_name is None:
            raise ValueError("An attached observation requires a collector or interface")
        self.observed_at = self.observed_at.replace(tzinfo=UTC) if self.observed_at.tzinfo is None else self.observed_at.astimezone(UTC)
        return self

    @field_validator("mac_address")
    @classmethod
    def validate_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        return normalize_ip(value) if value else value


class NetworkObservationBatch(APIModel):
    observations: list[NetworkObservation] = Field(min_length=1, max_length=2000)


class WirelessClientObservation(APIModel):
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
        if isinstance(value, bool):
            raise ValueError("RSSI must be a numeric measurement, not a boolean")
        return value

    @field_validator("mac_address", "bssid")
    @classmethod
    def validate_mac(cls, value: str | None) -> str | None:
        return normalize_mac(value) if value else value

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        return normalize_ip(value) if value else value


class WirelessSnapshot(APIModel):
    controller_id: str = Field(min_length=1, max_length=36)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    complete_snapshot: bool = Field(default=True, strict=True)
    clients: list[WirelessClientObservation] = Field(max_length=10000)

    @model_validator(mode="after")
    def coherent_snapshot(self) -> "WirelessSnapshot":
        def utc(value: datetime) -> datetime:
            return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

        self.observed_at = utc(self.observed_at)
        seen: set[str] = set()
        for client in self.clients:
            if client.mac_address in seen:
                raise ValueError("A wireless snapshot must contain each normalized MAC only once")
            seen.add(client.mac_address)
            client.observed_at = utc(client.observed_at or self.observed_at)
            if client.observed_at != self.observed_at:
                raise ValueError("Wireless client observation time must equal the snapshot collection time")
            if client.connected_at is not None:
                client.connected_at = utc(client.connected_at)
                if client.connected_at > self.observed_at:
                    raise ValueError("Wireless connection time cannot exceed the snapshot observation time")
        return self


class IngestResult(APIModel):
    observations_received: int
    endpoints_created: int
    endpoints_updated: int
    ip_observations_written: int
    attachments_written: int = 0
    wireless_sessions_written: int = 0
    network_dispositions: list[dict[str, Any]] = Field(default_factory=list)
    sessions_closed: int = 0
    alert_ids: list[str] = Field(default_factory=list)
    snapshot_disposition: str | None = None


class CurrentIP(APIModel):
    address: str
    source: ObservationSource
    vlan_id: int | None
    collector_device_id: str | None
    first_seen: datetime
    last_seen: datetime
    network_observation_state: str | None = None
    network_observed_at: datetime | None = None
    independently_verified: bool = False
    authorizes_incident_closure: bool = False


class CurrentAttachment(APIModel):
    source: ObservationSource
    collector_device_id: str | None
    interface_name: str | None
    vlan_id: int | None
    last_seen: datetime
    network_observation_state: str | None = None
    network_observed_at: datetime | None = None
    independently_verified: bool = False
    authorizes_incident_closure: bool = False


class CurrentWirelessSession(APIModel):
    id: str
    controller_id: str
    ip_address: str | None
    access_point: str | None
    ssid: str | None
    band: str | None
    channel: int | None
    vlan_id: int | None
    rssi: int | None
    snr: int | None
    connected_at: datetime | None
    last_seen: datetime


class EndpointRead(APIModel):
    id: str
    mac_address: str
    hostname: str | None
    username: str | None
    vendor: str | None
    first_seen: datetime
    last_seen: datetime
    current_ips: list[CurrentIP] = Field(default_factory=list)
    current_attachments: list[CurrentAttachment] = Field(default_factory=list)
    current_wireless_sessions: list[CurrentWirelessSession] = Field(default_factory=list)


class AlertRuleCreate(APIModel):
    name: str = Field(min_length=1, max_length=255)
    event_type: str = Field(min_length=1, max_length=128)
    severity: AlertSeverity
    enabled: bool = True
    conditions: dict[str, Any] = Field(default_factory=dict)
    cooldown_seconds: int = Field(default=300, ge=0, le=86400)


class AlertRuleRead(AlertRuleCreate):
    id: str
    created_at: datetime
    updated_at: datetime


class AlertEvent(APIModel):
    event_type: str = Field(min_length=1, max_length=128)
    entity_type: str = Field(min_length=1, max_length=64)
    entity_id: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    severity: AlertSeverity = AlertSeverity.WARNING
    details: dict[str, Any] = Field(default_factory=dict)
    dedup_key: str | None = Field(default=None, max_length=512)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AlertRead(APIModel):
    id: str
    rule_id: str | None
    dedup_key: str
    event_type: str
    severity: AlertSeverity
    status: AlertStatus
    title: str
    description: str
    entity_type: str
    entity_id: str
    occurrence_count: int
    details: dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    resolved_at: datetime | None
    resolved_by: str | None
    source_retirement_id: str | None = None


class AlertAction(APIModel):
    actor: str = Field(min_length=1, max_length=255)


class SituationSummaryRead(APIModel):
    id: str
    correlation_version: str
    status: str
    severity: AlertSeverity
    priority_score: int
    title: str
    summary: str
    primary_entity_type: str
    primary_entity_id: str
    alert_count: int
    active_alert_count: int
    occurrence_count: int
    correlation_confidence: float
    first_seen: datetime
    last_seen: datetime
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    resolved_at: datetime | None
    resolved_by: str | None
    created_at: datetime
    updated_at: datetime


class SituationAlertEvidenceRead(APIModel):
    alert_id: str
    condition_source_id: str | None = None
    role: str
    correlation_reason: str
    correlation_confidence: float
    correlation_evidence: dict[str, Any]
    event_type: str
    severity: AlertSeverity
    status: AlertStatus
    title: str
    description: str
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime


class SituationEventRead(APIModel):
    id: str
    sequence: int
    event_type: str
    actor: str
    details: dict[str, Any]
    created_at: datetime


class SituationInvestigationRead(APIModel):
    id: str
    title: str
    status: str
    confidence: float | None
    conclusion: str | None
    created_at: datetime
    updated_at: datetime


class SituationDetailRead(APIModel):
    situation: SituationSummaryRead
    alerts: list[SituationAlertEvidenceRead]
    events: list[SituationEventRead]
    investigations: list[SituationInvestigationRead]
    alerts_truncated: bool
    events_truncated: bool


class SituationAction(APIModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str | None = Field(default=None, min_length=3, max_length=4000)


class SituationReconcileRead(APIModel):
    correlated_alerts: int


class OperatorSummary(APIModel):
    """Inventory and source alerts only; no Service Intelligence dependency."""
    devices: int
    endpoints: int
    active_wireless_clients: int
    open_alerts: int
    critical_alerts: int
    recent_alerts: list[AlertRead]


class DashboardSummary(APIModel):
    devices: int
    endpoints: int
    active_wireless_clients: int
    open_alerts: int
    critical_alerts: int
    open_situations: int
    critical_situations: int
    recent_situations: list[SituationSummaryRead]
    recent_alerts: list[AlertRead]
    recent_endpoints: list[EndpointRead]
