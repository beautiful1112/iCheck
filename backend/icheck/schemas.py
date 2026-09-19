from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import AlertSeverity, AlertStatus, ObservationSource


MAC_PATTERN = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9a-f]", "", value.lower())
    if not MAC_PATTERN.fullmatch(compact):
        raise ValueError("MAC address must contain exactly 12 hexadecimal digits")
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


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
    created_at: datetime
    updated_at: datetime


class NetworkObservation(APIModel):
    mac_address: str
    ip_address: str | None = None
    source: ObservationSource
    collector_device_id: str | None = None
    interface_name: str | None = Field(default=None, max_length=255)
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    vendor: str | None = Field(default=None, max_length=128)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw_data: dict[str, Any] = Field(default_factory=dict)

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
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("mac_address", "bssid")
    @classmethod
    def validate_mac(cls, value: str | None) -> str | None:
        return normalize_mac(value) if value else value

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        return normalize_ip(value) if value else value


class WirelessSnapshot(APIModel):
    controller_id: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    complete_snapshot: bool = True
    clients: list[WirelessClientObservation] = Field(max_length=10000)


class IngestResult(APIModel):
    observations_received: int
    endpoints_created: int
    endpoints_updated: int
    ip_observations_written: int
    attachments_written: int = 0
    wireless_sessions_written: int = 0
    sessions_closed: int = 0
    alert_ids: list[str] = Field(default_factory=list)


class CurrentIP(APIModel):
    address: str
    source: ObservationSource
    vlan_id: int | None
    collector_device_id: str | None
    first_seen: datetime
    last_seen: datetime


class CurrentAttachment(APIModel):
    source: ObservationSource
    collector_device_id: str | None
    interface_name: str | None
    vlan_id: int | None
    last_seen: datetime


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


class AlertAction(APIModel):
    actor: str = Field(min_length=1, max_length=255)


class DashboardSummary(APIModel):
    devices: int
    endpoints: int
    active_wireless_clients: int
    open_alerts: int
    critical_alerts: int
    recent_alerts: list[AlertRead]
    recent_endpoints: list[EndpointRead]
