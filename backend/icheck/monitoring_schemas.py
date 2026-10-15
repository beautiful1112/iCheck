from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from .http_metrics import HTTPMonitorSpec
from .exporter_metrics import ExporterMonitorSpec


class MonitoringModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class MonitoringApproval(MonitoringModel):
    expected_revision: int = Field(ge=0)
    preview_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    gateway_profile: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,63}$")
    modules: list[str] = Field(default_factory=list, max_length=8)
    collectors: list[str] = Field(default_factory=list, max_length=32)
    schedule_seconds: int = Field(default=30, ge=15, le=3600)
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    validity_hours: int = Field(default=168, ge=1, le=720)
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=1000)

    @model_validator(mode="after")
    def validate_names_and_time(self):
        import re
        if self.timeout_seconds >= self.schedule_seconds:
            raise ValueError("Scrape timeout must be shorter than its schedule")
        for names in (self.modules, self.collectors):
            if len(names) != len(set(names)) or any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) for name in names):
                raise ValueError("Module and collector names must be distinct bounded identifiers")
        return self


class MonitoringWithdrawal(MonitoringModel):
    expected_revision: int = Field(ge=1)
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=1000)


class MonitoringEnrollmentRead(MonitoringModel):
    id: str
    connection_id: str
    revision: int
    enabled: bool
    gateway_profile: str
    modules: list[str]
    collectors: list[str]
    schedule_seconds: int
    timeout_seconds: int
    approved_until: datetime
    approved_by: str
    approved_at: datetime


class MonitoringPreview(MonitoringModel):
    device_id: str
    connection_id: str
    preview_hash: str
    eligible: bool
    blockers: list[str]
    warnings: list[str]
    enrollment: MonitoringEnrollmentRead | None
    currently_authorized: bool


class MonitoringTarget(MonitoringModel):
    enrollment_id: str
    enrollment_revision: int
    tenant_id: str
    region_id: str
    device_id: str
    connection_id: str
    device_identity_revision: int
    protocol: Literal["snmp", "windows_exporter", "https_api", "node_exporter", "cadvisor", "vmware_exporter"]
    host: str
    port: int
    site: str
    gateway_profile: str
    credential_profile_id: str | None
    modules: list[str]
    collectors: list[str]
    schedule_seconds: int
    timeout_seconds: int
    approved_until: datetime
    issued_at: datetime
    expires_at: datetime
    http_monitor: HTTPMonitorSpec | None = None
    credential_revision: int | None = Field(default=None, ge=0)
    snmp_module_sha256: str | None = Field(default=None,pattern=r"^[0-9a-f]{64}$")
    exporter_monitor:ExporterMonitorSpec|None=None


class MonitoringSnapshot(MonitoringModel):
    format_version: Literal["icheck.monitoring-targets/v1"] = "icheck.monitoring-targets/v1"
    tenant_id: str
    region_id: str
    issued_at: datetime
    expires_at: datetime
    targets: list[MonitoringTarget] = Field(max_length=10000)
