"""Connection configuration is separate from observation and polling authority."""
from datetime import UTC, datetime
import re
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


GroupID = Annotated[str, Field(pattern=r"^[1-9][0-9]{0,19}$")]


def validate_basic(username, password):
    if username is None or password is None:
        raise ValueError("Supply both username and password")
    if ":" in username.get_secret_value() or any(
        ord(char) < 32 or ord(char) == 127
        for value in (username, password) for char in value.get_secret_value()
    ):
        raise ValueError("Invalid Basic authentication credentials")


class IntegrationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    @field_validator("started_at", "updated_at", "finished_at", "observed_at", "last_test_at",
                     "next_run_at", "last_attempt_at", "last_success_at", "lease_expires_at", check_fields=False)
    @classmethod
    def utc_timestamp(cls, value):
        # SQLite does not preserve timezone metadata; persisted timestamps are UTC.
        return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


class ConnectionCreate(IntegrationModel):
    name: str = Field(min_length=1, max_length=128)
    provider: Literal["zabbix", "solarwinds_orion", "rest_webhook"] = "zabbix"
    api_url: str = Field(min_length=1, max_length=2048)
    group_ids: list[GroupID] = Field(default_factory=list, max_length=100)
    token: SecretStr | None = Field(default=None, min_length=16, max_length=4096)
    username: SecretStr | None = Field(default=None, min_length=1, max_length=255)
    password: SecretStr | None = Field(default=None, min_length=1, max_length=2048)

    @model_validator(mode="after")
    def authentication(self):
        if self.provider == "solarwinds_orion":
            if self.token is not None or self.username is None or self.password is None:
                raise ValueError("SolarWinds requires a read-only username and password")
            validate_basic(self.username, self.password)
        elif self.token is None or self.username is not None or self.password is not None:
            raise ValueError("This provider requires an API token")
        return self

    @field_validator("name")
    @classmethod
    def name_safe(cls, value):
        if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Use a name without surrounding whitespace or control characters")
        return value

    @field_validator("group_ids")
    @classmethod
    def groups_safe(cls, value):
        if any(int(group) > 2**64 - 1 for group in value):
            raise ValueError("Host group identifier is outside the supported range")
        return sorted(set(value), key=int)

    @field_validator("token")
    @classmethod
    def token_safe(cls, value):
        if value is None:
            return value
        if re.fullmatch(r"[A-Za-z0-9._~+/=-]+", value.get_secret_value()) is None:
            raise ValueError("Use an API token, not a password or complete HTTP header")
        return value


class ConnectionUpdate(IntegrationModel):
    expected_revision: int = Field(ge=1, strict=True)
    enabled: bool = Field(strict=True)
    name: str | None = Field(default=None, min_length=1, max_length=128)
    group_ids: list[GroupID] | None = Field(default=None, min_length=1, max_length=100)
    token: SecretStr | None = Field(default=None, min_length=16, max_length=4096)
    username: SecretStr | None = Field(default=None, min_length=1, max_length=255)
    password: SecretStr | None = Field(default=None, min_length=1, max_length=2048)
    name_safe = field_validator("name")(lambda value: ConnectionCreate.name_safe(value) if value is not None else value)
    groups_safe = field_validator("group_ids")(lambda value: ConnectionCreate.groups_safe(value) if value is not None else value)
    token_safe = field_validator("token")(lambda value: ConnectionCreate.token_safe(value) if value is not None else value)


class ConnectionRead(IntegrationModel):
    id: str
    name: str
    provider: Literal["zabbix", "solarwinds_orion", "rest_webhook"]
    api_url: str
    group_ids: list[str]
    enabled: bool
    revision: int
    token_configured: bool
    last_test_status: str | None
    last_test_error: str | None
    last_test_at: datetime | None
    last_test_revision: int | None
    synchronization: Literal["manual_and_scheduled"] = "manual_and_scheduled"


class ConnectionTest(IntegrationModel):
    expected_revision: int = Field(ge=1, strict=True)
    confirm: bool = Field(strict=True)

    @field_validator("confirm")
    @classmethod
    def confirmed(cls, value):
        if value is not True:
            raise ValueError("Confirm this outbound connection test explicitly")
        return value


class ConnectionTestResult(IntegrationModel):
    connection_id: str
    revision: int
    status: Literal["succeeded", "failed"]
    error_code: str | None = None
    checked_at: datetime
    resource_count: int | None = None
    truncated: bool | None = None
    meaning: str = "Tests API access only; no resource enrollment, synchronization or device-health claim"


class GroupDiscovery(ConnectionTest):
    search: str = Field(default="", max_length=128, pattern=r"^[^\x00-\x1f\x7f]*$")


class SyncStep(ConnectionTest):
    expected_cursor: int = Field(ge=0, le=10000, strict=True)


class SyncRead(IntegrationModel):
    id: str
    connection_id: str
    connection_revision: int
    status: str
    cursor: int
    total: int
    observed: int
    error_code: str | None
    can_resume: bool
    started_at: datetime
    updated_at: datetime
    finished_at: datetime | None


class ImportedResourceRead(IntegrationModel):
    id: str
    connection_id: str
    remote_id: str
    name: str
    monitoring_enabled: bool
    observed_at: datetime
    last_run_id: str
    health: Literal["unknown"] = "unknown"


class ScheduleUpdate(ConnectionTest):
    expected_schedule_revision: int = Field(ge=0, strict=True)
    enabled: bool = Field(strict=True)
    interval_seconds: int = Field(default=900, ge=300, le=86400, strict=True)
    retention_days: int = Field(default=30, ge=7, le=365, strict=True)


class ScheduleRead(IntegrationModel):
    connection_id: str
    revision: int = 0
    connection_revision: int
    enabled: bool = False
    interval_seconds: int = 900
    retention_days: int = 30
    next_run_at: datetime | None = None
    active_run_id: str | None = None
    lease_expires_at: datetime | None = None
    failures: int = 0
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None


class AssetBindingItem(IntegrationModel):
    resource_id: UUID
    expected_binding_revision: int = Field(ge=0, strict=True)
    source_name: str = Field(min_length=1, max_length=255)
    device_id: UUID | None
    expected_device_revision: int | None = Field(default=None, ge=1, strict=True)
    expected_device_identity_revision: int | None = Field(default=None, ge=1, strict=True)

    @model_validator(mode="after")
    def device_versions(self):
        if self.device_id is not None and (self.expected_device_revision is None or self.expected_device_identity_revision is None):
            raise ValueError("A device selection requires its reviewed revisions")
        if self.device_id is None and (self.expected_device_revision is not None or self.expected_device_identity_revision is not None):
            raise ValueError("Unlinking does not accept device revisions")
        return self


class AssetBindingsUpdate(ConnectionTest):
    expected_scan_id: UUID | None = None
    items: list[AssetBindingItem] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def distinct(self):
        ids = [item.resource_id for item in self.items]
        devices = [item.device_id for item in self.items if item.device_id is not None]
        if len(set(ids)) != len(ids) or len(set(devices)) != len(devices):
            raise ValueError("Select each source resource and canonical asset only once")
        if devices and self.expected_scan_id is None:
            raise ValueError("Linking requires a reviewed completed inventory scan")
        return self


class AlertFeedUpdate(ConnectionTest):
    expected_feed_revision: int = Field(ge=0, strict=True)
    enabled: bool = Field(strict=True)
    interval_seconds: int = Field(default=60, ge=60, le=3600, strict=True)


class ExternalAlertSilence(ConnectionTest):
    expected_event_checked_at: AwareDatetime
