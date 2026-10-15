"""Typed native Grafana plugin inputs; service tokens are write-only."""
from typing import Any, Literal
from datetime import datetime
import re
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

UID = r"^[A-Za-z0-9_-]{1,64}$"


class GrafanaModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class GrafanaConnectionCreate(GrafanaModel):
    name: str = Field(default="native-grafana", min_length=1, max_length=128)
    api_url: str = "http://127.0.0.1:3001/grafana"
    public_url: str = Field(max_length=2048)
    datasource_uid: str = Field(default="icheck-prometheus", pattern=UID)
    folder_uid: str = Field(default="icheck", pattern=UID)
    token: SecretStr = Field(min_length=10, max_length=4096)
    shared_dataset_acknowledged: Literal[True]

    @field_validator("token")
    @classmethod
    def token_safe(cls, value):
        if re.fullmatch(r"[A-Za-z0-9_./+=-]+", value.get_secret_value()) is None:
            raise ValueError("Use a Grafana service-account token, not a password or header value")
        return value


class GrafanaConnectionUpdate(GrafanaModel):
    expected_revision: int = Field(ge=1)
    enabled: bool
    token: SecretStr | None = Field(default=None, min_length=10, max_length=4096)
    token_safe = field_validator("token")(lambda value: GrafanaConnectionCreate.token_safe(value) if value is not None else value)


class GrafanaConnectionRead(GrafanaModel):
    id: str
    name: str
    api_url: str
    public_url: str
    datasource_uid: str
    folder_uid: str
    enabled: bool
    token_configured: bool
    shared_dataset_acknowledged: bool
    revision: int


class GrafanaMetricQuery(GrafanaModel):
    query: str = Field(min_length=1, max_length=2048)
    limit: int = Field(default=20, ge=1, le=100)


# Shape guidance for native Grafana settings, not a second date-math parser.
# Absence remains distinct from an explicit value for old proposals and folders.
DISPLAY_PROPERTIES = {
    "description": {"type": "string", "maxLength": 4000},
    "time": {"type": "object", "additionalProperties": False, "required": ["from", "to"],
        "description": "Saved default time range, not a title or URL filter. For the last hour use from=now-1h, to=now. Preserve current values on unrelated revisions.",
        "properties": {name: {"type": "string", "minLength": 1, "maxLength": 128,
            "not": {"pattern": r"[\x00-\x1f\x7f]"},
            "description": "Native Grafana relative date math or absolute timestamp string."}
            for name in ("from", "to")}},
    "refresh": {"type": "string", "maxLength": 32,
        "description": 'Browser auto-refresh interval, e.g. 30s or 1m. Use the empty string "" to turn it off. This does not configure collection or an agent schedule.'},
    "timezone": {"type": "string", "maxLength": 128,
        "description": "Native Grafana timezone: browser, utc or an IANA timezone. Preserve the existing value unless asked to change it."},
}
DISPLAY_GUIDANCE = ' Include requested saved time.from/time.to and refresh explicitly; a panel title or dashboard URL is not a saved time setting. Use refresh="" for off, not omission. On revisions copy the current definition, including time, refresh and timezone, then change only the requested settings. Report any unmet request rather than claiming full completion.'


class GrafanaPreview(GrafanaModel):
    resource_kind: Literal["dashboard", "folder"] = "dashboard"
    resource_uid: str | None = Field(default=None, pattern=UID)
    folder_uid: str | None = Field(default=None, pattern=UID)
    expected_resource_version: str | None = Field(default=None, min_length=1, max_length=128)
    definition: dict[str, Any]


class GrafanaConfirm(GrafanaModel):
    expected_plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    confirm: Literal[True]


class GrafanaChangeRead(GrafanaModel):
    id: str
    connection_id: str
    resource_kind: str
    resource_uid: str
    folder_uid: str
    definition: dict[str, Any]
    previous_resource: dict[str, Any] | None
    expected_resource_version: str | None
    plan_hash: str
    status: str
    approved_by: str | None
    applied_resource: dict[str, Any] | None
    error_code: str | None
    restore_of_id: str | None
    created_by: str
    created_at: datetime
    applied_at: datetime | None
    review_url: str
    resource_url: str
    warning: str = "Dashboard filters do not enforce device-level isolation; validation is not proof of fresh collection."
