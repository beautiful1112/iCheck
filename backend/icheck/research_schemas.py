"""Public technical research, separate from device access and credentials."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class ResearchSearch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=3, max_length=300)
    limit: int = Field(default=5, ge=1, le=8)


class ResearchRead(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=10, max_length=2048)


class ResearchSource(BaseModel):
    title: str
    url: str
    excerpt: str


class ResearchResult(BaseModel):
    status: str
    provider: str
    sources: list[ResearchSource] = Field(default_factory=list)
    retrieved_at: str
    untrusted_reference_material: bool = True
    device_support_verified: bool = False
    warning: str | None = None


class ResearchDocument(BaseModel):
    url: str
    title: str
    text: str
    sha256: str
    retrieved_at: str
    truncated: bool
    untrusted_reference_material: bool = True
    device_support_verified: bool = False


class ResearchSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=0)
    provider: Literal["brave", "searxng"]
    enabled: bool
    api_key: SecretStr | None = None
    searxng_url: str | None = Field(default=None, max_length=2048)
    daily_limit: int = Field(default=100, ge=1, le=10000)

    @field_validator("api_key")
    @classmethod
    def safe_key(cls, value):
        if value is not None:
            raw = value.get_secret_value()
            if not 10 <= len(raw) <= 512 or any(not 33 <= ord(c) <= 126 for c in raw):
                raise ValueError("API key must contain 10 to 512 printable characters without spaces")
        return value


class ResearchSettingsRead(BaseModel):
    source: Literal["managed", "environment", "default"]
    provider: str
    enabled: bool
    server_enabled: bool
    storage_ready: bool
    key_configured: bool
    searxng_url: str | None
    revision: int
    daily_limit: int | None
    calls_today: int
    quota_timezone: str = "UTC"
    last_test_status: str | None
    last_test_at: datetime | None


class ResearchSettingsTest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=1)
    approve_charge: Literal[True]


class ResearchSettingsTestRead(BaseModel):
    status: str
    message: str
    revision: int
    settings: ResearchSettingsRead
