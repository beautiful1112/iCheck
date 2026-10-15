"""Write-only secret inputs; all outputs are explicit redacted metadata."""
from datetime import datetime
from typing import Literal

from pydantic import Field, SecretStr, field_validator

from .ai_schemas import AIStrictModel, AIModelRead, AIModelRouteRead, AIProviderHealth


class SecretInput(AIStrictModel):
    @field_validator("api_key", check_fields=False)
    @classmethod
    def safe_key(cls, value: SecretStr | None):
        if value is not None:
            raw = value.get_secret_value()
            if not 10 <= len(raw) <= 512 or any(not 33 <= ord(c) <= 126 for c in raw):
                raise ValueError("API key must contain 10 to 512 printable characters without spaces")
        return value


class OpenRouterConnect(SecretInput):
    name: str = Field(default="openrouter", min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9_. -]*$")
    api_key: SecretStr
    approve_outbound: Literal[True]
    request_timeout_seconds: int = Field(default=120, ge=1, le=120)


class OpenRouterConnectionUpdate(SecretInput):
    expected_revision: int = Field(ge=1)
    api_key: SecretStr | None = None
    outbound_enabled: bool


class OpenRouterConnectionRead(AIStrictModel):
    provider_id: str
    name: str
    preset: str = "openrouter"
    base_url: str = "https://openrouter.ai/api/v1"
    credential_profile_id: str
    key_configured: bool = True
    provider_enabled: bool
    outbound_enabled: bool
    revision: int
    request_timeout_seconds: int = Field(ge=1, le=120)
    last_health_status: str | None
    last_checked_at: datetime | None


class OpenRouterSetupRead(AIStrictModel):
    storage_ready: bool
    endpoint: str = "https://openrouter.ai/api/v1"
    connections: list[OpenRouterConnectionRead]
    presets: list[dict[str, str]] = Field(default_factory=list)


class ManagedAIConnect(OpenRouterConnect):
    preset: Literal["openrouter", "openai", "anthropic", "gemini", "deepseek", "qwen_cn", "qwen_sg"]


class OpenRouterModelRead(AIStrictModel):
    id: str
    name: str
    context_window: int | None = None
    max_output_tokens: int | None = None
    capabilities: list[str]
    supported_parameters: list[str] = Field(default_factory=list)
    reasoning_mandatory: bool | None = None
    reasoning_supported_efforts: list[Literal["none", "minimal", "low", "medium", "high", "xhigh", "max"]] = Field(default_factory=list)
    reasoning_effort_unrestricted: bool = False


class OpenRouterCheckRead(AIStrictModel):
    connection_revision: int
    health: AIProviderHealth
    models: list[OpenRouterModelRead]
    configuration_hash: str


class OpenRouterConfigure(AIStrictModel):
    expected_connection_revision: int = Field(ge=1)
    model_id: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    cost_class: Literal["low", "standard", "premium"] = "standard"
    purposes: list[Literal["investigation", "capability.authoring"]] = Field(min_length=1, max_length=2)
    replace_existing_routes: bool = False
    expected_configuration_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    probe_reservation_id: str | None = Field(default=None, min_length=36, max_length=36)
    max_iterations: int = Field(default=8, ge=1, le=100)
    max_tool_calls: int = Field(default=20, ge=1, le=500)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    token_budget: int = Field(default=50000, ge=1, le=10000000)


class OpenRouterConfiguredRead(AIStrictModel):
    model: AIModelRead
    routes: list[AIModelRouteRead]


class ManagedAIConfigure(OpenRouterConfigure):
    expected_configuration_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    probe_reservation_id: str = Field(min_length=36, max_length=36)


class OpenRouterProbe(AIStrictModel):
    expected_connection_revision: int = Field(ge=1)
    model_id: str = Field(min_length=1, max_length=255)
    approve_charge: Literal[True]


class OpenRouterProbeRead(AIStrictModel):
    passed: bool
    model_id: str
    checked_at: datetime
    diagnostic: dict | None = None
    quota_reservation_id: str
