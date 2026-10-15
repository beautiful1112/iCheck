"""Reviewed, fixed-origin guided connections. No arbitrary key-bearing URLs."""
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ProviderPreset:
    id: str
    label: str
    base_url: str
    provider_type: str = "openai_compatible"
    auth_type: str = "bearer"
    notes: str = "Choose a model from your account and test it before assigning routes."


PRESETS = {p.id: p for p in (
    ProviderPreset("openrouter", "OpenRouter", "https://openrouter.ai/api/v1"),
    ProviderPreset("openai", "OpenAI", "https://api.openai.com/v1"),
    ProviderPreset("anthropic", "Anthropic Claude", "https://api.anthropic.com/v1", "anthropic", "api_key",
                   "Uses the native Claude Messages API. Requires an Anthropic API key, not a Claude subscription login."),
    ProviderPreset("gemini", "Google Gemini", "https://generativelanguage.googleapis.com/v1beta/openai",
                   notes="Uses Gemini's OpenAI-compatible API with a Gemini API key; not Vertex AI credentials."),
    ProviderPreset("deepseek", "DeepSeek", "https://api.deepseek.com",
                   notes="Uses JSON mode with application-side schema validation. Test your chosen chat model first."),
    ProviderPreset("qwen_cn", "Qwen — Beijing", "https://dashscope.aliyuncs.com/compatible-mode/v1",
                   notes="Use a Beijing-region Model Studio key. This is the supported legacy regional endpoint; workspace-specific endpoints use Advanced setup."),
    ProviderPreset("qwen_sg", "Qwen — Singapore", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
                   notes="Use a Singapore-region Model Studio key. This is the supported legacy regional endpoint; workspace-specific endpoints use Advanced setup."),
)}


def preset_catalog():
    return [asdict(p) for p in PRESETS.values()]


def preset_for_url(base_url):
    return next((p for p in PRESETS.values() if p.base_url == base_url.rstrip("/")), None)
