"""Static development metadata. Reading this catalog never opens a connection."""
from .contracts import ProviderDescriptor


PROVIDERS = (
    ProviderDescriptor(
        provider="zabbix",
        display_name="Zabbix",
        development_stage="guided_sync",
        configurable=True,
        implemented_operations=("resources.read", "alerts.read", "metrics.history.read"),
        protocol_targets=("7.0", "7.4"),
    ),
    ProviderDescriptor(
        provider="solarwinds_orion",
        display_name="SolarWinds Platform / Orion",
        development_stage="guided_sync",
        configurable=True,
        implemented_operations=("resources.read", "alerts.read", "metrics.history.read"),
        protocol_targets=("SWIS v3 / 2024.2 schema: node alerts and response-time history",),
    ),
    ProviderDescriptor(
        provider="rest_webhook",
        display_name="REST / webhook connector template",
        development_stage="guided_sync",
        configurable=True,
        implemented_operations=("resources.read", "alerts.read", "metrics.history.read", "webhook.recheck"),
        protocol_targets=("icheck.monitoring-bridge/v1",),
    ),
)
