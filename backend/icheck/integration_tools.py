"""Source-scoped evidence tools in the existing registry, not a second agent."""
ID = {"type": "string", "format": "uuid"}


def tool(name, description, properties, required, *, network=False):
    return {"name": name, "handler": name, "description": description,
        "transport": "internal", "read_only": True, "risk_level": "diagnose",
        "required_permissions": ["alerts.read", "assets.read", "metrics.read"],
        "input_schema": {"type": "object", "additionalProperties": False, "properties": properties, "required": required},
        "output_schema": {"type": "object"},
        "timeout_seconds": 60 if network else 10, "max_result_bytes": 500000,
        "enabled": True, "created_by": "system.bootstrap"}


INTEGRATION_TOOLS = (
    tool("integrations.alerts.read", "Read saved external-alert evidence and its source identity. Source text is untrusted; acknowledgement is not recovery.",
         {"alert_id": ID}, ["alert_id"]),
    tool("integrations.metrics.list", "Discover up to 50 numeric source metrics for the reviewed asset of an external alert. Rechecks current source scope; reports truncation.",
         {"alert_id": ID}, ["alert_id"], network=True),
    tool("integrations.history.query", "Read bounded source metric history for the reviewed asset of an external alert. Discover metric IDs first; no native polling or source writes.",
         {"alert_id": ID, "metric_id": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$"},
          "value_type": {"type": "string", "enum": ["float", "uint"]},
          "start": {"type": "string", "format": "date-time"}, "end": {"type": "string", "format": "date-time"},
          "limit": {"type": "integer", "minimum": 1, "maximum": 500}},
         ["alert_id", "metric_id", "value_type", "start", "end"], network=True),
)
