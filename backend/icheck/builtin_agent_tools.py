from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .agent_schemas import AgentToolCreate
from .models import AgentToolRegistration
from .services.agent_runtime import create_agent_tool


BUILTIN_AGENT_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "inventory.get_device",
        "description": (
            "Read a device identity, onboarding status, and bounded connection "
            "health summary by durable device ID."
        ),
        "transport": "internal",
        "handler": "inventory.get_device",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["device_id"],
            "properties": {
                "device_id": {"type": "string", "minLength": 1, "maxLength": 36},
            },
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "id",
                "name",
                "kind",
                "management_ip",
                "site",
                "onboarding_status",
                "connections",
            ],
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "kind": {"type": "string"},
                "management_ip": {"type": ["string", "null"]},
                "site": {"type": ["string", "null"]},
                "onboarding_status": {"type": "string"},
                "connections": {
                    "type": "array",
                    "maxItems": 32,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "id",
                            "protocol",
                            "verification_status",
                            "activation_status",
                            "runtime_status",
                            "health_reason",
                        ],
                        "properties": {
                            "id": {"type": "string"},
                            "protocol": {"type": "string"},
                            "verification_status": {"type": "string"},
                            "activation_status": {"type": ["string", "null"]},
                            "runtime_status": {"type": ["string", "null"]},
                            "health_reason": {"type": ["string", "null"]},
                        },
                    },
                },
            },
        },
        "risk_level": "observe",
        "read_only": True,
        "required_permissions": ["assets.read"],
        "timeout_seconds": 10,
        "max_result_bytes": 100_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "alerts.list_open",
        "description": (
            "List a bounded set of open or acknowledged alerts, optionally "
            "filtered by severity."
        ),
        "transport": "internal",
        "handler": "alerts.list_open",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "severity": {
                    "enum": ["info", "warning", "critical"],
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["alerts"],
            "properties": {
                "alerts": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "id",
                            "severity",
                            "status",
                            "title",
                            "entity_type",
                            "entity_id",
                            "last_seen",
                            "occurrence_count",
                        ],
                        "properties": {
                            "id": {"type": "string"},
                            "severity": {"type": "string"},
                            "status": {"type": "string"},
                            "title": {"type": "string"},
                            "entity_type": {"type": "string"},
                            "entity_id": {"type": "string"},
                            "last_seen": {"type": "string"},
                            "occurrence_count": {"type": "integer"},
                        },
                    },
                },
            },
        },
        "risk_level": "observe",
        "read_only": True,
        "required_permissions": ["alerts.read"],
        "timeout_seconds": 10,
        "max_result_bytes": 250_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "inventory.get_endpoint_history",
        "description": (
            "Read bounded IP, wired attachment, and wireless-controller history "
            "for one endpoint selected by durable ID, MAC address, or IP address."
        ),
        "transport": "internal",
        "handler": "inventory.get_endpoint_history",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "oneOf": [
                {"required": ["endpoint_id"]},
                {"required": ["mac_address"]},
                {"required": ["ip_address"]},
            ],
            "properties": {
                "endpoint_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "mac_address": {"type": "string", "minLength": 12, "maxLength": 32},
                "ip_address": {"type": "string", "minLength": 2, "maxLength": 45},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "id",
                "mac_address",
                "hostname",
                "vendor",
                "first_seen",
                "last_seen",
                "ip_history",
                "wired_history",
                "wireless_history",
            ],
            "properties": {
                "id": {"type": "string"},
                "mac_address": {"type": "string"},
                "hostname": {"type": ["string", "null"]},
                "vendor": {"type": ["string", "null"]},
                "first_seen": {"type": "string"},
                "last_seen": {"type": "string"},
                "ip_history": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "address",
                            "source",
                            "collector_device_id",
                            "vlan_id",
                            "active",
                            "first_seen",
                            "last_seen",
                        ],
                        "properties": {
                            "address": {"type": "string"},
                            "source": {"type": "string"},
                            "collector_device_id": {"type": ["string", "null"]},
                            "vlan_id": {"type": ["integer", "null"]},
                            "active": {"type": "boolean"},
                            "first_seen": {"type": "string"},
                            "last_seen": {"type": "string"},
                        },
                    },
                },
                "wired_history": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "source",
                            "collector_device_id",
                            "interface_name",
                            "vlan_id",
                            "active",
                            "first_seen",
                            "last_seen",
                        ],
                        "properties": {
                            "source": {"type": "string"},
                            "collector_device_id": {"type": ["string", "null"]},
                            "interface_name": {"type": ["string", "null"]},
                            "vlan_id": {"type": ["integer", "null"]},
                            "active": {"type": "boolean"},
                            "first_seen": {"type": "string"},
                            "last_seen": {"type": "string"},
                        },
                    },
                },
                "wireless_history": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "controller_id",
                            "ip_address",
                            "access_point",
                            "ssid",
                            "band",
                            "channel",
                            "vlan_id",
                            "rssi",
                            "snr",
                            "active",
                            "connected_at",
                            "disconnected_at",
                            "first_seen",
                            "last_seen",
                        ],
                        "properties": {
                            "controller_id": {"type": "string"},
                            "ip_address": {"type": ["string", "null"]},
                            "access_point": {"type": ["string", "null"]},
                            "ssid": {"type": ["string", "null"]},
                            "band": {"type": ["string", "null"]},
                            "channel": {"type": ["integer", "null"]},
                            "vlan_id": {"type": ["integer", "null"]},
                            "rssi": {"type": ["integer", "null"]},
                            "snr": {"type": ["integer", "null"]},
                            "active": {"type": "boolean"},
                            "connected_at": {"type": ["string", "null"]},
                            "disconnected_at": {"type": ["string", "null"]},
                            "first_seen": {"type": "string"},
                            "last_seen": {"type": "string"},
                        },
                    },
                },
            },
        },
        "risk_level": "observe",
        "read_only": True,
        "required_permissions": ["endpoints.read"],
        "timeout_seconds": 10,
        "max_result_bytes": 500_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "metrics.query_instant",
        "description": (
            "Run one bounded instant PromQL query against a registered, enabled "
            "Prometheus-compatible backend. Use for current metric evidence, not "
            "for long time ranges."
        ),
        "transport": "internal",
        "handler": "metrics.query_instant",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["backend_id", "query"],
            "properties": {
                "backend_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "query": {"type": "string", "minLength": 1, "maxLength": 2048},
                "time": {"type": "string", "format": "date-time"},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 15},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "backend_id",
                "mode",
                "result_type",
                "result",
                "warnings",
                "infos",
                "queried_at",
            ],
            "properties": {
                "backend_id": {"type": "string"},
                "mode": {"const": "instant"},
                "result_type": {"type": "string"},
                "result": {"type": "array", "maxItems": 100, "items": {}},
                "warnings": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {"type": "string"},
                },
                "infos": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {"type": "string"},
                },
                "queried_at": {"type": "string"},
            },
        },
        "risk_level": "diagnose",
        "read_only": True,
        "required_permissions": ["metrics.read"],
        "timeout_seconds": 20,
        "max_result_bytes": 1_000_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
)


def ensure_builtin_agent_tools(db: Session) -> list[AgentToolRegistration]:
    tools: list[AgentToolRegistration] = []
    for document in BUILTIN_AGENT_TOOLS:
        existing = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == document["name"]
            )
        )
        if existing is not None:
            tools.append(existing)
            continue
        tools.append(
            create_agent_tool(db, AgentToolCreate.model_validate(document))
        )
    return tools
