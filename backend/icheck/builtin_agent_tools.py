from __future__ import annotations

from copy import deepcopy
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .agent_schemas import AgentToolCreate
from .database import session_namespace
from .models import AgentToolRegistration
from .services.agent_runtime import create_agent_tool
from .situation_impact_schemas import SituationImpactRead
from .grafana_tools import GRAFANA_TOOLS
from .metric_alert_tools import METRIC_ALERT_TOOLS


KNOWLEDGE_NODE_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "id",
        "entity_type",
        "external_key",
        "display_name",
        "status",
        "active",
        "site",
        "last_seen",
    ],
    "properties": {
        "id": {"type": "string"},
        "entity_type": {"type": "string"},
        "external_key": {"type": "string"},
        "display_name": {"type": "string"},
        "status": {"type": ["string", "null"]},
        "active": {"type": "boolean"},
        "site": {"type": ["string", "null"]},
        "last_seen": {"type": "string"},
    },
}


LOG_ENTRY_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["timestamp", "labels", "line"],
    "properties": {
        "timestamp": {"type": "string"},
        "labels": {
            "type": "object",
            "additionalProperties": {"type": "string", "maxLength": 512},
            "maxProperties": 32,
        },
        "line": {"type": "string", "maxLength": 4096},
    },
}


WIRELESS_CLIENT_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "session_id",
        "endpoint_id",
        "mac_address",
        "hostname",
        "vendor",
        "ip_address",
        "access_point",
        "ssid",
        "bssid",
        "radio",
        "band",
        "channel",
        "vlan_id",
        "rssi",
        "snr",
        "active",
        "connected_at",
        "last_seen",
    ],
    "properties": {
        "session_id": {"type": "string"},
        "endpoint_id": {"type": "string"},
        "mac_address": {"type": "string"},
        "hostname": {"type": ["string", "null"]},
        "vendor": {"type": ["string", "null"]},
        "ip_address": {"type": ["string", "null"]},
        "access_point": {"type": ["string", "null"]},
        "ssid": {"type": ["string", "null"]},
        "bssid": {"type": ["string", "null"]},
        "radio": {"type": ["string", "null"]},
        "band": {"type": ["string", "null"]},
        "channel": {"type": ["integer", "null"]},
        "vlan_id": {"type": ["integer", "null"]},
        "rssi": {"type": ["integer", "null"]},
        "snr": {"type": ["integer", "null"]},
        "active": {"type": "boolean"},
        "connected_at": {"type": ["string", "null"]},
        "last_seen": {"type": "string"},
    },
}


def _log_query_output_schema(*, device_scoped: bool) -> dict[str, Any]:
    required = [
        "backend_id",
        "provider",
        "entries",
        "truncated",
        "warnings",
        "queried_at",
    ]
    properties: dict[str, Any] = {
        "backend_id": {"type": "string"},
        "provider": {"const": "loki"},
        "entries": {
            "type": "array",
            "maxItems": 1000,
            "items": LOG_ENTRY_OUTPUT_SCHEMA,
        },
        "truncated": {"type": "boolean"},
        "warnings": {
            "type": "array",
            "maxItems": 100,
            "items": {"type": "string", "maxLength": 1000},
        },
        "queried_at": {"type": "string"},
    }
    if device_scoped:
        required.insert(1, "device_id")
        properties["device_id"] = {"type": "string"}
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


SAVED_REPORT_ITEM_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "instance_id", "artifact_id", "artifact_version_id", "artifact_version",
        "generated_at", "snapshot_sha256", "artifact_content_hash",
        "overall_status", "section_count", "sample_count", "drifted_section_count",
    ],
    "properties": {
        "instance_id": {"type": "string", "maxLength": 36},
        "artifact_id": {"type": "string", "maxLength": 36},
        "artifact_version_id": {"type": "string", "maxLength": 36},
        "artifact_version": {"type": "integer", "minimum": 1},
        "generated_at": {"type": "string", "maxLength": 35},
        "snapshot_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "artifact_content_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "overall_status": {"enum": ["healthy", "warning", "critical", "unknown"]},
        "section_count": {"type": "integer", "minimum": 1, "maximum": 20},
        "sample_count": {"type": "integer", "minimum": 0},
        "drifted_section_count": {"type": "integer", "minimum": 0, "maximum": 20},
    },
}


SAVED_REPORT_SECTION_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "section_key", "service_key", "indicator_key", "kind", "unit", "state",
        "drift_code", "current_status", "current_value", "sample_count",
        "minimum", "maximum", "average", "first_observed_at", "last_observed_at",
        "trend", "breach_direction", "warning_threshold", "critical_threshold",
        "samples_truncated",
    ],
    "properties": {
        "section_key": {"type": "string", "maxLength": 128},
        "service_key": {"type": "string", "maxLength": 128},
        "indicator_key": {"type": "string", "maxLength": 128},
        "kind": {"enum": ["availability", "latency", "error_rate", "throughput",
                          "saturation", "business", "custom", None]},
        "unit": {"type": ["string", "null"], "maxLength": 32},
        "state": {"enum": ["ready", "no_data", "drifted"]},
        "drift_code": {"type": ["string", "null"], "maxLength": 64},
        "current_status": {"enum": ["healthy", "warning", "critical", "unknown"]},
        "current_value": {"type": ["number", "null"]},
        "sample_count": {"type": "integer", "minimum": 0},
        "minimum": {"type": ["number", "null"]},
        "maximum": {"type": ["number", "null"]},
        "average": {"type": ["number", "null"]},
        "first_observed_at": {"type": ["string", "null"], "maxLength": 35},
        "last_observed_at": {"type": ["string", "null"], "maxLength": 35},
        "trend": {"enum": ["improving", "degrading", "stable", "insufficient_data"]},
        "breach_direction": {"enum": ["above", "below", "none", None]},
        "warning_threshold": {"type": ["number", "null"]},
        "critical_threshold": {"type": ["number", "null"]},
        "samples_truncated": {"type": "boolean"},
    },
}


BUILTIN_AGENT_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "reports.get_retained_proofs",
        "description": (
            "Read bounded exact proof references and recorded relationship IDs from one saved v2 report. "
            "Current and initiating material scope are rechecked. Historical records do not grant execution "
            "authority, prove remediation causality, or verify physical truth. Full records remain in the report UI/API."
        ),
        "transport": "internal", "handler": "reports.get_retained_proofs",
        "input_schema": {"type": "object", "additionalProperties": False, "required": ["instance_id"],
            "properties": {"instance_id": {"type": "string", "minLength": 36, "maxLength": 36}}},
        "output_schema": {"type": "object", "additionalProperties": False,
            "required": ["format_version", "instance_id", "historical", "grants_future_authority",
                "remediation_causality_proven", "physical_truth_automatically_verified", "references"],
            "properties": {
                "format_version": {"const": "icheck.agent-retained-report-proofs/v1"},
                "instance_id": {"type": "string", "maxLength": 36},
                "historical": {"const": True}, "grants_future_authority": {"const": False},
                "remediation_causality_proven": {"const": False}, "physical_truth_automatically_verified": {"const": False},
                "references": {"type": "array", "minItems": 1, "maxItems": 20, "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["section_key", "reference_kind", "reference_id", "recorded_at", "relations"],
                    "properties": {
                        "section_key": {"type": "string", "maxLength": 128},
                        "reference_kind": {"enum": ["source_replacement_request", "source_retirement", "situation_closure_receipt"]},
                        "reference_id": {"type": "string", "maxLength": 36},
                        "recorded_at": {"type": "string", "maxLength": 35},
                        "relations": {"type": "array", "maxItems": 12, "items": {
                            "type": "object", "additionalProperties": False, "required": ["role", "id"],
                            "properties": {"role": {"enum": ["old_source_id", "new_source_id", "old_qualification_review_id",
                                "new_qualification_review_id", "prior_retirement_id", "request_id", "review_id", "old_watermark_receipt_id",
                                "new_receipt_id", "superseded_alert_id", "situation_id", "grant_id", "attempt_id", "event_id"]},
                                "id": {"type": "string", "maxLength": 36}}}},
                    }}},
            }},
        "risk_level": "observe", "read_only": True,
        "required_permissions": ["services.read", "alerts.read"], "timeout_seconds": 10,
        "max_result_bytes": 40_000, "enabled": True, "created_by": "system.bootstrap",
    },
    {
        "name": "reports.list_saved",
        "description": (
            "Find up to ten currently authorized retained service-health report "
            "snapshots across published or deprecated Report versions. Use for "
            "historical context and cite the returned instance IDs. Results "
            "are saved evidence, not a current health measurement."
        ),
        "transport": "internal",
        "handler": "reports.list_saved",
        "input_schema": {
            "type": "object", "additionalProperties": False, "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 10},
                "after_id": {"type": "string", "minLength": 36, "maxLength": 36},
            },
        },
        "output_schema": {
            "type": "object", "additionalProperties": False,
            "required": ["format_version", "evidence_basis", "items", "next_after_id"],
            "properties": {
                "format_version": {"const": "icheck.agent-saved-reports/v1"},
                "evidence_basis": {"const": "saved_snapshot"},
                "items": {"type": "array", "maxItems": 10, "items": SAVED_REPORT_ITEM_OUTPUT_SCHEMA},
                "next_after_id": {"type": ["string", "null"], "maxLength": 36},
            },
        },
        "risk_level": "observe", "read_only": True,
        "required_permissions": ["services.read"], "timeout_seconds": 10,
        "max_result_bytes": 25_000, "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "reports.get_saved",
        "description": (
            "Read bounded numeric sections of one exact authorized retained "
            "service-health report snapshot and cite its durable instance ID "
            "and SHA256. Use for historical diagnosis; obtain live evidence "
            "separately before claiming current health. Does not return report "
            "prose, source queries, document bytes, or private evidence."
        ),
        "transport": "internal",
        "handler": "reports.get_saved",
        "input_schema": {
            "type": "object", "additionalProperties": False,
            "required": ["instance_id"],
            "properties": {"instance_id": {"type": "string", "minLength": 36, "maxLength": 36}},
        },
        "output_schema": {
            "type": "object", "additionalProperties": False,
            "required": [
                "format_version", "evidence_basis", *SAVED_REPORT_ITEM_OUTPUT_SCHEMA["required"],
                "published_at", "lookback_minutes", "sections",
            ],
            "properties": {
                "format_version": {"const": "icheck.agent-saved-report/v1"},
                "evidence_basis": {"const": "saved_snapshot"},
                **SAVED_REPORT_ITEM_OUTPUT_SCHEMA["properties"],
                "published_at": {"type": "string", "maxLength": 35},
                "lookback_minutes": {"type": "integer", "minimum": 5, "maximum": 10080},
                "sections": {"type": "array", "minItems": 1, "maxItems": 20,
                             "items": SAVED_REPORT_SECTION_OUTPUT_SCHEMA},
            },
        },
        "risk_level": "observe", "read_only": True,
        "required_permissions": ["services.read"], "timeout_seconds": 10,
        "max_result_bytes": 80_000, "enabled": True,
        "created_by": "system.bootstrap",
    },
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
                "discovered_name": {"type": ["string", "null"], "maxLength": 255},
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
        "name": "wireless.list_controller_clients",
        "description": (
            "Read bounded current or recent Wi-Fi terminal sessions for one "
            "authorized wireless controller, with optional exact AP/SSID and "
            "weak-signal filters. Usernames and raw vendor payloads are omitted."
        ),
        "transport": "internal",
        "handler": "wireless.list_controller_clients",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["controller_id"],
            "properties": {
                "controller_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 36,
                },
                "access_point": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                },
                "ssid": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                },
                "rssi_at_most": {
                    "type": "integer",
                    "minimum": -150,
                    "maximum": 0,
                },
                "snr_at_most": {
                    "type": "integer",
                    "minimum": -50,
                    "maximum": 100,
                },
                "active_only": {"type": "boolean"},
                "max_age_minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10080,
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                },
            },
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "controller",
                "filters",
                "clients",
                "truncated",
                "observed_at",
            ],
            "properties": {
                "controller": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["id", "name", "site"],
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"},
                        "site": {"type": ["string", "null"]},
                    },
                },
                "filters": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "access_point",
                        "ssid",
                        "rssi_at_most",
                        "snr_at_most",
                        "active_only",
                        "max_age_minutes",
                    ],
                    "properties": {
                        "access_point": {"type": ["string", "null"]},
                        "ssid": {"type": ["string", "null"]},
                        "rssi_at_most": {"type": ["integer", "null"]},
                        "snr_at_most": {"type": ["integer", "null"]},
                        "active_only": {"type": "boolean"},
                        "max_age_minutes": {"type": "integer"},
                    },
                },
                "clients": {
                    "type": "array",
                    "maxItems": 100,
                    "items": WIRELESS_CLIENT_OUTPUT_SCHEMA,
                },
                "truncated": {"type": "boolean"},
                "observed_at": {"type": "string"},
            },
        },
        "risk_level": "diagnose",
        "read_only": True,
        "required_permissions": ["assets.read", "endpoints.read"],
        "timeout_seconds": 10,
        "max_result_bytes": 500_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "knowledge.query_graph",
        "description": (
            "Read a bounded one-hop generic knowledge graph around one exact "
            "entity. Use for custom Collector entities and relationships; the "
            "result omits arbitrary normalized attributes and raw source data."
        ),
        "transport": "internal",
        "handler": "knowledge.query_graph",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "oneOf": [
                {
                    "required": ["entity_id"],
                    "not": {
                        "anyOf": [
                            {"required": ["entity_type"]},
                            {"required": ["external_key"]},
                        ]
                    },
                },
                {
                    "required": ["entity_type", "external_key"],
                    "not": {"required": ["entity_id"]},
                },
            ],
            "properties": {
                "entity_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "entity_type": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 64,
                    "pattern": "^[a-z][a-z0-9_.-]*$",
                },
                "external_key": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 512,
                },
                "relationship_types": {
                    "type": "array",
                    "maxItems": 20,
                    "uniqueItems": True,
                    "items": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                        "pattern": "^[a-z][a-z0-9_.-]*$",
                    },
                },
                "direction": {
                    "enum": ["both", "incoming", "outgoing"],
                },
                "active_only": {"type": "boolean"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["root", "neighbors", "relationships", "truncated"],
            "properties": {
                "root": KNOWLEDGE_NODE_OUTPUT_SCHEMA,
                "neighbors": {
                    "type": "array",
                    "maxItems": 50,
                    "items": KNOWLEDGE_NODE_OUTPUT_SCHEMA,
                },
                "relationships": {
                    "type": "array",
                    "maxItems": 50,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "id",
                            "relationship_type",
                            "source_entity_id",
                            "target_entity_id",
                            "directed",
                            "active",
                            "last_seen",
                        ],
                        "properties": {
                            "id": {"type": "string"},
                            "relationship_type": {"type": "string"},
                            "source_entity_id": {"type": "string"},
                            "target_entity_id": {"type": "string"},
                            "directed": {"type": "boolean"},
                            "active": {"type": "boolean"},
                            "last_seen": {"type": "string"},
                        },
                    },
                },
                "truncated": {"type": "boolean"},
            },
        },
        "risk_level": "observe",
        "read_only": True,
        "required_permissions": ["assets.read"],
        "timeout_seconds": 10,
        "max_result_bytes": 250_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "situations.get_impact",
        "description": (
            "Read bounded, authorization-scoped topology and service context "
            "for one Situation. Every edge carries an evidence ID and the "
            "result explicitly does not claim root cause."
        ),
        "transport": "internal",
        "handler": "situations.get_impact",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["situation_id"],
            "properties": {
                "situation_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 36,
                },
            },
        },
        "output_schema": SituationImpactRead.model_json_schema(),
        "risk_level": "diagnose",
        "read_only": True,
        "required_permissions": ["alerts.read", "assets.read"],
        "timeout_seconds": 10,
        "max_result_bytes": 500_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "quality.get_execution_health",
        "description": "Read bounded, exact-version capability execution-health assessments. Use to investigate Collector, Tool, Skill or Workflow degradation; never treat healthy execution as correctness or automation permission. Does not run evaluations or change policy.",
        "transport": "internal",
        "handler": "quality.get_execution_health",
        "input_schema": {"type": "object", "additionalProperties": False, "properties": {
            "artifact_version_id": {"type": "string", "pattern": "^[0-9a-f-]{36}$"},
            "offset": {"type": "integer", "minimum": 0, "maximum": 1000},
            "limit": {"type": "integer", "minimum": 1, "maximum": 20},
        }},
        "output_schema": {"type": "object", "additionalProperties": False,
            "required": ["authorizes_automation", "evidence_scope", "items"], "properties": {
                "authorizes_automation": {"const": False},
                "evidence_scope": {"const": "execution_health_not_correctness"},
                "items": {"type": "array", "maxItems": 20, "items": {"type": "object", "additionalProperties": False,
                    "required": ["policy_id", "artifact_version_id", "policy_revision", "state", "current", "assessment"],
                    "properties": {
                        "policy_id": {"type": "string"}, "artifact_version_id": {"type": "string"},
                        "policy_revision": {"type": "integer"}, "state": {"enum": ["healthy", "degraded", "insufficient_data", "disabled", "needs_evaluation", "expired"]},
                        "current": {"type": "boolean"},
                        "assessment": {"type": ["object", "null"], "additionalProperties": False,
                            "required": ["id", "sample_count", "failed_count", "p95_ms", "reasons", "assessment_sha256", "evaluated_at", "valid_until"],
                            "properties": {"id": {"type": "string"}, "sample_count": {"type": "integer"}, "failed_count": {"type": "integer"},
                                "p95_ms": {"type": ["integer", "null"]}, "reasons": {"type": "array", "maxItems": 16, "items": {"type": "string"}},
                                "assessment_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                                "evaluated_at": {"type": "string"}, "valid_until": {"type": "string"}}},
                    }}},
            }},
        "risk_level": "observe", "read_only": True, "required_permissions": ["capabilities.read"],
        "timeout_seconds": 10, "max_result_bytes": 50000, "enabled": True, "created_by": "system.bootstrap",
    },
    {
        "name": "capacity.get_worker_scaling",
        "description": (
            "Read the latest regional collector and Agent worker scaling "
            "recommendations. Use it to explain capacity pressure or stale "
            "workers; it never creates or terminates hosts."
        ),
        "transport": "internal",
        "handler": "capacity.get_worker_scaling",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "pool": {"enum": ["collector", "agent"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["recommendations"],
            "properties": {
                "recommendations": {
                    "type": "array",
                    "maxItems": 50,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "policy_id",
                            "policy_name",
                            "pool",
                            "enabled",
                            "decision",
                        ],
                        "properties": {
                            "policy_id": {"type": "string"},
                            "policy_name": {"type": "string"},
                            "pool": {"enum": ["collector", "agent"]},
                            "enabled": {"type": "boolean"},
                            "decision": {
                                "type": ["object", "null"],
                                "additionalProperties": False,
                                "required": [
                                    "id",
                                    "queue_depth",
                                    "oldest_queue_age_seconds",
                                    "current_replicas",
                                    "ready_replicas",
                                    "busy_replicas",
                                    "stale_replicas",
                                    "desired_replicas",
                                    "direction",
                                    "reasons",
                                    "observed_at",
                                ],
                                "properties": {
                                    "id": {"type": "string"},
                                    "queue_depth": {"type": "integer"},
                                    "oldest_queue_age_seconds": {
                                        "type": ["number", "null"]
                                    },
                                    "current_replicas": {"type": "integer"},
                                    "ready_replicas": {"type": "integer"},
                                    "busy_replicas": {"type": "integer"},
                                    "stale_replicas": {"type": "integer"},
                                    "desired_replicas": {"type": "integer"},
                                    "direction": {
                                        "enum": ["scale_out", "scale_in", "hold"]
                                    },
                                    "reasons": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                    "observed_at": {"type": "string"},
                                },
                            },
                        },
                    },
                },
            },
        },
        "risk_level": "observe",
        "read_only": True,
        "required_permissions": ["scaling.read"],
        "timeout_seconds": 10,
        "max_result_bytes": 250_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "metrics.backends.list",
        "description": (
            "Discover enabled metric backends in the current workspace before "
            "calling metrics.query_instant, metrics.query_range or metrics.get_device_range. "
            "Use the returned backend_id, never a Grafana datasource UID or backend name. "
            "Returns only IDs, names and providers; does not query metrics or prove health. "
            "A backend is not automatically the source of a particular Grafana connection. "
            "If the intended backend is ambiguous, ask instead of guessing."
        ),
        "transport": "internal",
        "handler": "metrics.backends.list",
        "input_schema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 255,
                         "description": "Optional exact registered backend name, for narrowing a truncated list."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
        },
        "output_schema": {
            "type": "object", "additionalProperties": False,
            "required": ["backends", "truncated", "next_action"],
            "properties": {
                "backends": {"type": "array", "maxItems": 100, "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["backend_id", "name", "provider"],
                    "properties": {
                        "backend_id": {"type": "string"},
                        "name": {"type": "string"},
                        "provider": {"type": "string"},
                    },
                }},
                "truncated": {"type": "boolean"},
                "next_action": {"type": "string"},
            },
        },
        "risk_level": "observe", "read_only": True,
        "required_permissions": ["metrics.read"],
        "timeout_seconds": 10, "max_result_bytes": 100_000,
        "enabled": True, "created_by": "system.bootstrap",
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
    {
        "name": "metrics.query_range",
        "description": (
            "Run one bounded PromQL range query against a registered, enabled "
            "Prometheus-compatible backend. Use for recent metric trends up to "
            "seven days and 2000 evaluation steps."
        ),
        "transport": "internal",
        "handler": "metrics.query_range",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["backend_id", "query", "start", "end"],
            "properties": {
                "backend_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "query": {"type": "string", "minLength": 1, "maxLength": 2048},
                "start": {"type": "string", "format": "date-time"},
                "end": {"type": "string", "format": "date-time"},
                "step_seconds": {
                    "type": "integer",
                    "minimum": 15,
                    "maximum": 3600,
                },
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
                "mode": {"const": "range"},
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
    {
        "name": "metrics.get_device_range",
        "description": (
            "Read one bounded exporter metric series for an authorized device. "
            "The platform constructs and verifies stable namespace/device-ID "
            "selectors; device names and reused IP addresses are not authority."
        ),
        "transport": "internal",
        "handler": "metrics.get_device_range",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "backend_id",
                "device_id",
                "metric",
                "start",
                "end",
            ],
            "properties": {
                "backend_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "device_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "metric": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                    "pattern": "^[A-Za-z_:][A-Za-z0-9_:]*$",
                },
                "start": {"type": "string", "format": "date-time"},
                "end": {"type": "string", "format": "date-time"},
                "step_seconds": {
                    "type": "integer",
                    "minimum": 15,
                    "maximum": 3600,
                },
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 15},
                "limit": {"type": "integer", "minimum": 1, "maximum": 20},
            },
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "backend_id",
                "device_id",
                "metric",
                "mode",
                "result_type",
                "result",
                "warnings",
                "infos",
                "queried_at",
            ],
            "properties": {
                "backend_id": {"type": "string"},
                "device_id": {"type": "string"},
                "metric": {"type": "string"},
                "mode": {"const": "range"},
                "result_type": {"const": "matrix"},
                "result": {
                    "type": "array",
                    "maxItems": 20,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["metric", "values"],
                        "properties": {
                            "metric": {
                                "type": "object",
                                "additionalProperties": {
                                    "type": "string",
                                    "maxLength": 512,
                                },
                            },
                            "values": {
                                "type": "array",
                                "maxItems": 2001,
                                "items": {
                                    "type": "array",
                                    "minItems": 2,
                                    "maxItems": 2,
                                    "items": {},
                                },
                            },
                        },
                    },
                },
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
        "required_permissions": ["assets.read", "metrics.read"],
        "timeout_seconds": 20,
        "max_result_bytes": 1_000_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "logs.query_range",
        "description": (
            "Run one bounded recent LogQL range query against a registered Loki "
            "backend. Log lines are length-bounded and common credential forms "
            "are redacted; scoped investigations must use logs.get_device_range."
        ),
        "transport": "internal",
        "handler": "logs.query_range",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["backend_id", "query", "start", "end"],
            "properties": {
                "backend_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "query": {"type": "string", "minLength": 1, "maxLength": 2048},
                "start": {"type": "string", "format": "date-time"},
                "end": {"type": "string", "format": "date-time"},
                "direction": {"enum": ["forward", "backward"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 15},
            },
        },
        "output_schema": _log_query_output_schema(device_scoped=False),
        "risk_level": "diagnose",
        "read_only": True,
        "required_permissions": ["logs.read"],
        "timeout_seconds": 20,
        "max_result_bytes": 5_000_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "logs.get_device_range",
        "description": (
            "Read bounded recent Loki entries for one authorized device. The "
            "platform builds and verifies the exact backend-specific device "
            "label selector and removes unapproved labels."
        ),
        "transport": "internal",
        "handler": "logs.get_device_range",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["backend_id", "device_id", "start", "end"],
            "properties": {
                "backend_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "device_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "start": {"type": "string", "format": "date-time"},
                "end": {"type": "string", "format": "date-time"},
                "direction": {"enum": ["forward", "backward"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 15},
            },
        },
        "output_schema": _log_query_output_schema(device_scoped=True),
        "risk_level": "diagnose",
        "read_only": True,
        "required_permissions": ["assets.read", "logs.read"],
        "timeout_seconds": 20,
        "max_result_bytes": 5_000_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "windows.request_diagnostics",
        "description": (
            "Request one governed, preconfigured, read-only PSRP/CIM diagnostic "
            "collection for an authorized Windows device. The request cannot "
            "supply scripts, targets, credentials, or Collector configuration."
        ),
        "transport": "internal",
        "handler": "windows.request_diagnostics",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["device_id", "operations", "reason"],
            "properties": {
                "device_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "deployment_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 36,
                },
                "operations": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 4,
                    "uniqueItems": True,
                    "items": {
                        "enum": [
                            "operating_system",
                            "computer_system",
                            "logical_disks",
                            "network_adapters",
                        ]
                    },
                },
                "reason": {"type": "string", "minLength": 3, "maxLength": 1000},
            },
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "device_id",
                "deployment_id",
                "operations",
                "queue_status",
                "requested_at",
            ],
            "properties": {
                "device_id": {"type": "string"},
                "deployment_id": {"type": "string"},
                "operations": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 4,
                    "uniqueItems": True,
                    "items": {
                        "enum": [
                            "operating_system",
                            "computer_system",
                            "logical_disks",
                            "network_adapters",
                        ]
                    },
                },
                "queue_status": {
                    "enum": ["queued", "already_queued", "running"]
                },
                "requested_at": {"type": "string"},
            },
        },
        "risk_level": "change",
        "read_only": False,
        "required_permissions": ["assets.read", "collectors.manage"],
        "timeout_seconds": 10,
        "max_result_bytes": 100_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "windows.get_latest_diagnostics",
        "description": (
            "Read the latest fresh, successful, current-target PSRP/CIM diagnostic "
            "evidence for one authorized Windows device. After requesting a check, "
            "pass its deployment_id and requested_at as not_before to avoid old results. This never runs "
            "PowerShell or returns deployment credentials."
        ),
        "transport": "internal",
        "handler": "windows.get_latest_diagnostics",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["device_id"],
            "properties": {
                "device_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "operations": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 4,
                    "uniqueItems": True,
                    "items": {
                        "enum": [
                            "operating_system",
                            "computer_system",
                            "logical_disks",
                            "network_adapters",
                        ]
                    },
                },
                "max_age_minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10080,
                },
                "deployment_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "not_before": {"type": "string", "format": "date-time", "maxLength": 64},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "device_id",
                "run_id",
                "deployment_id",
                "status",
                "started_at",
                "finished_at",
                "records",
                "truncated",
            ],
            "properties": {
                "device_id": {"type": "string"},
                "run_id": {"type": "string"},
                "deployment_id": {"type": "string"},
                "status": {"const": "succeeded"},
                "started_at": {"type": "string"},
                "finished_at": {"type": "string"},
                "records": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["operation", "observed_at", "fields"],
                        "properties": {
                            "operation": {
                                "enum": [
                                    "operating_system",
                                    "computer_system",
                                    "logical_disks",
                                    "network_adapters",
                                ]
                            },
                            "observed_at": {"type": "string"},
                            "fields": {
                                "type": "object",
                                "additionalProperties": {
                                    "anyOf": [
                                        {"type": "string", "maxLength": 2000},
                                        {"type": "number"},
                                        {"type": "null"},
                                        {
                                            "type": "array",
                                            "maxItems": 32,
                                            "items": {
                                                "type": "string",
                                                "maxLength": 512,
                                            },
                                        },
                                    ]
                                },
                            },
                        },
                    },
                },
                "truncated": {"type": "boolean"},
            },
        },
        "risk_level": "diagnose",
        "read_only": True,
        "required_permissions": ["assets.read", "collectors.read"],
        "timeout_seconds": 10,
        "max_result_bytes": 500_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
    {
        "name": "knowledge.find_paths",
        "description": (
            "Find bounded shortest paths between two exact authorized knowledge "
            "entities. Use for deterministic multi-hop topology/dependency "
            "evidence; a path does not itself prove causality."
        ),
        "transport": "internal",
        "handler": "knowledge.find_paths",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["source_entity_id", "target_entity_id"],
            "properties": {
                "source_entity_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 36,
                },
                "target_entity_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 36,
                },
                "relationship_types": {
                    "type": "array",
                    "maxItems": 20,
                    "uniqueItems": True,
                    "items": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "pattern": "^[a-z][a-z0-9_.-]*$",
                    },
                },
                "direction": {"enum": ["outgoing", "both"]},
                "max_depth": {"type": "integer", "minimum": 1, "maximum": 4},
                "max_paths": {"type": "integer", "minimum": 1, "maximum": 20},
                "active_only": {"type": "boolean"},
            },
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["source", "target", "paths", "truncated"],
            "properties": {
                "source": KNOWLEDGE_NODE_OUTPUT_SCHEMA,
                "target": KNOWLEDGE_NODE_OUTPUT_SCHEMA,
                "paths": {
                    "type": "array",
                    "maxItems": 20,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["nodes", "relationships"],
                        "properties": {
                            "nodes": {
                                "type": "array",
                                "minItems": 2,
                                "maxItems": 5,
                                "items": KNOWLEDGE_NODE_OUTPUT_SCHEMA,
                            },
                            "relationships": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": 4,
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": [
                                        "id",
                                        "relationship_type",
                                        "source_entity_id",
                                        "target_entity_id",
                                        "directed",
                                        "active",
                                        "last_seen",
                                    ],
                                    "properties": {
                                        "id": {"type": "string"},
                                        "relationship_type": {"type": "string"},
                                        "source_entity_id": {"type": "string"},
                                        "target_entity_id": {"type": "string"},
                                        "directed": {"type": "boolean"},
                                        "active": {"type": "boolean"},
                                        "last_seen": {"type": "string"},
                                    },
                                },
                            },
                        },
                    },
                },
                "truncated": {"type": "boolean"},
            },
        },
        "risk_level": "diagnose",
        "read_only": True,
        "required_permissions": ["assets.read"],
        "timeout_seconds": 10,
        "max_result_bytes": 500_000,
        "enabled": True,
        "created_by": "system.bootstrap",
    },
)


def _remediation_quality_tool() -> dict[str, Any]:
    document = deepcopy(next(item for item in BUILTIN_AGENT_TOOLS if item["name"] == "quality.get_execution_health"))
    document.update(name="quality.get_remediation_outcomes", handler="quality.get_remediation_outcomes",
        description="Read bounded, exact-version remediation-outcome assessments from separately approved actions and causal post-checks, including typed state transitions when the published Tool declares them. Rollback restoration is not remediation success. Tool observations do not prove vendor truth or grant autonomy, change policy or run tools.", timeout_seconds=30)
    document["output_schema"]["properties"]["evidence_scope"] = {"const": "remediation_outcome_not_authority"}
    return document


BUILTIN_AGENT_TOOLS += (_remediation_quality_tool(),)


def _reviewed_situation_tools():
    from .situation_closure_schemas import (SituationClosureToolInput, SituationClosureReceiptRead,
        SituationRecoveryToolInput, SituationReplacementClosureToolInput)
    from .situation_recovery_schemas import SituationRecoveryEvidenceRead
    common = {"transport": "internal", "timeout_seconds": 30, "max_result_bytes": 3 * 1024 * 1024,
        "enabled": True, "created_by": "system.bootstrap"}
    return ({**common, "name": "situations.get_recovery_evidence", "handler": "situations.get_recovery_evidence",
        "description": "Check fresh, reviewed whole-Situation source recovery. Use a new check_key for another observation; replay revalidates the retained proof. Read-only evidence, never closure permission or repair causality.",
        "input_schema": SituationRecoveryToolInput.model_json_schema(), "output_schema": SituationRecoveryEvidenceRead.model_json_schema(),
        "risk_level": "diagnose", "read_only": True, "required_permissions": ["alerts.read"]},
        {**common, "name": "situations.close_reviewed", "handler": "situations.close_reviewed",
        "description": "Perform leased control-plane incident closure using separate independently reviewed authority and fresh complete source/action evidence. Default-off host gate. Runtime owns request identity and lease. Historical receipt is not physical truth, repair causality, or future write authority.",
        "input_schema": SituationClosureToolInput.model_json_schema(), "output_schema": SituationClosureReceiptRead.model_json_schema(),
        "risk_level": "change", "read_only": False, "required_permissions": ["alerts.read", "situations.close"]},
        {**common, "name": "situations.close_reviewed_v2", "handler": "situations.close_reviewed",
        "description": "Explicit replacement-aware v2 incident closure. Requires proof_version=2, a separately reviewed v2 grant and both replacement host gates. Uses current target quiet samples and exact permanent retirement references; runtime owns the journal and lease. Never reinterprets v1 consent or grants physical truth, repair causality or future authority.",
        "input_schema": SituationReplacementClosureToolInput.model_json_schema(), "output_schema": SituationClosureReceiptRead.model_json_schema(),
        "risk_level": "change", "read_only": False, "required_permissions": ["alerts.read", "situations.close"]})


BUILTIN_AGENT_TOOLS += _reviewed_situation_tools()


def _source_replacement_tools():
    from .source_replacement_schemas import (SourceReplacementProposalToolInput, SourceReplacementApplyToolInput,
        SourceReplacementRequestRead, SourceReplacementDetailRead, SourceRetirementRead, SourceReplacementReadToolInput)
    common = {"transport": "internal", "timeout_seconds": 30, "max_result_bytes": 2 * 1024 * 1024,
        "enabled": True, "created_by": "system.bootstrap"}
    return ({**common, "name": "collector_sources.get_replacement", "handler": "collector_sources.get_replacement",
        "description": "Read one exact peer-reviewed source replacement and retained cutover pointer. Use a new check_key for fresh review/revocation metadata; replay preserves its retained result. Both generations require material read scope. Record metadata is not current execution authority or incident recovery.",
        "input_schema": SourceReplacementReadToolInput.model_json_schema(),
        "output_schema": SourceReplacementDetailRead.model_json_schema(), "risk_level": "diagnose", "read_only": True,
        "required_permissions": ["alerts.read", "capabilities.read"]},
        {**common, "name": "collector_sources.propose_replacement", "handler": "collector_sources.propose_replacement",
        "description": "Propose exact old/new Collector source equivalence for independent human review inside iCheck. Runtime owns immutable retry identity. No producer cutover, automatic physical attestation or incident closure occurs.",
        "input_schema": SourceReplacementProposalToolInput.model_json_schema(), "output_schema": SourceReplacementRequestRead.model_json_schema(),
        "risk_level": "change", "read_only": False, "required_permissions": ["alerts.read", "capabilities.read", "alerts.manage"]},
        {**common, "name": "collector_sources.apply_reviewed_replacement", "handler": "collector_sources.apply_reviewed_replacement",
        "description": "Execute an exact independently accepted control-plane source cutover behind the default-off host gate. Runtime owns the retry identity; current origin, scope, clocks and peer authority are rechecked. No physical device operation or incident closure. Committed retry returns retained history only.",
        "input_schema": SourceReplacementApplyToolInput.model_json_schema(), "output_schema": SourceRetirementRead.model_json_schema(),
        "risk_level": "change", "read_only": False, "required_permissions": ["alerts.read", "capabilities.read", "alerts.sources.replace"]})


BUILTIN_AGENT_TOOLS += _source_replacement_tools()


def _device_onboarding_tools():
    from .onboarding_schemas import OnboardingInput
    common = {"transport": "internal", "risk_level": "observe", "read_only": True,
              "required_permissions": ["assets.read"], "timeout_seconds": 10,
              "max_result_bytes": 100_000, "enabled": True, "created_by": "system.bootstrap",
              "output_schema": {"type": "object"}}
    return (
        {**common, "name": "inventory.find_devices", "handler": "inventory.find_devices",
         "description": "Find existing site-scoped devices by an explicit bounded IP list. Use after human enrollment approval to get durable device/connection IDs and current preflight and activation status. No network scan or inventory changes.",
         "input_schema": {"type": "object", "additionalProperties": False, "required": ["management_ips"],
             "properties": {"site": {"type": ["string", "null"], "maxLength": 128},
                 "management_ips": {"type": "array", "minItems": 1, "maxItems": 50,
                     "items": {"type": "string", "minLength": 1, "maxLength": 64}}}}},
        {**common, "name": "credentials.list_device_profiles", "handler": "credentials.list_device_profiles",
         "description": "List enabled site-compatible device credential names and IDs only. Never retrieve, ask for or expose passwords, communities, tokens or private keys.",
         "input_schema": {"type": "object", "additionalProperties": False,
                          "properties": {"site": {"type": ["string", "null"], "maxLength": 128}}}},
        {**common, "name": "inventory.preview_onboarding", "handler": "inventory.preview_onboarding",
         "description": "Prepare a bounded batch of device IPs and credential references for human approval. This is a pure preview: it neither adds devices nor scans them. Return the plan and approval requirement; the operator GUI presents Approve enrollment. After approval, use inventory.get_device to check preflight, then inventory.preview_activation. Do not claim enrollment or monitoring until verified.",
         "input_schema": OnboardingInput.model_json_schema()},
        {**common, "name": "inventory.enroll_devices", "handler": "inventory.enroll_devices",
         "risk_level": "change", "read_only": False, "required_permissions": ["assets.read", "assets.write"],
         "description": "Runtime-owned deterministic enrollment for an explicit initiating Add/Enroll request. Exact IPs, saved profile and optional location must match the original human request; unavailable to previews, Skills, scheduled workflows or model-invented targets. Atomically writes inventory, queues verification and requests finite managed-SNMP monitoring. A blank Site stays blank. Success requires durable device IDs; never claims live monitoring before verification.",
         "input_schema": OnboardingInput.model_json_schema()},
        {**common, "name": "inventory.preview_activation", "handler": "inventory.preview_activation",
         "required_permissions": ["assets.activate"],
         "description": "Preview a published collection policy for an already enrolled and verified device connection. The human must approve the exact preview in the GUI. This tool never activates monitoring.",
         "input_schema": {"type": "object", "additionalProperties": False,
             "required": ["device_id", "connection_id", "policy_name"], "properties": {
                 "device_id": {"type": "string", "maxLength": 36}, "connection_id": {"type": "string", "maxLength": 36},
                 "policy_name": {"type": "string", "maxLength": 255}}}},
    )


BUILTIN_AGENT_TOOLS += _device_onboarding_tools()
BUILTIN_AGENT_TOOLS += GRAFANA_TOOLS
from .research_tools import RESEARCH_TOOLS
BUILTIN_AGENT_TOOLS += RESEARCH_TOOLS
from .autonomy_tools import AUTONOMY_TOOLS
BUILTIN_AGENT_TOOLS += AUTONOMY_TOOLS
BUILTIN_AGENT_TOOLS += METRIC_ALERT_TOOLS
from .integration_tools import INTEGRATION_TOOLS
BUILTIN_AGENT_TOOLS += INTEGRATION_TOOLS

BUILTIN_AGENT_TOOLS += ({"name": "platform.diagnose_ai_runtime", "handler": "platform.diagnose_ai_runtime",
    "description": "Diagnose an authorized failed AI investigation using retained model-attempt evidence and propose an in-product repair. Works without additional model inference, never reads secrets, changes configuration, retries tasks or adds devices. Human approval is required in the configuration GUI.",
    "transport": "internal", "risk_level": "diagnose", "read_only": True,
    "required_permissions": ["investigations.read"], "enabled": True, "created_by": "system.bootstrap",
    "timeout_seconds": 10, "max_result_bytes": 100000,
    "input_schema": {"type": "object", "additionalProperties": False, "required": ["investigation_id"],
        "properties": {"investigation_id": {"type": "string", "minLength": 1, "maxLength": 36}}},
    "output_schema": {"type": "object"}},)


def ensure_builtin_agent_tools(
    db: Session,
    *,
    commit: bool = True,
) -> list[AgentToolRegistration]:
    if db.get_bind().dialect.name == "postgresql":
        namespace = session_namespace(db)
        if namespace is None:
            raise ValueError("Built-in Tool bootstrap requires an explicit namespace")
        # Multiple API workers can cold-start against an empty catalog. Keep
        # the existence reads and every registration under one namespace-bound
        # transaction mutex; per-Tool commits would release it prematurely.
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:namespace, 0))"),
            {"namespace": "icheck.builtin-agent-tools:" + ":".join(namespace)})
    tools: list[AgentToolRegistration] = []
    for document in BUILTIN_AGENT_TOOLS:
        existing = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == document["name"]
            )
        )
        if existing is not None:
            if (existing.name == "inventory.get_device" and existing.created_by == "system.bootstrap"
                and existing.handler == existing.name and existing.transport == "internal" and existing.read_only):
                # Optional additive output only. Preserve custom definitions and
                # historical receipts; no permissions or invocation schema change.
                legacy = {**document["output_schema"], "properties": dict(document["output_schema"]["properties"])}
                legacy["properties"].pop("discovered_name", None)
                if existing.output_schema == legacy:
                    existing.output_schema = document["output_schema"]
            if (existing.name in {"credentials.list_device_profiles", "inventory.find_devices", "inventory.preview_onboarding"}
                    and existing.created_by == "system.bootstrap" and existing.handler == existing.name
                    and existing.transport == "internal" and existing.read_only
                    and "site" in existing.input_schema.get("required", [])):
                existing.input_schema = document["input_schema"]
            if (existing.name == "integrations.history.query" and existing.created_by == "system.bootstrap"
                    and existing.handler == existing.name and existing.transport == "internal" and existing.read_only
                    and existing.input_schema.get("properties", {}).get("metric_id") ==
                    {"type": "string", "pattern": "^[1-9][0-9]{0,19}$"}):
                # Provider-native metric IDs may be names, not only Zabbix item
                # numbers. Do not alter customized registrations.
                previous = {**document["input_schema"], "properties": {
                    **document["input_schema"]["properties"],
                    "metric_id": {"type": "string", "pattern": "^[1-9][0-9]{0,19}$"}}}
                if existing.input_schema == previous:
                    existing.input_schema = document["input_schema"]
            tools.append(existing)
            continue
        tools.append(
            create_agent_tool(
                db,
                AgentToolCreate.model_validate(document),
                commit=False,
            )
        )
    if commit:
        db.commit()
    return tools
