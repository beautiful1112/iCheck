from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .collector_schemas import ArtifactCreate
from .models import Artifact, ArtifactKind
from .services.collectors import (
    create_artifact,
    publish_artifact_version,
    validate_artifact_version,
)


def snmp_exporter_artifact_payload() -> dict[str, Any]:
    return {
        "name": "builtin-snmp-exporter",
        "kind": "collector",
        "description": (
            "Bounded SNMP collection through a site-local Prometheus "
            "SNMP Exporter."
        ),
        "owner": "icheck",
        "labels": {
            "builtin": True,
            "protocol": "snmp",
            "metrics_format": "prometheus",
        },
        "initial_version": {
            "definition": {
                "purpose": (
                    "Collect selected SNMP Exporter samples as normalized "
                    "observation envelopes."
                ),
                "production_metrics_path": (
                    "Prometheus scrapes SNMP Exporter and remote-writes to "
                    "the configured metrics backend."
                ),
            },
            "implementation": {
                "runtime": "builtin",
                "adapter": "snmp_exporter",
            },
            "tests": [
                {
                    "name": "if_mib sample",
                    "fixture": (
                        'ifHCInOctets{ifIndex="1",ifName="Gi0/1"} 12345'
                    ),
                }
            ],
            "created_by": "system.bootstrap",
            "collector_definition": {
                "adapter_type": "snmp_exporter",
                "mode": "poll",
                "output_kinds": ["observation"],
                "credential_profile_ref": None,
                "target_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["exporter_url", "target"],
                    "properties": {
                        "exporter_url": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 2048,
                        },
                        "target": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 512,
                        },
                    },
                },
                "config_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "modules": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 8,
                            "items": {
                                "type": "string",
                                "pattern": "^[A-Za-z0-9_.-]+$",
                            },
                        },
                        "auth_module": {
                            "type": "string",
                            "pattern": "^[A-Za-z0-9_.-]+$",
                        },
                        "timeout_seconds": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 120,
                        },
                        "max_response_bytes": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 50_000_000,
                        },
                        "max_metrics": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 2000,
                        },
                        "include_metric_prefixes": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "source": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 255,
                        },
                    },
                },
                "defaults": {
                    "modules": ["if_mib"],
                    "auth_module": "public_v2",
                    "timeout_seconds": 15,
                    "max_response_bytes": 10_000_000,
                    "max_metrics": 2000,
                    "include_metric_prefixes": [],
                },
            },
        },
    }


def snmp_topology_artifact_payload() -> dict[str, Any]:
    metric_name = {
        "type": "string",
        "pattern": "^[A-Za-z0-9_.-]+$",
    }
    return {
        "name": "builtin-snmp-device-adjacency",
        "kind": "collector",
        "description": (
            "Bounded LLDP/CDP adjacency snapshots through a site-local "
            "Prometheus SNMP Exporter."
        ),
        "owner": "icheck",
        "labels": {
            "builtin": True,
            "protocol": "snmp",
            "domain": "topology",
            "metrics_format": "prometheus",
        },
        "initial_version": {
            "definition": {
                "purpose": (
                    "Convert reviewed LLDP or CDP neighbor info metrics into "
                    "governed device adjacency snapshots."
                ),
                "input_contract": (
                    "The configured SNMP Exporter module must expose one "
                    "normalized info metric per physical neighbor link."
                ),
            },
            "implementation": {
                "runtime": "builtin",
                "adapter": "snmp_topology",
            },
            "tests": [
                {
                    "name": "normalized LLDP neighbor",
                    "fixture": (
                        'icheck_lldp_neighbor_info{local_port="Gi0/1",'
                        'remote_chassis_id="00:11:22:33:44:55",'
                        'remote_system_name="access-01",'
                        'remote_port="Gi0/48"} 1'
                    ),
                }
            ],
            "created_by": "system.bootstrap",
            "collector_definition": {
                "adapter_type": "snmp_topology",
                "mode": "poll",
                "output_kinds": ["relationship"],
                "credential_profile_ref": None,
                "target_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["exporter_url", "target"],
                    "properties": {
                        "exporter_url": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 2048,
                        },
                        "target": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 512,
                        },
                        "local_device_key": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 512,
                        },
                        "local_display_name": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 255,
                        },
                    },
                },
                "config_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "protocol": {
                            "type": "string",
                            "enum": ["lldp", "cdp"],
                        },
                        "modules": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 8,
                            "items": metric_name,
                        },
                        "auth_module": metric_name,
                        "timeout_seconds": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 120,
                        },
                        "max_response_bytes": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 50_000_000,
                        },
                        "neighbor_metric": metric_name,
                        "scrape_health_metric": metric_name,
                        "local_port_label": metric_name,
                        "remote_device_key_labels": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 8,
                            "uniqueItems": True,
                            "items": metric_name,
                        },
                        "remote_system_name_label": metric_name,
                        "remote_port_label": metric_name,
                        "remote_management_ip_label": metric_name,
                        "complete_snapshot": {"type": "boolean"},
                        "max_neighbors": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 2000,
                        },
                        "source": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 255,
                        },
                    },
                },
                "defaults": {
                    "protocol": "lldp",
                    "modules": ["icheck_lldp"],
                    "auth_module": "public_v2",
                    "timeout_seconds": 15,
                    "max_response_bytes": 10_000_000,
                    "neighbor_metric": "icheck_lldp_neighbor_info",
                    "scrape_health_metric": "snmp_scrape_walk_duration_seconds",
                    "local_port_label": "local_port",
                    "remote_device_key_labels": [
                        "remote_chassis_id",
                        "remote_system_name",
                    ],
                    "remote_system_name_label": "remote_system_name",
                    "remote_port_label": "remote_port",
                    "remote_management_ip_label": "remote_management_ip",
                    "complete_snapshot": True,
                    "max_neighbors": 1000,
                },
            },
        },
    }


def windows_exporter_artifact_payload() -> dict[str, Any]:
    return {
        "name": "builtin-windows-exporter",
        "kind": "collector",
        "description": (
            "Bounded windows_exporter metric collection for previews, "
            "validation, and investigation evidence."
        ),
        "owner": "icheck",
        "labels": {
            "builtin": True,
            "platform": "windows",
            "metrics_format": "prometheus",
        },
        "initial_version": {
            "definition": {
                "purpose": (
                    "Collect selected windows_exporter samples as normalized "
                    "observation envelopes."
                ),
                "production_metrics_path": (
                    "Prometheus continuously scrapes windows_exporter and "
                    "remote-writes to the configured metrics backend."
                ),
            },
            "implementation": {
                "runtime": "builtin",
                "adapter": "windows_exporter",
            },
            "tests": [
                {
                    "name": "CPU sample",
                    "fixture": "windows_cpu_time_total{core=\"0\",mode=\"idle\"} 1",
                }
            ],
            "created_by": "system.bootstrap",
            "collector_definition": {
                "adapter_type": "windows_exporter",
                "mode": "poll",
                "output_kinds": ["observation"],
                "credential_profile_ref": None,
                "target_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["url"],
                    "properties": {
                        "url": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 2048,
                        }
                    },
                },
                "config_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "collectors": {
                            "type": "array",
                            "maxItems": 32,
                            "items": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 128,
                            },
                        },
                        "include_metric_prefixes": {
                            "type": "array",
                            "maxItems": 32,
                            "items": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 128,
                            },
                        },
                        "timeout_seconds": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 120,
                        },
                        "max_response_bytes": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 50_000_000,
                        },
                        "max_metrics": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 2000,
                        },
                        "source": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 255,
                        },
                    },
                },
                "defaults": {
                    "collectors": [
                        "cpu",
                        "logical_disk",
                        "memory",
                        "net",
                        "os",
                        "service",
                        "system",
                    ],
                    "include_metric_prefixes": ["windows_"],
                    "timeout_seconds": 15,
                    "max_response_bytes": 10_000_000,
                    "max_metrics": 2000,
                },
            },
        },
    }


def psrp_cim_artifact_payload() -> dict[str, Any]:
    operations = [
        "operating_system",
        "computer_system",
        "logical_disks",
        "network_adapters",
    ]
    return {
        "name": "builtin-psrp-cim-diagnostics",
        "kind": "collector",
        "description": (
            "Governed, on-demand Windows diagnostics using fixed read-only "
            "CIM templates over PSRP/WinRM TLS."
        ),
        "owner": "icheck",
        "labels": {
            "builtin": True,
            "platform": "windows",
            "risk_level": "diagnose_read_only",
        },
        "initial_version": {
            "definition": {
                "purpose": "Run approved read-only Windows diagnostic queries.",
                "policy": {
                    "arbitrary_powershell": False,
                    "tls_required": True,
                    "credential_resolution": "external_broker_only",
                },
            },
            "implementation": {
                "runtime": "builtin",
                "adapter": "psrp_cim",
            },
            "tests": [
                {
                    "name": "operating-system inventory",
                    "operation": "operating_system",
                }
            ],
            "created_by": "system.bootstrap",
            "collector_definition": {
                "adapter_type": "psrp_cim",
                "mode": "poll",
                "output_kinds": ["observation"],
                "credential_profile_ref": None,
                "target_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["host"],
                    "properties": {
                        "host": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 255,
                        },
                        "port": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 65535,
                        },
                        "use_ssl": {"const": True},
                    },
                },
                "config_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "operations": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 4,
                            "uniqueItems": True,
                            "items": {"enum": operations},
                        },
                        "timeout_seconds": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 120,
                        },
                        "max_records": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 500,
                        },
                        "max_response_bytes": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 10_000_000,
                        },
                        "source": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 255,
                        },
                    },
                },
                "defaults": {
                    "operations": operations,
                    "timeout_seconds": 10,
                    "max_records": 500,
                    "max_response_bytes": 2_000_000,
                },
            },
        },
    }


def _ensure_builtin_artifact(
    db: Session,
    payload: dict[str, Any],
) -> Artifact:
    existing = db.scalar(
        select(Artifact).where(
            Artifact.kind == ArtifactKind.COLLECTOR,
            Artifact.name == payload["name"],
        )
    )
    if existing is not None:
        return existing
    artifact = create_artifact(
        db,
        ArtifactCreate.model_validate(payload),
    )
    version = artifact.versions[0]
    validate_artifact_version(db, version, "system.bootstrap")
    publish_artifact_version(db, version, "system.bootstrap")
    return artifact


def ensure_snmp_exporter_artifact(db: Session) -> Artifact:
    return _ensure_builtin_artifact(db, snmp_exporter_artifact_payload())


def ensure_snmp_topology_artifact(db: Session) -> Artifact:
    return _ensure_builtin_artifact(db, snmp_topology_artifact_payload())


def ensure_windows_exporter_artifact(db: Session) -> Artifact:
    return _ensure_builtin_artifact(db, windows_exporter_artifact_payload())


def ensure_psrp_cim_artifact(db: Session) -> Artifact:
    return _ensure_builtin_artifact(db, psrp_cim_artifact_payload())
