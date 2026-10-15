from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime
from typing import Any

from .snmp_exporter import NAME_PATTERN, collect_snmp_exporter


MAX_NEIGHBORS = 2000


def _required_name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not NAME_PATTERN.fullmatch(value):
        raise ValueError(f"{field} contains an invalid metric or label name")
    return value


def _label_names(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 8:
        raise ValueError(f"{field} must contain between 1 and 8 label names")
    names = [_required_name(item, field) for item in value]
    if len(set(names)) != len(names):
        raise ValueError(f"{field} cannot contain duplicate label names")
    return names


def _optional_text(value: Any, field: str, *, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ValueError(f"{field} must contain between 1 and {maximum} characters")
    return normalized


def _required_label(labels: dict[str, str], name: str, field: str) -> str:
    value = _optional_text(labels.get(name), field, maximum=512)
    if value is None:
        raise ValueError(f"SNMP topology metric is missing required label {name!r}")
    return value


def _observed_at(envelopes: list[dict[str, Any]]) -> datetime:
    values: list[datetime] = []
    for envelope in envelopes:
        value = envelope.get("observed_at")
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("SNMP topology sample timestamp is invalid") from exc
            values.append(
                parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed
            )
    return max(values) if values else datetime.now(UTC)


def collect_snmp_topology(assignment: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a normalized SNMP Exporter info metric into one adjacency snapshot."""

    allowed_kinds = set(assignment.get("output_kinds") or [])
    if "relationship" not in allowed_kinds:
        raise ValueError("snmp_topology collectors must declare relationship output")

    target = assignment.get("target") or {}
    configuration = {
        **(assignment.get("defaults") or {}),
        **(assignment.get("configuration") or {}),
    }
    protocol = configuration.get("protocol", "lldp")
    if protocol not in {"lldp", "cdp"}:
        raise ValueError("protocol must be lldp or cdp")
    neighbor_metric = _required_name(
        configuration.get("neighbor_metric", "icheck_lldp_neighbor_info"),
        "neighbor_metric",
    )
    health_metric = _required_name(
        configuration.get(
            "scrape_health_metric",
            "snmp_scrape_walk_duration_seconds",
        ),
        "scrape_health_metric",
    )
    local_port_label = _required_name(
        configuration.get("local_port_label", "local_port"),
        "local_port_label",
    )
    remote_key_labels = _label_names(
        configuration.get(
            "remote_device_key_labels",
            ["remote_chassis_id", "remote_system_name"],
        ),
        "remote_device_key_labels",
    )
    remote_name_label = _required_name(
        configuration.get("remote_system_name_label", "remote_system_name"),
        "remote_system_name_label",
    )
    remote_port_label = _required_name(
        configuration.get("remote_port_label", "remote_port"),
        "remote_port_label",
    )
    management_ip_label_value = configuration.get(
        "remote_management_ip_label",
        "remote_management_ip",
    )
    management_ip_label = (
        None
        if management_ip_label_value is None
        else _required_name(
            management_ip_label_value,
            "remote_management_ip_label",
        )
    )
    complete_snapshot = configuration.get("complete_snapshot", True)
    if not isinstance(complete_snapshot, bool):
        raise ValueError("complete_snapshot must be a boolean")
    max_neighbors = configuration.get("max_neighbors", 1000)
    if (
        isinstance(max_neighbors, bool)
        or not isinstance(max_neighbors, int)
        or max_neighbors < 1
        or max_neighbors > MAX_NEIGHBORS
    ):
        raise ValueError(f"max_neighbors must be between 1 and {MAX_NEIGHBORS}")

    snmp_target = _optional_text(target.get("target"), "target.target", maximum=512)
    if snmp_target is None:
        raise ValueError("snmp_topology target.target is required")
    local_device_key = _optional_text(
        target.get("local_device_key"),
        "target.local_device_key",
        maximum=512,
    ) or snmp_target
    local_display_name = _optional_text(
        target.get("local_display_name"),
        "target.local_display_name",
        maximum=255,
    ) or local_device_key

    metric_assignment = {
        **assignment,
        "output_kinds": ["observation"],
        "configuration": {
            **configuration,
            "include_metric_prefixes": [neighbor_metric, health_metric],
            "max_metrics": min(2000, max_neighbors + 64),
        },
        "_runtime": {
            **(assignment.get("_runtime") or {}),
            "allow_empty_snmp_metrics": True,
        },
    }
    samples = collect_snmp_exporter(metric_assignment)
    health_samples = [
        item
        for item in samples
        if item.get("payload", {}).get("metric") == health_metric
    ]
    if complete_snapshot and not health_samples:
        raise ValueError(
            "A complete SNMP topology snapshot requires the configured "
            "scrape_health_metric"
        )

    neighbor_samples = [
        item
        for item in samples
        if item.get("payload", {}).get("metric") == neighbor_metric
        and isinstance(item.get("payload", {}).get("value"), (int, float))
        and item["payload"]["value"] > 0
    ]
    if len(neighbor_samples) > max_neighbors:
        raise ValueError("SNMP topology response exceeded max_neighbors")

    neighbors: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str]] = set()
    for sample in neighbor_samples:
        labels = sample["payload"].get("labels") or {}
        if not isinstance(labels, dict):
            raise ValueError("SNMP topology metric labels must be an object")
        remote_device_key = next(
            (
                value
                for label in remote_key_labels
                if (value := _optional_text(
                    labels.get(label),
                    f"label.{label}",
                    maximum=512,
                ))
            ),
            None,
        )
        if remote_device_key is None:
            raise ValueError(
                "SNMP topology metric has no usable remote device identity"
            )
        local_port = _required_label(labels, local_port_label, "local_port")
        remote_port = _required_label(labels, remote_port_label, "remote_port")
        identity = (remote_device_key, local_port, remote_port)
        if identity in identities:
            raise ValueError("SNMP topology metric contains a duplicate link")
        identities.add(identity)
        remote_system_name = _optional_text(
            labels.get(remote_name_label),
            "remote_system_name",
            maximum=255,
        )
        management_ip = (
            _optional_text(
                labels.get(management_ip_label),
                "remote_management_ip",
                maximum=64,
            )
            if management_ip_label is not None
            else None
        )
        if management_ip is not None:
            try:
                management_ip = str(ipaddress.ip_address(management_ip))
            except ValueError as exc:
                raise ValueError(
                    "SNMP topology remote management address is invalid"
                ) from exc
        neighbors.append(
            {
                "remote_device_key": remote_device_key,
                "remote_system_name": remote_system_name,
                "local_port": local_port,
                "remote_port": remote_port,
                "management_ip": management_ip,
            }
        )

    neighbors.sort(
        key=lambda item: (
            item["remote_device_key"],
            item["local_port"],
            item["remote_port"],
        )
    )
    observed_at = _observed_at(samples)
    source = configuration.get(
        "source",
        f"snmp_topology:{assignment.get('artifact_name', 'unknown')}",
    )
    if not isinstance(source, str) or not source.strip() or len(source) > 255:
        raise ValueError("source must contain between 1 and 255 characters")
    idempotency_key = hashlib.sha256(
        f"{protocol}\0{local_device_key}\0{observed_at.isoformat()}".encode("utf-8")
    ).hexdigest()
    return [
        {
            "kind": "relationship",
            "type": "icheck.network.device-adjacency-snapshot/v1",
            "source": source.strip(),
            "subject": local_device_key,
            "observed_at": observed_at.isoformat(),
            "payload": {
                "local_device_key": local_device_key,
                "local_display_name": local_display_name,
                "protocol": protocol,
                "complete_snapshot": complete_snapshot,
                "neighbors": neighbors,
            },
            "idempotency_key": idempotency_key,
        }
    ]
