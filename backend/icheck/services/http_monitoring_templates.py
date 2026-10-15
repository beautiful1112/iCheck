"""Versioned Prometheus templates in the existing collector artifact lifecycle.

This runtime never emits inventory envelopes or schedules SQL collector runs.
Network reads happen only through the separately approved target test/gateway.
"""
import ipaddress
import json
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from ..collector_schemas import ArtifactCreate
from ..http_metrics import HTTPMonitorSpec, HTTPMetricError, extract_metrics, spec_hash
from ..models import ArtifactKind
from .collectors import assert_no_inline_secrets

SCHEMA = "icheck.monitoring-template/v1"
RUNTIME = {"runtime": "prometheus_gateway_v1", "adapter": "http_metrics"}
PERMISSIONS = ["assets.write", "metrics.read"]
DEPENDENCIES = ["icheck-monitoring-gateway", "prometheus", "grafana"]


class HTTPTemplateDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = Field(alias="schema", pattern=r"^icheck\.monitoring-template/v1$")
    plugin: str = Field(pattern=r"^http$")
    http_monitor: HTTPMonitorSpec
    port: int = Field(ge=1, le=65535)
    unsupported_metrics: list[str] = Field(default_factory=list, max_length=32)
    required_permissions: list[str]
    dependencies: list[str]


def request_from_url(url, intent):
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise HTTPMetricError("Use a credential-free HTTP(S) monitoring URL")
    try:
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        ipaddress.ip_address(parsed.hostname)
        server_name = None
    except ValueError:
        # An invalid port must not become a hostname request.
        try: port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        except ValueError: raise HTTPMetricError("Monitoring URL has an invalid port") from None
        server_name = parsed.hostname
    if not 1 <= port <= 65535: raise HTTPMetricError("Monitoring URL has an invalid port")
    try:
        request = HTTPMonitorSpec(mode="probe", scheme=parsed.scheme,
            path=(parsed.path or "/") + ("?" + parsed.query if parsed.query else ""), server_name=server_name,
            auth_mode=intent.auth_mode, credential_header=intent.credential_header)
    except ValueError:
        raise HTTPMetricError("Monitoring request path, certificate name or header is invalid or credential-bearing") from None
    if request.auth_mode != "none" and request.scheme != "https":
        raise HTTPMetricError("Authenticated monitoring requires HTTPS")
    return request, port


def studio_input(session):
    for message in session.messages:
        value = message.structured_content.get("http_monitoring_input") if message.role == "system" else None
        if isinstance(value, dict): return value
    return None


def artifact_payload(session, spec, request, *, actor, sample_provided):
    http_monitor = HTTPMonitorSpec.model_validate({**request.model_dump(), "mode": studio_input(session)["mode"],
        "metrics": [item.model_dump() for item in spec.metrics]})
    definition = {"schema": SCHEMA, "plugin": "http", "http_monitor": http_monitor.model_dump(), "port": studio_input(session)["port"],
        "unsupported_metrics": spec.unsupported_metrics, "required_permissions": PERMISSIONS, "dependencies": DEPENDENCIES}
    return ArtifactCreate(name=spec.artifact_name, kind=ArtifactKind.COLLECTOR, description=spec.description, owner=actor,
        labels={"plugin": "http", "monitoring_template": True}, initial_version={
            "definition": definition, "implementation": RUNTIME,
            "tests": [{"sample_document": session.sample_document}] if sample_provided and http_monitor.mode == "api" else [],
            "created_by": actor, "collector_definition": {"adapter_type": "http_metrics", "mode": "poll",
                # Compatibility metadata for the existing Collector registry.
                # Actual output is Prometheus exposition, never SQL envelopes.
                "output_kinds": ["observation"], "defaults": {}, "config_schema": {"type": "object", "additionalProperties": False},
                "target_schema": {"type": "object", "additionalProperties": False, "properties": {
                    "device_id": {"type": "string"}, "connection_id": {"type": "string"}}, "required": ["device_id", "connection_id"]}}})


def validate_contract(definition, implementation, tests, collector):
    parsed = HTTPTemplateDefinition.model_validate(definition)
    if (implementation != RUNTIME or collector is None or collector.adapter_type != "http_metrics"
            or collector.defaults or collector.credential_profile_ref or collector.mode.value != "poll"
            or collector.output_kinds != ["observation"]
            or parsed.required_permissions != PERMISSIONS or parsed.dependencies != DEPENDENCIES):
        raise ValueError("HTTP monitoring template must use the native Prometheus gateway contract without code or embedded credentials")
    assert_no_inline_secrets(definition, "http_monitoring_template")
    if len(tests) > 1: raise ValueError("HTTP templates use at most one bounded local response fixture")
    sample_count = 0
    for fixture in tests:
        if not isinstance(fixture, dict) or set(fixture) != {"sample_document"}:
            raise ValueError("HTTP monitoring fixture must contain only sanitized JSON sample data")
        assert_no_inline_secrets(fixture, "http_monitoring_fixture")
        _, _, sample_count = extract_metrics(parsed.http_monitor,
            json.dumps(fixture["sample_document"], allow_nan=False).encode())
    return {"runtime": RUNTIME["runtime"], "adapter": "http_metrics", "plugin": "http",
        "isolation": "declarative_no_generated_code", "validation_level": "fixture" if tests else "schema",
        "fixture_count": len(tests), "metric_samples": sample_count,
        "metric_names": [metric.name for metric in parsed.http_monitor.metrics], "spec_hash": spec_hash(parsed.http_monitor),
        "required_permissions": PERMISSIONS, "dependencies": DEPENDENCIES,
        "unsupported_metrics": parsed.unsupported_metrics, "live_target_tested": False, "continuous_collection_enabled": False}
