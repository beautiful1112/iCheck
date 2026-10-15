"""SNMP uses the same immutable Prometheus monitoring-template lifecycle as HTTP."""
import hashlib
import os
from pathlib import Path
import re

from pydantic import BaseModel, ConfigDict, Field
import yaml

from ..collector_schemas import ArtifactCreate
from ..managed_snmp import module_document, trusted_file
from ..models import ArtifactKind
from ..snmp_generator import GeneratorRuntime, MODULE, PROFILES, SNMPGeneratorRequest, compile_module, validate_compiled
from .http_monitoring_templates import SCHEMA, PERMISSIONS

RUNTIME = {"runtime": "prometheus_gateway_v1", "adapter": "snmp_exporter"}
DEPENDENCIES = ["snmp-generator", "snmp-module-installer", "icheck-monitoring-gateway", "prometheus", "grafana"]


class SNMPTemplateDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = Field(alias="schema", pattern=r"^icheck\.monitoring-template/v1$")
    plugin: str = Field(pattern=r"^snmp$")
    compiled_module: dict
    unsupported_metrics: list[str] = Field(default_factory=list, max_length=32)
    required_permissions: list[str]
    dependencies: list[str]


def native_runtime():
    try:
        return GeneratorRuntime.from_manifest(Path(os.environ.get("ICHECK_SNMP_GENERATOR_MANIFEST",
            "/etc/icheck-workers/snmp-runtime/generator.json")))
    except (OSError, ValueError, TypeError, KeyError):
        raise ValueError("Native SNMP generator is not configured; ask the server administrator to provision its protected runtime") from None


def shared_mibs():
    directory = Path(os.environ.get("ICHECK_SNMP_GENERATOR_MIB_DIRECTORY", "/opt/icheck/snmp-mibs"))
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError("Standard SNMP MIB dependencies are not installed")
    if not directory.exists(): return []  # A complete uploaded family may supply its own dependencies.
    if not directory.is_dir(): raise ValueError("Standard SNMP MIB dependency path is invalid")
    result = []
    for path in sorted(directory.iterdir()):
        if not path.is_file(): continue
        path = trusted_file(path)
        if len(result) >= 32 or path.stat().st_size > 1_000_000:
            raise ValueError("Standard SNMP MIB dependency bundle exceeds its bounds")
        result.append(path.read_text(encoding="utf-8"))
    return result


def input_context(intent):
    # Fail before a paid model call if the native compiler is unavailable.
    runtime = native_runtime(); runtime.validate()
    sources = {}
    provenance = []
    uploaded={}
    for text in [*shared_mibs(), *intent.mib_documents]:
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        names = MODULE.findall(normalized)
        if len(names) != 1 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", names[0]):
            raise ValueError("Each source MIB must contain one named module")
        name = names[0]
        if text in intent.mib_documents:
            if name in uploaded and uploaded[name]!=normalized:
                raise ValueError("MIB upload contains conflicting versions of the same module")
            uploaded[name]=normalized
        elif name in sources and sources[name]!=normalized:
            raise ValueError("Installed MIB dependencies contain conflicting versions")
        sources[name] = normalized
    requested_modules = list(intent.mib_modules)
    if intent.profile != "custom":
        requested_modules += list(dict.fromkeys(symbol.split("::")[0]
            for symbols in PROFILES[intent.profile].values() for symbol in symbols))
    from ..config import get_settings
    # Preserve offline catalogs with partial profiles: unavailable intents are
    # still disclosed. Explicitly requested missing families must not be guessed.
    if requested_modules and (intent.mib_modules or get_settings().research_enabled):
        from .mib_research import complete_bundle
        bundle = complete_bundle(list(dict.fromkeys(requested_modules)), list(sources.values()))
        sources = {MODULE.findall(text)[0]: text for text in bundle["documents"]}
        provenance = bundle["sources"]
    if not sources or len(sources) > 32 or sum(len(x.encode()) for x in sources.values()) > 4_000_000:
        raise ValueError("SNMP MIB bundle exceeds its source bounds")
    catalog = []
    if intent.profile != "custom":
        for metric_intent, symbols in PROFILES[intent.profile].items():
            for symbol in symbols:
                if symbol.split("::")[0] in sources:
                    catalog.append({"symbol": symbol, "intent": metric_intent})
    else:
        # Extract symbolic leaf names only. Imported OIDs/types/indexes are
        # resolved by the actual generator after model selection, not this scan.
        from .mib_ingestion import ASSIGNMENT_PATTERN, ACCESS_PATTERN, _strip_comments
        for name, text in sources.items():
            for match in ASSIGNMENT_PATTERN.finditer(_strip_comments(text)):
                access = ACCESS_PATTERN.search(match.group(3))
                if (match.group(2) == "OBJECT-TYPE" and access and access.group(1) in {"read-only", "read-write", "read-create"}
                        and not re.search(r"password|community|secret|token|private.?key",match.group(1),re.I)):
                    catalog.append({"symbol": name + "::" + match.group(1), "access": access.group(1)})
    if not catalog or len(catalog) > 500:
        raise ValueError("No bounded supported MIB catalog is available; upload this vendor MIB and its dependencies")
    return {"profile": intent.profile, "schedule_seconds": intent.schedule_seconds,
        "credential_profile_ref": intent.credential_profile_ref, "symbol_catalog": catalog,
        "mib_documents": list(sources.values()), "research_sources": provenance}


def studio_input(session):
    for message in session.messages:
        value = (message.structured_content or {}).get("snmp_monitoring_input") if message.role == "system" else None
        if isinstance(value, dict): return value
    return None


def compile_spec(context, spec):
    allowed = {item["symbol"] for item in context["symbol_catalog"]}
    if not set(spec.symbols).issubset(allowed):
        raise ValueError("AI selected a symbol outside this real MIB/profile catalog")
    request = SNMPGeneratorRequest(symbols=spec.symbols, lookups=spec.lookups)
    if any(lookup.lookup not in allowed for lookup in request.lookups):
        raise ValueError("AI selected a lookup outside this real MIB/profile catalog")
    return compile_module(request,runtime=native_runtime(),mib_documents=context["mib_documents"])


def artifact_payload(session, spec, compiled, *, actor):
    definition = {"schema": SCHEMA, "plugin": "snmp", "compiled_module": compiled,
        "unsupported_metrics": spec.unsupported_metrics, "required_permissions": PERMISSIONS, "dependencies": DEPENDENCIES}
    return ArtifactCreate(name=spec.artifact_name,kind=ArtifactKind.COLLECTOR,description=spec.description,owner=actor,
        labels={"plugin":"snmp","monitoring_template":True},initial_version={"definition":definition,
            "implementation":RUNTIME,"tests":[],"created_by":actor,"collector_definition":{
                "adapter_type":"snmp_exporter","mode":"poll","output_kinds":["observation"],"defaults":{},
                "config_schema":{"type":"object","additionalProperties":False},"target_schema":{
                    "type":"object","additionalProperties":False,"properties":{"device_id":{"type":"string"},
                        "connection_id":{"type":"string"}},"required":["device_id","connection_id"]}}})


def validate_contract(definition,implementation,tests,collector):
    parsed = SNMPTemplateDefinition.model_validate(definition)
    validate_compiled(parsed.compiled_module)
    if (implementation != RUNTIME or collector is None or collector.adapter_type != "snmp_exporter"
            or collector.defaults or collector.credential_profile_ref or collector.mode.value != "poll"
            or collector.output_kinds != ["observation"] or tests
            or parsed.required_permissions != PERMISSIONS or parsed.dependencies != DEPENDENCIES):
        raise ValueError("SNMP monitoring templates require compiled declarative modules, not code or inline credentials")
    return {"runtime":RUNTIME["runtime"],"adapter":"snmp_exporter","plugin":"snmp",
        "validation_level":"native_generator","metric_names":[m["name"] for m in parsed.compiled_module["expected_metrics"]],
        "module_name":parsed.compiled_module["module_name"],"module_sha256":parsed.compiled_module["module_sha256"],
        "unsupported_metrics":parsed.unsupported_metrics,"live_target_tested":False,"continuous_collection_enabled":False}


def installed(compiled):
    expected = validate_compiled(compiled)
    try: actual = module_document()["modules"].get(compiled["module_name"])
    except (OSError, ValueError): return False
    return actual == expected


def configuration(compiled, version_id):
    return {"modules":[compiled["module_name"]],"monitoring_template_version_id":version_id,
        "snmp_module_sha256":compiled["module_sha256"],"snmp_expected_metrics":compiled["expected_metrics"]}


def evidence_matches(connection, profile, *, evidence=None):
    proof = connection.last_verification_evidence if evidence is None else evidence
    expected = sorted(item["name"] for item in connection.configuration.get("snmp_expected_metrics", []))
    return (bool(expected) and proof.get("check") == "snmp_metric_query" and proof.get("success") is True
        and proof.get("module_sha256") == connection.configuration.get("snmp_module_sha256")
        and proof.get("metric_names") == expected and proof.get("modules") == connection.configuration.get("modules")
        and proof.get("target_host") == connection.device.management_ip and proof.get("target_port") == connection.port
        and isinstance(proof.get("metric_samples"),int) and not isinstance(proof["metric_samples"],bool)
        and proof["metric_samples"] >= len(expected) and profile is not None and profile.provider == "managed_device"
        and proof.get("credential_revision") == profile.revision)
