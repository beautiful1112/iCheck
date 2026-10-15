from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from ..studio_schemas import GeneratedSNMPExporterProposalSpec


PROPOSAL_SCHEMA = "icheck.snmp-exporter-proposal/v1"
PUBLICATION_GATE = {
    "required": "external_snmp_exporter_generator_v1",
    "satisfied": False,
}
OID_PATTERN = re.compile(r"^(?:0|1|2)(?:\.(?:0|[1-9][0-9]{0,9})){1,127}$")


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def validate_snmp_exporter_proposal_contract(
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
    collector_definition: Any,
) -> dict[str, Any]:
    if definition.get("schema") != PROPOSAL_SCHEMA:
        raise ValueError("Unsupported SNMP Exporter proposal schema")
    if implementation != {"runtime": "builtin", "adapter": "snmp_exporter"}:
        raise ValueError(
            "SNMP Exporter proposals require the trusted builtin adapter"
        )
    if definition.get("publication_gate") != PUBLICATION_GATE:
        raise ValueError(
            "SNMP Exporter proposals must retain the unsatisfied external "
            "generator publication gate"
        )
    spec = GeneratedSNMPExporterProposalSpec.model_validate(
        definition.get("spec")
    )
    provenance = definition.get("mib_provenance")
    if not isinstance(provenance, dict):
        raise ValueError("SNMP Exporter proposal MIB provenance is missing")
    document_sha256 = provenance.get("document_sha256")
    if (
        not isinstance(document_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", document_sha256) is None
    ):
        raise ValueError("SNMP Exporter proposal MIB hash is invalid")
    if (
        provenance.get("module_name") is None
        or provenance.get("parser") != "icheck_smi_subset_v1"
    ):
        raise ValueError("SNMP Exporter proposal MIB provenance is invalid")

    resolved = definition.get("resolved_walk_symbols")
    if not isinstance(resolved, list) or len(resolved) != len(spec.walk_symbols):
        raise ValueError("SNMP Exporter proposal walk evidence is incomplete")
    oids: list[str] = []
    for expected_name, item in zip(spec.walk_symbols, resolved, strict=True):
        if not isinstance(item, dict) or item.get("name") != expected_name:
            raise ValueError("SNMP Exporter proposal walk symbol order drifted")
        if item.get("kind") not in {
            "module_identity",
            "object_identifier",
            "object_identity",
            "object_type",
        }:
            raise ValueError("SNMP Exporter proposal contains a non-walkable symbol")
        oid = item.get("oid")
        if not isinstance(oid, str) or OID_PATTERN.fullmatch(oid) is None:
            raise ValueError("SNMP Exporter proposal contains an invalid OID")
        oids.append(oid)
    if len(oids) != len(set(oids)):
        raise ValueError("SNMP Exporter proposal walk OIDs must be unique")

    expected_module = {
        "walk": oids,
        "max_repetitions": spec.max_repetitions,
        "retries": spec.retries,
        "timeout": f"{spec.timeout_seconds}s",
    }
    if definition.get("generator_module") != expected_module:
        raise ValueError("SNMP Exporter generator proposal drifted from its spec")
    if collector_definition.adapter_type != "snmp_exporter":
        raise ValueError("SNMP Exporter proposal adapter drifted")
    if collector_definition.defaults.get("modules") != [
        spec.exporter_module_name
    ]:
        raise ValueError("SNMP Exporter proposal module default drifted")
    modules_schema = (
        collector_definition.config_schema.get("properties", {})
        .get("modules", {})
    )
    if modules_schema != {"const": [spec.exporter_module_name]}:
        raise ValueError("SNMP Exporter proposal module must be schema-pinned")
    if len(tests) != 1 or not isinstance(tests[0], dict):
        raise ValueError("SNMP Exporter proposal requires one hash-only test")
    expected_test = {
        "name": "Resolved MIB walk proposal",
        "mib_document_sha256": document_sha256,
        "generator_module_sha256": _canonical_hash(expected_module),
        "walk_symbol_count": len(oids),
    }
    if tests[0] != expected_test:
        raise ValueError("SNMP Exporter proposal hash evidence drifted")
    return {
        "runtime": "builtin",
        "isolation": "trusted_proposal_compiler",
        "tests_declared": 1,
        "proposal_contract": PROPOSAL_SCHEMA,
        "mib_document_sha256": document_sha256,
        "resolved_walk_symbol_count": len(oids),
        "generator_module_sha256": expected_test[
            "generator_module_sha256"
        ],
        "publication_blocked": True,
        "publication_blocker": "external_generator_compile_required",
    }


def assert_artifact_publication_ready(definition: dict[str, Any]) -> None:
    if definition.get("schema") != PROPOSAL_SCHEMA:
        return
    raise ValueError(
        "SNMP Exporter proposal cannot be published until an external "
        "generator compiles the module and a new attested deployable Artifact "
        "version passes live-device validation"
    )
