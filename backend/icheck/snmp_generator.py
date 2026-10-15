"""Native, secret-free MIB compilation; no target I/O or collection approval.

The generator parses real MIB dependencies through Net-SNMP. Models select
qualified leaf symbols, never manufacture numeric OIDs or exporter YAML.
The upstream generator has no --version flag: its protected build manifest
binds a declared source version to the actual executable digest instead.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

from pydantic import BaseModel, ConfigDict, Field, field_validator
import yaml

from .managed_snmp import trusted_file

FORMAT = "icheck.snmp-compiled-module/v1"
MAX_YAML = 2_000_000
SYMBOL = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}::[A-Za-z][A-Za-z0-9-]{0,127}$")
OID = re.compile(r"^[012](?:\.(?:0|[1-9][0-9]{0,9})){1,127}$")
MODULE = re.compile(r"(?m)^[ \t]*([A-Za-z][A-Za-z0-9-]*)\s+DEFINITIONS\s*::=\s*BEGIN\b")

# A starting catalog, not an invented OID map. The native generator resolves
# these real standard/vendor symbols, including AUGMENTS and imported types.
PROFILES = {
    "standard-network": {
        "uptime": ["SNMPv2-MIB::sysUpTime"],
        "interface_traffic": ["IF-MIB::ifHCInOctets", "IF-MIB::ifHCOutOctets"],
        "interface_status": ["IF-MIB::ifAdminStatus", "IF-MIB::ifOperStatus"],
        "interface_errors": ["IF-MIB::ifInErrors", "IF-MIB::ifOutErrors"],
        "interface_speed": ["IF-MIB::ifHighSpeed"],
    },
    "cisco-cpu": {
        "cpu_utilization": ["CISCO-PROCESS-MIB::cpmCPUTotal5secRev",
            "CISCO-PROCESS-MIB::cpmCPUTotal1minRev", "CISCO-PROCESS-MIB::cpmCPUTotal5minRev"],
    },
    "network-tables": {
        "arp_ipv4": ["IP-MIB::ipNetToMediaPhysAddress", "IP-MIB::ipNetToMediaType"],
        "ip_neighbors": ["IP-MIB::ipNetToPhysicalPhysAddress", "IP-MIB::ipNetToPhysicalState"],
        "mac_table": ["BRIDGE-MIB::dot1dTpFdbPort", "BRIDGE-MIB::dot1dTpFdbStatus"],
        "vlan_mac_table": ["Q-BRIDGE-MIB::dot1qTpFdbPort", "Q-BRIDGE-MIB::dot1qTpFdbStatus", "Q-BRIDGE-MIB::dot1qVlanFdbId"],
        "interface_mapping": ["BRIDGE-MIB::dot1dBasePortIfIndex", "IF-MIB::ifName"],
    },
}


def resolve_profile(profile: str, requested: list[str]) -> dict:
    if profile not in PROFILES or not isinstance(requested, list) or not 1 <= len(requested) <= 32:
        raise ValueError("Select a known SNMP profile and 1 to 32 metric intents")
    if any(not isinstance(x, str) or not 1 <= len(x) <= 128 for x in requested):
        raise ValueError("SNMP metric intents must be bounded strings")
    supported = PROFILES[profile]
    return {"profile": profile,
        "symbols": list(dict.fromkeys(s for key in requested for s in supported.get(key, []))),
        "unsupported_metrics": list(dict.fromkeys(key for key in requested if key not in supported))}


class SNMPLookup(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source_indexes: list[str] = Field(min_length=1, max_length=8)
    lookup: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9-]{0,127}::[A-Za-z][A-Za-z0-9-]{0,127}$")
    drop_source_indexes: bool = False

    @field_validator("source_indexes")
    @classmethod
    def index_names(cls, value):
        if len(set(value)) != len(value) or any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", x) for x in value):
            raise ValueError("Lookup indexes must be distinct symbolic column names")
        return value


class SNMPGeneratorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    symbols: list[str] = Field(min_length=1, max_length=32)
    max_repetitions: int = Field(default=20, ge=1, le=50)
    retries: int = Field(default=0, ge=0, le=2)
    timeout_seconds: int = Field(default=5, ge=1, le=15)
    lookups: list[SNMPLookup] = Field(default_factory=list, max_length=8)

    @field_validator("symbols")
    @classmethod
    def symbolic_leaves(cls, value):
        if len(set(value)) != len(value) or any(not SYMBOL.fullmatch(x) for x in value):
            raise ValueError("Select distinct module-qualified MIB leaf symbols, not numeric OIDs")
        return value


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_digest(value) -> str:
    return _digest(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())


class _UniqueLoader(yaml.SafeLoader):
    pass


def _unique_map(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, (str, int)) or isinstance(key, bool) or key in result:
            raise ValueError("SNMP configuration contains invalid or duplicate keys")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_map)


def load_yaml(encoded: bytes, *, maximum=MAX_YAML):
    if len(encoded) > maximum:
        raise ValueError("SNMP configuration exceeds its byte limit")
    try:
        depth = 0
        for token in yaml.scan(encoded):
            if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)):
                raise ValueError("SNMP configuration cannot use YAML aliases or anchors")
            if isinstance(token, (yaml.tokens.BlockMappingStartToken, yaml.tokens.BlockSequenceStartToken,
                    yaml.tokens.FlowMappingStartToken, yaml.tokens.FlowSequenceStartToken)):
                depth += 1
                if depth > 32: raise ValueError("SNMP configuration nesting is excessive")
            if isinstance(token, (yaml.tokens.BlockEndToken, yaml.tokens.FlowMappingEndToken, yaml.tokens.FlowSequenceEndToken)):
                depth -= 1
        return yaml.load(encoded, Loader=_UniqueLoader)
    except (yaml.YAMLError, UnicodeError, TypeError, RecursionError):
        raise ValueError("SNMP configuration must be bounded safe UTF-8 YAML") from None


def _command(command, *, cwd, timeout=120):
    # No shell, ambient credentials, proxies, user snmp.conf or target address.
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(cwd), "SNMPCONFPATH": str(cwd)}
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=out, stderr=err, start_new_session=True)
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise ValueError("Native SNMP command exceeded its deadline")
                if os.fstat(out.fileno()).st_size > 8_000_000 or os.fstat(err.fileno()).st_size > 8_000_000:
                    raise ValueError("Native SNMP diagnostics exceeded their limit")
                time.sleep(.02)
        finally:
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait(timeout=5)
        if process.returncode:
            # Raw diagnostics can include uploaded MIB contents and paths.
            raise ValueError("Native SNMP command failed; check MIB dependencies and selected symbols")
        if out.tell() > 8_000_000 or err.tell() > 8_000_000:
            raise ValueError("Native SNMP diagnostics exceeded their limit")
        out.seek(0)
        err.seek(0)
        return out.read(8_000_001) + b"\n" + err.read(8_000_001)


def dry_run_modules(modules: dict, *, exporter: Path, run=_command):
    # snmp_exporter refuses an empty Auths map even for --dry-run. This dummy
    # profile is only in the private validation file, never in a module catalog,
    # output contract or credential store. No listener or SNMP request is made.
    with tempfile.TemporaryDirectory(prefix="icheck-snmp-dry-run-") as directory:
        work = Path(directory)
        path = work / "snmp.yml"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            yaml.safe_dump({"auths": {"icheck_validation": {"version": 2, "community": "unused-dry-run"}},
                "modules": modules}, handle)
        run([str(exporter), "--dry-run", "--config.file=" + str(path)], cwd=work, timeout=15)


@dataclass(frozen=True)
class GeneratorRuntime:
    generator: Path
    exporter: Path
    version: str
    binary_sha256: str

    @classmethod
    def from_manifest(cls, path: Path):
        path = trusted_file(path)
        if path.stat().st_size > 4096:
            raise ValueError("SNMP generator manifest is oversized")
        document = json.loads(path.read_bytes())
        if set(document) != {"format", "generator_binary", "generator_version", "generator_sha256", "exporter_binary"}:
            raise ValueError("SNMP generator manifest has unsupported fields")
        if document["format"] != "icheck.snmp-generator-runtime/v1":
            raise ValueError("SNMP generator manifest version is unsupported")
        return cls(trusted_file(document["generator_binary"], executable=True),
            trusted_file(document["exporter_binary"], executable=True),
            document["generator_version"], document["generator_sha256"])

    def validate(self):
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.version):
            raise ValueError("SNMP generator source version is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.binary_sha256):
            raise ValueError("SNMP generator executable digest is invalid")
        for binary in (self.generator, self.exporter):
            if not binary.is_absolute() or binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
                raise ValueError("Native SNMP binaries must be absolute regular executables")
        if _digest(self.generator.read_bytes()) != self.binary_sha256:
            raise ValueError("SNMP generator executable does not match its build manifest")


def compile_module(request: SNMPGeneratorRequest, *, runtime: GeneratorRuntime,
        mib_documents: list[str], run=_command) -> dict:
    """Return an immutable secret-free candidate, never install or probe it."""
    request = SNMPGeneratorRequest.model_validate(request)
    runtime.validate()
    if not isinstance(mib_documents, list) or not 1 <= len(mib_documents) <= 32:
        raise ValueError("Provide the selected MIB family and its dependencies")
    staged, provenance, total = {}, [], 0
    for text in mib_documents:
        if not isinstance(text, str):
            raise ValueError("MIB sources must be UTF-8 text")
        try: encoded = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
        except UnicodeError: raise ValueError("MIB source is not UTF-8") from None
        total += len(encoded)
        names = MODULE.findall(encoded.decode())
        if (len(encoded) > 1_000_000 or total > 4_000_000 or b"\x00" in encoded or len(names) != 1
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", names[0])):
            raise ValueError("Each MIB must contain one bounded module; bundle limit is 4 MB")
        name = names[0]
        if name in staged:
            raise ValueError("MIB bundle contains duplicate module names")
        staged[name] = encoded
        provenance.append({"module": name, "sha256": _digest(encoded)})
    if any(symbol.split("::")[0] not in staged for symbol in [*request.symbols, *(x.lookup for x in request.lookups)]):
        raise ValueError("Selected symbols require their source MIB module in the bundle")
    provenance.sort(key=lambda item: item["module"])
    generator_module = {"walk": request.symbols, "max_repetitions": request.max_repetitions,
        "retries": request.retries, "timeout": f"{request.timeout_seconds}s"}
    if request.lookups:
        generator_module["lookups"] = [lookup.model_dump() for lookup in request.lookups]
    identity = {"generator_version": runtime.version, "generator_sha256": runtime.binary_sha256,
        "mibs": provenance, "generator_module": generator_module}
    module_name = "icheck_" + _json_digest(identity)[:24]
    with tempfile.TemporaryDirectory(prefix="icheck-snmp-generator-") as directory:
        work = Path(directory)
        version_output = run([str(runtime.exporter), "--version"], cwd=work, timeout=10)
        match = re.search(rb"\bversion[=,: ]+([0-9]+\.[0-9]+\.[0-9]+)", version_output or b"")
        if not match or match.group(1).decode() != runtime.version:
            raise ValueError("SNMP exporter version does not match the generator source version")
        mibs = work / "mibs"; mibs.mkdir(mode=0o700)
        for name, encoded in staged.items(): (mibs / (name + ".mib")).write_bytes(encoded)
        generator_config = work / "generator.yml"
        output = work / "snmp.yml"
        generator_config.write_text(yaml.safe_dump({"modules": {module_name: generator_module}}))
        run([str(runtime.generator), "--fail-on-parse-errors", "generate", "-m", str(mibs),
            "-g", str(generator_config), "-o", str(output)], cwd=work)
        if not output.is_file() or output.is_symlink() or output.stat().st_size > MAX_YAML:
            raise ValueError("Native SNMP generator did not produce bounded output")
        generated = load_yaml(output.read_bytes())
        if not isinstance(generated, dict) or set(generated) - {"modules", "auths"} or generated.get("auths"):
            raise ValueError("Generated SNMP modules must not contain credentials")
        modules = generated.get("modules")
        if not isinstance(modules, dict) or set(modules) != {module_name}:
            raise ValueError("Native SNMP output must contain the exact proposed module")
        compiled = modules[module_name]
        metrics = _metrics(compiled)
        leaf_names = {s.split("::")[1].replace("-", "_") for s in request.symbols}
        if {m["name"] for m in metrics} != leaf_names:
            raise ValueError("Select supported readable leaf metrics, not a subtree or notification")
        # Run the installed exporter's own strict parser; starts no listener.
        dry_run_modules(modules, exporter=runtime.exporter, run=run)
        module_yaml = yaml.safe_dump(compiled, sort_keys=True)
    return {"format": FORMAT, **identity, "module_name": module_name,
        "module_yaml": module_yaml, "module_sha256": _digest(module_yaml.encode()),
        "expected_metrics": metrics, "validation": "generator_and_exporter_dry_run",
        "live_target_tested": False, "continuous_collection_enabled": False}


def _metrics(module):
    if not isinstance(module, dict) or set(module) - {"walk", "get", "metrics", "max_repetitions", "retries", "timeout"}:
        raise ValueError("Compiled SNMP module contains unsupported configuration")
    metrics = module.get("metrics")
    if not isinstance(metrics, list) or not 1 <= len(metrics) <= 32:
        raise ValueError("Compiled SNMP module must contain 1 to 32 leaf metrics")
    result = []
    for metric in metrics:
        if (not isinstance(metric, dict) or not isinstance(metric.get("name"), str)
                or set(metric) - {"name", "oid", "type", "help", "indexes", "enum_values", "lookups"}
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", metric["name"])
                or not isinstance(metric.get("oid"), str) or not OID.fullmatch(metric["oid"])
                or metric.get("type") not in {"gauge", "counter", "DisplayString", "OctetString", "PhysAddress48", "InetAddressIPv4", "InetAddressIPv6"}):
            raise ValueError("Compiled SNMP metric has unsupported name, OID or type")
        result.append({"name": metric["name"], "oid": metric["oid"], "type": metric["type"]})
    if len({m["name"] for m in result}) != len(result):
        raise ValueError("Compiled SNMP metric names must be unique")
    allowed = {m["oid"] for m in result}
    for metric in metrics:
        lookups = metric.get("lookups", [])
        if not isinstance(lookups, list) or len(lookups) > 16:
            raise ValueError("Compiled SNMP lookups exceed their limit")
        for lookup in lookups:
            if (not isinstance(lookup, dict) or set(lookup) - {"labels", "labelname", "oid", "type"}
                    or not isinstance(lookup.get("labels"), list) or len(lookup["labels"]) > 8
                    or any(not isinstance(label, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", label) for label in lookup["labels"])
                    or not isinstance(lookup.get("labelname"), str)
                    or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", lookup["labelname"])):
                raise ValueError("Compiled SNMP lookup is invalid")
            if "oid" in lookup:
                if not isinstance(lookup["oid"], str) or not OID.fullmatch(lookup["oid"]) or lookup.get("type") not in {
                        "gauge", "DisplayString", "OctetString", "PhysAddress48", "InetAddressIPv4", "InetAddressIPv6"}:
                    raise ValueError("Compiled SNMP lookup OID/type is invalid")
                allowed.add(lookup["oid"])
            elif lookup["labels"]:
                raise ValueError("SNMP label deletion cannot contain source indexes")
    covered = set()
    for key in ("walk", "get"):
        values = module.get(key, [])
        if (not isinstance(values, list) or len(values) > 32 or any(not isinstance(v, str) for v in values)
                or len(set(values)) != len(values)):
            raise ValueError("Compiled SNMP collection OIDs are invalid")
        for value in values:
            original = value[:-2] if key == "get" and isinstance(value, str) and value.endswith(".0") else value
            if original not in allowed:
                raise ValueError("Compiled SNMP collection scope must match its reviewed leaf metrics")
            covered.add(original)
    if covered != allowed:
        raise ValueError("Compiled SNMP module does not collect every expected metric")
    return result


def validate_compiled(document: dict) -> dict:
    fields = {"format", "generator_version", "generator_sha256", "mibs", "generator_module", "module_name",
        "module_yaml", "module_sha256", "expected_metrics", "validation", "live_target_tested", "continuous_collection_enabled"}
    if (not isinstance(document, dict) or set(document) != fields or document.get("format") != FORMAT
            or document.get("validation") != "generator_and_exporter_dry_run"
            or document.get("live_target_tested") is not False or document.get("continuous_collection_enabled") is not False):
        raise ValueError("SNMP compiled candidate contract is invalid")
    identity = {k: document[k] for k in ("generator_version", "generator_sha256", "mibs", "generator_module")}
    if (not isinstance(identity["generator_version"], str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", identity["generator_version"])
            or not isinstance(identity["generator_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", identity["generator_sha256"])):
        raise ValueError("SNMP generation identity is invalid")
    mibs = identity["mibs"]
    if (not isinstance(mibs, list) or not 1 <= len(mibs) <= 32
            or any(not isinstance(m, dict) or set(m) != {"module", "sha256"}
                or not isinstance(m["module"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", m["module"])
                or not isinstance(m["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", m["sha256"]) for m in mibs)
            or len({m["module"] for m in mibs}) != len(mibs)):
        raise ValueError("SNMP MIB provenance is invalid")
    generator_module = identity["generator_module"]
    if (not isinstance(generator_module, dict) or set(generator_module) - {"walk", "max_repetitions", "retries", "timeout", "lookups"}
            or not {"walk", "max_repetitions", "retries", "timeout"} <= set(generator_module)
            or not isinstance(generator_module["timeout"], str) or not re.fullmatch(r"(?:[1-9]|1[0-5])s", generator_module["timeout"])):
        raise ValueError("SNMP generator module is invalid")
    request = SNMPGeneratorRequest(symbols=generator_module["walk"], max_repetitions=generator_module["max_repetitions"],
        retries=generator_module["retries"], timeout_seconds=int(generator_module["timeout"][:-1]), lookups=generator_module.get("lookups", []))
    if document["module_name"] != "icheck_" + _json_digest(identity)[:24]:
        raise ValueError("SNMP module name does not bind its generation inputs")
    if not isinstance(document["module_yaml"], str):
        raise ValueError("SNMP compiled YAML is missing")
    encoded = document["module_yaml"].encode()
    if _digest(encoded) != document["module_sha256"]:
        raise ValueError("SNMP compiled YAML digest does not match")
    module = load_yaml(encoded)
    if _metrics(module) != document["expected_metrics"]:
        raise ValueError("SNMP expected metrics do not match the compiled module")
    if ({m["name"] for m in document["expected_metrics"]} != {s.split("::")[1].replace("-", "_") for s in request.symbols}
            or any(module.get(k) != generator_module[k] for k in ("max_repetitions", "retries", "timeout"))):
        raise ValueError("Compiled SNMP module does not match its selected symbols and collection bounds")
    return module
