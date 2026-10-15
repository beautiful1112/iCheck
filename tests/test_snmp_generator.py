"""One focused native SNMP path; real MIB/compiler tests are explicitly opt-in."""
from copy import deepcopy
import hashlib
import fcntl
import json
import os
from pathlib import Path
import sys

import pytest
import yaml

from icheck import snmp_generator as compiler
from icheck.snmp_generator import GeneratorRuntime, SNMPGeneratorRequest, compile_module, resolve_profile, validate_compiled
from icheck.snmp_module_install import install_module

MIB = "TEST-MIB DEFINITIONS ::= BEGIN\nEND\n"
OID = "1.3.6.1.4.1.424242.1"


class Runner:
    def __init__(self): self.calls = []; self.fail_dry_run = False

    def __call__(self, command, *, cwd, timeout=120):
        self.calls.append(command)
        assert "shell" not in command
        assert Path(cwd).stat().st_mode & 0o077 == 0
        if command[-1] == "--version": return b"snmp_exporter, version 0.30.1\n"
        if "--dry-run" in command:
            if self.fail_dry_run: raise ValueError("Native validation failed")
            path = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--config.file=")))
            value = yaml.safe_load(path.read_bytes())
            assert set(value) == {"modules", "auths"}
            assert value["auths"] == {"icheck_validation": {"version": 2, "community": "unused-dry-run"}}
            assert path.stat().st_mode & 0o077 == 0
            return b""
        source = yaml.safe_load(Path(command[command.index("-g") + 1]).read_bytes())
        assert set(source) == {"modules"}
        name, spec = next(iter(source["modules"].items()))
        metric = spec["walk"][0].split("::")[1]
        compiled = {"walk": [OID], "metrics": [{"name": metric, "oid": OID, "type": "gauge", "help": "Unit fixture",
            "enum_values": {1: "up", 2: "down"}}], **{k:spec[k] for k in ("max_repetitions", "retries", "timeout")}}
        Path(command[command.index("-o") + 1]).write_text(yaml.safe_dump({"modules": {name: compiled}}))
        return b""


@pytest.fixture
def runtime(tmp_path):
    binary = tmp_path / "generator"
    binary.write_bytes(b"fixture binary, never executed"); binary.chmod(0o700)
    return GeneratorRuntime(binary, binary, "0.30.1", hashlib.sha256(binary.read_bytes()).hexdigest())


def candidate(runtime, runner=None, symbol="TEST-MIB::metric"):
    return compile_module(SNMPGeneratorRequest(symbols=[symbol]), runtime=runtime,
        mib_documents=[MIB], run=runner or Runner())


def test_symbolic_profiles_disclose_unsupported_metrics_without_inventing_oids():
    selected = resolve_profile("standard-network", ["uptime", "cpu_utilization", "interface_traffic"])
    assert selected["unsupported_metrics"] == ["cpu_utilization"]
    assert selected["symbols"] == ["SNMPv2-MIB::sysUpTime", "IF-MIB::ifHCInOctets", "IF-MIB::ifHCOutOctets"]
    assert resolve_profile("cisco-cpu", ["cpu_utilization"])["symbols"][0] == "CISCO-PROCESS-MIB::cpmCPUTotal5secRev"


@pytest.mark.parametrize("symbols", [[OID], ["metric"], ["TEST-MIB::metric;whoami"], ["TEST-MIB::metric"]*2])
def test_models_cannot_supply_numeric_oids_commands_or_duplicate_symbols(symbols):
    with pytest.raises(ValueError): SNMPGeneratorRequest(symbols=symbols)


def test_compile_binds_binary_mibs_symbols_and_keeps_enum_integer_keys(runtime):
    runner = Runner(); result = candidate(runtime, runner)
    assert result == candidate(runtime)
    module = validate_compiled(result)
    assert module["metrics"][0]["enum_values"] == {1:"up", 2:"down"}
    assert result["expected_metrics"] == [{"name":"metric", "oid":OID, "type":"gauge"}]
    assert not result["live_target_tested"] and not result["continuous_collection_enabled"]
    assert "--version" not in runner.calls[1]  # generator itself has no such flag
    assert not any("community" in x for x in runner.calls[1])
    assert "auths" not in result["module_yaml"]
    assert candidate(runtime, symbol="TEST-MIB::other")["module_name"] != result["module_name"]


def test_wrong_binary_mib_family_duplicate_bundle_or_exporter_version_fail(runtime):
    wrong = GeneratorRuntime(runtime.generator, runtime.exporter, runtime.version, "0"*64)
    with pytest.raises(ValueError, match="manifest"): candidate(wrong)
    with pytest.raises(ValueError, match="source MIB"): candidate(runtime, symbol="OTHER-MIB::metric")
    with pytest.raises(ValueError, match="duplicate module"):
        compile_module(SNMPGeneratorRequest(symbols=["TEST-MIB::metric"]),runtime=runtime,mib_documents=[MIB,MIB],run=Runner())
    def wrong_version(*args, **kwargs): return b"snmp_exporter, version 0.29.0\n"
    with pytest.raises(ValueError, match="version"):
        compile_module(SNMPGeneratorRequest(symbols=["TEST-MIB::metric"]),runtime=runtime,mib_documents=[MIB],run=wrong_version)


def test_native_exporter_parser_failure_cannot_be_called_compiled(runtime):
    runner = Runner(); runner.fail_dry_run = True
    with pytest.raises(ValueError, match="Native validation"): candidate(runtime, runner)


@pytest.mark.parametrize("encoded", [b"a: 1\na: 2", b"a: &x [1]\nb: *x", b"!!python/object:os.system {}", b"["*33+b"0"+b"]"*33])
def test_yaml_rejects_duplicate_keys_aliases_unsafe_tags_and_excessive_nesting(encoded):
    with pytest.raises(ValueError): compiler.load_yaml(encoded)


def test_candidate_rejects_mutation_broad_walk_or_live_success_claim(runtime):
    original = candidate(runtime)
    changed = deepcopy(original); changed["module_yaml"] += "\n# changed\n"
    with pytest.raises(ValueError, match="digest"): validate_compiled(changed)
    changed = deepcopy(original); changed["continuous_collection_enabled"] = True
    with pytest.raises(ValueError, match="contract"): validate_compiled(changed)
    changed = deepcopy(original)
    module = yaml.safe_load(changed["module_yaml"]); module["walk"] = ["1.3.6.1"]
    changed["module_yaml"] = yaml.safe_dump(module)
    changed["module_sha256"] = hashlib.sha256(changed["module_yaml"].encode()).hexdigest()
    with pytest.raises(ValueError, match="scope"): validate_compiled(changed)


def _catalog(tmp_path):
    path = tmp_path / "modules.yml"
    path.write_text(yaml.safe_dump({"modules": {"system": {"get": ["1.3.6.1.2.1.1.3.0"],
        "metrics": [{"name":"sysUpTime", "oid":"1.3.6.1.2.1.1.3", "type":"gauge", "help":"System uptime"}]}}}))
    path.chmod(0o444)
    return path


def test_install_requires_exact_preview_and_confirmation_preserves_builtin_and_versions(tmp_path, runtime, monkeypatch):
    from icheck import managed_snmp
    path = _catalog(tmp_path); initial = path.read_bytes(); first = candidate(runtime)
    expected = hashlib.sha256(initial).hexdigest()
    monkeypatch.setenv("ICHECK_MANAGED_SNMP_MODULES_FILE",str(path))
    monkeypatch.setattr(managed_snmp,"trusted_file",lambda p,**kw:Path(p))
    assert set(managed_snmp.module_document()["modules"]) == {"system"}
    calls = []
    def verify(modules, *, exporter): calls.append(deepcopy(modules))
    args = {"catalog":path,"exporter":runtime.exporter,"expected_catalog_sha256":expected,"verify":verify}
    preview = install_module(first, **args)
    assert not preview["installed"] and path.read_bytes() == initial
    installed = install_module(first, confirm=True, **args)
    assert installed["changed"] and installed["installed"]
    document = yaml.safe_load(path.read_bytes())
    assert document["modules"]["system"] == yaml.safe_load(initial)["modules"]["system"]
    assert document["modules"][first["module_name"]]["metrics"][0]["enum_values"] == {1:"up",2:"down"}
    assert path.stat().st_mode & 0o777 == 0o444
    assert set(managed_snmp.module_document()["modules"]) == {"system",first["module_name"]}
    with pytest.raises(ValueError, match="changed after preview"): install_module(first, confirm=True, **args)
    args["expected_catalog_sha256"] = installed["catalog_sha256"]
    assert install_module(first, confirm=True, **args)["changed"] is False
    second = candidate(runtime, symbol="TEST-MIB::other")
    install_module(second, confirm=True, **args)
    assert {"system",first["module_name"],second["module_name"]} == set(yaml.safe_load(path.read_bytes())["modules"])
    assert not installed["continuous_collection_enabled"]
    assert len(calls) == 4


def test_installer_validation_failure_catalog_race_and_name_collision_leave_original(tmp_path, runtime):
    path = _catalog(tmp_path); initial = path.read_bytes(); first = candidate(runtime)
    args = {"catalog":path,"exporter":runtime.exporter,"expected_catalog_sha256":hashlib.sha256(initial).hexdigest(),"confirm":True}
    def fail(*args, **kwargs): raise ValueError("Native parser rejected candidate")
    with pytest.raises(ValueError, match="parser"): install_module(first,verify=fail,**args)
    assert path.read_bytes() == initial
    def race(*args, **kwargs): path.chmod(0o600); path.write_bytes(initial+b"\n# raced\n")
    with pytest.raises(ValueError, match="during native validation"): install_module(first,verify=race,**args)
    assert path.read_bytes() == initial+b"\n# raced\n"
    altered=yaml.safe_load(initial); altered["modules"][first["module_name"]]={"walk":["1"]}
    path.write_text(yaml.safe_dump(altered)); args["expected_catalog_sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="immutable"): install_module(first,verify=lambda *a,**k:None,**args)
    assert yaml.safe_load(path.read_bytes()) == altered


def test_native_command_timeout_and_failure_are_redacted_and_cleaned(tmp_path):
    with pytest.raises(ValueError,match="deadline"):
        compiler._command([sys.executable,"-c","import time; time.sleep(30)"],cwd=tmp_path,timeout=.05)
    with pytest.raises(ValueError) as error:
        compiler._command([sys.executable,"-c","import sys; print('private-mib-data',file=sys.stderr); sys.exit(1)"],cwd=tmp_path)
    assert "private-mib-data" not in str(error.value)


def test_production_manifest_rejects_user_writable_runtime_custody(tmp_path):
    manifest = tmp_path / "generator.json"
    manifest.write_text("{}")
    with pytest.raises(ValueError,match="custody"):
        GeneratorRuntime.from_manifest(manifest)


def test_catalog_symlinks_cannot_redirect_an_install(tmp_path, runtime):
    original = _catalog(tmp_path)
    path = tmp_path / "link.yml"; path.symlink_to(original)
    before = original.read_bytes()
    with pytest.raises(OSError):
        install_module(candidate(runtime),catalog=path,exporter=runtime.exporter,
            expected_catalog_sha256=hashlib.sha256(before).hexdigest(),confirm=True,verify=lambda *a,**k:None)
    assert original.read_bytes() == before


def test_concurrent_install_returns_busy_instead_of_waiting_unbounded(tmp_path, runtime):
    path = _catalog(tmp_path); before = path.read_bytes()
    with (tmp_path/".modules.lock").open("wb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        with pytest.raises(ValueError,match="already in progress"):
            install_module(candidate(runtime),catalog=path,exporter=runtime.exporter,
                expected_catalog_sha256=hashlib.sha256(before).hexdigest(),confirm=True,verify=lambda *a,**k:None)
    assert path.read_bytes() == before


@pytest.mark.parametrize("profile,intents,expected", [
    ("standard-network",["uptime","interface_traffic","interface_status"],{"sysUpTime","ifHCInOctets","ifHCOutOctets","ifAdminStatus","ifOperStatus"}),
    ("cisco-cpu",["cpu_utilization"],{"cpmCPUTotal5secRev","cpmCPUTotal1minRev","cpmCPUTotal5minRev"}),
])
def test_real_standard_vendor_mibs_generate_and_install_private_catalog(tmp_path, profile, intents, expected):
    binary = os.environ.get("ICHECK_SNMP_TEST_GENERATOR_BINARY")
    mibs = os.environ.get("ICHECK_SNMP_TEST_MIB_DIRECTORY")
    if not binary or not mibs: pytest.skip("Requires actual native generator and real MIB dependency bundle")
    binary = Path(binary)
    runtime = GeneratorRuntime(binary,Path('/opt/icheck/bin/snmp_exporter'),"0.30.1",hashlib.sha256(binary.read_bytes()).hexdigest())
    sources = [p.read_text() for p in sorted(Path(mibs).iterdir()) if p.is_file()]
    selected = resolve_profile(profile,intents)
    result = compile_module(SNMPGeneratorRequest(symbols=selected["symbols"]),runtime=runtime,mib_documents=sources)
    assert {metric["name"] for metric in result["expected_metrics"]} == expected
    path = _catalog(tmp_path); original = path.read_bytes()
    installed = install_module(result,catalog=path,exporter=runtime.exporter,
        expected_catalog_sha256=hashlib.sha256(original).hexdigest(),confirm=True)
    assert installed["installed"] and not installed["continuous_collection_enabled"]
    installed_document = yaml.safe_load(path.read_bytes())
    assert installed_document["modules"]["system"] == yaml.safe_load(original)["modules"]["system"]
    assert installed_document["modules"][result["module_name"]] == validate_compiled(result)
    # A MIB dependency failure is not converted to a fake OID or canned module.
    stripped = [text for text in sources if "SNMPv2-SMI DEFINITIONS" not in text]
    with pytest.raises(ValueError,match="Native SNMP command failed"):
        compile_module(SNMPGeneratorRequest(symbols=selected["symbols"]),runtime=runtime,mib_documents=stripped)


def test_real_compiled_installed_uptime_module_collects_with_native_exporter(tmp_path, monkeypatch):
    import socket
    import threading
    from urllib.parse import urlencode
    from urllib.request import build_opener, ProxyHandler
    from prometheus_client.parser import text_string_to_metric_families
    from icheck import managed_snmp
    from test_managed_snmp_runtime import take, tlv
    binary = os.environ.get("ICHECK_SNMP_TEST_GENERATOR_BINARY")
    directory = os.environ.get("ICHECK_SNMP_TEST_MIB_DIRECTORY")
    if not binary or not directory: pytest.skip("Requires native generator and real MIB dependency bundle")
    binary = Path(binary)
    runtime = GeneratorRuntime(binary,Path('/opt/icheck/bin/snmp_exporter'),"0.30.1",hashlib.sha256(binary.read_bytes()).hexdigest())
    result = compile_module(SNMPGeneratorRequest(symbols=["SNMPv2-MIB::sysUpTime"]),runtime=runtime,
        mib_documents=[p.read_text() for p in sorted(Path(directory).iterdir()) if p.is_file()])
    catalog = _catalog(tmp_path)
    install_module(result,catalog=catalog,exporter=runtime.exporter,
        expected_catalog_sha256=hashlib.sha256(catalog.read_bytes()).hexdigest(),confirm=True)
    monkeypatch.setenv("ICHECK_MANAGED_SNMP_MODULES_FILE",str(catalog))
    trusted = managed_snmp.trusted_file
    monkeypatch.setattr(managed_snmp,"trusted_file",lambda p,**kw:catalog if str(p)==str(catalog) else trusted(p,**kw))
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.bind(("127.0.0.1",0)); sock.settimeout(.2)
    port = sock.getsockname()[1]; stop = threading.Event(); received = []
    community = "synthetic-compiled-module-test"
    def agent():
        while not stop.is_set():
            try: wire,peer = sock.recvfrom(4096)
            except socket.timeout: continue
            except OSError: break
            _,message,_,_ = take(wire)
            _,_,position,version = take(message)
            _,auth_value,position,auth = take(message,position)
            if auth_value != community.encode(): continue
            tag,pdu,_,_ = take(message,position)
            received.append(tag)
            _,_,position,request_id = take(pdu)
            _,_,position,_ = take(pdu,position); _,_,position,_ = take(pdu,position)
            _,bindings,_,_ = take(pdu,position); _,binding,_,_ = take(bindings)
            _,_,_,oid = take(binding)
            sock.sendto(tlv(0x30,version+auth+tlv(0xa2,request_id+tlv(2,b"\0")+tlv(2,b"\0")
                +tlv(0x30,tlv(0x30,oid+tlv(0x43,b"\x30\x39"))))),peer)
    thread = threading.Thread(target=agent,daemon=True); thread.start()
    try:
        with managed_snmp.exporter({"community":community},requested_modules=[result["module_name"]]) as url:
            query = urlencode({"target":f"127.0.0.1:{port}","auth":"managed","module":result["module_name"]})
            with build_opener(ProxyHandler({})).open(url+"/snmp?"+query,timeout=5) as response:
                body = response.read(1_000_001).decode()
            assert community not in body and community not in query
            samples = [s for family in text_string_to_metric_families(body) for s in family.samples if s.name=="sysUpTime"]
            # The native exporter preserves TimeTicks as hundredths of a
            # second; a dashboard must explicitly divide this metric by 100.
            assert len(samples)==1 and samples[0].value==12345
        assert received and set(received)=={0xa0}  # GET only, no broad walk
    finally:
        stop.set(); sock.close(); thread.join(timeout=1)
