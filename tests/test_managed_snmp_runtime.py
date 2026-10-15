"""Real native exporter against an in-process loopback SNMP fixture, never lab devices."""
import json
from pathlib import Path
import socket
import threading
from urllib.parse import urlencode
from urllib.request import ProxyHandler, build_opener
import pytest
import yaml
from icheck import managed_snmp


def tlv(tag, value):
    length = len(value)
    encoded = bytes([length]) if length < 128 else b"\x82" + length.to_bytes(2, "big")
    return bytes([tag]) + encoded + value


def take(data, offset=0):
    tag, length = data[offset], data[offset + 1]; start = offset + 2
    if length & 128:
        size = length & 127; length = int.from_bytes(data[start:start + size], "big"); start += size
    end = start + length
    return tag, data[start:end], end, data[offset:end]


@pytest.mark.skipif(not Path("/opt/icheck/bin/snmp_exporter").is_file(), reason="Native exporter not installed on this test host")
def test_native_exporter_uses_private_community_and_cleans_up(tmp_path, monkeypatch):
    module = tmp_path / "modules.yml"
    module.write_text(yaml.safe_dump({"modules": {"probe": {"get": ["1.3.6.1.2.1.1.3.0"],
        "metrics": [{"name": "sysUpTime", "oid": "1.3.6.1.2.1.1.3", "type": "gauge", "help": "Fixture uptime", "enum_values": {1: "one", 2: "two"}}],
        "timeout": "1s", "retries": 0}}}))
    monkeypatch.setenv("ICHECK_MANAGED_SNMP_MODULES_FILE", str(module))
    original = managed_snmp.trusted_file
    monkeypatch.setattr(managed_snmp, "trusted_file", lambda path, **kw: module if path == str(module) else original(path, **kw))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind(("127.0.0.1", 0)); sock.settimeout(.2)
    port = sock.getsockname()[1]; stop = threading.Event(); requests = []
    community = "synthetic-native-snmp-test"
    def agent():
        while not stop.is_set():
            try: wire, peer = sock.recvfrom(4096)
            except socket.timeout: continue
            except OSError: break
            _, message, _, _ = take(wire)
            _, _, pos, version = take(message)
            _, received, pos, auth = take(message, pos)
            requests.append(received)
            if received != community.encode(): continue
            _, pdu, _, _ = take(message, pos)
            _, _, pos, request_id = take(pdu)
            _, _, pos, _ = take(pdu, pos); _, _, pos, _ = take(pdu, pos)
            _, bindings, _, _ = take(pdu, pos); _, binding, _, _ = take(bindings)
            _, _, _, oid = take(binding)
            reply = tlv(0x30, version + auth + tlv(0xa2, request_id + tlv(2, b"\0") + tlv(2, b"\0")
                + tlv(0x30, tlv(0x30, oid + tlv(0x43, b"\x30\x39")))))
            sock.sendto(reply, peer)
    thread = threading.Thread(target=agent, daemon=True); thread.start()
    child_commands = []; temp_paths = []
    popen = managed_snmp.subprocess.Popen
    def start(command, **kwargs):
        assert all(community not in arg for arg in command)
        path = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--config.file=")))
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
        document = yaml.safe_load(path.read_text())
        assert document["auths"]["managed"]["community"] == community
        assert document["modules"]["probe"]["metrics"][0]["enum_values"] == {1: "one", 2: "two"}
        temp_paths.append(path); process = popen(command, **kwargs); child_commands.append(process); return process
    monkeypatch.setattr(managed_snmp.subprocess, "Popen", start)
    try:
        with managed_snmp.exporter({"community": community}) as url:
            query = urlencode({"target": f"127.0.0.1:{port}", "auth": "managed", "module": "probe"})
            assert community not in query
            with build_opener(ProxyHandler({})).open(url + "/snmp?" + query, timeout=5) as response:
                body = response.read().decode()
            assert "sysUpTime" in body and community not in body
        assert requests and all(r == community.encode() for r in requests)
        assert all(p.poll() is not None for p in child_commands)
        assert all(not p.exists() for p in temp_paths)
    finally:
        stop.set(); sock.close(); thread.join(timeout=1)


def test_untrusted_runtime_cannot_receive_a_secret(tmp_path):
    path = tmp_path / "unsafe.yml"; path.write_text("modules: {}"); path.chmod(0o666)
    with pytest.raises(ValueError, match="custody"):
        managed_snmp.trusted_file(path)


def test_module_cache_cannot_retain_credentials_and_reloads_atomic_catalog_changes(tmp_path, monkeypatch):
    source = tmp_path / "modules.yml"
    source.write_text("modules:\n  if_mib: {}\n")
    monkeypatch.setenv("ICHECK_MANAGED_SNMP_MODULES_FILE", str(source))
    monkeypatch.setattr(managed_snmp, "trusted_file", lambda path, **kw: Path(path))
    first = managed_snmp.module_document()
    first["auths"] = {"managed": {"community": "synthetic-cache-isolation"}}
    first["modules"]["if_mib"]["get"] = ["changed"]
    second = managed_snmp.module_document()
    assert second == {"modules": {"if_mib": {}}}
    # Runtime catalogs are replaced atomically, not edited in place. Same-size
    # in-place writes can share timestamps on coarse-resolution filesystems.
    replacement = tmp_path / "candidate.yml"
    replacement.write_text("modules:\n  system: {}\n")
    replacement.replace(source)
    assert managed_snmp.module_document() == {"modules": {"system": {}}}


@pytest.mark.skipif(not Path("/opt/icheck/bin/snmp_exporter").is_file(), reason="Native exporter not installed")
def test_native_identity_query_uses_four_get_scalars_not_interface_walks(monkeypatch):
    from icheck.collectors.snmp_exporter import collect_snmp_exporter
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0)); sock.settimeout(.2)
    port = sock.getsockname()[1]; stop = threading.Event(); requested_oids = []
    community = "synthetic-identity-only"
    def agent():
        while not stop.is_set():
            try: wire, peer = sock.recvfrom(8192)
            except socket.timeout: continue
            except OSError: break
            _, message, _, _ = take(wire)
            _, _, pos, version = take(message)
            _, received, pos, auth = take(message, pos)
            if received != community.encode(): continue
            tag, pdu, _, _ = take(message, pos)
            assert tag == 0xa0, "Identity verification must GET, never GETNEXT/GETBULK"
            _, _, pos, request_id = take(pdu)
            _, _, pos, _ = take(pdu, pos); _, _, pos, _ = take(pdu, pos)
            _, bindings, _, _ = take(pdu, pos)
            offset = 0; replies = []
            while offset < len(bindings):
                _, binding, offset, _ = take(bindings, offset)
                _, oid_value, _, oid = take(binding)
                requested_oids.append(oid_value)
                suffix = oid_value[-2]
                if suffix == 5: value = tlv(4, b"fixture-access")
                elif suffix == 3: value = tlv(0x43, b"\x30\x39")
                elif suffix == 2: value = tlv(6, b"\x2b\x06\x01\x04\x01\x01")
                else: value = tlv(4, b"Synthetic device description")
                replies.append(tlv(0x30, oid + value))
            reply = tlv(0x30, version + auth + tlv(0xa2, request_id + tlv(2, b"\0") + tlv(2, b"\0")
                + tlv(0x30, b"".join(replies))))
            sock.sendto(reply, peer)
    thread = threading.Thread(target=agent, daemon=True); thread.start()
    try:
        samples = collect_snmp_exporter({"artifact_name": "identity-fixture", "output_kinds": ["observation"],
            "target": {"exporter_url": "http://127.0.0.1:9116", "target": f"127.0.0.1:{port}"},
            "configuration": {"modules": ["if_mib"], "timeout_seconds": 5, "max_metrics": 100,
                "include_metric_prefixes": ["sysName", "sysDescr", "sysObjectID", "sysUpTime"]},
            "_runtime": {"credential": {"community": community}, "snmp_identity_preflight": True,
                "lease_seconds": 60, "exporter_allowed_hosts": ["127.0.0.1"], "snmp_allowed_targets": ["127.0.0.1"]}})
        assert len(requested_oids) == 4
        assert {oid[-2] for oid in requested_oids} == {1, 2, 3, 5}
        assert any(sample["payload"]["labels"].get("sysName") == "fixture-access" for sample in samples)
        assert community not in json.dumps(samples)
        assert all(sample["payload"]["modules"] == ["icheck_identity"] for sample in samples)
    finally:
        stop.set(); sock.close(); thread.join(timeout=1)
