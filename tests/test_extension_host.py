"""Real native processes and a loopback SSH simulator, not lab qualification."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import threading
from uuid import uuid4

import paramiko
import pytest
from fastapi import HTTPException
from sqlalchemy import select

from icheck.config import get_settings
from icheck.database import SessionLocal, set_session_namespace, DEFAULT_REGION_ID, DEFAULT_TENANT_ID
from icheck.extension_host import ExtensionHostError, NativeExtensionProcess, install_package
from icheck.extension_runtime import AuthorizedNetmikoTarget
from icheck.models import (Artifact, ArtifactKind, ArtifactVersion, ArtifactVersionStatus,
    AuditEvent, Device, DeviceConnection, ExtensionConfigurationBackup)
from icheck.services.control_plane_auth import development_principal
from icheck.services.extension_backups import store_configuration_backup, download_configuration_backup
from icheck.services.mcp_extensions import extension_documents
from icheck.services.tenancy import ensure_default_namespace
from test_mcp_extensions import SPEC, DEVICE


CONFIG = b"hostname simulated-switch\n! synthetic-private-config-body\n"


@contextmanager
def ssh_simulator(directory, *, legacy=False, authentication=None):
    """Tiny Cisco-like shell using real SSH transport and a pinned synthetic key."""
    key = paramiko.RSAKey.generate(2048)
    if legacy:
        from icheck.ssh_compatibility import transport_factory, LEGACY
        # Server advertises only the legacy wire algorithms, no modern fallback.
        factory = transport_factory(LEGACY)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    hosts = directory / "known_hosts"
    hosts.write_text(f"[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n")
    hosts.chmod(0o600)
    stopped = threading.Event()
    commands, transports = [], []

    class Server(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            if authentication is not None: authentication.append(username)
            return paramiko.AUTH_SUCCESSFUL if (username, password) == ("monitor", "synthetic-ssh-password") else paramiko.AUTH_FAILED
        def get_allowed_auths(self, username): return "password"
        def check_channel_request(self, kind, chanid): return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_pty_request(self, *args): return True
        def check_channel_shell_request(self, channel): return True

    def serve():
        while not stopped.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            transport = factory(conn) if legacy else paramiko.Transport(conn)
            if legacy:
                options = transport.get_security_options()
                options.kex = ("diffie-hellman-group14-sha1",)
                options.key_types = ("ssh-rsa",)
                options.ciphers = ("aes128-cbc",)
                options.digests = ("hmac-sha1",)
            transports.append(transport)
            try:
                transport.add_server_key(transport._key_info["ssh-rsa"](key=key.key) if legacy else key)
                transport.start_server(server=Server())
                channel = transport.accept(timeout=5)
                if channel is None: continue
                channel.settimeout(0.2)
                channel.sendall(b"simulated-switch#")
                pending = b""
                while not stopped.is_set():
                    try:
                        chunk = channel.recv(4096)
                    except socket.timeout:
                        continue
                    if not chunk: break
                    pending += chunk
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        command = line.decode().strip()
                        if command: commands.append(command)
                        body = ("Gi0/1 connected" if command == "show interfaces status" else
                            CONFIG.decode() if command == "show running-config" else "")
                        channel.sendall((command + "\r\n" + body + "\r\nsimulated-switch#").encode())
            except (EOFError, OSError, paramiko.SSHException):
                pass
            finally:
                transport.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, hosts, commands
    finally:
        stopped.set()
        listener.close()
        for transport in transports: transport.close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.fixture
def package(tmp_path):
    root = tmp_path / "packages"
    root.mkdir(mode=0o700)
    return install_package(root, str(uuid4()), SPEC)


def target(port, hosts, spec, tool, device_id, check=lambda: None):
    return AuthorizedNetmikoTarget(device_id, "127.0.0.1", port, spec.device_type,
        "monitor", "synthetic-ssh-password", str(hosts), tuple(tool.commands), check, timeout_seconds=5)


def test_native_install_discovery_immutable_files_and_no_inherited_secrets(package, monkeypatch):
    import subprocess
    actual_popen, launches = subprocess.Popen, []
    def record(*args, **kwargs):
        launches.append((args, kwargs))
        return actual_popen(*args, **kwargs)
    monkeypatch.setattr("icheck.extension_host.subprocess.Popen", record)
    # MCP stdout contains only the reviewed catalog, never environment values.
    monkeypatch.setenv("ICHECK_UNRELATED_SECRET", "do-not-inherit")
    result = NativeExtensionProcess().discover(package)
    assert [row["name"] for row in result["tools"]] == [row["name"] for row in SPEC["tools"]]
    assert "do-not-inherit" not in json.dumps(result)
    assert launches[0][1]["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    assert launches[0][1]["close_fds"] and launches[0][1]["start_new_session"]
    assert install_package(package.parent.parent, package.parent.name, SPEC) == package
    revised = deepcopy(SPEC)
    revised["description"] = "A different reviewed version"
    with pytest.raises(ExtensionHostError, match="differs"):
        install_package(package.parent.parent, package.parent.name, revised)
    package.chmod(0o600)
    package.write_text("raise RuntimeError('unreviewed executable')")
    with pytest.raises(ValueError, match="differs"):
        NativeExtensionProcess().discover(package)


def test_native_mcp_really_uses_netmiko_over_ssh_and_generated_parser(package, tmp_path):
    checks = []
    with ssh_simulator(tmp_path) as (port, hosts, commands):
        host = NativeExtensionProcess(timeout_seconds=30)
        result = host.call(package, "get_interface_status", {"device_id": DEVICE},
            resolve=lambda spec, tool, device_id: target(port, hosts, spec, tool, device_id, lambda: checks.append(True)),
            store_backup=lambda *_: pytest.fail("A read tool must not request backup custody"))
    assert result == {"interfaces": [{"name": "Gi0/1", "state": "connected"}]}
    assert "show interfaces status" in commands and "show running-config" not in commands
    assert len(checks) >= 4


def test_native_host_rechecks_revocation_and_hides_callback_exceptions(package, tmp_path):
    def revoked(): raise PermissionError("synthetic-private-revocation-detail")
    with ssh_simulator(tmp_path) as (port, hosts, commands):
        with pytest.raises(ExtensionHostError) as error:
            NativeExtensionProcess(timeout_seconds=10).call(package, "get_interface_status", {"device_id": DEVICE},
                resolve=lambda spec, tool, device_id: target(port, hosts, spec, tool, device_id, revoked), store_backup=None)
    assert "synthetic-private" not in str(error.value)
    assert not commands


def test_revocation_during_an_ssh_read_discards_evidence(package, tmp_path):
    with ssh_simulator(tmp_path) as (port, hosts, commands):
        def revalidate():
            if "show interfaces status" in commands:
                raise PermissionError("synthetic-revoked-during-read")
        with pytest.raises(ExtensionHostError) as error:
            NativeExtensionProcess(timeout_seconds=20).call(package, "get_interface_status", {"device_id": DEVICE},
                resolve=lambda spec, tool, device_id: target(port, hosts, spec, tool, device_id, revalidate), store_backup=None)
    assert "show interfaces status" in commands
    assert "synthetic-revoked" not in str(error.value)


def test_native_host_rejects_untrusted_ssh_host_key(package, tmp_path):
    with ssh_simulator(tmp_path) as (port, hosts, commands):
        wrong_key = paramiko.RSAKey.generate(2048)
        hosts.write_text(f"[127.0.0.1]:{port} {wrong_key.get_name()} {wrong_key.get_base64()}\n")
        with pytest.raises(ExtensionHostError):
            NativeExtensionProcess(timeout_seconds=20).call(package, "get_interface_status", {"device_id": DEVICE},
                resolve=lambda spec, tool, device_id: target(port, hosts, spec, tool, device_id), store_backup=None)
    assert not commands


def test_native_host_deadline_kills_process_before_acquisition(package, monkeypatch):
    import subprocess
    actual_popen, children = subprocess.Popen, []
    def record(*args, **kwargs):
        process = actual_popen(*args, **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr("icheck.extension_host.subprocess.Popen", record)
    # A normal Python startup is deliberately held before the trusted module runs.
    # This executable is a test-only launcher, never generated plugin content.
    launcher = package.parent.parent / "slow-python"
    launcher.write_text("#!/bin/sh\nexec /bin/sleep 30\n")
    launcher.chmod(0o700)
    with pytest.raises(ExtensionHostError, match="time limit"):
        NativeExtensionProcess(python_path=str(launcher), timeout_seconds=1).discover(package)
    assert children[0].returncode is not None
    with pytest.raises(ProcessLookupError): os.kill(children[0].pid, 0)


def test_generated_sandbox_can_share_native_host_process_group(monkeypatch):
    import subprocess
    from icheck.sandbox import HardenedProcessSandboxExecutor, execute_extension_tool
    actual_run, options = subprocess.run, []
    def record(*args, **kwargs):
        options.append(kwargs)
        return actual_run(*args, **kwargs)
    monkeypatch.setattr("icheck.sandbox.subprocess.run", record)
    executor = HardenedProcessSandboxExecutor(python_path="/usr/bin/python3", start_new_session=False)
    result = execute_extension_tool(SPEC["tools"][0]["source"], ["Gi0/1 connected"], {"device_id": DEVICE}, executor=executor)
    assert result == {"interfaces": [{"name": "Gi0/1", "state": "connected"}]}
    assert options[0]["start_new_session"] is False
    assert not options[0].get("pass_fds") and options[0].get("close_fds", True)


def test_backup_crosses_private_custody_only_is_encrypted_and_scoped(client, package, tmp_path, monkeypatch):
    key = tmp_path / "backup-key"
    key.write_bytes(os.urandom(32)); key.chmod(0o400)
    monkeypatch.setenv("ICHECK_DEVICE_MANAGED_SECRET_KEY_FILE", str(key)); get_settings.cache_clear()
    actor = development_principal()
    try:
        with ssh_simulator(tmp_path) as (port, hosts, commands), SessionLocal() as db:
            ensure_default_namespace(db)
            set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
            artifact = Artifact(id=str(uuid4()), name="native-extension", kind=ArtifactKind.TOOL, owner="fixture")
            definition, implementation, tests = extension_documents(SPEC)
            version = ArtifactVersion(id=str(uuid4()), artifact_id=artifact.id, version=1,
                status=ArtifactVersionStatus.VALIDATED, definition=definition, implementation=implementation,
                tests=tests, created_by="fixture")
            device = Device(id=DEVICE, name="ssh-simulator", kind="switch", management_ip="127.0.0.1", site="LAB")
            connection = DeviceConnection(id=str(uuid4()), device_id=device.id, protocol="ssh", adapter_type="ssh", port=port, created_by="fixture")
            db.add_all([artifact, device]); db.flush()
            db.add_all([version, connection]); db.commit()
            result = NativeExtensionProcess(timeout_seconds=30).call(package, "backup_configuration", {"device_id": DEVICE},
                resolve=lambda spec, tool, device_id: target(port, hosts, spec, tool, device_id),
                store_backup=lambda resolved, body: store_configuration_backup(db, actor,
                    version_id=version.id, connection_id=connection.id, tool_name="backup_configuration", target=resolved, body=body))
            db.commit(); db.expire_all()
            row = db.get(ExtensionConfigurationBackup, result["backup_id"])
            assert b"synthetic-private" not in row.encrypted_body
            assert "synthetic-private" not in json.dumps(result)
            assert "synthetic-private" not in json.dumps([event.details for event in db.scalars(select(AuditEvent))])
            body = download_configuration_backup(db, actor, row.id)
            assert body.strip() == CONFIG.strip()
            with pytest.raises(HTTPException) as denied:
                download_configuration_backup(db, replace(actor, authorization_scope={"device_ids": [str(uuid4())]}), row.id)
            assert denied.value.status_code == 404
            with pytest.raises(PermissionError):
                download_configuration_backup(db, replace(actor, principal_type="investigation_snapshot"), row.id)
            with pytest.raises(LookupError):
                download_configuration_backup(db, replace(actor, tenant_id=str(uuid4())), row.id)
            row.sha256 = "a" * 64
            db.flush()
            with pytest.raises(ValueError, match="custody"):
                download_configuration_backup(db, actor, row.id)
            db.rollback()
        response = client.get(f"/api/v1/capability-studio/configuration-backups/{result['backup_id']}/download")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["content-disposition"].startswith("attachment;")
        assert response.content.strip() == CONFIG.strip()
    finally:
        get_settings.cache_clear()
