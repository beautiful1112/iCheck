"""Native per-invocation MCP host. No database, inherited secrets or agent loop.

MCP uses stdin/stdout. A separate anonymous socket carries trusted authorization
and backup custody, inaccessible to the generated-code sandbox. Nothing from
that socket is forwarded to the model. The parent owns revocation and deadlines.
"""
import base64
from importlib.metadata import version
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from uuid import UUID

from .extension_runtime import (
    AuthorizedNetmikoTarget, ExtensionMCPServer, NetmikoReadBackend,
    load_extension_package,
)
from .extension_schemas import BACKUP_OUTPUT, DEVICE_INPUT
from .mcp_schemas import MCP_PROTOCOL_VERSION
from .sandbox import HardenedProcessSandboxExecutor
from .schema_validation import validate_instance

FRAME_LIMIT = 1_500_000
MCP_LIMIT = 262_144


class ExtensionHostError(ValueError):
    """Safe public failure: never include driver exceptions, output or credentials."""


def _private_directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ExtensionHostError("Extension package directory must be private and service-owned")


def install_package(root, version_id, spec):
    """Install immutable canonical files; activation/registration is a separate DB decision."""
    from .services.mcp_extensions import extension_documents
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root:
        raise ExtensionHostError("Extension package root must be an absolute non-symlink path")
    _private_directory(root)
    version_id = str(UUID(version_id))
    _, implementation, _ = extension_documents(spec)
    destination = root / version_id
    if destination.exists() or destination.is_symlink():
        _private_directory(destination)
        loaded = load_extension_package(destination / "server.py")
        if extension_documents(loaded)[1] != implementation:
            raise ExtensionHostError("Installed version differs from the reviewed package")
        return destination / "server.py"
    # Atomic directory rename means interrupted staging is never an installed version.
    with tempfile.TemporaryDirectory(prefix=".stage-", dir=root) as staging:
        stage = Path(staging)
        for name, body in implementation["files"].items():
            path = stage / name
            path.parent.mkdir(mode=0o700, exist_ok=True)
            with path.open("x", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), 0o400)
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
        load_extension_package(stage / "server.py")
        # root is writable only by the trusted service. Existing immutable versions
        # are not updated; a concurrent install must be checked on retry.
        try:
            os.rename(stage, destination)
        except OSError:
            raise ExtensionHostError("Extension installation raced; refresh and retry") from None
        for directory in (destination / "tools", destination, root):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    return destination / "server.py"


def _line(value):
    return (json.dumps(value, allow_nan=False, separators=(",", ":")) + "\n").encode()


class NativeExtensionProcess:
    def __init__(self, *, python_path=None, timeout_seconds=60):
        self.python_path = python_path or sys.executable
        self.timeout_seconds = timeout_seconds
        if not Path(self.python_path).is_absolute() or not 1 <= timeout_seconds <= 120:
            raise ValueError("Invalid native extension process limits")

    def discover(self, entrypoint):
        return self._run(entrypoint)

    def call(self, entrypoint, name, arguments, *, resolve, store_backup):
        validate_instance(arguments, DEVICE_INPUT, "extension arguments")
        UUID(arguments["device_id"])
        return self._run(entrypoint, name, arguments, resolve, store_backup)

    def _run(self, entrypoint, name=None, arguments=None, resolve=None, store_backup=None):
        spec = load_extension_package(entrypoint)
        tool = next((row for row in spec.tools if row.name == name), None)
        if name is not None and tool is None:
            raise ExtensionHostError("Unknown installed extension tool")
        expected_tools = ExtensionMCPServer(spec).tools()
        parent, child = socket.socketpair()
        process = None
        target = None
        stored_receipt = None
        authority_count = 0
        deadline = time.monotonic() + self.timeout_seconds
        try:
            process = subprocess.Popen(
                [self.python_path, "-I", "-B", "-m", "icheck.extension_host", str(entrypoint), str(child.fileno())],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                pass_fds=(child.fileno(),), close_fds=True, start_new_session=True,
                cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, bufsize=0)
            child.close()
            parent.settimeout(1)
            process.stdin.write(_line({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
                    "clientInfo": {"name": "icheck-native-host", "version": "1"}}}))
            buffers = {"mcp": b"", "authority": b""}
            awaiting = 1
            result = None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "mcp")
                selector.register(parent, selectors.EVENT_READ, "authority")
                while result is None:
                    if time.monotonic() >= deadline:
                        raise ExtensionHostError("Native extension exceeded its time limit")
                    if target is not None:
                        target.revalidate()
                    for key, _ in selector.select(min(0.25, max(0, deadline - time.monotonic()))):
                        channel = key.data
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            raise ExtensionHostError("Native extension stopped before completing its request")
                        buffers[channel] += chunk
                        limit = MCP_LIMIT if channel == "mcp" else FRAME_LIMIT
                        if len(buffers[channel]) > limit:
                            raise ExtensionHostError("Native extension exceeded its output limit")
                        while b"\n" in buffers[channel]:
                            raw, buffers[channel] = buffers[channel].split(b"\n", 1)
                            message = json.loads(raw)
                            if channel == "authority":
                                authority_count += 1
                                if tool is None or authority_count > 64 or not isinstance(message, dict):
                                    raise ExtensionHostError("Unexpected extension authority request")
                                operation = message.get("operation")
                                if operation == "resolve" and target is None and message == {
                                        "operation": "resolve", "tool": name, "device_id": arguments["device_id"]}:
                                    target = resolve(spec, tool, arguments["device_id"])
                                    if (not isinstance(target, AuthorizedNetmikoTarget)
                                            or target.device_id != arguments["device_id"]
                                            or target.device_type != spec.device_type
                                            or target.commands != tuple(tool.commands)):
                                        raise ExtensionHostError("Current target authorization is required")
                                    target.revalidate()
                                    payload = {field: getattr(target, field) for field in (
                                        "device_id", "host", "port", "device_type", "username", "password",
                                        "known_hosts", "commands", "timeout_seconds", "ssh_profile")}
                                elif operation == "revalidate" and target is not None and len(message) == 1:
                                    target.revalidate()
                                    payload = {}
                                elif (operation == "backup" and target is not None and tool.operation == "backup"
                                        and stored_receipt is None and set(message) == {"operation", "body"}):
                                    target.revalidate()
                                    body = base64.b64decode(message["body"], validate=True)
                                    if not 1 <= len(body) <= 1_000_000:
                                        raise ExtensionHostError("Backup exceeded its custody limit")
                                    stored_receipt = store_backup(target, body)
                                    validate_instance(stored_receipt, BACKUP_OUTPUT, "protected backup receipt")
                                    payload = stored_receipt
                                    del body
                                else:
                                    raise ExtensionHostError("Unexpected extension authority operation")
                                parent.sendall(_line({"result": payload}))
                                continue
                            if (not isinstance(message, dict) or message.get("jsonrpc") != "2.0"
                                    or message.get("id") != awaiting or "error" in message):
                                raise ExtensionHostError("Invalid native MCP response")
                            response = message.get("result", {})
                            if awaiting == 1:
                                if response.get("protocolVersion") != MCP_PROTOCOL_VERSION:
                                    raise ExtensionHostError("Native MCP version mismatch")
                                process.stdin.write(_line({"jsonrpc": "2.0", "method": "notifications/initialized"})
                                    + _line({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
                                awaiting = 2
                            elif awaiting == 2:
                                if response.get("tools") != expected_tools:
                                    raise ExtensionHostError("Installed MCP catalog differs from reviewed tools")
                                if tool is None:
                                    result = response
                                else:
                                    process.stdin.write(_line({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                        "params": {"name": name, "arguments": arguments}}))
                                    awaiting = 3
                            else:
                                if (target is None or response.get("isError") is not False
                                        or response.get("_meta") != {"icheck/evidence": "target-read"}):
                                    raise ExtensionHostError("Native extension call failed; check target, host keys and tool output")
                                result = response.get("structuredContent")
                                validate_instance(result, tool.output_schema, "native MCP output")
                                if tool.operation == "backup" and (stored_receipt is None or result != stored_receipt):
                                    raise ExtensionHostError("Native MCP backup receipt mismatch")
                                target.revalidate()
                return result
        except ExtensionHostError:
            raise
        except Exception:
            raise ExtensionHostError("Native extension failed; no credential or device output is exposed") from None
        finally:
            parent.close()
            child.close()
            if process is not None:
                # Also terminate a surviving sandbox child; timeout/cancellation
                # cannot leave a device acquisition running in the background.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                process.stdin.close()
                process.stdout.close()


class _AuthorityChannel:
    def __init__(self, descriptor):
        self.socket = socket.socket(fileno=descriptor)
        self.stream = self.socket.makefile("rb")

    def request(self, **document):
        self.socket.sendall(_line(document))
        raw = self.stream.readline(FRAME_LIMIT + 1)
        if len(raw) > FRAME_LIMIT or not raw.endswith(b"\n"):
            raise ExtensionHostError("Invalid native authority response")
        return json.loads(raw)["result"]

    def resolve(self, spec, tool, device_id):
        payload = self.request(operation="resolve", tool=tool.name, device_id=device_id)
        payload["commands"] = tuple(payload["commands"])
        return AuthorizedNetmikoTarget(**payload, revalidate=lambda: self.request(operation="revalidate"))

    def backup(self, target, body):
        return self.request(operation="backup", body=base64.b64encode(body).decode("ascii"))


def main():
    # Trusted acquisition is bounded independently of the generated-code sandbox.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    os.umask(0o077)
    try:
        spec = load_extension_package(sys.argv[1])
        if version("netmiko") != "4.8.0":
            return 1
        from netmiko import ConnectHandler
        if not callable(ConnectHandler):
            return 1
        authority = _AuthorityChannel(int(sys.argv[2]))
        server = ExtensionMCPServer(spec, backend=NetmikoReadBackend(authority.resolve, authority.backup),
            sandbox=HardenedProcessSandboxExecutor(python_path="/usr/bin/python3", start_new_session=False))
        while raw := sys.stdin.buffer.readline(MCP_LIMIT + 1):
            if len(raw) > MCP_LIMIT or not raw.endswith(b"\n"):
                return 1
            result = server.dispatch(json.loads(raw))
            if result is not None:
                sys.stdout.buffer.write(_line(result))
                sys.stdout.buffer.flush()
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
