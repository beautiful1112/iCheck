"""MCP dispatch and trusted acquisition for executable Studio extensions.

Generated source runs only in the existing kernel sandbox. This module is the
native host boundary, not a second agent loop. Deployment supplies current target
authorization, credential resolution and protected backup storage independently.
"""
from dataclasses import dataclass, field
from importlib.metadata import version
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys
from typing import Callable
from uuid import UUID

from .extension_schemas import BACKUP_OUTPUT, DEVICE_INPUT, GeneratedExtensionSpec
from .mcp_schemas import MCP_PROTOCOL_VERSION
from .sandbox import execute_extension_tool
from .schema_validation import validate_instance


@dataclass(frozen=True)
class AuthorizedNetmikoTarget:
    """Only a trusted resolver may construct this per-call authority snapshot."""
    device_id: str
    host: str
    port: int
    device_type: str
    username: str = field(repr=False)
    password: str = field(repr=False)
    known_hosts: str
    commands: tuple[str, ...]
    revalidate: Callable[[], None] = field(repr=False)
    timeout_seconds: int = 20
    ssh_profile: str = "modern"


class NetmikoReadBackend:
    def __init__(self, resolve, store_backup):
        self.resolve, self.store_backup = resolve, store_backup

    def acquire(self, spec, tool, device_id):
        target = self.resolve(spec, tool, device_id)
        if not isinstance(target, AuthorizedNetmikoTarget) or target.device_id != device_id:
            raise ValueError("Current target authorization is required")
        if target.device_type != spec.device_type or tuple(tool.commands) != target.commands:
            raise ValueError("Reviewed target commands or driver changed")
        ipaddress.ip_address(target.host)  # Native target resolution never follows generated hostnames.
        if not 1 <= target.port <= 65535 or not 1 <= target.timeout_seconds <= 60:
            raise ValueError("Invalid target limits")
        host_keys = Path(target.known_hosts)
        if not host_keys.is_absolute() or not host_keys.is_file():
            raise ValueError("Verified SSH host-key custody is required")
        info = host_keys.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}
                or info.st_mode & 0o022):
            raise ValueError("SSH host-key file custody is unsafe")
        target.revalidate()
        if version("netmiko") != "4.8.0":
            raise ValueError("The reviewed Netmiko dependency is unavailable")
        from .ssh_compatibility import netmiko_connection
        readings = []
        # No enable/config methods, SSH agent, user config, session log or implicit key discovery.
        with netmiko_connection(profile=target.ssh_profile, device_type=target.device_type, host=target.host, port=target.port,
                username=target.username, password=target.password, ssh_strict=True,
                system_host_keys=False, alt_host_keys=True, alt_key_file=target.known_hosts,
                use_keys=False, allow_agent=False, ssh_config_file=None, session_log=None,
                allow_auto_change=False, conn_timeout=target.timeout_seconds,
                auth_timeout=target.timeout_seconds, banner_timeout=target.timeout_seconds,
                blocking_timeout=target.timeout_seconds, session_timeout=target.timeout_seconds) as connection:
            for command in tool.commands:
                target.revalidate()
                output = connection.send_command(command, read_timeout=target.timeout_seconds,
                    use_textfsm=False, use_genie=False, use_ttp=False)
                target.revalidate()
                if not isinstance(output, str) or not output or len(output.encode()) > 1_000_000:
                    raise ValueError("Device read was empty or exceeded its output limit")
                if tool.operation == "backup":
                    # Raw configuration never crosses into generated source, an MCP response or a model prompt.
                    receipt = self.store_backup(target, output.encode())
                    validate_instance(receipt, BACKUP_OUTPUT, "protected backup receipt")
                    readings.append(receipt)
                else:
                    if sum(len(item.encode()) for item in readings) + len(output.encode()) > 1_000_000:
                        raise ValueError("Combined device reads exceeded the acquisition limit")
                    readings.append(output)
        target.revalidate()
        return readings


class ExtensionMCPServer:
    def __init__(self, spec, *, backend=None, sandbox=None, fixture=False):
        self.spec = GeneratedExtensionSpec.model_validate(spec)
        self.backend, self.sandbox, self.fixture = backend, sandbox, fixture
        self.initialized = False

    def tools(self):
        return [{"name": tool.name, "description": tool.description, "inputSchema": DEVICE_INPUT,
            "outputSchema": tool.output_schema, "annotations": {"readOnlyHint": tool.operation != "backup",
                "destructiveHint": False, "openWorldHint": True}} for tool in self.spec.tools]

    def call(self, name, arguments):
        tool = next((item for item in self.spec.tools if item.name == name), None)
        if tool is None:
            raise ValueError("Unknown extension tool")
        validate_instance(arguments, DEVICE_INPUT, "extension arguments")
        UUID(arguments["device_id"])
        if self.fixture:
            readings = tool.fixtures[0].readings
        elif self.backend is None:
            raise ValueError("Extension is not installed with current target authorization")
        else:
            readings = self.backend.acquire(self.spec, tool, arguments["device_id"])
        if tool.operation == "backup":
            if len(readings) != 1:
                raise ValueError("Backup tools require a protected receipt")
            validate_instance(readings[0], BACKUP_OUTPUT, "protected backup receipt")
        result = execute_extension_tool(tool.source, readings, arguments, executor=self.sandbox)
        validate_instance(result, tool.output_schema, "extension output")
        if tool.operation == "backup" and result != readings[0]:
            raise ValueError("Generated code cannot alter a protected backup receipt")
        from .services.collectors import assert_no_inline_secrets
        assert_no_inline_secrets(result, "extension result")
        return result

    def dispatch(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}}
        identifier = message.get("id")
        method, params = message.get("method"), message.get("params", {})
        if "id" not in message:
            return None
        response = {"jsonrpc": "2.0", "id": identifier}
        if not isinstance(params, dict):
            return {**response, "error": {"code": -32602, "message": "Invalid params"}}
        if method == "initialize":
            self.initialized = True
            result = {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.spec.artifact_name, "version": "1"}}
        elif method == "ping":
            result = {}
        elif not self.initialized:
            return {**response, "error": {"code": -32000, "message": "Initialize the extension first"}}
        elif method == "tools/list":
            if params.get("cursor"):
                return {**response, "error": {"code": -32602, "message": "Unknown cursor"}}
            result = {"tools": self.tools()}
        elif method == "tools/call":
            try:
                output = self.call(params.get("name"), params.get("arguments", {}))
                result = {"structuredContent": output, "content": [{"type": "text", "text": json.dumps(output)}],
                    "isError": False, "_meta": {"icheck/evidence": "fixture" if self.fixture else "target-read"}}
            except Exception:
                # Connection exceptions and device output can contain secrets; never echo them onto MCP.
                result = {"isError": True, "content": [{"type": "text", "text": "Extension call failed. Check installation, authorization, host keys and declared output."}]}
        else:
            return {**response, "error": {"code": -32601, "message": "Method not found"}}
        return {**response, "result": result}


def load_extension_package(entrypoint):
    """Read canonical reviewed files; never import a generated entry point."""
    manifest = Path(entrypoint).with_name("extension.json")
    if manifest.stat().st_size > 262_144:
        raise ValueError("Extension manifest exceeds its package limit")
    spec = json.loads(manifest.read_text())
    from .services.mcp_extensions import extension_documents
    _, implementation, _ = extension_documents(spec)
    for name, expected in implementation["files"].items():
        path = manifest.parent / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 262_144 or path.read_bytes().decode("utf-8") != expected:
            raise ValueError("Executable package differs from its reviewed files")
    return GeneratedExtensionSpec.model_validate(spec)


def package_main(entrypoint):
    """Executable package discovery/fixture runner. Live calls require the managed host."""
    if sys.argv[1:] not in ([], ["--fixture"]):
        raise SystemExit("Usage: server.py [--fixture]")
    spec = load_extension_package(entrypoint)
    server = ExtensionMCPServer(spec, fixture=sys.argv[1:] == ["--fixture"])
    while raw := sys.stdin.buffer.readline(256_001):
        if len(raw) > 256_000 or not raw.endswith(b"\n"):
            raise SystemExit("MCP request exceeds framing limit")
        try:
            result = server.dispatch(json.loads(raw))
        except (ValueError, TypeError):
            result = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Invalid JSON"}}
        if result is not None:
            print(json.dumps(result, allow_nan=False), flush=True)
