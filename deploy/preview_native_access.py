"""Scoped, native first-admin provisioning for Engineering Preview v0.1.

Copy this reviewed helper into root-owned, non-writable ancestry before use.
No password is accepted. Secrets are generated locally and never printed.
The operator explicitly chooses HTTPS addresses and finite collection networks.
Existing credentials/configuration are not replaced by replaying provisioning.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import sys
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ENV = Path("/etc/icheck/control-plane.env")
ACCESS = Path("/var/lib/icheck-preview-access")
KEY = re.compile(r"ICHECK_[A-Z0-9_]+\Z")
SAFE_PYTHON_KEYS = {"PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"}
PUBLIC_CA = Path("/etc/icheck-preview-ingress/preview-ca.pem")


def public_origins(addresses: list[str]) -> str:
    if len(addresses) > 8:
        raise ValueError("Too many preview HTTPS addresses")
    hosts = ["127.0.0.1", "localhost"]
    for value in addresses:
        address = ipaddress.IPv4Address(value)
        if address.is_unspecified or address.is_multicast or address.is_reserved:
            raise ValueError("Preview HTTPS requires explicit unicast IPv4 addresses")
        if str(address) not in hosts:
            hosts.append(str(address))
    return ",".join(f"https://{host}:8443" for host in hosts)


def trusted(path: Path) -> None:
    for item in (path, *path.parents):
        info = item.lstat()
        if item.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Unsafe deployment path")


def parse_environment(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or (not KEY.fullmatch(key) and key not in SAFE_PYTHON_KEYS) or key in result:
            raise ValueError("Unsupported or duplicate environment entry")
        if key in SAFE_PYTHON_KEYS and value != "1":
            raise ValueError("Unsafe Python environment flag")
        if any(ord(char) < 32 for char in value) or value.startswith(("'", '"')):
            raise ValueError("Unsupported environment quoting")
        result[key] = value
    return result


def render_environment(values: dict[str, str]) -> bytes:
    result = "".join(f"{key}={value}\n" for key, value in values.items())
    assert parse_environment(result) == values
    return result.encode("utf-8")


def atomic_environment(values: dict[str, str]) -> None:
    trusted(ENV)
    info = ENV.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o007:
        raise ValueError("Unsafe API environment file")
    temporary = ENV.parent / (".preview-api-" + secrets.token_hex(12))
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchown(handle.fileno(), info.st_uid, info.st_gid)
            handle.write(render_environment(values))
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
        os.replace(temporary, ENV)
        directory = os.open(ENV.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_api(addresses: list[str] | None = None) -> dict:
    origins = public_origins(addresses or [])
    trusted(ENV)
    values = parse_environment(ENV.read_text())
    for key, expected in {
        "ICHECK_ENVIRONMENT": "production",
        "ICHECK_CONTROL_PLANE_AUTH_MODE": "required",
        "ICHECK_CONTROL_PLANE_SESSION_COOKIE_SECURE": "true",
        "ICHECK_WORKER_MTLS_MODE": "required",
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "ICHECK_CHECKPOINT_SETUP_MODE": "verify",
        "ICHECK_REQUIRE_GOVERNED_CHANGE_CONTRACTS": "true",
    }.items():
        if values.get(key) != expected:
            raise ValueError("Preview security prerequisite is not configured")
    if ACCESS.exists():
        raise ValueError("First-admin custody already exists; inspect before retrying")
    for key in ("ICHECK_ENABLE_REVIEWED_CHANGE_EXECUTION", "ICHECK_ENABLE_REVIEWED_ROLLBACK_EXECUTION",
                "ICHECK_ENABLE_MCP_WRITE_DISPOSITION_CUSTODY", "ICHECK_ENABLE_REVIEWED_SOURCE_REPLACEMENT"):
        if values.get(key, "false") != "false":
            raise ValueError("Native preview provisioning requires infrastructure write features disabled")
    values["ICHECK_CONTROL_PLANE_LOCAL_BROWSER_LOGIN_ENABLED"] = "false"
    values["ICHECK_CONTROL_PLANE_PASSWORD_LOGIN_ENABLED"] = "true"
    values["ICHECK_CORS_ORIGINS"] = origins
    for key in ("ICHECK_CONTROL_PLANE_BOOTSTRAP_TOKEN", "ICHECK_COLLECTOR_REGISTRATION_TOKEN", "ICHECK_AGENT_REGISTRATION_TOKEN"):
        if not values.get(key):
            values[key] = secrets.token_urlsafe(48)
        if len(values[key]) < 32 or any(marker in values[key].lower() for marker in ("replace", "changeme", "change-me", "placeholder")):
            raise ValueError("Authority tokens must not be template placeholders or short values")
    if len({values[key] for key in ("ICHECK_CONTROL_PLANE_BOOTSTRAP_TOKEN", "ICHECK_COLLECTOR_REGISTRATION_TOKEN", "ICHECK_AGENT_REGISTRATION_TOKEN")}) != 3:
        raise ValueError("Human bootstrap and worker enrollment authorities require distinct tokens")
    atomic_environment(values)
    return {"prepared": True, "required_auth": True, "secure_cookies": True, "required_worker_mtls": True, "restart_required": True}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def bootstrap_admin(operator_user: str, *, username: str = 'admin', timeout_seconds: int = 15) -> dict:
    if type(timeout_seconds) is not int or timeout_seconds not in {15, 60, 120}:
        raise ValueError("Bootstrap request timeout must be 15, 60 or 120 seconds")
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', username):
        raise ValueError('Use a simple administrator username')
    trusted(ENV)
    operator = pwd.getpwnam(operator_user)
    if operator.pw_uid == 0 or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", operator_user):
        raise ValueError("A named non-root local operator is required")
    values = parse_environment(ENV.read_text())
    bootstrap = values.get("ICHECK_CONTROL_PLANE_BOOTSTRAP_TOKEN")
    if not bootstrap:
        raise ValueError("No pending first-admin bootstrap")
    trusted(PUBLIC_CA)
    ca_info = PUBLIC_CA.stat()
    if not stat.S_ISREG(ca_info.st_mode) or ca_info.st_nlink != 1 or ca_info.st_size > 16384:
        raise ValueError("Unsafe public evaluation CA file")
    ca_pem = PUBLIC_CA.read_bytes()
    trusted(ACCESS.parent)
    # Exclusive directory creation deliberately refuses retry after an
    # ambiguous response, rather than issuing a second credential blindly.
    ACCESS.mkdir(mode=0o700)
    # The public CA is part of operator custody, not an undocumented manual
    # copy needed later by smoke checks or the authenticated monitoring gateway.
    ca_fd = os.open(ACCESS / "preview-ca.pem", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    with os.fdopen(ca_fd, "wb") as handle:
        handle.write(ca_pem)
        handle.flush()
        os.fsync(handle.fileno())
        os.fchmod(handle.fileno(), 0o644)
    payload = json.dumps({"subject": username, "display_name": "Preview administrator", "token_name": "preview-v01-admin", "expires_in_hours": 720}).encode()
    request = Request("http://127.0.0.1:8000/api/v1/auth/bootstrap", data=payload,
        headers={"Content-Type": "application/json", "X-Icheck-Bootstrap-Token": bootstrap}, method="POST")
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=timeout_seconds) as response:
        raw = response.read(64 * 1024 + 1)
        if response.status != 201 or len(raw) > 64 * 1024:
            raise ValueError("Unexpected bootstrap response")
        result = json.loads(raw)
    token = result["token"]["access_token"]
    if not isinstance(token, str) or not re.fullmatch(r"icp_[A-Za-z0-9_-]{20,200}", token):
        raise ValueError("Invalid issued token")
    token_path = ACCESS / "admin-access-token"
    fd = os.open(token_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(token + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        os.fchown(handle.fileno(), operator.pw_uid, operator.pw_gid)
    os.chown(ACCESS, 0, operator.pw_gid)
    os.chmod(ACCESS, 0o750)
    # Remove only after durable custody. The operator must restart the API
    # to remove the bootstrap value from already-running process memory.
    values.pop("ICHECK_CONTROL_PLANE_BOOTSTRAP_TOKEN")
    atomic_environment(values)
    return {"administrator_created": True, "token_file": str(token_path),
        "public_ca_file": str(ACCESS / "preview-ca.pem"),
        "expires_at": result["token"]["token"]["expires_at"],
        "bootstrap_removed_from_environment": True, "restart_required": True}


def worker_environments(cidrs: list[str]) -> dict[str, dict[str, str]]:
    approved = [ipaddress.ip_network(value, strict=True) for value in cidrs]
    private = [ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15")]
    if not approved or len(approved) > 32 or any(network.version != 4 or not any(network.subnet_of(parent) for parent in private) for network in approved):
        raise ValueError("Preview collection requires finite explicit private/benchmark IPv4 lab CIDRs")
    targets = ",".join(str(network) for network in approved)
    common = {"ICHECK_ENVIRONMENT": "production", "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "ICHECK_CONTROL_PLANE_AUTH_MODE": "required", "ICHECK_CONTROL_PLANE_SESSION_COOKIE_SECURE": "true",
        "ICHECK_REQUIRE_GOVERNED_CHANGE_CONTRACTS": "true", "ICHECK_CONTROL_PLANE_URL": "https://127.0.0.1:8444",
        "ICHECK_TENANT_ID": "00000000-0000-0000-0000-000000000001",
        "ICHECK_REGION_ID": "00000000-0000-0000-0000-000000000002",
        "ICHECK_CREDENTIAL_ALLOW_ENVIRONMENT": "false", "ICHECK_LOG_LEVEL": "INFO",
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
    result = {}
    for name in ("collector", "agent"):
        directory = f"/etc/icheck-workers/{name}"
        values = {**common, "ICHECK_WORKER_TLS_CA_FILE": directory + "/worker-ca.pem",
            "ICHECK_WORKER_TLS_CERT_FILE": directory + "/client.pem", "ICHECK_WORKER_TLS_KEY_FILE": directory + "/client.key"}
        if name == "collector":
            values.update({"ICHECK_COLLECTOR_NAME": "preview-lab-collector", "ICHECK_COLLECTOR_SITE": "LAB",
                "ICHECK_COLLECTOR_CAPABILITIES": "http_json,http_json_sandbox,ssh_command_sandbox,snmp_exporter,snmp_topology,windows_exporter,psrp_cim",
                "ICHECK_COLLECTOR_REGISTRATION_TOKEN_FILE": directory + "/registration-token",
                "ICHECK_COLLECTOR_POLL_SECONDS": "5", "ICHECK_COLLECTOR_LEASE_SECONDS": "120",
                "ICHECK_COLLECTOR_MAX_ASSIGNMENTS": "4", "ICHECK_COLLECTOR_MAX_PREFLIGHTS": "4",
                "ICHECK_COLLECTOR_PREFLIGHT_TIMEOUT_SECONDS": "5",
                "ICHECK_COLLECTOR_PREFLIGHT_ALLOWED_TARGETS": targets,
                "ICHECK_COLLECTOR_PREFLIGHT_SNMP_EXPORTER_URL": "http://127.0.0.1:9116",
                "ICHECK_COLLECTOR_HTTP_ALLOWED_HOSTS": targets,
                "ICHECK_COLLECTOR_EXPORTER_ALLOWED_HOSTS": "127.0.0.1,localhost",
                "ICHECK_COLLECTOR_SNMP_ALLOWED_TARGETS": targets,
                "ICHECK_COLLECTOR_WINDOWS_EXPORTER_ALLOWED_HOSTS": targets,
                "ICHECK_COLLECTOR_WINDOWS_ALLOWED_TARGETS": targets,
                "ICHECK_COLLECTOR_PSRP_ALLOWED_PORTS": "5986", "ICHECK_COLLECTOR_PSRP_AUTH": "ntlm",
                "ICHECK_COLLECTOR_PSRP_CONFIGURATION_NAME": "Microsoft.PowerShell",
                "ICHECK_COLLECTOR_SSH_ALLOWED_TARGETS": targets,
                "ICHECK_COLLECTOR_SSH_KNOWN_HOSTS_FILE": directory + "/ssh_known_hosts",
                "ICHECK_SANDBOX_ENABLED": "true", "ICHECK_SANDBOX_BACKEND": "process",
                "ICHECK_SANDBOX_PYTHON_PATH": "/usr/bin/python3", "ICHECK_SANDBOX_TIMEOUT_SECONDS": "5"})
        else:
            values.update({"ICHECK_AGENT_WORKER_NAME": "preview-agent-01", "ICHECK_AGENT_WORKER_CAPABILITIES": "openai_compatible,anthropic,mcp",
                "ICHECK_AGENT_ALLOW_INSECURE_CONTROL_PLANE": "false", "ICHECK_AGENT_WORKER_POLL_SECONDS": "2",
                "ICHECK_AGENT_WORKER_LEASE_SECONDS": "300", "ICHECK_AGENT_REGISTRATION_TOKEN_FILE": directory + "/registration-token"})
        result[name] = values
    return result


def prepare_workers(cidrs: list[str]) -> dict:
    trusted(ENV)
    values = parse_environment(ENV.read_text())
    configurations = worker_environments(cidrs)
    paths = {"collector": ENV.parent / "collector.env", "agent": ENV.parent / "agent-worker.env"}
    accounts = {name: pwd.getpwnam("icheck-" + name) for name in paths}
    for name, path in paths.items():
        trusted(Path("/etc/icheck-workers") / name)
        if path.exists() or (Path("/etc/icheck-workers") / name / "registration-token").exists():
            raise ValueError("Existing worker configuration; inspect before provisioning")
        if not values.get("ICHECK_" + name.upper() + "_REGISTRATION_TOKEN"):
            raise ValueError("API registration authority is missing")
    for name, path in paths.items():
        directory = Path("/etc/icheck-workers") / name
        account = accounts[name]
        for target, content, uid, mode in [
            (directory / "registration-token", (values["ICHECK_" + name.upper() + "_REGISTRATION_TOKEN"] + "\n").encode(), account.pw_uid, 0o600),
            (path, render_environment(configurations[name]), 0, 0o640),
        ]:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
            with os.fdopen(fd, "wb") as handle:
                handle.write(content); handle.flush(); os.fsync(handle.fileno())
                os.fchown(handle.fileno(), uid, account.pw_gid)
        if name == "collector":
            fd = os.open(directory / "ssh_known_hosts", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
            os.close(fd)
    return {"workers_prepared": sorted(paths), "site": "LAB", "allowed_lab_cidrs": cidrs,
        "database_credentials_in_workers": False, "ssh_host_keys_preloaded": False, "services_started": False}


def configure_metrics() -> dict:
    trusted(ENV)
    values = parse_environment(ENV.read_text())
    if values.get("ICHECK_CONTROL_PLANE_AUTH_MODE") != "required":
        raise ValueError("Required authentication must remain enabled")
    hosts = [host.strip() for host in values.get("ICHECK_METRICS_ALLOWED_HOSTS", "").split(",") if host.strip()]
    for host in ("127.0.0.1", "localhost"):
        if host not in hosts:
            hosts.append(host)
    values["ICHECK_METRICS_ALLOWED_HOSTS"] = ",".join(hosts)
    atomic_environment(values)
    return {"local_prometheus_hosts_allowed": True, "restart_required": True, "ai_or_mcp_allowlists_changed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare-api", "bootstrap-admin", "prepare-workers", "configure-metrics"))
    parser.add_argument("--operator-user")
    parser.add_argument('--admin-username', default='admin', help='Initial web username; default: admin')
    parser.add_argument("--request-timeout-seconds", type=int, choices=(15, 60, 120), default=15,
        help="Bound the one-time bootstrap HTTP request on slow hosts; never authorizes replay after uncertainty")
    parser.add_argument("--listen-ip", action="append", help="Explicit server IPv4 address for HTTPS CORS; prepare-api only, otherwise loopback-only")
    parser.add_argument("--lab-cidr", action="append", help="Explicit finite private/benchmark lab network; required for prepare-workers")
    parser.add_argument("--acknowledge-preview-access", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or not args.acknowledge_preview_access:
        parser.error("Requires the root deployment operator and explicit preview-access acknowledgement")
    try:
        trusted(Path(__file__).absolute())
        if args.operation == "bootstrap-admin" and not args.operator_user:
            raise ValueError("Choose the local operator for protected token custody")
        if args.listen_ip and args.operation != "prepare-api":
            raise ValueError("HTTPS addresses apply only to prepare-api")
        if args.lab_cidr and args.operation != "prepare-workers":
            raise ValueError("Collection networks apply only to prepare-workers")
        if args.operation == "prepare-api":
            result = prepare_api(args.listen_ip)
        elif args.operation == "bootstrap-admin":
            result = bootstrap_admin(args.operator_user, username=args.admin_username, timeout_seconds=args.request_timeout_seconds)
        elif args.operation == "configure-metrics":
            result = configure_metrics()
        else:
            result = prepare_workers(args.lab_cidr or [])
    except Exception as error:
        # Never emit request bodies, response bodies, URLs or exception text.
        print(json.dumps({"passed": False, "error_type": type(error).__name__, "inspect_before_retrying": True}))
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
