"""Provision the preview's local Prometheus catalog and scoped discovery gateway.

Requires an existing protected administrator token, running native HTTPS API,
and the separately provisioned non-login gateway account. Never adds devices,
enrolls monitoring targets, resolves lab secrets, or starts services.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import UTC, datetime
import json
import ipaddress
import os
from pathlib import Path
import pwd
import secrets
import ssl
import subprocess
import sys
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

import yaml
from icheck.monitoring_gateway import GatewayConfig
from icheck.exporter_metrics import CATALOG

GATEWAY = Path("/etc/icheck-workers/monitoring-gateway")
PROM = Path("/etc/icheck-workers/prometheus")
ACCESS = Path("/var/lib/icheck-preview-access")
TENANT = "00000000-0000-0000-0000-000000000001"
REGION = "00000000-0000-0000-0000-000000000002"
PREVIEW_LAB_CIDRS = []  # No networks are authorized by the distributed package.


def trusted(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if item.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Unsafe deployment path")


def write_new(path, content, *, gid, mode=0o640):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content); handle.flush(); os.fsync(handle.fileno())
        os.fchown(handle.fileno(), 0, gid); os.fchmod(handle.fileno(), mode)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class API:
    def __init__(self, *, timeout_seconds=15):
        if type(timeout_seconds) is not int or timeout_seconds not in {15, 60, 120}:
            raise ValueError("Monitoring request timeout must be 15, 60 or 120 seconds")
        self.timeout_seconds = timeout_seconds
        trusted(ACCESS)
        info = (ACCESS / "admin-access-token").lstat()
        if not (ACCESS / "admin-access-token").is_file() or (ACCESS / "admin-access-token").is_symlink() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError("Unsafe administrator token custody")
        self.token = (ACCESS / "admin-access-token").read_text().strip()
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(
            context=ssl.create_default_context(cafile=str(ACCESS / "preview-ca.pem"))))

    def request(self, method, path, body=None):
        request = Request("https://127.0.0.1:8443/api/v1" + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json",
                "X-Icheck-Tenant-ID": TENANT, "X-Icheck-Region-ID": REGION}, method=method)
        with self.opener.open(request, timeout=self.timeout_seconds) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024 or response.status not in (200, 201):
                raise ValueError("Unexpected bounded API response")
            return json.loads(raw)


def gateway_configuration(cidrs):
    common = {"sites": ["LAB"], "allowed_targets": cidrs, "credential_profile_ids": [None]}
    result = {"tenant_id": TENANT, "region_id": REGION, "api_base_url": "https://127.0.0.1:8443",
        "api_tls": {"ca_file": str(GATEWAY / "preview-ca.pem")},
        "api_token_file": str(GATEWAY / "api-token"), "prometheus_token_file": str(GATEWAY / "prometheus-token"),
        "listen_address": "127.0.0.1", "port": 9120,
        "profiles": {
            "preview-snmp": {**common, "protocol": "snmp", "allowed_ports": [161], "allowed_modules": ["if_mib", "system"],
                "snmp_exporter_url": "http://127.0.0.1:9116/snmp", "snmp_auth_name": "public_v2"},
            "preview-windows": {**common, "protocol": "windows_exporter", "allowed_ports": [9182],
                "allowed_collectors": ["cpu", "memory", "logical_disk", "net", "os", "service", "system"], "windows_scheme": "https"}}}
    GatewayConfig.model_validate(result)
    return result


def discovery_job():
    auth = {"credentials_file": str(PROM / "gateway-token")}
    return {"job_name": "icheck_continuous", "honor_labels": False,
        "scrape_protocols": ["PrometheusText0.0.4"], "scrape_interval": "30s", "scrape_timeout": "10s",
        "body_size_limit": "10MB", "sample_limit": 20000, "label_limit": 64,
        "label_name_length_limit": 128, "label_value_length_limit": 2048, "authorization": auth,
        "http_sd_configs": [{"url": "http://127.0.0.1:9120/discovery", "refresh_interval": "15s", "authorization": auth.copy()}]}


def add_preview_plugin_profiles(config):
    """Add only the operator-approved preview LAB profiles, without I/O."""
    if not PREVIEW_LAB_CIDRS:
        raise ValueError('Explicit approved CIDRs are required; the release has no lab allowlist')
    result = deepcopy(config)
    common = {"sites": ["LAB"], "allowed_targets": PREVIEW_LAB_CIDRS.copy(),
              "credential_profile_ids": [None]}
    additions = {
        "preview-http": {**common, "protocol": "https_api", "allowed_ports": [80, 443],
                         "allowed_http_paths": ["/*"], "allow_insecure_http": True,
                         "allow_managed_http_credentials": True},
    }
    for name, protocol, plugin, port in (
        ("preview-linux", "node_exporter", "linux", 9100),
        ("preview-containers", "cadvisor", "containers", 8080),
        ("preview-vmware", "vmware_exporter", "vmware", 9272),
    ):
        collectors = (["hosts", "vms", "datastores"] if plugin == "vmware" else
                      list(dict.fromkeys(c for group in CATALOG[plugin].values()
                                         for c in group["collectors"])))
        additions[name] = {**common, "protocol": protocol, "allowed_ports": [port],
                           "allowed_collectors": collectors,
                           "allow_insecure_exporter_http": True,
                           "allow_managed_exporter_credentials": True}
    for name, profile in additions.items():
        if name in result["profiles"] and result["profiles"][name] != profile:
            raise ValueError("Existing plugin profile differs; refusing replacement")
        result["profiles"][name] = profile
    GatewayConfig.model_validate(result)
    return result


def provision_preview_plugin_profiles():
    """Back up and add approved profiles; never enroll or test a target."""
    from icheck.monitoring_gateway import protected_read
    trusted(Path(__file__).absolute())
    path = GATEWAY / "config.json"
    collector = Path("/etc/icheck/collector.env")
    for item in (path, collector, Path("/var/backups/icheck")):
        trusted(item)
    before = protected_read(str(path))
    env_bytes = protected_read(str(collector))
    env = dict(line.split("=", 1) for line in env_bytes.decode().splitlines()
               if line and not line.startswith("#"))
    if env.get("ICHECK_COLLECTOR_SITE") != "LAB" or set(
        env.get("ICHECK_COLLECTOR_PREFLIGHT_ALLOWED_TARGETS", "").split(",")
    ) != set(PREVIEW_LAB_CIDRS):
        raise ValueError("Collector target custody differs from approved LAB bounds")
    config = json.loads(before)
    if (config["tenant_id"], config["region_id"]) != (TENANT, REGION):
        raise ValueError("Unexpected preview workspace")
    result = add_preview_plugin_profiles(config)
    if result == config:
        return {"changed": False, "profiles": sorted(result["profiles"])}
    backup = Path("/var/backups/icheck") / (
        "lab-plugin-profiles-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))
    backup.mkdir(mode=0o700)
    write_new(backup / "gateway-before.json", before, gid=0, mode=0o600)
    write_new(backup / "collector-before.env", env_bytes, gid=0, mode=0o600)
    info = path.stat()
    temporary = path.with_name(".plugin-profiles-" + secrets.token_hex(12) + ".json")
    write_new(temporary, (json.dumps(result, indent=2) + "\n").encode(),
              gid=info.st_gid, mode=info.st_mode & 0o777)
    try:
        check = subprocess.run([sys.executable, "-I", "-B", "-c",
            "import json,sys;from icheck.monitoring_gateway import GatewayConfig,protected_read;"
            "GatewayConfig.model_validate(json.loads(protected_read(sys.argv[1])))", str(temporary)],
            user=pwd.getpwnam("icheck-monitoring-gateway").pw_uid, group=info.st_gid,
            extra_groups=[], env={"PATH": "/usr/bin:/bin"}, cwd="/",
            capture_output=True, timeout=30)
        if check.returncode:
            raise ValueError("Gateway service account cannot validate staged profiles")
        if protected_read(str(path)) != before or protected_read(str(collector)) != env_bytes:
            raise ValueError("Configuration changed while staging; original preserved")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    subprocess.run(["/usr/bin/systemctl", "restart", "icheck-monitoring-gateway.service"],
                   check=True, capture_output=True, timeout=60)
    subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "icheck-monitoring-gateway.service"],
                   check=True, capture_output=True, timeout=15)
    receipt = {"changed": True, "backup_directory": str(backup), "site": "LAB",
        "allowed_targets": PREVIEW_LAB_CIDRS, "profiles": sorted(result["profiles"]),
        "existing_profiles_preserved": all(result["profiles"][k] == v for k, v in config["profiles"].items()),
        "collector_configuration_unchanged": protected_read(str(collector)) == env_bytes,
        "credentialed_http_allowed": False, "gateway_service_active": True,
        "devices_created": False, "monitoring_enrollments_created": False,
        "lab_polling_performed": False, "model_calls_performed": False}
    write_new(backup / "result.json", (json.dumps(receipt, indent=2) + "\n").encode(), gid=0, mode=0o600)
    return receipt


def enable_preview_exporter_tests():
    """Enable only known metric-test capabilities in an upgraded Collector."""
    from icheck.collector_worker import validate_worker_capabilities
    from icheck.monitoring_gateway import protected_read
    trusted(Path(__file__).absolute())
    collector = Path("/etc/icheck/collector.env")
    for path in (collector, GATEWAY / "config.json", Path("/var/backups/icheck")):
        trusted(path)
    config = json.loads(protected_read(str(GATEWAY / "config.json")))
    if config != add_preview_plugin_profiles(config):
        raise ValueError("Approved plugin profiles must be provisioned first")
    before = protected_read(str(collector))
    lines = before.decode().splitlines(keepends=True)
    key = "ICHECK_COLLECTOR_CAPABILITIES="
    matching = [i for i, line in enumerate(lines) if line.startswith(key)]
    if len(matching) != 1:
        raise ValueError("Expected one explicit Collector capability setting")
    env = dict(line.strip().split("=", 1) for line in lines
               if line.strip() and not line.startswith("#"))
    if env.get("ICHECK_COLLECTOR_SITE") != "LAB" or set(
        env.get("ICHECK_COLLECTOR_PREFLIGHT_ALLOWED_TARGETS", "").split(",")
    ) != set(PREVIEW_LAB_CIDRS):
        raise ValueError("Collector custody differs from approved LAB bounds")
    capabilities = validate_worker_capabilities(env[key[:-1]].split(",") +
        ["node_exporter", "cadvisor", "vmware_exporter"])
    if capabilities == env[key[:-1]].split(","):
        return {"changed": False, "capabilities": capabilities}
    backup = Path("/var/backups/icheck") / (
        "lab-exporter-tests-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))
    backup.mkdir(mode=0o700)
    write_new(backup / "collector-before.env", before, gid=0, mode=0o600)
    lines[matching[0]] = key + ",".join(capabilities) + "\n"
    info = collector.stat()
    temporary = collector.with_name(".plugin-capabilities-" + secrets.token_hex(12) + ".env")
    write_new(temporary, "".join(lines).encode(), gid=info.st_gid, mode=info.st_mode & 0o777)
    try:
        if protected_read(str(collector)) != before:
            raise ValueError("Collector configuration changed during staging")
        os.replace(temporary, collector)
    finally:
        temporary.unlink(missing_ok=True)
    # The reviewed application switch starts the Collector after this update.
    # Configuration alone does not claim a device test or contact an endpoint.
    receipt = {"changed": True, "backup_directory": str(backup),
        "capabilities": capabilities, "only_capability_setting_changed": True,
        "allowlists_unchanged": True, "services_restarted": False,
        "lab_polling_performed": False, "model_calls_performed": False}
    write_new(backup / "result.json", (json.dumps(receipt, indent=2) + "\n").encode(), gid=0, mode=0o600)
    return receipt


def prepare(*, timeout_seconds=15):
    trusted(Path(__file__).absolute())
    for path in (GATEWAY.parent, PROM / "prometheus.yml", Path("/etc/icheck/collector.env")):
        trusted(path)
    gateway_user = pwd.getpwnam("icheck-monitoring-gateway")
    prometheus_user = pwd.getpwnam("icheck-prometheus")
    if GATEWAY.exists() or GATEWAY.is_symlink() or (PROM / "gateway-token").exists():
        raise ValueError("Existing gateway custody; inspect rather than replay")
    env = dict(line.split("=", 1) for line in Path("/etc/icheck/collector.env").read_text().splitlines() if line and not line.startswith("#"))
    cidrs = env["ICHECK_COLLECTOR_SNMP_ALLOWED_TARGETS"].split(",")
    config = gateway_configuration(cidrs)
    # Preserve all installed jobs; discovery adds no targets until the user
    # explicitly verifies and enrolls their own connections in the GUI.
    prom_path = PROM / "prometheus.yml"
    prom = yaml.safe_load(prom_path.read_text())
    if any(job["job_name"] == "icheck_continuous" for job in prom["scrape_configs"]):
        raise ValueError("Discovery job already exists")
    prom["scrape_configs"].append(discovery_job())
    api = API(timeout_seconds=timeout_seconds)
    identity = api.request("GET", "/auth/me")
    if identity["tenant_id"] != TENANT or identity["region_id"] != REGION or not ("*" in identity["permissions"] or "auth.admin" in identity["permissions"]):
        raise ValueError("Wrong administrator namespace or authority")
    principals = api.request("GET", "/auth/principals?limit=1000")
    roles = api.request("GET", "/auth/roles?limit=1000")
    if any(row["subject"] == "preview-monitoring-gateway" for row in principals) or any(row["name"] == "preview-monitoring-discovery" for row in roles):
        raise ValueError("Existing gateway identity; inspect before credential issue")
    # Claim custody before writes so an uncertain result cannot be replayed.
    GATEWAY.mkdir(mode=0o750)
    os.chown(GATEWAY, 0, gateway_user.pw_gid)
    role = api.request("POST", "/auth/roles", {"name": "preview-monitoring-discovery", "description": "Only current LAB asset enrollment reads for local Prometheus discovery", "permissions": ["assets.read"]})
    principal = api.request("POST", "/auth/principals", {"subject": "preview-monitoring-gateway", "display_name": "Preview monitoring gateway", "principal_type": "service", "allowed_region_ids": [REGION]})
    api.request("POST", f'/auth/principals/{principal["id"]}/bindings', {"role_id": role["id"], "scope": {"sites": ["LAB"]}})
    issued = api.request("POST", f'/auth/principals/{principal["id"]}/tokens', {"name": "preview-gateway-read", "expires_in_hours": 720})
    write_new(GATEWAY / "api-token", (issued["access_token"] + "\n").encode(), gid=gateway_user.pw_gid)
    caller = (secrets.token_urlsafe(48) + "\n").encode()
    write_new(GATEWAY / "prometheus-token", caller, gid=gateway_user.pw_gid)
    write_new(PROM / "gateway-token", caller, gid=prometheus_user.pw_gid)
    write_new(GATEWAY / "preview-ca.pem", (ACCESS / "preview-ca.pem").read_bytes(), gid=gateway_user.pw_gid, mode=0o644)
    write_new(GATEWAY / "config.json", (json.dumps(config, indent=2) + "\n").encode(), gid=gateway_user.pw_gid)
    temporary = PROM / (".preview-prometheus-" + secrets.token_hex(12) + ".yml")
    write_new(temporary, yaml.safe_dump(prom, sort_keys=False).encode(), gid=prometheus_user.pw_gid)
    check = subprocess.run(["/opt/icheck/bin/promtool", "check", "config", str(temporary)],
        user=prometheus_user.pw_uid, group=prometheus_user.pw_gid, extra_groups=[],
        env={"PATH": "/usr/bin:/bin"}, cwd="/", capture_output=True, timeout=30)
    if check.returncode:
        raise ValueError("Prometheus configuration validation failed; original remains active")
    os.replace(temporary, prom_path)
    backends = api.request("GET", "/metrics/backends?limit=1000")
    if not any(row["name"] == "native-lab-prometheus" for row in backends):
        api.request("POST", "/metrics/backends", {"name": "native-lab-prometheus", "provider": "prometheus",
            "query_base_url": "http://127.0.0.1:9090", "auth_type": "none", "created_by": "preview.deployment"})
    return {"prepared": True, "profiles": sorted(config["profiles"]), "site": "LAB",
        "gateway_permissions": ["assets.read"], "gateway_scope": {"sites": ["LAB"]},
        "api_token_expires_at": issued["token"]["expires_at"], "promtool_as_service_account": True,
        "devices_created": False, "monitoring_enrollments_created": False, "services_started": False}


def main():
    global PREVIEW_LAB_CIDRS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-local-monitoring", action="store_true")
    parser.add_argument('--allowed-cidr', action='append', default=[],
        help='Explicit approved private or benchmark IPv4 subnet; repeat for each subnet')
    parser.add_argument("--add-preview-plugin-profiles", action="store_true",
        help="Add explicitly approved LAB HTTP/Linux/container/VMware profiles; no enrollment or polling")
    parser.add_argument("--enable-preview-exporter-tests", action="store_true",
        help="Enable approved exporter test capabilities after upgrading the Collector; no service restart")
    parser.add_argument("--request-timeout-seconds", type=int, choices=(15, 60, 120), default=15,
        help="Bound each setup HTTP request on slow hosts; custody and replay refusals remain unchanged")
    args = parser.parse_args()
    if args.add_preview_plugin_profiles or args.enable_preview_exporter_tests:
        try:
            approved = [ipaddress.ip_network(value, strict=True) for value in args.allowed_cidr]
            bounds = [ipaddress.ip_network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15')]
            if not approved or len(approved) > 32 or any(network.version != 4 or not any(network.subnet_of(bound) for bound in bounds) for network in approved):
                raise ValueError('Explicit bounded private/benchmark CIDRs required')
            PREVIEW_LAB_CIDRS = list(dict.fromkeys(str(network) for network in approved))
        except ValueError:
            parser.error('Provide one or more valid --allowed-cidr private/benchmark IPv4 networks')
    if os.geteuid() != 0 or not args.acknowledge_local_monitoring:
        parser.error("Requires root deployment operator and explicit local-monitoring acknowledgement")
    if args.add_preview_plugin_profiles and args.enable_preview_exporter_tests:
        parser.error("Choose profile provisioning or Collector test configuration, not both")
    try:
        result = (enable_preview_exporter_tests() if args.enable_preview_exporter_tests else
                  provision_preview_plugin_profiles() if args.add_preview_plugin_profiles else
                  prepare(timeout_seconds=args.request_timeout_seconds))
    except Exception as error:
        print(json.dumps({"passed": False, "error_type": type(error).__name__, "inspect_before_retrying": True}))
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
