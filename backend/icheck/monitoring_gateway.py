"""Database-free Prometheus discovery and current-authority scrape gateway.

The protected gateway configuration, not API intent, selects local exporter
custody and network bounds. No last-good target file or durable authorization
cache can survive revocation, API failure, or this process's restart.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import threading
import time
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from pydantic import BaseModel, ConfigDict, Field, model_validator
from prometheus_client.parser import text_string_to_metric_families

from .monitoring_schemas import MonitoringSnapshot, MonitoringTarget
from .http_metrics import HTTPMetricError, auth_headers, fetch_http, render_result
from .exporter_metrics import PROTOCOLS, collect as collect_exporter, validate_response as validate_exporter_response


LOGGER = logging.getLogger("icheck.monitoring_gateway")


class GatewayError(RuntimeError):
    pass


class TLSFiles(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ca_file: str | None = None
    certificate_file: str | None = None
    key_file: str | None = None
    key_password_file: str | None = None

    @model_validator(mode="after")
    def pair(self):
        if bool(self.certificate_file) != bool(self.key_file):
            raise ValueError("Client TLS certificate and key must be paired")
        return self


class GatewayProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: str = Field(pattern=r"^(snmp|windows_exporter|node_exporter|cadvisor|vmware_exporter|https_api)$")
    sites: list[str] = Field(min_length=1, max_length=128)
    allowed_targets: list[str] = Field(min_length=1, max_length=128)
    allowed_ports: list[int] = Field(min_length=1, max_length=32)
    credential_profile_ids: list[str | None] = Field(min_length=1, max_length=128)
    allow_managed_snmp_credentials: bool = False
    allow_installed_snmp_templates: bool = False
    allow_managed_http_credentials: bool = False
    allow_managed_exporter_credentials: bool = False
    allow_insecure_exporter_http: bool = False
    allowed_exporter_server_names: list[str | None] = Field(default_factory=lambda: [None], max_length=128)
    allow_insecure_http: bool = False
    allowed_http_paths: list[str] = Field(default_factory=list, max_length=128)
    allowed_http_server_names: list[str | None] = Field(default_factory=lambda: [None], max_length=128)
    allowed_modules: list[str] = Field(default_factory=list, max_length=128)
    allowed_collectors: list[str] = Field(default_factory=list, max_length=128)
    snmp_exporter_url: str | None = None
    snmp_auth_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    snmp_transport: str = Field(default="udp", pattern=r"^(udp|udp6|tcp|tcp6)$")
    exporter_token_file: str | None = None
    exporter_tls: TLSFiles = Field(default_factory=TLSFiles)
    windows_scheme: str = Field(default="https", pattern=r"^(http|https)$")
    allow_insecure_windows_http: bool = False

    @model_validator(mode="after")
    def validate_custody(self):
        for target in self.allowed_targets: ipaddress.ip_network(target, strict=False)
        if any(not 1 <= port <= 65535 for port in self.allowed_ports):
            raise ValueError("Invalid allowed exporter port")
        if self.protocol == "snmp" and (not self.snmp_exporter_url or not self.snmp_auth_name or not (self.allowed_modules or self.allow_installed_snmp_templates)):
            raise ValueError("SNMP custody requires explicit exporter, auth and allowed modules")
        if self.protocol == "windows_exporter" and self.windows_scheme == "http" and not self.allow_insecure_windows_http:
            raise ValueError("Windows HTTP needs explicit protected-file exception; HTTPS is default")
        if self.protocol == "https_api" and (not self.allowed_http_paths or self.exporter_token_file):
            raise ValueError("HTTP custody requires explicit request paths and managed credential references")
        if self.protocol in {"node_exporter","cadvisor","vmware_exporter"} and (not self.allowed_collectors or self.exporter_token_file):
            raise ValueError("Native exporter custody requires explicit measurement scopes and managed credential references")
        if any(not path.startswith("/") or len(path) > 2048 or "*" in path[:-1]
               or ("*" in path and not path.endswith("/*")) for path in self.allowed_http_paths):
            raise ValueError("HTTP custody paths must be exact paths or explicit /prefix/* entries")
        return self


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    region_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    api_base_url: str
    api_token_file: str
    api_tls: TLSFiles = Field(default_factory=TLSFiles)
    allow_loopback_api_http: bool = False
    prometheus_token_file: str
    listen_address: str = "127.0.0.1"
    port: int = Field(default=9120, ge=1, le=65535)
    max_concurrency: int = Field(default=64, ge=1, le=256)
    max_api_bytes: int = Field(default=16000000, ge=1024, le=20000000)
    max_metric_bytes: int = Field(default=10000000, ge=1024, le=50000000)
    max_samples: int = Field(default=20000, ge=1, le=50000)
    profiles: dict[str, GatewayProfile]

    @model_validator(mode="after")
    def validate_local_and_api(self):
        if not ipaddress.ip_address(self.listen_address).is_loopback:
            raise ValueError("Prometheus gateway listener must be local loopback")
        parsed = urlsplit(self.api_base_url)
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"}):
            raise ValueError("API base URL must be a credential-free origin")
        if parsed.scheme != "https":
            try: local = ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError: local = False
            if parsed.scheme != "http" or not local or not self.allow_loopback_api_http:
                raise ValueError("API requires HTTPS except an explicit literal-loopback HTTP binding")
        if not self.profiles or len(self.profiles) > 256 or any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", name) for name in self.profiles):
            raise ValueError("Gateway profiles require bounded explicit identifiers")
        return self


def protected_read(path: str, *, maximum=1000000, secret=True, require_root=True) -> bytes:
    value = Path(path)
    if not value.is_absolute(): raise GatewayError("Custody file path must be absolute")
    if require_root:
        for parent in value.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise GatewayError("Custody file ancestry must be root-owned and non-writable")
    descriptor = os.open(value, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or (require_root and info.st_uid != 0)
                or info.st_mode & 0o022 or (secret and info.st_mode & 0o007) or info.st_size > maximum):
            raise GatewayError("Unsafe custody file permissions, owner, type or size")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk: break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum: raise GatewayError("Custody file exceeds its bound")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _token(path, reader):
    token = reader(path, maximum=4096).decode("utf-8").strip()
    if not token or len(token) > 2048 or any(character.isspace() for character in token):
        raise GatewayError("Invalid private bearer token file")
    return token


def _tls(files, reader):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if files.ca_file:
        context.load_verify_locations(cadata=reader(files.ca_file, secret=False).decode())
    if files.certificate_file:
        # Validate protected files before SSL loads them. Their ancestry is not
        # mutable by this service or untrusted users; raw values stay local.
        reader(files.certificate_file)
        reader(files.key_file)
        password = reader(files.key_password_file, maximum=4096).decode().strip() if files.key_password_file else None
        context.load_cert_chain(files.certificate_file, files.key_file, password=password)
    return context


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise GatewayError("Gateway redirects are forbidden")


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0: raise GatewayError("Scrape deadline expired")
    return remaining


def _body(response, maximum, deadline):
    chunks, total = [], 0
    while True:
        remaining = _remaining(deadline)
        socket = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
        if socket is not None: socket.settimeout(remaining)
        read = getattr(response, "read1", response.read)
        chunk = read(min(65536, maximum + 1 - total))
        _remaining(deadline)
        if not chunk: break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum: raise GatewayError("Gateway response exceeded its byte bound")
    return b"".join(chunks)


class MonitoringGateway:
    def __init__(self, config_loader, *, reader=protected_read, opener=None):
        self.config_loader = config_loader
        self.reader = reader
        self.opener = opener

    def _exporter_custody(self, profile):
        # Compare bounded local material, not just file names, across I/O.
        # Private bytes live only in this attempt and never enter API output,
        # discovery, metrics, an audit row or a durable authorization cache.
        files = [(profile.exporter_token_file, 4096, True),
                 (profile.exporter_tls.ca_file, 1000000, False),
                 (profile.exporter_tls.certificate_file, 1000000, True),
                 (profile.exporter_tls.key_file, 1000000, True),
                 (profile.exporter_tls.key_password_file, 4096, True)]
        return tuple((path, self.reader(path, maximum=maximum, secret=secret))
                     for path, maximum, secret in files if path)

    def _fetch(self, url, *, headers, tls, deadline, maximum, content_type):
        client = self.opener or build_opener(ProxyHandler({}), _NoRedirect(), HTTPSHandler(context=_tls(tls, self.reader)))
        request = Request(url, headers=headers, method="GET")
        with client.open(request, timeout=_remaining(deadline)) as response:
            if response.getcode() != 200 or response.headers.get_content_type() != content_type:
                raise GatewayError("Gateway response status or content type is invalid")
            return _body(response, maximum, deadline)

    def _api(self, config, path, deadline):
        body = self._fetch(config.api_base_url.rstrip("/") + "/api/v1" + path,
            headers={"Authorization": "Bearer " + _token(config.api_token_file, self.reader),
                "X-Icheck-Tenant-ID": config.tenant_id, "X-Icheck-Region-ID": config.region_id,
                "Accept": "application/json"}, tls=config.api_tls, deadline=deadline,
            maximum=config.max_api_bytes, content_type="application/json")
        return json.loads(body)

    def _current_target(self, config, enrollment_id, deadline):
        target = MonitoringTarget.model_validate(self._api(config, f"/monitoring/enrollments/{enrollment_id}/target", deadline))
        self._validate_target(config, target)
        return target

    def _validate_target(self, config, target):
        now = datetime.now(UTC)
        if (target.tenant_id != config.tenant_id or target.region_id != config.region_id
                or target.issued_at > now or target.expires_at <= now or target.approved_until <= now
                or (target.expires_at - target.issued_at).total_seconds() > 30
                or target.expires_at > target.approved_until):
            raise GatewayError("Target namespace, lifetime or approval is invalid")
        profile = config.profiles.get(target.gateway_profile)
        address = ipaddress.ip_address(target.host)
        credential_allowed = profile is not None and (
            target.credential_profile_id in profile.credential_profile_ids
            or (target.protocol == "snmp" and profile.allow_managed_snmp_credentials and bool(target.credential_profile_id))
            or (target.protocol == "https_api" and profile.allow_managed_http_credentials and bool(target.credential_profile_id))
            or (target.exporter_monitor is not None and profile.allow_managed_exporter_credentials and bool(target.credential_profile_id)))
        if (profile is None or profile.protocol != target.protocol or target.site not in profile.sites
                or target.port not in profile.allowed_ports or not credential_allowed
                or address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast
                or not any(address in ipaddress.ip_network(network, strict=False) for network in profile.allowed_targets)
                or not 15 <= target.schedule_seconds <= 3600 or not 1 <= target.timeout_seconds <= 30
                or target.timeout_seconds >= target.schedule_seconds):
            raise GatewayError("Target is outside protected gateway custody or network bounds")
        if target.protocol == "snmp":
            allowed=set(target.modules).issubset(profile.allowed_modules)
            if target.snmp_module_sha256 is not None:
                from .managed_snmp import module_document
                import hashlib,yaml
                if (len(target.modules)!=1 or not re.fullmatch(r"icheck_[0-9a-f]{24}",target.modules[0])
                        or not profile.allow_managed_snmp_credentials or target.credential_revision is None):
                    raise GatewayError("Native SNMP template custody is invalid")
                try: actual=module_document()["modules"].get(target.modules[0])
                except (OSError,ValueError): raise GatewayError("Installed SNMP template catalog is unavailable") from None
                if actual is None or hashlib.sha256(yaml.safe_dump(actual,sort_keys=True).encode()).hexdigest()!=target.snmp_module_sha256:
                    raise GatewayError("Installed SNMP module changed after target approval")
                allowed=allowed or profile.allow_installed_snmp_templates
            if not target.modules or target.collectors or not allowed:
                raise GatewayError("Target modules are outside protected SNMP custody")
        elif target.protocol == "https_api":
            spec = target.http_monitor
            allowed_path = spec is not None and any(spec.path == path or
                (path.endswith("/*") and spec.path.startswith(path[:-1])) for path in profile.allowed_http_paths)
            if (spec is None or target.modules or target.collectors or not allowed_path
                    or spec.server_name not in profile.allowed_http_server_names
                    or (spec.scheme == "http" and (not profile.allow_insecure_http or spec.auth_mode != "none"))
                    or (spec.auth_mode != "none" and (not target.credential_profile_id or target.credential_revision is None))):
                raise GatewayError("HTTP request is outside protected path, TLS or authentication custody")
        elif target.exporter_monitor is not None:
            spec = target.exporter_monitor
            if (PROTOCOLS[spec.plugin] != target.protocol or target.modules
                    or target.collectors != spec.collectors() or not set(target.collectors).issubset(profile.allowed_collectors)
                    or spec.server_name not in profile.allowed_exporter_server_names or profile.exporter_token_file
                    or (spec.scheme == "http" and not profile.allow_insecure_exporter_http)
                    or (spec.auth_mode != "none" and (not target.credential_profile_id or target.credential_revision is None))):
                raise GatewayError("Exporter request is outside protected collector, TLS or authentication custody")
        elif target.protocol in {"node_exporter","cadvisor","vmware_exporter"}:
            raise GatewayError("Native exporter requires a tested measurement template")
        elif target.modules or not set(target.collectors).issubset(profile.allowed_collectors):
            raise GatewayError("Target collectors are outside protected Windows custody")
        return profile

    def _scrape_http(self, config, profile, target, deadline):
        spec = target.http_monitor
        values = None
        try:
            if spec.auth_mode != "none":
                secret = self._api(config, f"/monitoring/enrollments/{target.enrollment_id}/managed-credential", deadline)
                expiry = datetime.fromisoformat(secret["expires_at"].replace("Z", "+00:00"))
                if expiry <= datetime.now(UTC) or secret["profile_revision"] != target.credential_revision:
                    raise GatewayError("HTTP credential lease expired or changed")
                deadline = min(deadline, time.monotonic() + (expiry - datetime.now(UTC)).total_seconds())
                values = secret["values"]
            headers = auth_headers(spec, values)
            # Leave time for the existing post-I/O authority/custody recheck.
            result = fetch_http(spec, target.host, target.port, headers,
                deadline=time.monotonic() + _remaining(deadline) * .75,
                tls_context=_tls(profile.exporter_tls, self.reader))
            body, _ = render_result(spec, result, values=values, headers=headers,
                max_samples=config.max_samples, max_bytes=config.max_metric_bytes)
            return body
        except HTTPMetricError:
            raise GatewayError("HTTP metric request failed; check the tested template, TLS and protected credential") from None
        finally:
            values = None

    def discovery(self):
        config = self.config_loader()
        snapshot = MonitoringSnapshot.model_validate(self._api(config, "/monitoring/targets", time.monotonic() + 5))
        now = datetime.now(UTC)
        if (snapshot.tenant_id != config.tenant_id or snapshot.region_id != config.region_id
                or snapshot.issued_at > now or snapshot.expires_at <= now
                or (snapshot.expires_at - snapshot.issued_at).total_seconds() > 30):
            raise GatewayError("Discovery namespace or lifetime is invalid")
        groups, seen = [], set()
        for target in snapshot.targets:
            # A custody mismatch withdraws this target; malformed or duplicate
            # snapshots fail the whole response rather than publish truncation.
            if target.enrollment_id in seen: raise GatewayError("Duplicate enrollment in discovery")
            seen.add(target.enrollment_id)
            try: self._validate_target(config, target)
            except GatewayError: continue
            host = f"[{target.host}]" if ":" in target.host else target.host
            listener = f"[{config.listen_address}]" if ":" in config.listen_address else config.listen_address
            groups.append({"targets": [f"{listener}:{config.port}"], "labels": {
                "__metrics_path__": f"/scrape/{target.enrollment_id}",
                "__scrape_interval__": f"{target.schedule_seconds}s", "__scrape_timeout__": f"{target.timeout_seconds}s",
                "instance": f"{host}:{target.port}", "site": target.site,
                "icheck_tenant_id": target.tenant_id, "icheck_region_id": target.region_id,
                "icheck_device_id": target.device_id, "icheck_connection_id": target.connection_id,
                "icheck_enrollment_id": target.enrollment_id, "icheck_enrollment_revision": str(target.enrollment_revision),
                "icheck_protocol": target.protocol}})
        return groups

    def _scrape_exporter(self, config, profile, target, deadline):
        values = None
        try:
            spec = target.exporter_monitor
            if spec.auth_mode != "none":
                secret = self._api(config, f"/monitoring/enrollments/{target.enrollment_id}/managed-credential", deadline)
                expiry = datetime.fromisoformat(secret["expires_at"].replace("Z", "+00:00"))
                if expiry <= datetime.now(UTC) or secret["profile_revision"] != target.credential_revision:
                    raise GatewayError("Exporter credential lease expired or changed")
                deadline = min(deadline, time.monotonic() + (expiry - datetime.now(UTC)).total_seconds())
                values = secret["values"]
            body, _ = collect_exporter(spec, target.host, target.port, values=values,
                deadline=time.monotonic() + _remaining(deadline) * .75,
                tls_context=_tls(profile.exporter_tls, self.reader))
            if len(body) > config.max_metric_bytes:
                raise GatewayError("Exporter response exceeds protected gateway byte budget")
            validate_exporter_response(spec, body, values=values, max_samples=config.max_samples)
            return body
        except HTTPMetricError:
            raise GatewayError("Exporter metric request failed; check collectors, TLS and protected credential") from None
        finally:
            values = None

    def scrape(self, enrollment_id):
        if not re.fullmatch(r"[a-f0-9-]{36}", enrollment_id): raise GatewayError("Invalid enrollment identifier")
        config = self.config_loader()
        custody_snapshot = config.model_dump()
        started = time.monotonic()
        initial = self._current_target(config, enrollment_id, started + 3)
        expiry_budget = (initial.expires_at - datetime.now(UTC)).total_seconds()
        deadline = min(started + initial.timeout_seconds, time.monotonic() + expiry_budget)
        profile = self._validate_target(config, initial)
        initial_material = self._exporter_custody(profile)
        address = f"[{initial.host}]" if ":" in initial.host else initial.host
        if initial.protocol == "snmp":
            parsed = urlsplit(profile.snmp_exporter_url)
            try: local = ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError: local = False
            if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or parsed.path not in {"", "/snmp"} or (parsed.scheme != "https" and not (parsed.scheme == "http" and local))):
                raise GatewayError("SNMP exporter must use HTTPS or literal local HTTP")
            url = profile.snmp_exporter_url.rstrip("/")
            if not url.endswith("/snmp"): url += "/snmp"
            params = [("target", f"{profile.snmp_transport}://{address}:{initial.port}"),
                      ("auth", profile.snmp_auth_name)] + [("module", name) for name in initial.modules]
        elif initial.protocol == "windows_exporter" and initial.exporter_monitor is None:
            url = f"{profile.windows_scheme}://{address}:{initial.port}/metrics"
            params = [("collect[]", name) for name in initial.collectors]
        else:
            url, params = "", []
        if params: url += "?" + urlencode(params)
        headers = {"Accept": "text/plain; version=0.0.4"}
        if profile.exporter_token_file:
            headers["Authorization"] = "Bearer " + _token(profile.exporter_token_file, self.reader)
        wire_deadline = min(deadline, time.monotonic() + _remaining(deadline) * .75)
        if initial.exporter_monitor is not None:
            body = self._scrape_exporter(config, profile, initial, deadline)
        elif initial.protocol == "https_api":
            body = self._scrape_http(config, profile, initial, deadline)
        elif initial.protocol == "snmp" and initial.credential_profile_id and profile.allow_managed_snmp_credentials:
            from .managed_snmp import exporter
            secret = self._api(config, f"/monitoring/enrollments/{enrollment_id}/managed-credential", deadline)
            values = secret["values"]
            if initial.credential_revision is not None and secret["profile_revision"]!=initial.credential_revision:
                raise GatewayError("SNMP credential changed after the requested-metric test")
            with exporter(values, timeout_seconds=_remaining(deadline), requested_modules=initial.modules) as local_url:
                managed_params = [("target", f"{profile.snmp_transport}://{address}:{initial.port}"),
                    ("auth", "managed")] + [("module", name) for name in initial.modules]
                body = self._fetch(local_url + "/snmp?" + urlencode(managed_params), headers={"Accept": "text/plain"},
                    tls=TLSFiles(), deadline=deadline, maximum=config.max_metric_bytes, content_type="text/plain")
            if any(value.encode() in body for value in values.values() if value):
                raise GatewayError("Exporter echoed private credential material")
            values = secret = None
        else:
            body = self._fetch(url, headers=headers, tls=profile.exporter_tls, deadline=wire_deadline,
                maximum=config.max_metric_bytes, content_type="text/plain")
        if "Authorization" in headers and headers["Authorization"][7:].encode() in body:
            raise GatewayError("Exporter echoed private authorization material")
        text_body = body.decode("utf-8")
        # The family parser can accumulate a whole family before yielding.
        # Bound sample lines first, without allocating a list of every line,
        # so its first yield cannot allocate an unbounded repeated family.
        candidate_samples = 0
        for line in StringIO(text_body):
            _remaining(deadline)
            if len(line.rstrip("\r\n")) > 65536: raise GatewayError("Metric line exceeds its bound")
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                candidate_samples += 1
                if candidate_samples > config.max_samples:
                    raise GatewayError("Metric sample budget exceeded before parsing")
        samples = 0
        for family in text_string_to_metric_families(text_body):
            for sample in family.samples:
                samples += 1
                if (samples > config.max_samples or len(sample.labels) > 64
                        or any(len(key) > 128 or len(value) > 2048 for key, value in sample.labels.items())):
                    raise GatewayError("Metric sample or label budget exceeded")
            _remaining(deadline)
        if not samples: raise GatewayError("Exporter returned no metric samples")
        # Re-read protected config and current API intent after device I/O.
        # A moved/withdrawn/rotated target cannot publish stale metric bytes.
        current_config = self.config_loader()
        current = self._current_target(current_config, enrollment_id, deadline)
        current_material = self._exporter_custody(self._validate_target(current_config, current))
        excluded = {"issued_at", "expires_at"}
        if (initial.model_dump(exclude=excluded) != current.model_dump(exclude=excluded)
                or custody_snapshot != current_config.model_dump()
                or len(initial_material) != len(current_material)
                or any(left[0] != right[0] or not hmac.compare_digest(left[1], right[1])
                       for left, right in zip(initial_material, current_material))
                or initial.expires_at <= datetime.now(UTC)):
            raise GatewayError("Monitoring authority or custody changed during scrape")
        _remaining(deadline)
        return body


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, handler, gateway, concurrency):
        self.gateway = gateway
        self.capacity = threading.BoundedSemaphore(concurrency)
        if ipaddress.ip_address(address[0]).version == 6:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.capacity.acquire(blocking=False):
            try: request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            finally: self.shutdown_request(request)
            return
        try: super().process_request(request, client_address)
        except BaseException:
            self.capacity.release()
            raise

    def process_request_thread(self, request, client_address):
        try: super().process_request_thread(request, client_address)
        finally: self.capacity.release()


class GatewayHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)
        def expire_headers():
            try: self.connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        self.header_deadline = threading.Timer(5, expire_headers)
        self.header_deadline.daemon = True
        self.header_deadline.start()

    def finish(self):
        self.header_deadline.cancel()
        super().finish()

    def log_message(self, *_):
        pass  # Never retain request URLs, headers, upstream bodies or secrets.

    def do_GET(self):
        self.header_deadline.cancel()
        gateway = self.server.gateway
        try:
            config = gateway.config_loader()
            expected = "Bearer " + _token(config.prometheus_token_file, gateway.reader)
            provided = self.headers.get("Authorization", "")
            if not hmac.compare_digest(provided.encode(), expected.encode()):
                self.send_error(401, "Prometheus authentication required")
                return
            if self.path == "/discovery":
                try: payload = gateway.discovery()
                except Exception:
                    LOGGER.warning("monitoring_discovery_unavailable")
                    payload = []  # HTTP 200 clears Prometheus's last-good list.
                body = json.dumps(payload, separators=(",", ":")).encode()
                content_type = "application/json"
            elif self.path.startswith("/scrape/"):
                body = gateway.scrape(self.path[len("/scrape/"):])
                content_type = "text/plain; version=0.0.4; charset=utf-8"
            elif self.path == "/-/ready":
                # No cached readiness; the API/custody must work now.
                gateway.discovery()
                body, content_type = b"ready\n", "text/plain"
            else:
                self.send_error(404, "Unknown monitoring route")
                return
            current_config = gateway.config_loader()
            current_authorization = "Bearer " + _token(current_config.prometheus_token_file, gateway.reader)
            if not hmac.compare_digest(provided.encode(), current_authorization.encode()):
                self.send_error(401, "Prometheus authentication changed")
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            LOGGER.warning("monitoring_request_refused type=%s", type(exc).__name__)
            try: self.send_error(503, "Monitoring authority or upstream is unavailable")
            except OSError: pass


def main():
    parser = argparse.ArgumentParser(description="Database-free current-authority Prometheus gateway")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    def load():
        return GatewayConfig.model_validate_json(protected_read(args.config))
    try: config = load()
    except Exception as exc:
        parser.error(f"Unsafe or invalid monitoring gateway configuration ({type(exc).__name__})")
    gateway = MonitoringGateway(load)
    with GatewayServer((config.listen_address, config.port), GatewayHandler, gateway, config.max_concurrency) as server:
        server.serve_forever(poll_interval=.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
