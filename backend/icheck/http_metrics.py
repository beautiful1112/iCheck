"""Declarative read-only HTTP/API adapter producing Prometheus text, not SQL samples.

The caller owns network/credential authorization. Requests connect to a pinned
device IP; optional certificate/Host names never select another network address.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import http.client
import ipaddress
import json
import math
import re
import shlex
import socket
import ssl
import threading
import time
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

SENSITIVE = re.compile(r"password|token|secret|authorization|credential|community|private[_-]?key|api[_-]?key", re.I)
RESERVED = {"job", "instance", "site", "le", "quantile"}


class HTTPMetricError(ValueError):
    """Static diagnostics only; no response text, URLs, credentials or headers."""


def pointer_tokens(value):
    if not isinstance(value, str) or len(value) > 512 or (value and not value.startswith("/")) or value.count("/") > 32:
        raise HTTPMetricError("Use a bounded JSON Pointer starting with /, or an empty root pointer")
    if re.search(r"~(?![01])", value) or any(ord(c) < 32 for c in value):
        raise HTTPMetricError("JSON Pointer contains an invalid escape or control character")
    tokens = [token.replace("~1", "/").replace("~0", "~") for token in value.split("/")[1:]] if value else []
    if any(SENSITIVE.search(token) for token in tokens):
        raise HTTPMetricError("Credential fields cannot be exported as metrics or labels")
    return tokens


def pointer(document, path):
    value = document
    for token in pointer_tokens(path):
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", token) and int(token) < len(value):
            value = value[int(token)]
        else:
            raise HTTPMetricError("A declared API metric or label is absent; revise its JSON Pointer")
    return value


class HTTPMetric(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    help: str = Field(default="API measurement", min_length=1, max_length=255)
    type: Literal["gauge", "counter"] = "gauge"
    records_pointer: str | None = None
    value_pointer: str
    labels: dict[str, str] = Field(default_factory=dict, max_length=8)

    @model_validator(mode="after")
    def valid(self):
        if self.name.startswith(("icheck_", "__")) or SENSITIVE.search(self.name):
            raise HTTPMetricError("Metric name is reserved or credential-like")
        if self.type == "counter" and not self.name.endswith("_total"):
            raise HTTPMetricError("Counter metric names must end with _total")
        if any(ord(c) < 32 and c != "\n" or ord(c) == 127 for c in self.help):
            raise HTTPMetricError("Metric help contains a control character")
        for value in [self.value_pointer, *(self.labels.values()), *([self.records_pointer] if self.records_pointer is not None else [])]:
            pointer_tokens(value)
        for key in self.labels:
            if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key) or key.startswith(("icheck_", "__"))
                    or key in RESERVED or SENSITIVE.search(key)):
                raise HTTPMetricError("Metric label is reserved, unsafe or credential-like")
        return self


class HTTPMonitorSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    contract: Literal["icheck.http-monitor/v1"] = "icheck.http-monitor/v1"
    mode: Literal["api", "probe"] = "api"
    scheme: Literal["https", "http"] = "https"
    method: Literal["GET", "HEAD"] = "GET"
    path: str = Field(default="/", min_length=1, max_length=2048)
    server_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
    auth_mode: Literal["none", "bearer", "basic", "api_key"] = "none"
    credential_header: str = Field(default="X-API-Key", pattern=r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
    expected_statuses: list[int] = Field(default_factory=lambda: [200], min_length=1, max_length=20)
    max_records: int = Field(default=200, ge=1, le=2000)
    max_response_bytes: int = Field(default=1000000, ge=1, le=2000000)
    metrics: list[HTTPMetric] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def valid(self):
        parsed = urlsplit(self.path)
        if (not self.path.startswith("/") or self.path.startswith("//") or parsed.scheme or parsed.netloc or parsed.fragment
                or any(ord(c) < 33 or ord(c) == 127 for c in self.path)
                or any(SENSITIVE.search(key) or key.lower() in {"key", "sig", "signature"} for key, _ in parse_qsl(parsed.query))):
            raise HTTPMetricError("Use a credential-free absolute request path, without an origin or fragment")
        if self.credential_header.lower() in {"host", "cookie", "connection", "content-length", "transfer-encoding", "proxy-authorization", "authorization"}:
            raise HTTPMetricError("API-key header is not allowed")
        if (any(status < 100 or status > 599 for status in self.expected_statuses)
                or len(set(self.expected_statuses)) != len(self.expected_statuses)):
            raise HTTPMetricError("Expected HTTP statuses must be distinct valid status codes")
        if self.mode == "api" and (self.method != "GET" or not self.metrics):
            raise HTTPMetricError("API metric templates need GET and at least one explicit numeric mapping")
        if self.mode == "probe" and self.metrics:
            raise HTTPMetricError("HTTP probe templates do not declare JSON metric mappings")
        if len({metric.name for metric in self.metrics}) != len(self.metrics):
            raise HTTPMetricError("Metric names must be distinct")
        if len({metric.name.removesuffix("_total") if metric.type == "counter" else metric.name for metric in self.metrics}) != len(self.metrics):
            raise HTTPMetricError("Metric family names must not collide after counter normalization")
        return self


def spec_hash(spec):
    return hashlib.sha256(json.dumps(spec.model_dump(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def parse_curl(command):
    """Parse a small GET/HEAD subset as data. Never execute a shell or retain auth."""
    if not isinstance(command, str) or len(command) > 8192 or any(char in command for char in ("\n", "\r", "`", "$", "|", ";", "<", ">")):
        raise HTTPMetricError("Curl input must be one bounded command without shell operators or substitution")
    try:
        args = shlex.split(command)
    except ValueError:
        raise HTTPMetricError("Curl input has invalid quoting") from None
    if not args or args.pop(0) != "curl":
        raise HTTPMetricError("Provide a curl GET/HEAD request, not a shell script")
    url, method = None, "GET"
    while args:
        option = args.pop(0)
        if re.fullmatch(r"-[sSfI]+", option):
            if "I" in option: method = "HEAD"
            continue
        if option in {"-s", "--silent", "-S", "--show-error", "-f", "--fail"}:
            continue
        if option in {"-I", "--head"}:
            method = "HEAD"; continue
        if option in {"-X", "--request", "--url"}:
            if not args: raise HTTPMetricError("Curl option needs a value")
            value = args.pop(0)
            if option == "--url":
                if url: raise HTTPMetricError("Use exactly one URL")
                url = value
            elif value in {"GET", "HEAD"}: method = value
            else: raise HTTPMetricError("Only GET and HEAD are supported; mutating requests need a separate workflow")
        elif option in {"-H", "--header"}:
            if not args: raise HTTPMetricError("Curl header needs a value")
            name, separator, value = args.pop(0).partition(":")
            if not separator or name.lower() != "accept" or value.strip() not in {"application/json", "*/*"}:
                raise HTTPMetricError("Only a non-secret Accept header is supported; choose authentication in the protected credential selector")
        elif option.startswith("-"):
            raise HTTPMetricError("Unsupported curl option; redirects, insecure TLS, credentials, uploads and files are not accepted")
        elif url is None: url = option
        else: raise HTTPMetricError("Use exactly one URL")
    parsed = urlsplit(url or "")
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.fragment or any(ord(c) < 33 for c in (url or ""))):
        raise HTTPMetricError("Curl needs one credential-free HTTP(S) URL")
    try: port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError: raise HTTPMetricError("Invalid URL port") from None
    if not 1 <= port <= 65535: raise HTTPMetricError("Invalid URL port")
    try:
        spec = HTTPMonitorSpec(mode="probe", scheme=parsed.scheme, method=method,
            path=(parsed.path or "/") + ("?" + parsed.query if parsed.query else ""))
    except ValueError:
        raise HTTPMetricError("Curl request path is invalid or credential-bearing") from None
    return {"host": parsed.hostname, "port": port, "request": spec.model_dump()}


def auth_headers(spec, values):
    if spec.auth_mode == "none": return {}
    values = values or {}
    if spec.auth_mode == "basic":
        username, password = values.get("username"), values.get("password")
        if (not isinstance(username, str) or not isinstance(password, str) or not username or not password
                or ":" in username or any(ord(c) < 32 or ord(c) == 127 for c in username + password)):
            raise HTTPMetricError("A valid protected username/password reference is required")
        value = "Basic " + base64.b64encode((username + ":" + password).encode()).decode()
        return {"Authorization": value}
    token = values.get("token")
    if not isinstance(token, str) or not token or any(ord(c) < 33 or ord(c) == 127 for c in token):
        raise HTTPMetricError("A valid protected API token reference is required")
    return {spec.credential_header: token} if spec.auth_mode == "api_key" else {"Authorization": "Bearer " + token}


def _escape(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _json(body):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result: raise HTTPMetricError("API JSON contains ambiguous duplicate keys")
            result[key] = value
        return result
    try:
        return json.loads(body, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(HTTPMetricError("API JSON contains a non-finite number")))
    except (ValueError, UnicodeError, RecursionError):
        raise HTTPMetricError("API response is not bounded, unambiguous JSON") from None


def extract_metrics(spec, body, *, max_samples=20000, forbidden_values=()):
    if len(body) > spec.max_response_bytes:
        raise HTTPMetricError("API response exceeded its byte budget")
    document = _json(body)
    lines, identities = [], set()
    for metric in spec.metrics:
        records = pointer(document, metric.records_pointer) if metric.records_pointer is not None else [document]
        if not isinstance(records, list) or not 1 <= len(records) <= spec.max_records:
            raise HTTPMetricError("API record count is absent or exceeds its template limit")
        lines.extend(["# HELP " + metric.name + " " + metric.help.replace("\\", "\\\\").replace("\n", "\\n"), "# TYPE " + metric.name + " " + metric.type])
        for record in records:
            value = pointer(record, metric.value_pointer)
            try: finite = isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
            except OverflowError: finite = False
            if not finite or (metric.type == "counter" and value < 0):
                raise HTTPMetricError("API measurement must be a finite numeric value, and counters cannot be negative")
            labels = {}
            for key, path in metric.labels.items():
                label = pointer(record, path)
                if (isinstance(label, bool) or not isinstance(label, (str, int)) or len(str(label)) > 128
                        or any(ord(char) < 32 or ord(char) == 127 for char in str(label))):
                    raise HTTPMetricError("API label is not a bounded safe scalar")
                if any(value in str(label) for value in forbidden_values):
                    raise HTTPMetricError("API label echoed credential material; no data is exported")
                labels[key] = str(label)
            identity = (metric.name, tuple(sorted(labels.items())))
            if identity in identities: raise HTTPMetricError("API mappings would emit duplicate metric series")
            identities.add(identity)
            if len(identities) > max_samples:
                raise HTTPMetricError("API mappings exceeded their sample budget")
            suffix = "{" + ",".join(key + '=\"' + _escape(item) + '\"' for key, item in sorted(labels.items())) + "}" if labels else ""
            lines.append(metric.name + suffix + " " + str(value))
    return "\n".join(lines) + "\n", sorted({metric.name for metric in spec.metrics}), len(identities)


@dataclass
class HTTPResult:
    body: bytes
    status: int
    seconds: float
    tls_expiry: float | None = None
    content_type: str = ""


def fetch_http(spec, host, port, headers, *, deadline, tls_context=None):
    address = str(ipaddress.ip_address(host))
    timeout = deadline - time.monotonic()
    if timeout <= 0: raise HTTPMetricError("HTTP test deadline expired")
    name = spec.server_name or address
    connection = (http.client.HTTPSConnection(name, port, timeout=timeout, context=tls_context or ssl.create_default_context())
        if spec.scheme == "https" else http.client.HTTPConnection(name, port, timeout=timeout))
    # Preserve TLS SNI/certificate and Host validation, but connect only to the
    # caller-authorized IP. DNS cannot redirect this request or rebind it.
    def pinned_connect(unused, timeout, source_address=None):
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise HTTPMetricError("HTTP request deadline expired")
        sock = socket.create_connection((address, port), min(timeout, remaining), source_address)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            sock.close()
            raise HTTPMetricError("HTTP request deadline expired")
        sock.settimeout(remaining)  # TLS handshake consumes the same total budget.
        return sock
    connection._create_connection = pinned_connect
    started = time.monotonic()
    transport = [None]
    def expire():
        sock = transport[0] or connection.sock
        if sock is not None:
            try: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
    timer = threading.Timer(max(0, deadline - time.monotonic()), expire)
    timer.daemon = True
    try:
        timer.start(); connection.connect()
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise HTTPMetricError("HTTP request deadline expired")
        connection.sock.settimeout(remaining)
        transport[0] = connection.sock  # HTTPConnection may clear .sock on Connection: close.
        certificate = connection.sock.getpeercert() if spec.scheme == "https" else {}
        expiry = ssl.cert_time_to_seconds(certificate["notAfter"]) if certificate.get("notAfter") else None
        connection.request(spec.method, spec.path, headers={"Accept": "application/json" if spec.mode == "api" else "*/*", "Cache-Control": "no-cache", **headers})
        response = connection.getresponse()
        body = response.read(spec.max_response_bytes + 1) if spec.method == "GET" else b""
        if len(body) > spec.max_response_bytes or time.monotonic() >= deadline:
            raise HTTPMetricError("HTTP response exceeded its byte or elapsed-time budget")
        return HTTPResult(body, response.status, time.monotonic() - started, expiry, response.getheader("Content-Type", "").split(";", 1)[0].strip().lower())
    except (OSError, http.client.HTTPException, ValueError):
        raise HTTPMetricError("HTTP request failed; inspect target policy, TLS and protected authentication") from None
    finally:
        timer.cancel(); connection.close()


def render_result(spec, result, *, values=None, headers=None, max_samples=20000, max_bytes=10000000):
    if len(result.body) > spec.max_response_bytes:
        raise HTTPMetricError("HTTP response exceeded its byte budget")
    forbidden = [value for key, value in (values or {}).items() if key != "username" and value]
    forbidden.extend((headers or {}).values())
    authorization = (headers or {}).get("Authorization")
    if authorization: forbidden.append(authorization.partition(" ")[2])
    if any(value.encode() in result.body for value in forbidden):
        raise HTTPMetricError("HTTP response echoed credential material; no data is exported")
    success = result.status in spec.expected_statuses
    extra, names, samples = "", [], 0
    if success and spec.mode == "api":
        if result.content_type != "application/json" and not result.content_type.endswith("+json"):
            raise HTTPMetricError("API metric response must be JSON")
        extra, names, samples = extract_metrics(spec, result.body, max_samples=max(0, max_samples - 4), forbidden_values=forbidden)
    metrics = {"icheck_http_request_success": int(success), "icheck_http_status_code": result.status,
               "icheck_http_request_duration_seconds": result.seconds}
    if result.tls_expiry is not None: metrics["icheck_http_tls_expiry_timestamp_seconds"] = result.tls_expiry
    text = "".join("# TYPE " + name + " gauge\n" + name + " " + str(value) + "\n" for name, value in metrics.items()) + extra
    body = text.encode()
    if len(body) > max_bytes: raise HTTPMetricError("HTTP metrics exceeded their byte budget")
    return body, {"success": success, "metric_names": names, "metric_samples": samples,
        "spec_hash": spec_hash(spec), "status_code": result.status, "latency_ms": round(result.seconds * 1000),
        "tls_tested": spec.scheme == "https", "authentication_tested": spec.auth_mode != "none"}
