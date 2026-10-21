"""Pinned, verified HTTPS to explicitly approved on-prem monitoring origins.

No ambient proxy, redirects, arbitrary methods or caller-supplied headers. Private
addresses are supported only behind the exact administrator-approved origin.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from urllib.parse import urlsplit

from ..config import get_settings
from .zabbix import ConnectorError, MAX_RESPONSE_BYTES, _READ_METHODS


class EndpointError(ValueError):
    pass


def _parts(value: str):
    if (not isinstance(value, str) or not value or len(value) > 2048
            or not value.isascii() or re.search(r"[\s\\%\x00-\x1f\x7f]", value)):
        raise EndpointError("Use an absolute HTTPS endpoint without escapes or whitespace")
    try:
        parts = urlsplit(value)
        host, port = parts.hostname, parts.port if parts.port is not None else 443
    except ValueError:
        raise EndpointError("Invalid monitoring endpoint") from None
    if (parts.scheme != "https" or not host or parts.username is not None
            or parts.password is not None or "?" in value or "#" in value
            or not 1 <= port <= 65535 or parts.netloc.endswith(":")):
        raise EndpointError("Monitoring endpoints require HTTPS without credentials, query or fragment")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if (len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                   for label in host.split("."))):
            raise EndpointError("Invalid monitoring hostname") from None
    else:
        if not _allowed_address(address):
            raise EndpointError("Local, link-local and special-use endpoints are not allowed")
    authority = f"[{host}]" if ":" in host else host
    if port != 443:
        authority += f":{port}"
    origin = "https://" + authority
    return parts, host, port, origin


def _allowed_address(address):
    # IPv4-mapped IPv6 and translation/tunnel ranges must not bypass IPv4 checks.
    if isinstance(address, ipaddress.IPv6Address) and (
        address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None
    ):
        return False
    if (address.is_loopback or address.is_link_local or address.is_multicast
            or address.is_unspecified or address.is_reserved):
        return False
    private_networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
    return address.is_global or any(address in ipaddress.ip_network(network) for network in private_networks)


def canonical_endpoint(value: str, provider: str = "zabbix") -> str:
    parts, _, _, origin = _parts(value)
    path = parts.path.rstrip("/")
    if (not re.fullmatch(r"(?:/[A-Za-z0-9_.-]+)*", path)
            or any(segment in {".", ".."} for segment in path.split("/"))):
        raise EndpointError("Use a simple API base path without traversal or encoded segments")
    if provider == "solarwinds_orion":
        suffix = "/SolarWinds/InformationService/v3/Json/Query"
        if path not in {"", suffix, suffix.removesuffix("/Query")}:
            raise EndpointError("Use the SolarWinds SWIS origin or v3 JSON Query endpoint")
        path = suffix
    elif provider == "rest_webhook":
        if not path:
            raise EndpointError("The connector bridge requires an explicit API path")
    elif provider != "zabbix":
        raise EndpointError("Unsupported monitoring provider")
    elif not path.endswith("/api_jsonrpc.php"):
        path += "/api_jsonrpc.php"
    return origin + path


def approved_endpoint(value: str, provider: str = "zabbix") -> str:
    endpoint = canonical_endpoint(value, provider)
    origin = _parts(endpoint)[3]
    approved = set()
    for item in get_settings().monitoring_integration_allowed_origins.split(","):
        if not item.strip():
            continue
        parts, _, _, candidate = _parts(item.strip())
        if parts.path not in {"", "/"}:
            raise EndpointError("Monitoring origin allowlist must contain origins, not paths")
        approved.add(candidate)
    if origin not in approved:
        raise EndpointError("Monitoring origin is not approved by the server administrator")
    return endpoint


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self):
        # DNS is resolved once by the caller; certificate identity remains the
        # original hostname, not the chosen IP. Never retry another destination.
        sock = socket.create_connection((self._address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def _resolve(host, port):
    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses or any(not _allowed_address(ipaddress.ip_address(value)) for value in addresses):
        raise ConnectorError("source_address_rejected")
    return addresses[0]


def _reject_constant(_):
    raise ValueError("Non-finite JSON number")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _no_secret_echo(value, token):
    # Check decoded strings too, so JSON escape sequences cannot hide a token.
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str) and token in item:
            raise ConnectorError("source_secret_echo")
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


class ZabbixHTTPSTransport:
    provider = "zabbix"

    def __init__(self, endpoint: str, token: str, *, budget_seconds: int = 30):
        self._endpoint = endpoint
        self._token = token
        self._deadline = time.monotonic() + min(max(budget_seconds, 1), 30)

    def request(self, payload, *, timeout_seconds, max_response_bytes):
        try:
            return self._request(payload, timeout_seconds, max_response_bytes)
        except ConnectorError:
            raise
        except EndpointError:
            raise ConnectorError("source_endpoint_not_approved") from None
        except (TimeoutError, socket.timeout):
            raise ConnectorError("source_timeout") from None
        except ssl.SSLError:
            raise ConnectorError("source_tls_failed") from None
        except Exception:
            raise ConnectorError("source_unavailable") from None

    def _prepare(self, payload):
        if (set(payload) != {"jsonrpc", "id", "method", "params"}
                or payload.get("method") not in _READ_METHODS or payload.get("jsonrpc") != "2.0"):
            raise ConnectorError("unsupported_operation")
        return payload, None if payload["method"] == "apiinfo.version" else "Bearer " + self._token

    def _path(self, payload, path):
        return path

    def _document(self, document):
        return document

    def _secrets(self):
        return [self._token]

    def _request(self, payload, timeout_seconds, max_response_bytes):
        original = payload
        payload, authorization = self._prepare(payload)
        endpoint = approved_endpoint(self._endpoint, self.provider)  # Recheck current egress policy.
        parts, host, port, _ = _parts(endpoint)
        deadline = min(self._deadline, time.monotonic() + min(max(timeout_seconds, 1), 30))

        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                raise ConnectorError("source_timeout")
            return value

        remaining()
        address = _resolve(host, port)
        connection = PinnedHTTPSConnection(host, port, address, remaining())
        try:
            body = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
            if len(body) > 64_000 or any(secret in body.decode("utf-8") for secret in self._secrets()):
                raise ConnectorError("invalid_source_request")
            headers = {"Content-Type": "application/json", "Accept": "application/json",
                       "Accept-Encoding": "identity", "Connection": "close"}
            if authorization:
                headers["Authorization"] = authorization
            connection.request("POST", self._path(original, parts.path), body=body, headers=headers)
            sock = connection.sock
            if sock:
                sock.settimeout(remaining())
            response = connection.getresponse()
            if response.status != 200:
                raise ConnectorError("source_http_rejected")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise ConnectorError("source_encoding_rejected")
            if response.getheader("Transfer-Encoding", "chunked").lower() != "chunked":
                raise ConnectorError("source_encoding_rejected")
            if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() not in {
                "application/json", "application/json-rpc",
            }:
                raise ConnectorError("invalid_source_response")
            limit = min(max(max_response_bytes, 1), MAX_RESPONSE_BYTES)
            length = response.getheader("Content-Length")
            if length is not None and (not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > limit):
                raise ConnectorError("source_response_too_large")
            data = bytearray()
            while True:
                timeout = remaining()
                if sock:
                    sock.settimeout(timeout)
                chunk = response.read1(min(8192, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise ConnectorError("source_response_too_large")
            remaining()
            if length is not None and len(data) != int(length):
                raise ConnectorError("invalid_source_response")
            try:
                document = json.loads(data.decode("utf-8"), parse_constant=_reject_constant,
                                      object_pairs_hook=_unique_object)
            except (ValueError, RecursionError):
                raise ConnectorError("invalid_source_response") from None
            document = self._document(document)
            if not isinstance(document, dict):
                raise ConnectorError("invalid_source_response")
            for secret in self._secrets():
                _no_secret_echo(document, secret)
            return document
        finally:
            connection.close()


class OrionHTTPSTransport(ZabbixHTTPSTransport):
    provider = "solarwinds_orion"

    def _prepare(self, payload):
        # Query strings are compiled from fixed internal templates, never accepted
        # from the API, AI, uploaded packages or source responses.
        from .orion import compile_query
        return compile_query(payload), "Basic " + self._token

    def _path(self, payload, path):
        if payload.get("operation") == "suppression":
            return path.removesuffix("/Query") + "/Invoke/Orion.AlertSuppression/GetAlertSuppressionState"
        return path

    def _document(self, document):
        return {"results": document} if isinstance(document, list) else document

    def _secrets(self):
        import base64
        decoded = base64.b64decode(self._token, validate=True).decode("utf-8")
        return [self._token, decoded, decoded.split(":", 1)[1]]


class BridgeHTTPSTransport(ZabbixHTTPSTransport):
    provider = "rest_webhook"

    def _prepare(self, payload):
        from .bridge import BridgeRequest
        request = BridgeRequest.model_validate(payload)
        return request.model_dump(mode="json"), "Bearer " + self._token
