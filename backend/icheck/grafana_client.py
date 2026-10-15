"""Bounded native HTTP adapter. No caller-selected routes, headers or secrets."""
import json
import os
from pathlib import Path
import stat
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import get_settings
from .credentials import SecretRedactor

MAX_BYTES = 2 * 1024 * 1024


class GrafanaError(ValueError):
    pass


class GrafanaConflict(GrafanaError):
    pass


class GrafanaOutcomeUnknown(GrafanaError):
    pass


def secret_key():
    settings = get_settings()
    path = settings.grafana_secret_key_file or settings.ai_managed_secret_key_file
    if not path or not Path(path).is_absolute():
        raise GrafanaError("Protected integration key storage is not configured")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) not in {0o400, 0o440}):
                raise GrafanaError("Integration key custody is unsafe")
            value = handle.read(33)
        if len(value) != 32:
            raise GrafanaError("Integration key is invalid")
        return value
    except OSError:
        raise GrafanaError("Protected integration key is unavailable") from None


def aad(connection):
    return json.dumps(["icheck.grafana-token/v1", connection.id, connection.tenant_id,
        connection.region_id, connection.api_url, connection.public_url, connection.datasource_uid,
        connection.folder_uid, connection.revision], separators=(",", ":")).encode()


def encrypt_token(connection, token):
    nonce = os.urandom(12)
    return b"\x01" + nonce + AESGCM(secret_key()).encrypt(nonce, token.encode(), aad(connection))


def decrypt_token(connection):
    try:
        raw = connection.encrypted_token
        if raw[:1] != b"\x01":
            raise ValueError()
        return AESGCM(secret_key()).decrypt(raw[1:13], raw[13:], aad(connection)).decode("ascii")
    except Exception:
        raise GrafanaError("Grafana token custody is unavailable or has changed") from None


def validate_urls(api_url, public_url):
    settings = get_settings()
    for value in (api_url, public_url):
        parsed = urlsplit(value)
        if (not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment
                or any(ord(char) < 33 or ord(char) == 127 for char in value)):
            raise GrafanaError("Connection URLs must not contain credentials, query parameters or control characters")
        try:
            port = parsed.port
            if port is not None and not 1 <= port <= 65535:
                raise ValueError()
        except ValueError:
            raise GrafanaError("Connection URL port is invalid") from None
    public = urlsplit(public_url)
    if public.scheme != "https":
        raise GrafanaError("Grafana browser access requires HTTPS")
    if api_url.rstrip("/") != "http://127.0.0.1:3001/grafana":
        parsed = urlsplit(api_url)
        allowed = [host.strip().lower() for host in settings.grafana_allowed_hosts.split(",") if host.strip()]
        if parsed.scheme != "https" or parsed.hostname.lower() not in allowed:
            raise GrafanaError("Use the native loopback Grafana endpoint or an explicitly allowed HTTPS host")
    return api_url.rstrip("/"), public_url.rstrip("/")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GrafanaClient:
    def __init__(self, connection):
        if not connection.enabled or not connection.shared_dataset_acknowledged:
            raise GrafanaError("Grafana connection is disabled or its shared data scope is not acknowledged")
        self.base, self.public = validate_urls(connection.api_url, connection.public_url)
        self.token = decrypt_token(connection)
        self.redactor = SecretRedactor()
        self.redactor.add(self.token)
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.deadline = time.monotonic() + 30

    def _request(self, route, *, method="GET", document=None, absent_ok=False):
        try:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise GrafanaError("Grafana operation exceeded its time budget")
            with self.opener.open(Request(self.base + route, method=method,
                headers={"Authorization": "Bearer " + self.token, "Accept": "application/json",
                         "Content-Type": "application/json"},
                data=None if document is None else json.dumps(document).encode()), timeout=min(15, remaining)) as response:
                raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                if method != "GET":
                    raise GrafanaOutcomeUnknown("Grafana write response exceeded its limit; inspect the planned UID")
                raise GrafanaError("Grafana response exceeds the bounded result size")
            text = raw.decode()
            if self.redactor.redact_text(text) != text:
                if method != "GET":
                    raise GrafanaOutcomeUnknown("Grafana write response exposed credential material; inspect the resource privately")
                raise GrafanaError("Grafana resource contains credential material; remove it before using the AI plugin")
            return json.loads(text)
        except HTTPError as error:
            status = error.code
            error.close()
            if status == 404 and absent_ok:
                return None
            if status in (409, 412):
                raise GrafanaConflict("Grafana changed; refresh the resource and review a new proposal") from None
            if method != "GET" and status >= 500:
                raise GrafanaOutcomeUnknown("Grafana write outcome is unknown; inspect the planned UID before retrying") from None
            raise GrafanaError("Grafana request failed (HTTP " + str(status) + ")") from None
        except (URLError, OSError, UnicodeError, json.JSONDecodeError):
            if method != "GET":
                raise GrafanaOutcomeUnknown("Grafana write response was lost; inspect the planned UID") from None
            raise GrafanaError("Grafana read failed; inspect connection, TLS and token permissions") from None

    def resource(self, kind, uid):
        return self._request(f"/apis/{kind}.grafana.app/v1/namespaces/default/{kind}s/{quote(uid, safe='')}", absent_ok=True)

    def list_resources(self, kind, limit=100):
        return self._request(f"/apis/{kind}.grafana.app/v1/namespaces/default/{kind}s?limit={min(limit, 100)}")

    def save(self, kind, document, *, existing):
        route = f"/apis/{kind}.grafana.app/v1/namespaces/default/{kind}s"
        if existing:
            route += "/" + quote(document["metadata"]["name"], safe="")
        return self._request(route, method="PUT" if existing else "POST", document=document)

    def health(self, datasource_uid):
        health = self._request("/api/health")
        source = self._request("/api/datasources/uid/" + quote(datasource_uid, safe="") + "/health")
        return {"version": health.get("version"), "database": health.get("database"),
                "datasource_status": source.get("status")}

    def metrics(self, datasource_uid):
        document = self._request("/api/datasources/proxy/uid/" + quote(datasource_uid, safe="") +
                                 "/api/v1/label/__name__/values")
        if document.get("status") != "success" or not isinstance(document.get("data"), list):
            raise GrafanaError("Prometheus metric discovery returned an invalid result")
        return document["data"]

    def query(self, datasource_uid, expression, limit):
        return self._request("/api/datasources/proxy/uid/" + quote(datasource_uid, safe="") +
            "/api/v1/query?" + urlencode({"query": expression, "timeout": "3s", "limit": limit + 1}))
