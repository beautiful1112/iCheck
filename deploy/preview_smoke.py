"""Read-only Preview v0.1 API smoke check. Never creates or enrolls lab devices."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import ssl
import stat
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

MAX_BODY = 2 * 1024 * 1024
READS = {
    "devices": ("/assets/devices?limit=1", list),
    "interfaces": ("/assets/interfaces?limit=1&sample_limit=100", dict),
    "terminals": ("/endpoints?limit=1", list),
    "alerts": ("/alerts?limit=1", list),
    "alert_rules": ("/alert-rules", list),
    "ai_providers": ("/ai/providers?limit=1", list),
    "ai_models": ("/ai/models?limit=1", list),
    "ai_routes": ("/ai/routes?limit=1", list),
    "tools": ("/agent/tools?limit=1", list),
    "investigations": ("/agent/investigations?limit=1", list),
    "artifacts": ("/artifacts?limit=1", list),
    "topology_views": ("/topology/views?limit=1", list),
    "collector_health": ("/collectors/health", dict),
}


class SmokeError(ValueError):
    """Only fixed, non-secret diagnostic messages may escape this boundary."""


def api_base(value: str, allow_loopback_http: bool = False) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
        loopback = bool(parsed.hostname and ipaddress.ip_address(parsed.hostname).is_loopback)
    except ValueError:
        # A DNS name is valid for HTTPS, never for the HTTP exception.
        try:
            parsed = urlsplit(value)
            port = parsed.port
            loopback = False
        except ValueError:
            raise SmokeError("Invalid API address") from None
    if (not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.path.rstrip("/") != "/api/v1"
            or any(ord(char) < 33 or ord(char) == 127 for char in value)
            or (parsed.scheme != "https" and not
                (parsed.scheme == "http" and allow_loopback_http and loopback))
            or (port is not None and not 1 <= port <= 65535)):
        raise SmokeError("API must be credential-free HTTPS ending in /api/v1; explicit literal-loopback HTTP is test-only")
    return value.rstrip("/")


def read_token(path: Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077
                    or info.st_uid not in {0, os.geteuid()} or info.st_nlink != 1):
                raise SmokeError("Token file must be a private, owned regular file with a single link")
            raw = handle.read(4097)
    except OSError:
        raise SmokeError("Unable to securely open the token file") from None
    if len(raw) > 4096:
        raise SmokeError("Token file exceeds the supported size")
    try:
        token = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise SmokeError("Token file must contain one ASCII access token") from None
    if not token or any(not 33 <= ord(char) <= 126 for char in token):
        raise SmokeError("Token file must contain one ASCII access token")
    return token


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class API:
    def __init__(self, base: str, token: str, *, ca_file: str | None = None, timeout: int = 10):
        self.base, self.token, self.timeout = base, token, timeout
        self.opener = build_opener(ProxyHandler({}), NoRedirect(),
                                   HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))

    def get(self, path: str, *, authenticated: bool = True):
        if not path.startswith("/") or path.startswith("//") or "#" in path:
            raise SmokeError("Invalid relative API path")
        headers = {"Accept": "application/json"}
        if authenticated:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            with self.opener.open(Request(self.base + path, headers=headers, method="GET"), timeout=self.timeout) as response:
                body = response.read(MAX_BODY + 1)
                if response.status != 200 or len(body) > MAX_BODY:
                    raise SmokeError("API response status or size is invalid")
                return json.loads(body)
        except HTTPError as exc:
            code = exc.code
            exc.close()
            raise SmokeError(f"API request returned HTTP {code}") from None
        except (URLError, OSError, UnicodeError, json.JSONDecodeError):
            raise SmokeError("API request failed transport or JSON validation") from None


def smoke(api: API) -> dict:
    checks = []
    health = api.get("/health", authenticated=False)
    if not isinstance(health, dict) or health.get("status") != "ok":
        raise SmokeError("API health is not ready")
    checks.append("health")
    try:
        api.get("/assets/devices?limit=1", authenticated=False)
    except SmokeError as exc:
        if str(exc) not in {"API request returned HTTP 401", "API request returned HTTP 403"}:
            raise SmokeError("Required authentication could not be verified") from None
    else:
        raise SmokeError("Unauthenticated inventory was accepted; required authentication is missing")
    checks.append("required_authentication")
    for name, (path, expected) in READS.items():
        if not isinstance(api.get(path), expected):
            raise SmokeError(f"Unexpected response shape for {name}")
        checks.append(name)
    return {"format_version": "icheck.engineering-preview-smoke/v1", "passed": True,
            "checks": checks, "read_only": True, "live_device_acceptance": False}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--api", required=True, help="Credential-free HTTPS URL ending in /api/v1")
    result.add_argument("--token-file", required=True, type=Path)
    result.add_argument("--ca-file")
    result.add_argument("--allow-loopback-http", action="store_true")
    result.add_argument("--timeout", type=int, choices=range(1, 31), default=10)
    return result


def main():
    args = parser().parse_args()
    try:
        api = API(api_base(args.api, args.allow_loopback_http), read_token(args.token_file),
                  ca_file=args.ca_file, timeout=args.timeout)
        print(json.dumps(smoke(api), sort_keys=True))
    except (SmokeError, OSError, ssl.SSLError):
        # Never print URLs, response bodies, token values or TLS exception text.
        print(json.dumps({"passed": False, "error": "Preview smoke check failed; inspect auth, permissions, TLS and API availability"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
