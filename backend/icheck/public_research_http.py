"""Credential-free public HTTPS reads, with pinned DNS and bounded responses.

This is deliberately not the device HTTP gateway. Model-selected URLs cannot
reach loopback, private networks, cloud metadata or ambient authenticated proxies.
"""
import http.client
import ipaddress
import re
import socket
import ssl
import time
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit


class ResearchUnavailable(ValueError):
    def __init__(self, message, *, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def public_url(value: str) -> str:
    if not isinstance(value, str) or not 10 <= len(value) <= 2048 or re.search(r"[\s\\\x00-\x1f\x7f]", value):
        raise ResearchUnavailable("Research requires a bounded public HTTPS URL")
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        if (parsed.scheme != "https" or parsed.port not in {None, 443} or parsed.username
                or parsed.password or not host or not re.fullmatch(r"[a-z0-9.-]+", host)
                or "." not in host or host.endswith((".local", ".internal", ".localhost", ".test", ".invalid"))):
            raise ValueError()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not _public(address):
            raise ValueError()
        if re.search(r"(?:token|password|secret|api[_-]?key|signature|credential|authorization)=", unquote(value), re.I):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ResearchUnavailable("Research URL must be public HTTPS without credentials or signed parameters") from None
    return urlunsplit(("https", host, parsed.path or "/", parsed.query, ""))


def _public(address):
    return address.is_global and not address.is_multicast and not address.is_reserved


def public_addresses(host):
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
        if not addresses or any(not _public(ipaddress.ip_address(address)) for address in addresses):
            raise ResearchUnavailable("Research host does not resolve exclusively to public addresses")
        return addresses
    except (OSError, ValueError):
        raise ResearchUnavailable("Public research host resolution failed") from None


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, address, timeout):
        super().__init__(host, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        # Connect to the validated address, preserving original Host/SNI and
        # certificate verification. There is no second DNS lookup to rebind.
        sock = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def fetch(url, *, timeout=12, maximum=1_000_000, headers=None, redirects=3):
    current = public_url(url)
    deadline = time.monotonic() + timeout
    for hop in range(redirects + 1):
        parsed = urlsplit(current)
        addresses = public_addresses(parsed.hostname)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ResearchUnavailable("Public research request timed out")
        connection = PinnedHTTPSConnection(parsed.hostname, addresses[0], remaining)
        try:
            connection.request("GET", urlunsplit(("", "", parsed.path, parsed.query, "")), headers={
                "User-Agent": "iCheck-Research/0.1 (+public-documentation)",
                "Accept": "text/html,text/plain,application/json,application/xml,application/rss+xml",
                "Accept-Encoding": "identity", **(headers or {}),
            })
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                if hop == redirects or headers:
                    raise ResearchUnavailable("Research redirect limit reached or authenticated redirect refused")
                current = public_url(urljoin(current, response.getheader("Location", "")))
                continue
            if response.status != 200:
                raise ResearchUnavailable(f"Public research returned HTTP {response.status}", status_code=response.status)
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise ResearchUnavailable("Compressed research responses are not supported")
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type not in {"text/html", "text/plain", "text/markdown", "application/json",
                                     "application/xml", "text/xml", "application/rss+xml", "application/xhtml+xml"}:
                raise ResearchUnavailable("Research source is not a supported text document")
            chunks, size = [], 0
            while size <= maximum:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ResearchUnavailable("Public research request timed out")
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(8192, maximum + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                chunks.append(chunk)
            if size > maximum:
                raise ResearchUnavailable("Public research document exceeds the size limit")
            return current, content_type, b"".join(chunks)
        except (OSError, http.client.HTTPException):
            raise ResearchUnavailable("Public research transport failed") from None
        finally:
            connection.close()
    raise ResearchUnavailable("Public research redirect limit reached")
