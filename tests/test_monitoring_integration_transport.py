"""Network-free verification of the external monitoring HTTPS boundary."""
import io
import json
import socket
import ssl

import pytest

from icheck.config import get_settings
from icheck.monitoring_connectors import https_transport as wire
from icheck.monitoring_connectors.zabbix import ConnectorError

TOKEN = "fixture-only-zabbix-token"
ENDPOINT = "https://zabbix.example.test/zabbix/api_jsonrpc.php"


@pytest.fixture(autouse=True)
def clean_database():
    yield  # Pure transport tests must not initialize a database.


@pytest.fixture(autouse=True)
def policy(monkeypatch):
    monkeypatch.setenv("ICHECK_MONITORING_INTEGRATION_ALLOWED_ORIGINS", "https://zabbix.example.test")
    get_settings.cache_clear()
    monkeypatch.setattr(wire.socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail("Unexpected DNS"))
    monkeypatch.setattr(wire.socket, "create_connection", lambda *args, **kwargs: pytest.fail("Unexpected socket"))
    yield
    get_settings.cache_clear()


@pytest.mark.parametrize("url,expected", [
    ("https://ZABBIX.example.test:443/zabbix/", ENDPOINT),
    (ENDPOINT, ENDPOINT),
    ("https://zabbix.example.test", "https://zabbix.example.test/api_jsonrpc.php"),
    ("https://10.20.30.40:8443/monitor", "https://10.20.30.40:8443/monitor/api_jsonrpc.php"),
    ("https://[fd00::1]/", "https://[fd00::1]/api_jsonrpc.php"),
])
def test_endpoint_canonicalization_is_offline(url, expected):
    assert wire.canonical_endpoint(url) == expected


@pytest.mark.parametrize("url", [
    "http://zabbix.example.test", "https://user:secret@zabbix.example.test", "https://zabbix.example.test?token=x",
    "https://zabbix.example.test/#", "https://zabbix.example.test:0", "https://zabbix.example.test:65536",
    "https://zabbix.example.test:", "https://zabbix.example.test/../api_jsonrpc.php",
    "https://zabbix.example.test/%2e%2e", "https://zabbix.example.test/a//b", "https://zabbix.example.test\\@evil.test",
    "https://zabbix.example.test\n", "https://zabbix.example.test./", "https://127.0.0.1",
    "https://169.254.169.254", "https://[::1]", "https://[::ffff:192.0.2.1]", "https://224.0.0.1",
    "https://0.0.0.0", "https://[fe80::1]", "https://bad_host.test", "https://example.test/space here",
])
def test_reject_unsafe_endpoints(url):
    with pytest.raises(wire.EndpointError):
        wire.canonical_endpoint(url)


def test_allowlist_is_exact_origin_and_closed_by_default(monkeypatch):
    assert wire.approved_endpoint(ENDPOINT) == ENDPOINT
    for url in ("https://zabbix.example.test:8443", "https://other.example.test", "https://child.zabbix.example.test"):
        with pytest.raises(wire.EndpointError):
            wire.approved_endpoint(url)
    for policy in ("", "https://*.example.test", "https://zabbix.example.test/zabbix"):
        monkeypatch.setenv("ICHECK_MONITORING_INTEGRATION_ALLOWED_ORIGINS", policy)
        get_settings.cache_clear()
        with pytest.raises(wire.EndpointError):
            wire.approved_endpoint(ENDPOINT)


@pytest.mark.parametrize("addresses", [[], ["127.0.0.1"], ["10.10.1.2", "169.254.169.254"], ["::ffff:127.0.0.1"]])
def test_dns_rejects_any_disallowed_address(monkeypatch, addresses):
    monkeypatch.setattr(wire.socket, "getaddrinfo", lambda *a, **k:
                        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 443)) for addr in addresses])
    with pytest.raises(ConnectorError, match="source_address_rejected"):
        wire._resolve("zabbix.example.test", 443)


def test_dns_permits_private_approved_destination(monkeypatch):
    monkeypatch.setattr(wire.socket, "getaddrinfo", lambda *a, **k:
                        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.40", 443))])
    assert wire._resolve("zabbix.example.test", 443) == "10.20.30.40"


class Response:
    def __init__(self, body, *, status=200, headers=None):
        self.status = status
        self.body = io.BytesIO(body)
        self.headers = {"Content-Type": "application/json", **(headers or {})}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read1(self, size):
        return self.body.read(size)


@pytest.fixture
def network(monkeypatch):
    calls = []
    monkeypatch.setattr(wire, "_resolve", lambda h, p: "10.20.30.40")

    class Connection:
        response = Response(b'{"jsonrpc":"2.0","id":"fixture","result":"7.0.20"}')
        closed = False
        sock = None

        def __init__(self, host, port, address, timeout):
            calls.append({"host": host, "port": port, "address": address, "timeout": timeout})

        def request(self, method, path, *, body, headers):
            calls[-1].update(method=method, path=path, body=body, headers=headers)

        def getresponse(self):
            return self.response

        def close(self):
            Connection.closed = True

    monkeypatch.setattr(wire, "PinnedHTTPSConnection", Connection)
    return Connection, calls


def request(method="host.get", **bounds):
    return wire.ZabbixHTTPSTransport(ENDPOINT, TOKEN).request(
        {"jsonrpc": "2.0", "id": "fixture", "method": method, "params": {}},
        timeout_seconds=10, max_response_bytes=bounds.get("limit", 10000))


@pytest.mark.parametrize("method", ["apiinfo.version", "host.get", "problem.get", "item.get", "history.get"])
def test_only_authenticated_reads_send_token_and_never_in_body(network, method):
    connection, calls = network
    assert request(method)["result"] == "7.0.20"
    assert len(calls) == 1 and connection.closed
    call = calls[0]
    assert call["host"] == "zabbix.example.test" and call["address"] == "10.20.30.40"
    assert call["port"] == 443 and 0 < call["timeout"] <= 10
    assert call["method"] == "POST" and call["path"] == "/zabbix/api_jsonrpc.php"
    assert TOKEN.encode() not in call["body"]
    assert call["headers"].get("Authorization") == (None if method == "apiinfo.version" else "Bearer " + TOKEN)


def test_no_write_or_arbitrary_method_and_recheck_current_policy(network, monkeypatch):
    _, calls = network
    for method in ("host.create", "script.execute", "user.login", "arbitrary"):
        with pytest.raises(ConnectorError, match="unsupported_operation"):
            request(method)
    monkeypatch.setenv("ICHECK_MONITORING_INTEGRATION_ALLOWED_ORIGINS", "")
    get_settings.cache_clear()
    with pytest.raises(ConnectorError, match="source_endpoint_not_approved"):
        request()
    assert calls == []


@pytest.mark.parametrize("body,status,headers,code", [
    (b'{}', 302, {"Location": "https://evil.test"}, "source_http_rejected"),
    (b'private auth error', 401, {}, "source_http_rejected"),
    (b'{}', 200, {"Content-Encoding": "gzip"}, "source_encoding_rejected"),
    (b'{}', 200, {"Content-Type": "text/html"}, "invalid_source_response"),
    (b'{}', 200, {"Content-Length": "50000"}, "source_response_too_large"),
    (b'{}', 200, {"Content-Length": "3"}, "invalid_source_response"),
    (b'x' * 101, 200, {}, "source_response_too_large"),
    (b'{"result":NaN}', 200, {}, "invalid_source_response"),
    (b'{"result":1,"result":2}', 200, {}, "invalid_source_response"),
    (b'{}', 200, {"Transfer-Encoding": "gzip"}, "source_encoding_rejected"),
    (b'[]', 200, {}, "invalid_source_response"),
    (b'not json', 200, {}, "invalid_source_response"),
    (json.dumps({"error": TOKEN}).encode(), 200, {}, "source_secret_echo"),
    (json.dumps({"result": TOKEN}).replace("f", "\\u0066").encode(), 200, {}, "source_secret_echo"),
])
def test_transport_rejects_untrusted_responses_without_echo(network, body, status, headers, code):
    connection, calls = network
    connection.response = Response(body, status=status, headers=headers)
    with pytest.raises(ConnectorError, match=code) as error:
        request(limit=100)
    assert str(error.value) == code and TOKEN not in str(error.value)
    assert connection.closed and len(calls) == 1


def test_expired_budget_sends_nothing(network, monkeypatch):
    _, calls = network
    transport = wire.ZabbixHTTPSTransport(ENDPOINT, TOKEN)
    monkeypatch.setattr(wire.time, "monotonic", lambda: transport._deadline + 1)
    with pytest.raises(ConnectorError, match="source_timeout"):
        transport.request({"jsonrpc": "2.0", "id": "fixture", "method": "host.get", "params": {}},
                          timeout_seconds=10, max_response_bytes=100)
    assert calls == []


def test_one_budget_spans_multiple_rpc_requests(network, monkeypatch):
    connection, calls = network
    clock = [100.0]
    monkeypatch.setattr(wire.time, "monotonic", lambda: clock[0])
    transport = wire.ZabbixHTTPSTransport(ENDPOINT, TOKEN, budget_seconds=1)
    payload = {"jsonrpc": "2.0", "id": "fixture", "method": "apiinfo.version", "params": {}}
    assert transport.request(payload, timeout_seconds=10, max_response_bytes=100)["result"] == "7.0.20"
    clock[0] += 2
    with pytest.raises(ConnectorError, match="source_timeout"):
        transport.request({**payload, "method": "host.get"}, timeout_seconds=10, max_response_bytes=100)
    assert len(calls) == 1 and connection.closed


def test_tls_pins_address_but_verifies_original_identity(monkeypatch):
    calls = []
    sock = object()
    monkeypatch.setattr(wire.socket, "create_connection", lambda address, timeout: (calls.append((address, timeout)), sock)[1])
    connection = wire.PinnedHTTPSConnection("zabbix.example.test", 8443, "10.20.30.40", 5)
    assert connection._context.verify_mode == ssl.CERT_REQUIRED
    assert connection._context.check_hostname is True
    monkeypatch.setattr(connection._context, "wrap_socket", lambda value, server_hostname:
                        calls.append((value, server_hostname)) or value)
    connection.connect()
    assert calls == [(("10.20.30.40", 8443), 5), (sock, "zabbix.example.test")]


@pytest.mark.parametrize("error,code", [(ssl.SSLError("private detail"), "source_tls_failed"),
                                       (TimeoutError("private detail"), "source_timeout"),
                                       (OSError("private detail"), "source_unavailable")])
def test_network_errors_are_sanitized(network, monkeypatch, error, code):
    connection, _ = network
    def fail(self):
        raise error
    monkeypatch.setattr(connection, "getresponse", fail)
    with pytest.raises(ConnectorError, match=code) as result:
        request()
    assert str(result.value) == code and connection.closed
