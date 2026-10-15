"""One adapter path: declarative template -> target test -> enrollment -> scrape.

Local HTTP fixtures are real wire tests, not claims of lab-device qualification.
No production service, model, exporter job or credential is touched.
"""
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import shutil
import ssl
import subprocess
import threading
import time

import pytest
from pydantic import ValidationError
from prometheus_client.parser import text_string_to_metric_families

from icheck.database import SessionLocal
from icheck.device_preflight_worker import DevicePreflightFailure, execute_device_preflight
from icheck.http_metrics import (HTTPMetricError, HTTPMonitorSpec, HTTPResult, auth_headers,
    extract_metrics, fetch_http, parse_curl, pointer, render_result, spec_hash)
from icheck.models import DeviceConnection, CredentialProfile, MetricBackend, utcnow
from icheck.monitoring_gateway import GatewayError, GatewayProfile
from icheck.monitoring_gateway import GatewayServer, GatewayHandler
from icheck.services import monitoring
from test_monitoring_gateway import gateway
from test_managed_device_credentials import device_key
from test_device_preflights import register_worker


def spec(**changes):
    return HTTPMonitorSpec.model_validate({"scheme": "http", "path": "/status", "metrics": [
        {"name": "vendor_queue_depth", "value_pointer": "/queue/depth"},
        {"name": "vendor_port_bytes_total", "type": "counter", "records_pointer": "/ports",
         "value_pointer": "/bytes", "labels": {"port": "/name"}}], **changes})


BODY = b'{"queue":{"depth":7},"ports":[{"name":"eth0","bytes":123},{"name":"eth1","bytes":456}]}'


@pytest.fixture
def endpoint():
    state = {"body": BODY, "status": 200, "content_type": "application/json", "calls": []}
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            state["calls"].append((self.path, self.headers.get("Authorization"), self.headers.get("Host")))
            body = state["body_factory"]() if state.get("body_factory") else state["body"]
            self.send_response(state["status"])
            self.send_header("Content-Type", state["content_type"])
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                if state.get("drip"):
                    for value in body:
                        self.wfile.write(bytes([value])); self.wfile.flush(); time.sleep(.02)
                else: self.wfile.write(body)
            except (OSError, ValueError): pass
        def log_message(self, *_): pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    yield server, state
    server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_real_http_json_numeric_metrics_and_no_response_in_evidence(endpoint):
    server, state = endpoint
    request = spec()
    result = fetch_http(request, "127.0.0.1", server.server_port, {}, deadline=time.monotonic() + 2)
    body, proof = render_result(request, result)
    samples = [sample for family in text_string_to_metric_families(body.decode()) for sample in family.samples]
    assert any(sample.name == "vendor_queue_depth" and sample.value == 7 for sample in samples)
    assert any(sample.name == "vendor_port_bytes_total" and sample.labels == {"port": "eth1"} and sample.value == 456 for sample in samples)
    assert proof["metric_samples"] == 3 and proof["success"] and proof["spec_hash"] == spec_hash(request)
    assert state["calls"][0][0] == "/status" and '"queue":' not in json.dumps(proof)


def test_unexpected_status_is_failure_even_when_gateway_can_be_scraped(endpoint):
    server, state = endpoint; state["status"] = 503
    result = fetch_http(spec(), "127.0.0.1", server.server_port, {}, deadline=time.monotonic() + 2)
    body, proof = render_result(spec(), result)
    assert not proof["success"] and proof["metric_samples"] == 0
    assert b"icheck_http_request_success 0" in body and b"vendor_queue_depth" not in body


def test_drip_response_connection_close_uses_total_deadline(endpoint):
    server, state = endpoint; state["drip"] = True
    started = time.monotonic()
    with pytest.raises(HTTPMetricError):
        fetch_http(spec(), "127.0.0.1", server.server_port, {}, deadline=started + .15)
    assert time.monotonic() - started < .8


def test_redirect_is_observed_not_followed(endpoint):
    server, state = endpoint; state["status"] = 302
    result = fetch_http(spec(), "127.0.0.1", server.server_port, {}, deadline=time.monotonic() + 2)
    assert result.status == 302 and len(state["calls"]) == 1


def test_real_https_account_authentication_certificate_and_ip_pin(endpoint, tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    server, state = endpoint
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.fixture.test")])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.fixture.test")]), critical=False)
        .sign(key, hashes.SHA256()))
    cert_file = tmp_path / "fixture.crt"; key_file = tmp_path / "fixture.key"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); key_file.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert_file, key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    request = spec(scheme="https", server_name="api.fixture.test", auth_mode="basic")
    values = {"username": "monitor", "password": "fixture-only-password"}
    headers = auth_headers(request, values)
    with pytest.raises(HTTPMetricError): fetch_http(request, "127.0.0.1", server.server_port, headers, deadline=time.monotonic() + 2)
    trusted = ssl.create_default_context(cafile=cert_file)
    result = fetch_http(request, "127.0.0.1", server.server_port, headers, deadline=time.monotonic() + 2, tls_context=trusted)
    body, proof = render_result(request, result, values=values, headers=headers)
    assert proof["tls_tested"] and proof["authentication_tested"] and result.tls_expiry > time.time()
    assert state["calls"][-1][1] == headers["Authorization"] and state["calls"][-1][2] == f"api.fixture.test:{server.server_port}"
    assert values["password"].encode() not in body
    with pytest.raises(HTTPMetricError):
        fetch_http(spec(scheme="https", server_name="wrong.fixture.test"), "127.0.0.1", server.server_port, {}, deadline=time.monotonic() + 2, tls_context=trusted)


@pytest.mark.parametrize("command", ["curl -k https://example.test", "curl -L https://example.test",
    "curl -u user:private-password https://example.test", "curl -H 'Authorization: private-token' https://example.test",  # gitleaks:allow -- synthetic rejection fixtures
    "curl -d '{}' https://example.test", "curl https://user:private-password@example.test",
    "curl https://example.test/?token=private-token", "curl $(id)", "curl https://example.test & id"])
def test_curl_subset_rejects_secrets_mutation_and_shell_execution(command):
    with pytest.raises(ValueError) as error: parse_curl(command)
    assert "private-password" not in str(error.value) and "private-token" not in str(error.value)


def test_curl_is_data_with_query_separators_and_json_pointer_escapes():
    parsed = parse_curl("curl -sSf -H 'Accept: application/json' 'https://api.example.test:8443/stats?a=1&b=2'")
    assert parsed["request"]["path"] == "/stats?a=1&b=2" and parsed["port"] == 8443
    assert parsed["request"]["mode"] == "probe"
    assert pointer({"a/b": {"~value": 3}}, "/a~1b/~0value") == 3
    with pytest.raises(HTTPMetricError): pointer([1], "/00")


@pytest.mark.parametrize("body", [b'{"queue":{"depth":true}}', b'{"queue":{"depth":"7"}}',
    b'{"queue":{"depth":NaN}}', b'{"queue":{"depth":1,"depth":2}}',
    json.dumps({"queue": {"depth": 10**400}}).encode(), b'{}'])
def test_api_missing_boolean_nonfinite_ambiguous_and_huge_numbers_fail(body):
    with pytest.raises(HTTPMetricError): extract_metrics(spec(), body)


def test_credentials_series_labels_and_sample_budgets_are_not_exported():
    with pytest.raises(ValidationError): spec(metrics=[{"name": "vendor_value", "value_pointer": "/token"}])
    with pytest.raises(ValidationError): spec(metrics=[{"name": "vendor_value", "value_pointer": "/x", "labels": {"job": "/name"}}])
    with pytest.raises(ValidationError): spec(metrics=[{"name": "vendor_count", "type": "counter", "value_pointer": "/x"}])
    with pytest.raises(HTTPMetricError): extract_metrics(spec(), BODY, max_samples=2)
    with pytest.raises(HTTPMetricError): render_result(spec(), HTTPResult(BODY + b'private-password', 200, .1, content_type="application/json"), values={"password": "private-password"})
    assert auth_headers(spec(auth_mode="basic", scheme="https"), {"username": "monitor", "password": "test-only"})["Authorization"].startswith("Basic ")
    escaped = b'{"queue":{"depth":7},"ports":[{"name":"test-\\u006fnly", "bytes":1}]}'
    with pytest.raises(HTTPMetricError): render_result(spec(), HTTPResult(escaped, 200, .1, content_type="application/json"), values={"password": "test-only"})


def setup_http(client, *, profile=None, **changes):
    request = spec(**changes)
    response = client.post("/api/v1/assets/devices", json={"name": "API fixture", "kind": "other", "management_ip": "198.18.1.10", "site": "LAB", "created_by": "lab.admin", "connections": [{"protocol": "https_api"}]})
    assert response.status_code == 201, response.text
    device = response.json(); connection = device["connections"][0]
    base = f"/api/v1/assets/devices/{device['id']}/connections/{connection['id']}"
    response = client.patch(base + "/http-configuration", json={"expected_revision": device["revision"], "port": 8080 if request.scheme == "http" else 443,
        "http_monitor": request.model_dump(), "credential_profile_ref": profile["id"] if profile else None,
        "actor": "lab.admin", "reason": "Configure read-only API measurement template."})
    assert response.status_code == 200, response.text
    device = response.json()
    return device, connection, base, request


def enrolled_http(client, **changes):
    device, connection, base, request = setup_http(client, **changes)
    _, proof = render_result(request, HTTPResult(BODY, 200, .01, content_type="application/json"))
    proof.update(check="http_metric_query", target_host=device["management_ip"], target_port=8080 if request.scheme == "http" else 443,
        credential_revision=changes.get("profile", {}).get("revision") if changes.get("profile") else None)
    with SessionLocal() as db:
        c = db.get(DeviceConnection, connection["id"]); c.verification_status = "verified"; c.last_verified_at = utcnow(); c.last_verification_evidence = proof; db.commit()
    preview = client.get(base + "/monitoring").json()
    response = client.post(base + "/monitoring/approve", json={"expected_revision": 0, "preview_hash": preview["preview_hash"], "gateway_profile": "lab-readonly", "actor": "lab.admin", "reason": "Enable this tested read-only API template."})
    assert response.status_code == 200, response.text
    return device, connection, base, request, response.json()


def http_gateway(config):
    config.profiles["lab-readonly"] = GatewayProfile.model_validate({"protocol": "https_api", "sites": ["LAB"],
        "allowed_targets": ["198.18.1.0/24"], "allowed_ports": [8080, 443], "credential_profile_ids": [None],
        "allow_managed_http_credentials": True, "allow_insecure_http": True, "allowed_http_paths": ["/status"]})


def test_transport_only_cannot_approve_and_curl_preview_has_no_echo(client):
    _, connection, base, request = setup_http(client)
    with SessionLocal() as db:
        c = db.get(DeviceConnection, connection["id"]); c.verification_status = "verified"; c.last_verified_at = utcnow(); c.last_verification_evidence = {"check": "tcp_connect"}; db.commit()
    preview = client.get(base + "/monitoring").json()
    assert not preview["eligible"] and "Test" in preview["blockers"][0]
    bad = client.post("/api/v1/assets/http-monitor/preview-request", json={"curl": "curl -u user:private-password https://example.test"})  # gitleaks:allow -- synthetic rejection fixture
    assert bad.status_code == 422 and "private-password" not in bad.text
    bad = client.post("/api/v1/assets/http-monitor/preview-request", json={"curl": "curl https://example.test", "password": "private-password"})
    assert bad.status_code == 422 and "private-password" not in bad.text


def test_http_discovery_scrape_and_withdraw_during_io(client, gateway, monkeypatch):
    subject, config, opener = gateway; http_gateway(config)
    _, _, base, request, enrollment = enrolled_http(client)
    assert len(subject.discovery()) == 1
    def fetch(spec, host, port, headers, **kwargs):
        assert spec == request and host == "198.18.1.10" and port == 8080 and not headers
        return HTTPResult(BODY, 200, .01, content_type="application/json")
    monkeypatch.setattr("icheck.monitoring_gateway.fetch_http", fetch)
    assert b"vendor_queue_depth 7" in subject.scrape(enrollment["id"])
    def withdrawn(*args, **kwargs):
        assert client.post(base + "/monitoring/withdraw", json={"expected_revision": 1, "actor": "lab.admin", "reason": "Withdraw during the HTTP fixture scrape."}).status_code == 200
        return fetch(*args, **kwargs)
    monkeypatch.setattr("icheck.monitoring_gateway.fetch_http", withdrawn)
    with pytest.raises(GatewayError): subject.scrape(enrollment["id"])
    assert subject.discovery() == []


@pytest.mark.parametrize("change", ["path", "network", "port", "site", "tls"])
def test_http_protected_custody_rejects_before_target_io(client, gateway, monkeypatch, change):
    subject, config, opener = gateway; http_gateway(config)
    _, _, _, _, enrollment = enrolled_http(client)
    p = config.profiles["lab-readonly"]
    if change == "path": p.allowed_http_paths = ["/other"]
    elif change == "network": p.allowed_targets = ["203.0.113.0/24"]
    elif change == "port": p.allowed_ports = [443]
    elif change == "site": p.sites = ["OTHER"]
    else: p.allow_insecure_http = False
    monkeypatch.setattr("icheck.monitoring_gateway.fetch_http", lambda *args, **kwargs: pytest.fail("Denied target must never be contacted"))
    assert subject.discovery() == []
    with pytest.raises(GatewayError): subject.scrape(enrollment["id"])


def test_protected_http_path_prefix_allows_custom_vendor_api_without_core_edit(client, gateway):
    subject, config, opener = gateway; http_gateway(config)
    device, connection, base, request, enrollment = enrolled_http(client, path="/api/vendor/stats?a=1&b=2")
    config.profiles["lab-readonly"].allowed_http_paths = ["/api/*"]
    assert len(subject.discovery()) == 1
    config.profiles["lab-readonly"].allowed_http_paths = ["/other/*"]
    assert subject.discovery() == []


def test_http_template_edit_queues_test_and_withdraws_old_enrollment(client):
    device, connection, base, request, enrollment = enrolled_http(client)
    body = {"expected_revision": device["revision"], "port": 8080, "http_monitor": spec(path="/revised").model_dump(), "actor": "lab.admin", "reason": "Revise the requested API path and retest."}
    response = client.patch(base + "/http-configuration", json=body)
    assert response.status_code == 200, response.text
    assert response.json()["connections"][0]["verification_status"] == "pending"
    assert client.get("/api/v1/monitoring/targets").json()["targets"] == []
    assert client.patch(base + "/http-configuration", json=body).status_code == 409
    events = client.get("/api/v1/audit-events", params={"event_type": "device.connection.http_configuration.updated"}).json()
    assert any(event["details"].get("previous_template", {}).get("path") == "/status" for event in events if event["details"].get("previous_template"))


def test_http_credential_rotation_fences_proof_and_preserves_old_protocol_hash(client, device_key):
    p = client.post("/api/v1/device-credentials", json={"kind": "http_basic", "name": "api-account", "site": "LAB", "username": "monitor", "password": "test-only-password"}).json()
    device, connection, base, request, enrollment = enrolled_http(client, profile=p, scheme="https", auth_mode="basic")
    with SessionLocal() as db:
        row = db.get(CredentialProfile, p["id"]); legacy = monitoring._credential_fingerprint(row); http = monitoring._credential_fingerprint(row, include_revision=True)
        row.revision += 1; db.commit()
        assert monitoring._credential_fingerprint(row) == legacy
        assert monitoring._credential_fingerprint(row, include_revision=True) != http
    assert not client.get(base + "/monitoring").json()["currently_authorized"]
    assert client.get("/api/v1/monitoring/targets").json()["targets"] == []


def test_http_health_uses_request_failure_not_exporter_up(client):
    from icheck.monitoring_schemas import MonitoringTarget
    from icheck.services.asset_health import _samples
    from icheck.services.control_plane_auth import development_principal
    device, connection, base, request, enrollment = enrolled_http(client)
    target = MonitoringTarget.model_validate(client.get("/api/v1/monitoring/targets").json()["targets"][0])
    principal = development_principal(); now = utcnow()
    labels = {"icheck_device_id": device["id"], "icheck_connection_id": connection["id"], "icheck_enrollment_id": enrollment["id"],
        "icheck_enrollment_revision": "1", "icheck_tenant_id": principal.tenant_id, "icheck_region_id": principal.region_id}
    document = [{"metric": {**labels, "icheck_health_field": "up"}, "value": [now.timestamp(), "0"]},
        {"metric": {**labels, "icheck_health_field": "observed_at"}, "value": [now.timestamp(), str(now.timestamp())]}]
    result = _samples(document, [target], principal, now)[device["id"]][0]
    assert result["state"] == "poll_failed" and result["source"] == "Prometheus HTTP request success"


def test_real_target_test_is_not_tcp_only_and_missing_mapping_fails(endpoint):
    server, state = endpoint
    assignment = {"target_host": "127.0.0.1", "port": server.server_port, "adapter_type": "http_json", "configuration": {"http_monitor": spec().model_dump()}}
    args = {"allowed_targets": ["127.0.0.1/32"], "timeout_seconds": 2, "snmp_exporter_url": None, "exporter_allowed_hosts": [], "snmp_allowed_targets": [], "lease_seconds": 15}
    proof, _ = execute_device_preflight(assignment, **args)
    assert proof["check"] == "http_metric_query" and proof["metric_samples"] == 3 and proof["verified"]
    state["body"] = b'{}'
    with pytest.raises(DevicePreflightFailure): execute_device_preflight(assignment, **args)


def test_worker_test_completion_rejects_transport_proof(client):
    device, connection, base, request = setup_http(client)
    worker, headers = register_worker(client, name="http-fixture", site="LAB", capabilities=["http_json"])
    claim = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim", headers=headers, json={"max_assignments": 1, "lease_seconds": 60}).json()[0]
    path = f"/api/v1/collector-workers/{worker['id']}/device-preflights/{claim['preflight_id']}/complete"
    bad = client.post(path, headers=headers, json={"lease_token": claim["lease_token"], "status": "verified", "evidence": {"check": "tcp_connect"}})
    assert bad.status_code == 409
    _, proof = render_result(request, HTTPResult(BODY, 200, .01, content_type="application/json"))
    proof.update(check="http_metric_query", target_host=claim["target_host"], target_port=claim["port"])
    good = client.post(path, headers=headers, json={"lease_token": claim["lease_token"], "status": "verified", "evidence": proof})
    assert good.status_code == 200, good.text
    assert client.get(base + "/monitoring").json()["eligible"]


def test_managed_http_lease_and_worker_metric_test_do_not_expose_account(client, device_key, monkeypatch):
    from icheck.collector_worker import run_device_preflight
    values = {"username": "monitor", "password": "fixture-only-password"}
    response = client.post("/api/v1/device-credentials", json={"name": "api-account", "kind": "http_basic", "site": "LAB", **values})
    assert response.status_code == 201
    p = response.json()
    device, connection, base, request = setup_http(client, profile=p, scheme="https", auth_mode="basic")
    worker, headers = register_worker(client, name="http-account-fixture", site="LAB", capabilities=["http_json"])
    claim = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim", headers=headers, json={"max_assignments": 1, "lease_seconds": 60}).json()[0]
    lease_path = f"/api/v1/collector-workers/{worker['id']}/device-preflights/{claim['preflight_id']}/managed-credential"
    assert client.post(lease_path, headers=headers, json={"lease_token": "incorrect-long-enough-token"}).status_code == 409
    lease = client.post(lease_path, headers=headers, json={"lease_token": claim["lease_token"]})
    assert lease.status_code == 200 and lease.json()["values"] == values and lease.headers["cache-control"] == "no-store"
    def transport(spec, host, port, request_headers, **kwargs):
        assert request_headers == auth_headers(request, values) and host == device["management_ip"] and port == 443
        return HTTPResult(BODY, 200, .01, content_type="application/json")
    monkeypatch.setattr("icheck.device_preflight_worker.fetch_http", transport)
    class WorkerClient:
        def request(self, method, path, body):
            reply = client.request(method, path, headers=headers, json=body)
            assert reply.status_code == 200, reply.text
            return reply.json()
    assert run_device_preflight(WorkerClient(), worker["id"], claim, allowed_targets=["198.18.1.0/24"], timeout_seconds=2,
        snmp_exporter_url=None, exporter_allowed_hosts=[], snmp_allowed_targets=[], lease_seconds=60)
    assert "_runtime" not in claim
    current = client.get(f"/api/v1/assets/devices/{device['id']}")
    assert values["password"] not in current.text and client.get(base + "/monitoring").json()["eligible"]
    assert values["password"] not in client.get("/api/v1/audit-events").text


def test_only_configured_gateway_service_can_resolve_http_enrollment(client, device_key, monkeypatch):
    from icheck.auth import current_principal
    from icheck.config import get_settings
    from icheck.main import app
    from icheck.services.control_plane_auth import development_principal, PrincipalContext
    from icheck.database import DEFAULT_TENANT_ID, DEFAULT_REGION_ID
    p = client.post("/api/v1/device-credentials", json={"name": "api-token", "kind": "https_token", "site": "LAB", "token": "fixture-only-api-token"}).json()
    device, connection, base, request, enrollment = enrolled_http(client, profile=p, scheme="https", auth_mode="bearer")
    path = f"/api/v1/monitoring/enrollments/{enrollment['id']}/managed-credential"
    monkeypatch.setenv("ICHECK_MANAGED_MONITORING_GATEWAY_SUBJECT", "gateway.fixture"); get_settings.cache_clear()
    service = PrincipalContext(principal_id="test-service", subject="gateway.fixture", principal_type="service", auth_method="bearer",
        role_names=("collector",), permissions=frozenset({"assets.read"}), authorization_scope={"sites": ["LAB"]},
        tenant_id=DEFAULT_TENANT_ID, region_id=DEFAULT_REGION_ID)
    try:
        assert client.get(path).status_code == 403
        app.dependency_overrides[current_principal] = lambda: service
        good = client.get(path)
        assert good.status_code == 200 and good.json()["values"] == {"token": "fixture-only-api-token"} and good.headers["cache-control"] == "no-store"
        assert good.json()["profile_revision"] == 1
        app.dependency_overrides.pop(current_principal)
        assert client.post(base + "/monitoring/withdraw", json={"expected_revision": 1, "actor": "lab.admin", "reason": "Withdraw the test API monitoring enrollment."}).status_code == 200
        app.dependency_overrides[current_principal] = lambda: service
        assert client.get(path).status_code == 404
    finally:
        app.dependency_overrides.pop(current_principal, None); get_settings.cache_clear()


@pytest.mark.parametrize("native_template", [False, True])
def test_private_prometheus_collects_fresh_numeric_api_samples(client, gateway, endpoint, monkeypatch, tmp_path, native_template):
    binary = os.environ.get("ICHECK_HTTP_MONITORING_PROMETHEUS_BINARY")
    if not binary: pytest.skip("Set an existing native Prometheus binary for the private integration path")
    assert Path(binary).is_file()
    from urllib.request import urlopen
    subject, config, opener = gateway; http_gateway(config)
    server, state = endpoint
    actual_fetch = fetch_http
    def fixture_transport(spec, host, port, headers, **kwargs):
        # Explicit test-only routing. Production still rejects loopback targets.
        assert host == "198.18.1.10" and port == 8080
        return actual_fetch(spec, "127.0.0.1", server.server_port, headers, **kwargs)
    monkeypatch.setattr("icheck.monitoring_gateway.fetch_http", fixture_transport)
    native = None
    if native_template:
        from dataclasses import replace
        from icheck.auth import current_principal
        from icheck.main import app
        from icheck.services.control_plane_auth import development_principal
        from test_http_monitoring_studio import draft, target, complete, enable_payload
        app.dependency_overrides[current_principal] = lambda: replace(development_principal(), principal_type="user", auth_method="bearer", subject="test.admin")
        try:
            doc, native_path, _, _ = draft(client, monkeypatch)
            queued, payload = target(client, native_path, doc)
            monkeypatch.setattr("icheck.device_preflight_worker.fetch_http", fixture_transport)
            complete(client, queued, payload, executor=lambda claim: execute_device_preflight(claim,
                allowed_targets=["198.18.1.0/24"], timeout_seconds=2, snmp_exporter_url=None,
                exporter_allowed_hosts=[], snmp_allowed_targets=[], lease_seconds=60))
            tested = client.get(native_path + "/monitoring/state", params={key: payload[key] for key in ("artifact_version_id", "device_id", "connection_id")}).json()
            response = client.post(native_path + "/monitoring/enable", json={**enable_payload(tested, payload), "gateway_profile": "lab-readonly", "schedule_seconds": 15, "timeout_seconds": 1})
            assert response.status_code == 200, response.text
            enrollment = response.json()["monitoring"]["enrollment"]
            device = {"id": payload["device_id"]}; native = (doc, native_path, payload)
        finally: app.dependency_overrides.pop(current_principal, None)
    else:
        device, connection, base, request, enrollment = enrolled_http(client)
    gateway_server = GatewayServer(("127.0.0.1", 0), GatewayHandler, subject, 2)
    thread = threading.Thread(target=gateway_server.serve_forever, daemon=True); thread.start()
    config.port = gateway_server.server_port
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0)); port = reserved.getsockname()[1]
    config_file = tmp_path / "prometheus.yml"
    config_file.write_text(f'''global:
  scrape_interval: 1s
scrape_configs:
  - job_name: icheck_continuous
    scrape_interval: 1s
    scrape_timeout: 800ms
    authorization:
      credentials: private-prometheus-token
    http_sd_configs:
      - url: http://127.0.0.1:{config.port}/discovery
        refresh_interval: 1s
        authorization:
          credentials: private-prometheus-token
''')
    process = subprocess.Popen([binary, "--config.file=" + str(config_file), "--storage.tsdb.path=" + str(tmp_path / "tsdb"),
        "--storage.tsdb.retention.time=1h", "--web.listen-address=127.0.0.1:" + str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        start = time.time(); end = time.monotonic() + 35; samples = []
        while time.monotonic() < end:
            assert process.poll() is None, "Private Prometheus failed to start"
            try:
                with urlopen(f"http://127.0.0.1:{port}/api/v1/query?query=vendor_queue_depth", timeout=1) as response:
                    samples = json.load(response)["data"]["result"]
                if samples: break
            except OSError: pass
            time.sleep(.1)
        if not samples:
            with urlopen(f"http://127.0.0.1:{port}/api/v1/targets", timeout=1) as response:
                active = json.load(response)["data"]["activeTargets"]
            pytest.fail("Private fixture collection absent: " + json.dumps({"targets": len(active),
                "health": [row["health"] for row in active], "errors": [row["lastError"] for row in active],
                "fixture_requests": len(state["calls"]), "discovered": len(subject.discovery())}))
        assert samples[0]["metric"]["icheck_device_id"] == device["id"]
        assert samples[0]["metric"]["icheck_enrollment_id"] == enrollment["id"]
        assert float(samples[0]["value"][1]) == 7 and float(samples[0]["value"][0]) >= start
        with urlopen(f"http://127.0.0.1:{port}/api/v1/query?query=timestamp(vendor_queue_depth)", timeout=1) as response:
            assert float(json.load(response)["data"]["result"][0]["value"][1]) >= start
        from icheck.services.asset_health import _health_expression
        from urllib.parse import urlencode
        with urlopen(f"http://127.0.0.1:{port}/api/v1/query?" + urlencode({"query": _health_expression(device["id"])}), timeout=1) as response:
            health = json.load(response)
        assert health["status"] == "success"
        by_field = {sample["metric"]["icheck_health_field"]: float(sample["value"][1]) for sample in health["data"]["result"]}
        assert by_field["up"] == 1 and by_field["observed_at"] >= start
        if native:
            from icheck.services import monitoring_templates
            from icheck.services.control_plane_auth import development_principal
            with SessionLocal() as db:
                backend = MetricBackend(name="native-private-proof", provider="prometheus", query_base_url="https://prometheus.example.test",
                    external_labels={}, enabled=True, created_by="test")
                db.add(backend); db.commit()
            def actual_query(db, backend, payload, **kwargs):
                with urlopen(f"http://127.0.0.1:{port}/api/v1/query?" + urlencode({"query": payload.query}), timeout=3) as response:
                    result = json.load(response)
                assert result["status"] == "success", result
                from types import SimpleNamespace
                return SimpleNamespace(result_type=result["data"]["resultType"], result=result["data"]["result"])
            monkeypatch.setattr("icheck.services.metrics.query_instant", actual_query)
            with SessionLocal() as db:
                doc, _, payload = native
                proof = monitoring_templates.verify_samples(db, development_principal(), doc["id"], doc["artifact_version_id"],
                    payload["device_id"], payload["connection_id"], backend.id)
                assert proof["fresh_samples_verified"], proof
                assert proof["stage"] == "collecting" and any(item["name"] == "vendor_queue_depth" for item in proof["metric_evidence"])
        assert state["calls"], "Prometheus must receive adapter bytes from the actual fixture HTTP endpoint"
    finally:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        gateway_server.shutdown(); gateway_server.server_close(); thread.join(timeout=2)
        shutil.rmtree(tmp_path / "tsdb", ignore_errors=True)  # Test-only WAL, after its process has exited.
