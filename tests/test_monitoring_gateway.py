from datetime import datetime, UTC, timedelta
from email.message import Message
from io import BytesIO
import json
from pathlib import Path
import threading
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

import pytest

from icheck.monitoring_gateway import (GatewayConfig, GatewayError, GatewayHandler, GatewayServer,
    MonitoringGateway, protected_read)
from icheck.models import DeviceMonitoringEnrollment
from icheck.database import SessionLocal, DEFAULT_TENANT_ID, DEFAULT_REGION_ID
from test_monitoring_enrollments import seeded, approve


class Response:
    def __init__(self, body, *, content_type="application/json", status=200):
        self.stream = BytesIO(body)
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        self.status = status
    def getcode(self): return self.status
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def read(self, maximum): return self.stream.read(maximum)


class Opener:
    def __init__(self, client):
        self.client = client
        self.requests = []
        self.before_wire = None
        self.after_wire = None
        self.body = b"# TYPE ifOperStatus gauge\nifOperStatus{ifIndex=\"1\"} 1\n"
        self.api_fault = False
        self.mutate_snapshot = None
    def open(self, request, *, timeout):
        self.requests.append(request)
        parsed = urlsplit(request.full_url)
        if parsed.hostname == "control.example.test":
            if self.api_fault: raise RuntimeError("Private API diagnostic must not be emitted")
            response = self.client.get(parsed.path, headers=dict(request.header_items()))
            body = response.content
            if self.mutate_snapshot and parsed.path.endswith("/targets"):
                document = response.json()
                self.mutate_snapshot(document)
                body = json.dumps(document).encode()
            return Response(body, status=response.status_code)
        if self.before_wire: self.before_wire()
        if self.after_wire: self.after_wire()
        return Response(self.body, content_type="text/plain")


@pytest.fixture
def gateway(client, tmp_path):
    api_token = tmp_path / "api-token"
    prometheus_token = tmp_path / "prometheus-token"
    for path, value in [(api_token, "private-api-read-token"), (prometheus_token, "private-prometheus-token")]:
        path.write_text(value)
        path.chmod(0o600)
    config = GatewayConfig.model_validate({
        "tenant_id": DEFAULT_TENANT_ID, "region_id": DEFAULT_REGION_ID,
        "api_base_url": "https://control.example.test", "api_token_file": str(api_token),
        "prometheus_token_file": str(prometheus_token), "profiles": {"lab-readonly": {
            "protocol": "snmp", "sites": ["LAB"], "allowed_targets": ["198.18.1.0/24"],
            "allowed_ports": [161], "credential_profile_ids": [None], "allowed_modules": ["if_mib"],
            "snmp_exporter_url": "http://127.0.0.1:9116/snmp", "snmp_auth_name": "protected_lab_v3",
        }},
    })
    opener = Opener(client)
    subject = MonitoringGateway(lambda: config, reader=lambda *args, **kwargs: protected_read(*args, require_root=False, **kwargs), opener=opener)
    return subject, config, opener


def approved(client):
    _, _, _, path = seeded(client)
    response = approve(client, path)
    assert response.status_code == 200, response.text
    return response.json(), path


def test_gui_approval_discovers_continuous_scrape_with_exact_custody_and_no_secrets(client, gateway):
    subject, config, opener = gateway
    enrollment, path = approved(client)
    groups = subject.discovery()
    assert len(groups) == 1
    assert groups[0]["labels"]["__metrics_path__"] == "/scrape/" + enrollment["id"]
    assert groups[0]["labels"]["instance"] == "198.18.1.10:161"
    assert groups[0]["labels"]["__scrape_interval__"] == "30s"
    assert "private-" not in json.dumps(groups) and "protected_lab_v3" not in json.dumps(groups)
    assert subject.scrape(enrollment["id"]) == opener.body
    outbound = [request for request in opener.requests if urlsplit(request.full_url).hostname == "127.0.0.1"]
    assert len(outbound) == 1
    query = parse_qs(urlsplit(outbound[0].full_url).query)
    assert query == {"target": ["udp://198.18.1.10:161"], "module": ["if_mib"], "auth": ["protected_lab_v3"]}
    assert outbound[0].get_header("Authorization") is None
    # A restarted gateway has no persisted targets or retained authority cache.
    restarted = MonitoringGateway(subject.config_loader, reader=subject.reader, opener=opener)
    assert len(restarted.discovery()) == 1
    withdrawn = client.post(path + "/withdraw", json={"expected_revision": 1,
        "actor": "lab.admin", "reason": "Withdraw this exact continuous scrape approval."})
    assert withdrawn.status_code == 200
    assert subject.discovery() == [] and restarted.discovery() == []
    sent = len(outbound)
    with pytest.raises(GatewayError): subject.scrape(enrollment["id"])
    assert len([r for r in opener.requests if urlsplit(r.full_url).hostname == "127.0.0.1"]) == sent


@pytest.mark.parametrize("change", ["site", "network", "port", "credential", "modules"])
def test_protected_custody_mismatch_never_contacts_device(client, gateway, change):
    subject, config, opener = gateway
    enrollment, _ = approved(client)
    profile = config.profiles["lab-readonly"]
    if change == "site": profile.sites = ["OTHER"]
    elif change == "network": profile.allowed_targets = ["203.0.113.0/24"]
    elif change == "port": profile.allowed_ports = [1161]
    elif change == "credential": profile.credential_profile_ids = ["another-profile"]
    else: profile.allowed_modules = ["other_mib"]
    assert subject.discovery() == []
    with pytest.raises(GatewayError): subject.scrape(enrollment["id"])
    assert all(urlsplit(request.full_url).hostname == "control.example.test" for request in opener.requests)


def test_withdrawal_during_remote_io_discards_metrics(client, gateway):
    subject, config, opener = gateway
    enrollment, path = approved(client)
    def revoke():
        response = client.post(path + "/withdraw", json={"expected_revision": 1,
            "actor": "lab.admin", "reason": "Withdraw during the bounded remote scrape."})
        assert response.status_code == 200, response.text
    opener.after_wire = revoke
    with pytest.raises(GatewayError): subject.scrape(enrollment["id"])
    assert subject.discovery() == []


@pytest.mark.parametrize("mutation", ["foreign_namespace", "expired", "duplicate"])
def test_untrusted_snapshot_cannot_publish_foreign_expired_or_duplicate_targets(client, gateway, mutation):
    subject, config, opener = gateway
    approved(client)
    def change(document):
        if mutation == "foreign_namespace": document["tenant_id"] = "00000000-0000-0000-0000-000000000099"
        elif mutation == "expired": document["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        else: document["targets"].append(document["targets"][0])
    opener.mutate_snapshot = change
    with pytest.raises(GatewayError): subject.discovery()


@pytest.mark.parametrize("kind", ["bytes", "samples", "empty", "invalid"])
def test_metrics_remain_byte_sample_and_parse_bounded(client, gateway, kind):
    subject, config, opener = gateway
    enrollment, _ = approved(client)
    if kind == "bytes":
        config.max_metric_bytes = 1024
        opener.body = b"a" * 1025
    elif kind == "samples":
        config.max_samples = 1
        opener.body = b"metric_a 1\nmetric_b 2\n"
    elif kind == "empty": opener.body = b"# no samples\n"
    else: opener.body = b"bad metric not-a-number\n"
    with pytest.raises((GatewayError, ValueError)): subject.scrape(enrollment["id"])


def test_repeated_metric_family_exceeds_budget_before_parser_allocation(client, gateway, monkeypatch):
    subject, config, opener = gateway
    enrollment, _ = approved(client)
    config.max_samples = 1
    opener.body = b'# TYPE repeated gauge\nrepeated{item="a"} 1\nrepeated{item="b"} 2\n'
    def forbidden_parser(_):
        raise AssertionError("An oversized family must never reach the accumulating parser")
    monkeypatch.setattr("icheck.monitoring_gateway.text_string_to_metric_families", forbidden_parser)
    with pytest.raises(GatewayError, match="before parsing"): subject.scrape(enrollment["id"])


def test_actual_gateway_http_discovery_authentication_and_api_failure_clear_targets(client, gateway):
    subject, config, opener = gateway
    approved(client)
    server = GatewayServer(("127.0.0.1", 0), GatewayHandler, subject, 2)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        with pytest.raises(HTTPError) as denied: urlopen(origin + "/discovery", timeout=3)
        assert denied.value.code == 401
        request = Request(origin + "/discovery", headers={"Authorization": "Bearer private-prometheus-token"})
        with urlopen(request, timeout=3) as response:
            assert response.headers.get_content_type() == "application/json"
            assert len(json.load(response)) == 1
        opener.api_fault = True
        with urlopen(request, timeout=3) as response:
            assert response.status == 200 and json.load(response) == []
        with pytest.raises(HTTPError) as refused:
            urlopen(Request(origin + "/-/ready", headers={"Authorization": "Bearer private-prometheus-token"}), timeout=3)
        assert refused.value.code == 503
        assert b"Private API diagnostic" not in refused.value.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_secret_file_permissions_symlinks_and_plaintext_configuration_fail_closed(tmp_path):
    path = tmp_path / "secret"
    path.write_text("secret-only-in-private-file")
    path.chmod(0o644)
    with pytest.raises(GatewayError): protected_read(str(path), require_root=False)
    path.chmod(0o600)
    assert protected_read(str(path), require_root=False) == b"secret-only-in-private-file"
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError): protected_read(str(link), require_root=False)
    with pytest.raises(GatewayError): protected_read(str(path), require_root=True)


def test_default_windows_custody_requires_tls_and_cannot_embed_a_password():
    from pydantic import ValidationError
    from icheck.monitoring_gateway import GatewayProfile
    document = {"protocol": "windows_exporter", "sites": ["LAB"], "allowed_targets": ["198.18.1.0/24"],
        "allowed_ports": [9182], "credential_profile_ids": [None], "allowed_collectors": ["cpu"], "windows_scheme": "http"}
    with pytest.raises(ValidationError): GatewayProfile.model_validate(document)
    document["windows_scheme"] = "https"
    assert GatewayProfile.model_validate(document).windows_scheme == "https"
    document["password"] = "not-allowed-inline"
    with pytest.raises(ValidationError): GatewayProfile.model_validate(document)


def test_windows_https_full_metrics_path_and_private_bearer_never_enters_discovery(client, gateway, tmp_path):
    from icheck.monitoring_gateway import GatewayProfile
    subject, config, opener = gateway
    _, _, _, path = seeded(client, protocol="windows_exporter")
    enrollment = approve(client, path, protocol="windows_exporter").json()
    token_file = tmp_path / "exporter-token"
    token_file.write_text("private-windows-exporter-bearer")
    token_file.chmod(0o600)
    config.profiles["lab-readonly"] = GatewayProfile.model_validate({
        "protocol": "windows_exporter", "sites": ["LAB"], "allowed_targets": ["198.18.1.0/24"],
        "allowed_ports": [9182], "credential_profile_ids": [None], "allowed_collectors": ["cpu", "memory"],
        "exporter_token_file": str(token_file)})
    assert "private-windows" not in json.dumps(subject.discovery())
    assert subject.scrape(enrollment["id"]) == opener.body
    request = next(request for request in opener.requests if urlsplit(request.full_url).hostname == "198.18.1.10")
    assert request.full_url == "https://198.18.1.10:9182/metrics?collect%5B%5D=cpu&collect%5B%5D=memory"
    assert request.get_header("Authorization") == "Bearer private-windows-exporter-bearer"
    opener.body = b'metric{echo="private-windows-exporter-bearer"} 1\n'
    with pytest.raises(GatewayError, match="echoed private"): subject.scrape(enrollment["id"])


def test_changed_protected_mapping_during_io_cannot_publish_metric_bytes(client, gateway):
    subject, config, opener = gateway
    enrollment, _ = approved(client)
    opener.after_wire = lambda: setattr(config, "max_samples", 19999)
    with pytest.raises(GatewayError, match="custody changed"): subject.scrape(enrollment["id"])


@pytest.mark.parametrize("material", ["bearer", "ca"])
def test_changed_exporter_file_material_at_same_path_discards_metric_bytes(client, gateway, tmp_path, material):
    subject, config, opener = gateway
    enrollment, _ = approved(client)
    path = tmp_path / "exporter-material"
    path.write_text("initial-private-token" if material == "bearer" else "synthetic-ca-material")
    path.chmod(0o600)
    profile = config.profiles["lab-readonly"]
    if material == "bearer": profile.exporter_token_file = str(path)
    else: profile.exporter_tls.ca_file = str(path)
    opener.after_wire = lambda: path.write_text("rotated-material-at-the-same-path")
    # The opener is a wire fixture, not a live TLS handshake/CA acceptance.
    with pytest.raises(GatewayError, match="custody changed"): subject.scrape(enrollment["id"])


def test_prometheus_token_rotation_before_response_withholds_metric_body(client, gateway):
    subject, config, opener = gateway
    enrollment, _ = approved(client)
    opener.after_wire = lambda: Path(config.prometheus_token_file).write_text("rotated-prometheus-token")
    server = GatewayServer(("127.0.0.1", 0), GatewayHandler, subject, 2)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = Request(f"http://127.0.0.1:{server.server_port}/scrape/{enrollment['id']}",
                          headers={"Authorization": "Bearer private-prometheus-token"})
        with pytest.raises(HTTPError) as revoked: urlopen(request, timeout=3)
        assert revoked.value.code == 401
        assert b"ifOperStatus" not in revoked.value.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_required_asset_read_token_cannot_approve_and_revocation_refuses_cached_scrapes(client, gateway, monkeypatch):
    from icheck.config import get_settings
    subject, config, opener = gateway
    enrollment, path = approved(client)
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    try:
        response = client.post("/api/v1/auth/bootstrap", headers={"X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token"},
            json={"subject": "admin@example.test", "display_name": "Administrator"})
        assert response.status_code == 201
        admin = {"Authorization": "Bearer " + response.json()["token"]["access_token"]}
        response = client.post("/api/v1/auth/roles", headers=admin,
            json={"name": "monitoring-reader", "description": "Read-only scoped monitoring gateway", "permissions": ["assets.read"]})
        assert response.status_code == 201
        role_id = response.json()["id"]
        response = client.post("/api/v1/auth/principals", headers=admin,
            json={"subject": "monitoring.gateway", "display_name": "Monitoring Gateway", "principal_type": "service"})
        assert response.status_code == 201
        principal_id = response.json()["id"]
        response = client.post(f"/api/v1/auth/principals/{principal_id}/bindings", headers=admin,
            json={"role_id": role_id, "scope": {"sites": ["LAB"]}})
        assert response.status_code == 201
        response = client.post(f"/api/v1/auth/principals/{principal_id}/tokens", headers=admin,
            json={"name": "gateway-test", "expires_in_hours": 1})
        assert response.status_code == 201
        token = response.json()["access_token"]
        Path(config.api_token_file).write_text(token)
        preview = client.get(path, headers={"Authorization": "Bearer " + token})
        assert preview.status_code == 200
        denied = client.post(path + "/approve", headers={"Authorization": "Bearer " + token}, json={
            "expected_revision": 1, "preview_hash": preview.json()["preview_hash"], "gateway_profile": "lab-readonly",
            "modules": ["if_mib"], "actor": "forged.admin", "reason": "Attempt approval from a read-only credential."})
        assert denied.status_code == 403
        assert len(subject.discovery()) == 1
        assert subject.scrape(enrollment["id"]) == opener.body
        response = client.patch(f"/api/v1/auth/principals/{principal_id}", headers=admin,
            json={"enabled": False, "reason": "Revoke monitoring gateway identity."})
        assert response.status_code == 200
        before = len(opener.requests)
        with pytest.raises(GatewayError): subject.scrape(enrollment["id"])
        assert len(opener.requests) == before + 1
        assert urlsplit(opener.requests[-1].full_url).hostname == "control.example.test"
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()
