"""One shared native exporter acceptance path; fixtures are not lab claims."""
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4
import json
import time

import pytest
from pydantic import ValidationError

from icheck.auth import current_principal
from icheck.database import SessionLocal, DEFAULT_TENANT_ID, DEFAULT_REGION_ID
from icheck.device_preflight_worker import execute_device_preflight, DevicePreflightFailure
from icheck.exporter_metrics import ExporterMonitorSpec, PROTOCOLS, SUCCESS, health_metric, collect, validate_response
from icheck.http_metrics import HTTPMetricError
from icheck.main import app
from icheck.models import ArtifactVersion, CredentialProfile, DeviceConnection, MetricBackend, utcnow
from icheck.monitoring_gateway import GatewayError, GatewayProfile
from icheck.services.control_plane_auth import development_principal
from test_capability_studio import configure_authoring_route, FakeStructuredOpener
from test_device_preflights import register_worker
from test_http_monitoring import endpoint
from test_http_monitoring_studio import get_state, enable_payload
from test_managed_device_credentials import device_key
from test_monitoring_gateway import gateway


@pytest.fixture(autouse=True)
def human():
    app.dependency_overrides[current_principal] = lambda: replace(development_principal(), principal_type="user", subject="test.admin", auth_method="bearer")
    yield
    app.dependency_overrides.pop(current_principal, None)


def spec(plugin="linux", **changes):
    return ExporterMonitorSpec.model_validate({"plugin": plugin, "groups": ["cpu", "memory", "uptime"], "scheme": "http",
        **({"vmware_scope":"hosts","vmware_name":"fixture-esxi","vmware_datacenter":"fixture-dc"} if plugin=="vmware" else {}), **changes})


def metric_body(request):
    if request.plugin=="vmware":
        from icheck.vmware_metrics import LABEL
        fields={LABEL[request.vmware_scope]:request.vmware_name,"dc_name":request.vmware_datacenter or "fixture-dc"}
        if request.vmware_scope=="vms": fields.update(host_name="fixture-esxi",ds_name="fixture-ds",cluster_name="fixture-cluster")
        labels=",".join(key+"="+json.dumps(value) for key,value in fields.items())
        lines=[f"# TYPE {health_metric(request)} gauge",f"{health_metric(request)}{{{labels}}} 1"]
        for name in request.metrics():
            extra=',partition="/"' if "guest_disk" in name else ""
            value=time.time()-100 if "boot_timestamp" in name else 2000 if name=="vmware_vm_mem_usage_average" else 32768 if "memory" in name else 7
            lines += [f"# TYPE {name} gauge",f"{name}{{{labels}{extra}}} {value}"]
        return ("\n".join(lines)+"\n").encode()
    if request.plugin == "containers":
        from icheck.container_metrics import STATIC_NAMES
        now = time.time(); stamp = str(round(now * 1000))
        labels = 'id="/docker/fixture-app",image="fixture/image:1",name="fixture-app"'
        lines = ["# TYPE container_scrape_error gauge", "container_scrape_error 0",
            "# TYPE container_last_seen gauge", f"container_last_seen{{{labels}}} {now} {stamp}"]
        for name, kind in request.metrics().items():
            extra = ',cpu="total"' if name == "container_cpu_usage_seconds_total" else ""
            timestamp = "" if name in STATIC_NAMES else " " + stamp
            value = now - 100 if name == "container_start_time_seconds" else 1048576 if "bytes" in name else 7
            lines += [f"# TYPE {name} {kind}", f"{name}{{{labels}{extra}}} {value}{timestamp}"]
        return ("\n".join(lines) + "\n").encode()
    lines = []
    for name, kind in request.metrics().items():
        lines += [f"# TYPE {name} {kind}", f"{name} 7"]
    lines += [f"# TYPE {SUCCESS[request.plugin]} gauge"]
    lines += [f'{SUCCESS[request.plugin]}{{collector="{collector}"}} 1' for collector in request.collectors()]
    return ("\n".join(lines) + "\n").encode()


def draft(client, monkeypatch, plugin="linux", *, port=None, documents=None, auth="none", vmware_scope="hosts", groups=None):
    configure_authoring_route(client)
    document = {"artifact_name": f"{plugin}-host", "description": "Measure selected native host collectors.",
        "groups": groups or (["disk"] if plugin=="vmware" and vmware_scope=="datastores" else ["cpu", "memory", "uptime"]), "unsupported_metrics": []}
    opener = FakeStructuredOpener(documents or [document])
    monkeypatch.setattr("icheck.services.structured_model.build_opener", lambda *_: opener)
    payload = {"title": f"{plugin} monitoring", "brief": "Monitor CPU, available memory and uptime every thirty seconds.",
        "created_by": "lab.admin", "exporter_monitoring": {"plugin": plugin, "scheme": "https" if auth != "none" else "http", "auth_mode": auth}}
    if plugin=="vmware": payload["exporter_monitoring"].update(vmware_scope=vmware_scope,vmware_name="fixture-esxi" if vmware_scope=="hosts" else "fixture-app" if vmware_scope=="vms" else "fixture-ds",vmware_datacenter="fixture-dc")
    if port: payload["exporter_monitoring"]["port"] = port
    created = client.post("/api/v1/capability-studio/sessions", json=payload)
    assert created.status_code == 201, created.text
    path = "/api/v1/capability-studio/sessions/" + created.json()["id"]
    key = str(uuid4())
    generated = client.post(path + "/generate", json={"actor": "lab.admin", "request_key": key})
    assert generated.status_code == 200, generated.text
    return generated.json(), path, opener, key


def target(client, path, doc, plugin="linux", *, profile=None):
    created = client.post("/api/v1/assets/devices", json={"name": "Exporter test host", "kind": "other" if plugin=="vmware" else "linux_server" if plugin == "containers" else plugin + "_server", "management_ip": "198.18.1.10",
        "site": "LAB", "created_by": "lab.admin", "connections": [{"protocol": PROTOCOLS[plugin]}]})
    assert created.status_code == 201, created.text
    device = created.json()
    payload = {"artifact_version_id": doc["artifact_version_id"], "device_id": device["id"], "connection_id": device["connections"][0]["id"],
        "expected_device_revision": device["revision"], "actor": "lab.admin", "reason": "Test this exact exporter template against the selected host."}
    if profile: payload["credential_profile_ref"] = profile["id"]
    queued = client.post(path + "/monitoring/test", json=payload)
    assert queued.status_code == 200, queued.text
    return queued.json(), payload


def complete(client, state, payload, plugin="linux", *, executor=None):
    worker, headers = register_worker(client, name=f"{plugin}-test-worker", site="LAB", capabilities=[PROTOCOLS[plugin]])
    claim = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim", headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60}).json()[0]
    request = ExporterMonitorSpec.model_validate(claim["configuration"]["exporter_monitor"])
    if executor:
        evidence, _ = executor(claim)
    else:
        evidence = validate_response(request, metric_body(request))
        evidence.update(check="native_exporter_metric_query", target_host=claim["target_host"], target_port=claim["port"],
            tls_tested=request.scheme == "https", authentication_tested=request.auth_mode != "none", credential_revision=claim["credential_revision"])
    response = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/{claim['preflight_id']}/complete", headers=headers,
        json={"lease_token": claim["lease_token"], "status": "verified", "evidence": evidence})
    assert response.status_code == 200, response.text


def enabled(client, monkeypatch, plugin="linux", **changes):
    doc, path, opener, key = draft(client, monkeypatch, plugin, **changes)
    state, payload = target(client, path, doc, plugin)
    complete(client, state, payload, plugin)
    state = get_state(client, path, payload).json()
    approval = enable_payload(state, payload)
    approval.update(gateway_profile="lab-readonly", schedule_seconds=30, collectors=state["template"]["exporter_monitor"]["groups"])
    approval["collectors"] = ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"]).collectors()
    response = client.post(path + "/monitoring/enable", json=approval)
    assert response.status_code == 200, response.text
    return doc, path, payload, response.json()


@pytest.mark.parametrize("plugin", ["linux", "windows"])
def test_real_exporter_wire_reads_selected_collectors_and_every_measurement(endpoint, plugin):
    server, state = endpoint
    request = spec(plugin)
    state.update(body=metric_body(request), content_type="text/plain; version=0.0.4")
    body, evidence = collect(request, "127.0.0.1", server.server_port, deadline=time.monotonic() + 2)
    assert evidence["metric_names"] == sorted(request.metrics()) and evidence["collector_success"]
    assert "collect%5B%5D=cpu" in state["calls"][0][0] and b'collector=' in body
    assignment = {"adapter_type": PROTOCOLS[plugin], "target_host": "127.0.0.1", "port": server.server_port,
        "configuration": {"exporter_monitor": request.model_dump()}}
    proof, _ = execute_device_preflight(assignment, allowed_targets=["127.0.0.1/32"], timeout_seconds=2,
        snmp_exporter_url=None, exporter_allowed_hosts=[], snmp_allowed_targets=[], lease_seconds=60)
    assert proof["check"] == "native_exporter_metric_query" and proof["target_port"] == server.server_port


@pytest.mark.parametrize("fault", ["missing", "failed", "type", "nonfinite", "duplicate", "timestamp", "reserved", "secret", "budget"])
def test_invalid_or_incomplete_exporter_evidence_fails(fault):
    request = spec(); body = metric_body(request); options = {}
    if fault == "missing": body = body.replace(b"node_memory_MemTotal_bytes 7\n", b"")
    if fault == "failed": body = body.replace(b'collector="cpu"} 1', b'collector="cpu"} 0')
    if fault == "type": body = body.replace(b"node_cpu_seconds_total counter", b"node_cpu_seconds_total gauge")
    if fault == "nonfinite": body = body.replace(b"node_cpu_seconds_total 7", b"node_cpu_seconds_total NaN")
    if fault == "duplicate": body += b"node_memory_MemTotal_bytes 7\n"
    if fault == "timestamp": body = body.replace(b"node_cpu_seconds_total 7", b"node_cpu_seconds_total 7 1234")
    if fault == "reserved": body += b'other{icheck_device_id="forged"} 1\n'
    if fault == "secret": body += b'other{detail="private-\\"token"} 1\n'; options["values"] = {"token": 'private-"token'}
    if fault == "budget": options["max_samples"] = 1
    with pytest.raises(HTTPMetricError): validate_response(request, body, **options)


def test_unknown_groups_or_http_credentials_are_not_native_templates():
    with pytest.raises(ValidationError): spec(groups=["invented_gpu"])
    with pytest.raises(ValidationError): spec(auth_mode="basic")
    request = spec("windows")
    assert "windows_memory_total_bytes" not in request.metrics()
    assert "windows_system_boot_time_timestamp" in request.metrics()


def test_native_exporter_https_verifies_certificate_and_protected_basic_auth(endpoint, tmp_path):
    import ssl
    from datetime import UTC, datetime, timedelta
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    server, state = endpoint
    request = spec("windows", scheme="https", auth_mode="basic", server_name="exporter.fixture.test")
    state.update(body=metric_body(request), content_type="text/plain")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "exporter.fixture.test")]); now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("exporter.fixture.test")]), critical=False).sign(key, hashes.SHA256()))
    cert_file = tmp_path / "exporter.crt"; key_file = tmp_path / "exporter.key"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); key_file.chmod(0o600)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(cert_file, key_file)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    values = {"username": "fixture-reader", "password": "synthetic-exporter-password"}
    with pytest.raises(HTTPMetricError): collect(request, "127.0.0.1", server.server_port, values=values, deadline=time.monotonic() + 2)
    body, proof = collect(request, "127.0.0.1", server.server_port, values=values, deadline=time.monotonic() + 2,
        tls_context=ssl.create_default_context(cafile=cert_file))
    assert proof["tls_tested"] and proof["authentication_tested"] and proof["success"]
    assert state["calls"][-1][1].startswith("Basic ") and state["calls"][-1][2] == f"exporter.fixture.test:{server.server_port}"
    assert values["password"].encode() not in body


@pytest.mark.parametrize("plugin", ["linux", "windows"])
def test_studio_test_enable_uses_immutable_template_not_sql_collection(client, monkeypatch, plugin):
    doc, path, payload, state = enabled(client, monkeypatch, plugin)
    assert state["stage"] == "enabled_awaiting_fresh_samples" and not state["fresh_samples_verified"]
    target = client.get("/api/v1/monitoring/targets").json()["targets"][0]
    assert target["protocol"] == PROTOCOLS[plugin] and target["exporter_monitor"]["plugin"] == plugin
    with SessionLocal() as db:
        version = db.get(ArtifactVersion, doc["artifact_version_id"])
        assert version.status.value == "published" and version.implementation["runtime"] == "prometheus_gateway_v1"
        assert version.collector_definition.defaults == {} and version.validation_report["live_target_tested"] is False


def exporter_gateway(config, request, port):
    config.profiles["lab-readonly"] = GatewayProfile(protocol=PROTOCOLS[request.plugin], sites=["LAB"],
        allowed_targets=["198.18.1.0/24"], allowed_ports=[port], credential_profile_ids=[None],
        allowed_collectors=request.collectors(), allow_insecure_exporter_http=True)


def test_exporter_gateway_withdraws_target_after_metric_io(client, monkeypatch, gateway):
    subject, config, _ = gateway
    _, path, payload, state = enabled(client, monkeypatch)
    request = ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"])
    exporter_gateway(config, request, state["template"]["port"])
    assert len(subject.discovery()) == 1
    def read(*args, **kwargs):
        assert client.post(f"/api/v1/assets/devices/{payload['device_id']}/connections/{payload['connection_id']}/monitoring/withdraw",
            json={"expected_revision": 1, "actor": "lab.admin", "reason": "Withdraw during scrape fixture."}).status_code == 200
        return metric_body(request), validate_response(request, metric_body(request))
    monkeypatch.setattr("icheck.monitoring_gateway.collect_exporter", read)
    with pytest.raises(GatewayError): subject.scrape(state["monitoring"]["enrollment"]["id"])
    assert subject.discovery() == []


@pytest.mark.parametrize("fault", ["collectors", "network", "port", "http", "token"])
def test_exporter_protected_custody_denies_before_io(client, monkeypatch, gateway, fault):
    subject, config, _ = gateway
    _, path, payload, state = enabled(client, monkeypatch)
    request = ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"])
    exporter_gateway(config, request, state["template"]["port"])
    profile = config.profiles["lab-readonly"]
    if fault == "collectors": profile.allowed_collectors = ["cpu"]
    if fault == "network": profile.allowed_targets = ["203.0.113.0/24"]
    if fault == "port": profile.allowed_ports = [9182]
    if fault == "http": profile.allow_insecure_exporter_http = False
    if fault == "token": profile.exporter_token_file = "must-not-read"
    monkeypatch.setattr("icheck.monitoring_gateway.collect_exporter", lambda *a, **kw: pytest.fail("Unauthorized exporter contacted"))
    assert subject.discovery() == []
    with pytest.raises(GatewayError): subject.scrape(state["monitoring"]["enrollment"]["id"])


def test_legacy_http_secret_scope_remains_valid_without_expansion(client, device_key):
    from icheck.services.device_credentials import resolve
    row = client.post("/api/v1/device-credentials", json={"name": "legacy-http", "kind": "https_token", "site": "LAB", "token": "synthetic-private-value"})
    assert row.status_code == 201
    with SessionLocal() as db:
        profile = db.get(CredentialProfile, row.json()["id"])
        profile.allowed_adapters = ["http_json", "http_json_sandbox"]; db.commit()
        assert resolve(db, profile)["token"] == "synthetic-private-value"
    rotated = client.put("/api/v1/device-credentials/" + row.json()["id"], json={"name": "legacy-http", "kind": "https_token", "site": "LAB",
        "token": "synthetic-rotated-value", "expected_revision": 1, "reason": "Rotate without extending scope."})
    assert rotated.status_code == 200 and rotated.json()["allowed_adapters"] == ["http_json", "http_json_sandbox"]


def fresh_reader(monkeypatch, payload, state, *, fault=None):
    request = ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"])
    names = list(request.metrics()) + [SUCCESS[request.plugin]]
    stamp = utcnow().timestamp() - (2000 if fault == "stale" else 0)
    labels = {"job": "icheck_continuous", "icheck_tenant_id": DEFAULT_TENANT_ID, "icheck_region_id": DEFAULT_REGION_ID,
        "icheck_device_id": payload["device_id"], "icheck_connection_id": payload["connection_id"],
        "icheck_enrollment_id": state["monitoring"]["enrollment"]["id"], "icheck_enrollment_revision": "1"}
    def query(db, backend, payload, **kwargs):
        if payload.query.startswith("count by"):
            result = [{"metric": {"__name__": name}, "value": [stamp, "1"]} for name in names if fault != "up_only"]
        elif payload.query.startswith("label_replace"):
            result = [{"metric": {"icheck_metric_name": name}, "value": [stamp, str(stamp)]} for name in names]
        elif payload.query.startswith(SUCCESS[request.plugin]):
            result = [{"metric": {**labels, "collector": collector}, "value": [stamp, "0" if fault == "failed_collector" else "1"]}
                for collector in request.collectors() if fault != "missing_collector"]
        else:
            result = [{"metric": labels, "value": [stamp, "1"]}]
        return SimpleNamespace(result_type="vector", result=result)
    monkeypatch.setattr("icheck.services.metrics.query_instant", query)


@pytest.mark.parametrize("fault", [None, "up_only", "stale", "failed_collector", "missing_collector"])
def test_freshness_checks_raw_metric_timestamps_and_collector_health(client, monkeypatch, fault):
    _, path, payload, state = enabled(client, monkeypatch)
    with SessionLocal() as db:
        db.add(MetricBackend(name="exporter-prometheus", provider="prometheus", query_base_url="https://prometheus.example.test",
            external_labels={}, enabled=True, created_by="test")); db.commit()
    fresh_reader(monkeypatch, payload, state, fault=fault)
    response = get_state(client, path, payload, verify_samples="true")
    assert response.status_code == 200, response.text
    assert response.json()["fresh_samples_verified"] is (fault is None)


@pytest.mark.parametrize("plugin", ["linux", "windows"])
def test_native_grafana_proposal_has_real_queries_and_confirmed_saved_url(client, monkeypatch, tmp_path, plugin):
    from icheck.config import get_settings
    from icheck.services import grafana
    from test_grafana_plugin import FakeGrafana
    _, path, payload, state = enabled(client, monkeypatch, plugin)
    with SessionLocal() as db:
        db.add(MetricBackend(name="exporter-prometheus", provider="prometheus", query_base_url="https://prometheus.example.test",
            external_labels={}, enabled=True, created_by="test")); db.commit()
    fresh_reader(monkeypatch, payload, state)
    key = tmp_path / "grafana.key"; key.write_bytes(b"g" * 32); key.chmod(0o400)
    monkeypatch.setenv("ICHECK_GRAFANA_SECRET_KEY_FILE", str(key)); get_settings.cache_clear()
    fake = FakeGrafana()
    request = ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"])
    fake.metrics = lambda _: list(request.metrics())
    monkeypatch.setattr(grafana, "CLIENT", fake)
    try:
        connection = client.post("/api/v1/grafana/connections", json={"name": "exporter-grafana", "public_url": "https://icheck.test/grafana/",
            "token": "synthetic-grafana-secret", "shared_dataset_acknowledged": True}).json()
        params = {key: payload[key] for key in ("artifact_version_id", "device_id", "connection_id")} | {"grafana_connection_id": connection["id"]}
        proposed = client.post(path + "/monitoring/dashboard-proposal", params=params)
        assert proposed.status_code == 200, proposed.text
        assert fake.writes == []
        definition = proposed.json()["definition"]
        assert any(panel["title"] == "Memory in use" and "100 * (1 -" in panel["targets"][0]["expr"] for panel in definition["panels"])
        assert any(panel["title"] == "Uptime" for panel in definition["panels"])
        repeated = client.post(path + "/monitoring/dashboard-proposal", params=params)
        assert repeated.json()["id"] == proposed.json()["id"]
        confirmed = client.post(f"/api/v1/grafana/changes/{proposed.json()['id']}/confirm", json={"confirm": True, "expected_plan_hash": proposed.json()["plan_hash"]})
        assert confirmed.status_code == 200, confirmed.text
        after = get_state(client, path, payload).json()
        assert after["grafana_dashboard_url"].startswith("https://icheck.test/grafana/d/icheck-" + plugin + "-")
        assert len(fake.writes) == 1 and "synthetic-grafana-secret" not in json.dumps(after)
    finally:
        get_settings.cache_clear()


def test_exporter_edit_restore_preserves_versions_and_requires_retest(client, monkeypatch):
    first = {"artifact_name": "host-metrics", "description": "Measure CPU and memory.", "groups": ["cpu", "memory"]}
    revised = {**first, "artifact_name": "must-not-rename", "groups": ["cpu", "memory", "network"]}
    doc, path, _, key = draft(client, monkeypatch, documents=[first, revised])
    assert client.post(path + "/publish", json={"actor": "lab.admin", "expected_artifact_version_id": doc["artifact_version_id"]}).status_code == 200
    state, payload = target(client, path, doc); complete(client, state, payload)
    response = client.post(path + "/messages", json={"actor": "lab.admin", "content": "Also monitor interface traffic.", "request_key": str(uuid4())})
    assert response.status_code == 200, response.text
    new = response.json()
    assert new["artifact_version_id"] != doc["artifact_version_id"]
    state = get_state(client, path, {**payload, "artifact_version_id": new["artifact_version_id"]}).json()
    assert not state["bound_to_template"] and state["stage"] == "select_and_test_target"
    assert client.post(path + "/publish", json={"actor": "lab.admin", "expected_artifact_version_id": new["artifact_version_id"]}).status_code == 200
    restored = client.post(f"/api/v1/artifacts/{doc['artifact_id']}/restore-candidates", json={"source_version": 1, "reason": "Restore the prior metric selection.", "actor": "lab.admin"})
    assert restored.status_code == 201, restored.text
    assert restored.json()["version"] == 3 and restored.json()["definition"]["exporter_monitor"]["groups"] == ["cpu", "memory"]


def test_protected_exporter_worker_credential_is_revision_bound_and_not_retained(client, monkeypatch, device_key):
    from icheck.collector_worker import run_device_preflight
    from icheck.http_metrics import HTTPResult, auth_headers
    values = {"username": "fixture-monitor", "password": "synthetic-exporter-password"}
    profile = client.post("/api/v1/device-credentials", json={"name": "exporter-account", "kind": "http_basic", "site": "LAB", **values}).json()
    doc, path, _, _ = draft(client, monkeypatch, auth="basic")
    state, payload = target(client, path, doc, profile=profile)
    worker, headers = register_worker(client, name="protected-exporter-test", site="LAB", capabilities=["node_exporter"])
    claim = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim", headers=headers,
        json={"max_assignments": 1, "lease_seconds": 60}).json()[0]
    request = ExporterMonitorSpec.model_validate(claim["configuration"]["exporter_monitor"])
    def transport(spec, host, port, request_headers, **kwargs):
        assert host == "198.18.1.10" and request_headers["Authorization"] == auth_headers(request.request(), values)["Authorization"]
        return HTTPResult(metric_body(request), 200, .01, content_type="text/plain")
    monkeypatch.setattr("icheck.exporter_metrics.fetch_http", transport)
    class WorkerClient:
        def request(self, method, path, body):
            response = client.request(method, path, headers=headers, json=body)
            assert response.status_code == 200, response.text
            return response.json()
    assert run_device_preflight(WorkerClient(), worker["id"], claim, allowed_targets=["198.18.1.0/24"], timeout_seconds=2,
        snmp_exporter_url=None, exporter_allowed_hosts=[], snmp_allowed_targets=[], lease_seconds=60)
    assert "_runtime" not in claim
    state = get_state(client, path, payload).json()
    assert state["monitoring"]["eligible"] and values["password"] not in json.dumps(state)
    assert values["password"] not in client.get("/api/v1/audit-events").text


@pytest.mark.parametrize("plugin", ["linux", "windows", "containers", "vmware"])
def test_only_gateway_service_can_resolve_and_rotation_withdraws_exporter_authority(client, monkeypatch, device_key, plugin):
    from icheck.config import get_settings
    from icheck.services.control_plane_auth import PrincipalContext
    profile = client.post("/api/v1/device-credentials", json={"name": "exporter-token", "kind": "https_token", "site": "LAB", "token": "synthetic-exporter-secret"}).json()
    doc, path, _, _ = draft(client, monkeypatch, plugin, auth="bearer")
    state, payload = target(client, path, doc, plugin, profile=profile)
    complete(client, state, payload, plugin)
    state = get_state(client, path, payload).json()
    approval = enable_payload(state, payload); approval.pop("credential_profile_ref")
    approval.update(gateway_profile="lab-readonly", collectors=ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"]).collectors())
    response = client.post(path + "/monitoring/enable", json=approval)
    assert response.status_code == 200, response.text
    enrollment = response.json()["monitoring"]["enrollment"]
    secret_path = f"/api/v1/monitoring/enrollments/{enrollment['id']}/managed-credential"
    monkeypatch.setenv("ICHECK_MANAGED_MONITORING_GATEWAY_SUBJECT", "gateway.fixture"); get_settings.cache_clear()
    service = PrincipalContext(principal_id="test-service", subject="gateway.fixture", principal_type="service", auth_method="bearer",
        role_names=("collector",), permissions=frozenset({"assets.read"}), authorization_scope={"sites": ["LAB"]},
        tenant_id=DEFAULT_TENANT_ID, region_id=DEFAULT_REGION_ID)
    human_actor = app.dependency_overrides[current_principal]
    try:
        assert client.get(secret_path).status_code == 403
        app.dependency_overrides[current_principal] = lambda: service
        secret = client.get(secret_path)
        assert secret.status_code == 200 and secret.json()["values"] == {"token": "synthetic-exporter-secret"}
        assert secret.headers["cache-control"] == "no-store" and secret.json()["profile_revision"] == 1
        app.dependency_overrides[current_principal] = human_actor
        rotated = client.put("/api/v1/device-credentials/" + profile["id"], json={"name": "exporter-token", "kind": "https_token", "site": "LAB",
            "token": "synthetic-exporter-rotated-secret", "expected_revision": 1, "reason": "Rotate the protected test exporter credential."})
        assert rotated.status_code == 200, rotated.text
        assert client.get("/api/v1/monitoring/targets").json()["targets"] == []
        app.dependency_overrides[current_principal] = lambda: service
        assert client.get(secret_path).status_code == 404
    finally:
        app.dependency_overrides[current_principal] = human_actor
        get_settings.cache_clear()


@pytest.mark.parametrize("plugin", ["linux", "containers", "vmware"])
def test_private_exporter_to_prometheus_proves_fresh_source_metrics(client, monkeypatch, gateway, endpoint, tmp_path, plugin):
    import os, shutil, socket, subprocess, threading
    from pathlib import Path
    from urllib.parse import urlencode
    from urllib.request import urlopen
    from icheck.monitoring_gateway import GatewayServer, GatewayHandler
    from icheck.services import monitoring_templates
    node = os.environ.get("ICHECK_EXPORTER_TEST_NODE_BINARY")
    prometheus = os.environ.get("ICHECK_EXPORTER_TEST_PROMETHEUS_BINARY")
    if not prometheus or (plugin == "linux" and not node): pytest.skip("Explicit native binaries required for the private exporter path")
    assert Path(prometheus).is_file()
    if plugin == "linux": assert Path(node).is_file()
    def port():
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0)); return reservation.getsockname()[1]
    fixture, fixture_state = endpoint
    node_port, prom_port = (fixture.server_port if plugin != "linux" else port()), port()
    process = None
    if plugin == "linux":
        process = subprocess.Popen([node, f"--web.listen-address=127.0.0.1:{node_port}", "--collector.disable-defaults",
            "--collector.cpu", "--collector.meminfo", "--collector.stat", "--collector.time"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        fixture_request = spec(plugin)
        fixture_state.update(content_type="text/plain", body_factory=lambda: metric_body(fixture_request))
    prom_process = None; server = None; thread = None
    subject, config, _ = gateway
    actual_fetch = __import__("icheck.exporter_metrics", fromlist=["fetch_http"]).fetch_http
    def fixture_transport(spec, host, destination_port, headers, **kwargs):
        assert host == "198.18.1.10" and destination_port == node_port
        return actual_fetch(spec, "127.0.0.1", node_port, headers, **kwargs)
    monkeypatch.setattr("icheck.exporter_metrics.fetch_http", fixture_transport)
    try:
        until = time.monotonic() + 5
        while time.monotonic() < until:
            assert process is None or process.poll() is None
            try:
                with urlopen(f"http://127.0.0.1:{node_port}/metrics", timeout=1): break
            except OSError: time.sleep(.05)
        doc, path, _, _ = draft(client, monkeypatch, plugin, port=node_port)
        state, payload = target(client, path, doc, plugin)
        complete(client, state, payload, plugin, executor=lambda claim: execute_device_preflight(claim, allowed_targets=["198.18.1.0/24"],
            timeout_seconds=3, snmp_exporter_url=None, exporter_allowed_hosts=[], snmp_allowed_targets=[], lease_seconds=60))
        state = get_state(client, path, payload).json()
        request = ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"])
        approval = enable_payload(state, payload)
        approval.update(gateway_profile="lab-readonly", collectors=request.collectors(), schedule_seconds=15, timeout_seconds=3)
        approved = client.post(path + "/monitoring/enable", json=approval)
        assert approved.status_code == 200, approved.text
        exporter_gateway(config, request, node_port)
        server = GatewayServer(("127.0.0.1", 0), GatewayHandler, subject, 2); config.port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        configuration = tmp_path / "prometheus.yml"
        configuration.write_text(f'''global:
  scrape_interval: 1s
scrape_configs:
  - job_name: icheck_continuous
    scrape_timeout: 3s
    scrape_interval: 15s
    authorization:
      credentials: private-prometheus-token
    http_sd_configs:
      - url: http://127.0.0.1:{config.port}/discovery
        refresh_interval: 1s
        authorization:
          credentials: private-prometheus-token
''')
        prom_process = subprocess.Popen([prometheus, "--config.file=" + str(configuration), "--storage.tsdb.path=" + str(tmp_path / "tsdb"),
            "--storage.tsdb.retention.time=1h", f"--web.listen-address=127.0.0.1:{prom_port}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with SessionLocal() as db:
            backend = MetricBackend(name="private-native-proof", provider="prometheus", query_base_url="https://prometheus.example.test",
                external_labels={}, enabled=True, created_by="test")
            db.add(backend); db.commit(); backend_id = backend.id
        def actual_query(db, backend, payload, **kwargs):
            with urlopen(f"http://127.0.0.1:{prom_port}/api/v1/query?" + urlencode({"query": payload.query}), timeout=3) as response:
                result = json.load(response)
            assert result["status"] == "success"
            return SimpleNamespace(result_type=result["data"]["resultType"], result=result["data"]["result"])
        monkeypatch.setattr("icheck.services.metrics.query_instant", actual_query)
        until = time.monotonic() + 35; proof = None
        while time.monotonic() < until:
            assert prom_process.poll() is None and (process is None or process.poll() is None)
            try:
                with SessionLocal() as db:
                    proof = monitoring_templates.verify_samples(db, development_principal(), doc["id"], doc["artifact_version_id"],
                        payload["device_id"], payload["connection_id"], backend_id)
                if proof["fresh_samples_verified"]: break
            except OSError: pass
            time.sleep(.2)
        assert proof and proof["fresh_samples_verified"], proof
        assert proof["stage"] == "collecting" and set(request.metrics()).issubset({m["name"] for m in proof["metric_evidence"]})
        memory = actual_query(None, None, SimpleNamespace(query="node_memory_MemTotal_bytes" if plugin == "linux" else "vmware_host_memory_usage" if plugin=="vmware" else "container_memory_working_set_bytes"))
        assert float(memory.result[0]["value"][1]) > 1024
        if plugin == "containers":
            assert memory.result[0]["metric"]["id"] == "/docker/fixture-app"
            stamp = actual_query(None, None, SimpleNamespace(query="timestamp(container_memory_working_set_bytes)"))
            assert 0 <= time.time() - float(stamp.result[0]["value"][1]) < 60
    finally:
        for item in (prom_process, process):
            if item:
                item.terminate()
                try: item.wait(timeout=5)
                except subprocess.TimeoutExpired: item.kill(); item.wait(timeout=5)
        if server: server.shutdown(); server.server_close()
        if thread: thread.join(timeout=2)
        shutil.rmtree(tmp_path / "tsdb", ignore_errors=True)
