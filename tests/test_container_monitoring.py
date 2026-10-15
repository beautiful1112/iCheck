"""cAdvisor fixture workflow; no fixture is claimed as a real container runtime."""
from copy import deepcopy
import hashlib
import json
import time
from types import SimpleNamespace

import pytest
from prometheus_client.parser import text_string_to_metric_families

from icheck.database import SessionLocal, DEFAULT_TENANT_ID, DEFAULT_REGION_ID
from icheck.exporter_metrics import ExporterMonitorSpec, collect, spec_hash, validate_response
from icheck.http_metrics import HTTPMetricError
from icheck.models import MetricBackend, CredentialProfile, utcnow
from icheck.monitoring_gateway import GatewayError
from test_exporter_monitoring import human, metric_body, draft, target, complete, enabled, exporter_gateway
from test_http_monitoring import endpoint
from test_http_monitoring_studio import get_state
from test_managed_device_credentials import device_key
from test_monitoring_gateway import gateway


def spec(**changes):
    return ExporterMonitorSpec.model_validate({"plugin":"containers","groups":["cpu","memory","uptime"],"scheme":"http",**changes})


def samples(body):
    return [sample for family in text_string_to_metric_families(body.decode()) for sample in family.samples]


def test_cadvisor_wire_filters_environment_and_preserves_source_timestamps(endpoint):
    from icheck.container_metrics import render_container_metrics
    server, state = endpoint; request = spec()
    body = metric_body(request).replace(b'image="fixture/image:1"', b'image="fixture/image:1",container_env_password="must-not-export",container_label_team="private-team"')
    state.update(body=body, content_type="text/plain")
    output, proof = collect(request,"127.0.0.1",server.server_port,deadline=time.monotonic()+2)
    assert state["calls"][0][0] == "/metrics"  # No invented collect[] API.
    assert b"must-not-export" not in output and b"private-team" not in output
    assert proof["container_ids"] == ["/docker/fixture-app"] and proof["container_count"] == 1
    original = next(sample for sample in samples(body) if sample.name == "container_cpu_usage_seconds_total")
    projected = next(sample for sample in samples(output) if sample.name == original.name)
    assert float(projected.timestamp) == float(original.timestamp)
    assert not proof["application_health_verified"] and proof["source_timestamps_preserved"]


@pytest.mark.parametrize("fault", ["host_only","no_image","stale","future","missing_timestamp","scrape_error","missing_metric","missing_container",
    "selector","duplicate_after_projection","partial_container","credential_echo"])
def test_no_container_health_or_metric_success_without_declared_fresh_data(fault):
    request = spec(); body = metric_body(request); options = {}
    if fault == "host_only": body = body.replace(b'id="/docker/fixture-app"',b'id="/"')
    if fault == "no_image": body = body.replace(b'image="fixture/image:1"',b'image=""')
    if fault in {"stale","future","missing_timestamp"}:
        lines=body.decode().splitlines()
        index=next(i for i,line in enumerate(lines) if line.startswith("container_cpu_usage_seconds_total{"))
        parts=lines[index].rsplit(" ",1)
        lines[index]=parts[0] if fault=="missing_timestamp" else parts[0]+" "+str(round((time.time()+(-120 if fault=="stale" else 120))*1000))
        body=("\n".join(lines)+"\n").encode()
    if fault == "scrape_error": body=body.replace(b"container_scrape_error 0",b"container_scrape_error 1")
    if fault == "missing_metric": body=b"\n".join(line for line in body.splitlines() if not line.startswith(b"container_memory_working_set_bytes{"))+b"\n"
    if fault == "missing_container": body=b"# TYPE container_scrape_error gauge\ncontainer_scrape_error 0\n"
    if fault == "selector": request=spec(container_name="another-container")
    if fault == "duplicate_after_projection":
        line=next(line for line in body.splitlines() if line.startswith(b"container_cpu_usage_seconds_total{"))
        body+=line.replace(b'image="fixture/image:1"',b'image="fixture/image:1",container_label_different="discarded"')+b"\n"
    if fault == "partial_container":
        line=next(line for line in body.splitlines() if line.startswith(b"container_last_seen{"))
        body+=line.replace(b'/docker/fixture-app',b'/docker/other')+b"\n"
    if fault == "credential_echo": body+=b'# diagnostic synthetic-private-token\n'; options["values"]={"token":"synthetic-private-token"}
    with pytest.raises(HTTPMetricError): validate_response(request,body,**options)


def test_noncontainer_v1_hashes_and_prior_exporter_credentials_do_not_expand(client,device_key):
    request=ExporterMonitorSpec(plugin="linux",groups=["cpu"])
    before={"contract":"icheck.exporter-monitor/v1","plugin":"linux","groups":["cpu"],"scheme":"https","server_name":None,"auth_mode":"none"}
    expected=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    assert spec_hash(request)==expected
    from icheck.services.device_credentials import resolve
    profile=client.post("/api/v1/device-credentials",json={"name":"prior-exporter","kind":"https_token","site":"LAB","token":"synthetic-token"}).json()
    with SessionLocal() as db:
        old=db.get(CredentialProfile,profile["id"])
        old.allowed_adapters=["http_json","http_json_sandbox","node_exporter","windows_exporter"]; db.commit()
        assert resolve(db,old)=={"token":"synthetic-token"}
        assert "cadvisor" not in old.allowed_adapters


def test_container_studio_enables_same_contract_with_real_fixture_metric_proof(client,monkeypatch,endpoint):
    from icheck.device_preflight_worker import execute_device_preflight
    server,state=endpoint
    doc,path,_,_=draft(client,monkeypatch,"containers",port=server.server_port)
    queued,payload=target(client,path,doc,"containers")
    request=spec(); state.update(body=metric_body(request),content_type="text/plain")
    from icheck.exporter_metrics import fetch_http as actual_fetch
    def transport(spec,host,port,headers,**kwargs):
        assert host=="198.18.1.10" and port==server.server_port
        return actual_fetch(spec,"127.0.0.1",port,headers,**kwargs)
    monkeypatch.setattr("icheck.exporter_metrics.fetch_http",transport)
    complete(client,queued,payload,"containers",executor=lambda claim:execute_device_preflight(claim,
        allowed_targets=["198.18.1.0/24"],timeout_seconds=3,snmp_exporter_url=None,exporter_allowed_hosts=[],snmp_allowed_targets=[],lease_seconds=60))
    state=get_state(client,path,payload).json()
    assert state["stage"]=="tested_not_enabled" and state["target_test"]["container_count"]==1
    assert not state["target_test"]["application_health_verified"]


def test_container_gateway_rechecks_withdrawal_after_filtered_scrape(client,monkeypatch,gateway):
    from icheck.container_metrics import render_container_metrics
    subject,config,_=gateway
    _,path,payload,state=enabled(client,monkeypatch,"containers")
    request=ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"])
    exporter_gateway(config,request,state["template"]["port"])
    assert len(subject.discovery())==1
    def read(*args,**kwargs):
        assert client.post(f"/api/v1/assets/devices/{payload['device_id']}/connections/{payload['connection_id']}/monitoring/withdraw",
            json={"expected_revision":1,"actor":"test.admin","reason":"Withdraw the container fixture during I/O."}).status_code==200
        return render_container_metrics(request,metric_body(request))
    monkeypatch.setattr("icheck.monitoring_gateway.collect_exporter",read)
    with pytest.raises(GatewayError): subject.scrape(state["monitoring"]["enrollment"]["id"])
    assert subject.discovery()==[]


def fresh_reader(monkeypatch,payload,state,*,fault=None):
    request=ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"])
    business=list(request.metrics())+["container_last_seen"]; names=business+["container_scrape_error"]
    stamp=utcnow().timestamp()-(2000 if fault=="stale" else 0)
    labels={"job":"icheck_continuous","icheck_tenant_id":DEFAULT_TENANT_ID,"icheck_region_id":DEFAULT_REGION_ID,
        "icheck_device_id":payload["device_id"],"icheck_connection_id":payload["connection_id"],
        "icheck_enrollment_id":state["monitoring"]["enrollment"]["id"],"icheck_enrollment_revision":"1"}
    def query(db,backend,payload,**kwargs):
        expression=payload.query
        if expression.startswith("count by (__name__)"):
            result=[{"metric":{"__name__":name},"value":[stamp,"1"]} for name in names if fault!="up_only"]
        elif expression.startswith("count by (id,"):
            result=[{"metric":{"__name__":name,"id":"/docker/fixture-app" if fault!="split_container" or index%2==0 else "/docker/other"},"value":[stamp,"1"]} for index,name in enumerate(business)]
        elif expression.startswith("label_replace"):
            result=[{"metric":{"icheck_metric_name":name},"value":[stamp,str(stamp)]} for name in names]
        elif expression.startswith("container_scrape_error"):
            result=[{"metric":labels,"value":[stamp,"1" if fault=="error" else "0"]}]
        else: result=[{"metric":labels,"value":[stamp,"1"]}]
        return SimpleNamespace(result_type="vector",result=result)
    monkeypatch.setattr("icheck.services.metrics.query_instant",query)


@pytest.mark.parametrize("fault",[None,"up_only","stale","split_container","error"])
def test_container_freshness_needs_each_metric_on_the_same_runtime_container(client,monkeypatch,fault):
    _,path,payload,state=enabled(client,monkeypatch,"containers")
    with SessionLocal() as db:
        db.add(MetricBackend(name="fixture-container-prometheus",provider="prometheus",query_base_url="https://prometheus.example.test",
            external_labels={},enabled=True,created_by="test")); db.commit()
    fresh_reader(monkeypatch,payload,state,fault=fault)
    response=get_state(client,path,payload,verify_samples="true")
    assert response.status_code==200,response.text
    assert response.json()["fresh_samples_verified"] is (fault is None)


def test_container_grafana_uses_cores_and_guarded_limit_without_workload_health_claim(client,monkeypatch,tmp_path):
    from icheck.config import get_settings
    from icheck.services import grafana
    from test_grafana_plugin import FakeGrafana
    _,path,payload,state=enabled(client,monkeypatch,"containers")
    with SessionLocal() as db:
        db.add(MetricBackend(name="fixture-container-prometheus",provider="prometheus",query_base_url="https://prometheus.example.test",
            external_labels={},enabled=True,created_by="test")); db.commit()
    fresh_reader(monkeypatch,payload,state)
    key=tmp_path/"grafana.key"; key.write_bytes(b"g"*32); key.chmod(0o400)
    monkeypatch.setenv("ICHECK_GRAFANA_SECRET_KEY_FILE",str(key)); get_settings.cache_clear()
    request=spec(); fake=FakeGrafana(); fake.metrics=lambda _:list(request.metrics())
    monkeypatch.setattr(grafana,"CLIENT",fake)
    try:
        connection=client.post("/api/v1/grafana/connections",json={"name":"fixture-container-grafana","public_url":"https://icheck.test/grafana/",
            "token":"synthetic-grafana-token","shared_dataset_acknowledged":True}).json()
        params={key:payload[key] for key in ("artifact_version_id","device_id","connection_id")}|{"grafana_connection_id":connection["id"]}
        proposal=client.post(path+"/monitoring/dashboard-proposal",params=params)
        assert proposal.status_code==200,proposal.text
        panels=proposal.json()["definition"]["panels"]
        assert any(p["title"]=="Container CPU cores" for p in panels)
        assert any(" > 0)" in p["targets"][0]["expr"] for p in panels)
        assert any(p["title"]=="Container age" for p in panels) and fake.writes==[]
        confirmed=client.post(f"/api/v1/grafana/changes/{proposal.json()['id']}/confirm",json={"confirm":True,"expected_plan_hash":proposal.json()["plan_hash"]})
        assert confirmed.status_code==200,confirmed.text
        assert get_state(client,path,payload).json()["grafana_dashboard_url"].startswith("https://icheck.test/grafana/d/icheck-containers-")
    finally: get_settings.cache_clear()
