"""One VMware exporter source path; fixtures are not real-vSphere acceptance."""
import json
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from icheck.database import SessionLocal, DEFAULT_TENANT_ID, DEFAULT_REGION_ID
from icheck.device_preflight_worker import execute_device_preflight
from icheck.exporter_metrics import ExporterMonitorSpec, collect, validate_response, health_metric
from icheck.http_metrics import HTTPMetricError
from icheck.models import MetricBackend, CredentialProfile, utcnow
from icheck.monitoring_gateway import GatewayError
from icheck.vmware_metrics import CATALOG, LABEL, render_vmware_metrics
from test_exporter_monitoring import human, draft, target, complete, enabled, spec as exporter_spec, metric_body, exporter_gateway
from test_http_monitoring import endpoint
from test_http_monitoring_studio import get_state
from test_managed_device_credentials import device_key
from test_monitoring_gateway import gateway


def spec(scope="hosts", **changes):
    return exporter_spec("vmware", vmware_scope=scope, vmware_name="fixture-esxi" if scope=="hosts" else "fixture-app" if scope=="vms" else "fixture-ds",
        groups=["disk"] if scope=="datastores" else ["cpu","memory","uptime"], **changes)


@pytest.mark.parametrize("scope", ["hosts","vms","datastores"])
def test_vmware_actual_wire_and_worker_require_selected_object_measurements(endpoint, scope):
    server, state=endpoint; request=spec(scope).model_copy(update={"groups":list(CATALOG[scope])})
    body=metric_body(request).replace(b'dc_name="fixture-dc"',b'dc_name="fixture-dc",tags="private-team",custom_secret="not-for-prometheus"')
    state.update(body=body,content_type="text/plain")
    projected, proof=collect(request,"127.0.0.1",server.server_port,deadline=time.monotonic()+3)
    assert state["calls"][0][0]=="/metrics"  # Never forward target/section overrides.
    assert b"private-team" not in projected and b"custom_secret" not in projected
    assert proof["vmware_name"]==request.vmware_name and proof["collector_success"]
    assert proof["source_timestamp_available"] is False and not proof["object_health_verified"]
    assert validate_response(request,projected)["success"]
    assignment={"adapter_type":"vmware_exporter","target_host":"127.0.0.1","port":server.server_port,"configuration":{"exporter_monitor":request.model_dump()}}
    evidence,_=execute_device_preflight(assignment,allowed_targets=["127.0.0.1/32"],timeout_seconds=3,
        snmp_exporter_url=None,exporter_allowed_hosts=[],snmp_allowed_targets=[],lease_seconds=60)
    assert evidence["check"]=="native_exporter_metric_query" and evidence["metric_names"]==sorted(request.metrics())


@pytest.mark.parametrize("fault", ["missing_metric","wrong_name","ambiguous_dc","split_identity","missing_dc","bad_type","nonfinite","timestamp","duplicate","credential_echo","bad_state","oversized"])
def test_vmware_projection_fails_closed_without_complete_unambiguous_measurements(fault):
    request=spec(); body=metric_body(request); options={}
    if fault=="missing_metric": body=b"\n".join(line for line in body.splitlines() if not line.startswith(b"vmware_host_memory_usage{"))+b"\n"
    if fault=="wrong_name": body=body.replace(b"fixture-esxi",b"another-esxi")
    if fault=="ambiguous_dc": body+=body.replace(b"fixture-dc",b"other-dc"); request=request.model_copy(update={"vmware_datacenter":None})
    if fault=="split_identity": body=body.replace(b'vmware_host_cpu_usage{',b'vmware_host_cpu_usage{cluster_name="different-cluster",')
    if fault=="missing_dc": body=body.replace(b',dc_name="fixture-dc"',b""); request=request.model_copy(update={"vmware_datacenter":None})
    if fault=="bad_type": body=body.replace(b"vmware_host_cpu_usage gauge",b"vmware_host_cpu_usage counter")
    if fault=="nonfinite": body+=b"bad_metric NaN\n"
    if fault=="timestamp": body=b"\n".join(line+b" 123" if line.startswith(b"vmware_host_cpu_usage{") else line for line in body.splitlines())+b"\n"
    if fault=="duplicate": body+=next(line for line in body.splitlines() if line.startswith(b"vmware_host_cpu_usage{"))+b"\n"
    if fault=="credential_echo": body+=b"# protected synthetic-private-token\n"; options["values"]={"token":"synthetic-private-token"}
    if fault=="bad_state": body=body.replace(b"} 1\n",b"} 2\n",1)
    if fault=="oversized": body+=b"#"*2_000_000
    with pytest.raises(HTTPMetricError): validate_response(request,body,**options)


def test_vmware_scope_selection_and_guest_disk_partition_coverage():
    with pytest.raises(ValidationError): exporter_spec("vmware",vmware_scope="datastores",groups=["cpu"])
    with pytest.raises(ValidationError): ExporterMonitorSpec(plugin="vmware",groups=["cpu"])
    with pytest.raises(ValidationError): ExporterMonitorSpec(plugin="linux",groups=["cpu"],vmware_scope="hosts",vmware_name="invented")
    request=spec("vms").model_copy(update={"groups":["disk"]})
    body=metric_body(request)
    assert validate_response(request,body)["success"]
    lines=body.splitlines()
    body=b"\n".join(line.replace(b'partition="/"',b'partition="/var"') if line.startswith(b"vmware_vm_guest_disk_free{") else line for line in lines)+b"\n"
    with pytest.raises(HTTPMetricError): validate_response(request,body)


@pytest.mark.parametrize("scope", ["hosts","vms","datastores"])
def test_vmware_studio_reuses_reviewed_enable_and_does_not_claim_collection(client,monkeypatch,scope):
    _,path,payload,state=enabled(client,monkeypatch,"vmware",vmware_scope=scope)
    assert state["stage"]=="enabled_awaiting_fresh_samples" and not state["fresh_samples_verified"]
    target=client.get("/api/v1/monitoring/targets").json()["targets"][0]
    assert target["protocol"]=="vmware_exporter" and target["collectors"]==[scope]
    assert target["exporter_monitor"]["vmware_scope"]==scope


def fresh_reader(monkeypatch,payload,state,*,fault=None):
    request=ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"])
    names=list(request.metrics())+[health_metric(request)]; label=LABEL[request.vmware_scope]
    stamp=utcnow().timestamp()-(2000 if fault=="stale" else 0)
    namespace={"job":"icheck_continuous","icheck_tenant_id":DEFAULT_TENANT_ID,"icheck_region_id":DEFAULT_REGION_ID,
        "icheck_device_id":payload["device_id"],"icheck_connection_id":payload["connection_id"],
        "icheck_enrollment_id":state["monitoring"]["enrollment"]["id"],"icheck_enrollment_revision":"1"}
    entity={label:request.vmware_name,"dc_name":"fixture-dc"}
    def query(db,backend,payload,**kwargs):
        expression=payload.query
        if expression.startswith("count by (__name__)"):
            result=[{"metric":{"__name__":name},"value":[stamp,"1"]} for name in names if fault!="up_only"]
        elif expression.startswith("count by (partition,"):
            result=[{"metric":{"__name__":name,"partition":"/" if index==0 or fault!="split_partition" else "/var"},"value":[stamp,"1"]}
                for index,name in enumerate(["vmware_vm_guest_disk_capacity","vmware_vm_guest_disk_free"])]
        elif expression.startswith("count by ("+label):
            result=[{"metric":{"__name__":name,**entity,**({label:"another-object"} if fault=="wrong_object" and index==0 else {})},"value":[stamp,"1"]}
                for index,name in enumerate(names)]
        elif expression.startswith("label_replace"):
            result=[{"metric":{"icheck_metric_name":name},"value":[stamp,str(stamp)]} for name in names]
        elif expression.startswith(health_metric(request)):
            result=[{"metric":{**namespace,**entity},"value":[stamp,"2" if fault=="bad_state" else "0" if fault=="object_off" else "1"]}]
        else: result=[{"metric":namespace,"value":[stamp,"1"]}]
        return SimpleNamespace(result_type="vector",result=result)
    monkeypatch.setattr("icheck.services.metrics.query_instant",query)


@pytest.mark.parametrize("fault", [None,"up_only","stale","wrong_object","bad_state","object_off","split_partition"])
def test_vmware_freshness_is_selected_object_collection_not_fault_resolution(client,monkeypatch,fault):
    _,path,payload,state=enabled(client,monkeypatch,"vmware",vmware_scope="vms",groups=["cpu","disk"])
    with SessionLocal() as db:
        db.add(MetricBackend(name="fixture-vmware-prometheus",provider="prometheus",query_base_url="https://prometheus.example.test",
            external_labels={},enabled=True,created_by="test")); db.commit()
    fresh_reader(monkeypatch,payload,state,fault=fault)
    result=get_state(client,path,payload,verify_samples="true")
    assert result.status_code==200,result.text
    assert result.json()["fresh_samples_verified"] is (fault in {None,"object_off"})


def test_vmware_gateway_rechecks_current_authority_after_projection(client,monkeypatch,gateway):
    subject,config,_=gateway
    _,path,payload,state=enabled(client,monkeypatch,"vmware")
    request=ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"])
    exporter_gateway(config,request,state["template"]["port"])
    assert len(subject.discovery())==1
    def read(*args,**kwargs):
        assert client.post(f"/api/v1/assets/devices/{payload['device_id']}/connections/{payload['connection_id']}/monitoring/withdraw",
            json={"expected_revision":1,"actor":"test.admin","reason":"Withdraw VMware fixture while the wire read is pending."}).status_code==200
        return render_vmware_metrics(request,metric_body(request))
    monkeypatch.setattr("icheck.monitoring_gateway.collect_exporter",read)
    with pytest.raises(GatewayError): subject.scrape(state["monitoring"]["enrollment"]["id"])
    assert subject.discovery()==[]


def test_previous_container_http_credentials_resolve_and_rotate_without_expanding_scope(client,device_key):
    from icheck.services.device_credentials import resolve
    profile=client.post("/api/v1/device-credentials",json={"name":"prior-containers","kind":"https_token","site":"LAB","token":"synthetic-token"}).json()
    previous=["http_json","http_json_sandbox","node_exporter","windows_exporter","cadvisor"]
    with SessionLocal() as db:
        row=db.get(CredentialProfile,profile["id"]); row.allowed_adapters=previous; db.commit()
        assert resolve(db,row)=={"token":"synthetic-token"}
    rotated=client.put("/api/v1/device-credentials/"+profile["id"],json={"name":"prior-containers","kind":"https_token","site":"LAB",
        "token":"synthetic-rotated-token","expected_revision":1,"reason":"Rotate within the original container credential scope."})
    assert rotated.status_code==200 and rotated.json()["allowed_adapters"]==previous


@pytest.mark.parametrize("scope", ["hosts","vms","datastores"])
def test_vmware_grafana_proposal_confirms_units_gauges_and_saved_url(client,monkeypatch,tmp_path,scope):
    from icheck.config import get_settings
    from icheck.services import grafana
    from test_grafana_plugin import FakeGrafana
    _,path,payload,state=enabled(client,monkeypatch,"vmware",vmware_scope=scope)
    request=ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"])
    with SessionLocal() as db:
        db.add(MetricBackend(name="fixture-vmware-prometheus",provider="prometheus",query_base_url="https://prometheus.example.test",
            external_labels={},enabled=True,created_by="test")); db.commit()
    fresh_reader(monkeypatch,payload,state)
    key=tmp_path/"grafana.key"; key.write_bytes(b"g"*32); key.chmod(0o400)
    monkeypatch.setenv("ICHECK_GRAFANA_SECRET_KEY_FILE",str(key)); get_settings.cache_clear()
    fake=FakeGrafana(); fake.metrics=lambda _:list(request.metrics()); monkeypatch.setattr(grafana,"CLIENT",fake)
    try:
        connection=client.post("/api/v1/grafana/connections",json={"name":"fixture-vmware-grafana","public_url":"https://icheck.test/grafana/",
            "token":"synthetic-grafana-token","shared_dataset_acknowledged":True}).json()
        params={key:payload[key] for key in ("artifact_version_id","device_id","connection_id")}|{"grafana_connection_id":connection["id"]}
        proposal=client.post(path+"/monitoring/dashboard-proposal",params=params)
        assert proposal.status_code==200,proposal.text
        panels=proposal.json()["definition"]["panels"]
        assert not any("rate(" in panel["targets"][0]["expr"] for panel in panels)
        assert any(" > 0)" in panel["targets"][0]["expr"] for panel in panels)
        if scope=="vms":
            assert any(panel["title"]=="vmware_vm_mem_usage_average" and panel["targets"][0]["expr"].endswith(" / 100")
                and panel["fieldConfig"]["defaults"]["unit"]=="percent" for panel in panels)
        if scope=="hosts": assert any(" * 1024 * 1024" in panel["targets"][0]["expr"] for panel in panels)
        assert fake.writes==[]
        confirmed=client.post(f"/api/v1/grafana/changes/{proposal.json()['id']}/confirm",json={"confirm":True,"expected_plan_hash":proposal.json()["plan_hash"]})
        assert confirmed.status_code==200,confirmed.text
        assert len(fake.writes)==1
        assert get_state(client,path,payload).json()["grafana_dashboard_url"].startswith("https://icheck.test/grafana/d/icheck-vmware-")
    finally: get_settings.cache_clear()
