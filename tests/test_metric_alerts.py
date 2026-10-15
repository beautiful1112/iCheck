"""One native metric-rule path; private engine checks are not live deployment."""
from contextlib import contextmanager
from datetime import datetime,timedelta
import json
from types import SimpleNamespace
from dataclasses import replace

import pytest
from sqlalchemy import select
from icheck.auth import current_principal
from icheck.config import get_settings
from icheck.database import SessionLocal,DEFAULT_TENANT_ID,DEFAULT_REGION_ID
from icheck.main import app
from icheck.models import AlertRule,MetricRuleChange,MetricBackend,utcnow
from icheck.metric_rule_runtime import catalog,digest,RuleRuntimeUnknown,RuleRuntimeConflict
from icheck.services import metric_alerts
from icheck.services.control_plane_auth import PrincipalContext
from test_http_monitoring_studio import collecting, fresh_reader
from test_preview_alert_workspace import administrator
from test_http_monitoring import endpoint

ACTUAL_QUERY_INSTANT=metric_alerts.metrics.query_instant


class FakeRuntime:
    def __init__(self,backend_id):
        self.binding={"backend_id":backend_id,"tenant_id":DEFAULT_TENANT_ID,"region_id":DEFAULT_REGION_ID,"receiver":"icheck-inbox"}
        self.document=catalog(); self.loaded=catalog(); self.writes=[]; self.reloads=0; self.response_loss=False; self.before_admit=None
    def guard(self,actor,backend_id):
        if (actor.tenant_id,actor.region_id,backend_id)!=(DEFAULT_TENANT_ID,DEFAULT_REGION_ID,self.binding["backend_id"]): raise RuleRuntimeConflict("Wrong runtime namespace/backend")
    @contextmanager
    def lock(self): yield
    def read(self): return self.document
    def write(self,document,expected_hash,*,admit=lambda:None):
        if digest(self.document)!=expected_hash: raise RuleRuntimeConflict("Catalog changed")
        if self.before_admit: self.before_admit()
        admit(); self.writes.append(document); self.document=document
    def reload(self):
        self.reloads+=1; self.loaded=self.document
        if self.response_loss: raise RuleRuntimeUnknown("Synthetic reload response loss")
    def matches(self,document): return self.loaded==document


@pytest.fixture
def prepared(client,administrator,monkeypatch,tmp_path):
    client.headers.update(administrator)
    client.headers.update({"X-Icheck-Tenant-ID":DEFAULT_TENANT_ID,"X-Icheck-Region-ID":DEFAULT_REGION_ID})
    doc,path,target,state=collecting(client,monkeypatch)
    # Reuse the real Studio/dashboard confirmation path, with a named fake wire.
    from icheck.services import grafana
    from test_grafana_plugin import FakeGrafana
    key=tmp_path/"grafana.key"; key.write_bytes(b"g"*32); key.chmod(0o400)
    monkeypatch.setenv("ICHECK_GRAFANA_SECRET_KEY_FILE",str(key)); get_settings.cache_clear()
    fake=FakeGrafana(); fake.metrics=lambda _: ["vendor_queue_depth","icheck_http_request_success","icheck_http_request_duration_seconds"]
    monkeypatch.setattr(grafana,"CLIENT",fake); fresh_reader(monkeypatch,target,state)
    connection=client.post("/api/v1/grafana/connections",json={"name":"metric-fixture","public_url":"https://icheck.test/grafana/",
        "token":"fixture-only-grafana-token","shared_dataset_acknowledged":True})
    assert connection.status_code==201,connection.text
    proposed=client.post(path+"/monitoring/dashboard-proposal",params={key:target[key] for key in ("artifact_version_id","device_id","connection_id")}
        | {"grafana_connection_id":connection.json()["id"]})
    assert proposed.status_code==200,proposed.text
    applied=client.post("/api/v1/grafana/changes/"+proposed.json()["id"]+"/confirm",json={"confirm":True,"expected_plan_hash":proposed.json()["plan_hash"]})
    assert applied.status_code==200 and applied.json()["status"]=="applied",applied.text
    with SessionLocal() as db: backend_id=db.scalar(select(MetricBackend.id))
    monkeypatch.setenv("ICHECK_METRIC_RULE_BACKEND_ID",backend_id); get_settings.cache_clear()
    runtime=FakeRuntime(backend_id); monkeypatch.setattr(metric_alerts,"RUNTIME",lambda:runtime)
    def query(db,backend,payload,**kwargs):
        db.commit()  # Production query auditing commits; confirmation must reacquire authority.
        value=utcnow().timestamp() if payload.query.startswith("min(timestamp") else 7
        return SimpleNamespace(result_type="vector",result=[{"metric":{},"value":[utcnow().timestamp(),str(value)]}])
    monkeypatch.setattr("icheck.services.metrics.query_instant",query)
    definition={"name":"Queue depth high","backend_id":backend_id,"enrollment_id":state["monitoring"]["enrollment"]["id"],
        "metric":"vendor_queue_depth","threshold":5,"hold_seconds":0,"severity":"critical"}
    return runtime,definition,target,state


def preview(client,definition,**kwargs):
    response=client.post("/api/v1/metric-alerts/preview",json={"definition":definition,**kwargs})
    assert response.status_code==201,response.text
    return response.json()


def confirm(client,proposal):
    return client.post("/api/v1/metric-alerts/changes/"+proposal["id"]+"/confirm",json={"confirm":True,"expected_plan_hash":proposal["plan_hash"]})


def notification(proposal,*,status="firing",starts=None,ends=None):
    rule=proposal["compiled_rule"]; now=utcnow()
    return {"version":"4","receiver":"icheck-inbox","status":status,"notification_reason":"group_interval",
        "groupLabels":{"icheck_metric_rule_id":proposal["rule_id"]},"routeLabels":{},"commonLabels":{},"commonAnnotations":{},
        "alerts":[{"status":status,"labels":{"alertname":rule["alert"],**rule["labels"],"unsafe_custom_label":"not-stored"},
            "annotations":{"summary":"untrusted summary","dashboard_url":"https://untrusted.test/?token=must-not-be-stored"},
            "startsAt":(starts or now-timedelta(seconds=2)).isoformat(),"endsAt":(ends or now).isoformat(),
            "generatorURL":"https://untrusted.test/?secret=not-stored","fingerprint":"untrusted-fingerprint"}]}


def service_actor(monkeypatch):
    monkeypatch.setenv("ICHECK_METRIC_ALERT_WEBHOOK_SUBJECT","alertmanager.fixture"); get_settings.cache_clear()
    actor=PrincipalContext(principal_id="fixture-service",subject="alertmanager.fixture",principal_type="service",auth_method="bearer",
        permissions=frozenset({"alerts.emit","assets.read"}),authorization_scope={"all":True},role_names=("metric-receiver",),
        tenant_id=DEFAULT_TENANT_ID,region_id=DEFAULT_REGION_ID)
    app.dependency_overrides[current_principal]=lambda:actor
    return actor


def test_native_rule_preview_then_exact_human_confirmation(client,prepared):
    runtime,definition,target,_=prepared
    proposal=preview(client,definition)
    assert runtime.writes==[] and proposal["status"]=="proposed"
    assert "icheck_enrollment_revision" in proposal["compiled_rule"]["expr"]
    assert proposal["test_evidence"]["current_value"]==7
    assert all(rule["event_type"]!="metric.prometheus" for rule in client.get("/api/v1/alert-rules").json())
    applied=confirm(client,proposal)
    assert applied.status_code==200,applied.text
    assert applied.json()["status"]=="applied" and len(runtime.writes)==1
    assert confirm(client,proposal).json()["status"]=="applied" and len(runtime.writes)==1
    assert client.get("/api/v1/metric-alerts/rules").json()[0]["revision"]==1


def test_alert_requires_saved_relevant_dashboard_not_generic_link(client,prepared):
    from icheck.models import GrafanaConnection
    runtime,definition,_,_=prepared
    with SessionLocal() as db:
        db.scalar(select(GrafanaConnection)).enabled=False; db.commit()
    response=client.post("/api/v1/metric-alerts/preview",json={"definition":definition})
    assert response.status_code==400 and "Grafana dashboard" in response.json()["detail"]
    assert runtime.writes==[]


def test_custom_saved_dashboard_can_replace_the_generated_dashboard(client,prepared):
    from copy import deepcopy
    from icheck.models import GrafanaChange
    _,definition,_,_=prepared
    with SessionLocal() as db:
        saved=db.scalar(select(GrafanaChange)); custom=deepcopy(saved.definition)
        connection_id=saved.connection_id; generated_uid=saved.resource_uid
        version=saved.applied_resource["metadata"]["resourceVersion"]
    def save(uid,spec,expected=None):
        payload={"resource_uid":uid,"definition":spec}
        if expected: payload["expected_resource_version"]=expected
        proposed=client.post(f"/api/v1/grafana/connections/{connection_id}/preview",json=payload)
        assert proposed.status_code==201,proposed.text
        response=client.post("/api/v1/grafana/changes/"+proposed.json()["id"]+"/confirm",
            json={"confirm":True,"expected_plan_hash":proposed.json()["plan_hash"]})
        assert response.status_code==200 and response.json()["status"]=="applied",response.text
    save("custom-queue-dashboard",custom)
    # The latest generated dashboard no longer includes the requested metric.
    revised=deepcopy(custom)
    for panel in revised["panels"]:
        for query in panel.get("targets",[]): query["expr"]=query["expr"].replace("vendor_queue_depth","icheck_http_request_success")
    save(generated_uid,revised,version)
    proposal=preview(client,definition)
    assert "/d/custom-queue-dashboard?" in proposal["compiled_rule"]["annotations"]["dashboard_url"]


def test_native_ai_tools_use_existing_executor_and_never_enable_rules(client,prepared):
    from icheck.builtin_agent_tools import ensure_builtin_agent_tools
    from icheck.models import AgentToolRegistration,Investigation
    from icheck.services.agent_tools import DatabaseToolExecutor
    from icheck.services.agent_authorization import tool_scope_allows
    from icheck.schema_validation import validate_instance
    runtime,definition,_,_=prepared
    assert client.get("/api/v1/metric-alerts/setup").json()["runtime_provisioned"] is True
    with SessionLocal() as db:
        from icheck.database import set_session_namespace
        set_session_namespace(db,DEFAULT_TENANT_ID,DEFAULT_REGION_ID)
        ensure_builtin_agent_tools(db)
        investigation=Investigation(title="Prepare a queue alert",objective="Return a human review URL, not an active rule",
            scope={},route_id="fixture-route",model_id="fixture-model",created_by="operator.fixture",
            permission_snapshot=["alerts.read","metrics.read"],authorization_scope={"all":True})
        executor=DatabaseToolExecutor(db,investigation)
        registrations={row.name:row for row in db.scalars(select(AgentToolRegistration).where(AgentToolRegistration.name.like("alerts.metric%")))}
        assert len(registrations)==3 and all(row.read_only for row in registrations.values())
        result,evidence=executor._execute(registrations["alerts.metric_rules.targets"],{},tool_call_id="fixture-targets")
        assert result["backend_id"]==definition["backend_id"] and result["targets"][0]["enrollment_id"]==definition["enrollment_id"]
        assert evidence[0].evidence_type=="metric_rule"
        arguments={"definition":definition}
        validate_instance(arguments,registrations["alerts.metric_rule.preview"].input_schema,"metric rule preview input")
        proposal,evidence=executor._execute(registrations["alerts.metric_rule.preview"],arguments,tool_call_id="fixture-preview")
        assert proposal["status"]=="proposed" and proposal["review_url"].startswith("/alerts/metric-rules?proposal=")
        receipt,_=executor._execute(registrations["alerts.metric_rule.change.get"],{"change_id":proposal["id"]},tool_call_id="fixture-receipt")
        assert receipt["plan_hash"]==proposal["plan_hash"] and runtime.writes==[]
        investigation.authorization_scope={"sites":["LAB"]}
        assert not tool_scope_allows(investigation,registrations["alerts.metric_rule.preview"])


def test_reload_response_loss_is_inspected_without_repeating_write(client,prepared):
    runtime,definition,_,_=prepared; proposal=preview(client,definition); runtime.response_loss=True
    result=confirm(client,proposal)
    assert result.status_code==200 and result.json()["status"]=="unknown"
    assert len(runtime.writes)==1 and runtime.reloads==1
    runtime.response_loss=False
    result=confirm(client,proposal)
    assert result.json()["status"]=="applied" and len(runtime.writes)==1 and runtime.reloads==1


def test_revision_restore_and_withdrawal_do_not_need_unavailable_source_data(client,prepared,monkeypatch):
    runtime,definition,target,_=prepared
    first=preview(client,definition); assert confirm(client,first).json()["status"]=="applied"
    second=preview(client,{**definition,"threshold":9},rule_id=first["rule_id"],expected_revision=1)
    assert confirm(client,second).json()["status"]=="applied"
    restored=client.post("/api/v1/metric-alerts/changes/"+second["id"]+"/restore-preview")
    assert restored.status_code==201,restored.text
    assert restored.json()["definition"]["threshold"]==5
    assert confirm(client,restored.json()).json()["revision"]==3
    assert client.post(f"/api/v1/assets/devices/{target['device_id']}/connections/{target['connection_id']}/monitoring/withdraw",
        json={"expected_revision":1,"actor":"admin","reason":"Withdraw this synthetic source before disabling its native rule."}).status_code==200
    def unavailable(*args,**kwargs): raise AssertionError("Withdrawal must not query unavailable metric data")
    monkeypatch.setattr("icheck.services.metrics.query_instant",unavailable)
    disabled=preview(client,{**first["definition"],"enabled":False},rule_id=first["rule_id"],expected_revision=3)
    assert confirm(client,disabled).json()["status"]=="applied"
    assert runtime.document==catalog()
    with SessionLocal() as db:
        row=db.get(AlertRule,first["rule_id"])
        assert not row.enabled and row.conditions["revision"]==4
        assert len(db.scalars(select(MetricRuleChange).where(MetricRuleChange.rule_id==row.id)).all())==4


def test_receiver_clearance_cannot_become_quiet_recovery_proof(client,prepared,monkeypatch):
    from icheck.models import AlertConditionState
    _,definition,_,_=prepared; proposal=preview(client,definition)
    assert confirm(client,proposal).json()["status"]=="applied"
    payload=notification(proposal); service_actor(monkeypatch)
    try:
        assert client.post("/api/v1/metric-alerts/webhook",json=payload).status_code==200
        cleared=notification(proposal,status="resolved",starts=datetime.fromisoformat(payload["alerts"][0]["startsAt"]))
        assert client.post("/api/v1/metric-alerts/webhook",json=cleared).status_code==200
    finally: app.dependency_overrides.pop(current_principal,None)
    with SessionLocal() as db:
        state=db.scalar(select(AlertConditionState).where(AlertConditionState.dedup_key=="metric:"+proposal["rule_id"]+":1"))
        assert state.state=="unknown"


def test_service_identity_cannot_confirm_native_rule(client,prepared,monkeypatch):
    runtime,definition,_,_=prepared; proposal=preview(client,definition)
    actor=service_actor(monkeypatch)
    app.dependency_overrides[current_principal]=lambda:replace(actor,permissions=frozenset({"*"}))
    try: result=confirm(client,proposal)
    finally: app.dependency_overrides.pop(current_principal,None)
    assert result.status_code==403 and runtime.writes==[]


@pytest.mark.parametrize("fault",["metric","boolean","nonfinite","template","source_revision","plan_hash","catalog"])
def test_rule_input_and_current_authority_fail_closed(client,prepared,fault):
    runtime,definition,target,state=prepared
    if fault in {"metric","boolean","nonfinite","template"}:
        invalid={**definition}
        if fault=="metric": invalid["metric"]="not_declared"
        if fault=="boolean": invalid["threshold"]=True
        if fault=="nonfinite": invalid["threshold"]="Infinity"
        if fault=="template": invalid["name"]="{{ query another_tenant_metric }}"
        response=client.post("/api/v1/metric-alerts/preview",json={"definition":invalid})
        assert response.status_code in {400,422} and runtime.writes==[]
        return
    proposal=preview(client,definition)
    if fault=="source_revision":
        assert client.post(f"/api/v1/assets/devices/{target['device_id']}/connections/{target['connection_id']}/monitoring/withdraw",
            json={"expected_revision":1,"actor":"admin","reason":"Withdraw before native rule confirmation."}).status_code==200
    if fault=="plan_hash": proposal["plan_hash"]="0"*64
    if fault=="catalog": runtime.document=catalog([{**proposal["compiled_rule"],"alert":"unrelated-native-rule"}])
    result=confirm(client,proposal)
    assert result.status_code in {400,404,409} and runtime.writes==[]


def test_webhook_retains_episode_links_and_ack_is_not_clearance(client,prepared,monkeypatch):
    runtime,definition,_,_=prepared; proposal=preview(client,definition)
    assert confirm(client,proposal).json()["status"]=="applied"
    payload=notification(proposal)
    assert client.post("/api/v1/metric-alerts/webhook",json=payload).status_code==403
    service_actor(monkeypatch)
    try:
        response=client.post("/api/v1/metric-alerts/webhook",json=payload)
        assert response.status_code==200,response.text
        identifier=response.json()["episodes"][0]["alert_id"]
        replay=client.post("/api/v1/metric-alerts/webhook",json=payload)
        assert replay.json()["episodes"][0]["alert_id"]==identifier
    finally: app.dependency_overrides.pop(current_principal,None)
    episode=next(row for row in client.get("/api/v1/alerts").json() if row["id"]==identifier)
    assert episode["status"]=="open" and episode["occurrence_count"]==1
    assert episode["details"]["dashboard_url"].startswith("https://icheck.test/grafana/d/icheck-http-") and episode["details"]["investigation_url"].startswith("/?brief=")
    assert "unsafe_custom_label" not in json.dumps(episode) and "untrusted.test" not in json.dumps(episode)
    assert episode["details"]["fault_recovery_verified"] is False
    acknowledged=client.post(f"/api/v1/alerts/{identifier}/acknowledge",json={"actor":"spoofed"})
    assert acknowledged.status_code==200 and acknowledged.json()["status"]=="acknowledged"
    assert client.post(f"/api/v1/alerts/{identifier}/resolve",json={"actor":"admin"}).status_code==409
    service_actor(monkeypatch)
    try:
        cleared=notification(proposal,status="resolved",starts=datetime.fromisoformat(payload["alerts"][0]["startsAt"]))
        assert client.post("/api/v1/metric-alerts/webhook",json=cleared).status_code==200
        assert client.post("/api/v1/metric-alerts/webhook",json=payload).status_code==200  # Late old firing cannot reopen.
    finally: app.dependency_overrides.pop(current_principal,None)
    episode=next(row for row in client.get("/api/v1/alerts").json() if row["id"]==identifier)
    assert episode["status"]=="resolved" and episode["details"]["fault_recovery_verified"] is False
    assert "recovery unverified" in episode["resolved_by"]


@pytest.mark.parametrize("fault",["namespace","revision","receiver","truncated","time","oversize"])
def test_untrusted_notification_cannot_cross_source_boundary(client,prepared,monkeypatch,fault):
    _,definition,_,_=prepared; proposal=preview(client,definition)
    assert confirm(client,proposal).json()["status"]=="applied"
    payload=notification(proposal)
    if fault=="namespace": payload["alerts"][0]["labels"]["icheck_tenant_id"]="other"
    if fault=="revision": payload["alerts"][0]["labels"]["icheck_metric_rule_revision"]="99"
    if fault=="receiver": payload["receiver"]="another-receiver"
    if fault=="truncated": payload["truncatedAlerts"]=1
    if fault=="time": payload["alerts"][0]["startsAt"]=(utcnow()+timedelta(seconds=60)).isoformat()
    if fault=="oversize": payload["alerts"][0]["annotations"]["oversized"]="x"*256000
    service_actor(monkeypatch)
    try: result=client.post("/api/v1/metric-alerts/webhook",json=payload)
    finally: app.dependency_overrides.pop(current_principal,None)
    assert result.status_code in {400,403,413,422}
    assert client.get("/api/v1/alerts").json()==[]


def test_private_native_deployment_examples_are_valid(tmp_path):
    import os,subprocess
    from pathlib import Path
    import yaml
    prometheus=os.environ.get("ICHECK_METRIC_ALERT_TEST_PROMETHEUS_BINARY")
    alertmanager=os.environ.get("ICHECK_METRIC_ALERT_TEST_ALERTMANAGER_BINARY")
    if not prometheus or not alertmanager: pytest.skip("Explicit native binaries required to validate deployment examples")
    root=Path(__file__).resolve().parents[1]/"deploy"/"alertmanager"
    token=tmp_path/"receiver.token"; token.write_text("fixture-only-notification-token"); token.chmod(0o600)
    configuration=yaml.safe_load((root/"alertmanager.yml.example").read_text())
    webhook=configuration["receivers"][0]["webhook_configs"][0]
    assert webhook["url"]=="http://127.0.0.1:8000/api/v1/metric-alerts/webhook" and webhook["send_resolved"] is True
    assert webhook["http_config"]["follow_redirects"] is False
    webhook["http_config"]["authorization"]["credentials_file"]=str(token)
    am_config=tmp_path/"alertmanager.yml"; am_config.write_text(json.dumps(configuration))
    rules=tmp_path/"rules.yml"; rules.write_text((root/"rules.yml.example").read_text())
    configuration=yaml.safe_load((root/"prometheus-alerting.yml.example").read_text())
    assert "scrape_configs" not in configuration  # Integration never replaces existing jobs.
    configuration["rule_files"]=[str(rules)]
    prom_config=tmp_path/"prometheus.yml"; prom_config.write_text(json.dumps(configuration))
    for arguments in ([str(Path(alertmanager).with_name("amtool")),"check-config",str(am_config)],
            [str(Path(prometheus).with_name("promtool")),"check","config",str(prom_config)]):
        checked=subprocess.run(arguments,capture_output=True,text=True,timeout=10)
        assert checked.returncode==0,checked.stderr


def test_private_prometheus_alertmanager_delivers_firing_and_cleared_receipts(client,prepared,monkeypatch,endpoint,tmp_path):
    import os,socket,subprocess,threading,time
    from pathlib import Path
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    from urllib.parse import urlencode
    from urllib.request import urlopen
    from icheck.metric_rule_runtime import NativeRuleRuntime
    prometheus=os.environ.get("ICHECK_METRIC_ALERT_TEST_PROMETHEUS_BINARY")
    alertmanager=os.environ.get("ICHECK_METRIC_ALERT_TEST_ALERTMANAGER_BINARY")
    if not prometheus or not alertmanager: pytest.skip("Explicit native binaries required for private notification qualification")
    assert Path(prometheus).is_file() and Path(alertmanager).is_file()
    _,definition,target,state=prepared
    fixture,fixture_state=endpoint
    fixture_state.update(body=b"# TYPE vendor_queue_depth gauge\nvendor_queue_depth 7\n",content_type="text/plain")
    def port():
        with socket.socket() as handle: handle.bind(("127.0.0.1",0)); return handle.getsockname()[1]
    prom_port,am_port=port(),port()
    directory=tmp_path/"managed-rules"; directory.mkdir(mode=0o750)
    for key,value in {"ICHECK_METRIC_RULE_DIRECTORY":str(directory),"ICHECK_METRIC_RULE_BACKEND_ID":definition["backend_id"],
        "ICHECK_METRIC_RULE_TENANT_ID":DEFAULT_TENANT_ID,"ICHECK_METRIC_RULE_REGION_ID":DEFAULT_REGION_ID,
        "ICHECK_METRIC_RULE_PROMETHEUS_URL":f"http://127.0.0.1:{prom_port}",
        "ICHECK_METRIC_ALERT_WEBHOOK_SUBJECT":"private-alertmanager"}.items(): monkeypatch.setenv(key,value)
    get_settings.cache_clear(); monkeypatch.setattr(metric_alerts,"RUNTIME",NativeRuleRuntime)
    principal=client.post("/api/v1/auth/principals",json={"subject":"private-alertmanager","display_name":"Private notification receiver","principal_type":"service"}).json()
    role=client.post("/api/v1/auth/roles",json={"name":"private-metric-receiver","description":"Only native notification ingestion","permissions":["alerts.emit","assets.read"]}).json()
    assert client.post(f"/api/v1/auth/principals/{principal['id']}/bindings",json={"role_id":role["id"],"scope":{"all":True}}).status_code==201
    issued=client.post(f"/api/v1/auth/principals/{principal['id']}/tokens",json={"name":"private-alertmanager","expires_in_hours":1}).json()
    token=issued["access_token"]; secret=tmp_path/"notification.token"; secret.write_text(token); secret.chmod(0o600)
    receipts=[]; api_lock=threading.Lock()
    class Receiver(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            if self.headers.get("Authorization")!="Bearer "+token: self.send_error(403); return
            body=self.rfile.read(int(self.headers.get("Content-Length","0")))
            with api_lock:
                response=client.post("/api/v1/metric-alerts/webhook",content=body,headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"})
                diagnostic=None
                if response.status_code==422:
                    from icheck.metric_alert_schemas import AlertmanagerWebhook
                    try: AlertmanagerWebhook.model_validate(json.loads(body))
                    except Exception as error:
                        diagnostic=([{"loc":entry["loc"],"type":entry["type"]} for entry in error.errors()] if hasattr(error,"errors") else type(error).__name__)
                receipts.append({"http_status":response.status_code,"data":response.json(),"schema_diagnostic":diagnostic})
            self.send_response(response.status_code); self.end_headers()
            try: self.wfile.write(b"{}")
            except OSError: pass
    receiver=ThreadingHTTPServer(("127.0.0.1",0),Receiver)
    thread=threading.Thread(target=receiver.serve_forever,daemon=True); thread.start()
    am_config=tmp_path/"alertmanager.yml"
    am_config.write_text(json.dumps({"route":{"receiver":"icheck-inbox","group_by":["icheck_metric_rule_id","icheck_metric_rule_revision"],
        "group_wait":"0s","group_interval":"1s","repeat_interval":"1m"},"receivers":[{"name":"icheck-inbox","webhook_configs":[{
            "url":f"http://127.0.0.1:{receiver.server_port}/notify","send_resolved":True,"timeout":"3s",
            "http_config":{"authorization":{"credentials_file":str(secret)},"follow_redirects":False}}]}]}))
    labels={"icheck_tenant_id":DEFAULT_TENANT_ID,"icheck_region_id":DEFAULT_REGION_ID,"icheck_device_id":target["device_id"],
        "icheck_connection_id":target["connection_id"],"icheck_enrollment_id":state["monitoring"]["enrollment"]["id"],"icheck_enrollment_revision":"1"}
    prom_config=tmp_path/"prometheus.yml"
    prom_config.write_text(json.dumps({"global":{"scrape_interval":"1s","evaluation_interval":"1s"},
        "rule_files":[str(directory/"rules.yml")],"alerting":{"alertmanagers":[{"static_configs":[{"targets":[f"127.0.0.1:{am_port}"]}]}]},
        "scrape_configs":[{"job_name":"icheck_continuous","static_configs":[{"targets":[f"127.0.0.1:{fixture.server_port}"],"labels":labels}]}]}))
    processes=[]
    try:
        processes.append(subprocess.Popen([alertmanager,"--config.file="+str(am_config),"--storage.path="+str(tmp_path/"am-data"),
            f"--web.listen-address=127.0.0.1:{am_port}","--cluster.listen-address="],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        processes.append(subprocess.Popen([prometheus,"--config.file="+str(prom_config),"--storage.tsdb.path="+str(tmp_path/"tsdb"),
            "--storage.tsdb.retention.time=1h",f"--web.listen-address=127.0.0.1:{prom_port}","--web.enable-lifecycle"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        def request(db,backend,operation,fields,timeout):
            assert operation=="query"
            with urlopen(f"http://127.0.0.1:{prom_port}/api/v1/query?"+urlencode(fields),timeout=3) as response: return json.load(response)
        # Exercise the production query-authority/audit path with only the
        # test wire destination redirected to private native Prometheus.
        monkeypatch.setattr("icheck.services.metrics._request_prometheus",request)
        monkeypatch.setattr("icheck.services.metrics.query_instant",ACTUAL_QUERY_INSTANT)
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            assert all(process.poll() is None for process in processes)
            try:
                with urlopen(f"http://127.0.0.1:{prom_port}/api/v1/query?query=vendor_queue_depth",timeout=1) as response:
                    if json.load(response)["data"]["result"]: break
            except OSError: pass
            time.sleep(.1)
        proposal=preview(client,definition)
        applied=confirm(client,proposal)
        assert applied.status_code==200 and applied.json()["status"]=="applied",applied.text
        deadline=time.monotonic()+35
        while time.monotonic()<deadline:
            assert all(process.poll() is None for process in processes)
            with api_lock:
                accepted=[item for item in receipts if item["http_status"]==200 and item["data"]["episodes"][0]["source_status"]=="firing"]
            if accepted: break
            time.sleep(.1)
        assert accepted,receipts
        identifier=accepted[0]["data"]["episodes"][0]["alert_id"]
        with api_lock:
            assert client.post(f"/api/v1/alerts/{identifier}/acknowledge",json={"actor":"admin"}).json()["status"]=="acknowledged"
        fixture_state["body"]=b"# TYPE vendor_queue_depth gauge\nvendor_queue_depth 0\n"
        deadline=time.monotonic()+35; cleared=[]
        while time.monotonic()<deadline:
            assert all(process.poll() is None for process in processes)
            with api_lock: cleared=[item for item in receipts if item["http_status"]==200 and item["data"]["episodes"][0]["source_status"]=="resolved"]
            if cleared: break
            time.sleep(.1)
        assert cleared,receipts
        with api_lock: episode=next(row for row in client.get("/api/v1/alerts").json() if row["id"]==identifier)
        assert episode["status"]=="resolved" and not episode["details"]["fault_recovery_verified"]
        assert episode["details"]["dashboard_url"].startswith("https://icheck.test/grafana/d/icheck-http-")
    finally:
        for process in processes:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        receiver.shutdown(); receiver.server_close(); thread.join(timeout=2)
        import shutil
        for path in (tmp_path/"tsdb",tmp_path/"am-data"): shutil.rmtree(path,ignore_errors=True)
        secret.unlink(missing_ok=True)
        get_settings.cache_clear()
