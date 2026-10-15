"""Shared Studio lifecycle with actual native compilation when explicitly enabled."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import socket
import threading
from types import SimpleNamespace
from uuid import uuid4

import pytest
import yaml

from icheck.auth import current_principal
from icheck.database import SessionLocal
from icheck.main import app
from icheck.models import ArtifactVersion,CredentialProfile,DeviceConnection,MetricBackend,utcnow
from icheck.services.control_plane_auth import development_principal
from icheck.services import snmp_monitoring_templates as templates
from icheck.snmp_generator import GeneratorRuntime,compile_module,SNMPGeneratorRequest
from icheck.snmp_module_install import install_module as store
from icheck.snmp_install_client import send_document,receive_document
from icheck.snmp_install_broker import handle
from test_capability_studio import configure_authoring_route,FakeStructuredOpener
from test_device_preflights import register_worker
from test_managed_device_credentials import device_key,credential
from test_snmp_generator import Runner,_catalog
from test_monitoring_gateway import gateway

SPEC={"artifact_name":"snmp-uptime","description":"Monitor actual device uptime through the native exporter.",
    "symbols":["SNMPv2-MIB::sysUpTime"],"unsupported_metrics":["CPU utilization is not in the standard-network profile"]}


@pytest.fixture(autouse=True)
def human():
    app.dependency_overrides[current_principal]=lambda:replace(development_principal(),principal_type="user",subject="test.admin",auth_method="bearer")
    yield
    app.dependency_overrides.pop(current_principal,None)


@pytest.fixture
def native(tmp_path,monkeypatch):
    from icheck import managed_snmp,snmp_install_client
    binary=os.environ.get("ICHECK_SNMP_TEST_GENERATOR_BINARY")
    directory=os.environ.get("ICHECK_SNMP_TEST_MIB_DIRECTORY")
    real=bool(binary and directory)
    if real:
        binary=Path(binary); exporter=Path('/opt/icheck/bin/snmp_exporter')
        mibs=[p.read_text() for p in sorted(Path(directory).iterdir()) if p.is_file()]
    else:
        binary=tmp_path/'generator'; binary.write_bytes(b'fixture-only binary'); binary.chmod(0o700)
        exporter=binary; mibs=["SNMPv2-MIB DEFINITIONS ::= BEGIN\nEND\n"]
    runtime=GeneratorRuntime(binary,exporter,"0.30.1",hashlib.sha256(binary.read_bytes()).hexdigest())
    monkeypatch.setattr(templates,"native_runtime",lambda:runtime)
    monkeypatch.setattr(templates,"shared_mibs",lambda:mibs)
    if not real:
        monkeypatch.setattr(templates,"compile_module",lambda *a,**kw:compile_module(*a,**kw,run=Runner()))
    catalog=_catalog(tmp_path)
    initial=yaml.safe_load(catalog.read_bytes())
    initial['modules']['if_mib']=deepcopy(initial['modules']['system'])
    catalog.chmod(0o600); catalog.write_text(yaml.safe_dump(initial)); catalog.chmod(0o444)
    monkeypatch.setenv("ICHECK_MANAGED_SNMP_MODULES_FILE",str(catalog))
    trusted=managed_snmp.trusted_file
    def custody(p,**kw): return catalog if str(p)==str(catalog) else trusted(p,**kw)
    monkeypatch.setattr(managed_snmp,"trusted_file",custody)
    monkeypatch.setattr(snmp_install_client,"trusted_file",custody)
    monkeypatch.setattr(snmp_install_client,"CATALOG",catalog)
    def install(compiled,expected):
        options={} if real else {"verify":lambda *a,**kw:None}
        return store(compiled,catalog=catalog,exporter=exporter,expected_catalog_sha256=expected,confirm=True,**options)
    monkeypatch.setattr(snmp_install_client,"install_module",install)
    return SimpleNamespace(runtime=runtime,catalog=catalog,real=real,mibs=mibs)


def draft(client,monkeypatch,documents=None):
    configure_authoring_route(client)
    opener=FakeStructuredOpener(documents or [SPEC])
    monkeypatch.setattr("icheck.services.structured_model.build_opener",lambda *_:opener)
    created=client.post('/api/v1/capability-studio/sessions',json={"title":"SNMP uptime","brief":"Monitor uptime every thirty seconds; disclose unavailable CPU metrics.",
        "snmp_monitoring":{"profile":"standard-network"},"created_by":"lab.admin"})
    assert created.status_code==201,created.text
    path='/api/v1/capability-studio/sessions/'+created.json()['id']; key=str(uuid4())
    generated=client.post(path+'/generate',json={"actor":"lab.admin","request_key":key})
    assert generated.status_code==200,generated.text
    return generated.json(),path,opener,key


def install(client,path,doc):
    preview=client.get(path+'/monitoring/module-preview',params={'artifact_version_id':doc['artifact_version_id']})
    assert preview.status_code==200,preview.text
    payload={k:preview.json()[k] for k in ('artifact_version_id','expected_catalog_sha256','preview_hash')}
    response=client.post(path+'/monitoring/install-module',json={**payload,'actor':'lab.admin','reason':'Install exactly this reviewed immutable native module.'})
    assert response.status_code==200,response.text
    assert response.json()['installed'] and not response.json()['continuous_collection_enabled']
    return response.json()


def target(client,path,doc):
    profile=credential(client)
    created=client.post('/api/v1/assets/devices',json={'name':'Explicit SNMP target','kind':'switch','management_ip':'198.18.1.10',
        'site':'LAB','created_by':'lab.admin','connections':[{'protocol':'snmp','credential_profile_ref':profile['id']}]})
    assert created.status_code==201,created.text
    device=created.json(); connection=device['connections'][0]
    payload={'artifact_version_id':doc['artifact_version_id'],'device_id':device['id'],'connection_id':connection['id'],
        'expected_device_revision':device['revision'],'credential_profile_ref':profile['id'],'actor':'lab.admin','reason':'Test the requested module on this selected SNMP target.'}
    response=client.post(path+'/monitoring/test',json=payload)
    assert response.status_code==200,response.text
    return response.json(),payload


def state(client,path,payload,**params):
    return client.get(path+'/monitoring/state',params={k:payload[k] for k in ('artifact_version_id','device_id','connection_id')}|params)


def complete(client,payload,*,bad=False):
    worker,headers=register_worker(client,name='snmp-template-worker',site='LAB',capabilities=['snmp_exporter'])
    claim=client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim",headers=headers,json={'max_assignments':1,'lease_seconds':60}).json()[0]
    config=claim['configuration']
    proof={'check':'snmp_exporter_query'} if bad else {'check':'snmp_metric_query','success':True,'modules':config['modules'],
        'module_sha256':config['snmp_module_sha256'],'metric_names':sorted(m['name'] for m in config['snmp_expected_metrics']),
        'metric_samples':1,'target_host':claim['target_host'],'target_port':claim['port'],'credential_revision':claim['credential_revision']}
    result=client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/{claim['preflight_id']}/complete",headers=headers,
        json={'lease_token':claim['lease_token'],'status':'verified','evidence':proof})
    return result,claim,headers,worker['id']


def enable(client,path,payload,view):
    return client.post(path+'/monitoring/enable',json={**{k:v for k,v in payload.items() if k!='credential_profile_ref'},'expected_device_revision':view['device_revision'],
        'preview_hash':view['monitoring']['preview_hash'],'expected_revision':0,'gateway_profile':'lab-snmp-native',
        'modules':[view['template']['compiled_module']['module_name']],'schedule_seconds':30,'timeout_seconds':10})


def test_native_conversation_compile_replay_private_sources_and_explicit_install(client,monkeypatch,native):
    doc,path,opener,key=draft(client,monkeypatch)
    assert doc['status']=='validated' and len(opener.requests)==1
    assert 'DEFINITIONS ::= BEGIN' not in str(opener.requests) and 'mib_documents' not in str(doc)
    replay=client.post(path+'/generate',json={'actor':'lab.admin','request_key':key})
    assert replay.status_code==200 and replay.json()['artifact_version_id']==doc['artifact_version_id'] and len(opener.requests)==1
    before=native.catalog.read_bytes()
    preview=client.get(path+'/monitoring/module-preview',params={'artifact_version_id':doc['artifact_version_id']}).json()
    assert not preview['installed'] and native.catalog.read_bytes()==before
    installed=install(client,path,doc)
    assert installed['installed']
    assert yaml.safe_load(native.catalog.read_bytes())['modules']['system']==yaml.safe_load(before)['modules']['system']
    assert client.get('/api/v1/monitoring/targets').json()['targets']==[]


def test_exact_installed_module_full_metric_test_then_approved_activation(client,monkeypatch,native,device_key):
    doc,path,_,_=draft(client,monkeypatch); install(client,path,doc)
    view,payload=target(client,path,doc)
    assert view['stage']=='testing'
    bad,claim,headers,worker_id=complete(client,payload,bad=True)
    assert bad.status_code==409 and 'SNMP metric test' in bad.text
    assert enable(client,path,payload,view).status_code==409
    # The refused completion retains the same current lease for correction.
    config=claim['configuration']; proof={'check':'snmp_metric_query','success':True,'modules':config['modules'],
        'module_sha256':config['snmp_module_sha256'],'metric_names':['sysUpTime'],'metric_samples':1,
        'target_host':claim['target_host'],'target_port':claim['port'],'credential_revision':claim['credential_revision']}
    corrected=client.post(f"/api/v1/collector-workers/{worker_id}/device-preflights/{claim['preflight_id']}/complete",headers=headers,
        json={'lease_token':claim['lease_token'],'status':'verified','evidence':proof})
    assert corrected.status_code==200,corrected.text
    view=state(client,path,payload).json(); assert view['stage']=='tested_not_enabled'
    activated=enable(client,path,payload,view)
    assert activated.status_code==200,activated.text
    assert activated.json()['stage']=='enabled_awaiting_fresh_samples' and not activated.json()['fresh_samples_verified']
    issued=client.get('/api/v1/monitoring/targets').json()['targets'][0]
    assert issued['snmp_module_sha256']==view['template']['compiled_module']['module_sha256'] and issued['credential_revision']==1
    with SessionLocal() as db:
        profile=db.get(CredentialProfile,issued['credential_profile_id']); profile.revision+=1; db.commit()
    assert client.get('/api/v1/monitoring/targets').json()['targets']==[]


def test_revision_is_immutable_and_stale_catalog_or_model_symbol_is_rejected(client,monkeypatch,native):
    doc,path,_,_=draft(client,monkeypatch)
    preview=client.get(path+'/monitoring/module-preview',params={'artifact_version_id':doc['artifact_version_id']}).json()
    native.catalog.chmod(0o600); native.catalog.write_bytes(native.catalog.read_bytes()+b'\n# another installer\n')
    payload={k:preview[k] for k in ('artifact_version_id','expected_catalog_sha256','preview_hash')}
    rejected=client.post(path+'/monitoring/install-module',json={**payload,'actor':'lab.admin','reason':'Try to use an obsolete catalog preview.'})
    assert rejected.status_code==409
    # A proposal outside the source catalog cannot turn into exporter YAML.
    opener=FakeStructuredOpener([{**SPEC,'symbols':['SNMPv2-MIB::inventedMetric']}])
    monkeypatch.setattr('icheck.services.structured_model.build_opener',lambda *_:opener)
    result=client.post(path+'/messages',json={'actor':'lab.admin','content':'Please add an unavailable measurement.','request_key':str(uuid4())})
    assert result.status_code==422 and 'catalog' in result.text
    with SessionLocal() as db:
        original=db.get(ArtifactVersion,doc['artifact_version_id'])
        assert original.definition['compiled_module']['expected_metrics'][0]['name']=='sysUpTime'


def test_broker_custody_accepts_canonical_installed_release_alias(tmp_path,monkeypatch):
    import icheck.snmp_install_broker as broker
    release=tmp_path/'release'; module=release/'lib/icheck/snmp_install_broker.py'
    module.parent.mkdir(parents=True);module.write_text('# fixture')
    active=tmp_path/'active';active.symlink_to(release,target_is_directory=True)
    checked=[]
    monkeypatch.setattr(broker,'__file__',str(active/'lib/icheck/snmp_install_broker.py'))
    monkeypatch.setattr(broker.sys,'prefix',str(active))
    monkeypatch.setattr(broker,'trusted_file',lambda path:checked.append(path))
    broker.validate_module_custody()
    assert checked==[module.resolve()]


def test_broker_custody_rejects_module_outside_installed_prefix(tmp_path,monkeypatch):
    import icheck.snmp_install_broker as broker
    prefix=tmp_path/'release';prefix.mkdir()
    module=tmp_path/'outside.py';module.write_text('# fixture')
    monkeypatch.setattr(broker,'__file__',str(module))
    monkeypatch.setattr(broker.sys,'prefix',str(prefix))
    monkeypatch.setattr(broker,'trusted_file',lambda _:pytest.fail('Escaped module must not pass custody validation'))
    with pytest.raises(ValueError,match='outside'):
        broker.validate_module_custody()


def test_local_broker_peer_identity_and_narrow_install_request(native,monkeypatch):
    if not native.real:
        import icheck.snmp_install_broker as broker
        original=store
        monkeypatch.setattr(broker,'install_module',lambda *a,**kw:original(*a,**kw,verify=lambda *a,**kw:None))
    compiled=templates.compile_module(SNMPGeneratorRequest(symbols=['SNMPv2-MIB::sysUpTime']),runtime=native.runtime,mib_documents=native.mibs)
    request={'format':'icheck.snmp-install-request/v1','candidate':compiled,'expected_catalog_sha256':hashlib.sha256(native.catalog.read_bytes()).hexdigest()}
    for uid,expected in [(os.getuid()+1,False),(os.getuid(),True)]:
        caller,server=socket.socketpair()
        def serve():
            with server: handle(server,api_uid=uid,catalog=native.catalog,exporter=native.runtime.exporter)
        thread=threading.Thread(target=serve); thread.start()
        with caller:
            caller.settimeout(5)
            if expected: send_document(caller,request)
            result=receive_document(caller)
        thread.join(timeout=2)
        assert result['installed'] is expected


@pytest.mark.parametrize('fault',[None,'missing','stale','failed'])
def test_snmp_freshness_requires_requested_metric_samples_not_only_up(client,monkeypatch,native,device_key,tmp_path,fault):
    doc,path,_,_=draft(client,monkeypatch); install(client,path,doc)
    _,payload=target(client,path,doc)
    completed,_,_,_=complete(client,payload); assert completed.status_code==200,completed.text
    tested=state(client,path,payload).json(); activated=enable(client,path,payload,tested)
    assert activated.status_code==200,activated.text
    with SessionLocal() as db:
        db.add(MetricBackend(name='snmp-proof',provider='prometheus',query_base_url='https://prometheus.example.test',external_labels={},enabled=True,created_by='test')); db.commit()
    enrollment=activated.json()['monitoring']['enrollment']
    labels={'job':'icheck_continuous','icheck_tenant_id':'00000000-0000-0000-0000-000000000001',
        'icheck_region_id':'00000000-0000-0000-0000-000000000002','icheck_device_id':payload['device_id'],
        'icheck_connection_id':payload['connection_id'],'icheck_enrollment_id':enrollment['id'],'icheck_enrollment_revision':'1'}
    stamp=utcnow().timestamp()
    def query(db,backend,payload,**kw):
        if payload.query.startswith('count by'):
            result=[] if fault=='missing' else [{'metric':{'__name__':'sysUpTime'},'value':[stamp,'1']}]
        elif payload.query.startswith('label_replace'):
            result=[{'metric':{'icheck_metric_name':'sysUpTime'},'value':[stamp,str(stamp-1000 if fault=='stale' else stamp)]}]
        else: result=[{'metric':labels,'value':[stamp,'0' if fault=='failed' else '1']}]
        return SimpleNamespace(result_type='vector',result=result)
    monkeypatch.setattr('icheck.services.metrics.query_instant',query)
    evidence=state(client,path,payload,verify_samples=True)
    assert evidence.status_code==200,evidence.text
    assert evidence.json()['fresh_samples_verified'] is (fault is None)
    assert evidence.json()['stage']==('collecting' if fault is None else 'enabled_awaiting_fresh_samples')
    if fault is None:
        from icheck.config import get_settings
        from icheck.services import grafana
        from test_grafana_plugin import FakeGrafana
        key=tmp_path/'grafana.key'; key.write_bytes(b'g'*32); key.chmod(0o400)
        monkeypatch.setenv('ICHECK_GRAFANA_SECRET_KEY_FILE',str(key)); get_settings.cache_clear()
        remote=FakeGrafana(); remote.metrics=lambda _:['sysUpTime']
        monkeypatch.setattr(grafana,'CLIENT',remote)
        try:
            connection=client.post('/api/v1/grafana/connections',json={'name':'snmp-dashboard','public_url':'https://icheck.test/grafana/',
                'token':'fixture-only-grafana-token','shared_dataset_acknowledged':True}).json()
            params={k:payload[k] for k in ('artifact_version_id','device_id','connection_id')}|{'grafana_connection_id':connection['id']}
            proposal=client.post(path+'/monitoring/dashboard-proposal',params=params)
            assert proposal.status_code==200,proposal.text
            panel=proposal.json()['definition']['panels'][0]
            assert panel['targets'][0]['expr'].endswith(' / 100') and panel['fieldConfig']['defaults']['unit']=='s'
            assert not remote.writes
            confirmed=client.post(f"/api/v1/grafana/changes/{proposal.json()['id']}/confirm",json={'confirm':True,'expected_plan_hash':proposal.json()['plan_hash']})
            assert confirmed.status_code==200,confirmed.text
            saved=state(client,path,payload).json()
            assert saved['grafana_dashboard_url'].startswith('https://icheck.test/grafana/d/icheck-snmp-')
            assert 'fixture-only-grafana-token' not in str(saved)
        finally: get_settings.cache_clear()


@pytest.fixture
def uptime_agent():
    from test_managed_snmp_runtime import take,tlv
    from test_managed_device_credentials import COMMUNITY
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.bind(('127.0.0.1',0)); sock.settimeout(.2)
    port=sock.getsockname()[1]; stop=threading.Event(); requests=[]
    def agent():
        while not stop.is_set():
            try: wire,peer=sock.recvfrom(4096)
            except socket.timeout: continue
            except OSError: break
            _,message,_,_=take(wire); _,_,pos,version=take(message)
            _,value,pos,auth=take(message,pos)
            if value!=COMMUNITY.encode(): continue
            tag,pdu,_,_=take(message,pos); requests.append(tag)
            _,_,pos,request_id=take(pdu); _,_,pos,_=take(pdu,pos); _,_,pos,_=take(pdu,pos)
            _,bindings,_,_=take(pdu,pos); _,binding,_,_=take(bindings); _,_,_,oid=take(binding)
            sock.sendto(tlv(0x30,version+auth+tlv(0xa2,request_id+tlv(2,b'\0')+tlv(2,b'\0')
                +tlv(0x30,tlv(0x30,oid+tlv(0x43,b'\x30\x39'))))),peer)
    thread=threading.Thread(target=agent,daemon=True); thread.start()
    try: yield port,requests
    finally: stop.set(); sock.close(); thread.join(timeout=1)


def fixture_exporter_transport(port):
    from urllib.parse import urlsplit,urlunsplit,parse_qs,urlencode
    from urllib.request import Request,build_opener,ProxyHandler
    transport=build_opener(ProxyHandler({}))
    def open_request(request,*,timeout):
        parsed=urlsplit(request.full_url); query=parse_qs(parsed.query)
        assert parsed.hostname=='127.0.0.1' and parsed.port!=9116  # Never use the running shared exporter.
        assert query['target'][0] in {'198.18.1.10','udp://198.18.1.10:161'}
        query['target']=[f'udp://127.0.0.1:{port}']
        url=urlunsplit((parsed.scheme,parsed.netloc,parsed.path,urlencode(query,doseq=True),''))
        return transport.open(Request(url,headers=dict(request.header_items())),timeout=timeout)
    return open_request


def test_native_studio_test_enable_gateway_and_private_prometheus_samples(client,monkeypatch,native,device_key,gateway,uptime_agent,tmp_path):
    import json,subprocess,time,shutil
    from urllib.request import urlopen
    from urllib.parse import urlsplit,urlencode
    from icheck.config import get_settings
    from icheck.device_preflight_worker import execute_device_preflight
    from icheck.monitoring_gateway import GatewayServer,GatewayHandler
    from icheck.services import monitoring_templates
    binary=os.environ.get('ICHECK_SNMP_TEST_PROMETHEUS_BINARY')
    if not native.real or not binary: pytest.skip('Requires real native generator/MIBs and a native Prometheus binary')
    port,requests=uptime_agent; wire=fixture_exporter_transport(port)
    monkeypatch.setattr('icheck.collectors.snmp_exporter.build_opener',lambda *_:SimpleNamespace(open=wire))
    doc,path,_,_=draft(client,monkeypatch); install(client,path,doc)
    _,payload=target(client,path,doc)
    worker,headers=register_worker(client,name='real-snmp-worker',site='LAB',capabilities=['snmp_exporter'])
    claim=client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim",headers=headers,json={'max_assignments':1,'lease_seconds':60}).json()[0]
    secret=client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/{claim['preflight_id']}/managed-credential",headers=headers,json={'lease_token':claim['lease_token']})
    assert secret.status_code==200,secret.text
    claim['_runtime']={'credential':secret.json()['values'],'credential_revision':secret.json()['profile_revision']}
    proof,_=execute_device_preflight(claim,allowed_targets=['198.18.1.0/24'],timeout_seconds=2,
        snmp_exporter_url='http://127.0.0.1:9116',exporter_allowed_hosts=['127.0.0.1'],snmp_allowed_targets=['198.18.1.0/24'],lease_seconds=60)
    completed=client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/{claim['preflight_id']}/complete",headers=headers,
        json={'lease_token':claim['lease_token'],'status':'verified','evidence':proof})
    assert completed.status_code==200,completed.text
    assert proof['metric_names']==['sysUpTime'] and proof['metric_samples']==1
    activated=enable(client,path,payload,state(client,path,payload).json()); assert activated.status_code==200,activated.text
    enrollment=activated.json()['monitoring']['enrollment']
    subject,config,opener=gateway
    profile=config.profiles['lab-readonly']; profile.allow_managed_snmp_credentials=True; profile.allow_installed_snmp_templates=True
    with SessionLocal() as db: cid=db.get(DeviceConnection,payload['connection_id']).credential_profile_ref
    profile.credential_profile_ids=[cid]; config.profiles['lab-snmp-native']=profile
    monkeypatch.setenv('ICHECK_MANAGED_MONITORING_GATEWAY_SUBJECT','test.gateway'); get_settings.cache_clear()
    service=replace(development_principal(),principal_type='service',subject='test.gateway',auth_method='bearer')
    original=opener.open
    def authorized_open(request,*,timeout):
        if urlsplit(request.full_url).hostname!='control.example.test': return wire(request,timeout=timeout)
        previous=app.dependency_overrides[current_principal]
        app.dependency_overrides[current_principal]=lambda:service
        try: return original(request,timeout=timeout)
        finally: app.dependency_overrides[current_principal]=previous
    monkeypatch.setattr(opener,'open',authorized_open)
    assert subject.discovery() and b'sysUpTime 12345' in subject.scrape(enrollment['id'])
    server=GatewayServer(('127.0.0.1',0),GatewayHandler,subject,2)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start(); config.port=server.server_port
    with socket.socket() as reserved: reserved.bind(('127.0.0.1',0)); prometheus_port=reserved.getsockname()[1]
    config_file=tmp_path/'prometheus.yml'
    config_file.write_text(f'''global:
  scrape_interval: 1s
scrape_configs:
  - job_name: icheck_continuous
    scrape_interval: 1s
    scrape_timeout: 800ms
    authorization:
      credentials: private-prometheus-token
    http_sd_configs:
      - url: http://127.0.0.1:{server.server_port}/discovery
        refresh_interval: 1s
        authorization:
          credentials: private-prometheus-token
''')
    process=None
    try:
        process=subprocess.Popen([binary,'--config.file='+str(config_file),'--storage.tsdb.path='+str(tmp_path/'tsdb'),
            '--storage.tsdb.retention.time=1h','--web.listen-address=127.0.0.1:'+str(prometheus_port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def read(expression):
            with urlopen(f'http://127.0.0.1:{prometheus_port}/api/v1/query?'+urlencode({'query':expression}),timeout=3) as response:
                data=json.load(response)
            assert data['status']=='success',data
            return SimpleNamespace(result_type=data['data']['resultType'],result=data['data']['result'])
        deadline=time.monotonic()+35; samples=[]
        while time.monotonic()<deadline:
            assert process.poll() is None
            try: samples=read('sysUpTime').result
            except OSError: pass
            if samples: break
            time.sleep(.1)
        assert samples and float(samples[0]['value'][1])==12345
        assert samples[0]['metric']['icheck_enrollment_id']==enrollment['id']
        with SessionLocal() as db:
            backend=MetricBackend(name='real-private-snmp',provider='prometheus',query_base_url='https://prometheus.example.test',external_labels={},enabled=True,created_by='test')
            db.add(backend); db.commit()
        monkeypatch.setattr('icheck.services.metrics.query_instant',lambda db,backend,payload,**kw:read(payload.query))
        with SessionLocal() as db:
            evidence=monitoring_templates.verify_samples(db,development_principal(),doc['id'],doc['artifact_version_id'],payload['device_id'],payload['connection_id'],backend.id)
            assert evidence['fresh_samples_verified'] and evidence['stage']=='collecting',evidence
        assert requests and set(requests)=={0xa0}
    finally:
        if process is not None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        shutil.rmtree(tmp_path/'tsdb',ignore_errors=True)
        get_settings.cache_clear()


def test_service_cannot_approve_privileged_module_installation(client,monkeypatch,native):
    doc,path,_,_=draft(client,monkeypatch)
    preview=client.get(path+'/monitoring/module-preview',params={'artifact_version_id':doc['artifact_version_id']}).json()
    before=native.catalog.read_bytes()
    app.dependency_overrides[current_principal]=lambda:replace(development_principal(),principal_type='service',subject='test.agent',auth_method='bearer')
    payload={k:preview[k] for k in ('artifact_version_id','expected_catalog_sha256','preview_hash')}
    response=client.post(path+'/monitoring/install-module',json={**payload,'actor':'test.agent','reason':'An agent must not approve its own module install.'})
    assert response.status_code==403 and native.catalog.read_bytes()==before


def test_snmp_revision_and_restore_keep_old_compiled_recipe_without_source_edits(client,monkeypatch,native):
    revised={**SPEC,'artifact_name':'model-must-not-rename','description':'A revised operator description for the same real uptime measurement.'}
    doc,path,opener,_=draft(client,monkeypatch,documents=[SPEC,revised])
    assert client.post(path+'/publish',json={'actor':'lab.admin','expected_artifact_version_id':doc['artifact_version_id']}).status_code==200
    new=client.post(path+'/messages',json={'actor':'lab.admin','content':'Clarify the purpose but keep the same measurement.','request_key':str(uuid4())})
    assert new.status_code==200,new.text
    assert new.json()['artifact_version_id']!=doc['artifact_version_id']
    assert client.post(path+'/publish',json={'actor':'lab.admin','expected_artifact_version_id':new.json()['artifact_version_id']}).status_code==200
    restored=client.post(f"/api/v1/artifacts/{doc['artifact_id']}/restore-candidates",json={'source_version':1,'reason':'Restore the earlier SNMP template definition.','actor':'lab.admin'})
    assert restored.status_code==201,restored.text
    assert restored.json()['version']==3 and restored.json()['status']=='validated'
    with SessionLocal() as db:
        original=db.get(ArtifactVersion,doc['artifact_version_id'])
        assert original.definition['compiled_module']==restored.json()['definition']['compiled_module']
        assert original.artifact.name=='snmp-uptime'
