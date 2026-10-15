from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from icheck.database import SessionLocal
from icheck.models import Device, DeviceConnection, DeviceMonitoringEnrollment, MetricBackend, utcnow
from icheck.services import asset_health
from icheck.services.control_plane_auth import development_principal
from icheck.services.metrics import MetricBackendUnavailable
from test_monitoring_enrollments import seeded, approve


def monitored(client):
    device, connection, _, path = seeded(client)
    result = approve(client, path)
    assert result.status_code == 200, result.text
    with SessionLocal() as db:
        backend = MetricBackend(name="test-health", provider="prometheus", query_base_url="https://prometheus.example.test",
            external_labels={}, enabled=True, created_by="test")
        db.add(backend); db.commit(); backend_id = backend.id
    return device, connection, result.json(), backend_id


def vector(device, connection, enrollment, *, up="1", age=10, **labels):
    principal = development_principal()
    base = {"icheck_device_id": device["id"], "icheck_connection_id": connection["id"],
        "icheck_enrollment_id": enrollment["id"], "icheck_enrollment_revision": str(enrollment["revision"]),
        "icheck_tenant_id": principal.tenant_id, "icheck_region_id": principal.region_id, **labels}
    stamp = utcnow().timestamp()
    return [{"metric": {**base, "icheck_health_field":"up"}, "value":[stamp,up]},
        {"metric": {**base,"icheck_health_field":"observed_at"}, "value":[stamp,str(stamp-age)]}]


def reply(monkeypatch, samples):
    requests = []
    def query(db, backend, payload, *, principal):
        requests.append((payload,principal))
        return SimpleNamespace(result_type="vector",result=samples)
    monkeypatch.setattr(asset_health,"query_instant",query)
    return requests


@pytest.mark.parametrize("kind,category",[("switch","wired"),("router","wired"),("wireless_controller","wireless"),
    ("wireless_access_point","wireless"),("firewall","firewalls"),("physical_server","servers"),
    ("linux_server","servers"),("windows_server","servers"),("storage","storage"),("hypervisor","other")])
def test_category_counts_and_filters_cover_registered_types(client,kind,category):
    with SessionLocal() as db:
        db.add(Device(name="category-test",kind=kind,management_ip="198.18.0.2",site="LAB"));db.commit()
    counts=client.get("/api/v1/assets/devices/summary").json()
    assert counts["total"]==1 and counts["categories"][category]==1
    page=client.get("/api/v1/assets/devices/page",params={"category":category}).json()
    assert len(page["items"])==1 and page["items"][0]["kind"]==kind
    assert len(client.get("/api/v1/assets/devices",params={"category":category}).json())==1
    assert client.get("/api/v1/assets/devices/page?category=made-up").status_code==422


def test_category_pagination_is_global_not_first_page_and_cursor_is_bound(client):
    with SessionLocal() as db:
        db.add_all(Device(name=f"wired-{i:03}",kind="switch",site="LAB") for i in range(120))
        db.add_all(Device(name=f"storage-{i:03}",kind="storage",site="LAB") for i in range(55));db.commit()
    assert client.get("/api/v1/assets/devices/summary").json()["categories"]["storage"]==55
    first=client.get("/api/v1/assets/devices/page?category=storage&limit=50").json()
    assert len(first["items"])==50 and first["next_cursor"]
    second=client.get("/api/v1/assets/devices/page",params={"category":"storage","cursor":first["next_cursor"]}).json()
    assert len(second["items"])==5
    assert client.get("/api/v1/assets/devices/page",params={"category":"wired","cursor":first["next_cursor"]}).status_code==422


@pytest.mark.parametrize("up,age,state",[("1",10,"up"),("0",10,"poll_failed"),("1",120,"stale"),("0",120,"stale"),
    ("1",-100,"unknown"),("NaN",10,"unknown"),("0.5",10,"unknown")])
def test_live_status_uses_current_fresh_up_not_historical_verification(client,monkeypatch,up,age,state):
    device,connection,enrollment,_=monitored(client)
    requests=reply(monkeypatch,vector(device,connection,enrollment,up=up,age=age))
    response=client.get("/api/v1/assets/devices/health",params={"device_ids":device["id"]})
    assert response.status_code==200,response.text
    assert response.headers["cache-control"]=="no-store"
    assert response.json()["items"][0]["state"]==state
    assert len(requests)==1 and requests[0][0].timeout_seconds==3
    assert 'job="icheck_continuous"' in requests[0][0].query


@pytest.mark.parametrize("changes",[{"icheck_region_id":"other"},{"icheck_tenant_id":"other"},
    {"icheck_device_id":"other"},{"icheck_connection_id":"other"},{"icheck_enrollment_id":"other"},
    {"icheck_enrollment_revision":"999"}])
def test_stale_or_foreign_series_cannot_establish_current_health(client,monkeypatch,changes):
    device,connection,enrollment,_=monitored(client)
    reply(monkeypatch,vector(device,connection,enrollment,**changes))
    body=client.get("/api/v1/assets/devices/health",params={"device_ids":device["id"]}).json()
    assert body["items"][0]["state"]=="unknown"
    assert "other" not in str(body)


def test_ambiguous_conflicting_samples_do_not_become_up(client,monkeypatch):
    device,connection,enrollment,_=monitored(client)
    reply(monkeypatch,vector(device,connection,enrollment)+vector(device,connection,enrollment,up="0"))
    body=client.get("/api/v1/assets/devices/health",params={"device_ids":device["id"]}).json()
    assert body["items"][0]["state"]=="unknown"


def test_unavailable_metrics_has_safe_unknown_reason_and_no_raw_error(client,monkeypatch):
    device,_,_,_=monitored(client)
    def fail(*args,**kwargs):raise MetricBackendUnavailable("provider-secret-must-not-escape")
    monkeypatch.setattr(asset_health,"query_instant",fail)
    response=client.get("/api/v1/assets/devices/health",params={"device_ids":device["id"]})
    assert response.json()["items"][0]["state"]=="unknown"
    assert "provider-secret" not in response.text


def test_assets_read_does_not_grant_metric_reads_or_foreign_asset_visibility(client,monkeypatch):
    device,connection,enrollment,_=monitored(client)
    requests=reply(monkeypatch,vector(device,connection,enrollment))
    with SessionLocal() as db:
        principal=replace(development_principal(),permissions=frozenset({"assets.read"}))
        body=asset_health.device_health(db,principal,[device["id"]])
        assert body["items"][0]["state"]=="unknown" and body["diagnostic"]=="metrics_read_required"
        assert requests==[]
        principal=replace(development_principal(),authorization_scope={"sites":["OTHER"]})
        assert asset_health.asset_summary(db,principal)["total"]==0
        assert asset_health.device_health(db,principal,[device["id"]])["items"]==[]
        assert requests==[]


def test_verified_but_not_authorized_does_not_mean_up(client,monkeypatch):
    device,_,_,_=seeded(client)
    monkeypatch.setattr(asset_health,"query_instant",lambda *args,**kwargs:pytest.fail("No authorization, no query"))
    body=client.get("/api/v1/assets/devices/health",params={"device_ids":device["id"]}).json()
    assert body["items"][0]["state"]=="not_monitored"


def test_withdrawal_during_query_invalidates_observation(client,monkeypatch):
    device,connection,enrollment,_=monitored(client)
    samples=vector(device,connection,enrollment)
    def query(db,*args,**kwargs):
        row=db.get(DeviceMonitoringEnrollment,enrollment["id"]);row.enabled=False;db.commit()
        return SimpleNamespace(result_type="vector",result=samples)
    monkeypatch.setattr(asset_health,"query_instant",query)
    body=client.get("/api/v1/assets/devices/health",params={"device_ids":device["id"]}).json()
    assert body["items"][0]["state"]=="unknown"
    assert body["diagnostic"]=="monitoring_authority_changed"


def test_health_requests_are_bounded(client):
    assert client.get("/api/v1/assets/devices/health").status_code==422
    assert client.get("/api/v1/assets/devices/health",params=[("device_ids",str(i)) for i in range(51)]).status_code==422
    assert client.get("/api/v1/assets/devices/health",params={"device_ids":"x' or 1=1"}).status_code==422


@pytest.mark.parametrize("change,expected",[("fresh","up"),("old","stale"),("failed","poll_failed"),
    ("future","unknown"),("drift","unknown")])
def test_published_scheduled_templates_expose_current_collector_health(client,change,expected):
    from icheck.builtin_artifacts import snmp_exporter_artifact_payload
    from icheck.models import DeviceConnectionActivation,CollectorDeployment
    from test_device_activation import publish_artifact,onboard_snmp_device,verify_snmp_connection,publish_policy,activation_policy_payload,preview_and_approve
    version=publish_artifact(client,snmp_exporter_artifact_payload())
    device=onboard_snmp_device(client);connection=verify_snmp_connection(client,device)
    policy=publish_policy(client,activation_policy_payload(version["id"]))
    _,result=preview_and_approve(client,device["id"],connection["id"],policy,"Enable this synthetic scheduled template.")
    with SessionLocal() as db:
        activation=db.get(DeviceConnectionActivation,result["activation"]["id"])
        activation.last_success_at=utcnow()-timedelta(seconds=20)
        if change=="old":activation.last_success_at=utcnow()-timedelta(seconds=1000)
        elif change=="failed":activation.last_failure_at=utcnow();activation.consecutive_failures=1
        elif change=="future":activation.last_success_at=utcnow()+timedelta(seconds=1000)
        elif change=="drift":db.get(CollectorDeployment,activation.deployment_id).enabled=False
        db.commit()
    body=client.get("/api/v1/assets/devices/health",params={"device_ids":device["id"]}).json()
    assert body["items"][0]["state"]==expected
    assert body["items"][0]["connections"][0]["source"]=="Approved scheduled Collector runtime"


@pytest.mark.parametrize("plugin_failed,expected", [(False,"up"),(True,"degraded")])
def test_native_and_plugin_sources_are_both_retained_on_the_same_connection(client,monkeypatch,plugin_failed,expected):
    from icheck.builtin_artifacts import snmp_exporter_artifact_payload
    from icheck.models import DeviceConnectionActivation
    from test_device_activation import publish_artifact,onboard_snmp_device,verify_snmp_connection,publish_policy,activation_policy_payload,preview_and_approve
    version=publish_artifact(client,snmp_exporter_artifact_payload())
    device=onboard_snmp_device(client);connection=verify_snmp_connection(client,device)
    path=f"/api/v1/assets/devices/{device['id']}/connections/{connection['id']}/monitoring"
    enrollment=approve(client,path).json()
    policy=publish_policy(client,activation_policy_payload(version["id"]))
    _,result=preview_and_approve(client,device["id"],connection["id"],policy,"Enable this synthetic scheduled template.")
    with SessionLocal() as db:
        db.add(MetricBackend(name="test-health",provider="prometheus",query_base_url="https://prometheus.example.test",external_labels={},enabled=True,created_by="test"))
        activation=db.get(DeviceConnectionActivation,result["activation"]["id"])
        activation.last_success_at=utcnow()-timedelta(seconds=20)
        if plugin_failed:activation.last_failure_at=utcnow();activation.consecutive_failures=1
        db.commit()
    reply(monkeypatch,vector(device,connection,enrollment))
    body=client.get("/api/v1/assets/devices/health",params={"device_ids":device["id"]}).json()
    item=body["items"][0]
    assert item["state"]==expected
    assert len(item["connections"])==2
    assert {row["source"] for row in item["connections"]}=={"Prometheus up","Approved scheduled Collector runtime"}
