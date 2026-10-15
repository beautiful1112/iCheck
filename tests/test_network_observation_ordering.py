from datetime import timedelta

import pytest
from sqlalchemy import func, select

from icheck.database import SessionLocal
from icheck.models import (Alert, Endpoint, EndpointAttachment, IPAddressObservation,
    NetworkObservationState, ObservationSource, utcnow)
from icheck.schemas import NetworkObservationBatch
from icheck.projection_schemas import NETWORK_OBSERVATION_V1
from icheck.services.inventory import ingest_network_observations
from test_inventory import create_device

session = SessionLocal
MAC = "00:1b:44:11:3a:b7"


def body(device, at, **extra):
    return {"mac_address": MAC, "source": "arp", "collector_device_id": device,
        "interface_name": "eth1", "vlan_id": 10, "hostname": "current-host",
        "ip_address": "192.0.2.10", "observed_at": at.isoformat(), **extra}


def post(client, *observations, success=True):
    response = client.post("/api/v1/inventory/network-observations", json={"observations": list(observations)})
    assert (response.status_code == 200) is success, response.text
    return response


def ips(db):
    return {row.ip_address for row in db.scalars(select(IPAddressObservation).where(IPAddressObservation.active.is_(True)))}


def test_late_network_sample_cannot_regress_ip_attachment_metadata_or_alert(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now))
    newer = body(device, now+timedelta(seconds=2), ip_address="192.0.2.20", interface_name="eth2", hostname="new-host")
    post(client, newer)
    with session() as db:
        before = [(row.id, row.active, row.last_seen) for row in db.scalars(select(IPAddressObservation))]
        alert_count = db.scalar(select(func.count()).select_from(Alert))
    result = post(client, body(device, now+timedelta(seconds=1))).json()
    assert set(result["network_dispositions"][0]["channels"].values()) == {"stale"}
    assert result["endpoints_updated"] == result["ip_observations_written"] == result["attachments_written"] == 0
    with session() as db:
        assert ips(db) == {"192.0.2.20"}
        assert db.scalar(select(Endpoint)).hostname == "new-host"
        assert db.scalar(select(EndpointAttachment).where(EndpointAttachment.active.is_(True))).interface_name == "eth2"
        assert [(row.id, row.active, row.last_seen) for row in db.scalars(select(IPAddressObservation))] == before
        assert db.scalar(select(func.count()).select_from(Alert)) == alert_count


def test_exact_retry_is_duplicate_and_same_clock_conflict_requires_newer_measurement(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now))
    retry = post(client, body(device, now, mac_address="00-1B-44-11-3A-B7")).json()
    assert set(retry["network_dispositions"][0]["channels"].values()) == {"duplicate"}
    conflict = post(client, body(device, now, ip_address="192.0.2.11", interface_name="eth2")).json()
    assert conflict["network_dispositions"][0]["channels"]["ipv4"] == "conflict"
    assert conflict["network_dispositions"][0]["channels"]["attachment"] == "conflict"
    again = post(client, body(device, now)).json()
    assert again["network_dispositions"][0]["channels"]["ipv4"] == "conflict"
    visible = client.get("/api/v1/endpoints").json()[0]
    assert visible["current_ips"][0]["network_observation_state"] == "conflict"
    assert visible["current_ips"][0]["independently_verified"] is False
    assert visible["current_attachments"][0]["network_observation_state"] == "conflict"
    with session() as db:
        assert ips(db) == {"192.0.2.10"}
        assert db.scalar(select(EndpointAttachment).where(EndpointAttachment.active.is_(True))).interface_name == "eth1"
    post(client, body(device, now+timedelta(seconds=1), ip_address="192.0.2.30"))
    with session() as db:
        assert ips(db) == {"192.0.2.30"}
        assert set(db.scalars(select(NetworkObservationState.state))) == {"accepted"}


def test_explicit_alias_address_set_dual_stack_and_empty_clear_do_not_infer_omission(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now, ip_address=None,
        ip_addresses=["192.0.2.10", "192.0.2.11", "2001:db8::10", "fe80::10"]))
    with session() as db:
        assert ips(db) == {"192.0.2.10", "192.0.2.11", "2001:db8::10", "fe80::10"}
    post(client, body(device, now+timedelta(seconds=1), ip_address=None))
    with session() as db:
        assert len(ips(db)) == 4  # Absence of address input changes neither family.
    post(client, body(device, now+timedelta(seconds=2), ip_address="192.0.2.20"))
    with session() as db:
        assert ips(db) == {"192.0.2.20", "2001:db8::10", "fe80::10"}
    post(client, body(device, now+timedelta(seconds=3), ip_address=None, ip_addresses=[]))
    with session() as db:
        assert ips(db) == set()
        assert db.scalar(select(func.count()).select_from(IPAddressObservation)) == 5
    old = post(client, body(device, now+timedelta(seconds=2), ip_address=None,
        ip_addresses=["192.0.2.10", "2001:db8::10"])).json()
    assert old["network_dispositions"][0]["channels"]["ipv4"] == "stale"
    assert old["network_dispositions"][0]["channels"]["ipv6"] == "stale"
    with session() as db:
        assert ips(db) == set()


def test_complete_clear_before_first_address_retains_clock_and_blocks_late_creation(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now+timedelta(seconds=2), ip_address=None, ip_addresses=[]))
    old = post(client, body(device, now+timedelta(seconds=1))).json()
    assert old["network_dispositions"][0]["channels"]["ipv4"] == "stale"
    with session() as db:
        assert ips(db) == set()
        assert db.scalar(select(func.count()).select_from(IPAddressObservation)) == 0


def test_source_and_collector_clocks_are_independent_and_clear_only_owned_records(client):
    a, b, now = create_device(client)["id"], create_device(client, name="other-switch", kind="router")["id"], utcnow()
    post(client, body(a, now+timedelta(seconds=2)), body(b, now, ip_address="192.0.2.30"))
    post(client, body(a, now, source="dhcp", ip_address="192.0.2.40"))
    post(client, body(a, now+timedelta(seconds=3), ip_address=None, ip_addresses=[]))
    with session() as db:
        assert ips(db) == {"192.0.2.30", "192.0.2.40"}
        assert db.scalar(select(func.count()).select_from(Endpoint)) == 1


def test_same_clock_dual_stack_legacy_points_share_metadata_and_attachment_without_false_conflict(client):
    device, now = create_device(client)["id"], utcnow()
    result = post(client, body(device, now), body(device, now, ip_address="2001:db8::10")).json()
    assert result["network_dispositions"][0]["channels"]["ipv4"] == "accepted"
    assert result["network_dispositions"][1]["channels"]["ipv6"] == "accepted"
    assert result["network_dispositions"][1]["channels"]["attachment"] == "duplicate"
    with session() as db:
        assert ips(db) == {"192.0.2.10", "2001:db8::10"}


@pytest.mark.parametrize("kind", ["incoherent", "future", "duplicate_ip", "ambiguous_ip", "boolean_vlan", "oversized", "disabled", "wifi", "deep_json", "long_zone", "contradictory_detach"])
def test_invalid_batch_is_atomic_and_never_creates_inventory_or_watermarks(client, kind):
    device, now = create_device(client)["id"], utcnow()
    row = body(device, now)
    if kind == "incoherent":
        result = post(client, row, body(device, now, ip_address="192.0.2.20"), success=False)
    else:
        if kind == "future":
            row["observed_at"] = (now+timedelta(minutes=6)).isoformat()
        elif kind == "duplicate_ip":
            row.update(ip_address=None, ip_addresses=["2001:db8::1", "2001:0db8:0:0:0:0:0:1"])
        elif kind == "ambiguous_ip":
            row["ip_addresses"] = []
        elif kind == "boolean_vlan":
            row["vlan_id"] = True
        elif kind == "oversized":
            row["raw_data"] = {"long": "x"*65536}
        elif kind == "disabled":
            from icheck.models import Device
            with session() as db:
                db.get(Device, device).enabled = False
                db.commit()
        elif kind == "deep_json":
            nested = {}
            for _ in range(33):
                nested = {"nested": nested}
            row["raw_data"] = nested
        elif kind == "long_zone":
            row["ip_address"] = "fe80::1%"+"x"*50
        elif kind == "contradictory_detach":
            row["attachment_present"] = False
        else:
            row["source"] = "wifi_controller"
        result = post(client, row, success=False)
    assert result.status_code == 422
    with session() as db:
        for model in (Endpoint, IPAddressObservation, EndpointAttachment, NetworkObservationState):
            assert db.scalar(select(func.count()).select_from(model)) == 0


def test_three_ordered_samples_in_one_batch_do_not_mistake_own_writes_for_pending_edits(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, *(body(device, now+timedelta(seconds=index), ip_address=f"192.0.2.{10+index}") for index in (2, 0, 1)))
    with session() as db:
        assert ips(db) == {"192.0.2.12"}
        assert db.scalar(select(func.count()).select_from(IPAddressObservation)) == 3


@pytest.mark.parametrize("kind", ["endpoint", "watermark", "ip", "attachment"])
def test_pending_relevant_inventory_edits_are_refused_before_flush_or_overwrite(client, kind):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now))
    model = {"endpoint": Endpoint, "watermark": NetworkObservationState, "ip": IPAddressObservation, "attachment": EndpointAttachment}[kind]
    with session() as db:
        row = db.scalar(select(model))
        if kind == "endpoint":
            row.hostname = "pending-user-edit"
        elif kind == "watermark":
            row.payload = "pending-user-edit"
        elif kind == "ip":
            row.active = False
        else:
            row.interface_name = "pending-user-edit"
        with pytest.raises(ValueError, match="pending network"):
            ingest_network_observations(db, NetworkObservationBatch.model_validate({"observations": [body(device, now+timedelta(seconds=1))]}))
        assert db.is_modified(row)
        db.rollback()


def test_explicit_address_set_order_and_ipv6_spelling_are_idempotent(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now, ip_address=None, ip_addresses=["192.0.2.11", "2001:db8::10", "192.0.2.10"]))
    result = post(client, body(device, now, ip_address=None,
        ip_addresses=["2001:0db8:0:0:0:0:0:10", "192.0.2.10", "192.0.2.11"])).json()
    assert set(result["network_dispositions"][0]["channels"].values()) == {"duplicate"}


def test_generated_invalid_vlan_retains_dead_letter_without_inventory_writes(client):
    from icheck.models import KnowledgeProjectionStatus
    from test_knowledge_projection import _start_scoped_run, _post_envelope, _project_one
    device, assignment, headers = _start_scoped_run(client, name="network-boolean-vlan")
    frame = {"kind": "observation", "type": NETWORK_OBSERVATION_V1, "source": "generated-network",
        "observed_at": utcnow().isoformat(), "payload": {"mac_address": MAC, "source": "arp", "vlan_id": True}}
    response = _post_envelope(client, assignment, headers, frame)
    assert response.status_code == 200, response.text
    _projection_id, status = _project_one()
    assert status == KnowledgeProjectionStatus.DEAD_LETTER
    with session() as db:
        assert db.scalar(select(func.count()).select_from(Endpoint)) == 0


def test_generated_address_set_and_late_sample_share_direct_clock_contract(client):
    from icheck.models import KnowledgeProjectionStatus, KnowledgeProjection
    from test_knowledge_projection import _start_scoped_run, _post_envelope, _project_one
    device, assignment, headers = _start_scoped_run(client, name="network-ordered-generated")
    now = utcnow()
    for at, payload in [(now+timedelta(seconds=2), {"ip_addresses": ["192.0.2.10", "2001:db8::10"]}),
        (now+timedelta(seconds=1), {"ip_address": "192.0.2.20"})]:
        response = _post_envelope(client, assignment, headers, {"kind": "observation",
            "type": NETWORK_OBSERVATION_V1, "source": "generated-network", "observed_at": at.isoformat(),
            "payload": {"mac_address": MAC, "source": "arp", "interface_name": "eth1", **payload}})
        assert response.status_code == 200, response.text
        projection_id, status = _project_one()
        assert status == KnowledgeProjectionStatus.SUCCEEDED
    with session() as db:
        assert ips(db) == {"192.0.2.10", "2001:db8::10"}
        assert db.get(KnowledgeProjection, projection_id).result_summary["network_dispositions"][0]["channels"]["ipv4"] == "stale"


def test_scoped_mixed_batch_cannot_hide_an_unbound_observation_behind_one_authorized_device(client):
    from icheck.services.control_plane_auth import PrincipalContext
    principal = PrincipalContext(principal_id=None, subject="scoped-ingestor", principal_type="human",
        permissions=frozenset({"inventory.ingest"}), role_names=(), authorization_scope={"sites": ["HQ"]}, auth_method="fixture")
    from fastapi import HTTPException
    device, now = create_device(client)["id"], utcnow()
    batch = NetworkObservationBatch.model_validate({"observations": [body(device, now),
        body(None, now, mac_address="00:1b:44:11:3a:b8")]})
    with session() as db:
        with pytest.raises(HTTPException) as error:
            ingest_network_observations(db, batch, principal=principal)
        assert error.value.status_code == 403
        db.rollback()
        assert db.scalar(select(func.count()).select_from(Endpoint)) == 0


def test_missing_port_preserves_known_attachment_and_explicit_detach_blocks_late_resurrection(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now))
    missing = post(client, body(device, now+timedelta(seconds=1), interface_name=None)).json()
    assert missing["network_dispositions"][0]["channels"]["attachment"] == "not_observed"
    with session() as db:
        assert db.scalar(select(EndpointAttachment).where(EndpointAttachment.active.is_(True))).interface_name == "eth1"
    post(client, body(device, now+timedelta(seconds=3), interface_name=None, attachment_present=False))
    late = post(client, body(device, now+timedelta(seconds=2), interface_name="eth2")).json()
    assert late["network_dispositions"][0]["channels"]["attachment"] == "stale"
    post(client, body(device, now+timedelta(seconds=4), interface_name=None))
    with session() as db:
        assert db.scalar(select(func.count()).select_from(EndpointAttachment).where(EndpointAttachment.active.is_(True))) == 0
    post(client, body(device, now+timedelta(seconds=5), interface_name="eth3", attachment_present=True))
    with session() as db:
        assert db.scalar(select(EndpointAttachment).where(EndpointAttachment.active.is_(True))).interface_name == "eth3"


def test_detach_before_first_attachment_retains_clock_and_missing_port_cannot_reactivate(client):
    device, now = create_device(client)["id"], utcnow()
    post(client, body(device, now+timedelta(seconds=2), interface_name=None, attachment_present=False))
    post(client, body(device, now+timedelta(seconds=1)))
    post(client, body(device, now+timedelta(seconds=3), interface_name=None))
    with session() as db:
        assert db.scalar(select(func.count()).select_from(EndpointAttachment)) == 0
        state = db.scalar(select(NetworkObservationState).where(NetworkObservationState.dimension == "attachment"))
        assert state.observed_at.replace(tzinfo=now.tzinfo) == now+timedelta(seconds=2)
