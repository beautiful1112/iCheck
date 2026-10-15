from datetime import UTC, datetime, timedelta
from dataclasses import replace

from icheck.database import SessionLocal
from icheck.inventory_views_api import endpoint_history, list_interfaces
from icheck.models import CollectorRun, CollectorRunStatus, CollectionEnvelope
from icheck.services.control_plane_auth import development_principal
from test_inventory import create_device
from test_knowledge_projection import _start_scoped_run, _post_envelope


def collected(client, name="interfaces", site="HQ"):
    device, assignment, headers = _start_scoped_run(client, name=name, site=site)
    now = datetime.now(UTC)
    for minute, value in ((0, 2), (1, 1)):
        response = _post_envelope(client, assignment, headers, {
            "kind": "observation", "type": "metric.sample", "source": "snmp_exporter:test",
            "observed_at": (now + timedelta(minutes=minute)).isoformat(),
            "payload": {"metric": "ifOperStatus", "labels": {"ifIndex": "7", "ifName": "Gi0/7",
                        "vendor_note": "MUST_NOT_ESCAPE"}, "value": value},
        })
        assert response.status_code == 200, response.text
    return device, assignment


def succeed(assignment):
    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        run.status = CollectorRunStatus.SUCCEEDED
        db.commit()


def test_interface_view_reads_only_successful_collected_evidence(client):
    device, assignment = collected(client)
    assert client.get("/api/v1/assets/interfaces").json()["items"] == []
    succeed(assignment)
    response = client.get("/api/v1/assets/interfaces")
    assert response.status_code == 200, response.text
    item = response.json()["items"][0]
    assert item["device_id"] == device["id"]
    assert item["name"] == "Gi0/7" and item["if_index"] == "7"
    assert item["metrics"] == {"ifOperStatus": 1.0}
    assert set(item["evidence_ids"]) == set(item["metric_observed_at"]) == {"ifOperStatus"}
    assert "MUST_NOT_ESCAPE" not in response.text
    assert "vendor_note" not in response.text
    bounded = client.get("/api/v1/assets/interfaces?sample_limit=1").json()
    assert bounded["truncated"] is True and bounded["samples_examined"] == 1


def test_interface_view_scope_and_malformed_samples(client):
    hk, assignment = collected(client, "hk", "Hong Kong")
    ny, other = collected(client, "ny", "New York")
    succeed(assignment); succeed(other)
    with SessionLocal() as db:
        sample = db.query(CollectionEnvelope).filter_by(run_id=assignment["run_id"]).first()
        sample.payload = {"metric": "ifOperStatus", "labels": {"ifIndex": "bad"}, "value": 1}
        db.commit()
        principal = replace(development_principal(), authorization_scope={"sites": ["Hong Kong"]})
        result = list_interfaces(db, device_id=None, limit=100, sample_limit=100, principal=principal)
        assert [row["device_id"] for row in result["items"]] == [hk["id"]]
        assert result["items"][0]["device_id"] != ny["id"]
        assert list_interfaces(db, device_id=ny["id"], limit=100, sample_limit=100,
                               principal=principal)["items"] == []
    assert client.get("/api/v1/assets/interfaces?limit=1001").status_code == 422


def test_history_api_retains_inactive_ip_and_scopes_sources(client):
    device = create_device(client)
    now = datetime.now(UTC)
    for minute, address in ((0, "10.0.1.1"), (1, "10.0.1.2")):
        result = client.post("/api/v1/inventory/network-observations", json={"observations": [{
            "mac_address": "02:00:00:00:00:01", "collector_device_id": device["id"],
            "source": "arp", "ip_address": address, "interface_name": "Gi0/1",
            "observed_at": (now + timedelta(minutes=minute)).isoformat(),
        }]})
        assert result.status_code == 200, result.text
    identity = client.get("/api/v1/endpoints").json()[0]["id"]
    result = client.get(f"/api/v1/endpoints/{identity}/history")
    assert result.status_code == 200, result.text
    history = result.json()
    # Closing the old observation can share the new observation's last_seen.
    # Stable ID tie-breaking must not be mistaken for an active-first contract.
    assert {row["ip_address"]: row["active"] for row in history["ip_history"]} == {
        "10.0.1.2": True, "10.0.1.1": False,
    }
    assert "raw_data" not in result.text and "username" not in result.text
    assert client.get(f"/api/v1/endpoints/{identity}/history?limit=1").json()["truncated"] == ["ip_history"]
    with SessionLocal() as db:
        principal = replace(development_principal(), authorization_scope={"sites": ["HQ"]})
        assert len(endpoint_history(identity, db, limit=50, principal=principal)["ip_history"]) == 2
    assert client.get("/api/v1/endpoints/missing/history").status_code == 404
