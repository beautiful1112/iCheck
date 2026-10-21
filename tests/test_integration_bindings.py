"""Reviewed bulk mapping is local identity work, never device enrollment."""
from dataclasses import replace
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from icheck.auth import current_principal
from icheck.database import SessionLocal, set_session_namespace, NamespaceViolation
from icheck.main import app
from icheck.models import (Device, DeviceMonitoringEnrollment, AuditEvent,
    MonitoringIntegrationBinding as Binding, MonitoringIntegrationResource as Resource)
from icheck.services.control_plane_auth import development_principal
from test_integration_discovery_sync import source, enabled, start, step
from test_monitoring_integrations import protected_configuration, BASE, TOKEN


def asset(name, **extra):
    with SessionLocal() as db:
        row = Device(name=name, kind="network", **extra)
        db.add(row)
        db.commit()
        return row.id


def inventory(client, source, count=3):
    source.hosts = [str(100 + i) for i in range(count)]
    row = enabled(client)
    run = start(client, row)
    while run["can_resume"]:
        run = step(client, row, run)
    return row, f"{BASE}/{row['id']}"


def plan(client, path, query=""):
    response = client.get(path + "/asset-mapping" + query)
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    return response.json()


def choice(item, device=None):
    device = device or item["suggestion"]
    return {"resource_id": item["resource_id"], "source_name": item["name"],
        "expected_binding_revision": item["binding_revision"], "device_id": device["id"],
        "expected_device_revision": device["revision"], "expected_device_identity_revision": device["identity_revision"]}


def body(view, items=None):
    return {"expected_revision": view["connection_revision"], "confirm": True, "expected_scan_id": view["scan_id"],
        "items": items if items is not None else [choice(item) for item in view["items"] if item["suggestion"]]}


def unlink(item):
    return {"resource_id": item["resource_id"], "source_name": item["name"],
            "expected_binding_revision": item["binding_revision"], "device_id": None}


def test_bulk_review_links_existing_assets_without_remote_calls_or_enrollment(client, source):
    row, path = inventory(client, source)
    ids = {asset("Device 100"), asset("Device 101")}
    calls = len(source.calls)
    view = plan(client, path)
    assert view["can_link"] and view["total"] == 3
    assert [item["match"] for item in view["items"]] == ["exact_name", "exact_name", "no_match"]
    assert all(item["state"] == "unlinked" for item in view["items"])
    result = client.put(path + "/asset-mapping", json=body(view))
    assert result.status_code == 200, result.text
    assert result.json() == {"updated": 2, "linked": 2, "unlinked": 0}
    current = plan(client, path)
    assert {item["device"]["id"] for item in current["items"] if item["device"]} == ids
    assert [item["state"] for item in current["items"]] == ["linked", "linked", "unlinked"]
    assert len(source.calls) == calls
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Device)) == 2
        assert db.scalar(select(func.count()).select_from(DeviceMonitoringEnrollment)) == 0
        audits = db.scalars(select(AuditEvent).where(AuditEvent.event_type == "monitoring_integration.asset_binding_reviewed")).all()
        assert len(audits) == 2
        assert TOKEN not in str([event.details for event in audits])


def test_one_thousand_reviewed_matches_are_one_bounded_atomic_request(client, source):
    _, path = inventory(client, source, 1000)
    with SessionLocal() as db:
        db.add_all([Device(name=f"Device {i}", kind="network") for i in range(100, 1100)])
        db.commit()
    view = plan(client, path, "?limit=1000")
    assert len(view["items"]) == 1000
    result = client.put(path + "/asset-mapping", json=body(view))
    assert result.status_code == 200, result.text
    assert result.json()["linked"] == 1000
    assert client.get(path + "/asset-mapping?limit=1001").status_code == 422
    assert client.put(path + "/asset-mapping", json=body(view, [choice(view["items"][0])] * 1001)).status_code == 422


def test_exact_name_is_only_a_suggestion_duplicate_names_are_ambiguous_across_pages(client, source):
    _, path = inventory(client, source)
    asset("Device 100")
    asset("device 101")  # Deliberately no case/substring inference.
    with SessionLocal() as db:
        other = db.scalar(select(Resource).where(Resource.remote_id == "102"))
        other.name = "Device 100"
        db.commit()
    view = plan(client, path, "?limit=1")
    assert view["items"][0]["match"] == "ambiguous" and view["items"][0]["suggestion"] is None
    assert plan(client, path)["items"][-1]["match"] == "no_match"


def test_manual_exception_search_and_binding_use_existing_asset_identity(client, source):
    _, path = inventory(client, source, 1)
    identifier = asset("Branch switch", management_ip="192.0.2.10", site="Branch")
    response = client.get(path + "/asset-candidates?search=192.0.2.10")
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    assert response.json()["items"][0]["id"] == identifier
    view = plan(client, path)
    assert client.put(path + "/asset-mapping", json=body(view, [choice(view["items"][0], response.json()["items"][0])])).status_code == 200
    assert plan(client, path)["items"][0]["device"]["name"] == "Branch switch"
    assert client.get(path + "/asset-candidates?search=%25").json()["items"] == []
    assert client.get(path + "/asset-candidates?search=%20").json()["items"] == []


def test_candidate_search_is_bounded_and_hides_disabled_assets(client, source):
    _, path = inventory(client, source, 1)
    for i in range(22):
        asset(f"Switch {i}", enabled=i != 0)
    result = client.get(path + "/asset-candidates?search=Switch").json()
    assert len(result["items"]) == 20 and result["truncated"]
    assert all(item["enabled"] for item in result["items"])


@pytest.mark.parametrize("change", ["binding", "device_revision", "device_identity", "source_name", "scan", "scope", "disabled", "missing"])
def test_review_is_invalidated_by_relevant_changes(client, source, change):
    row, path = inventory(client, source, 1)
    identifier = asset("Device 100")
    view = plan(client, path)
    payload = body(view)
    if change == "binding":
        assert client.put(path + "/asset-mapping", json=payload).status_code == 200
    elif change in {"device_revision", "device_identity", "source_name"}:
        with SessionLocal() as db:
            if change == "source_name":
                db.get(Resource, view["items"][0]["resource_id"]).name = "Renamed"
            else:
                device = db.get(Device, identifier)
                if change == "device_identity":
                    device.identity_revision += 1
                else:
                    device.revision += 1
            db.commit()
    elif change in {"scope", "disabled"}:
        assert client.put(path, json={"expected_revision": row["revision"], "enabled": change != "disabled", "group_ids": ["2"]}).status_code == 200
    else:
        if change == "missing":
            source.missing = {"100"}
        run = step(client, row, start(client, row))
        assert run["status"] == "completed"
    response = client.put(path + "/asset-mapping", json=payload)
    assert response.status_code == 409, response.text


def test_partial_batch_is_not_committed_when_one_asset_changes(client, source):
    _, path = inventory(client, source, 2)
    asset("Device 100")
    identifier = asset("Device 101")
    payload = body(plan(client, path))
    with SessionLocal() as db:
        db.get(Device, identifier).revision += 1
        db.commit()
    assert client.put(path + "/asset-mapping", json=payload).status_code == 409
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Binding)) == 0


def test_unlink_is_available_after_scope_change_and_preserves_revision_history(client, source):
    row, path = inventory(client, source, 1)
    asset("Device 100")
    first = plan(client, path)
    assert client.put(path + "/asset-mapping", json=body(first)).status_code == 200
    assert client.put(path, json={"expected_revision": row["revision"], "enabled": False}).status_code == 200
    view = plan(client, path)
    assert not view["can_link"]
    item = view["items"][0]
    assert item["state"] == "needs_review" and item["reason"] == "connection_disabled"
    payload = body(view, [unlink(item)])
    assert client.put(path + "/asset-mapping", json=payload).status_code == 200
    assert client.put(path + "/asset-mapping", json=payload).status_code == 409
    with SessionLocal() as db:
        binding = db.get(Binding, item["resource_id"])
        assert binding.device_id is None and binding.revision == 2


@pytest.mark.parametrize("change,reason", [("source_name", "source_name_changed"), ("asset", "asset_identity_changed"),
    ("disabled", "asset_unavailable"), ("missing", "not_seen_in_latest_scan"), ("active", "complete_inventory_sync_required")])
def test_saved_binding_state_rechecks_current_evidence_without_deleting_it(client, source, change, reason):
    row, path = inventory(client, source, 1)
    identifier = asset("Device 100")
    view = plan(client, path)
    assert client.put(path + "/asset-mapping", json=body(view)).status_code == 200
    if change in {"active", "missing"}:
        source.missing = {"100"}
        run = start(client, row)
        if change == "missing":
            step(client, row, run)
    else:
        with SessionLocal() as db:
            if change == "source_name":
                db.get(Resource, view["items"][0]["resource_id"]).name = "Changed"
            elif change == "asset":
                db.get(Device, identifier).identity_revision += 1
            else:
                db.get(Device, identifier).enabled = False
            db.commit()
    result = plan(client, path)["items"][0]
    assert result["state"] == "needs_review" and result["reason"] == reason
    assert result["binding_revision"] == 1 and result["device"]["id"] == identifier


def test_duplicate_asset_claim_requires_explicit_unlink_first(client, source):
    _, path = inventory(client, source, 2)
    asset("Device 100")
    view = plan(client, path)
    first, second = view["items"]
    selected = first["suggestion"]
    assert client.put(path + "/asset-mapping", json=body(view, [choice(first), choice(second, selected)])).status_code == 422
    assert client.put(path + "/asset-mapping", json=body(view, [choice(first)])).status_code == 200
    assert client.put(path + "/asset-mapping", json=body(view, [choice(second, selected)])).status_code == 409
    current = plan(client, path)
    assert client.put(path + "/asset-mapping", json=body(current, [unlink(current["items"][0])])).status_code == 200
    assert client.put(path + "/asset-mapping", json=body(current, [choice(second, selected)])).status_code == 200


@pytest.mark.parametrize("permissions,scope,kind,expected", [
    (("metrics.read",), {"all": True}, "development", 403),
    (("metrics.read", "assets.read"), {"all": True}, "development", 200),
    (("*",), {"sites": ["Branch"]}, "development", 403),
    (("*",), {"all": True}, "service", 200),
])
def test_read_and_write_authority_are_separate(client, source, permissions, scope, kind, expected):
    _, path = inventory(client, source, 1)
    asset("Device 100")
    payload = body(plan(client, path))
    principal = replace(development_principal(), permissions=frozenset(permissions),
                        authorization_scope=scope, principal_type=kind)
    app.dependency_overrides[current_principal] = lambda: principal
    assert client.get(path + "/asset-mapping").status_code == expected
    assert client.get(path + "/asset-candidates?search=Device").status_code == expected
    assert client.put(path + "/asset-mapping", json=payload).status_code == 403


def test_other_connection_resource_and_foreign_asset_cannot_be_bound(client, source):
    row, path = inventory(client, source, 1)
    asset("Device 100")
    view = plan(client, path)
    payload = body(view)
    payload["items"][0]["resource_id"] = str(uuid4())
    assert client.put(path + "/asset-mapping", json=payload).status_code == 404
    with SessionLocal() as db:
        foreign = Device(id=str(uuid4()), name="Foreign device", kind="network", tenant_id=str(uuid4()), region_id=str(uuid4()))
        db.add(foreign)
        db.commit()
        foreign_id = foreign.id
    payload = body(view)
    payload["items"][0]["device_id"] = foreign_id
    assert client.put(path + "/asset-mapping", json=payload).status_code == 404
    assert client.get(path + "/asset-candidates?search=Foreign").json()["items"] == []
    from icheck.services import integration_bindings
    with SessionLocal() as db:
        set_session_namespace(db, str(uuid4()), str(uuid4()))
        with pytest.raises(NamespaceViolation):
            integration_bindings.listing(db, row["id"], development_principal())


@pytest.mark.parametrize("alter", ["confirmation", "duplicate", "scan", "revision", "missing_device_revision"])
def test_binding_request_shape_is_strict(client, source, alter):
    _, path = inventory(client, source, 1)
    asset("Device 100")
    payload = body(plan(client, path))
    if alter == "confirmation":
        payload["confirm"] = False
    elif alter == "duplicate":
        payload["items"] *= 2
    elif alter == "scan":
        payload["expected_scan_id"] = None
    elif alter == "revision":
        payload["items"][0]["expected_binding_revision"] = True
    else:
        payload["items"][0].pop("expected_device_revision")
    assert client.put(path + "/asset-mapping", json=payload).status_code == 422
