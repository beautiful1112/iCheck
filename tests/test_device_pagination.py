from dataclasses import replace

import pytest
from fastapi import HTTPException

from icheck.database import SessionLocal
from icheck.device_api import page_onboarded_devices
from icheck.models import Device
from icheck.services.control_plane_auth import PrincipalContext


def _seed_devices(count: int = 135) -> None:
    with SessionLocal() as db:
        db.add_all(
            Device(
                name=f"page-device-{number:03d}",
                kind="switch",
                management_ip=f"198.18.{number // 254}.{number % 254 + 1}",
                site="LAB" if number % 2 == 0 else "BRANCH",
                onboarding_status="verified" if number % 3 == 0 else "pending_verification",
            )
            for number in range(count)
        )
        db.commit()


@pytest.mark.parametrize("explicit_null", [False, True])
@pytest.mark.parametrize("surface", ["list", "page", "detail"])
def test_assets_reads_preserve_inventory_without_management_ip(client, explicit_null, surface):
    payload = {"name": "discovered-without-ip", "kind": "switch", "site": "LAB"}
    if explicit_null:
        payload["management_ip"] = None
    created = client.post("/api/v1/devices", json=payload)
    assert created.status_code == 201, created.text
    device_id = created.json()["id"]
    path = "/api/v1/assets/devices"
    if surface == "page":
        path += "/page"
    elif surface == "detail":
        path += "/" + device_id
    response = client.get(path)
    assert response.status_code == 200, response.text
    body = response.json()
    device = body["items"][0] if surface == "page" else body[0] if surface == "list" else body
    assert device["id"] == device_id
    assert device["management_ip"] is None
    assert device["connections"] == []


@pytest.mark.parametrize("address", [None, "", "not-an-ip"])
def test_new_monitoring_enrollment_still_requires_valid_management_ip(client, address):
    response = client.post("/api/v1/assets/devices", json={
        "name": "invalid-new-enrollment", "kind": "switch", "site": "LAB",
        "management_ip": address, "connections": [{"protocol": "icmp"}], "created_by": "operator",
    })
    assert response.status_code == 422


def test_device_pages_cover_more_than_legacy_list_limit(client):
    _seed_devices()
    legacy = client.get("/api/v1/assets/devices")
    assert legacy.status_code == 200
    assert len(legacy.json()) == 100

    names: list[str] = []
    cursor = None
    while True:
        params = {"limit": 17}
        if cursor:
            params["cursor"] = cursor
        response = client.get("/api/v1/assets/devices/page", params=params)
        assert response.status_code == 200, response.text
        page = response.json()
        assert 1 <= len(page["items"]) <= 17
        names.extend(item["name"] for item in page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break

    assert names == [f"page-device-{number:03d}" for number in range(135)]
    assert len(set(names)) == 135


def test_device_pages_reach_past_one_thousand_rows(client):
    _seed_devices(1005)
    names: list[str] = []
    cursor = None
    seen_cursors: set[str] = set()
    while True:
        params = {"limit": 100}
        if cursor:
            params["cursor"] = cursor
        response = client.get("/api/v1/assets/devices/page", params=params)
        assert response.status_code == 200, response.text
        page = response.json()
        names.extend(item["name"] for item in page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
        assert cursor not in seen_cursors
        seen_cursors.add(cursor)
        assert len(seen_cursors) <= 11
    assert names == sorted(f"page-device-{number:03d}" for number in range(1005))


def test_device_page_search_filters_and_cursor_are_bound(client):
    _seed_devices()
    path = "/api/v1/assets/devices/page"
    params = {"search": "page-device-12", "site": "LAB", "limit": 2}
    first = client.get(path, params=params)
    assert first.status_code == 200, first.text
    assert [item["name"] for item in first.json()["items"]] == [
        "page-device-120",
        "page-device-122",
    ]
    cursor = first.json()["next_cursor"]
    assert cursor
    second = client.get(path, params={**params, "cursor": cursor})
    assert second.status_code == 200, second.text
    assert [item["name"] for item in second.json()["items"]] == [
        "page-device-124",
        "page-device-126",
    ]

    mismatched = client.get(path, params={"search": "page-device-13", "cursor": cursor})
    assert mismatched.status_code == 422
    assert mismatched.json()["detail"] == "Invalid device page cursor"
    malformed = client.get(path, params={"cursor": "%%%"})
    assert malformed.status_code == 422
    assert client.get(path, params={"limit": 101}).status_code == 422
    site_search = client.get(path, params={"search": "branch", "limit": 1})
    assert site_search.status_code == 200
    assert site_search.json()["items"][0]["site"] == "BRANCH"
    literal_wildcard = client.get(path, params={"search": "%"})
    assert literal_wildcard.status_code == 200
    assert literal_wildcard.json()["items"] == []


def test_device_page_cursor_accepts_maximum_length_unicode_name(client):
    with SessionLocal() as db:
        db.add_all(
            [
                Device(name="\u4e2d" * 255, kind="switch", management_ip="198.18.1.1"),
                Device(name="\u9f99", kind="switch", management_ip="198.18.1.2"),
            ]
        )
        db.commit()
    first = client.get("/api/v1/assets/devices/page", params={"limit": 1})
    assert first.status_code == 200, first.text
    cursor = first.json()["next_cursor"]
    assert cursor and len(cursor) > 1024
    second = client.get(
        "/api/v1/assets/devices/page",
        params={"limit": 1, "cursor": cursor},
    )
    assert second.status_code == 200, second.text
    assert [item["name"] for item in second.json()["items"]] == ["\u9f99"]


def test_device_page_rechecks_scope_and_rejects_cross_scope_cursor():
    _seed_devices(8)
    principal = PrincipalContext(
        principal_id="scoped-operator",
        subject="scoped-operator@example.test",
        principal_type="user",
        permissions=frozenset({"assets.read"}),
        role_names=(),
        authorization_scope={"sites": ["LAB"]},
        auth_method="token",
    )
    with SessionLocal() as db:
        first = page_onboarded_devices(
            search=None,
            kind=None,
            site=None,
            onboarding_status=None,
            limit=2,
            cursor=None,
            principal=principal,
            db=db,
        )
        assert [item.name for item in first.items] == [
            "page-device-000",
            "page-device-002",
        ]
        second = page_onboarded_devices(
            search=None,
            kind=None,
            site=None,
            onboarding_status=None,
            limit=2,
            cursor=first.next_cursor,
            principal=principal,
            db=db,
        )
        assert [item.name for item in second.items] == [
            "page-device-004",
            "page-device-006",
        ]
        assert second.next_cursor is None

        broadened = replace(principal, authorization_scope={"all": True})
        with pytest.raises(HTTPException) as error:
            page_onboarded_devices(
                search=None,
                kind=None,
                site=None,
                onboarding_status=None,
                limit=2,
                cursor=first.next_cursor,
                principal=broadened,
                db=db,
            )
        assert error.value.status_code == 422
