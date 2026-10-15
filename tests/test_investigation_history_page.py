"""Bounded, namespace-local Investigation history for the AI operator UI."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import select

from icheck.agent_api import page_investigations
from icheck.database import SessionLocal, set_session_namespace
from icheck.models import Device, Investigation
from icheck.services.control_plane_auth import PrincipalContext

from test_agent_runtime import configure_investigation_route


def _create(client, title: str):
    response = client.post("/api/v1/agent/investigations", json={
        "title": title,
        "objective": "Review bounded operator history.",
        "scope": {},
        "route_purpose": "investigation",
        "created_by": "history.operator",
    })
    assert response.status_code == 201, response.text
    return response.json()


def test_dashboard_history_filters_before_paging_and_rejects_other_connection_cursor(client):
    configure_investigation_route(client)
    connection, other = str(uuid4()), str(uuid4())
    rows = [_create(client, f"Dashboard {index}") for index in range(5)]
    with SessionLocal() as db:
        for index, row in enumerate(rows):
            if index < 4:
                db.get(Investigation, row["id"]).scope = {"capability_task": "grafana-dashboard",
                    "grafana_connection_id": connection if index < 3 else other}
        db.commit()
    params = {"capability_task": "grafana-dashboard", "grafana_connection_id": connection, "limit": 2}
    endpoint = "/api/v1/agent/investigations/page"
    first = client.get(endpoint, params=params)
    assert first.status_code == 200, first.text
    assert len(first.json()["items"]) == 2
    second = client.get(endpoint, params={**params, "cursor": first.json()["next_cursor"]})
    assert len(second.json()["items"]) == 1 and second.json()["next_cursor"] is None
    assert {row["id"] for row in first.json()["items"] + second.json()["items"]} == {row["id"] for row in rows[:3]}
    assert client.get(endpoint, params={**params, "cursor": rows[3]["id"]}).status_code == 422
    assert client.get(endpoint, params={"grafana_connection_id": connection}).status_code == 422
    assert client.get(endpoint, params={"capability_task": "arbitrary"}).status_code == 422


def test_history_page_keyset_status_filter_and_cursor_validation(client):
    configure_investigation_route(client)
    created = [_create(client, f"History {index}") for index in range(7)]
    common_time = datetime(2026, 10, 5, 1, 0, tzinfo=UTC)
    with SessionLocal() as db:
        for index, item in enumerate(created):
            saved = db.get(Investigation, item["id"])
            saved.created_at = common_time
            if index in (1, 5):
                saved.status = "completed"
        db.commit()
        expected = list(db.scalars(
            select(Investigation).order_by(
                Investigation.created_at.desc(), Investigation.id.desc(),
            )
        ).all())

    ids = []
    cursor = None
    while True:
        params = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        response = client.get("/api/v1/agent/investigations/page", params=params)
        assert response.status_code == 200, response.text
        page = response.json()
        ids.extend(item["id"] for item in page["items"])
        if not page["next_cursor"]:
            break
        assert page["next_cursor"] == page["items"][-1]["id"]
        cursor = page["next_cursor"]
    assert ids == [item.id for item in expected]
    assert len(ids) == len(set(ids)) == 7

    completed = client.get(
        "/api/v1/agent/investigations/page",
        params={"status": "completed", "limit": 1},
    )
    assert completed.status_code == 200, completed.text
    assert len(completed.json()["items"]) == 1
    assert completed.json()["next_cursor"] is not None
    wrong_filter = client.get(
        "/api/v1/agent/investigations/page",
        params={"status": "running", "cursor": completed.json()["next_cursor"]},
    )
    assert wrong_filter.status_code == 422
    for bad_cursor in ("bad-cursor", str(uuid4())):
        denied = client.get(
            "/api/v1/agent/investigations/page", params={"cursor": bad_cursor},
        )
        assert denied.status_code == 422
    assert len(client.get("/api/v1/agent/investigations?limit=30").json()) == 7


def test_history_page_scans_past_hidden_rows_and_rejects_revoked_cursor(client):
    route = configure_investigation_route(client)
    with SessionLocal() as db:
        allowed = Device(
            name="history-allowed", kind="switch", site="LAB",
            created_by="history.operator",
        )
        hidden = Device(
            name="history-hidden", kind="switch", site="OTHER",
            created_by="history.operator",
        )
        db.add_all([allowed, hidden])
        db.flush()
        now = datetime(2026, 10, 5, 2, 0, tzinfo=UTC)

        def add_item(index: int, device_id: str):
            db.add(Investigation(
                title=f"Scoped history {index}", objective="Scoped pagination",
                scope={"device_ids": [device_id]},
                authorization_scope={"device_ids": [device_id]},
                status="pending", route_id=route["id"],
                model_id=route["primary_model_id"],
                max_iterations=2, max_tool_calls=2,
                timeout_seconds=60, token_budget=100,
                created_by="history.operator",
                created_at=now - timedelta(seconds=index),
            ))

        add_item(0, allowed.id)
        for index in range(1, 206):
            add_item(index, hidden.id)
        add_item(206, allowed.id)
        db.commit()
        principal = PrincipalContext(
            principal_id=None, subject="history.operator",
            principal_type="user",
            permissions=frozenset({"investigations.read"}),
            role_names=("viewer",),
            authorization_scope={"device_ids": [allowed.id]},
            auth_method="test",
        )
        set_session_namespace(db, principal.tenant_id, principal.region_id)
        first = page_investigations(None, 1, None, principal, db)
        assert len(first.items) == 1
        assert first.items[0].title == "Scoped history 0"
        assert first.next_cursor == first.items[0].id
        second = page_investigations(None, 1, first.next_cursor, principal, db)
        assert [item.title for item in second.items] == ["Scoped history 206"]
        assert second.next_cursor is None

        revoked = PrincipalContext(
            principal_id=None, subject="history.operator",
            principal_type="user", permissions=principal.permissions,
            role_names=principal.role_names,
            authorization_scope={"device_ids": [hidden.id]},
            auth_method="test",
        )
        from fastapi import HTTPException

        try:
            page_investigations(None, 1, first.next_cursor, revoked, db)
        except HTTPException as exc:
            assert exc.status_code == 422
        else:
            raise AssertionError("Revoked investigation cursor was accepted")
