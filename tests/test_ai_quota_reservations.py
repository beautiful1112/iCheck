"""Operator-facing quota receipts remain actor- and namespace-scoped."""

from uuid import uuid4

from icheck.database import (
    DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace,
)
from icheck.services.ai_authoring_quota import (
    list_authoring_reservations,
    reserve_authoring_tokens,
    settle_authoring_tokens,
)


def _receipt(db, actor: str, *, source_id: str | None = None, known: int | None = None):
    receipt_id = reserve_authoring_tokens(
        db, actor=actor, entity_type="investigation_step",
        entity_id=str(uuid4()), token_budget=100,
        source_entity_type="investigation", source_entity_id=source_id or str(uuid4()),
        source_step=0,
    )
    if known is not None:
        settle_authoring_tokens(
            db, receipt_id, known_tokens=known,
            external_charge_unknown=False,
        )
    return receipt_id


def test_reservation_list_is_keyset_paged_and_source_filtered(client):
    source_id = str(uuid4())
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        first = _receipt(db, "l1.operator", source_id=source_id)
        second = _receipt(db, "l1.operator", source_id=source_id)
        _receipt(db, "another.operator")
        _receipt(db, "l1.operator", known=37)
    response = client.get("/api/v1/ai/authoring-quota/reservations", params={
        "actor": "l1.operator", "state": "pending", "limit": 1,
        "source_entity_id": source_id,
    })
    assert response.status_code == 200, response.text
    first_page = response.json()
    assert len(first_page["items"]) == 1
    assert first_page["next_cursor"] is not None
    assert first_page["items"][0]["source_entity_type"] == "investigation"
    assert first_page["items"][0]["source_entity_id"] == source_id
    assert first_page["items"][0]["source_step"] == 0
    next_page = client.get("/api/v1/ai/authoring-quota/reservations", params={
        "actor": "l1.operator", "state": "pending", "limit": 1,
        "source_entity_id": source_id,
        "cursor": first_page["next_cursor"],
    })
    assert next_page.status_code == 200, next_page.text
    assert next_page.json()["next_cursor"] is None
    assert {first_page["items"][0]["id"], next_page.json()["items"][0]["id"]} == {
        first, second,
    }
    attention = client.get("/api/v1/ai/authoring-quota/reservations", params={
        "actor": "l1.operator", "state": "attention",
    })
    assert attention.status_code == 200, attention.text
    assert {item["id"] for item in attention.json()["items"]} == {first, second}
    denied_cursor = client.get("/api/v1/ai/authoring-quota/reservations", params={
        "actor": "another.operator", "cursor": first,
    })
    assert denied_cursor.status_code == 400


def test_reservation_listing_excludes_another_namespace_even_with_same_actor():
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        own_id = _receipt(db, "operator@example.test")
        other_tenant, other_region = str(uuid4()), str(uuid4())
        set_session_namespace(db, other_tenant, other_region)
        other_id = _receipt(db, "operator@example.test")
        rows, cursor = list_authoring_reservations(
            db, actor="operator@example.test", state="all", limit=100,
        )
        assert cursor is None
        assert [row.id for row in rows] == [other_id]
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        rows, _ = list_authoring_reservations(
            db, actor="operator@example.test", state="all", limit=100,
        )
        assert [row.id for row in rows] == [own_id]
