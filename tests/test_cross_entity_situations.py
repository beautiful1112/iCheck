from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from icheck.database import SessionLocal
from icheck.models import Situation
from icheck.services.authorization_scope import situation_scope_clause
from icheck.services.control_plane_auth import PrincipalContext


def _device(client, name: str, address: str) -> dict:
    response = client.post(
        "/api/v1/devices",
        json={
            "name": name,
            "kind": "server",
            "management_ip": address,
            "site": "Correlation Lab",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _service(
    client,
    key: str,
    components: list[tuple[str, bool]],
) -> dict:
    response = client.post(
        "/api/v1/services",
        json={
            "service_key": key,
            "name": key.replace("-", " ").title(),
            "owner_team": "Correlation SRE",
            "criticality": "tier_1",
            "business_impact": "high",
            "components": [
                {
                    "node_type": "device",
                    "entity_id": device_id,
                    "role": "compute",
                    "required": required,
                    "evidence_note": "Reviewed test binding",
                }
                for device_id, required in components
            ],
            "created_by": "service.owner",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _alert(
    client,
    device: dict,
    *,
    suffix: str,
    observed_at: datetime,
) -> dict:
    response = client.post(
        "/api/v1/alerts/events",
        json={
            "event_type": f"device.health.{suffix}",
            "entity_type": "device",
            "entity_id": device["id"],
            "title": f"{device['name']} health {suffix}",
            "description": "Deterministic cross-entity acceptance evidence.",
            "severity": "warning",
            "dedup_key": f"{device['id']}:{suffix}",
            "observed_at": observed_at.isoformat(),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_reviewed_required_service_components_correlate_with_frozen_evidence(
    client,
):
    first = _device(client, "checkout-a", "192.0.2.211")
    second = _device(client, "checkout-b", "192.0.2.212")
    service = _service(
        client,
        "checkout-cluster",
        [(first["id"], True), (second["id"], True)],
    )
    observed = datetime.now(UTC)
    _alert(client, first, suffix="cpu", observed_at=observed)
    _alert(
        client,
        second,
        suffix="memory",
        observed_at=observed + timedelta(minutes=1),
    )

    situations = client.get("/api/v1/situations").json()
    assert len(situations) == 1
    situation = situations[0]
    assert situation["correlation_version"] == "reviewed_service/v2"
    assert situation["alert_count"] == 2
    assert situation["correlation_confidence"] == 0.85
    assert "across 2 reviewed service components" in situation["summary"]

    detail = client.get(f"/api/v1/situations/{situation['id']}").json()
    correlated = next(
        item
        for item in detail["alerts"]
        if item["correlation_reason"] == "shared_service_component"
    )
    assert correlated["correlation_confidence"] == 0.85
    assert correlated["correlation_evidence"] == {
        "contract": "icheck.situation-correlation-evidence/v1",
        "evidence_type": "reviewed_service_component",
        "service_id": service["id"],
        "service_revision": 1,
        "source_component_id": next(
            item["id"]
            for item in service["components"]
            if item["entity_id"] == second["id"]
        ),
        "target_component_id": next(
            item["id"]
            for item in service["components"]
            if item["entity_id"] == first["id"]
        ),
        "source_entity_type": "device",
        "source_entity_id": second["id"],
        "target_entity_type": "device",
        "target_entity_id": first["id"],
        "catalog_observed_at": service["updated_at"],
        "correlation_window_seconds": 900,
    }
    attached = next(
        event
        for event in detail["events"]
        if event["event_type"] == "alert.attached"
        and event["details"].get("reason") == "shared_service_component"
    )
    assert attached["details"]["confidence"] == 0.85
    assert attached["details"]["correlation_evidence_type"] == (
        "reviewed_service_component"
    )
    assert len(attached["details"]["correlation_evidence_sha256"]) == 64

    impact = client.get(f"/api/v1/situations/{situation['id']}/impact")
    assert impact.status_code == 200, impact.text
    impact = impact.json()
    assert {f"device:{first['id']}", f"device:{second['id']}"} <= {
        node["id"] for node in impact["nodes"]
    }
    correlation_edge = next(
        edge
        for edge in impact["edges"]
        if edge["evidence_type"] == "situation_alert_correlation"
    )
    assert correlation_edge["relationship_type"] == (
        "correlated_by_reviewed_service"
    )
    assert correlation_edge["source"] == f"device:{first['id']}"
    assert correlation_edge["target"] == f"device:{second['id']}"
    assert any(
        path["target_node_id"] == f"device:{second['id']}"
        and path["hop_count"] == 1
        for path in impact["paths"]
    )

    def scoped(device_ids: list[str]) -> PrincipalContext:
        return PrincipalContext(
            principal_id="scope-test",
            subject="scope-test",
            principal_type="service",
            permissions=frozenset({"alerts.read"}),
            role_names=("viewer",),
            authorization_scope={"device_ids": device_ids},
            auth_method="test",
        )

    with SessionLocal() as db:
        partially_visible = db.scalar(
            select(Situation).where(situation_scope_clause(scoped([first["id"]])))
        )
        fully_visible = db.scalar(
            select(Situation).where(
                situation_scope_clause(scoped([first["id"], second["id"]]))
            )
        )
        assert partially_visible is None
        assert fully_visible is not None and fully_visible.id == situation["id"]

    # A later distinct Alert on an already represented entity must remain in
    # the same Situation even though its own membership needs no indirect proof.
    _alert(
        client,
        second,
        suffix="disk",
        observed_at=observed + timedelta(minutes=2),
    )
    detail = client.get(f"/api/v1/situations/{situation['id']}").json()
    assert detail["situation"]["alert_count"] == 3
    disk = next(item for item in detail["alerts"] if item["event_type"].endswith("disk"))
    assert disk["correlation_reason"] == "same_entity"
    assert disk["correlation_confidence"] == 1.0
    assert disk["correlation_evidence"] == {}
    assert detail["situation"]["correlation_confidence"] == 0.85


def test_ambiguous_service_candidates_fail_closed_into_a_new_situation(client):
    first = _device(client, "service-a", "192.0.2.221")
    bridge = _device(client, "service-bridge", "192.0.2.222")
    third = _device(client, "service-c", "192.0.2.223")
    _service(
        client,
        "service-a-bridge",
        [(first["id"], True), (bridge["id"], True)],
    )
    _service(
        client,
        "service-c-bridge",
        [(third["id"], True), (bridge["id"], True)],
    )
    observed = datetime.now(UTC)
    _alert(client, first, suffix="first", observed_at=observed)
    _alert(client, third, suffix="third", observed_at=observed)
    _alert(client, bridge, suffix="bridge", observed_at=observed)

    situations = client.get("/api/v1/situations").json()
    assert len(situations) == 3
    assert {item["correlation_version"] for item in situations} == {
        "same_entity/v1"
    }
    assert {item["correlation_confidence"] for item in situations} == {1.0}


def test_stale_or_non_required_service_bindings_do_not_cross_correlate(client):
    old_side = _device(client, "stale-a", "192.0.2.231")
    fresh_side = _device(client, "stale-b", "192.0.2.232")
    _service(
        client,
        "stale-service",
        [(old_side["id"], True), (fresh_side["id"], True)],
    )
    now = datetime.now(UTC)
    _alert(
        client,
        old_side,
        suffix="old",
        observed_at=now - timedelta(minutes=16),
    )
    _alert(client, fresh_side, suffix="fresh", observed_at=now)
    assert len(client.get("/api/v1/situations").json()) == 2

    optional = _device(client, "optional-c", "192.0.2.233")
    required = _device(client, "required-d", "192.0.2.234")
    _service(
        client,
        "optional-service",
        [(optional["id"], False), (required["id"], True)],
    )
    _alert(client, optional, suffix="optional", observed_at=now)
    _alert(client, required, suffix="required", observed_at=now)
    assert len(client.get("/api/v1/situations").json()) == 4
