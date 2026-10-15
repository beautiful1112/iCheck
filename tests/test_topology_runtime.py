from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from icheck.collector_schemas import ArtifactCreate
from icheck.config import get_settings
from icheck.database import SessionLocal
from icheck.models import ArtifactVersion, KnowledgeEntity, KnowledgeRelationship
from icheck.services.collectors import (
    create_artifact,
    publish_artifact_version,
    validate_artifact_version,
)
from icheck.services.topology_views import topology_artifact_documents
from icheck.studio_schemas import GeneratedTopologySpec


BOOTSTRAP_HEADERS = {
    "X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token"
}


def _device(client, *, name: str, site: str, address: str) -> dict:
    response = client.post(
        "/api/v1/devices",
        json={
            "name": name,
            "kind": "switch",
            "management_ip": address,
            "site": site,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _observe_endpoint(client, device: dict, *, mac: str, address: str) -> None:
    response = client.post(
        "/api/v1/inventory/network-observations",
        json={
            "observations": [
                {
                    "mac_address": mac,
                    "ip_address": address,
                    "source": "arp",
                    "collector_device_id": device["id"],
                    "interface_name": "Ethernet1/1",
                    "observed_at": datetime.now(UTC).isoformat(),
                }
            ]
        },
    )
    assert response.status_code == 200, response.text


def _knowledge_pair(db, *, site: str, prefix: str) -> None:
    now = datetime.now(UTC)
    left = KnowledgeEntity(
        namespace="runtime-test",
        scope_key=f"site:{site}",
        scope_site=site,
        entity_type="network.device",
        external_key=f"{prefix}-left",
        display_name=f"{prefix}-left",
        active=True,
        attributes={"raw_payload": "must-not-render"},
        first_seen=now,
        last_seen=now,
        observed_at=now,
    )
    right = KnowledgeEntity(
        namespace="runtime-test",
        scope_key=f"site:{site}",
        scope_site=site,
        entity_type="network.device",
        external_key=f"{prefix}-right",
        display_name=f"{prefix}-right",
        active=True,
        attributes={"private": "must-not-render"},
        first_seen=now,
        last_seen=now,
        observed_at=now,
    )
    db.add_all([left, right])
    db.flush()
    db.add(
        KnowledgeRelationship(
            namespace="runtime-test",
            scope_key=f"site:{site}",
            scope_site=site,
            relationship_type="network.link",
            source_entity_id=left.id,
            target_entity_id=right.id,
            directed=False,
            active=True,
            attributes={"vendor_blob": "must-not-render"},
            first_seen=now,
            last_seen=now,
            observed_at=now,
        )
    )


def _publish_topology(*, name: str = "operator-runtime-topology") -> str:
    spec = GeneratedTopologySpec(
        artifact_name=name,
        description="Live operator view of current scoped infrastructure.",
        node_types=["device", "endpoint", "knowledge_entity"],
        edge_types=["wired_attachment", "knowledge_relationship"],
        knowledge_entity_types=["network.device"],
        knowledge_relationship_types=["network.link"],
        enabled_devices_only=True,
        active_entities_only=True,
        active_edges_only=True,
        layout="force",
        group_by="site",
        max_nodes=100,
        max_edges=100,
    )
    definition, implementation, tests = topology_artifact_documents(spec)
    with SessionLocal() as db:
        artifact = create_artifact(
            db,
            ArtifactCreate.model_validate(
                {
                    "name": name,
                    "kind": "topology",
                    "description": spec.description,
                    "owner": "topology.author",
                    "initial_version": {
                        "definition": definition,
                        "implementation": implementation,
                        "tests": tests,
                        "created_by": "topology.author",
                    },
                }
            ),
        )
        version = validate_artifact_version(
            db,
            artifact.versions[0],
            "topology.validator",
        )
        publish_artifact_version(db, version, "topology.publisher")
        return artifact.id


def _operator_headers(client, *, site: str, subject: str, admin_headers: dict) -> dict:
    roles = client.get("/api/v1/auth/roles", headers=admin_headers).json()
    operator_role = next(item for item in roles if item["name"] == "operator")
    principal = client.post(
        "/api/v1/auth/principals",
        headers=admin_headers,
        json={"subject": subject, "display_name": subject},
    ).json()
    binding = client.post(
        f"/api/v1/auth/principals/{principal['id']}/bindings",
        headers=admin_headers,
        json={"role_id": operator_role["id"], "scope": {"sites": [site]}},
    )
    assert binding.status_code == 201, binding.text
    token = client.post(
        f"/api/v1/auth/principals/{principal['id']}/tokens",
        headers=admin_headers,
        json={"name": "topology-runtime", "expires_in_hours": 24},
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_published_topology_runtime_is_live_bounded_and_object_scoped(
    client,
    monkeypatch,
):
    hk = _device(client, name="hk-runtime-switch", site="Hong Kong", address="10.1.0.1")
    ny = _device(client, name="ny-runtime-switch", site="New York", address="10.2.0.1")
    _observe_endpoint(client, hk, mac="02:00:00:00:01:01", address="10.1.1.10")
    _observe_endpoint(client, ny, mac="02:00:00:00:02:02", address="10.2.1.10")
    with SessionLocal() as db:
        _knowledge_pair(db, site="Hong Kong", prefix="hk-graph")
        _knowledge_pair(db, site="New York", prefix="ny-graph")
        db.commit()
    artifact_id = _publish_topology()
    hk_alert = client.post(
        "/api/v1/alerts/events",
        json={
            "event_type": "device.reachability.degraded",
            "entity_type": "device",
            "entity_id": hk["id"],
            "title": "Hong Kong switch reachability degraded",
            "severity": "critical",
        },
    )
    assert hk_alert.status_code == 201, hk_alert.text
    ny_alert = client.post(
        "/api/v1/alerts/events",
        json={
            "event_type": "device.reachability.degraded",
            "entity_type": "device",
            "entity_id": ny["id"],
            "title": "New York switch reachability degraded",
            "severity": "critical",
        },
    )
    assert ny_alert.status_code == 201, ny_alert.text
    situations = client.get("/api/v1/situations").json()
    hk_situation = next(
        item for item in situations if item["primary_entity_id"] == hk["id"]
    )
    ny_situation = next(
        item for item in situations if item["primary_entity_id"] == ny["id"]
    )

    views = client.get("/api/v1/topology/views")
    assert views.status_code == 200, views.text
    assert [item["artifact_id"] for item in views.json()] == [artifact_id]
    assert views.json()[0]["version"] == 1
    assert "definition" not in views.text

    global_render = client.get(f"/api/v1/topology/views/{artifact_id}/render")
    assert global_render.status_code == 200, global_render.text
    global_document = global_render.json()
    assert global_document["scope_applied"] is False
    assert global_document["node_count"] == 8
    assert global_document["edge_count"] == 4
    assert global_document["limits"] == {"nodes": 100, "edges": 100}
    assert "must-not-render" not in global_render.text
    assert "vendor_blob" not in global_render.text

    focused = client.get(
        f"/api/v1/topology/views/{artifact_id}/render",
        params={"situation_id": hk_situation["id"]},
    )
    assert focused.status_code == 200, focused.text
    focused_document = focused.json()
    assert focused_document["context"]["situation_id"] == hk_situation["id"]
    assert focused_document["context"]["root_node_id"] == f"device:{hk['id']}"
    assert focused_document["context"]["hypothesis_boundary"] == (
        "deterministic_context_not_root_cause"
    )
    assert focused_document["node_count"] == 2
    assert focused_document["edge_count"] == 1
    assert {item["entity_id"] for item in focused_document["nodes"]} == {
        hk["id"],
        next(
            item["entity_id"]
            for item in focused_document["nodes"]
            if item["node_type"] == "endpoint"
        ),
    }
    assert "ny-runtime-switch" not in focused.text

    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    try:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            headers=BOOTSTRAP_HEADERS,
            json={"subject": "admin@example.test", "display_name": "Admin"},
        )
        assert bootstrap.status_code == 201, bootstrap.text
        admin_headers = {
            "Authorization": f"Bearer {bootstrap.json()['token']['access_token']}"
        }
        hk_headers = _operator_headers(
            client,
            site="Hong Kong",
            subject="hk.operator@example.test",
            admin_headers=admin_headers,
        )
        empty_headers = _operator_headers(
            client,
            site="Tokyo",
            subject="tokyo.operator@example.test",
            admin_headers=admin_headers,
        )

        scoped = client.get(
            f"/api/v1/topology/views/{artifact_id}/render",
            headers=hk_headers,
        )
        assert scoped.status_code == 200, scoped.text
        document = scoped.json()
        assert document["scope_applied"] is True
        assert document["node_count"] == 4
        assert document["edge_count"] == 2
        assert {node["site"] for node in document["nodes"] if node["site"]} == {
            "Hong Kong"
        }
        assert "hk-runtime-switch" in scoped.text
        assert "hk-graph-left" in scoped.text
        assert "ny-runtime-switch" not in scoped.text
        assert "ny-graph-left" not in scoped.text
        assert "10.2.1.10" not in scoped.text

        empty = client.get(
            f"/api/v1/topology/views/{artifact_id}/render",
            headers=empty_headers,
        )
        assert empty.status_code == 200, empty.text
        assert empty.json()["node_count"] == 0
        assert empty.json()["edge_count"] == 0

        denied_context = client.get(
            f"/api/v1/topology/views/{artifact_id}/render",
            params={"situation_id": ny_situation["id"]},
            headers=hk_headers,
        )
        assert denied_context.status_code == 404

        missing_version = client.get(
            f"/api/v1/topology/views/{artifact_id}/render",
            params={"version": 999},
            headers=hk_headers,
        )
        assert missing_version.status_code == 404
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()


def test_topology_runtime_excludes_drafts_and_rejects_published_contract_drift(
    client,
):
    device = _device(client, name="runtime-seed", site="HQ", address="10.10.0.1")
    _observe_endpoint(client, device, mac="02:00:00:00:10:10", address="10.10.1.10")
    artifact_id = _publish_topology(name="drift-test-topology")

    spec = GeneratedTopologySpec(
        artifact_name="draft-only-topology",
        description="This view has not been published.",
        node_types=["device"],
        edge_types=[],
        max_nodes=10,
        max_edges=10,
    )
    definition, implementation, tests = topology_artifact_documents(spec)
    with SessionLocal() as db:
        create_artifact(
            db,
            ArtifactCreate.model_validate(
                {
                    "name": spec.artifact_name,
                    "kind": "topology",
                    "description": spec.description,
                    "owner": "topology.author",
                    "initial_version": {
                        "definition": definition,
                        "implementation": implementation,
                        "tests": tests,
                        "created_by": "topology.author",
                    },
                }
            ),
        )
    assert [item["artifact_id"] for item in client.get("/api/v1/topology/views").json()] == [
        artifact_id
    ]

    with SessionLocal() as db:
        version = db.scalar(
            select(ArtifactVersion).where(
                ArtifactVersion.artifact_id == artifact_id
            )
        )
        assert version is not None
        version.implementation = {"runtime": "drifted"}
        db.commit()

    response = client.get(f"/api/v1/topology/views/{artifact_id}/render")
    assert response.status_code == 409
    assert response.json()["detail"] == "Published topology contract is invalid"
