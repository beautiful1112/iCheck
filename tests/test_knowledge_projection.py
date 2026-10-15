from datetime import timedelta

import pytest
from sqlalchemy import func, select

from icheck.config import get_settings
from icheck.database import SessionLocal
from icheck.models import (
    Alert,
    CollectionEnvelope,
    CollectorDeployment,
    Endpoint,
    IPAddressObservation,
    KnowledgeEntity,
    KnowledgeProjection,
    KnowledgeProjectionStatus,
    KnowledgeRelationship,
    WirelessClientSession,
    utcnow,
)
from icheck.projection_schemas import (
    ALERT_EVENT_V1,
    DEVICE_ADJACENCY_SNAPSHOT_V1,
    KNOWLEDGE_ENTITY_V1,
    KNOWLEDGE_RELATIONSHIP_V1,
    NETWORK_OBSERVATION_V1,
    WIRELESS_SNAPSHOT_V1,
    KnowledgeEntityProjection,
)
from icheck.services.knowledge_projection import (
    claim_projections,
    process_projection_assignment,
    register_projection_worker,
)
from icheck.services.topology_views import (
    topology_inventory_catalog,
    topology_preview,
)
from icheck.studio_schemas import GeneratedTopologySpec


REGISTRATION_HEADERS = {
    "X-iCheck-Registration-Token": "test-registration-token"
}
BOOTSTRAP_HEADERS = {
    "X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token"
}


def _publish_collector(client, *, name: str, output_kind: str):
    created = client.post(
        "/api/v1/artifacts",
        json={
            "name": name,
            "kind": "collector",
            "description": "Projection contract test collector",
            "owner": "platform-team",
            "labels": {"domain": "knowledge"},
            "initial_version": {
                "definition": {"purpose": "Exercise normalized projection"},
                "implementation": {"runtime": "builtin", "adapter": "http_json"},
                "tests": [{"name": "contract", "fixture": {"items": []}}],
                "created_by": "capability.author",
                "collector_definition": {
                    "adapter_type": "http_json",
                    "mode": "poll",
                    "output_kinds": [output_kind],
                    "target_schema": {
                        "type": "object",
                        "required": ["url"],
                    },
                    "config_schema": {"type": "object"},
                    "defaults": {},
                },
            },
        },
    )
    assert created.status_code == 201, created.text
    version = created.json()["versions"][0]
    validated = client.post(
        f"/api/v1/artifact-versions/{version['id']}/validate",
        json={"actor": "capability.reviewer"},
    )
    assert validated.status_code == 200, validated.text
    published = client.post(
        f"/api/v1/artifact-versions/{version['id']}/publish",
        json={"actor": "capability.publisher"},
    )
    assert published.status_code == 200, published.text
    return published.json()


def _start_scoped_run(
    client,
    *,
    name: str,
    device_kind: str = "switch",
    output_kind: str = "observation",
    site: str = "HQ",
):
    device = client.post(
        "/api/v1/devices",
        json={
            "name": f"{name}-device",
            "kind": device_kind,
            "management_ip": None,
            "site": site,
            "created_by": "test",
        },
    )
    assert device.status_code == 201, device.text
    device_json = device.json()
    version = _publish_collector(
        client,
        name=f"{name}-artifact",
        output_kind=output_kind,
    )
    deployment = client.post(
        "/api/v1/collector-deployments",
        json={
            "name": f"{name}-deployment",
            "artifact_version_id": version["id"],
            "scope_device_id": device_json["id"],
            "scope_device_identity_revision": device_json["identity_revision"],
            "scope_site": site,
            "target": {"url": "https://inventory.example.test/data"},
            "configuration": {},
            "worker_selector": {"site": site},
            "schedule_seconds": 300,
            "created_by": "platform.operator",
        },
    )
    assert deployment.status_code == 201, deployment.text
    registration = client.post(
        "/api/v1/collector-workers/register",
        json={
            "name": f"{name}-collector-worker",
            "site": site,
            "capabilities": ["http_json"],
            "labels": {"io_supervisor_v1": True},
        },
        headers=REGISTRATION_HEADERS,
    )
    assert registration.status_code == 200, registration.text
    worker = registration.json()["worker"]
    headers = {
        "Authorization": f"Bearer {registration.json()['access_token']}"
    }
    claimed = client.post(
        f"/api/v1/collector-workers/{worker['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 120},
        headers=headers,
    )
    assert claimed.status_code == 200, claimed.text
    assert len(claimed.json()) == 1
    assignment = claimed.json()[0]
    admitted = client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/admit",
        json={
            "lease_token": assignment["lease_token"],
            "assignment_sha256": assignment["assignment_sha256"],
        },
        headers=headers,
    )
    assert admitted.status_code == 200, admitted.text
    return device_json, assignment, headers


def _post_envelope(client, assignment, headers, envelope):
    return client.post(
        f"/api/v1/collector-runs/{assignment['run_id']}/envelopes",
        json={
            "lease_token": assignment["lease_token"],
            "envelopes": [envelope],
        },
        headers=headers,
    )


def _project_one(*, worker_name: str = "projection-worker-01"):
    with SessionLocal() as db:
        worker = register_projection_worker(db, name=worker_name)
        assignments = claim_projections(
            db,
            worker,
            limit=1,
            lease_seconds=120,
        )
        assert len(assignments) == 1
        result = process_projection_assignment(db, worker, assignments[0])
        return result.id, result.status


def test_network_envelope_projects_once_into_endpoint_ip_and_attachment(client):
    device, assignment, headers = _start_scoped_run(
        client,
        name="network",
    )
    envelope = {
        "kind": "observation",
        "type": NETWORK_OBSERVATION_V1,
        "source": "switch-arp",
        "subject": "AA-BB-CC-DD-EE-01",
        "observed_at": "2026-09-25T03:10:00Z",
        "idempotency_key": "arp:aa-bb-cc-dd-ee-01:1",
        "payload": {
            "mac_address": "AA-BB-CC-DD-EE-01",
            "ip_address": "10.20.30.41",
            "source": "arp",
            "interface_name": "GigabitEthernet1/0/1",
            "vlan_id": 30,
            "hostname": "lab-client-01",
            "raw_data": {"age_seconds": 2},
        },
    }
    accepted = _post_envelope(client, assignment, headers, envelope)
    duplicate = _post_envelope(client, assignment, headers, envelope)
    assert accepted.json() == {"received": 1, "accepted": 1, "duplicates": 0}
    assert duplicate.json() == {"received": 1, "accepted": 0, "duplicates": 1}

    projection_id, status = _project_one()
    assert status == KnowledgeProjectionStatus.SUCCEEDED

    with SessionLocal() as db:
        endpoint = db.scalar(select(Endpoint))
        assert endpoint is not None
        assert endpoint.mac_address == "aa:bb:cc:dd:ee:01"
        ip = db.scalar(select(IPAddressObservation))
        assert ip is not None
        assert ip.ip_address == "10.20.30.41"
        assert ip.collector_device_id == device["id"]
        assert db.scalar(select(func.count()).select_from(KnowledgeProjection)) == 1

    health = client.get("/api/v1/knowledge-projections/health")
    assert health.status_code == 200, health.text
    assert health.json()["succeeded"] == 1
    assert health.json()["pending"] == 0
    listed = client.get("/api/v1/knowledge-projections").json()
    assert listed[0]["id"] == projection_id
    assert listed[0]["result_summary"]["contract"] == NETWORK_OBSERVATION_V1
    assert "payload" not in listed[0]


def test_wireless_snapshot_projects_terminal_session_and_rule_alert(client):
    controller, assignment, headers = _start_scoped_run(
        client,
        name="wireless",
        device_kind="wireless_controller",
    )
    response = _post_envelope(
        client,
        assignment,
        headers,
        {
            "kind": "observation",
            "type": WIRELESS_SNAPSHOT_V1,
            "source": "wlc-api",
            "observed_at": "2026-09-25T03:15:00Z",
            "idempotency_key": "wlc:snapshot:1",
            "payload": {
                "complete_snapshot": True,
                "clients": [
                    {
                        "mac_address": "aa:bb:cc:dd:ee:02",
                        "ip_address": "10.20.30.42",
                        "hostname": "wifi-client-02",
                        "access_point": "ap-hq-01",
                        "ssid": "corp",
                        "rssi": -82,
                        "snr": 18,
                        "vlan_id": 30,
                    }
                ],
            },
        },
    )
    assert response.status_code == 200, response.text
    _, status = _project_one()
    assert status == KnowledgeProjectionStatus.SUCCEEDED
    with SessionLocal() as db:
        session = db.scalar(select(WirelessClientSession))
        assert session is not None
        assert session.controller_id == controller["id"]
        assert session.active is True
        alert = db.scalar(select(Alert).where(Alert.event_type == "wireless.rssi.low"))
        assert alert is not None
        assert alert.details["rssi"] == -82


def test_alert_envelope_projects_with_subject_and_deduplication(client):
    device, assignment, headers = _start_scoped_run(
        client,
        name="event",
        output_kind="event",
    )
    response = _post_envelope(
        client,
        assignment,
        headers,
        {
            "kind": "event",
            "type": ALERT_EVENT_V1,
            "source": "firewall-api",
            "subject": device["id"],
            "observed_at": "2026-09-25T03:20:00Z",
            "idempotency_key": "firewall:ha:down:1",
            "payload": {
                "event_type": "firewall.ha.peer_down",
                "entity_type": "device",
                "title": "Firewall peer is unavailable",
                "severity": "critical",
                "details": {"peer": "secondary"},
            },
        },
    )
    assert response.status_code == 200, response.text
    _, status = _project_one()
    assert status == KnowledgeProjectionStatus.SUCCEEDED
    with SessionLocal() as db:
        alert = db.scalar(
            select(Alert).where(Alert.event_type == "firewall.ha.peer_down")
        )
        assert alert is not None
        assert alert.entity_id == device["id"]
        assert alert.severity.value == "critical"


def test_generic_entity_projection_is_idempotent_and_does_not_regress(client):
    device, assignment, headers = _start_scoped_run(
        client,
        name="generic-entity",
        output_kind="entity",
    )
    newer = _post_envelope(
        client,
        assignment,
        headers,
        {
            "kind": "entity",
            "type": KNOWLEDGE_ENTITY_V1,
            "source": "custom-switch-api",
            "observed_at": "2026-09-25T04:30:00Z",
            "idempotency_key": "interface:ethernet1:2",
            "payload": {
                "entity_type": "network.interface",
                "external_key": "Ethernet1",
                "display_name": "Ethernet 1",
                "status": "up",
                "attributes": {"speed_bps": 10000000000, "mtu": 1500},
            },
        },
    )
    older = _post_envelope(
        client,
        assignment,
        headers,
        {
            "kind": "entity",
            "type": KNOWLEDGE_ENTITY_V1,
            "source": "custom-switch-api",
            "observed_at": "2026-09-25T04:20:00Z",
            "idempotency_key": "interface:ethernet1:1",
            "payload": {
                "entity_type": "network.interface",
                "external_key": "Ethernet1",
                "display_name": "stale-name",
                "status": "down",
                "active": False,
                "attributes": {"speed_bps": 1000000000},
            },
        },
    )
    assert newer.status_code == 200, newer.text
    assert older.status_code == 200, older.text
    assert _project_one(worker_name="entity-projector-1")[1] == (
        KnowledgeProjectionStatus.SUCCEEDED
    )
    assert _project_one(worker_name="entity-projector-2")[1] == (
        KnowledgeProjectionStatus.SUCCEEDED
    )

    with SessionLocal() as db:
        entities = list(db.scalars(select(KnowledgeEntity)).all())
        assert len(entities) == 1
        entity = entities[0]
        assert entity.scope_device_id == device["id"]
        assert entity.scope_key == f"device:{device['id']}"
        assert entity.namespace.startswith("artifact:")
        assert entity.status == "up"
        assert entity.active is True
        assert entity.display_name == "Ethernet 1"
        assert entity.attributes == {"speed_bps": 10000000000, "mtu": 1500}
        assert entity.first_seen.isoformat().startswith("2026-09-25T04:20:00")
        assert entity.last_seen.isoformat().startswith("2026-09-25T04:30:00")

    listed = client.get(
        "/api/v1/knowledge/entities",
        params={"entity_type": "network.interface", "active": True},
    )
    assert listed.status_code == 200, listed.text
    assert [item["external_key"] for item in listed.json()] == ["Ethernet1"]


def test_generic_entity_attributes_are_bounded_and_reject_raw_payload_keys():
    with pytest.raises(ValueError, match="64 keys"):
        KnowledgeEntityProjection.model_validate(
            {
                "entity_type": "application",
                "external_key": "billing",
                "attributes": {f"key-{index}": index for index in range(65)},
            }
        )
    with pytest.raises(ValueError, match="cannot exceed depth"):
        KnowledgeEntityProjection.model_validate(
            {
                "entity_type": "application",
                "external_key": "billing",
                "attributes": {
                    "nested": {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}
                },
            }
        )
    with pytest.raises(ValueError, match="reserved for raw source data"):
        KnowledgeEntityProjection.model_validate(
            {
                "entity_type": "application",
                "external_key": "billing",
                "attributes": {
                    "nested": {"raw_payload": {"opaque": "vendor-data"}}
                },
            }
        )


def test_generic_undirected_relationship_canonicalizes_reversed_endpoints(client):
    _, assignment, headers = _start_scoped_run(
        client,
        name="generic-relationship",
        output_kind="relationship",
    )
    for index, (source, target, cost) in enumerate(
        (("switch-a", "switch-b", 10), ("switch-b", "switch-a", 20)),
        start=1,
    ):
        accepted = _post_envelope(
            client,
            assignment,
            headers,
            {
                "kind": "relationship",
                "type": KNOWLEDGE_RELATIONSHIP_V1,
                "source": "lldp-api",
                "observed_at": f"2026-09-25T04:{30 + index}:00Z",
                "idempotency_key": f"link:a-b:{index}",
                "payload": {
                    "relationship_type": "network.link",
                    "source": {
                        "entity_type": "network.device",
                        "external_key": source,
                        "display_name": source,
                    },
                    "target": {
                        "entity_type": "network.device",
                        "external_key": target,
                        "display_name": target,
                    },
                    "directed": False,
                    "attributes": {"cost": cost},
                },
            },
        )
        assert accepted.status_code == 200, accepted.text
        assert _project_one(worker_name=f"relationship-projector-{index}")[1] == (
            KnowledgeProjectionStatus.SUCCEEDED
        )

    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(KnowledgeEntity)) == 2
        relationships = list(db.scalars(select(KnowledgeRelationship)).all())
        assert len(relationships) == 1
        assert relationships[0].directed is False
        assert relationships[0].attributes == {"cost": 20}
        catalog = topology_inventory_catalog(db)
        assert catalog["knowledge_entity_types"] == ["network.device"]
        assert catalog["knowledge_relationship_types"] == ["network.link"]
        preview = topology_preview(
            db,
            GeneratedTopologySpec(
                artifact_name="generic-link-map",
                description="Render normalized custom collector links.",
                node_types=["knowledge_entity"],
                edge_types=["knowledge_relationship"],
                knowledge_entity_types=["network.device"],
                knowledge_relationship_types=["network.link"],
                sites=["HQ"],
                max_nodes=10,
                max_edges=10,
            ),
        )
        assert preview["node_count"] == 2
        assert preview["edge_count"] == 1
        assert {node["node_type"] for node in preview["nodes"]} == {
            "knowledge_entity"
        }
        assert preview["edges"][0]["relationship_type"] == "network.link"
        assert "cost" not in str(preview)

    listed = client.get(
        "/api/v1/knowledge/relationships",
        params={"relationship_type": "network.link"},
    )
    assert listed.status_code == 200, listed.text
    assert len(listed.json()) == 1
    assert listed.json()[0]["attributes"] == {"cost": 20}


def test_adjacency_snapshot_closes_missing_links_and_rejects_stale_reactivation(
    client,
):
    _, assignment, headers = _start_scoped_run(
        client,
        name="adjacency-snapshot",
        output_kind="relationship",
    )

    def submit(observed_at, neighbors, key):
        accepted = _post_envelope(
            client,
            assignment,
            headers,
            {
                "kind": "relationship",
                "type": DEVICE_ADJACENCY_SNAPSHOT_V1,
                "source": "lldp-exporter",
                "subject": "core-01",
                "observed_at": observed_at,
                "idempotency_key": key,
                "payload": {
                    "local_device_key": "core-01",
                    "local_display_name": "Core 01",
                    "protocol": "lldp",
                    "complete_snapshot": True,
                    "neighbors": neighbors,
                },
            },
        )
        assert accepted.status_code == 200, accepted.text
        assert _project_one(worker_name=f"projector-{key}")[1] == (
            KnowledgeProjectionStatus.SUCCEEDED
        )

    access_01 = {
        "remote_device_key": "chassis-01",
        "remote_system_name": "Access 01",
        "local_port": "Gi0/1",
        "remote_port": "Gi0/48",
        "management_ip": "10.0.0.21",
    }
    access_02 = {
        "remote_device_key": "chassis-02",
        "remote_system_name": "Access 02",
        "local_port": "Gi0/2",
        "remote_port": "Gi0/48",
        "management_ip": "10.0.0.22",
    }
    submit("2026-09-25T05:00:00Z", [access_01, access_02], "adjacency-1")
    submit("2026-09-25T06:00:00Z", [access_01], "adjacency-2")
    submit("2026-09-25T04:00:00Z", [access_02], "adjacency-stale")

    with SessionLocal() as db:
        entities = list(
            db.scalars(
                select(KnowledgeEntity).order_by(KnowledgeEntity.external_key)
            ).all()
        )
        relationships = list(
            db.scalars(
                select(KnowledgeRelationship).order_by(
                    KnowledgeRelationship.target_entity_id
                )
            ).all()
        )
        assert len(entities) == 3
        entity_by_key = {item.external_key: item for item in entities}
        assert entity_by_key["core-01"].active is True
        assert entity_by_key["chassis-01"].active is True
        assert entity_by_key["chassis-02"].active is False
        assert entity_by_key["chassis-02"].status == "absent"
        assert len(relationships) == 2
        active_targets = {
            next(
                entity.external_key
                for entity in entities
                if entity.id in {
                    relationship.source_entity_id,
                    relationship.target_entity_id,
                }
                and entity.external_key != "core-01"
            )
            for relationship in relationships
            if relationship.active
        }
        assert active_targets == {"chassis-01"}
        assert {
            relationship.relationship_type for relationship in relationships
        } == {"network.l2_neighbor.lldp"}
        active = next(item for item in relationships if item.active)
        assert active.attributes == {
            "protocol": "lldp",
            "links": [{"local_port": "Gi0/1", "remote_port": "Gi0/48"}],
        }
        catalog = topology_inventory_catalog(db)
        assert "network.l2_neighbor.lldp" in catalog[
            "knowledge_relationship_types"
        ]


def test_generic_projection_requires_an_explicit_deployment_scope(client):
    _, assignment, headers = _start_scoped_run(
        client,
        name="generic-unscoped",
        output_kind="entity",
    )
    with SessionLocal() as db:
        deployment = db.get(CollectorDeployment, assignment["deployment_id"])
        assert deployment is not None
        deployment.scope_device_id = None
        deployment.scope_device_identity_revision = None
        deployment.scope_site = None
        db.commit()
    accepted = _post_envelope(
        client,
        assignment,
        headers,
        {
            "kind": "entity",
            "type": KNOWLEDGE_ENTITY_V1,
            "source": "unsafe-global-api",
            "idempotency_key": "unscoped:1",
            "payload": {
                "entity_type": "application",
                "external_key": "payments",
            },
        },
    )
    assert accepted.status_code == 200, accepted.text
    projection_id, status = _project_one(worker_name="unscoped-projector")
    assert status == KnowledgeProjectionStatus.DEAD_LETTER
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(KnowledgeEntity)) == 0
        projection = db.get(KnowledgeProjection, projection_id)
        assert projection is not None
        assert projection.error_type == "ProjectionPermanentError"


def test_projection_scope_violation_dead_letters_without_domain_write(client):
    _, assignment, headers = _start_scoped_run(client, name="scope")
    other = client.post(
        "/api/v1/devices",
        json={
            "name": "other-switch",
            "kind": "switch",
            "site": "OTHER",
            "created_by": "test",
        },
    ).json()
    response = _post_envelope(
        client,
        assignment,
        headers,
        {
            "kind": "observation",
            "type": NETWORK_OBSERVATION_V1,
            "source": "switch-arp",
            "idempotency_key": "scope-violation:1",
            "payload": {
                "mac_address": "aa:bb:cc:dd:ee:03",
                "source": "arp",
                "collector_device_id": other["id"],
            },
        },
    )
    assert response.status_code == 200, response.text
    projection_id, status = _project_one()
    assert status == KnowledgeProjectionStatus.DEAD_LETTER
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Endpoint)) == 0
        projection = db.get(KnowledgeProjection, projection_id)
        assert projection is not None
        assert projection.error_type == "ProjectionPermanentError"
        assert len(projection.error_sha256 or "") == 64
        assert projection.result_summary == {}

    retried = client.post(
        f"/api/v1/knowledge-projections/{projection_id}/retry",
        json={"actor": "operator", "reason": "Re-evaluate after scope review"},
    )
    assert retried.status_code == 200, retried.text
    assert retried.json()["status"] == "pending"
    assert retried.json()["attempt_count"] == 0


def test_envelope_contract_rejects_secrets_and_undeclared_kinds(client):
    _, assignment, headers = _start_scoped_run(client, name="contract")
    secret = _post_envelope(
        client,
        assignment,
        headers,
        {
            "kind": "observation",
            "type": NETWORK_OBSERVATION_V1,
            "source": "unsafe",
            "idempotency_key": "unsafe:1",
            "payload": {
                "mac_address": "aa:bb:cc:dd:ee:04",
                "source": "arp",
                "password": "plaintext",
            },
        },
    )
    wrong_kind = _post_envelope(
        client,
        assignment,
        headers,
        {
            "kind": "event",
            "type": ALERT_EVENT_V1,
            "source": "unsafe",
            "idempotency_key": "unsafe:2",
            "payload": {
                "event_type": "test",
                "entity_type": "device",
                "entity_id": "unknown",
                "title": "Wrong contract kind",
            },
        },
    )
    assert secret.status_code == 409
    assert "secret reference" in secret.text
    assert wrong_kind.status_code == 409
    assert "not declared" in wrong_kind.text
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(CollectionEnvelope)) == 0
        assert db.scalar(select(func.count()).select_from(KnowledgeProjection)) == 0


def test_expired_projection_lease_is_reassigned_without_old_worker_replay(client):
    _, assignment, headers = _start_scoped_run(client, name="reassign")
    response = _post_envelope(
        client,
        assignment,
        headers,
        {
            "kind": "observation",
            "type": NETWORK_OBSERVATION_V1,
            "source": "switch-arp",
            "idempotency_key": "reassign:1",
            "payload": {
                "mac_address": "aa:bb:cc:dd:ee:05",
                "source": "arp",
            },
        },
    )
    assert response.status_code == 200, response.text

    with SessionLocal() as db:
        first = register_projection_worker(db, name="projection-worker-a")
        old_assignment = claim_projections(
            db,
            first,
            limit=1,
            lease_seconds=15,
        )[0]
        projection = db.get(KnowledgeProjection, old_assignment.projection_id)
        assert projection is not None
        projection.lease_expires_at = utcnow() - timedelta(seconds=1)
        db.commit()

        second = register_projection_worker(db, name="projection-worker-b")
        replacement = claim_projections(
            db,
            second,
            limit=1,
            lease_seconds=120,
        )
        assert len(replacement) == 1
        assert replacement[0].projection_id == old_assignment.projection_id
        with pytest.raises(ValueError, match="another worker"):
            process_projection_assignment(db, first, old_assignment)
        result = process_projection_assignment(db, second, replacement[0])
        assert result.status == KnowledgeProjectionStatus.SUCCEEDED
        assert result.attempt_count == 2


def test_projection_operations_are_filtered_by_deployment_site_scope(
    client,
    monkeypatch,
):
    for name, site in (("scoped-hq", "HQ"), ("scoped-ny", "NY")):
        _, assignment, headers = _start_scoped_run(
            client,
            name=name,
            site=site,
            output_kind="entity",
        )
        accepted = _post_envelope(
            client,
            assignment,
            headers,
            {
                "kind": "entity",
                "type": KNOWLEDGE_ENTITY_V1,
                "source": name,
                "idempotency_key": f"{name}:1",
                "payload": {
                    "entity_type": "service.instance",
                    "external_key": name,
                    "display_name": name,
                    "status": "healthy",
                },
            },
        )
        assert accepted.status_code == 200, accepted.text
        assert _project_one(worker_name=f"{name}-projector")[1] == (
            KnowledgeProjectionStatus.SUCCEEDED
        )

    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    try:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            headers=BOOTSTRAP_HEADERS,
            json={
                "subject": "admin@example.test",
                "display_name": "Initial Admin",
            },
        )
        assert bootstrap.status_code == 201, bootstrap.text
        admin_headers = {
            "Authorization": f"Bearer {bootstrap.json()['token']['access_token']}"
        }
        roles = client.get(
            "/api/v1/auth/roles",
            headers=admin_headers,
        ).json()
        operator_role = next(item for item in roles if item["name"] == "operator")
        principal = client.post(
            "/api/v1/auth/principals",
            headers=admin_headers,
            json={
                "subject": "hq.operator@example.test",
                "display_name": "HQ Operator",
            },
        ).json()
        binding = client.post(
            f"/api/v1/auth/principals/{principal['id']}/bindings",
            headers=admin_headers,
            json={
                "role_id": operator_role["id"],
                "scope": {"sites": ["HQ"]},
            },
        )
        assert binding.status_code == 201, binding.text
        token = client.post(
            f"/api/v1/auth/principals/{principal['id']}/tokens",
            headers=admin_headers,
            json={"name": "hq-projections", "expires_in_hours": 24},
        ).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        listed = client.get(
            "/api/v1/knowledge-projections",
            headers=headers,
        )
        assert listed.status_code == 200, listed.text
        assert [item["envelope_source"] for item in listed.json()] == [
            "scoped-hq"
        ]
        entities = client.get(
            "/api/v1/knowledge/entities",
            headers=headers,
        )
        assert entities.status_code == 200, entities.text
        assert [item["external_key"] for item in entities.json()] == [
            "scoped-hq"
        ]
        health = client.get(
            "/api/v1/knowledge-projections/health",
            headers=headers,
        )
        assert health.status_code == 200, health.text
        assert health.json()["succeeded"] == 1
        assert health.json()["pending"] == 0
        assert (
            client.get(
                "/api/v1/knowledge-projection-workers",
                headers=headers,
            ).status_code
            == 403
        )
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()


def test_repeated_expired_leases_dead_letter_at_attempt_ceiling(client):
    _, assignment, headers = _start_scoped_run(client, name="lease-ceiling")
    accepted = _post_envelope(
        client,
        assignment,
        headers,
        {
            "kind": "observation",
            "type": NETWORK_OBSERVATION_V1,
            "source": "switch-arp",
            "idempotency_key": "lease-ceiling:1",
            "payload": {
                "mac_address": "aa:bb:cc:dd:ee:06",
                "source": "arp",
            },
        },
    )
    assert accepted.status_code == 200, accepted.text
    with SessionLocal() as db:
        worker = register_projection_worker(db, name="projection-worker-ceiling")
        claimed = claim_projections(
            db,
            worker,
            limit=1,
            lease_seconds=15,
        )
        assert len(claimed) == 1
        projection = db.get(KnowledgeProjection, claimed[0].projection_id)
        assert projection is not None
        projection.attempt_count = projection.max_attempts
        projection.lease_expires_at = utcnow() - timedelta(seconds=1)
        db.commit()

        assert (
            claim_projections(
                db,
                worker,
                limit=1,
                lease_seconds=15,
            )
            == []
        )
        db.refresh(projection)
        assert projection.status == KnowledgeProjectionStatus.DEAD_LETTER
        assert projection.error_type == "ProjectionLeaseExpired"
        assert len(projection.error_sha256 or "") == 64
