from __future__ import annotations

from datetime import UTC, datetime, timedelta

from icheck.database import SessionLocal
from icheck.models import (
    Endpoint,
    EndpointAttachment,
    KnowledgeEntity,
    KnowledgeRelationship,
    ObservationSource,
)


def _knowledge_entity(db, *, key: str, observed_at: datetime) -> KnowledgeEntity:
    entity = KnowledgeEntity(
        namespace="artifact:topology-correlation-test",
        scope_key="site:Topology Lab",
        scope_site="Topology Lab",
        entity_type="network.device",
        external_key=key,
        display_name=key,
        status="observed",
        active=True,
        attributes={},
        first_seen=observed_at,
        last_seen=observed_at,
        observed_at=observed_at,
    )
    db.add(entity)
    db.flush()
    return entity


def _knowledge_relationship(
    db,
    *,
    source: KnowledgeEntity,
    target: KnowledgeEntity,
    observed_at: datetime,
    relationship_type: str = "network.link",
    directed: bool = False,
) -> KnowledgeRelationship:
    relationship = KnowledgeRelationship(
        namespace=source.namespace,
        scope_key=source.scope_key,
        scope_site=source.scope_site,
        relationship_type=relationship_type,
        source_entity_id=source.id,
        target_entity_id=target.id,
        directed=directed,
        active=True,
        attributes={},
        first_seen=observed_at,
        last_seen=observed_at,
        observed_at=observed_at,
    )
    db.add(relationship)
    db.flush()
    return relationship


def _alert(
    client,
    *,
    entity_type: str,
    entity_id: str,
    suffix: str,
    observed_at: datetime,
) -> dict:
    response = client.post(
        "/api/v1/alerts/events",
        json={
            "event_type": f"topology.symptom.{suffix}",
            "entity_type": entity_type,
            "entity_id": entity_id,
            "title": f"Topology symptom {suffix}",
            "description": "Evidence-qualified topology correlation acceptance.",
            "severity": "warning",
            "dedup_key": f"topology:{entity_type}:{entity_id}:{suffix}",
            "observed_at": observed_at.isoformat(),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_fresh_undirected_knowledge_topology_correlates_without_causal_claim(client):
    observed = datetime.now(UTC).replace(microsecond=0)
    with SessionLocal() as db:
        first = _knowledge_entity(db, key="edge-a", observed_at=observed)
        second = _knowledge_entity(db, key="edge-b", observed_at=observed)
        relationship = _knowledge_relationship(
            db,
            source=first,
            target=second,
            observed_at=observed,
            relationship_type="network.l2_neighbor.lldp",
        )
        first_id, second_id, relationship_id = first.id, second.id, relationship.id
        db.commit()

    _alert(
        client,
        entity_type="knowledge_entity",
        entity_id=first_id,
        suffix="link-a",
        observed_at=observed,
    )
    _alert(
        client,
        entity_type="knowledge_entity",
        entity_id=second_id,
        suffix="link-b",
        observed_at=observed + timedelta(minutes=1),
    )

    situations = client.get("/api/v1/situations").json()
    assert len(situations) == 1
    situation = situations[0]
    assert situation["correlation_version"] == "qualified_topology/v3"
    assert situation["correlation_confidence"] == 0.7
    assert "evidence-linked adjacent entities" in situation["summary"]

    detail = client.get(f"/api/v1/situations/{situation['id']}").json()
    membership = next(
        item
        for item in detail["alerts"]
        if item["correlation_reason"] == "fresh_topology_adjacency"
    )
    evidence = membership["correlation_evidence"]
    assert evidence["evidence_type"] == "fresh_topology_adjacency"
    assert evidence["topology_evidence_type"] == "knowledge_relationship"
    assert evidence["topology_evidence_id"] == relationship_id
    assert evidence["topology_relationship_type"] == "network.l2_neighbor.lldp"
    assert evidence["causal_claim"] is False
    assert evidence["source_entity_id"] == second_id
    assert evidence["target_entity_id"] == first_id

    impact = client.get(f"/api/v1/situations/{situation['id']}/impact")
    assert impact.status_code == 200, impact.text
    correlation_edge = next(
        item
        for item in impact.json()["edges"]
        if item["evidence_type"] == "situation_alert_topology_correlation"
    )
    assert correlation_edge["relationship_type"] == (
        "correlated_by_fresh_topology"
    )

    # Later topology state cannot rewrite the frozen membership evidence.
    with SessionLocal() as db:
        stored = db.get(KnowledgeRelationship, relationship_id)
        assert stored is not None
        stored.active = False
        stored.observed_at = observed + timedelta(minutes=2)
        db.commit()
    frozen = client.get(f"/api/v1/situations/{situation['id']}").json()
    frozen_membership = next(
        item
        for item in frozen["alerts"]
        if item["correlation_reason"] == "fresh_topology_adjacency"
    )
    assert frozen_membership["correlation_evidence"] == evidence


def test_fresh_native_attachment_correlates_device_and_endpoint(client):
    observed = datetime.now(UTC).replace(microsecond=0)
    device_response = client.post(
        "/api/v1/devices",
        json={
            "name": "access-switch-01",
            "kind": "switch",
            "management_ip": "192.0.2.245",
            "site": "Topology Lab",
        },
    )
    assert device_response.status_code == 201, device_response.text
    device = device_response.json()
    with SessionLocal() as db:
        endpoint = Endpoint(
            mac_address="aa:bb:cc:dd:ee:f1",
            hostname="terminal-f1",
            first_seen=observed,
            last_seen=observed,
        )
        db.add(endpoint)
        db.flush()
        attachment = EndpointAttachment(
            endpoint_id=endpoint.id,
            collector_device_id=device["id"],
            source=ObservationSource.MAC_TABLE,
            interface_name="Gi1/0/24",
            active=True,
            first_seen=observed,
            last_seen=observed,
            observed_at=observed,
            raw_data={},
        )
        db.add(attachment)
        db.flush()
        endpoint_id, attachment_id = endpoint.id, attachment.id
        db.commit()

    _alert(
        client,
        entity_type="device",
        entity_id=device["id"],
        suffix="switch",
        observed_at=observed,
    )
    _alert(
        client,
        entity_type="endpoint",
        entity_id=endpoint_id,
        suffix="terminal",
        observed_at=observed + timedelta(minutes=1),
    )
    situations = client.get("/api/v1/situations").json()
    assert len(situations) == 1
    assert situations[0]["correlation_version"] == "qualified_topology/v3"
    detail = client.get(f"/api/v1/situations/{situations[0]['id']}").json()
    membership = next(
        item
        for item in detail["alerts"]
        if item["correlation_reason"] == "fresh_topology_adjacency"
    )
    assert membership["correlation_evidence"]["topology_evidence_type"] == (
        "endpoint_attachment"
    )
    assert membership["correlation_evidence"]["topology_evidence_id"] == (
        attachment_id
    )
    assert membership["correlation_evidence"]["causal_claim"] is False


def test_ambiguous_topology_candidates_fail_closed(client):
    observed = datetime.now(UTC).replace(microsecond=0)
    with SessionLocal() as db:
        first = _knowledge_entity(db, key="ambiguous-a", observed_at=observed)
        bridge = _knowledge_entity(db, key="ambiguous-bridge", observed_at=observed)
        third = _knowledge_entity(db, key="ambiguous-c", observed_at=observed)
        _knowledge_relationship(
            db,
            source=first,
            target=bridge,
            observed_at=observed,
        )
        _knowledge_relationship(
            db,
            source=third,
            target=bridge,
            observed_at=observed,
        )
        first_id, bridge_id, third_id = first.id, bridge.id, third.id
        db.commit()

    _alert(
        client,
        entity_type="knowledge_entity",
        entity_id=first_id,
        suffix="ambiguous-a",
        observed_at=observed,
    )
    _alert(
        client,
        entity_type="knowledge_entity",
        entity_id=third_id,
        suffix="ambiguous-c",
        observed_at=observed,
    )
    _alert(
        client,
        entity_type="knowledge_entity",
        entity_id=bridge_id,
        suffix="ambiguous-bridge",
        observed_at=observed + timedelta(minutes=1),
    )
    situations = client.get("/api/v1/situations").json()
    assert len(situations) == 3
    assert {item["correlation_version"] for item in situations} == {
        "same_entity/v1"
    }


def test_stale_disallowed_or_directed_relationships_do_not_correlate(client):
    observed = datetime.now(UTC).replace(microsecond=0)
    pairs: list[tuple[str, str, str]] = []
    with SessionLocal() as db:
        for prefix, relationship_type, directed, relationship_time in (
            (
                "stale",
                "network.link",
                False,
                observed - timedelta(minutes=16),
            ),
            ("disallowed", "service.supports", False, observed),
            ("directed", "network.link", True, observed),
        ):
            first = _knowledge_entity(
                db,
                key=f"{prefix}-a",
                observed_at=observed,
            )
            second = _knowledge_entity(
                db,
                key=f"{prefix}-b",
                observed_at=observed,
            )
            _knowledge_relationship(
                db,
                source=first,
                target=second,
                observed_at=relationship_time,
                relationship_type=relationship_type,
                directed=directed,
            )
            pairs.append((prefix, first.id, second.id))
        db.commit()

    for prefix, first_id, second_id in pairs:
        _alert(
            client,
            entity_type="knowledge_entity",
            entity_id=first_id,
            suffix=f"{prefix}-a",
            observed_at=observed,
        )
        _alert(
            client,
            entity_type="knowledge_entity",
            entity_id=second_id,
            suffix=f"{prefix}-b",
            observed_at=observed + timedelta(minutes=1),
        )
    situations = client.get("/api/v1/situations").json()
    assert len(situations) == 6
    assert {item["correlation_version"] for item in situations} == {
        "same_entity/v1"
    }


def test_inactive_knowledge_entity_does_not_use_topology_for_correlation(client):
    observed = datetime.now(UTC).replace(microsecond=0)
    with SessionLocal() as db:
        inactive = _knowledge_entity(
            db,
            key="inactive-source",
            observed_at=observed,
        )
        active = _knowledge_entity(
            db,
            key="active-neighbor",
            observed_at=observed,
        )
        inactive.active = False
        _knowledge_relationship(
            db,
            source=inactive,
            target=active,
            observed_at=observed,
        )
        inactive_id, active_id = inactive.id, active.id
        db.commit()

    _alert(
        client,
        entity_type="knowledge_entity",
        entity_id=active_id,
        suffix="active-neighbor",
        observed_at=observed,
    )
    _alert(
        client,
        entity_type="knowledge_entity",
        entity_id=inactive_id,
        suffix="inactive-source",
        observed_at=observed + timedelta(minutes=1),
    )
    situations = client.get("/api/v1/situations").json()
    assert len(situations) == 2
    assert {item["correlation_version"] for item in situations} == {
        "same_entity/v1"
    }
