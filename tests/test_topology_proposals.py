from __future__ import annotations

import pytest

from icheck.database import SessionLocal
from icheck.services.control_plane_auth import PrincipalContext
from icheck.services.topology_views import (
    topology_artifact_documents,
    validate_topology_artifact_contract,
)
from icheck.studio_schemas import GeneratedTopologySpec
from test_agent_runtime import configure_investigation_route
from test_topology_studio import TOPOLOGY_SPEC, seed_topology


CONTRACT = "icheck.topology-proposal/v1"


def _investigation(client, *, title: str, artifact_name: str):
    scope = {"requested_output_contract": CONTRACT}
    created = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": title,
            "objective": "Propose an evidence-grounded operational topology view.",
            "scope": scope,
            "route_purpose": "investigation",
            "created_by": "l1.operator",
        },
    )
    assert created.status_code == 201, created.text
    investigation = created.json()
    started = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/start",
        json={"actor": "l1.operator"},
    )
    assert started.status_code == 200, started.text
    evidence = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/evidence",
        json={
            "evidence_type": "topology_observation",
            "evidence_id": f"catalog:{artifact_name}",
            "summary": "Current HQ inventory contains network devices and endpoints.",
        },
    )
    assert evidence.status_code == 201, evidence.text
    return investigation, scope, evidence.json()


def _complete(client, investigation, scope, evidence, spec):
    return client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/checkpoints",
        json={
            "node": "reason",
            "state": {
                "investigation_id": investigation["id"],
                "objective": investigation["objective"],
                "scope": scope,
                "status": "completed",
                "iteration": 1,
                "plan": ["Inspect evidence", "Propose a bounded view"],
                "hypotheses": [],
                "evidence_ids": [evidence["id"]],
                "tool_call_ids": [],
                "confidence": 0.9,
                "conclusion": "A grouped HQ access view is useful.",
                "uncertainty": ["Inventory changes after proposal time."],
                "structured_output": {
                    "contract": CONTRACT,
                    "rationale": "Show current HQ attachment evidence for L1 triage.",
                    "spec": spec,
                    "supporting_evidence_ids": [evidence["id"]],
                    "uncertainty": ["The view is current-state context, not causality."],
                },
            },
            "token_usage": 55,
            "actor": "agent.worker-test",
        },
    )


def test_investigation_topology_proposal_publishes_ordinary_artifact(client):
    seed_topology(client)
    configure_investigation_route(client)
    investigation, scope, evidence = _investigation(
        client,
        title="Design HQ access view",
        artifact_name=TOPOLOGY_SPEC["artifact_name"],
    )
    completed = _complete(
        client,
        investigation,
        scope,
        evidence,
        TOPOLOGY_SPEC,
    )
    assert completed.status_code == 201, completed.text

    proposals = client.get("/api/v1/topology/proposals")
    assert proposals.status_code == 200, proposals.text
    proposal = proposals.json()[0]
    assert proposal["status"] == "proposed"
    for key, value in TOPOLOGY_SPEC.items():
        assert proposal["spec"][key] == value
    assert proposal["evidence"][0]["evidence_reference_id"] == evidence["id"]
    preview = proposal["validation_report"]["preview"]
    assert preview["node_count"] == 4
    assert preview["edge_count"] == 4
    assert "must-not-enter-preview" not in str(preview)

    published = client.post(
        f"/api/v1/topology/proposals/{proposal['id']}/publish",
        json={
            "actor": "topology.reviewer",
            "reason": "The selectors and minimized preview match the cited evidence.",
        },
    )
    assert published.status_code == 200, published.text
    published = published.json()
    assert published["status"] == "published"
    assert published["artifact_id"]
    assert published["artifact_version_id"]

    artifact = client.get(
        f"/api/v1/artifacts/{published['artifact_id']}"
    ).json()
    assert artifact["kind"] == "topology"
    assert artifact["labels"]["topology_proposal_id"] == proposal["id"]
    assert artifact["versions"][0]["status"] == "published"
    views = client.get("/api/v1/topology/views").json()
    assert published["artifact_id"] in {item["artifact_id"] for item in views}

    conflicting, conflict_scope, conflict_evidence = _investigation(
        client,
        title="Propose a conflicting HQ view",
        artifact_name=TOPOLOGY_SPEC["artifact_name"],
    )
    conflict_completed = _complete(
        client,
        conflicting,
        conflict_scope,
        conflict_evidence,
        TOPOLOGY_SPEC,
    )
    assert conflict_completed.status_code == 201, conflict_completed.text
    conflict_proposal = client.get(
        "/api/v1/topology/proposals?status=proposed"
    ).json()[0]
    conflict_publish = client.post(
        f"/api/v1/topology/proposals/{conflict_proposal['id']}/publish",
        json={
            "actor": "topology.reviewer",
            "reason": "Exercise atomic conflict rollback.",
        },
    )
    assert conflict_publish.status_code == 409
    unchanged = client.get(
        f"/api/v1/topology/proposals/{conflict_proposal['id']}"
    ).json()
    assert unchanged["status"] == "proposed"
    assert unchanged["artifact_id"] is None
    matching = [
        item
        for item in client.get("/api/v1/artifacts?kind=topology").json()
        if item["name"] == TOPOLOGY_SPEC["artifact_name"]
    ]
    assert len(matching) == 1


def test_topology_proposal_fails_closed_and_supports_rejection(client):
    seed_topology(client)
    configure_investigation_route(client)
    investigation, scope, evidence = _investigation(
        client,
        title="Reject invented topology evidence",
        artifact_name="invented-evidence-view",
    )
    invalid_spec = {**TOPOLOGY_SPEC, "artifact_name": "invented-evidence-view"}
    invalid = _complete(
        client,
        investigation,
        scope,
        {**evidence, "id": "invented-reference"},
        invalid_spec,
    )
    assert invalid.status_code == 409
    assert "evidence" in invalid.text
    assert client.get("/api/v1/topology/proposals").json() == []

    second, second_scope, second_evidence = _investigation(
        client,
        title="Review a disposable topology view",
        artifact_name="disposable-hq-view",
    )
    spec = {**TOPOLOGY_SPEC, "artifact_name": "disposable-hq-view"}
    completed = _complete(
        client,
        second,
        second_scope,
        second_evidence,
        spec,
    )
    assert completed.status_code == 201, completed.text
    proposal = client.get("/api/v1/topology/proposals").json()[0]
    rejected = client.post(
        f"/api/v1/topology/proposals/{proposal['id']}/reject",
        json={
            "actor": "topology.reviewer",
            "reason": "The view duplicates an existing operator workspace.",
        },
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["status"] == "rejected"
    assert rejected.json()["artifact_id"] is None


def test_topology_proposal_preview_is_limited_to_investigation_scope(client):
    for name, site, address in (
        ("hk-topology-01", "Hong Kong", "192.0.2.71"),
        ("ny-topology-01", "New York", "192.0.2.72"),
    ):
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
    principal = PrincipalContext(
        principal_id="hk-reviewer",
        subject="hk.operator@example.test",
        principal_type="investigation_snapshot",
        permissions=frozenset({"assets.read"}),
        role_names=("operator",),
        authorization_scope={"sites": ["Hong Kong"]},
        auth_method="investigation_snapshot",
    )
    spec = GeneratedTopologySpec(
        artifact_name="hk-scoped-proposal",
        description="Only show authorized Hong Kong devices.",
        node_types=["device"],
        edge_types=[],
        sites=["Hong Kong"],
        max_nodes=20,
        max_edges=20,
    )
    definition, implementation, tests = topology_artifact_documents(spec)
    with SessionLocal() as db:
        report = validate_topology_artifact_contract(
            db,
            definition,
            implementation,
            tests,
            principal=principal,
        )
        assert [item["label"] for item in report["preview"]["nodes"]] == [
            "hk-topology-01"
        ]

        forbidden = spec.model_copy(update={"sites": ["New York"]})
        documents = topology_artifact_documents(forbidden)
        with pytest.raises(ValueError, match="unavailable sites"):
            validate_topology_artifact_contract(
                db,
                *documents,
                principal=principal,
            )
