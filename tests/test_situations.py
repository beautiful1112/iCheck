from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from icheck.builtin_agent_tools import ensure_builtin_agent_tools
from icheck.database import SessionLocal
from icheck.models import (
    AgentToolRegistration,
    Alert,
    AlertSeverity,
    AlertStatus,
    KnowledgeEntity,
    KnowledgeRelationship,
    Situation,
    utcnow,
)
from icheck.schema_validation import validate_instance
from icheck.services.agent_tools import execute_internal_tool

from test_agent_runtime import configure_investigation_route


def _device(client, name="situation-edge-01"):
    response = client.post(
        "/api/v1/devices",
        json={
            "name": name,
            "kind": "router",
            "management_ip": "192.0.2.77",
            "site": "Lab",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _alert(
    client,
    device_id: str,
    *,
    event_type: str,
    title: str,
    severity: str,
    dedup_key: str,
):
    response = client.post(
        "/api/v1/alerts/events",
        json={
            "event_type": event_type,
            "entity_type": "device",
            "entity_id": device_id,
            "title": title,
            "description": f"Evidence for {event_type}",
            "severity": severity,
            "details": {"source": "acceptance-test"},
            "dedup_key": dedup_key,
            "observed_at": datetime.now(UTC).isoformat(),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_alerts_correlate_into_one_prioritized_situation(client):
    device = _device(client)
    warning = _alert(
        client,
        device["id"],
        event_type="interface.loss.high",
        title="WAN packet loss is high",
        severity="warning",
        dedup_key="loss:wan",
    )
    initial = client.get("/api/v1/situations").json()
    assert len(initial) == 1
    situation_id = initial[0]["id"]
    assert initial[0]["alert_count"] == 1
    assert initial[0]["active_alert_count"] == 1
    assert initial[0]["severity"] == "warning"

    duplicate = _alert(
        client,
        device["id"],
        event_type="interface.loss.high",
        title="WAN packet loss is high",
        severity="warning",
        dedup_key="loss:wan",
    )
    assert duplicate["id"] == warning["id"]
    assert duplicate["occurrence_count"] == 2
    after_duplicate = client.get(
        f"/api/v1/situations/{situation_id}"
    ).json()
    assert after_duplicate["situation"]["occurrence_count"] == 2
    assert [item["event_type"] for item in after_duplicate["events"]] == [
        "alert.attached",
        "situation.created",
    ]

    critical = _alert(
        client,
        device["id"],
        event_type="bgp.neighbor.down",
        title="WAN BGP neighbor unavailable",
        severity="critical",
        dedup_key="bgp:wan",
    )
    situations = client.get("/api/v1/situations").json()
    assert len(situations) == 1
    situation = situations[0]
    assert situation["id"] == situation_id
    assert situation["severity"] == "critical"
    assert situation["alert_count"] == 2
    assert situation["active_alert_count"] == 2
    assert situation["occurrence_count"] == 3
    assert situation["priority_score"] > 100
    assert "+1 related" in situation["title"]
    assert situation["correlation_confidence"] == 1.0

    detail = client.get(f"/api/v1/situations/{situation_id}")
    assert detail.status_code == 200, detail.text
    document = detail.json()
    assert {item["alert_id"] for item in document["alerts"]} == {
        warning["id"],
        critical["id"],
    }
    assert document["alerts_truncated"] is False
    assert document["events_truncated"] is False
    assert "situation.severity_changed" in {
        item["event_type"] for item in document["events"]
    }

    dashboard = client.get("/api/v1/dashboard/summary").json()
    assert dashboard["open_alerts"] == 2
    assert dashboard["open_situations"] == 1
    assert dashboard["critical_situations"] == 1
    assert dashboard["recent_situations"][0]["id"] == situation_id


def test_situation_lifecycle_preserves_alert_truth_and_starts_new_generation(client):
    device = _device(client)
    first = _alert(
        client,
        device["id"],
        event_type="device.cpu.high",
        title="Device CPU high",
        severity="warning",
        dedup_key="cpu:high",
    )
    situation = client.get("/api/v1/situations").json()[0]
    acknowledged = client.post(
        f"/api/v1/situations/{situation['id']}/acknowledge",
        json={
            "actor": "l1.operator",
            "reason": "Investigation assigned to the network team",
        },
    )
    assert acknowledged.status_code == 200, acknowledged.text
    assert acknowledged.json()["status"] == "acknowledged"

    second = _alert(
        client,
        device["id"],
        event_type="device.memory.high",
        title="Device memory high",
        severity="critical",
        dedup_key="memory:high",
    )
    reopened = client.get(f"/api/v1/situations/{situation['id']}").json()
    assert reopened["situation"]["status"] == "open"
    assert "situation.attention_reopened" in {
        item["event_type"] for item in reopened["events"]
    }
    refused = client.post(
        f"/api/v1/situations/{situation['id']}/resolve",
        json={
            "actor": "l1.operator",
            "reason": "Attempted premature closure",
        },
    )
    assert refused.status_code == 409
    assert "Alerts remain active" in refused.text

    for alert_id in (first["id"], second["id"]):
        resolved = client.post(
            f"/api/v1/alerts/{alert_id}/resolve",
            json={"actor": "l1.operator"},
        )
        assert resolved.status_code == 200, resolved.text
    finished = client.get(f"/api/v1/situations/{situation['id']}").json()
    assert finished["situation"]["status"] == "resolved"
    assert finished["situation"]["active_alert_count"] == 0
    assert finished["situation"]["priority_score"] == 0
    assert {item["status"] for item in finished["alerts"]} == {"resolved"}

    next_alert = _alert(
        client,
        device["id"],
        event_type="device.temperature.high",
        title="Device temperature high",
        severity="warning",
        dedup_key="temperature:high",
    )
    current = client.get("/api/v1/situations?status=open").json()
    assert len(current) == 1
    assert current[0]["id"] != situation["id"]
    assert current[0]["alert_count"] == 1
    assert client.get(
        f"/api/v1/situations/{situation['id']}"
    ).json()["alerts"][0]["alert_id"] != next_alert["id"]


def test_situation_can_bind_a_durable_investigation(client):
    configure_investigation_route(client)
    device = _device(client)
    _alert(
        client,
        device["id"],
        event_type="device.unreachable",
        title="Device unreachable",
        severity="critical",
        dedup_key="device:unreachable",
    )
    situation = client.get("/api/v1/situations").json()[0]
    created = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": "Investigate device reachability Situation",
            "objective": "Explain the correlated device symptoms with evidence.",
            "scope": {
                "device_ids": [device["id"]],
                "situation_id": situation["id"],
            },
            "situation_id": situation["id"],
            "route_purpose": "investigation",
            "created_by": "l1.operator",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["situation_id"] == situation["id"]
    detail = client.get(f"/api/v1/situations/{situation['id']}").json()
    assert [item["id"] for item in detail["investigations"]] == [
        created.json()["id"]
    ]
    assert "investigation.created" in {
        item["event_type"] for item in detail["events"]
    }


def test_situation_hypothesis_keeps_evidence_and_confidence_history(client):
    configure_investigation_route(client)
    device = _device(client)
    alert = _alert(
        client,
        device["id"],
        event_type="interface.errors.high",
        title="Interface errors are high",
        severity="critical",
        dedup_key="interface:errors",
    )
    situation = client.get("/api/v1/situations").json()[0]
    created = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": "Find the cause of interface errors",
            "objective": "Propose an evidence-backed root-cause hypothesis.",
            "scope": {
                "device_ids": [device["id"]],
                "situation_id": situation["id"],
            },
            "situation_id": situation["id"],
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
            "evidence_type": "alert",
            "evidence_id": alert["id"],
            "summary": "Physical interface error counter crossed its threshold.",
        },
    )
    assert evidence.status_code == 201, evidence.text

    def checkpoint(status, iteration, confidence, evidence_id):
        return {
            "node": "reason",
            "state": {
                "investigation_id": investigation["id"],
                "objective": investigation["objective"],
                "scope": investigation["scope"],
                "status": status,
                "iteration": iteration,
                "plan": ["Inspect interface evidence"],
                "hypotheses": [
                    {
                        "statement": "The physical uplink is degraded.",
                        "confidence": confidence,
                        "supporting_evidence_ids": [evidence_id],
                    }
                ],
                "evidence_ids": [evidence_id],
                "tool_call_ids": [],
                "confidence": confidence,
                "conclusion": (
                    "The physical uplink is the leading evidence-backed cause."
                    if status == "completed"
                    else None
                ),
                "uncertainty": ["Optical power is not yet available."],
            },
            "token_usage": 25,
            "actor": "agent.worker-test",
        }

    invented = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/checkpoints",
        json=checkpoint("running", 1, 0.35, "invented-evidence-id"),
    )
    assert invented.status_code == 409
    assert "same Investigation" in invented.text

    first = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/checkpoints",
        json=checkpoint("running", 1, 0.35, evidence.json()["id"]),
    )
    assert first.status_code == 201, first.text
    candidate = client.get(
        f"/api/v1/situations/{situation['id']}/hypotheses"
    ).json()[0]
    assert candidate["status"] == "candidate"
    assert candidate["revision_count"] == 1

    final = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/checkpoints",
        json=checkpoint("completed", 2, 0.82, evidence.json()["id"]),
    )
    assert final.status_code == 201, final.text
    hypotheses = client.get(
        f"/api/v1/situations/{situation['id']}/hypotheses"
    )
    assert hypotheses.status_code == 200, hypotheses.text
    hypothesis = hypotheses.json()[0]
    assert hypothesis["status"] == "proposed"
    assert hypothesis["current_confidence"] == 0.82
    assert hypothesis["revision_count"] == 2
    assert [item["confidence"] for item in hypothesis["revisions"]] == [
        0.35,
        0.82,
    ]
    assert hypothesis["revisions"][-1]["evidence"][0] == {
        "evidence_reference_id": evidence.json()["id"],
        "stance": "supporting",
        "evidence_type": "alert",
        "evidence_id": alert["id"],
        "summary": "Physical interface error counter crossed its threshold.",
        "observed_at": None,
    }

    accepted = client.post(
        f"/api/v1/situations/{situation['id']}/hypotheses/{hypothesis['id']}/accept",
        json={
            "actor": "l2.network",
            "reason": "Packet and interface evidence support this diagnosis",
        },
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["status"] == "accepted"
    assert accepted.json()["reviewed_by"] == "l2.network"
    detail = client.get(f"/api/v1/situations/{situation['id']}").json()
    assert {
        "hypotheses.proposed",
        "hypothesis.accepted",
    } <= {item["event_type"] for item in detail["events"]}


def test_situation_impact_assessment_is_evidence_bound_and_human_governed(client):
    configure_investigation_route(client)
    device = _device(client)
    alert = _alert(
        client,
        device["id"],
        event_type="service.checkout.degraded",
        title="Checkout requests are failing",
        severity="critical",
        dedup_key="checkout:degraded",
    )
    situation = client.get("/api/v1/situations").json()[0]
    contract = "icheck.situation-impact-assessment/v1"
    created = client.post(
        "/api/v1/agent/investigations",
        json={
            "title": "Assess checkout service impact",
            "objective": "Assess service impact using persisted evidence.",
            "scope": {
                "device_ids": [device["id"]],
                "situation_id": situation["id"],
                "requested_output_contract": contract,
            },
            "situation_id": situation["id"],
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
            "evidence_type": "alert",
            "evidence_id": alert["id"],
            "summary": "Checkout error-rate threshold is breached.",
        },
    )
    assert evidence.status_code == 201, evidence.text
    evidence_id = evidence.json()["id"]

    def completed_checkpoint(affected_node_id: str):
        return {
            "node": "reason",
            "state": {
                "investigation_id": investigation["id"],
                "objective": investigation["objective"],
                "scope": investigation["scope"],
                "status": "completed",
                "iteration": 1,
                "plan": ["Assess impact from authorized context"],
                "hypotheses": [],
                "evidence_ids": [evidence_id],
                "tool_call_ids": [],
                "confidence": 0.74,
                "conclusion": "Checkout service impact is likely.",
                "uncertainty": ["Downstream order processing is not measured."],
                "structured_output": {
                    "contract": contract,
                    "impact_level": "high",
                    "summary": "Checkout service requests may be materially affected.",
                    "confidence": 0.74,
                    "affected_node_ids": [affected_node_id],
                    "supporting_evidence_ids": [evidence_id],
                    "uncertainty": [
                        "Downstream order processing is not measured."
                    ],
                },
            },
            "token_usage": 30,
            "actor": "agent.worker-test",
        }

    missing_output_payload = completed_checkpoint(f"device:{device['id']}")
    missing_output_payload["state"]["structured_output"] = None
    missing_output = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/checkpoints",
        json=missing_output_payload,
    )
    assert missing_output.status_code == 409, missing_output.text
    assert "requires an impact assessment structured_output" in missing_output.text

    invalid = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/checkpoints",
        json=completed_checkpoint("knowledge:invented-node"),
    )
    assert invalid.status_code == 409, invalid.text
    assert "current authorized impact graph" in invalid.text
    assert client.get(
        f"/api/v1/situations/{situation['id']}/impact-assessments"
    ).json() == []

    persisted = client.post(
        f"/api/v1/agent/investigations/{investigation['id']}/checkpoints",
        json=completed_checkpoint(f"device:{device['id']}"),
    )
    assert persisted.status_code == 201, persisted.text
    response = client.get(
        f"/api/v1/situations/{situation['id']}/impact-assessments"
    )
    assert response.status_code == 200, response.text
    assessment = response.json()[0]
    assert assessment["status"] == "proposed"
    assert assessment["impact_level"] == "high"
    assert assessment["confidence"] == 0.74
    assert assessment["affected_node_ids"] == [f"device:{device['id']}"]
    assert assessment["evidence"] == [
        {
            "evidence_reference_id": evidence_id,
            "evidence_type": "alert",
            "evidence_id": alert["id"],
            "summary": "Checkout error-rate threshold is breached.",
            "observed_at": None,
        }
    ]

    accepted = client.post(
        f"/api/v1/situations/{situation['id']}/impact-assessments/{assessment['id']}/accept",
        json={
            "actor": "service.owner",
            "reason": "Alert evidence matches the observed checkout failure window",
        },
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["status"] == "accepted"
    assert accepted.json()["reviewed_by"] == "service.owner"
    detail = client.get(f"/api/v1/situations/{situation['id']}").json()
    assert {
        "impact_assessment.proposed",
        "impact_assessment.accepted",
    } <= {item["event_type"] for item in detail["events"]}


def test_situation_impact_returns_bounded_evidence_paths_without_claiming_cause(
    client,
):
    device = _device(client)
    observed = client.post(
        "/api/v1/inventory/network-observations",
        json={
            "observations": [
                {
                    "mac_address": "02:00:00:00:77:01",
                    "ip_address": "10.77.0.51",
                    "source": "arp",
                    "collector_device_id": device["id"],
                    "interface_name": "Ethernet1/7",
                    "observed_at": datetime.now(UTC).isoformat(),
                }
            ]
        },
    )
    assert observed.status_code == 200, observed.text
    with SessionLocal() as db:
        now = utcnow()
        service = KnowledgeEntity(
            namespace="artifact:situation-impact",
            scope_key=f"device:{device['id']}",
            scope_device_id=device["id"],
            scope_site="Lab",
            entity_type="service",
            external_key="branch-connectivity",
            display_name="Branch connectivity",
            status="degraded",
            active=True,
            attributes={"private_payload": "must-not-render"},
            first_seen=now,
            last_seen=now,
            observed_at=now,
        )
        application = KnowledgeEntity(
            namespace="artifact:situation-impact",
            scope_key="site:Lab",
            scope_device_id=None,
            scope_site="Lab",
            entity_type="application",
            external_key="checkout",
            display_name="Checkout",
            status="at_risk",
            active=True,
            attributes={"owner": "must-not-render"},
            first_seen=now,
            last_seen=now,
            observed_at=now,
        )
        db.add_all([service, application])
        db.flush()
        db.add(
            KnowledgeRelationship(
                namespace="artifact:situation-impact",
                scope_key=f"device:{device['id']}",
                scope_device_id=device["id"],
                scope_site="Lab",
                relationship_type="service.supports",
                source_entity_id=service.id,
                target_entity_id=application.id,
                directed=True,
                active=True,
                attributes={"secret_context": "must-not-render"},
                first_seen=now,
                last_seen=now,
                observed_at=now,
            )
        )
        db.commit()

    _alert(
        client,
        device["id"],
        event_type="device.reachability.degraded",
        title="Branch reachability degraded",
        severity="critical",
        dedup_key="reachability:branch",
    )
    situation = client.get("/api/v1/situations").json()[0]
    response = client.get(f"/api/v1/situations/{situation['id']}/impact")
    assert response.status_code == 200, response.text
    document = response.json()
    assert document["hypothesis_boundary"] == (
        "deterministic_context_not_root_cause"
    )
    assert document["root_node_id"] == f"device:{device['id']}"
    assert document["summary"] == {
        "native_neighbor_count": 1,
        "knowledge_entity_count": 2,
            "service_count": 0,
            "service_dependency_count": 0,
            "service_indicator_count": 0,
            "service_indicator_breach_count": 0,
            "stale_service_indicator_count": 0,
            "path_count": 3,
    }
    assert {item["role"] for item in document["nodes"]} == {
        "root",
        "adjacent",
        "scoped_component",
        "dependency",
    }
    service_path = next(
        item
        for item in document["paths"]
        if item["relationship_types"][-1] == "service.supports"
    )
    assert service_path["hop_count"] == 2
    assert document["nodes_truncated"] is False
    assert document["edges_truncated"] is False
    assert "must-not-render" not in response.text

    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == "situations.get_impact"
            )
        )
        assert tool is not None
        tool_result, evidence = execute_internal_tool(
            db,
            tool,
            {"situation_id": situation["id"]},
        )
        validate_instance(tool_result, tool.output_schema, "impact tool result")
    assert tool_result["root_node_id"] == document["root_node_id"]
    assert evidence[0].evidence_type == "situation_impact"
    assert evidence[0].evidence_id == situation["id"]


def test_reconcile_endpoint_backfills_unlinked_active_alerts_idempotently(client):
    device = _device(client)
    with SessionLocal() as db:
        alert = Alert(
            dedup_key="legacy:unlinked",
            event_type="device.legacy.alert",
            severity=AlertSeverity.WARNING,
            status=AlertStatus.OPEN,
            title="Legacy uncorrelated alert",
            description="Created before the Situation correlator was enabled.",
            entity_type="device",
            entity_id=device["id"],
            occurrence_count=1,
            details={},
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
        db.add(alert)
        db.commit()
    first = client.post("/api/v1/situations/reconcile/active-alerts?limit=100")
    assert first.status_code == 200, first.text
    assert first.json() == {"correlated_alerts": 1}
    second = client.post("/api/v1/situations/reconcile/active-alerts?limit=100")
    assert second.status_code == 200, second.text
    assert second.json() == {"correlated_alerts": 0}
    with SessionLocal() as db:
        assert db.query(Situation).count() == 1
