from dataclasses import replace
from datetime import timedelta
import importlib

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, func, inspect, select, text

from icheck.autonomy_schemas import CapabilityDiscovery, CapabilityNeed, InvestigationFollowup
from icheck.builtin_agent_tools import ensure_builtin_agent_tools
from icheck.database import SessionLocal, set_session_namespace
from icheck.models import (AgentExecution, AgentToolRegistration, Alert, AlertInvestigationEvent,
    AlertInvestigationPolicy, AlertSeverity, AlertStatus, Investigation, InvestigationCapabilityRequest,
    InvestigationToolCall, utcnow)
from icheck.services import alert_investigation as automation
from icheck.services import investigation_assistance as assistance
from icheck.services.agent_authorization import require_tool_permissions, tool_scope_allows
from icheck.services.agent_tools import execute_internal_tool
from icheck.services.control_plane_auth import development_principal
from icheck.services.model_reasoner import OpenAICompatibleReasoner, SYSTEM_PROMPT
from test_agent_runtime import configure_investigation_route


def enable(client, **changes):
    response = client.put("/api/v1/autonomy/alert-policy", json={"expected_revision": 0, "enabled": True, **changes})
    assert response.status_code == 200, response.text
    return response.json()


def new_alert(db, *, entity="switch-a", severity=AlertSeverity.CRITICAL, site=None, **changes):
    row = Alert(dedup_key=f"test:{entity}:{utcnow().isoformat()}", event_type="device.unavailable",
        title="Switch unavailable", entity_type="device", entity_id=entity, severity=severity,
        status=AlertStatus.OPEN, first_seen=utcnow(), **changes)
    db.add(row); db.commit()
    return row


def investigation(client, *, mode="diagnose", **changes):
    response = client.post("/api/v1/agent/investigations", json=dict(
        title="Diagnose intermittent connectivity", objective="Find why users cannot reach their gateway",
        execution_mode=mode, created_by="operator", **changes))
    assert response.status_code == 201, response.text
    return response.json()


def test_policy_defaults_off_and_never_calls_provider(client, monkeypatch):
    result = client.get("/api/v1/autonomy/alert-policy").json()
    assert result["enabled"] is False and result["revision"] == 0
    assert result["dispatcher_healthy"] is False
    with SessionLocal() as db:
        new_alert(db)
        assert automation.dispatch_alert_investigations(db) == 0
        assert db.scalar(select(func.count()).select_from(Investigation)) == 0


def test_policy_requires_route_optimistic_revision_and_valid_scope(client):
    response = client.put("/api/v1/autonomy/alert-policy", json={"expected_revision": 0, "enabled": True})
    assert response.status_code == 409
    configure_investigation_route(client)
    enable(client)
    assert client.put("/api/v1/autonomy/alert-policy", json={"expected_revision": 0}).status_code == 409
    for scope in ({"all": False, "sites": []}, {"all": True, "sites": ["LAB"]}):
        assert client.put("/api/v1/autonomy/alert-policy", json={"expected_revision": 1, "scope": scope}).status_code == 422


def test_dispatch_is_read_only_atomic_and_idempotent(client):
    configure_investigation_route(client)
    enable(client)
    with SessionLocal() as db:
        alert = new_alert(db)
        assert automation.dispatch_alert_investigations(db) == 1
        assert automation.dispatch_alert_investigations(db) == 0
        event = db.scalar(select(AlertInvestigationEvent))
        run = db.get(Investigation, event.investigation_id)
        assert run.execution_mode == "diagnose" and run.status == "running"
        assert run.scope["alert_id"] == alert.id
        assert run.token_budget == 1000 and run.max_tool_calls == 2
        assert db.scalar(select(func.count()).select_from(AgentExecution)) == 1
        assert db.get(Alert, alert.id).status == AlertStatus.OPEN
    status = client.get("/api/v1/autonomy/alert-policy").json()
    assert status["runs_today"] == 1 and status["dispatcher_healthy"] is True


def test_alert_grouping_concurrency_and_daily_limit(client):
    configure_investigation_route(client)
    enable(client, max_concurrent=1, daily_limit=1)
    with SessionLocal() as db:
        first = new_alert(db)
        second = new_alert(db)
        third = new_alert(db, entity="switch-b")
        assert automation.dispatch_alert_investigations(db) == 2
        events = list(db.scalars(select(AlertInvestigationEvent).order_by(AlertInvestigationEvent.created_at)))
        assert {e.status for e in events} == {"grouped", "dispatched"}
        assert len({e.investigation_id for e in events}) == 1
        assert db.scalar(select(AlertInvestigationEvent).where(AlertInvestigationEvent.alert_id == third.id)) is None
        run = db.get(Investigation, events[0].investigation_id); run.status = "completed"; db.commit()
        assert automation.dispatch_alert_investigations(db) == 0  # daily limit remains


@pytest.mark.parametrize("condition", ["resolved", "old", "severity", "pause"])
def test_non_actionable_alerts_do_not_start_ai(client, condition):
    configure_investigation_route(client)
    enable(client, **({"paused_until": (utcnow() + timedelta(hours=1)).isoformat()} if condition == "pause" else {}))
    with SessionLocal() as db:
        row = new_alert(db)
        if condition == "resolved": row.status = AlertStatus.RESOLVED
        if condition == "severity": row.severity = AlertSeverity.INFO
        if condition == "old":
            policy = automation.policy_row(db); policy.enabled_at -= timedelta(hours=1)
            row.first_seen -= timedelta(minutes=30)
        db.commit()
        assert automation.dispatch_alert_investigations(db) == 1
        assert db.scalar(select(AlertInvestigationEvent)).status == "skipped"
        assert db.scalar(select(func.count()).select_from(Investigation)) == 0


def test_enabling_policy_does_not_backfill(client):
    configure_investigation_route(client)
    with SessionLocal() as db: new_alert(db)
    enable(client)
    with SessionLocal() as db:
        assert automation.dispatch_alert_investigations(db) == 0


def test_disabled_or_revoked_policy_does_not_dispatch(client, monkeypatch):
    configure_investigation_route(client)
    enable(client)
    with SessionLocal() as db:
        new_alert(db)
        monkeypatch.setattr(automation, "_automation_principal", lambda *_: replace(development_principal(), permissions=frozenset()))
        assert automation.dispatch_alert_investigations(db) == 0
        assert automation.policy_row(db).dispatcher_status == "authority_unavailable"
    saved = client.put("/api/v1/autonomy/alert-policy", json={"expected_revision": 1, "enabled": False})
    assert saved.status_code == 200
    with SessionLocal() as db:
        assert automation.dispatch_alert_investigations(db) == 0


def test_dispatch_failure_does_not_leave_partial_investigation(client, monkeypatch):
    configure_investigation_route(client)
    enable(client)
    def fail(*args, **kwargs): raise ValueError("runtime unavailable")
    monkeypatch.setattr(automation, "start_investigation", fail)
    with SessionLocal() as db:
        new_alert(db)
        assert automation.dispatch_alert_investigations(db) == 0
        assert db.scalar(select(func.count()).select_from(Investigation)) == 0
        assert db.scalar(select(func.count()).select_from(AlertInvestigationEvent)) == 0
        assert automation.policy_row(db).dispatcher_status == "runtime_unavailable"


def test_site_policy_excludes_unmanaged_and_other_site_alerts(client):
    configure_investigation_route(client)
    enable(client, scope={"all": False, "sites": ["LAB"]})
    ids = []
    for site in ["LAB", "OTHER"]:
        response = client.post("/api/v1/assets/devices", json={"name": f"switch-{site}", "kind": "switch",
            "management_ip": "192.0.2.1" if site == "LAB" else "192.0.2.2", "site": site,
            "connections": [{"protocol": "icmp", "configuration": {"probe_timeout_seconds": 2}}], "created_by": "admin"})
        assert response.status_code == 201, response.text
        ids.append(response.json()["id"])
    with SessionLocal() as db:
        for identifier in ids: new_alert(db, entity=identifier)
        new_alert(db, entity="unknown")
        assert automation.dispatch_alert_investigations(db) == 1
        assert db.scalar(select(Investigation)).authorization_scope == {"all": False, "sites": ["LAB"]}


@pytest.mark.parametrize("transport", ["internal", "mcp", "managed_mcp"])
@pytest.mark.parametrize("write_kind", ["write", "change_risk", "contract"])
def test_diagnose_mode_enforced_below_prompt(transport, write_kind):
    run = Investigation(execution_mode="diagnose", permission_snapshot=["*"], scope={}, authorization_scope={"all": True})
    tool = AgentToolRegistration(name="network.mutate", handler="network.mutate", transport=transport,
        read_only=write_kind != "write", risk_level="change" if write_kind == "change_risk" else "observe",
        change_contract={} if write_kind == "contract" else None, required_permissions=[])
    assert not tool_scope_allows(run, tool)
    with pytest.raises(PermissionError): require_tool_permissions(run, tool)


def test_capability_discovery_and_request_are_scoped_no_execution(client):
    configure_investigation_route(client)
    created = investigation(client)
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        run = db.get(Investigation, created["id"])
        catalog = assistance.discover(db, run, CapabilityDiscovery(query="inventory"))
        assert catalog["tools"] and all(t["read_only"] for t in catalog["tools"])
        assert "research" in catalog
        tool = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == "investigation.request_capability"))
        payload = dict(kind="mcp", description="Read Cisco MAC address tables through a new read-only tool", reason="No matching tool is installed")
        result, evidence = execute_internal_tool(db, tool, payload, investigation=run)
        again, _ = execute_internal_tool(db, tool, payload, investigation=run)
        assert result["id"] == again["id"] and evidence == []
        assert db.scalar(select(func.count()).select_from(InvestigationCapabilityRequest)) == 1
        assert db.scalar(select(func.count()).select_from(AgentExecution)) == 0
    response = client.get(f"/api/v1/autonomy/requests/{result['id']}")
    assert response.status_code == 200 and response.json()["studio_url"].startswith("/studio/builder?capability_request=")


def test_assistance_cannot_be_invoked_without_executor_context(client):
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        tool = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == "investigation.discover_capabilities"))
        with pytest.raises(PermissionError): execute_internal_tool(db, tool, {})


def test_capability_handoff_retains_one_studio_session_without_generation(client):
    configure_investigation_route(client)
    created = investigation(client)
    with SessionLocal() as db:
        request = assistance.save_request(db, db.get(Investigation, created["id"]), CapabilityNeed(kind="skill",
            description="Create a reusable read-only network diagnosis Skill", reason="Save the reviewed diagnostic approach"))
    session = client.post("/api/v1/capability-studio/sessions/skills", json={
        "title": "Reusable diagnosis", "brief": "Create a read-only Cisco diagnosis Skill", "created_by": "operator"})
    assert session.status_code == 201, session.text
    endpoint = f"/api/v1/autonomy/requests/{request.id}/studio-session"
    payload = {"session_id": session.json()["id"]}
    linked = client.put(endpoint, json=payload)
    assert linked.status_code == 200, linked.text
    assert linked.json()["studio_session_id"] == session.json()["id"]
    assert "&session=" in client.get(f"/api/v1/autonomy/requests/{request.id}").json()["studio_url"]
    assert client.put(endpoint, json=payload).status_code == 200
    other = client.post("/api/v1/capability-studio/sessions/skills", json={
        "title": "Different draft", "brief": "Create a different read-only diagnosis Skill", "created_by": "operator"})
    assert client.put(endpoint, json={"session_id": other.json()["id"]}).status_code == 409


def test_followup_is_new_readonly_run_and_preserves_history(client):
    configure_investigation_route(client)
    previous = investigation(client)
    endpoint = f"/api/v1/autonomy/investigations/{previous['id']}/continue"
    assert client.post(endpoint, json={"message": "Please continue"}).status_code == 409
    with SessionLocal() as db:
        run = db.get(Investigation, previous["id"]); run.status = "escalated"; run.escalation_reason = "Missing MAC table tool"
        db.commit()
    response = client.post(endpoint, json={"message": "The MAC tool is now installed; check availability and continue"})
    assert response.status_code == 201, response.text
    assert response.json()["parent_investigation_id"] == previous["id"]
    assert response.json()["execution_mode"] == "diagnose"
    retry = client.post(endpoint, json={"message": "The MAC tool is now installed; check availability and continue"})
    assert retry.status_code == 201 and retry.json()["id"] == response.json()["id"]
    assert client.post(endpoint, json={"message": "A different follow-up"}).status_code == 409
    with SessionLocal() as db:
        run = db.get(Investigation, response.json()["id"])
        set_session_namespace(db, run.tenant_id, run.region_id)
        history = assistance.continuation_context(db, run, set())
        assert history[0]["conclusion"] == "Missing MAC table tool" and history[0]["historical"]
        assert db.get(Investigation, previous["id"]).status == "escalated"
        assert run.tokens_used == 0 and run.parent_investigation_id != run.id


def test_provider_repair_retry_preserves_diagnostic_boundary(client):
    configure_investigation_route(client)
    previous = investigation(client)
    with SessionLocal() as db:
        run = db.get(Investigation, previous["id"])
        run.status = "failed"
        db.commit()
    response = client.post(f"/api/v1/agent/investigations/{previous['id']}/repair-retry", json={"actor": "operator"})
    assert response.status_code == 201, response.text
    assert response.json()["execution_mode"] == "diagnose"


def test_cross_namespace_requests_and_history_are_hidden(client):
    configure_investigation_route(client)
    created = investigation(client)
    with SessionLocal() as db:
        row = assistance.save_request(db, db.get(Investigation, created["id"]), CapabilityNeed(
            description="Read additional Cisco interface counters", reason="Additional evidence is needed"))
        set_session_namespace(db, "another-tenant", "another-region")
        assert db.get(InvestigationCapabilityRequest, row.id) is None


def test_readonly_reasoner_guidance_requires_evidence_and_capability_discovery():
    assert "No user-authored workflow" in SYSTEM_PROMPT
    assert "not recovery proof" in SYSTEM_PROMPT
    assert "investigation.request_capability" in SYSTEM_PROMPT
    assert "research.search" in SYSTEM_PROMPT


def test_graph_discovers_tools_saves_missing_capability_and_escalates(client):
    from langgraph.checkpoint.memory import InMemorySaver
    from icheck.langgraph_runtime import GraphDecision, GraphToolRequest
    from icheck.services.agent_graph import run_database_investigation
    configure_investigation_route(client, max_tool_calls=4)
    created = investigation(client)
    assert client.post(f"/api/v1/agent/investigations/{created['id']}/start", json={"actor": "operator"}).status_code == 200
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        run = db.get(Investigation, created["id"])
        set_session_namespace(db, run.tenant_id, run.region_id)
        decisions = iter([
            GraphDecision(action="continue", plan=["Find a MAC table tool"], tool_requests=[GraphToolRequest(
                tool_name="investigation.discover_capabilities", arguments={"query": "mac"}, purpose="Discover relevant installed tools")]),
            GraphDecision(action="continue", plan=["Save the missing operation for review"], tool_requests=[GraphToolRequest(
                tool_name="investigation.request_capability", arguments={"kind": "mcp", "description": "Add a read-only Cisco MAC table tool",
                    "reason": "No tool currently supplies the required evidence"}, purpose="Save a capability brief")]),
            GraphDecision(action="escalate", escalation_reason="MAC table evidence needs a new reviewed capability; no cause verified"),
        ])
        result = run_database_investigation(db, run, reasoner=lambda _: next(decisions), checkpointer=InMemorySaver())
        assert result["status"] == "escalated", result
        assert result["tool_calls_used"] == 2
        assert db.scalar(select(func.count()).select_from(InvestigationCapabilityRequest)) == 1
        calls = list(db.scalars(select(InvestigationToolCall)))
        assert all(call.status == "succeeded" for call in calls)
        assert run.conclusion is None


def test_autonomy_migration_preserves_existing_investigations():
    migration = importlib.import_module("migrations.versions.z3f5h7j9l1n4_alert_investigation_autonomy")
    assert migration.down_revision == "y2e4g6i8k0m3"
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE investigations (id VARCHAR(36) PRIMARY KEY, objective TEXT)")
        connection.exec_driver_sql("CREATE TABLE alerts (id VARCHAR(36) PRIMARY KEY)")
        connection.exec_driver_sql("CREATE TABLE control_plane_principals (id VARCHAR(36) PRIMARY KEY)")
        connection.exec_driver_sql("INSERT INTO investigations VALUES ('existing', 'preserve this')")
        with Operations.context(MigrationContext.configure(connection)): migration.upgrade()
        assert connection.execute(text("SELECT objective,execution_mode FROM investigations")).first() == ("preserve this", "standard")
        connection.exec_driver_sql("UPDATE investigations SET execution_mode='diagnose'")
        with Operations.context(MigrationContext.configure(connection)):
            with pytest.raises(RuntimeError, match="diagnostic"): migration.downgrade()
        connection.exec_driver_sql("UPDATE investigations SET execution_mode='standard'")
        with Operations.context(MigrationContext.configure(connection)): migration.downgrade()
        assert "alert_investigation_policies" not in inspect(connection).get_table_names()
