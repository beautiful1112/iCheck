"""Configuration self-repair is evidence-backed, bounded and human-approved."""
import json
from io import BytesIO
from urllib.error import HTTPError

import pytest
from sqlalchemy import select

from icheck.ai_failure_diagnostics import provider_diagnostic
from icheck.database import SessionLocal
from icheck.models import AIManagedConnection, AIProviderConfig, AIModelConfig, AIModelRoute, AuditEvent, Investigation, AIAuthoringQuotaReservation
from icheck.services.audit import record_audit_event
from icheck.services.model_reasoner import OpenAICompatibleReasoner, ModelReasonerUnavailable
from icheck.langgraph_runtime import initial_graph_state
from test_openrouter_setup import managed_key, provider_network, connect, configure, namespace_session, BASE, KEY, CATALOG
from test_password_login import required_auth, bootstrap, login


def preview(client, kind, item, enabled=False):
    response = client.post(f"/api/v1/ai/catalog/{kind}/{item}/lifecycle/preview", json={"enabled": enabled})
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def apply(client, kind, item, plan, enabled=False):
    return client.post(f"/api/v1/ai/catalog/{kind}/{item}/lifecycle", json={
        "enabled": enabled, "preview_hash": plan["preview_hash"], "reason": "Operator reviewed dependencies"})


@pytest.mark.parametrize("outbound_enabled", [False, True])
def test_retired_provider_is_explicit_and_discovery_never_contacts_upstream(client, managed_key, provider_network, outbound_enabled):
    connection = connect(client)
    assert connection["provider_enabled"] is True
    with namespace_session() as db:
        db.get(AIProviderConfig, connection["provider_id"]).enabled = False
        custody = db.scalar(select(AIManagedConnection))
        custody.outbound_enabled = outbound_enabled
        encrypted = custody.encrypted_secret
        db.commit()
    setup = client.get("/api/v1/ai/openrouter/setup")
    assert setup.status_code == 200 and setup.headers["cache-control"] == "no-store"
    assert setup.json()["connections"][0]["provider_enabled"] is False
    assert setup.json()["connections"][0]["outbound_enabled"] is outbound_enabled
    checked = client.post(f"/api/v1/ai/openrouter/{connection['provider_id']}/check")
    assert checked.status_code == 200
    assert checked.json()["health"]["status"] == "unhealthy"
    assert "provider is retired" in checked.json()["health"]["error"]
    assert "Restore it in Guided provider setup" in checked.json()["health"]["error"]
    assert "approved endpoint" not in checked.text and not provider_network
    with namespace_session() as db:
        assert db.scalar(select(AIManagedConnection)).encrypted_secret == encrypted
    assert KEY not in setup.text + checked.text


def test_retired_provider_cannot_be_reapproved_or_rotate_key_until_restored(client, managed_key, provider_network):
    connection = connect(client)
    pid = connection["provider_id"]
    assert apply(client, "providers", pid, preview(client, "providers", pid)).status_code == 200
    with namespace_session() as db:
        custody = db.scalar(select(AIManagedConnection))
        before = (custody.encrypted_secret, custody.revision, custody.outbound_enabled)
    response = client.put(f"/api/v1/ai/openrouter/{pid}/connection", json={
        "expected_revision": 2, "outbound_enabled": True, "api_key": KEY + "-replacement"})
    assert response.status_code == 409 and "provider is retired" in response.text
    with namespace_session() as db:
        custody = db.scalar(select(AIManagedConnection))
        assert (custody.encrypted_secret, custody.revision, custody.outbound_enabled) == before
    assert not provider_network and KEY not in response.text


def test_direct_provider_restore_preserves_key_and_requires_separate_outbound_approval(client, managed_key, provider_network):
    connection = connect(client)
    pid = connection["provider_id"]
    with namespace_session() as db:
        encrypted = db.scalar(select(AIManagedConnection)).encrypted_secret
    assert apply(client, "providers", pid, preview(client, "providers", pid)).status_code == 200
    restore = preview(client, "providers", pid, True)
    assert not restore["blockers"]
    assert apply(client, "providers", pid, restore, True).status_code == 200
    restored = client.get("/api/v1/ai/openrouter/setup").json()["connections"][0]
    assert restored["provider_enabled"] is True and restored["outbound_enabled"] is False
    assert client.post(f"/api/v1/ai/openrouter/{pid}/check").json()["health"]["error"] == "AI provider outbound access is disabled for this connection"
    assert not provider_network
    assert client.put(f"/api/v1/ai/openrouter/{pid}/connection", json={"expected_revision": 2, "outbound_enabled": True}).status_code == 200
    assert client.post(f"/api/v1/ai/openrouter/{pid}/check").json()["health"]["status"] == "healthy"
    assert len(provider_network) == 2
    with namespace_session() as db:
        assert db.scalar(select(AIManagedConnection)).encrypted_secret == encrypted
    assert client.get("/api/v1/ai/models").json() == [] and client.get("/api/v1/ai/routes").json() == []


def test_enabled_provider_endpoint_drift_still_fails_closed(client, managed_key, provider_network):
    connection = connect(client)
    with namespace_session() as db:
        db.get(AIProviderConfig, connection["provider_id"]).base_url = "https://other.example.invalid/v1"
        db.commit()
    checked = client.post(f"/api/v1/ai/openrouter/{connection['provider_id']}/check").json()
    assert checked["health"]["error"] == "Managed AI connection settings do not match their approved endpoint"
    assert not provider_network


def test_same_display_name_switch_preserves_old_identity_and_unselected_route(client, managed_key, provider_network):
    connection = connect(client)
    old = configure(client, connection).json()
    checked = client.post(f"/api/v1/ai/openrouter/{connection['provider_id']}/check").json()
    response = configure(client, connection, model_id="example/no-tools", replace_existing_routes=True,
        purposes=["investigation"], expected_configuration_hash=checked["configuration_hash"])
    assert response.status_code == 200, response.text
    new = response.json()["model"]
    assert new["id"] != old["model"]["id"] and new["display_name"] == "Operations reasoner"
    models = client.get("/api/v1/ai/models").json()
    retained = next(m for m in models if m["id"] == old["model"]["id"])
    assert retained["model_name"] == "openai/gpt-4o" and "previous" in retained["display_name"]
    routes = {r["purpose"]: r for r in client.get("/api/v1/ai/routes").json()}
    assert routes["capability.authoring"]["primary_model_id"] == retained["id"]
    assert routes["investigation"]["primary_model_id"] == new["id"]


def test_stale_configuration_cannot_replace_routes(client, managed_key, provider_network):
    connection = connect(client)
    checked = client.post(f"/api/v1/ai/openrouter/{connection['provider_id']}/check").json()
    assert configure(client, connection).status_code == 200
    before = client.get("/api/v1/ai/routes").json()
    response = configure(client, connection, replace_existing_routes=True, model_id="example/no-tools",
        expected_configuration_hash=checked["configuration_hash"])
    assert response.status_code == 409 and "changed after review" in response.text
    assert client.get("/api/v1/ai/routes").json() == before


def test_batch_catalog_and_direct_configuration_are_rejected(client, managed_key, provider_network, monkeypatch):
    monkeypatch.setitem(CATALOG, "data", CATALOG["data"] + [{"id": "example/reasoner:batch", "supported_parameters": ["response_format", "tools"]}])
    connection = connect(client)
    checked = client.post(f"/api/v1/ai/openrouter/{connection['provider_id']}/check").json()
    assert not any(m["id"].endswith(":batch") for m in checked["models"])
    assert configure(client, connection, model_id="example/reasoner:batch").status_code == 422
    response = client.post("/api/v1/ai/models", json={"provider_id": connection["provider_id"],
        "display_name": "batch", "model_name": "example/reasoner:batch", "capabilities": ["chat", "json_schema"]})
    assert response.status_code == 422


def test_lifecycle_dependency_order_retains_history_and_revokes_outbound(client, managed_key, provider_network):
    connection = connect(client)
    configured = configure(client, connection).json()
    model_id, provider_id = configured["model"]["id"], connection["provider_id"]
    blocked = preview(client, "models", model_id)
    assert len(blocked["dependencies"]) == 2 and blocked["blockers"]
    assert apply(client, "models", model_id, blocked).status_code == 409
    for route in configured["routes"]:
        plan = preview(client, "routes", route["id"])
        assert not plan["blockers"]
        assert apply(client, "routes", route["id"], plan).status_code == 200
    assert apply(client, "models", model_id, preview(client, "models", model_id)).status_code == 200
    assert apply(client, "providers", provider_id, preview(client, "providers", provider_id)).status_code == 200
    assert apply(client, "credentials", connection["credential_profile_id"], preview(client, "credentials", connection["credential_profile_id"])).status_code == 200
    assert len(client.get("/api/v1/ai/models").json()) == 1
    assert client.get("/api/v1/ai/models").json()[0]["enabled"] is False
    assert preview(client, "providers", provider_id, True)["blockers"]
    assert apply(client, "credentials", connection["credential_profile_id"], preview(client, "credentials", connection["credential_profile_id"], True), True).status_code == 200
    assert apply(client, "providers", provider_id, preview(client, "providers", provider_id, True), True).status_code == 200
    assert client.get("/api/v1/ai/openrouter/setup").json()["connections"][0]["outbound_enabled"] is False
    assert len(client.get("/api/v1/ai/routes").json()) == 2
    assert KEY not in client.get("/api/v1/audit-events").text


def test_lifecycle_stale_preview_and_active_investigation_block_removal(client, managed_key, provider_network):
    connection = connect(client); configured = configure(client, connection).json()
    route = next(r for r in configured["routes"] if r["purpose"] == "investigation")
    old = preview(client, "routes", route["id"])
    created = client.post("/api/v1/agent/investigations", json={"title": "Retained pin", "objective": "Read inventory", "created_by": "operator"})
    assert created.status_code == 201, created.text
    assert apply(client, "routes", route["id"], old).status_code == 409
    fresh = preview(client, "routes", route["id"])
    assert "active investigation" in " ".join(fresh["blockers"])
    assert apply(client, "routes", route["id"], fresh).status_code == 409
    assert preview(client, "models", configured["model"]["id"])["blockers"]


def test_ai_lifecycle_cannot_retire_a_reference_shared_with_collectors(client):
    response = client.post("/api/v1/credential-profiles", json={"name": "shared-reference", "provider": "environment",
        "secret_ref": "env://ICHECK_TEST_AI_PROVIDER_TOKEN", "allowed_adapters": ["ai_provider", "snmp"], "created_by": "test"})
    assert response.status_code == 201, response.text
    reviewed = preview(client, "credentials", response.json()["id"])
    assert "shared with non-AI adapters" in " ".join(reviewed["blockers"])
    assert apply(client, "credentials", response.json()["id"], reviewed).status_code == 409
    assert client.get("/api/v1/credential-profiles").json()[0]["enabled"] is True


def probe_network(monkeypatch, *, status=None, invalid=False, malformed=False):
    requests = []
    class Response:
        status = 200
        def __init__(self, data): self.data = json.dumps(data).encode()
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self, n): return self.data[:n]
    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            if request.full_url.endswith("/key"): return Response({"data": {"is_management_key": False}})
            if request.full_url.endswith("/models"): return Response(CATALOG)
            assert request.full_url == BASE + "/chat/completions" and request.method == "POST"
            assert timeout <= 30
            if status: raise HTTPError(request.full_url, status, KEY, {}, BytesIO(json.dumps({"error": {"message": KEY}}).encode()))
            if malformed: return Response([KEY])
            return Response({"usage": {"total_tokens": 42}, "choices": [{"message": {"content": "invalid" if invalid else json.dumps({"action": "complete", "conclusion": "Model inference verified"})}}]})
    monkeypatch.setattr("icheck.services.openrouter_setup.build_opener", lambda *args: Opener())
    return requests


@pytest.mark.parametrize("status,invalid,code", [(None, False, None), (404, False, "provider_endpoint_unavailable"), (401, False, "provider_key_rejected"), (None, True, "model_schema_invalid")])
def test_probe_is_opt_in_bounded_accounted_and_never_changes_routes(client, managed_key, monkeypatch, status, invalid, code):
    requests = probe_network(monkeypatch, status=status, invalid=invalid)
    connection = connect(client)
    url = f"/api/v1/ai/openrouter/{connection['provider_id']}/probe"
    payload = {"expected_connection_revision": 1, "model_id": "openai/gpt-4o", "approve_charge": False}
    assert client.post(url, json=payload).status_code == 422 and not requests
    payload["approve_charge"] = True
    response = client.post(url, json=payload)
    assert response.status_code == 200, response.text
    result = response.json(); assert result["passed"] is (code is None)
    assert response.headers["cache-control"] == "no-store" and KEY not in response.text
    if code: assert result["diagnostic"]["code"] == code
    data = json.loads(requests[-1].data)
    assert data["max_tokens"] == 512 and "tools" not in data
    assert data["response_format"]["type"] == "json_schema"
    assert client.get("/api/v1/ai/routes").json() == []
    with namespace_session() as db:
        receipt = db.get(AIAuthoringQuotaReservation, result["quota_reservation_id"])
        assert receipt.status == "settled"
        assert receipt.external_charge_unknown is bool(status)
        assert receipt.known_tokens == (0 if status else 42)
    assert KEY not in client.get("/api/v1/audit-events").text


def test_successful_probe_is_bound_to_exact_model_actor_and_key_revision(client, managed_key, monkeypatch):
    probe_network(monkeypatch); connection = connect(client)
    receipt = client.post(f"/api/v1/ai/openrouter/{connection['provider_id']}/probe", json={
        "expected_connection_revision": 1, "model_id": "openai/gpt-4o", "approve_charge": True}).json()["quota_reservation_id"]
    assert configure(client, connection, probe_reservation_id=receipt, model_id="example/no-tools").status_code == 409
    assert configure(client, connection, probe_reservation_id=receipt).status_code == 200
    assert client.put(f"/api/v1/ai/openrouter/{connection['provider_id']}/connection", json={"expected_revision": 1, "api_key": KEY, "outbound_enabled": True}).status_code == 200
    connection["revision"] = 2
    assert configure(client, connection, probe_reservation_id=receipt, replace_existing_routes=True).status_code == 409


def test_malformed_probe_response_is_safe_diagnostic_not_api_500(client, managed_key, monkeypatch):
    probe_network(monkeypatch, malformed=True); connection = connect(client)
    response = client.post(f"/api/v1/ai/openrouter/{connection['provider_id']}/probe", json={
        "expected_connection_revision": 1, "model_id": "openai/gpt-4o", "approve_charge": True})
    assert response.status_code == 200 and response.json()["diagnostic"]["code"] == "model_schema_invalid"
    assert KEY not in response.text and not response.json()["passed"]


@pytest.mark.parametrize("embedded", [False, True])
def test_probe_retains_exact_safe_400_validation_in_receipt_and_audit(client, managed_key, monkeypatch, embedded):
    calls = []
    failure = {"error": {"code": 400, "message": "Provider returned error", "metadata": {
        "provider_name": "Alibaba", "error_type": "invalid_request", "provider_code": "InvalidParameter",
        "raw": json.dumps({"message": "response_format.json_schema.strict must be true " + KEY})}}}
    class Response:
        status = 200
        def __init__(self, doc): self.raw = json.dumps(doc).encode()
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self, size): return self.raw[:size]
    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            if request.full_url.endswith("/key"): return Response({"data": {"is_management_key": False}})
            if request.full_url.endswith("/models"): return Response(CATALOG)
            if embedded: return Response(failure)
            raise HTTPError(request.full_url, 400, KEY, {}, BytesIO(json.dumps(failure).encode()))
    monkeypatch.setattr("icheck.services.openrouter_setup.build_opener", lambda *_: Opener())
    connection = connect(client)
    response = client.post(f"/api/v1/ai/openrouter/{connection['provider_id']}/probe", json={
        "expected_connection_revision": 1, "model_id": "openai/gpt-4o", "approve_charge": True})
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    value = response.json()
    assert not value["passed"] and value["diagnostic"]["code"] == "provider_schema_strict_required"
    assert value["diagnostic"]["provider_error"]["parameter"] == "response_format.json_schema.strict"
    assert value["diagnostic"]["root_cause_known"] is True
    if embedded: assert value["diagnostic"]["transport_status"] == 200
    assert len([call for call in calls if call.method == "POST"]) == 1
    audit = client.get("/api/v1/audit-events?event_type=ai.openrouter.model_probed").json()[0]
    assert audit["details"]["diagnostic"] == value["diagnostic"]
    assert KEY not in response.text + json.dumps(audit)
    assert client.get("/api/v1/ai/routes").json() == []
    with namespace_session() as db:
        receipt = db.get(AIAuthoringQuotaReservation, value["quota_reservation_id"])
        assert receipt.status == "settled" and receipt.external_charge_unknown


@pytest.mark.parametrize("invalid_decision", [False, True])
def test_qwen_probe_uses_strict_full_graph_schema_and_preserves_local_validation(client, managed_key, monkeypatch, invalid_decision):
    from icheck.langgraph_runtime import GraphDecision
    model = "qwen/qwen3.8-max-0902"
    monkeypatch.setitem(CATALOG, "data", CATALOG["data"] + [{"id": model,
        "supported_parameters": ["response_format", "structured_outputs", "reasoning", "reasoning_effort"],
        "reasoning": {"mandatory": True, "supported_efforts": ["medium", "low"]}}])
    calls = []
    class Response:
        status = 200
        def __init__(self, doc): self.raw = json.dumps(doc).encode()
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self, n): return self.raw[:n]
    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            if request.full_url.endswith("/key"): return Response({"data": {"is_management_key": False}})
            if request.full_url.endswith("/models"): return Response(CATALOG)
            payload = json.loads(request.data)
            assert payload["response_format"]["json_schema"]["strict"] is True
            assert payload["response_format"]["json_schema"]["schema"] == GraphDecision.model_json_schema()
            assert payload["max_tokens"] == 512 and payload["reasoning"] == {"enabled": True, "effort": "low"}
            assert timeout <= 30 and "tools" not in payload
            decision = {"action": "complete", "conclusion": "Model inference verified"}
            if invalid_decision: decision["tool_requests"] = [{"tool_name": "unauthorized", "purpose": "no", "arguments": {}}]
            return Response({"usage": {"total_tokens": 42}, "choices": [{"message": {"content": json.dumps(decision)}}]})
    monkeypatch.setattr("icheck.services.openrouter_setup.build_opener", lambda *_: Opener())
    connection = connect(client)
    response = client.post(f"/api/v1/ai/openrouter/{connection['provider_id']}/probe", json={
        "expected_connection_revision": 1, "model_id": model, "approve_charge": True})
    assert response.status_code == 200 and response.json()["passed"] is not invalid_decision
    if invalid_decision: assert response.json()["diagnostic"]["code"] == "model_schema_invalid"
    assert len([call for call in calls if call.method == "POST"]) == 1
    assert client.get("/api/v1/ai/routes").json() == []


def test_legacy_failure_has_specific_model_independent_repair_and_history_is_immutable(client, managed_key, provider_network):
    connection = connect(client); configured = configure(client, connection).json()
    created = client.post("/api/v1/agent/investigations", json={"title": "Onboard switch", "objective": "Preview onboarding using lab at site LAB", "scope": {"site": "LAB"}, "created_by": "operator"})
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]
    with namespace_session() as db:
        db.get(AIModelConfig, configured["model"]["id"]).model_name = "example/reasoner:batch"
        row = db.get(Investigation, investigation_id); row.status = "escalated"; row.escalation_reason = "Reasoner failed: ControlPlaneHTTPError"
        record_audit_event(db, event_type="investigation.model.failed", actor_type="agent", actor_id="l1", entity_type="investigation", entity_id=investigation_id,
            outcome="failure", details={"model_id": row.model_id, "error": "AI provider returned HTTP 404", "candidate_index": 0})
        db.commit()
    response = client.get(f"/api/v1/agent/investigations/{investigation_id}/diagnosis")
    assert response.status_code == 200, response.text
    result = response.json(); assert result["diagnostic"]["code"] == "batch_model_not_interactive"
    assert result["diagnostic"]["upstream_status"] == 404
    assert result["repair"]["proposed_model_name"] == "example/reasoner"
    assert result["evidence"][0]["audit_event_id"]
    assert not result["configuration_changed"] and not result["model_inference_performed"]
    assert client.get(f"/api/v1/agent/investigations/{investigation_id}").json()["escalation_reason"] == "Reasoner failed: ControlPlaneHTTPError"
    assert client.post(f"/api/v1/agent/investigations/{investigation_id}/repair-retry", json={"actor": "l1"}).status_code == 409
    repaired = configure(client, connection, model_id="example/no-tools", replace_existing_routes=True)
    assert repaired.status_code == 200, repaired.text
    retried = client.post(f"/api/v1/agent/investigations/{investigation_id}/repair-retry", json={"actor": "l1"})
    assert retried.status_code == 201, retried.text
    assert retried.json()["id"] != investigation_id
    assert retried.json()["objective"] == created.json()["objective"]
    assert retried.json()["scope"] == created.json()["scope"]
    assert retried.json()["model_id"] == repaired.json()["model"]["id"]
    assert client.get(f"/api/v1/agent/investigations/{investigation_id}").json()["status"] == "escalated"


@pytest.mark.parametrize("status", [401, 402, 403, 404, 429, 500])
def test_provider_diagnostic_never_echoes_untrusted_secret_or_prompt(status):
    result = provider_diagnostic(status, json.dumps({"error": {"message": KEY + " private-device-data"}}).encode())
    assert KEY not in json.dumps(result) and "private-device-data" not in json.dumps(result)
    assert result["upstream_status"] == status and result["recommendation"]


@pytest.mark.parametrize("batch", [False, True])
def test_real_remote_worker_escalates_specific_failure_without_control_plane_500(client, managed_key, provider_network, monkeypatch, batch):
    from icheck.agent_schemas import AgentExecutionAssignment
    from icheck.agent_worker import execute_remote_assignment
    from test_agent_execution import register_worker, bearer, APIAgentControlClient
    connection = connect(client); configured = configure(client, connection).json()
    row = client.post("/api/v1/agent/investigations", json={"title": "Specific failure", "objective": "Read inventory", "created_by": "operator"}).json()
    assert client.post(f"/api/v1/agent/investigations/{row['id']}/start", json={"actor": "operator"}).status_code == 200
    worker = register_worker(client, "failure-fixture")
    claimed = client.post(f"/api/v1/agent/workers/{worker['worker']['id']}/executions/claim", headers=bearer(worker["access_token"]), json={"max_assignments": 1, "lease_seconds": 60})
    assignment = AgentExecutionAssignment.model_validate(claimed.json()[0])
    requests = []
    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            raise HTTPError(request.full_url, 404, KEY, {}, BytesIO(json.dumps({"error": {"message": KEY}}).encode()))
    monkeypatch.setattr("icheck.services.model_reasoner.build_opener", lambda *_: Opener())
    if batch:
        with namespace_session() as db:
            db.get(AIModelConfig, configured["model"]["id"]).model_name = "example/reasoner:batch"; db.commit()
    execute_remote_assignment(APIAgentControlClient(client, worker["access_token"]), assignment,
        lease_seconds=60, credential_broker=None, mcp_allowed_hosts=[])
    result = client.get(f"/api/v1/agent/investigations/{row['id']}").json()
    assert result["status"] == "escalated" and result["tool_calls_used"] == 0
    assert "ControlPlaneHTTPError" not in result["escalation_reason"] and KEY not in result["escalation_reason"]
    assert ("Batch-only" if batch else "eligible inference endpoint") in result["escalation_reason"]
    assert len(requests) == (0 if batch else 1)
    diagnosis = client.get(f"/api/v1/agent/investigations/{row['id']}/diagnosis").json()
    assert diagnosis["diagnostic"]["code"] == ("batch_model_not_interactive" if batch else "provider_endpoint_unavailable")
    assert KEY not in client.get("/api/v1/audit-events").text


def test_lifecycle_browser_requires_csrf_and_service_tokens_cannot_approve(client, managed_key, required_auth):
    _, headers = bootstrap(client)
    connection = client.post("/api/v1/ai/openrouter/connections", headers=headers, json={"name": "openrouter", "api_key": KEY, "approve_outbound": True}).json()
    url = f"/api/v1/ai/catalog/providers/{connection['provider_id']}/lifecycle/preview"
    csrf = login(client).json()["csrf_token"]
    assert client.post(url, json={"enabled": False}).status_code == 403
    assert client.post(url, headers={"X-Icheck-CSRF-Token": csrf}, json={"enabled": False}).status_code == 200
    client.cookies.clear()
    service = client.post("/api/v1/auth/principals", headers=headers, json={"subject": "service", "display_name": "Service", "principal_type": "service"}).json()
    role = next(r for r in client.get("/api/v1/auth/roles", headers=headers).json() if r["name"] == "admin")
    assert client.post(f"/api/v1/auth/principals/{service['id']}/bindings", headers=headers, json={"role_id": role["id"], "scope": {"all": True}}).status_code == 201
    token = client.post(f"/api/v1/auth/principals/{service['id']}/tokens", headers=headers, json={"name": "service", "expires_in_hours": 1}).json()["access_token"]
    assert client.post(url, headers={"Authorization": "Bearer " + token}, json={"enabled": False}).status_code == 403
