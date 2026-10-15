"""One focused Grafana path plus its secret/authority/concurrency boundaries."""
from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select

from icheck.auth import current_principal
from icheck.builtin_agent_tools import ensure_builtin_agent_tools
from icheck.config import get_settings
from icheck.database import SessionLocal
from icheck.grafana_client import decrypt_token, GrafanaConflict, GrafanaOutcomeUnknown
from icheck.main import app
from icheck.models import AgentToolRegistration, GrafanaChange, GrafanaConnection
from icheck.schema_validation import validate_instance
from icheck.services import grafana
from icheck.services.agent_tools import execute_internal_tool
from icheck.services.agent_authorization import tool_advertisement_allows
from icheck.services.control_plane_auth import development_principal
from test_monitoring_enrollments import seeded

TOKEN = "unit-test-grafana-private-token"


@pytest.mark.parametrize("query_samples", [False, True, "grafana"])
def test_model_loop_retains_connection_context_across_metric_discovery(integration, monkeypatch, query_samples):
    from langgraph.checkpoint.memory import InMemorySaver
    from icheck.models import Investigation, InvestigationToolCall
    from icheck.services.agent_graph import run_database_investigation
    from icheck.services.model_reasoner import OpenAICompatibleReasoner
    from test_agent_graph_integration import _configure_route, FakeChatResponse
    from test_builtin_agent_tools import FakePrometheusOpener
    client, conn, fake = integration
    _configure_route(client)
    backend = client.post("/api/v1/metrics/backends", json={"name": "platform-prometheus", "provider": "prometheus",
        "query_base_url": "https://prometheus.example.test", "created_by": "fixture"})
    assert backend.status_code == 201, backend.text
    metric_requests = []
    monkeypatch.setattr("icheck.services.metrics.build_opener", lambda *args: FakePrometheusOpener(metric_requests))
    created = client.post("/api/v1/agent/investigations", json={"title":"Remember discovered connection",
        "objective":"Propose a platform dashboard using discovered metrics", "scope":{"capability_task":"grafana-dashboard"},
        "created_by":"operator"})
    assert created.status_code == 201, created.text
    identity = created.json()["id"]
    assert client.post(f"/api/v1/agent/investigations/{identity}/start", json={"actor":"operator"}).status_code == 200

    class Wire:
        requests = []
        def open(self, request, timeout):
            payload = json.loads(request.data)
            state = json.loads(payload["messages"][1]["content"])["investigation"]
            self.requests.append(state)
            if len(self.requests) == 1:
                name, args = "grafana.connections.list", {}
            elif len(self.requests) == 2:
                connection_id = state["tool_results"][0]["result"]["connections"][0]["id"]
                name, args = "grafana.metrics.discover", {"connection_id":connection_id, "filter":"up", "limit":20}
            elif query_samples == "grafana" and len(self.requests) == 3:
                retained = state["retained_tool_results"]["items"]
                connection = retained[0]["result"]["connections"][0]
                assert "grafana.metrics.query" in retained[0]["result"]["metric_query_guidance"]
                name, args = "grafana.metrics.query", {"connection_id": connection["id"], "query": "up"}
            elif query_samples is True and len(self.requests) == 3:
                retained = state["retained_tool_results"]["items"]
                assert "metrics.backends.list" in retained[0]["result"]["metric_query_guidance"]
                name, args = "metrics.backends.list", {}
            elif query_samples is True and len(self.requests) == 4:
                discovered = state["tool_results"][0]["result"]["backends"]
                assert len(discovered) == 1 and discovered[0]["backend_id"] == backend.json()["id"]
                name, args = "metrics.query_instant", {"backend_id": discovered[0]["backend_id"], "query": "up"}
            else:
                assert len(self.requests) == (4 if query_samples == "grafana" else 5 if query_samples else 3)
                assert state["tool_results"][0]["tool_name"] == ("grafana.metrics.query" if query_samples == "grafana" else "metrics.query_instant" if query_samples else "grafana.metrics.discover")
                retained = state["retained_tool_results"]["items"]
                assert len(retained) == (2 if query_samples == "grafana" else 3 if query_samples else 1)
                history = {item["tool_name"]: item["result"] for item in retained}
                connection = history["grafana.connections.list"]["connections"][0]
                assert connection["id"] == conn["id"]
                observed = history["grafana.metrics.discover"] if query_samples else state["tool_results"][0]["result"]
                assert "up" in observed["metrics"]
                name, args = "grafana.dashboard.preview", {"connection_id":connection["id"], "definition":definition()}
            return FakeChatResponse({"choices":[{"message":{"content":json.dumps({"action":"continue",
                "tool_requests":[{"tool_name":name,"arguments":args,"purpose":"Use observed context without repeating discovery"}]})}}],
                "usage":{"total_tokens":11}})

    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        run = db.get(Investigation, identity)
        # Isolated fixture budget only; never changes an installed model route.
        run.max_iterations = run.max_tool_calls = 6
        db.commit()
        wire = Wire()
        reasoner = OpenAICompatibleReasoner(db, run, opener=wire)
        assert "metrics.backends.list" in {tool["name"] for tool in reasoner.tool_catalog}
        advertised = next(tool for tool in reasoner.tool_catalog if tool["name"] == "grafana.dashboard.preview")
        display = advertised["input_schema"]["properties"]["definition"]["properties"]
        assert display["time"]["required"] == ["from", "to"] and display["refresh"]["type"] == "string"
        result = run_database_investigation(db, run, reasoner=reasoner,
            checkpointer=InMemorySaver())
        steps = 4 if query_samples == "grafana" else 5 if query_samples else 3
        assert result["status"] == "completed" and len(wire.requests) == steps
        assert result["tool_calls_used"] == steps and result["tokens_used"] == steps * 11
        assert len(db.scalars(select(InvestigationToolCall).where(InvestigationToolCall.investigation_id == identity)).all()) == steps
        assert len(metric_requests) == int(query_samples is True)
        assert fake.writes == [], "Only a reviewed local proposal, never a Grafana mutation"


@pytest.mark.parametrize("oversized", [False, True])
def test_retained_model_context_is_bounded_and_cannot_borrow_other_calls(integration, oversized):
    from icheck.models import Investigation, InvestigationToolCall
    from icheck.services.model_reasoner import OpenAICompatibleReasoner, MAX_RETAINED_TOOL_CONTEXT_BYTES
    from test_agent_graph_integration import _configure_route
    client, _, _ = integration
    _configure_route(client)
    def create():
        row = client.post("/api/v1/agent/investigations", json={"title":"Context boundary",
            "objective":"Read only this investigation's observations", "created_by":"operator"})
        assert row.status_code == 201, row.text
        return row.json()["id"]
    own, foreign = create(), create()
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        tools = {tool.name:tool for tool in db.scalars(select(AgentToolRegistration)).all()}
        visible = tools["grafana.metrics.discover"]
        excluded = tools["grafana.connections.list"]
        actor = db.get(Investigation, own)
        reasoner = OpenAICompatibleReasoner(db, actor, tool_allowlist={visible.name})
        def call(i, *, run=own, tool=visible, iteration=1, status="succeeded"):
            row = InvestigationToolCall(investigation_id=run, tool_id=tool.id, iteration=iteration,
                call_hash=f"{i:064x}", arguments={"filter":"a" * 20000 if oversized else "up"}, status=status,
                result={"value":"x" * 20000 if oversized else "up"})
            db.add(row); db.flush()
            return row.id
        keep = [call(i) for i in range(18)]
        foreign_id = call(100, run=foreign)
        excluded_id = call(101, tool=excluded)
        future_id = call(102, iteration=3)
        unfinished = call(103, status="running")
        uncheckpointed = call(104)
        db.commit()
        state = {"tool_results":[{"call_id":keep[-1]}], "iteration":2,
            "tool_call_ids":[*keep, foreign_id, excluded_id, future_id, unfinished]}
        context = reasoner._retained_tool_context(state)
        ids = {item["call_id"] for item in context["items"]}
        assert len(ids) == 16 and context["truncated"]
        assert ids.issubset(keep) and not ids.intersection({foreign_id, excluded_id, future_id, unfinished, uncheckpointed, keep[-1]})
        assert len(json.dumps(context, ensure_ascii=True).encode()) <= MAX_RETAINED_TOOL_CONTEXT_BYTES
        if oversized:
            assert all(item["result_omitted"] and item["arguments_omitted"] for item in context["items"])
            assert all(item["result"] is None and item["arguments"] is None for item in context["items"])
        visible.enabled = False
        db.commit()
        assert reasoner._retained_tool_context(state) == {"items":[], "truncated":False}


def test_dashboard_preview_finishes_database_graph_without_an_extra_model_call(integration):
    from langgraph.checkpoint.memory import InMemorySaver
    from icheck.langgraph_runtime import GraphDecision, GraphToolRequest
    from icheck.models import Investigation, InvestigationCheckpoint, InvestigationToolCall
    from icheck.services.agent_graph import run_database_investigation
    from test_agent_graph_integration import _configure_route

    client, conn, fake = integration
    _configure_route(client)
    response = client.post("/api/v1/agent/investigations", json={
        "title": "Preview one dashboard", "objective": "Prepare a dashboard for my review",
        "scope": {"capability_task": "grafana-dashboard"}, "created_by": "operator"})
    assert response.status_code == 201, response.text
    identifier = response.json()["id"]
    assert client.post(f"/api/v1/agent/investigations/{identifier}/start", json={"actor": "operator"}).status_code == 200
    reasons = []

    def reasoner(state):
        reasons.append(state["iteration"])
        assert len(reasons) == 1, "Native preview must finish without another inference"
        return GraphDecision(action="continue", token_usage=17, tool_requests=[GraphToolRequest(
            tool_name="grafana.dashboard.preview", purpose="Create a reviewable proposal",
            arguments={"connection_id": conn["id"], "definition": definition()})])

    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        investigation = db.get(Investigation, identifier)
        saver = InMemorySaver()
        result = run_database_investigation(db, investigation, reasoner=reasoner, checkpointer=saver)
        db.refresh(investigation)
        assert result["status"] == investigation.status == "completed"
        assert result["tokens_used"] == 17 and result["iteration"] == 1
        change_id = result["structured_output"]["change_ids"][0]
        assert db.get(GrafanaChange, change_id).status == "proposed"
        assert result["structured_output"]["applied"] is False
        assert f"/dashboards?change={change_id}" in result["conclusion"]
        assert "not been applied" in result["conclusion"]
        call = db.scalar(select(InvestigationToolCall).where(InvestigationToolCall.investigation_id == identifier))
        assert call.status == "succeeded" and result["tool_call_ids"] == [call.id]
        checkpoints = db.scalars(select(InvestigationCheckpoint).where(InvestigationCheckpoint.investigation_id == identifier)).all()
        assert any(row.state["status"] == "completed" for row in checkpoints)
        assert saver.get_tuple({"configurable": {"thread_id": identifier}}) is not None
    assert fake.writes == [], "Preview completion must not save anything to Grafana"


@pytest.mark.parametrize("defect", ["mcp", "other-tool", "workflow", "skill", "ordinary", "folder", "applied", "foreign-link", "malformed"])
def test_preview_completion_is_only_minted_for_native_studio_dashboard(integration, defect):
    from icheck.services.agent_tools import _grafana_preview_completion
    client, conn, _ = integration
    proposal = propose(client, conn)
    actor = SimpleNamespace(scope={"capability_task": "grafana-dashboard"}, workflow_snapshot=None, skill_artifact_version_id=None)
    tool = SimpleNamespace(name="grafana.dashboard.preview", handler="grafana.dashboard.preview", transport="internal", read_only=True)
    if defect == "mcp": tool.transport = "mcp"
    elif defect == "other-tool": tool.name = tool.handler = "example.external"
    elif defect == "workflow": actor.workflow_snapshot = {"version": 1}
    elif defect == "skill": actor.skill_artifact_version_id = "bound-skill"
    elif defect == "ordinary": actor.scope = {}
    elif defect == "folder": proposal["resource_kind"] = "folder"
    elif defect == "applied": proposal["status"] = "applied"
    elif defect == "foreign-link": proposal["review_url"] = "https://outside.test/"
    elif defect == "malformed": proposal = {"task_completion": {"change_id": proposal["id"]}}
    assert _grafana_preview_completion(actor, tool, proposal) is None


class FakeGrafana:
    def __init__(self):
        self.resources = {("folder", "icheck"): {"metadata": {"name": "icheck", "resourceVersion": "1",
            "annotations": {}}, "spec": {"title": "iCheck"}}}
        self.writes = []
        self.lose_response = False

    def __call__(self, connection):
        self.connection = connection
        return self

    def metrics(self, _):
        return ["up", "ifOperStatus", "ifHCInOctets"]

    def health(self, _):
        return {"version": "13.2.3", "database": "ok", "datasource_status": "OK"}

    def query(self, datasource_uid, query, limit):
        assert datasource_uid == self.connection.datasource_uid
        return {"status": "success", "data": {"resultType": "vector", "result": [
            {"metric": {"__name__": "up", "job": "prometheus", "username": "private-label"}, "value": [1791900000, "1"]}
        ]}}

    def resource(self, kind, uid):
        return deepcopy(self.resources.get((kind, uid)))

    def list_resources(self, kind, limit):
        return {"metadata": {}, "items": [deepcopy(item) for (k, _), item in self.resources.items() if k == kind][:limit]}

    def save(self, kind, document, *, existing):
        uid = document["metadata"]["name"]
        old = self.resources.get((kind, uid))
        if existing and (old is None or old["metadata"]["resourceVersion"] != document["metadata"]["resourceVersion"]):
            raise GrafanaConflict("Version conflict")
        if not existing and old is not None:
            raise GrafanaConflict("UID conflict")
        result = deepcopy(document)
        result["metadata"]["resourceVersion"] = str(int(old["metadata"]["resourceVersion"]) + 1 if old else 1)
        self.resources[(kind, uid)] = result
        self.writes.append((kind, uid))
        if self.lose_response:
            raise GrafanaOutcomeUnknown("Injected response loss")
        return result


@pytest.fixture
def integration(client, tmp_path, monkeypatch):
    key = tmp_path / "key"
    key.write_bytes(b"g" * 32)
    key.chmod(0o400)
    monkeypatch.setenv("ICHECK_GRAFANA_SECRET_KEY_FILE", str(key))
    get_settings.cache_clear()
    fake = FakeGrafana()
    monkeypatch.setattr(grafana, "CLIENT", fake)
    response = client.post("/api/v1/grafana/connections", json={"name": "native",
        "public_url": "https://icheck.test/grafana/", "token": TOKEN, "shared_dataset_acknowledged": True})
    assert response.status_code == 201, response.text
    yield client, response.json(), fake
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def definition(title="Observed metrics"):
    return {"title": title, "schemaVersion": 41, "panels": [{"id": 1, "title": "Target scrape state",
        "type": "timeseries", "datasource": {"type": "prometheus", "uid": "icheck-prometheus"},
        "targets": [{"refId": "A", "expr": "up", "range": True}], "gridPos": {"x": 0, "y": 0, "w": 12, "h": 8}}]}


def propose(client, connection, spec=None, **extra):
    response = client.post(f"/api/v1/grafana/connections/{connection['id']}/preview",
        json={"definition": spec or definition(), **extra})
    assert response.status_code == 201, response.text
    return response.json()


def apply(client, proposal):
    return client.post(f"/api/v1/grafana/changes/{proposal['id']}/confirm",
        json={"expected_plan_hash": proposal["plan_hash"], "confirm": True})


@pytest.mark.parametrize("protocol,plugin", [("snmp","snmp"), ("https_api","http"),
    ("node_exporter","linux"), ("windows_exporter","windows"), ("cadvisor","containers"), ("vmware_exporter","vmware")])
def test_saved_target_links_use_confirmed_native_dashboards_without_network_calls(integration, monkeypatch, protocol, plugin):
    client, conn, fake = integration
    device, target, _, _ = seeded(client, protocol=protocol)
    path = f"/api/v1/grafana/devices/{device['id']}/dashboards?from=1791870000000&to=1791871800000"
    proposal = propose(client, conn, resource_uid=f"icheck-{plugin}-{target['id'].replace('-', '')}")
    assert client.get(path).json()["dashboards"] == []  # A preview is not a saved dashboard.
    assert apply(client, proposal).json()["status"] == "applied"
    # Saved navigation must not call Grafana, Prometheus or a device.
    monkeypatch.setattr(grafana, "CLIENT", lambda *_: pytest.fail("Unexpected remote navigation lookup"))
    response = client.get(path)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    links = response.json()["dashboards"]
    assert len(links) == 1 and links[0]["change_id"] == proposal["id"]
    assert links[0]["protocol"] == protocol and TOKEN not in response.text
    assert parse_qs(urlsplit(links[0]["url"]).query) == {"from":["1791870000000"], "to":["1791871800000"],
        "var-device":[device["id"]], "var-connection":[target["id"]]}
    from icheck.models import DeviceConnection
    with SessionLocal() as db:
        db.get(DeviceConnection, target["id"]).enabled = False
        db.commit()
    assert client.get(path).json()["dashboards"][0]["connection_enabled"] is False
    assert client.get(path.replace("1791870000000", "javascript:bad")).status_code == 400
    assert client.get("/api/v1/grafana/devices/missing/dashboards").status_code == 404
    scoped = replace(development_principal(), authorization_scope={"sites":["LAB"]})
    app.dependency_overrides[current_principal] = lambda: scoped
    assert client.get(path).status_code == 403


def test_create_revision_restore_is_one_retained_confirmed_path(integration):
    client, conn, fake = integration
    initial = {**definition(), "time": {"from": "now-1h", "to": "now"}, "refresh": "30s", "timezone": "utc"}
    first = propose(client, conn, initial)
    assert fake.writes == [] and first["status"] == "proposed"
    result = apply(client, first)
    assert result.status_code == 200, result.text
    saved = result.json()
    assert saved["status"] == "applied" and saved["resource_url"].startswith("https://icheck.test/grafana/d/")
    updated = {**definition("Revised title"), "time": {"from": "now-2h", "to": "now-1h"}, "refresh": "", "timezone": "browser"}
    revised = propose(client, conn, updated, resource_uid=saved["resource_uid"],
        expected_resource_version=saved["applied_resource"]["metadata"]["resourceVersion"])
    assert revised["previous_resource"]["spec"]["title"] == "Observed metrics"
    assert apply(client, revised).json()["status"] == "applied"
    for field in ("time", "refresh", "timezone"):
        assert saved["applied_resource"]["spec"][field] == initial[field]
        assert revised["definition"][field] == updated[field]
        assert revised["previous_resource"]["spec"][field] == initial[field]
        assert fake.resources[("dashboard", first["resource_uid"])]["spec"][field] == updated[field]
    restore = client.post(f"/api/v1/grafana/changes/{revised['id']}/restore-preview")
    assert restore.status_code == 201, restore.text
    assert len(fake.writes) == 2
    assert apply(client, restore.json()).json()["status"] == "applied"
    assert fake.resources[("dashboard", first["resource_uid"])]["spec"]["title"] == "Observed metrics"
    for field in ("time", "refresh", "timezone"):
        assert restore.json()["definition"][field] == initial[field]
        assert fake.resources[("dashboard", first["resource_uid"])]["spec"][field] == initial[field]
    assert len(fake.writes) == 3


@pytest.mark.parametrize("setting", [
    {"time": None}, {"time": {"from": "now-1h"}}, {"time": {"from": 123, "to": "now"}},
    {"time": {"from": "now-1h\n", "to": "now"}}, {"refresh": False}, {"timezone": ["utc"]},
])
def test_display_setting_shapes_are_rejected_before_native_writes(integration, setting):
    client, conn, fake = integration
    response = client.post(f"/api/v1/grafana/connections/{conn['id']}/preview", json={"definition": {**definition(), **setting}})
    assert response.status_code == 400 and fake.writes == []
    assert TOKEN not in response.text


def test_optional_native_display_settings_do_not_invent_defaults(integration):
    client, conn, _ = integration
    plain = propose(client, conn)
    assert "time" not in plain["definition"] and "refresh" not in plain["definition"]
    absolute = {"from": "2026-10-13T00:00:00.000Z", "to": "2026-10-13T01:00:00.000Z"}
    selected = propose(client, conn, {**definition(), "time": absolute, "refresh": "", "timezone": "Asia/Shanghai"})
    assert selected["definition"]["time"] == absolute and selected["definition"]["refresh"] == ""


def test_connection_tokens_are_encrypted_write_only_and_validation_never_echoes_them(integration):
    client, conn, _ = integration
    assert TOKEN not in json.dumps(conn) and conn["token_configured"]
    with SessionLocal() as db:
        row = db.get(GrafanaConnection, conn["id"])
        assert TOKEN.encode() not in row.encrypted_token
        assert decrypt_token(row) == TOKEN
    bad = client.post("/api/v1/grafana/connections", json={"public_url": "https://icheck.test/grafana/",
        "token": TOKEN, "shared_dataset_acknowledged": True, "password": "other-private-value"})
    assert bad.status_code == 422
    assert TOKEN not in bad.text and "other-private-value" not in bad.text
    assert bad.headers["cache-control"] == "no-store"


def test_stale_plan_and_remote_edits_cannot_be_overwritten(integration):
    client, conn, fake = integration
    initial = propose(client, conn)
    wrong = client.post(f"/api/v1/grafana/changes/{initial['id']}/confirm",
        json={"expected_plan_hash": "0" * 64, "confirm": True})
    assert wrong.status_code == 409 and fake.writes == []
    saved = apply(client, initial).json()
    proposed = propose(client, conn, definition("Planned edit"), resource_uid=initial["resource_uid"],
        expected_resource_version=saved["applied_resource"]["metadata"]["resourceVersion"])
    remote = fake.resources[("dashboard", initial["resource_uid"])]
    remote["metadata"]["resourceVersion"] = "99"
    remote["spec"]["title"] = "User edited in Grafana"
    assert apply(client, proposed).status_code == 409
    assert remote["spec"]["title"] == "User edited in Grafana" and len(fake.writes) == 1


def test_response_loss_is_reconciled_by_read_without_a_duplicate_write(integration):
    client, conn, fake = integration
    plan = propose(client, conn)
    fake.lose_response = True
    result = apply(client, plan)
    assert result.json()["status"] == "unknown" and len(fake.writes) == 1
    # The same UID and owned change annotation identify the committed remote write.
    reconciled = apply(client, plan)
    assert reconciled.json()["status"] == "applied" and len(fake.writes) == 1
    assert apply(client, plan).json()["status"] == "applied" and len(fake.writes) == 1


def test_unresolved_response_loss_never_blindly_retries(integration):
    client, conn, fake = integration
    plan = propose(client, conn)
    fake.lose_response = True
    assert apply(client, plan).json()["status"] == "unknown"
    fake.resources.pop(("dashboard", plan["resource_uid"]))
    assert apply(client, plan).json()["status"] == "unknown" and len(fake.writes) == 1


@pytest.mark.parametrize("mutation", ["unknown_metric", "wrong_source", "unsafe_panel", "invalid_query", "secret_link", "constant", "credential_parameter", "reserved_variable", "variable_source"])
def test_dashboard_validation_rejects_unsafe_or_invented_data(integration, mutation):
    client, conn, fake = integration
    spec = definition()
    if mutation == "unknown_metric": spec["panels"][0]["targets"][0]["expr"] = "invented_vendor_temperature"
    if mutation == "wrong_source": spec["panels"][0]["datasource"]["uid"] = "unapproved-source"
    if mutation == "unsafe_panel": spec["panels"][0]["type"] = "arbitrary-html-plugin"
    if mutation == "invalid_query": spec["panels"][0]["targets"][0]["expr"] = "rate("
    if mutation == "secret_link": spec["links"] = [{"url": "https://outside.test/?token=secret"}]
    if mutation == "constant": spec["panels"][0]["targets"][0]["expr"] = "vector(1)"
    if mutation == "credential_parameter": spec["links"] = [{"url": "/grafana/d/x?var-token=not-a-dashboard-variable"}]
    if mutation == "reserved_variable": spec["templating"] = {"list": [{"name": "password", "type": "constant", "query": "no"}]}
    if mutation == "variable_source": spec["templating"] = {"list": [{"name": "device", "type": "query", "query": "label_values(up, instance)", "datasource": {"type": "prometheus", "uid": "other"}}]}
    response = client.post(f"/api/v1/grafana/connections/{conn['id']}/preview", json={"definition": spec})
    assert response.status_code == 400 and fake.writes == []


def test_folder_create_and_revision_use_the_same_confirmation(integration):
    client, conn, fake = integration
    first = propose(client, conn, {"title": "Network"}, resource_kind="folder")
    saved = apply(client, first).json()
    assert saved["status"] == "applied" and "/dashboards/f/" in saved["resource_url"]
    revised = propose(client, conn, {"title": "Network team"}, resource_kind="folder", resource_uid=first["resource_uid"],
                      expected_resource_version=saved["applied_resource"]["metadata"]["resourceVersion"])
    assert apply(client, revised).json()["status"] == "applied"
    assert fake.resources[("folder", first["resource_uid"])]["spec"]["title"] == "Network team"


def test_folder_depth_is_bounded_but_dashboards_can_use_a_managed_child(integration):
    client, conn, fake = integration
    folder = apply(client, propose(client, conn, {"title": "Network"}, resource_kind="folder")).json()
    child = folder["resource_uid"]
    response = client.post(f"/api/v1/grafana/connections/{conn['id']}/preview", json={
        "resource_kind": "folder", "folder_uid": child, "definition": {"title": "Too deep"}})
    assert response.status_code == 400 and len(fake.writes) == 1
    dashboard = propose(client, conn, folder_uid=child)
    assert apply(client, dashboard).json()["status"] == "applied"


def test_global_reader_can_propose_but_only_human_manager_can_confirm(integration):
    client, conn, fake = integration
    plan = propose(client, conn)
    reader = replace(development_principal(), permissions=frozenset({"metrics.read"}))
    app.dependency_overrides[current_principal] = lambda: reader
    assert client.get("/api/v1/grafana/changes").status_code == 200
    assert apply(client, plan).status_code == 403
    service = replace(development_principal(), principal_type="service", auth_method="bearer")
    app.dependency_overrides[current_principal] = lambda: service
    assert apply(client, plan).status_code == 403
    scoped = replace(reader, authorization_scope={"sites": ["LAB"]})
    app.dependency_overrides[current_principal] = lambda: scoped
    assert client.get("/api/v1/grafana/connections").status_code == 403
    assert fake.writes == []


def test_rotation_invalidates_pending_proposal_without_changing_dashboards(integration):
    client, conn, fake = integration
    plan = propose(client, conn)
    response = client.put(f"/api/v1/grafana/connections/{conn['id']}", json={"expected_revision": 1,
        "enabled": True, "token": "new-unit-test-grafana-private-token"})
    assert response.status_code == 200 and response.json()["revision"] == 2
    assert apply(client, plan).status_code == 409 and fake.writes == []


def test_tools_use_the_existing_registry_and_create_only_a_local_proposal(integration):
    _, conn, fake = integration
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        tool = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == "grafana.dashboard.preview"))
        result, _ = execute_internal_tool(db, tool, {"connection_id": conn["id"], "definition": definition()})
        validate_instance(result, tool.output_schema, "Grafana proposal")
        assert result["status"] == "proposed" and fake.writes == []
        assert db.get(GrafanaChange, result["id"]) is not None


def test_native_tool_guidance_types_panel_ids_sources_and_variables():
    from icheck.grafana_tools import GRAFANA_TOOLS
    schema = next(row for row in GRAFANA_TOOLS if row["name"] == "grafana.dashboard.preview")["input_schema"]
    good = {"connection_id":"connection", "definition":definition()}
    validate_instance(good, schema, "Native Grafana tool")
    for mutation in ("id", "source", "variable"):
        payload = deepcopy(good)
        if mutation == "id": payload["definition"]["panels"][0]["id"] = "1"
        if mutation == "source": payload["definition"]["panels"][0]["datasource"]["type"] = "other"
        if mutation == "variable": payload["definition"]["templating"] = {"list":[{"name":"source", "type":"datasource"}]}
        with pytest.raises(ValueError): validate_instance(payload, schema, "Native Grafana tool")
    validate_instance({"connection_id":"connection", "resource_kind":"folder", "definition":{"title":"Operations"}}, schema, "Folder tool")
    fields = schema["properties"]["definition"]["properties"]
    assert fields["time"]["required"] == ["from", "to"]
    assert 'empty string' in fields["refresh"]["description"]
    display = {"connection_id":"connection", "definition":{**definition(), "time":{"from":"now-1h", "to":"now"}, "refresh":""}}
    validate_instance(display, schema, "Explicit display settings")
    display["definition"]["refresh"] = None
    with pytest.raises(ValueError): validate_instance(display, schema, "Null is not off")


def test_metric_discovery_keeps_exact_name_ahead_of_truncated_substring_matches(integration, monkeypatch):
    _, conn, fake = integration
    monkeypatch.setattr(fake, "metrics", lambda _: ["up", "uptime_seconds", "unrelated"] +
        [f"prometheus_updates_{i}" for i in range(250)])
    with SessionLocal() as db:
        result, evidence = grafana.tools_for_ai("grafana.metrics.discover", db,
            {"connection_id":conn["id"], "filter":"up", "limit":20}, development_principal())
        assert result["metrics"][:2] == ["up", "uptime_seconds"]
        assert result["exact_match"] == "up" and result["truncated"] and result["match_count"] == 252
        assert len(result["metrics"]) == 20 and "do not repeat" in result["next_action"]
        assert fake.writes == [] and evidence == []
        missing, _ = grafana.tools_for_ai("grafana.metrics.discover", db,
            {"connection_id":conn["id"], "filter":"missing_metric", "limit":20}, development_principal())
        assert missing["metrics"] == [] and missing["exact_match"] is None and not missing["truncated"]
        assert "unavailable" in missing["next_action"]


def test_guarded_legacy_grafana_catalog_sync_preserves_customization(client):
    from deploy.sync_native_grafana_tool import sync_registration, LEGACY_DESCRIPTION
    from icheck.grafana_tools import GRAFANA_TOOLS, preview
    from icheck.database import set_session_namespace
    document = next(row for row in GRAFANA_TOOLS if row["name"] == "grafana.dashboard.preview")
    legacy = {**document["input_schema"], "properties":{**document["input_schema"]["properties"], "definition":preview["properties"]["definition"]}}
    with SessionLocal() as db:
        principal=development_principal(); set_session_namespace(db, principal.tenant_id, principal.region_id)
        ensure_builtin_agent_tools(db)
        row = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == document["name"]))
        identity = row.id
        row.input_schema, row.description = legacy, "Operator customized description"
        db.commit()
        with pytest.raises(ValueError, match="Customized"): sync_registration(db)
        assert row.description == "Operator customized description"
        row.description = LEGACY_DESCRIPTION; db.commit()
        assert sync_registration(db)["changed"] is True
        assert row.id == identity and row.input_schema == document["input_schema"]
        assert sync_registration(db)["changed"] is False


def test_guarded_typed_grafana_catalog_sync_preserves_disable_and_custom_fields(client):
    from deploy.sync_native_grafana_tool import sync_registration
    from icheck.grafana_tools import GRAFANA_TOOLS
    from icheck.grafana_schemas import DISPLAY_GUIDANCE, DISPLAY_PROPERTIES
    from icheck.database import set_session_namespace
    document = next(row for row in GRAFANA_TOOLS if row["name"] == "grafana.dashboard.preview")
    previous = deepcopy(document["input_schema"])
    for field in DISPLAY_PROPERTIES: previous["properties"]["definition"]["properties"].pop(field)
    with SessionLocal() as db:
        principal = development_principal(); set_session_namespace(db, principal.tenant_id, principal.region_id)
        ensure_builtin_agent_tools(db)
        row = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == document["name"]))
        identity = row.id
        row.input_schema = previous
        row.description = document["description"].removesuffix(DISPLAY_GUIDANCE)
        row.enabled = False
        db.commit()
        custom = deepcopy(previous); custom["properties"]["definition"]["properties"]["title"]["maxLength"] = 200
        row.input_schema = custom; db.commit()
        with pytest.raises(ValueError, match="Customized"): sync_registration(db)
        assert row.input_schema == custom and not row.enabled
        row.input_schema = previous; db.commit()
        assert sync_registration(db)["changed"] is True
        assert row.id == identity and row.input_schema == document["input_schema"] and not row.enabled
        assert sync_registration(db)["changed"] is False


@pytest.mark.parametrize("auth_method", ["browser_session", "bearer"])
def test_real_human_auth_methods_can_confirm(integration, auth_method):
    client, conn, _ = integration
    plan = propose(client, conn)
    actor = replace(development_principal(), subject="signed-in-admin", principal_type="user", auth_method=auth_method)
    app.dependency_overrides[current_principal] = lambda: actor
    assert apply(client, plan).json()["status"] == "applied"


def test_definition_can_use_observed_metric_variables_and_native_annotations(integration):
    client, conn, _ = integration
    spec = definition()
    spec["panels"][0]["targets"][0]["expr"] = 'up{instance=~"$instance"}'
    spec["templating"] = {"list": [{"name": "instance", "type": "query", "query": "label_values(up, instance)"}]}
    spec["annotations"] = {"list": [{"name": "Annotations & Alerts", "enable": True,
        "datasource": {"type": "grafana", "uid": "-- Grafana --"}, "type": "dashboard"}]}
    plan = propose(client, conn, spec)
    assert plan["definition"]["templating"]["list"][0]["datasource"]["uid"] == "icheck-prometheus"
    assert apply(client, plan).json()["status"] == "applied"


def test_agent_advertisement_cannot_expand_scope_or_substitute_grafana_contract(integration):
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        tool = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == "grafana.dashboard.preview"))
        actor = SimpleNamespace(permission_snapshot=["metrics.read"], authorization_scope={"all": True}, scope={})
        assert tool_advertisement_allows(actor, tool)
        actor.authorization_scope = {"sites": ["LAB"]}
        assert not tool_advertisement_allows(actor, tool)
        actor.authorization_scope = {"all": True}
        actor.permission_snapshot = []
        assert not tool_advertisement_allows(actor, tool)
        actor.permission_snapshot = ["metrics.read"]
        for field, value in [("handler", "quality.get_execution_health"), ("transport", "mcp"), ("read_only", False), ("change_contract", {})]:
            original = getattr(tool, field)
            setattr(tool, field, value)
            assert not tool_advertisement_allows(actor, tool)
            setattr(tool, field, original)


def test_dashboard_builder_scope_excludes_device_and_infrastructure_tools(integration):
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        actor = SimpleNamespace(permission_snapshot=["*"], authorization_scope={"all": True}, scope={"capability_task": "grafana-dashboard"})
        tools = {row.name: row for row in db.scalars(select(AgentToolRegistration)).all()}
        assert tool_advertisement_allows(actor, tools["grafana.dashboard.preview"])
        assert tool_advertisement_allows(actor, tools["metrics.query_instant"])
        assert tool_advertisement_allows(actor, tools["metrics.backends.list"])
        assert not tool_advertisement_allows(actor, tools["inventory.enroll_devices"])
        assert not tool_advertisement_allows(actor, tools["quality.get_execution_health"])


def test_metric_discovery_requires_owned_read_permission_even_with_custom_metadata(integration):
    from icheck.services.agent_authorization import require_tool_permissions
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        tool = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == "metrics.backends.list"))
        actor = SimpleNamespace(permission_snapshot=["metrics.read"], authorization_scope={"all": True}, scope={})
        assert tool_advertisement_allows(actor, tool)
        tool.required_permissions = []
        actor.permission_snapshot = []
        assert not tool_advertisement_allows(actor, tool)
        with pytest.raises(PermissionError, match="metrics.read"):
            require_tool_permissions(actor, tool)
        actor.permission_snapshot = ["metrics.read"]
        for field, value in [("handler", "metrics.query_instant"), ("transport", "mcp"), ("read_only", False), ("change_contract", {})]:
            original = getattr(tool, field)
            setattr(tool, field, value)
            assert not tool_advertisement_allows(actor, tool)
            setattr(tool, field, original)


def test_grafana_sample_query_uses_connection_not_backend_and_preserves_global_boundary(integration, monkeypatch):
    client, conn, fake = integration
    path = f"/api/v1/grafana/connections/{conn['id']}/metrics/query"
    response = client.post(path, json={"query": "up", "limit": 5})
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    result = response.json()
    assert result["connection_id"] == conn["id"] and result["datasource_uid"] == "icheck-prometheus"
    assert result["result"][0]["metric"] == {"__name__": "up", "job": "prometheus"}
    assert result["result"][0]["labels_omitted"] and "private-label" not in response.text
    assert "not source freshness" in result["warning"] and not result["truncated"]
    assert fake.writes == []
    monkeypatch.setattr(fake, "query", lambda *args: pytest.fail("Unauthorized/invalid query must not dispatch"))
    for query in ["invented_metric", "up{job=~\"$job\"}", "vector(1)", "rate("]:
        assert client.post(path, json={"query": query}).status_code == 400
    assert client.post(path, json={"query": "up", "limit": 101}).status_code == 422
    with SessionLocal() as db:
        ensure_builtin_agent_tools(db)
        tool = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == "grafana.metrics.query"))
        actor = SimpleNamespace(permission_snapshot=["metrics.read"], authorization_scope={"sites": ["LAB"]}, scope={})
        assert not tool_advertisement_allows(actor, tool)
    principal = development_principal()
    for denied in [replace(principal, permissions=frozenset()), replace(principal, authorization_scope={"sites": ["LAB"]})]:
        app.dependency_overrides[current_principal] = lambda denied=denied: denied
        assert client.post(path, json={"query": "up"}).status_code == 403
    app.dependency_overrides[current_principal] = lambda: replace(principal, tenant_id="foreign")
    assert client.post(path, json={"query": "up"}).status_code == 404


@pytest.mark.parametrize("case", ["empty", "truncated", "bad-row", "bad-value", "wrong-type"])
def test_grafana_sample_query_bounds_and_missing_evidence(integration, monkeypatch, case):
    client, conn, fake = integration
    samples = [{"metric": {"job": "prometheus"}, "value": [1791900000, "1"]}] * 3
    if case == "empty": samples = []
    if case == "bad-row": samples = [None]
    if case == "bad-value": samples = [{"metric": {}, "value": ["not-a-timestamp", "secret"]}]
    document = {"status": "success", "data": {"resultType": "matrix" if case == "wrong-type" else "vector", "result": samples}}
    monkeypatch.setattr(fake, "query", lambda *args: document)
    response = client.post(f"/api/v1/grafana/connections/{conn['id']}/metrics/query", json={"query": "up", "limit": 2})
    assert response.status_code == (200 if case in {"empty", "truncated"} else 400)
    if response.status_code == 200:
        assert response.json()["truncated"] is (case == "truncated")
        assert len(response.json()["result"]) == (2 if case == "truncated" else 0)
    assert fake.writes == []


def test_grafana_sample_transport_uses_fixed_read_route_and_query_budget(integration, monkeypatch):
    from icheck.grafana_client import GrafanaClient
    _, conn, _ = integration
    seen = []
    monkeypatch.setattr(GrafanaClient, "_request", lambda self, route, **kwargs: seen.append((route, kwargs)))
    with SessionLocal() as db:
        native = GrafanaClient(db.get(GrafanaConnection, conn["id"]))
        native.query("icheck-prometheus", 'up{job="prometheus"}', 20)
    route, kwargs = seen[0]
    assert urlsplit(route).path == "/api/datasources/proxy/uid/icheck-prometheus/api/v1/query"
    assert parse_qs(urlsplit(route).query) == {"query": ['up{job="prometheus"}'], "timeout": ["3s"], "limit": ["21"]}
    assert kwargs == {} and TOKEN not in route
