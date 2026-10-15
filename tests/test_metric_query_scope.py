from dataclasses import replace
import json
from urllib.parse import parse_qs

import promql_parser as promql
import pytest

from icheck.config import get_settings
from icheck.database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace
from icheck.metric_schemas import PrometheusInstantQuery
from icheck.models import Device, MetricBackend
from icheck.services.control_plane_auth import development_principal
from icheck.services.metric_query_scope import (
    DEVICE_LABEL, REGION_LABEL, TENANT_LABEL, MetricQueryAuthority,
    MetricScopeError, compile_scoped_query, query_authority,
)
from icheck.services.metrics import MetricQueryError, query_instant
from test_metrics import FakeResponse, create_metric_backend


def vector_selectors(query):
    selectors = []

    def visit(node):
        if isinstance(node, promql.VectorSelector):
            selectors.append(node)
        return True

    promql.walk(promql.parse(query), pre_visit=visit)
    return selectors


def selector_labels(query):
    """Fixture evaluator for a single selector; real evaluation has its own gate."""
    selector = vector_selectors(query)[0]
    labels = {m.name: m.value for m in selector.matchers.matchers if m.op == promql.MatchOp.Equal}
    if DEVICE_LABEL not in labels:
        for matcher in selector.matchers.matchers:
            if matcher.name == DEVICE_LABEL and matcher.op == promql.MatchOp.Re:
                labels[DEVICE_LABEL] = matcher.value.split("|")[0]
    return labels


@pytest.mark.parametrize("query,count", [
    ("up", 1), ('up{job="windows",instance=~".*"}', 1),
    ("sum(up) / count(up)", 2), ("up or node_cpu_seconds_total", 2),
    ("up unless node_cpu_seconds_total", 2),
    ("rate(node_cpu_seconds_total[5m])", 1),
    ("sum_over_time((up + node_cpu_seconds_total)[5m:30s])", 2),
    ("up @ 123.4 offset -1m", 1), ("up @ start() offset 1h", 1),
    ("up @ end()", 1),
    ('up * on(job,instance) group_left(site) target_info', 2),
    ('label_replace(up,"display","$1","job","(.*)")', 1),
    ('label_join(up,"display","-","job","instance")', 1),
    ('topk(scalar(count(up)), node_cpu_seconds_total)', 2),
    ("vector(1)", 0), ("time()", 0),
])
def test_all_selectors_are_qualified_before_evaluation(query, count):
    authority = MetricQueryAuthority("tenant-a", "region-a", 1, ("device-1", "device-2"))
    compiled = compile_scoped_query(query, authority)
    selectors = vector_selectors(compiled)
    assert len(selectors) == count
    for selector in selectors:
        actual = {(m.name, m.value, str(m.op)) for m in selector.matchers.matchers}
        assert (TENANT_LABEL, "tenant-a", str(promql.MatchOp.Equal)) in actual
        assert (REGION_LABEL, "region-a", str(promql.MatchOp.Equal)) in actual
        assert (DEVICE_LABEL, "device-1|device-2", str(promql.MatchOp.Re)) in actual


@pytest.mark.parametrize("query", [
    "info(up)", 'info(up,{__name__="target_info"})',
    'label_replace(up,"icheck_tenant_id","foreign","job",".*")',
    'label_join(up,"icheck_device_id","-","job","instance")',
    'up{site="a" or site="b"}', 'sum(up{private="sensitive-name"}',
])
def test_implicit_reads_authority_rewrites_and_unsupported_syntax_fail_closed(query):
    with pytest.raises(MetricScopeError) as error:
        compile_scoped_query(query, MetricQueryAuthority("t", "r", 1, None))
    assert "sensitive-name" not in str(error.value)


def test_empty_scope_excludes_unlabeled_series_and_conflicting_labels_are_conjoined():
    compiled = compile_scoped_query('up{icheck_tenant_id="foreign"}', MetricQueryAuthority("t", "r", 1, ()))
    matchers = vector_selectors(compiled)[0].matchers.matchers
    assert {(m.value, str(m.op)) for m in matchers if m.name == DEVICE_LABEL} == {
        ("", str(promql.MatchOp.Equal)), ("", str(promql.MatchOp.NotEqual)),
    }
    assert {m.value for m in matchers if m.name == TENANT_LABEL} == {"foreign", "t"}


@pytest.mark.parametrize("limit,value,query", [
    ("MAX_QUERY_NODES", 1, "sum(up)"),
    ("MAX_QUERY_SELECTORS", 1, "up or down"),
    ("MAX_COMPILED_BYTES", 20, "up"),
])
def test_scope_expansion_limits_refuse_instead_of_truncating(monkeypatch, limit, value, query):
    monkeypatch.setattr("icheck.services.metric_query_scope." + limit, value)
    with pytest.raises(MetricScopeError, match="limit"):
        compile_scoped_query(query, MetricQueryAuthority("t", "r", 1, ("d",)))


def test_utf8_input_byte_budget_and_regex_literal_device_ids():
    authority = MetricQueryAuthority("t", "r", 1, ("a+b", "a.b"))
    compiled = compile_scoped_query("up", authority)
    matcher = next(m for m in vector_selectors(compiled)[0].matchers.matchers if m.name == DEVICE_LABEL)
    assert matcher.value == r"a\+b|a\.b"
    with pytest.raises(MetricScopeError, match="byte limit"):
        compile_scoped_query('up{label="' + "\u754c" * 3000 + '"}', authority)
    with pytest.raises(MetricScopeError, match="valid UTF-8"):
        compile_scoped_query('up{label="\ud800"}', authority)


@pytest.mark.parametrize("value", [
    'quote"and\\backslash', r"a\+b|a\.b", "\u754c", "line\nbreak", "icheck_scope_literal_1",
])
def test_escaped_literals_and_marker_lookalikes_survive_ast_serialization(value):
    authority = MetricQueryAuthority("t", "r", 1, ("a+b",))
    compiled = compile_scoped_query('up{display=' + json.dumps(value, ensure_ascii=False) + '}', authority)
    labels = vector_selectors(compiled)[0].matchers.matchers
    assert next(m.value for m in labels if m.name == "display") == value
    query = 'label_replace(up,"destination",' + json.dumps(value, ensure_ascii=False) + ',"job","(.*)")'
    expression = promql.parse(compile_scoped_query(query, authority))
    assert expression.args[2].val == value


def _device(client, site="LAB"):
    response = client.post("/api/v1/devices", json={"name": "metric-" + site, "kind": "switch",
        "site": site, "management_ip": "198.18.1.1" if site == "LAB" else "198.18.1.2"})
    assert response.status_code == 201, response.text
    return response.json()


def test_current_device_scope_namespace_and_inventory_budget(client, monkeypatch):
    backend = create_metric_backend(client)
    own = _device(client)
    other = _device(client, "OTHER")
    principal = replace(development_principal(), authorization_scope={"sites": ["LAB"]})
    with SessionLocal() as db:
        row = db.get(MetricBackend, backend["id"])
        assert query_authority(db, row, principal).device_ids == (own["id"],)
        assert other["id"] not in query_authority(db, row, principal).device_ids
        monkeypatch.setattr("icheck.services.metric_query_scope.MAX_SCOPE_DEVICES", 0)
        with pytest.raises(MetricScopeError, match="narrow"):
            query_authority(db, row, principal)
        with pytest.raises(MetricScopeError, match="authenticated"):
            query_authority(db, row, None)
        set_session_namespace(db, "foreign", "foreign")
        with pytest.raises(MetricScopeError, match="session"):
            query_authority(db, row, principal)


@pytest.mark.parametrize("change", ["device_site", "backend_revision", "backend_disabled"])
def test_authority_changes_during_io_discard_results_and_record_only_failure(client, monkeypatch, change):
    backend = create_metric_backend(client)
    device = _device(client)
    principal = replace(development_principal(), authorization_scope={"sites": ["LAB"]})

    class ChangingOpener:
        def open(self, request, timeout):
            with SessionLocal() as owner:
                if change == "device_site": owner.get(Device, device["id"]).site = "OTHER"
                elif change == "backend_revision": owner.get(MetricBackend, backend["id"]).revision += 1
                else: owner.get(MetricBackend, backend["id"]).enabled = False
                owner.commit()
            return FakeResponse({"status": "success", "data": {"resultType": "vector",
                "result": [{"metric": {}, "value": [1, "99999"]}]}})

    monkeypatch.setattr("icheck.services.metrics.build_opener", lambda *_: ChangingOpener())
    with SessionLocal() as db:
        with pytest.raises(MetricQueryError, match="changed|disabled"):
            query_instant(db, db.get(MetricBackend, backend["id"]),
                PrometheusInstantQuery(query="sum(up)", actor="trusted-test"), principal=principal)
    events = client.get("/api/v1/audit-events", params={"event_type": "metrics.query.failed"}).json()
    assert len(events) == 1 and "99999" not in json.dumps(events)
    assert not client.get("/api/v1/audit-events", params={"event_type": "metrics.query.executed"}).json()


def test_authenticated_api_queries_use_current_site_scope_and_trusted_actor(client, monkeypatch):
    backend = create_metric_backend(client)
    own = _device(client)
    other = _device(client, "OTHER")
    requests = []

    class EmptyOpener:
        def open(self, request, timeout):
            requests.append(parse_qs(request.data.decode())["query"][0])
            return FakeResponse({"status": "success", "data": {"resultType": "vector", "result": []}})

    monkeypatch.setattr("icheck.services.metrics.build_opener", lambda *_: EmptyOpener())
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    try:
        bootstrap = client.post("/api/v1/auth/bootstrap", headers={
            "X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token"},
            json={"subject": "admin.metric", "display_name": "Metric Admin"})
        assert bootstrap.status_code == 201, bootstrap.text
        admin = {"Authorization": "Bearer " + bootstrap.json()["token"]["access_token"]}
        roles = client.get("/api/v1/auth/roles", headers=admin).json()
        role = next(r for r in roles if r["name"] == "operator")
        response = client.post("/api/v1/auth/principals", headers=admin,
            json={"subject": "site.metric", "display_name": "Site Reader"})
        assert response.status_code == 201, response.text
        principal = response.json()
        binding = client.post(f"/api/v1/auth/principals/{principal['id']}/bindings", headers=admin,
            json={"role_id": role["id"], "scope": {"sites": ["LAB"]}})
        assert binding.status_code == 201, binding.text
        token = client.post(f"/api/v1/auth/principals/{principal['id']}/tokens", headers=admin,
            json={"name": "metric-reader", "expires_in_hours": 24})
        assert token.status_code == 201, token.text
        headers = {"Authorization": "Bearer " + token.json()["access_token"]}
        path = f"/api/v1/metrics/backends/{backend['id']}/query"
        assert client.post(path, json={"query": "sum(up)", "actor": "forged-admin"}).status_code == 401
        response = client.post(path, headers=headers, json={"query": "sum(up) / count(up)", "actor": "forged-admin"})
        assert response.status_code == 200, response.text
        assert len(requests) == 1
        for selector in vector_selectors(requests[0]):
            actual = {m.name: m.value for m in selector.matchers.matchers}
            assert actual[TENANT_LABEL] == DEFAULT_TENANT_ID
            assert actual[REGION_LABEL] == DEFAULT_REGION_ID
            assert actual[DEVICE_LABEL] == own["id"]
            assert other["id"] not in actual[DEVICE_LABEL]
        events = client.get("/api/v1/audit-events", headers=admin,
            params={"event_type": "metrics.query.executed"}).json()
        assert len(events) == 1 and events[0]["actor_id"] == "site.metric"
        assert client.post(path, headers=headers, json={"query": "info(up)", "actor": "test"}).status_code == 422
        assert len(requests) == 1
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()


@pytest.mark.parametrize("invalid", ["foreign_tenant", "foreign_region", "different_device", "missing_identity", "missing_metric"])
def test_device_tool_rejects_wrong_stable_identity_even_when_ip_is_reused(client, monkeypatch, invalid):
    from icheck.services.agent_tools import _get_device_range_metrics
    backend = create_metric_backend(client)
    device = _device(client)

    class WrongIdentityOpener:
        def open(self, request, timeout):
            labels = selector_labels(parse_qs(request.data.decode())["query"][0])
            labels["instance"] = device["management_ip"] + ":9182"
            if invalid == "foreign_tenant": labels[TENANT_LABEL] = "foreign"
            elif invalid == "foreign_region": labels[REGION_LABEL] = "foreign"
            elif invalid == "different_device": labels[DEVICE_LABEL] = "different"
            elif invalid == "missing_identity": labels.pop(DEVICE_LABEL)
            else: labels.pop("__name__")
            return FakeResponse({"status": "success", "data": {"resultType": "matrix",
                "result": [{"metric": labels, "values": [[1, "1"]]}]}})

    monkeypatch.setattr("icheck.services.metrics.build_opener", lambda *_: WrongIdentityOpener())
    with SessionLocal() as db:
        with pytest.raises(PermissionError, match="selector|different metric"):
            _get_device_range_metrics(db, {"backend_id": backend["id"], "device_id": device["id"],
                "metric": "up", "start": "2026-10-09T00:00:00Z", "end": "2026-10-09T00:01:00Z"},
                development_principal())
