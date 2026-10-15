"""One reusable current-demo evidence path. All API data here is a fixture."""
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from deploy.preview_lab_demo import PLUGINS, SmokeError, backup_receipt, binding, demo


class FixtureAPI:
    def __init__(self):
        now = datetime.now(timezone.utc).timestamp()
        self.states = {}
        self.documents = {}
        self.reads = []
        self.selections = []
        for plugin in sorted(PLUGINS):
            session, version, device, connection = [name + "-" + plugin for name in ("session", "version", "device", "connection")]
            self.selections.append((session, version, device, connection))
            uid = "icheck-" + plugin + "-" + connection.replace("-", "")
            url = "https://icheck.test/grafana/d/" + uid
            names = ["fixture_measurement"] if plugin != "http" else ["icheck_http_request_success", "icheck_http_status_code", "icheck_http_request_duration_seconds"]
            self.states[session] = {"artifact_version_id":version, "device_id":device, "connection_id":connection,
                "template":{"plugin":plugin, "compiled_module":{"expected_metrics":[{"name":names[0]}]}, "http_monitor":{"metrics":[]}},
                "expected_metrics":names, "stage":"collecting", "fresh_samples_verified":True, "bound_to_template":True,
                "module_installed":True, "monitoring":{"currently_authorized":True, "enrollment":{"id":"enrollment-" + plugin,
                    "revision":1, "approved_at":datetime.fromtimestamp(now-600, timezone.utc).isoformat(), "schedule_seconds":30, "timeout_seconds":10}},
                "metric_evidence":[{"name":name, "series_count":1, "oldest_sample_timestamp":now-5} for name in names],
                "dashboard_change_id":"change-"+plugin, "dashboard_status":"applied", "grafana_dashboard_url":url}
            self.documents["/grafana/changes/change-"+plugin] = {"id":"change-"+plugin, "status":"applied", "resource_kind":"dashboard",
                "resource_uid":uid, "connection_id":"grafana", "resource_url":url}
            self.documents["/grafana/connections/grafana/resources/dashboard/"+uid] = {"resource":{"metadata":{"name":uid}}, "url":url}
        self.documents["/agent/tools?limit=1000"] = [{"id":name, "name":tool, "read_only":True} for name, tool in
            (("metrics", "metrics.query_instant"), ("inventory", "inventory.get_device"), ("preview", "grafana.dashboard.preview"))]
        for identity in ("diagnostic", "builder"):
            path = "/agent/investigations/"+identity
            self.documents[path] = {"status":"completed", "finished_at":"2026-10-13T08:00:00Z", "conclusion":"Fixture evidence only",
                "iterations_used":2, "max_iterations":4, "tool_calls_used":2, "max_tool_calls":5, "tokens_used":100, "token_budget":1000}
            self.documents[path+"/checkpoints?limit=1000"] = [{"state":{"evidence_ids":["evidence"]}}]
            self.documents[path+"/evidence?limit=1000"] = [{"id":"evidence"}]
            self.documents[path+"/tool-calls?limit=1000"] = ([{"status":"succeeded", "tool_id":tool, "result":{}} for tool in ("metrics","inventory")]
                if identity == "diagnostic" else [{"status":"succeeded", "tool_id":"preview", "result":{"id":change}} for change in ("created", "revised")])
        self.documents["/grafana/changes/created"] = {"status":"applied", "resource_kind":"dashboard", "connection_id":"grafana", "resource_uid":"ai-dashboard",
            "definition":{"title":"First"}, "previous_resource":None, "applied_resource":{"metadata":{"resourceVersion":"1"}}}
        self.documents["/grafana/changes/revised"] = {"status":"applied", "resource_kind":"dashboard", "connection_id":"grafana", "resource_uid":"ai-dashboard",
            "definition":{"title":"Revised"}, "previous_resource":{"metadata":{"resourceVersion":"1"}}}
        self.documents["/capability-studio/sessions/extension"] = {"artifact_kind":"workflow", "status":"published", "artifact_id":"artifact", "artifact_version_id":"v2"}
        self.documents["/capability-studio/sessions/extension/generations"] = [{"status":"validated", "usage_recorded":True, "model_id":"model",
            "model_document_sha256":"1"*64, "artifact_version_id":version} for version in ("v1", "v2")]
        self.documents["/artifacts/artifact"] = {"versions":[{"id":version, "content_hash":str(index)*64, "status":"published"} for index, version in enumerate(("v1","v2"), 1)]}
        details = {"source":"prometheus_alertmanager", "notification_receiver":"icheck-inbox", "notification_received_at":"2026-10-13T08:00:00Z",
            "fault_recovery_verified":False, "investigation_url":"/?brief=Fixture", "dashboard_url":"https://icheck.test/grafana/d/metric",
            "metric_rule_id":"rule", "metric_rule_revision":1}
        self.documents["/alerts?limit=1000"] = [{"id":"alert", "event_type":"metric.prometheus", "entity_id":"device-snmp", "details":details}]
        self.documents["/metric-alerts/changes?limit=100"] = [{"status":"applied", "rule_id":"rule", "revision":1,
            "definition":{"enrollment_id":"enrollment-snmp"}, "compiled_rule":{"annotations":{key:details[key] for key in ("dashboard_url", "investigation_url")}}}]
        receipt = {"backup_id":"00000000-0000-4000-8000-000000000001", "created_at":"2026-10-13T08:00:00Z",
            "sha256":"a"*64, "bytes":128}
        declared = [{"name":name, "operation":operation, "commands":[command], "source":"fixture source",
            "fixtures":[{"name":"fixture"}], "output_schema":{"type":"object"}}
            for name, operation, command in (("interfaces", "read", "show interfaces status"), ("backup", "backup", "show running-config"))]
        self.documents["/capability-studio/sessions/mcp"] = {"artifact_kind":"tool", "status":"validated",
            "artifact_id":"mcp-artifact", "artifact_version_id":"mcp-v2"}
        self.documents["/capability-studio/sessions/mcp/generations"] = [{"status":"validated", "usage_recorded":True,
            "model_id":"model", "model_document_sha256":"1"*64, "artifact_version_id":version} for version in ("mcp-v1", "mcp-v2")]
        self.documents["/artifacts/mcp-artifact"] = {"versions":[{"id":version, "content_hash":str(index)*64, "status":"validated",
            "definition":{"format_version":"icheck.mcp-extension/v1", "spec":{"runtime":"icheck_netmiko_extension_v1",
                "dependencies":["netmiko==4.8.0"], "tools":deepcopy(declared)}},
            "implementation":{"entrypoint":"server.py", "files":{"server.py":"fixture source"}}, "tests":[{"fixture":True}],
            "validation_report":{"package_generated":True}} for index, version in enumerate(("mcp-v1", "mcp-v2"), 1)]}
        selected = {"device_id":"device-snmp", "connection_id":"ssh", "host_public_key":"fixture public key"}
        self.documents["/capability-studio/extensions"] = {"storage_configured":True, "items":[{"id":"installation",
            "artifact_id":"mcp-artifact", "active_version_id":"mcp-v2", "previous_version_id":"mcp-v1", "enabled":True,
            "transport":"managed_mcp", "bindings":[deepcopy(selected)], "previous_bindings":[deepcopy(selected)],
            "tool_ids":{row["name"]:row["name"] for row in declared}}]}
        for version in ("mcp-v1", "mcp-v2"):
            self.documents["/capability-studio/extensions/tests?artifact_version_id="+version] = [{**selected,
                "artifact_version_id":version, "tool_name":row["name"], "status":"succeeded", "completed_at":"2026-10-13T08:00:00Z",
                "result":deepcopy(receipt) if row["operation"] == "backup" else {"interfaces":["fixture"]}} for row in declared]
        self.documents["/agent/tools?limit=1000"].extend({"id":row["name"], "name":"extensions.fixture."+row["name"],
            "enabled":True, "read_only":True, "transport":"managed_mcp", "handler":"installation:mcp-v2:"+row["name"],
            "output_schema":row["output_schema"]} for row in declared)
        path = "/agent/investigations/mcp-run"
        self.documents[path] = deepcopy(self.documents["/agent/investigations/diagnostic"])
        self.documents[path+"/checkpoints?limit=1000"] = [{"state":{"evidence_ids":["native-interfaces", "native-backup"]}}]
        self.documents[path+"/evidence?limit=1000"] = [{"id":"native-"+row["name"], "investigation_id":"mcp-run",
            "evidence_type":"native_mcp_result", "evidence_id":"extension:installation:mcp-v2:call-"+row["name"]} for row in declared]
        self.documents[path+"/tool-calls?limit=1000"] = [{"id":"call-"+row["name"], "investigation_id":"mcp-run",
            "tool_id":row["name"], "status":"succeeded", "arguments":{"device_id":"device-snmp"},
            "result":deepcopy(receipt) if row["operation"] == "backup" else {"interfaces":["fixture"]}} for row in declared]

    def get(self, path):
        self.reads.append(path)
        if path.startswith("/capability-studio/sessions/") and "/monitoring/state?" in path:
            assert parse_qs(urlsplit(path).query)["verify_samples"] == ["true"]
            return deepcopy(self.states[path.split("/")[3]])
        return deepcopy(self.documents[path])


def check(api, **changes):
    return demo(api, **{"monitoring":api.selections, "investigation":"diagnostic", "extension_session":"extension", "metric_alert":"alert",
        "grafana_changes":["created", "revised"], "dashboard_investigations":["builder"],
        "mcp_session":"mcp", "mcp_investigations":["mcp-run"], **changes})


def test_current_full_and_early_evidence_scopes_are_not_physical_or_gui_acceptance():
    api = FixtureAPI()
    result = check(api)
    assert result["scope"] == "full" and len(result["monitoring"]) == 6
    assert result["gui_journey_verified"] is False and result["physical_truth_verified"] is False
    assert result["fault_recovery_verified"] is False and result["model_calls_initiated"] == 0
    assert result["format_version"].endswith("/v3")
    assert result["executable_mcp"]["device_ids"] == ["device-snmp"]
    assert result["executable_mcp"]["backup_bodies_downloaded"] == 0
    assert result["executable_mcp"]["disable_and_rollback_gui_verified"] is False
    assert "sha256" not in str(result) and "fixture source" not in str(result)
    assert not any("download" in path for path in api.reads)
    assert not any("collector-runs" in path or "topology" in path for path in api.reads)
    snmp = next(row for row in api.selections if row[0] == "session-snmp")
    early = check(api, monitoring=[snmp], scope="early", mcp_session=None, mcp_investigations=None)
    assert early["scope"] == "early" and early["executable_mcp"] is None
    with pytest.raises(SmokeError, match="all six"):
        check(api, monitoring=[snmp])
    assert binding("s:v:d:c") == ("s","v","d","c")
    with pytest.raises(SmokeError):
        binding("../s:v:d:c")


@pytest.mark.parametrize("mutation", ["stale", "up_only", "partial", "withdrawn", "proposal", "remote_missing", "wrong_rule", "inventory_alert", "assumed_recovery", "no_revision", "not_api_collector", "no_ai_preview"])
def test_incomplete_or_contradictory_evidence_is_rejected(mutation):
    api = FixtureAPI()
    state = api.states["session-snmp"]
    if mutation == "stale": state["metric_evidence"][0]["oldest_sample_timestamp"] -= 3600
    if mutation == "up_only": state["metric_evidence"][0]["name"] = "up"
    if mutation == "partial": state["template"]["compiled_module"]["expected_metrics"].append({"name":"missing"})
    if mutation == "withdrawn": state["monitoring"]["currently_authorized"] = False
    if mutation == "proposal": state["dashboard_status"] = "proposed"
    if mutation == "remote_missing": api.documents["/grafana/connections/grafana/resources/dashboard/icheck-snmp-connectionsnmp"]["resource"]["metadata"]["name"] = "wrong"
    if mutation == "wrong_rule": api.documents["/metric-alerts/changes?limit=100"][0]["revision"] = 2
    if mutation == "inventory_alert": api.documents["/alerts?limit=1000"][0]["event_type"] = "endpoint.new"
    if mutation == "assumed_recovery": api.documents["/alerts?limit=1000"][0]["details"]["fault_recovery_verified"] = True
    if mutation == "no_revision": api.documents["/capability-studio/sessions/extension/generations"].pop()
    if mutation == "not_api_collector": api.documents["/capability-studio/sessions/extension"]["artifact_kind"] = "collector"
    if mutation == "no_ai_preview": api.documents["/agent/investigations/builder/tool-calls?limit=1000"].pop()
    with pytest.raises(SmokeError):
        check(api)


@pytest.mark.parametrize("mutation", ["missing", "unpaired", "duplicate_run", "too_many_runs", "contract_only", "unmetered",
    "not_installed", "disabled", "same_version", "same_content", "wrong_current", "no_source", "no_fixtures",
    "no_validation", "no_previous_tests", "newer_failed_test", "different_target", "different_host_key", "disabled_registration",
    "external_registration", "wrong_handler", "wrong_schema", "failed_call", "wrong_version_evidence", "wrong_run_evidence",
    "wrong_run_call", "uncited", "wrong_device", "version_only", "empty_read", "raw_configuration", "malformed_receipt", "running"])
def test_executable_mcp_requires_generated_tested_installed_and_cited_calls(mutation):
    api = FixtureAPI()
    installed = api.documents["/capability-studio/extensions"]["items"][0]
    versions = api.documents["/artifacts/mcp-artifact"]["versions"]
    current = versions[1]
    tests = api.documents["/capability-studio/extensions/tests?artifact_version_id=mcp-v2"]
    registration = api.documents["/agent/tools?limit=1000"][-1]
    path = "/agent/investigations/mcp-run"
    calls = api.documents[path+"/tool-calls?limit=1000"]
    evidence = api.documents[path+"/evidence?limit=1000"]
    arguments = {}
    if mutation == "missing": arguments = {"mcp_session":None, "mcp_investigations":None}
    if mutation == "unpaired": arguments = {"mcp_investigations":None}
    if mutation == "duplicate_run": arguments = {"mcp_investigations":["mcp-run", "mcp-run"]}
    if mutation == "too_many_runs": arguments = {"mcp_investigations":[str(i) for i in range(5)]}
    if mutation == "contract_only": current["definition"]["format_version"] = "icheck.external-mcp-contract/v1"
    if mutation == "unmetered": api.documents["/capability-studio/sessions/mcp/generations"][0]["usage_recorded"] = False
    if mutation == "not_installed": api.documents["/capability-studio/extensions"]["items"] = []
    if mutation == "disabled": installed["enabled"] = False
    if mutation == "same_version": installed["previous_version_id"] = installed["active_version_id"]
    if mutation == "same_content": current["content_hash"] = versions[0]["content_hash"]
    if mutation == "wrong_current": api.documents["/capability-studio/sessions/mcp"]["artifact_version_id"] = "other"
    if mutation == "no_source": current["definition"]["spec"]["tools"][0]["source"] = ""
    if mutation == "no_fixtures": current["definition"]["spec"]["tools"][0]["fixtures"] = []
    if mutation == "no_validation": current["validation_report"] = {}
    if mutation == "no_previous_tests": api.documents["/capability-studio/extensions/tests?artifact_version_id=mcp-v1"] = []
    if mutation == "newer_failed_test": tests.insert(0, {**tests[0], "status":"failed"})
    if mutation == "different_target": tests[0]["device_id"] = "other"
    if mutation == "different_host_key": tests[0]["host_public_key"] = "changed"
    if mutation == "disabled_registration": registration["enabled"] = False
    if mutation == "external_registration": registration["transport"] = "mcp"
    if mutation == "wrong_handler": registration["handler"] = "installation:mcp-v1:backup"
    if mutation == "wrong_schema": registration["output_schema"] = {}
    if mutation == "failed_call": calls[1]["status"] = "failed"
    if mutation == "wrong_version_evidence": evidence[1]["evidence_id"] = "extension:installation:mcp-v1:call-backup"
    if mutation == "wrong_run_evidence": evidence[1]["investigation_id"] = "other"
    if mutation == "wrong_run_call": calls[1]["investigation_id"] = "other"
    if mutation == "uncited": api.documents[path+"/checkpoints?limit=1000"][0]["state"]["evidence_ids"] = []
    if mutation == "wrong_device": calls[1]["arguments"]["device_id"] = "other"
    if mutation == "version_only": current["definition"]["spec"]["tools"][0]["commands"] = ["show version"]
    if mutation == "empty_read": calls[0]["result"] = {}
    if mutation == "raw_configuration": calls[1]["result"]["configuration"] = "must not be printed or downloaded"
    if mutation == "malformed_receipt": calls[1]["result"]["backup_id"] = "not-an-id"
    if mutation == "running": api.documents[path]["status"] = "running"
    with pytest.raises(SmokeError):
        check(api, **arguments)
    assert not any("download" in path for path in api.reads)


def test_backup_receipts_are_metadata_only():
    value = {"backup_id":"00000000-0000-4000-8000-000000000001", "created_at":"2026-10-13T08:00:00+00:00",
        "sha256":"a"*64, "bytes":128}
    assert backup_receipt(value)
    for changes in ({"bytes":True}, {"bytes":0}, {"bytes":1_000_001}, {"created_at":"2026-10-13T08:00:00"},
                    {"created_at":"invalid"}, {"sha256":"wrong"}, {"configuration":"body"}):
        assert not backup_receipt({**value, **changes})


def test_installed_reads_and_backup_can_span_two_bounded_investigations():
    api = FixtureAPI()
    first, second = "/agent/investigations/mcp-run", "/agent/investigations/mcp-backup"
    for suffix in ("", "/checkpoints?limit=1000", "/evidence?limit=1000", "/tool-calls?limit=1000"):
        api.documents[second+suffix] = deepcopy(api.documents[first+suffix])
    api.documents[first+"/tool-calls?limit=1000"].pop()
    api.documents[second+"/tool-calls?limit=1000"].pop(0)
    for row in api.documents[second+"/evidence?limit=1000"] + api.documents[second+"/tool-calls?limit=1000"]:
        row["investigation_id"] = "mcp-backup"
    assert check(api, mcp_investigations=["mcp-run", "mcp-backup"])["executable_mcp"]["installed_interface_and_backup_calls"]


def test_missing_full_scope_mcp_selection_fails_before_any_api_requests():
    api = FixtureAPI()
    with pytest.raises(SmokeError, match="MCP session"):
        check(api, mcp_session=None, mcp_investigations=None)
    assert api.reads == []
