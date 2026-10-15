"""Read-only evidence check for the current Studio/Prometheus/Grafana demo.

Never enrolls or probes targets, runs models, applies changes or infers recovery.
A pass covers product evidence, not physical truth or GUI interaction.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import re
from urllib.parse import urlencode, urlsplit
from uuid import UUID

if __package__:
    from .preview_smoke import API, SmokeError, api_base, parser, read_token
else:
    from preview_smoke import API, SmokeError, api_base, parser, read_token


def check_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9-]{1,36}", value):
        raise SmokeError("Invalid product record ID")
    return value


PLUGINS = {"snmp", "http", "linux", "windows", "containers", "vmware"}


def binding(value: str) -> tuple[str, str, str, str]:
    parts = value.split(":")
    if len(parts) != 4:
        raise SmokeError("Use session:version:device:connection record IDs")
    return tuple(check_id(part) for part in parts)


def monitoring_evidence(api: API, selected: tuple[str, str, str, str]) -> dict:
    session, version, device, connection = selected
    state = api.get(f"/capability-studio/sessions/{session}/monitoring/state?" + urlencode({
        "artifact_version_id":version, "device_id":device, "connection_id":connection, "verify_samples":"true"}))
    plugin = state["template"]["plugin"]
    if (plugin not in PLUGINS or state["artifact_version_id"] != version or state["device_id"] != device
            or state["connection_id"] != connection or state["stage"] != "collecting"
            or state["fresh_samples_verified"] is not True or state["bound_to_template"] is not True
            or state["module_installed"] is not True or state["monitoring"]["currently_authorized"] is not True):
        raise SmokeError("Selected template lacks current authority and fresh declared measurements")
    evidence = state.get("metric_evidence", [])
    if not evidence or len({row["name"] for row in evidence}) != len(evidence):
        raise SmokeError("Measurement evidence is missing or duplicated")
    if plugin == "snmp":
        expected = {row["name"] for row in state["template"]["compiled_module"]["expected_metrics"]}
    elif plugin == "http":
        expected = {row["name"] for row in state["template"]["http_monitor"]["metrics"]}
        expected.update({"icheck_http_request_success", "icheck_http_status_code", "icheck_http_request_duration_seconds"})
    else:
        expected = set(state["expected_metrics"])
    if not expected or not expected.issubset({row["name"] for row in evidence}):
        raise SmokeError("Exporter up alone or partial measurement coverage is not collection proof")
    now = datetime.now(timezone.utc).timestamp()
    enrollment = state["monitoring"]["enrollment"]
    approved = datetime.fromisoformat(enrollment["approved_at"].replace("Z", "+00:00")).timestamp()
    freshness = max(60, 3 * enrollment["schedule_seconds"] + enrollment["timeout_seconds"])
    for row in evidence:
        count, stamp = float(row["series_count"]), float(row["oldest_sample_timestamp"])
        if (not math.isfinite(count) or not count.is_integer() or not 1 <= count <= 20000
                or not math.isfinite(stamp) or not approved - 1 <= stamp <= now + 5 or now - stamp > freshness):
            raise SmokeError("Measurements are absent, stale or older than the current approval")
    change = api.get("/grafana/changes/" + check_id(state["dashboard_change_id"]))
    uid = "icheck-" + plugin + "-" + connection.replace("-", "")
    url = urlsplit(change["resource_url"])
    if (state["dashboard_status"] != "applied" or change["status"] != "applied"
            or change["resource_kind"] != "dashboard" or change["resource_uid"] != uid
            or change["resource_url"] != state["grafana_dashboard_url"] or url.scheme != "https"
            or not url.hostname or url.username or url.password or url.query or url.fragment
            or not url.path.endswith("/d/" + uid)):
        raise SmokeError("The exact enrollment has no confirmed native saved dashboard")
    remote = api.get(f"/grafana/connections/{check_id(change['connection_id'])}/resources/dashboard/{uid}")
    if remote["resource"]["metadata"]["name"] != uid or remote["url"] != change["resource_url"]:
        raise SmokeError("Saved dashboard is unavailable at the selected Grafana connection")
    return {"plugin":plugin, "device_id":device, "connection_id":connection,
        "enrollment_id":enrollment["id"], "enrollment_revision":enrollment["revision"],
        "measurement_count":len(evidence), "dashboard_change_id":change["id"]}


def investigation_records(api: API, investigation: str) -> tuple[list, list, list]:
    investigation_path = f"/agent/investigations/{investigation}"
    run = api.get(investigation_path)
    checkpoints = api.get(investigation_path + "/checkpoints?limit=1000")
    evidence = api.get(investigation_path + "/evidence?limit=1000")
    calls = api.get(investigation_path + "/tool-calls?limit=1000")
    if (run.get("status") not in {"completed", "escalated"}
            or not run.get("finished_at") or not (run.get("conclusion") or run.get("escalation_reason"))
            or run["iterations_used"] > run["max_iterations"]
            or run["tool_calls_used"] > run["max_tool_calls"]
            or run["tokens_used"] > run["token_budget"]
            or not checkpoints):
        raise SmokeError("Investigation lacks retained bounded terminal state and evidence")
    return checkpoints, evidence, calls


def investigation_evidence(api: API, investigation: str, tools: dict, *, diagnostic: bool = True) -> dict:
    checkpoints, evidence, calls = investigation_records(api, investigation)
    successful_tools = {tools[row["tool_id"]]["name"] for row in calls
                        if row["status"] == "succeeded" and row["tool_id"] in tools}
    if diagnostic and (not any(name.startswith("metrics.") for name in successful_tools)
            or not any(name.startswith(("inventory.", "knowledge.", "wireless.")) for name in successful_tools)
            or any(not tools.get(row["tool_id"], {}).get("read_only", False) for row in calls)):
        raise SmokeError("Investigation must retain read-only metrics and inventory Tool calls")
    references = {row["id"] for row in evidence}
    if diagnostic and not any(references.intersection(row.get("state", {}).get("evidence_ids", [])) for row in checkpoints):
        raise SmokeError("No retained checkpoint cites the evidence ledger")
    return {"tool_names":sorted(successful_tools), "checkpoints":len(checkpoints), "evidence_references":len(evidence),
        "preview_ids":{call["result"]["id"] for call in calls if call["status"] == "succeeded"
            and tools.get(call["tool_id"], {}).get("name") == "grafana.dashboard.preview"
            and isinstance(call.get("result"), dict) and isinstance(call["result"].get("id"), str)}}


def generated_versions(api: API, session_id: str, artifact_id: str) -> dict:
    generations = api.get(f"/capability-studio/sessions/{session_id}/generations")
    versions = {row["artifact_version_id"] for row in generations if row["status"] == "validated"
        and row["usage_recorded"] is True and row["model_id"] and row["model_document_sha256"]}
    artifact = api.get("/artifacts/" + check_id(artifact_id))
    return {row["id"]: row for row in artifact["versions"] if row["id"] in versions and row["content_hash"]}


def extension_evidence(api: API, session_id: str) -> None:
    session = api.get("/capability-studio/sessions/" + session_id)
    if session["artifact_kind"] not in {"workflow", "collector"} or session["status"] != "published":
        raise SmokeError("Select a published custom API collector or workflow Studio conversation")
    matching = list(generated_versions(api, session_id, session["artifact_id"]).values())
    if session["artifact_kind"] == "collector":
        matching = [row for row in matching if (row.get("collector_definition") or {}).get("adapter_type")
                    in {"http_json", "http_json_sandbox"}]
    if (len({row["content_hash"] for row in matching}) < 2
            or not any(row["id"] == session["artifact_version_id"] and row["status"] == "published" for row in matching)):
        raise SmokeError("Studio lacks distinct generated creation and revision versions")


def backup_receipt(value: object) -> bool:
    """Validate metadata only; never fetch or print a configuration body."""
    if (not isinstance(value, dict) or set(value) != {"backup_id", "created_at", "sha256", "bytes"}
            or not isinstance(value["backup_id"], str) or not isinstance(value["created_at"], str)
            or not isinstance(value["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
            or type(value["bytes"]) is not int or not 1 <= value["bytes"] <= 1_000_000):
        return False
    try:
        return (str(UUID(value["backup_id"])) == value["backup_id"]
            and datetime.fromisoformat(value["created_at"].replace("Z", "+00:00")).tzinfo is not None)
    except ValueError:
        return False


def mcp_evidence(api: API, session_id: str, investigations: list[str], tools: dict) -> dict:
    session = api.get("/capability-studio/sessions/" + session_id)
    if session["artifact_kind"] != "tool" or session["status"] not in {"validated", "published"}:
        raise SmokeError("Select a validated executable MCP Studio conversation")
    versions = generated_versions(api, session_id, session["artifact_id"])
    installations = api.get("/capability-studio/extensions")
    matches = [row for row in installations["items"] if row["artifact_id"] == session["artifact_id"]]
    if not installations["storage_configured"] or len(matches) != 1:
        raise SmokeError("Executable MCP package has no provisioned managed installation")
    installed = matches[0]
    current, previous = installed["active_version_id"], installed["previous_version_id"]
    if (installed["enabled"] is not True or installed["transport"] != "managed_mcp"
            or current != session["artifact_version_id"] or current == previous
            or current not in versions or previous not in versions
            or versions[current]["content_hash"] == versions[previous]["content_hash"]):
        raise SmokeError("MCP creation and revision must be generated, distinct and installed with rollback retained")
    declared_versions, tested_targets = {}, []
    for version_id, bindings in ((current, installed["bindings"]), (previous, installed["previous_bindings"])):
        version = versions[version_id]
        definition, implementation = version["definition"], version["implementation"]
        spec = definition.get("spec", {})
        if (version["status"] not in {"validated", "published"}
                or definition.get("format_version") != "icheck.mcp-extension/v1"
                or spec.get("runtime") != "icheck_netmiko_extension_v1" or not spec.get("dependencies")
                or implementation.get("entrypoint") != "server.py" or not implementation.get("files")
                or version.get("validation_report", {}).get("package_generated") is not True or not version.get("tests")):
            raise SmokeError("A tool contract or external MCP registration is not an executable package")
        declared = {row["name"]: row for row in spec["tools"]}
        if not declared or any(not row.get("source") or not row.get("fixtures") for row in declared.values()):
            raise SmokeError("Executable tools need generated source and validated fixtures")
        declared_versions[version_id] = declared
        tests = api.get("/capability-studio/extensions/tests?" + urlencode({"artifact_version_id":version_id}))
        latest = {}
        for test in tests:  # API orders newest first; an older success cannot hide a failed retest.
            latest.setdefault((test["device_id"], test["connection_id"], test["tool_name"]), test)
        passed = set()
        for binding in bindings:
            if all((test := latest.get((binding["device_id"], binding["connection_id"], name)))
                   and test["artifact_version_id"] == version_id and test["status"] == "succeeded"
                   and test["completed_at"] and test["host_public_key"] == binding["host_public_key"]
                   and (tool["operation"] != "backup" or backup_receipt(test["result"]))
                   for name, tool in declared.items()):
                passed.add(binding["device_id"])
        tested_targets.append(passed)
    eligible_devices = tested_targets[0] & tested_targets[1]
    declared = declared_versions[current]
    if not eligible_devices or set(installed["tool_ids"]) != set(declared):
        raise SmokeError("Both installed MCP versions need retained successful tests on the same selected target")
    for name, identity in installed["tool_ids"].items():
        registered = tools.get(identity, {})
        if (registered.get("enabled") is not True or registered.get("read_only") is not True
                or registered.get("transport") != "managed_mcp"
                or registered.get("handler") != f"{installed['id']}:{current}:{name}"
                or registered.get("output_schema") != declared[name]["output_schema"]):
            raise SmokeError("MCP tools are not registered against the active executable version")
    interface_names = {name for name, row in declared.items() if row["operation"] == "read"
        and any("interface" in command for command in row["commands"])}
    backup_names = {name for name, row in declared.items() if row["operation"] == "backup"}
    successful = {}
    for identity in investigations:
        checkpoints, evidence, calls = investigation_records(api, identity)
        cited = {reference for checkpoint in checkpoints for reference in checkpoint.get("state", {}).get("evidence_ids", [])}
        native = {row["evidence_id"] for row in evidence if row["investigation_id"] == identity
            and row["evidence_type"] == "native_mcp_result" and row["id"] in cited}
        for call in calls:
            device = call.get("arguments", {}).get("device_id")
            if (call["investigation_id"] != identity or call["status"] != "succeeded" or device not in eligible_devices
                    or call["arguments"] != {"device_id":device}
                    or f"extension:{installed['id']}:{current}:{call['id']}" not in native):
                continue
            name = next((name for name, tool_id in installed["tool_ids"].items() if tool_id == call["tool_id"]), None)
            if (name in interface_names and isinstance(call["result"], dict) and call["result"]
                    or name in backup_names and backup_receipt(call["result"])):
                successful.setdefault(device, set()).add(name)
    devices = sorted(device for device, names in successful.items() if names & interface_names and names & backup_names)
    if not devices:
        raise SmokeError("Installed MCP interface and backup calls need matching cited native evidence on the tested target")
    return {"installation_id": installed["id"], "active_version_id":current, "previous_version_id":previous,
        "device_ids":devices, "installed_interface_and_backup_calls":True, "backup_bodies_downloaded":0,
        "disable_and_rollback_gui_verified":False}


def demo(api: API, *, monitoring: list[tuple[str, str, str, str]], investigation: str,
         extension_session: str, metric_alert: str, grafana_changes: list[str],
         dashboard_investigations: list[str], scope: str = "full",
         mcp_session: str | None = None, mcp_investigations: list[str] | None = None) -> dict:
    if scope not in {"early", "full"} or not 1 <= len(monitoring) <= 6 or len(set(monitoring)) != len(monitoring):
        raise SmokeError("Select one to six distinct monitoring bindings and early/full scope")
    if len(grafana_changes) != 2 or len(set(grafana_changes)) != 2 or not 1 <= len(dashboard_investigations) <= 4:
        raise SmokeError("Select dashboard creation/revision and their bounded AI investigations")
    if (scope == "full" and not mcp_session or bool(mcp_session) != bool(mcp_investigations)
            or mcp_investigations and (not 1 <= len(mcp_investigations) <= 4
                or len(set(mcp_investigations)) != len(mcp_investigations))):
        raise SmokeError("Full scope requires an MCP session and one to four distinct installed-tool investigations")
    observed = [monitoring_evidence(api, row) for row in monitoring]
    plugins = {row["plugin"] for row in observed}
    if len(plugins) != len(observed) or (scope == "full" and plugins != PLUGINS) or not plugins.intersection({"snmp", "http"}):
        raise SmokeError("Full scope requires all six plugins; early scope requires SNMP or HTTP")
    tools = {row["id"]:row for row in api.get("/agent/tools?limit=1000")}
    diagnostic = investigation_evidence(api, investigation, tools)
    proposals = set()
    for identity in dashboard_investigations:
        proposals.update(investigation_evidence(api, identity, tools, diagnostic=False)["preview_ids"])
    first, revised = [api.get("/grafana/changes/" + identity) for identity in grafana_changes]
    if (not set(grafana_changes).issubset(proposals) or any(row["status"] != "applied" for row in (first, revised))
            or first["resource_kind"] != "dashboard" or revised["resource_kind"] != "dashboard"
            or first["previous_resource"] is not None or not revised["previous_resource"]
            or (first["connection_id"], first["resource_uid"]) != (revised["connection_id"], revised["resource_uid"])
            or first["definition"] == revised["definition"]
            or first["applied_resource"]["metadata"]["resourceVersion"] != revised["previous_resource"]["metadata"]["resourceVersion"]):
        raise SmokeError("Retained AI previews lack confirmed creation and consecutive revision of one dashboard")
    extension_evidence(api, extension_session)
    mcp = mcp_evidence(api, mcp_session, mcp_investigations, tools) if mcp_session else None
    alert = next((row for row in api.get("/alerts?limit=1000") if row["id"] == metric_alert), None)
    if not alert or alert["event_type"] != "metric.prometheus":
        raise SmokeError("Select a Prometheus metric-alert episode, not an inventory event")
    details = alert.get("details", {})
    if (details.get("source") != "prometheus_alertmanager" or not details.get("notification_receiver")
            or not details.get("notification_received_at") or details.get("fault_recovery_verified") is not False
            or not details.get("investigation_url", "").startswith("/?brief=")
            or alert["entity_id"] not in {row["device_id"] for row in observed}):
        raise SmokeError("Metric delivery, selected-source or recovery boundaries are absent")
    rules = api.get("/metric-alerts/changes?limit=100")
    if not any(row["status"] == "applied" and row["rule_id"] == details.get("metric_rule_id")
            and row["revision"] == details.get("metric_rule_revision")
            and row["definition"]["enrollment_id"] in {item["enrollment_id"] for item in observed}
            and row["compiled_rule"]["annotations"]["investigation_url"] == details.get("investigation_url")
            and row["compiled_rule"]["annotations"]["dashboard_url"] == details.get("dashboard_url") for row in rules):
        raise SmokeError("Metric notification has no matching retained applied rule revision")
    return {"format_version": "icheck.engineering-preview-demo-evidence/v3", "passed": True, "scope":scope,
            "read_only": True, "checked_at": datetime.now(timezone.utc).isoformat(),
            "monitoring":observed, "investigation_tool_names":diagnostic["tool_names"],
            "checkpoints":diagnostic["checkpoints"], "evidence_references":diagnostic["evidence_references"],
            "confirmed_ai_dashboard_creation_and_revision":True, "custom_studio_creation_and_revision":True,
            "executable_mcp":mcp,
            "metric_notification_receipt":True, "fault_recovery_verified":False,
            "physical_truth_verified": False, "gui_journey_verified": False,
            "lab_device_probes_initiated":0, "model_calls_initiated":0,
            "boundary": "Product evidence and read-only Prometheus/Grafana checks; GUI actions, genuine sources, provider transport and fault causality require separate observation"}


def main():
    arguments = parser()
    arguments.description = __doc__
    arguments.add_argument("--scope", choices=("early", "full"), default="full")
    arguments.add_argument("--monitoring", action="append", type=binding, required=True,
        help="Repeat session:version:device:connection IDs for each selected plugin")
    arguments.add_argument("--grafana-change", action="append", type=check_id, required=True, help="Creation then revision IDs")
    arguments.add_argument("--dashboard-investigation", action="append", type=check_id, required=True)
    arguments.add_argument("--mcp-session", type=check_id, help="Executable MCP creation/revision session; required for full scope")
    arguments.add_argument("--mcp-investigation", action="append", type=check_id,
        help="Repeat for installed interface/backup tool runs; required with --mcp-session")
    for name in ("investigation", "extension-session", "metric-alert"):
        arguments.add_argument("--" + name, required=True, type=check_id)
    args = arguments.parse_args()
    try:
        api = API(api_base(args.api, args.allow_loopback_http), read_token(args.token_file),
                  ca_file=args.ca_file, timeout=args.timeout)
        result = demo(api, monitoring=args.monitoring, investigation=args.investigation,
            extension_session=args.extension_session, metric_alert=args.metric_alert, grafana_changes=args.grafana_change,
            dashboard_investigations=args.dashboard_investigation, scope=args.scope,
            mcp_session=args.mcp_session, mcp_investigations=args.mcp_investigation)
        print(json.dumps(result, sort_keys=True))
    except (SmokeError, OSError, KeyError, TypeError, ValueError, OverflowError):
        print(json.dumps({"passed": False, "error": "Demo evidence check failed; complete the GUI checklist and inspect retained records"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
