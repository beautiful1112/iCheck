"""Native metric-rule tools; no AI write/confirmation handler is exposed."""
from .metric_alert_schemas import MetricRulePreview

PLUGIN={"contract":"icheck.metric-rule-plugin/v1","name":"prometheus-alerts","version":1,
    "inputs":"Approved enrollment, declared measurement, threshold, interval and severity",
    "outputs":"Tested native rule proposal, retained revisions and Alertmanager episodes",
    "secret_reference":"Server-only Alertmanager receiver token file; never a rule/URL/chat value",
    "permissions":{"preview":"global alerts.read and metrics.read","confirm":"global alerts.admin and metrics.manage, current human"},
    "dependencies":["Existing Prometheus","Native promtool","Protected managed rule directory","Alertmanager receiver"],
    "validation":["Declared metric and fresh samples","Counter/value semantics","Namespace/enrollment binding","Native rule parser"],
    "activation":"Exact plan-hash human confirmation, catalog CAS and verified Prometheus reload",
    "health":"Retained apply status and actual notification receipt; never inferred recovery",
    "rollback":"New preview of the retained prior definition, revalidated source and explicit confirmation"}


def tool(name,description,schema):
    return {"name":name,"handler":name,"description":description,"transport":"internal","risk_level":"observe","read_only":True,
        "required_permissions":["alerts.read","metrics.read"],"enabled":True,"created_by":"system.bootstrap","timeout_seconds":30,"max_result_bytes":100000,
        "input_schema":schema,"output_schema":{"type":"object"}}


METRIC_ALERT_TOOLS=(
    tool("alerts.metric_rules.targets","List approved native monitoring enrollments and their actual declared metrics. Availability is not fresh collection. Select an exact enrollment before proposing a threshold.",
        {"type":"object","additionalProperties":False,"properties":{},"required":[]}),
    tool("alerts.metric_rule.preview","Test a declared measurement and propose a native Prometheus threshold rule without enabling it. Use the configured backend, an approved enrollment, rate for counters and value for gauges. Explain raw units and missing-data limitations. Return the review URL for a signed-in human; never claim notification delivery or recovery.",MetricRulePreview.model_json_schema()),
    tool("alerts.metric_rule.change.get","Inspect a retained native rule proposal/apply receipt. Unknown outcomes require inspection, not a new write. Acknowledgement and source clearance never prove fault recovery.",
        {"type":"object","additionalProperties":False,"properties":{"change_id":{"type":"string","minLength":1,"maxLength":36}},"required":["change_id"]}),
)
