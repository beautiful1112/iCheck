"""Small native plugin contract and typed tools, shared by GUI and agent loops."""
from .grafana_schemas import DISPLAY_GUIDANCE, DISPLAY_PROPERTIES, GrafanaChangeRead, GrafanaMetricQuery, GrafanaPreview

PLUGIN = {"contract": "icheck.grafana-plugin/v1", "name": "grafana", "version": 1,
    "inputs": "connection ID, native dashboard/folder definition, current resource version",
    "outputs": "validated proposal, retained prior definition, saved Grafana URL",
    "secret_reference": "managed-grafana://connection-id (encrypted server-side bearer token)",
    "permissions": {"read_and_propose": "global metrics.read", "configure_and_confirm": "global metrics.manage, human"},
    "dependencies": ["Grafana native v1 HTTP API (qualified on OSS 13.2.3)", "configured Prometheus datasource", "managed folder"],
    "validation": ["bounded native panels", "PromQL parse and observed metric catalog", "source and link allowlists"],
    "activation": "exact plan hash, human confirmation, resourceVersion compare-and-swap",
    "health": "Grafana API and configured datasource readiness",
    "rollback": "new preview from retained prior definition; current version and confirmation required"}

ID = {"type": "string", "minLength": 1, "maxLength": 36}
UID = {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"}

# Native Grafana JSON guidance, not a competing dashboard renderer. Exact source,
# query, layout, secret and uniqueness checks remain in the native validator.
SOURCE = {"type":"object", "additionalProperties":False, "required":["type","uid"],
    "description":"Use the exact datasource_uid returned by grafana.connections.list; omit this object to use that configured source.",
    "properties":{"type":{"const":"prometheus"}, "uid":{"type":"string", "minLength":1, "maxLength":64}}}
DEFINITION = {"type":"object", "required":["title"], "properties":{
    "title":{"type":"string", "minLength":1, "maxLength":255},
    **DISPLAY_PROPERTIES,
    "panels":{"type":"array", "minItems":1, "maxItems":20, "items":{"type":"object", "required":["id","type","targets"],
        "properties":{"id":{"type":"integer", "description":"Distinct integer for each panel, never a quoted string."},
            "title":{"type":"string", "maxLength":255},
            "type":{"enum":["timeseries","stat","gauge","bargauge","table","state-timeline","status-history","piechart","histogram","heatmap"]},
            "datasource":SOURCE,
            "gridPos":{"type":"object", "additionalProperties":False, "required":["x","y","w","h"], "properties":{
                "x":{"type":"integer","minimum":0,"maximum":23}, "y":{"type":"integer","minimum":0,"maximum":10000},
                "w":{"type":"integer","minimum":1,"maximum":24}, "h":{"type":"integer","minimum":1,"maximum":30}}},
            "targets":{"type":"array", "minItems":1, "maxItems":8, "items":{"type":"object", "required":["expr"], "properties":{
                "expr":{"type":"string","minLength":1}, "refId":{"type":"string"}, "datasource":SOURCE,
                "range":{"type":"boolean"}, "instant":{"type":"boolean"}}}}}}},
    "templating":{"type":"object", "properties":{"list":{"type":"array", "maxItems":12, "items":{"type":"object",
        "required":["name","type"], "properties":{"name":{"type":"string"}, "type":{"enum":["query","custom","constant"]},
            "datasource":SOURCE}}}}}},
    "description":"Dashboard: native title and metric panels. Folder: title only. Variables are optional; omit templating when unnecessary. No datasource-type variables."}


def tool(name, description, properties, required, output=None):
    return {"name": name, "handler": name, "transport": "internal",
        "description": description, "risk_level": "observe", "read_only": True,
        "required_permissions": ["metrics.read"], "timeout_seconds": 30, "max_result_bytes": 300000,
        "enabled": True, "created_by": "system.bootstrap",
        "input_schema": {"type": "object", "additionalProperties": False,
                         "properties": properties, "required": required},
        "output_schema": output or {"type": "object"}}


preview = GrafanaPreview.model_json_schema()
GRAFANA_TOOLS = (
    tool("grafana.connections.list", "Discover enabled native Grafana connections in the trusted engineering workspace. Never returns a token.", {}, []),
    tool("grafana.health", "Read Grafana and Prometheus datasource readiness; exporter health does not prove device metrics.", {"connection_id": ID}, ["connection_id"]),
    tool("grafana.metrics.discover", "Discover actual metric names before drafting queries. Retained names do not prove freshness; unsupported metrics must be reported.",
         {"connection_id": ID, "filter": {"type": "string", "maxLength": 128}, "limit": {"type": "integer", "minimum": 1, "maximum": 200}}, ["connection_id"]),
    tool("grafana.metrics.query", "Read bounded current samples and labels from this Grafana connection's configured Prometheus datasource. Use this for dashboard authoring, including platform self-metrics; no iCheck backend ID is needed. Global workspace access only: the shared dataset is not device-isolated. Discover actual metric names first, use concrete instant-vector PromQL (no dashboard variables, range-vector or scalar result), and report missing data. Evaluation timestamps are not source freshness; timestamp(metric) can inspect stored sample times. Never probes a target or applies a dashboard.",
         {"connection_id": ID, **GrafanaMetricQuery.model_json_schema()["properties"]}, ["connection_id", "query"]),
    tool("grafana.dashboards.search", "Find managed dashboards and return real full-page URLs. Search is bounded and reports truncation.",
         {"connection_id": ID, "query": {"type": "string", "maxLength": 128}}, ["connection_id"]),
    tool("grafana.folders.search", "Find the managed Grafana root and child folders, including their current resource versions.",
         {"connection_id": ID, "query": {"type": "string", "maxLength": 128}}, ["connection_id"]),
    tool("grafana.dashboard.get", "Read a managed dashboard's native definition and exact resourceVersion before proposing a revision.", {"connection_id": ID, "uid": UID}, ["connection_id", "uid"]),
    tool("grafana.folder.get", "Read a managed folder's native definition and exact resourceVersion before proposing a revision.", {"connection_id": ID, "uid": UID}, ["connection_id", "uid"]),
    tool("grafana.dashboard.link", "Open an existing managed dashboard with optional device/time filters, never a service token. Filters are not isolation.",
         {"connection_id": ID, "uid": UID, "device_id": ID, "from": {"type": "string", "maxLength": 32}, "to": {"type": "string", "maxLength": 32}}, ["connection_id", "uid"]),
    tool("grafana.dashboard.preview", "Validate and save a dashboard or folder proposal without changing Grafana. Discover connection datasource_uid and observed metrics first. Dashboard example: title, panels:[{id:1,type:timeseries,targets:[{refId:A,expr:observed_metric}]}]. Omitted datasource/layout are filled with the configured source and native grid. Panel IDs must be distinct integers. Use query/custom/constant variables only; no datasource variable. Existing revisions require exact resource_uid and expected_resource_version. Return review_url for human confirmation; never claim it is applied." + DISPLAY_GUIDANCE,
         {**preview["properties"], "definition": DEFINITION, "connection_id": ID}, ["connection_id", "definition"], GrafanaChangeRead.model_json_schema()),
    tool("grafana.dashboard.restore.preview", "Propose restoring an applied revision's retained prior definition against the current Grafana version. No remote write; human confirmation is required.",
         {"change_id": ID}, ["change_id"], GrafanaChangeRead.model_json_schema()),
    tool("grafana.changes.get", "Inspect actual proposal/apply status and the saved dashboard URL. Unknown write outcomes must not be retried as new writes.",
         {"change_id": ID}, ["change_id"], GrafanaChangeRead.model_json_schema()),
)
