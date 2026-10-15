"""Native Grafana plugin: read tools, durable previews and human-confirmed edits.

This manages dashboards, not device/collector authority. A shared Prometheus
dataset is accessible only to globally scoped engineering-workspace principals.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
import re
import secrets
from urllib.parse import urlencode, urlsplit, parse_qsl

import promql_parser
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..database import validate_session_namespace
from ..config import get_settings
from ..grafana_client import (GrafanaClient, GrafanaConflict, GrafanaError,
    GrafanaOutcomeUnknown, decrypt_token, encrypt_token, validate_urls)
from ..grafana_schemas import DISPLAY_PROPERTIES, GrafanaMetricQuery, GrafanaPreview
from ..schema_validation import validate_instance
from ..models import GrafanaChange, GrafanaConnection, new_id, utcnow
from .audit import record_audit_event
from .authorization_scope import has_global_scope, namespace_clause
from .collectors import assert_no_inline_secrets

CLIENT = GrafanaClient
UID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,31}\Z")
PANELS = {"timeseries", "stat", "gauge", "bargauge", "table", "state-timeline",
          "status-history", "piechart", "histogram", "heatmap"}
WARNING = "Shared engineering dataset: variables are filters, not device isolation. Dashboard validation does not prove fresh metric collection."


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def guard(principal, permission="metrics.read", *, human=False):
    if not principal.permits(permission) or not has_global_scope(principal):
        raise PermissionError("Grafana requires the selected engineering workspace's global " + permission + " permission")
    development = (get_settings().control_plane_auth_mode == "disabled" and principal.subject == "development"
                   and principal.principal_type == "development" and principal.auth_method == "disabled")
    if human and not development and principal.auth_method not in {"browser_session", "bearer"}:
        raise PermissionError("Only a signed-in human can confirm a Grafana change")
    if human and not development and principal.principal_type != "user":
        raise PermissionError("Service identities cannot confirm Grafana changes")


def connection(db, identifier, principal, *, lock=False):
    guard(principal)
    query = select(GrafanaConnection).where(GrafanaConnection.id == identifier,
        namespace_clause(GrafanaConnection, principal)).execution_options(populate_existing=True)
    row = db.scalar(query.with_for_update() if lock else query)
    if row is None:
        raise LookupError("Grafana connection not found")
    return row


def change(db, identifier, principal, *, lock=False):
    guard(principal)
    query = select(GrafanaChange).where(GrafanaChange.id == identifier,
        namespace_clause(GrafanaChange, principal)).execution_options(populate_existing=True)
    row = db.scalar(query.with_for_update() if lock else query)
    if row is None:
        raise LookupError("Grafana proposal not found")
    return row


def audit(db, row, principal, event, details=None):
    record_audit_event(db, event_type="grafana." + event, actor_type="user",
        actor_id=principal.subject, entity_type=row.__tablename__, entity_id=row.id,
        details=details or {})


def create_connection(db, payload, principal):
    guard(principal, "metrics.manage", human=True)
    tenant, region = validate_session_namespace(db)
    api_url, public_url = validate_urls(payload.api_url, payload.public_url)
    token = payload.token.get_secret_value()
    if any(token in value for value in (payload.name, api_url, public_url, payload.datasource_uid, payload.folder_uid)):
        raise GrafanaError("Service tokens belong only in the protected token field")
    row = GrafanaConnection(id=new_id(), tenant_id=tenant, region_id=region,
        name=payload.name, api_url=api_url, public_url=public_url, datasource_uid=payload.datasource_uid,
        folder_uid=payload.folder_uid, revision=1, enabled=True, shared_dataset_acknowledged=True,
        created_by=principal.subject)
    row.encrypted_token = encrypt_token(row, token)
    db.add(row)
    try:
        db.flush()
        audit(db, row, principal, "connection.created", {"revision": 1})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise GrafanaConflict("A Grafana connection with this name already exists") from None
    return row


def update_connection(db, identifier, payload, principal):
    guard(principal, "metrics.manage", human=True)
    row = connection(db, identifier, principal, lock=True)
    if row.revision != payload.expected_revision:
        raise GrafanaConflict("Connection changed; refresh before rotating or disabling it")
    token = payload.token.get_secret_value() if payload.token is not None else decrypt_token(row)
    row.revision += 1
    row.enabled = payload.enabled
    row.encrypted_token = encrypt_token(row, token)
    audit(db, row, principal, "connection.updated", {"revision": row.revision, "enabled": row.enabled})
    db.commit()
    return row


def metric_names(client, row):
    return sorted({name for name in client.metrics(row.datasource_uid)
                   if isinstance(name, str) and re.fullmatch(r"[A-Za-z_:][A-Za-z0-9_:]{0,255}", name)})


def clean_definition(definition):
    result = deepcopy(definition)
    for field in ("id", "uid", "version"):
        result.pop(field, None)
    return result


def query_metrics(expression, variables):
    if not isinstance(expression, str) or not expression or len(expression) > 8192:
        raise GrafanaError("Each panel needs a bounded PromQL expression")
    expanded = expression
    for macro, value in (("$__rate_interval", "5m"), ("$__interval", "30s"),
                         ("$__range_s", "3600"), ("$__range", "1h")):
        expanded = expanded.replace(macro, value)
    for name in sorted(variables, key=len, reverse=True):
        expanded = expanded.replace("${" + name + ":regex}", "icheck-preview")
        expanded = expanded.replace("${" + name + "}", "icheck-preview")
        expanded = re.sub(r"\$" + re.escape(name) + r"\b", "icheck-preview", expanded)
    if re.search(r"\$(?:\{|[A-Za-z_])", expanded):
        raise GrafanaError("Unknown dashboard variable or unsupported Grafana query macro")
    try:
        parsed = promql_parser.parse(expanded)
    except (ValueError, RuntimeError):
        raise GrafanaError("Invalid or unsupported PromQL; revise the proposed query") from None
    names = set()
    nodes = 0
    def inspect(node):
        nonlocal nodes
        nodes += 1
        if nodes > 200:
            raise GrafanaError("PromQL exceeds the dashboard query complexity limit")
        if isinstance(node, promql_parser.VectorSelector):
            if not node.name:
                raise GrafanaError("Use explicit metric names in dashboard queries")
            names.add(node.name)
        return True
    promql_parser.walk(parsed, inspect)
    if not names:
        raise GrafanaError("A metric panel must query observed metric names, not generated constant data")
    return names


def query_samples(client, row, arguments):
    payload = GrafanaMetricQuery.model_validate({key: value for key, value in arguments.items() if key != "connection_id"})
    if "$" in payload.query:
        raise GrafanaError("Sample queries require concrete PromQL, not dashboard variables")
    assert_no_inline_secrets({"query": payload.query}, "Grafana sample query")
    if decrypt_token(row) in payload.query:
        raise GrafanaError("Service tokens must never appear in sample queries")
    names = query_metrics(payload.query, set())
    if names - set(metric_names(client, row)):
        raise GrafanaError("Sample query references unobserved metric names")
    document = client.query(row.datasource_uid, payload.query, payload.limit)
    if not isinstance(document, dict) or document.get("status") != "success":
        raise GrafanaError("Grafana sample query failed")
    data = document.get("data", {})
    if not isinstance(data, dict) or data.get("resultType") != "vector" or not isinstance(data.get("result"), list):
        raise GrafanaError("Sample queries must return an instant vector, not a range or scalar")
    rows = data["result"]
    result = []
    for sample in rows[:payload.limit]:
        if not isinstance(sample, dict):
            raise GrafanaError("Grafana returned an invalid metric sample")
        labels, value = sample.get("metric"), sample.get("value")
        if (not isinstance(labels, dict) or not isinstance(value, list) or len(value) != 2
                or isinstance(value[0], bool) or not isinstance(value[0], (int, float)) or not math.isfinite(value[0])
                or not isinstance(value[1], str) or len(value[1]) > 64):
            raise GrafanaError("Grafana returned an invalid metric sample")
        try:
            float(value[1])  # Prometheus may legitimately return NaN/+Inf/-Inf.
        except ValueError:
            raise GrafanaError("Grafana returned an invalid metric value") from None
        safe = {key: val for key, val in labels.items() if isinstance(key, str)
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key)
            and not re.search(r"token|password|secret|credential|authorization|community|api_key|username", key, re.I)
            and isinstance(val, str) and len(val) <= 512}
        safe = dict(list(safe.items())[:32])
        result.append({"metric": safe, "value": value, "labels_omitted": len(safe) != len(labels)})
    response = {"connection_id": row.id, "datasource_uid": row.datasource_uid,
        "result_type": "vector", "result": result, "truncated": len(rows) > payload.limit,
        "queried_at": utcnow().isoformat(), "upstream_warnings_present": bool(document.get("warnings") or document.get("infos")),
        "warning": WARNING + " Evaluation timestamps are not source freshness. No samples means unavailable evidence, not healthy monitoring."}
    if len(canonical(response).encode()) > 100000:
        raise GrafanaError("Grafana sample query result exceeds 100 KB; narrow the query or limit")
    return response


def validate_definition(definition, row, client, *, kind="dashboard"):
    try:
        if len(canonical(definition).encode()) > 128000:
            raise GrafanaError("Dashboard definition exceeds 128 KB")
    except (TypeError, ValueError):
        raise GrafanaError("Definition must be finite, bounded JSON") from None
    assert_no_inline_secrets(definition, "Grafana definition")
    if decrypt_token(row) in canonical(definition):
        raise GrafanaError("Service tokens must never appear in a dashboard definition")
    spec = clean_definition(definition)
    if not isinstance(spec.get("title"), str) or not 1 <= len(spec["title"]) <= 255:
        raise GrafanaError("A resource title of 1 to 255 characters is required")
    if kind == "folder":
        if set(spec) != {"title"}:
            raise GrafanaError("Folder proposals change only the folder title")
        return spec
    allowed = {"title", "description", "schemaVersion", "editable", "tags", "timezone", "time",
        "timepicker", "refresh", "panels", "templating", "links", "annotations", "graphTooltip",
        "fiscalYearStartMonth", "weekStart", "preload", "liveNow"}
    if set(spec) - allowed:
        raise GrafanaError("Dashboard uses unsupported top-level settings")
    try:
        validate_instance({key: spec[key] for key in DISPLAY_PROPERTIES if key in spec},
            {"type": "object", "properties": DISPLAY_PROPERTIES}, "Grafana display settings")
    except ValueError:
        raise GrafanaError("Use native string display settings and a time object with both from and to") from None
    annotations = spec.get("annotations", {"list": []})
    if not isinstance(annotations, dict) or not isinstance(annotations.get("list", []), list) or len(annotations.get("list", [])) > 10:
        raise GrafanaError("Use a bounded native Grafana annotation list")
    for annotation in annotations.get("list", []):
        if not isinstance(annotation, dict) or annotation.get("datasource") not in (
                {"type": "grafana", "uid": "-- Grafana --"}, {"type": "datasource", "uid": "grafana"}):
            raise GrafanaError("Only native Grafana annotations are supported in this plugin")
    panels = spec.get("panels")
    if not isinstance(panels, list) or not 1 <= len(panels) <= 20:
        raise GrafanaError("Use 1 to 20 standard Grafana panels")
    templating = spec.get("templating", {})
    if not isinstance(templating, dict):
        raise GrafanaError("Dashboard templating must be an object")
    variables = templating.get("list", [])
    if not isinstance(variables, list) or len(variables) > 12:
        raise GrafanaError("Use at most 12 dashboard variables")
    variable_names = set()
    names = set()
    for variable in variables:
        if not isinstance(variable, dict):
            raise GrafanaError("Each dashboard variable must be an object")
        name = variable.get("name", "")
        if (not isinstance(name, str) or not VARIABLE.fullmatch(name) or name in variable_names or name.startswith("__")
                or name.lower() in {"token", "password", "secret", "credential", "api_key", "authorization", "community"}):
            raise GrafanaError("Variable names must be unique identifiers")
        variable_names.add(name)
        if variable.get("type") not in {"query", "custom", "constant"}:
            raise GrafanaError("Only bounded query, custom and constant variables are supported")
    def source(value):
        if value not in (None, {"type": "prometheus", "uid": row.datasource_uid}):
            raise GrafanaError("Every metric query must use the configured Prometheus data source")
    source(spec.get("datasource"))
    for variable in variables:
        source(variable.get("datasource"))
        if variable["type"] == "query":
            variable["datasource"] = {"type": "prometheus", "uid": row.datasource_uid}
            query = variable.get("query", "")
            query = query.get("query", "") if isinstance(query, dict) else query
            if not isinstance(query, str) or len(query) > 8192:
                raise GrafanaError("Variable query must be a bounded string")
            matched = re.fullmatch(r"label_values\((.+),\s*([A-Za-z_][A-Za-z0-9_]*)\)", query)
            if not matched:
                raise GrafanaError("Query variables must use label_values(explicit_metric, label)")
            names.update(query_metrics(matched.group(1), variable_names))
    ids = set()
    for index, panel in enumerate(panels):
        if not isinstance(panel, dict) or panel.get("type") not in PANELS or "libraryPanel" in panel:
            raise GrafanaError("Unsupported panel/plugin or library panel; use standard metric panels")
        identifier = panel.get("id")
        if not isinstance(identifier, int) or isinstance(identifier, bool) or identifier in ids:
            raise GrafanaError("Panels need distinct integer IDs")
        ids.add(identifier)
        source(panel.get("datasource"))
        panel["datasource"] = {"type": "prometheus", "uid": row.datasource_uid}
        grid = panel.setdefault("gridPos", {"x": index % 2 * 12, "y": index // 2 * 8, "w": 12, "h": 8})
        if (not isinstance(grid, dict) or set(grid) != {"x", "y", "w", "h"} or
                any(not isinstance(v, int) or isinstance(v, bool) for v in grid.values()) or
                not (0 <= grid["x"] < 24 and 0 <= grid["y"] <= 10000 and
                     1 <= grid["w"] <= 24 - grid["x"] and 1 <= grid["h"] <= 30)):
            raise GrafanaError("Panel layout must fit Grafana's 24-column grid")
        targets = panel.get("targets")
        if not isinstance(targets, list) or not 1 <= len(targets) <= 8:
            raise GrafanaError("Each metric panel needs 1 to 8 Prometheus queries")
        for target in targets:
            if not isinstance(target, dict):
                raise GrafanaError("Each panel query target must be an object")
            source(target.get("datasource"))
            target["datasource"] = {"type": "prometheus", "uid": row.datasource_uid}
            if set(target) - {"refId", "expr", "legendFormat", "format", "instant", "range",
                              "datasource", "editorMode", "interval", "intervalFactor", "exemplar", "hide"}:
                raise GrafanaError("Unsupported query target options")
            names.update(query_metrics(target.get("expr"), variable_names))
    # Bound embedded links at every nesting level, including field data links.
    origins = {urlsplit(row.public_url).netloc}
    def inspect_links(value, depth=0):
        if depth > 16:
            raise GrafanaError("Definition nesting exceeds its limit")
        if isinstance(value, dict):
            if "url" in value:
                url = value["url"]
                if not isinstance(url, str) or any(ord(c) < 32 for c in url):
                    raise GrafanaError("Invalid dashboard link")
                parsed = urlsplit(url)
                if parsed.username is not None or parsed.password is not None or (parsed.netloc and (parsed.scheme != "https" or parsed.netloc not in origins)):
                    raise GrafanaError("Dashboard links must stay in the configured HTTPS workspace")
                if any(key.lower().removeprefix("var-") in {"token", "password", "secret", "credential", "api_key", "authorization"}
                       for key, _ in parse_qsl(parsed.query)):
                    raise GrafanaError("Dashboard URLs cannot carry credential parameters")
                if not parsed.netloc and (not url.startswith("/") or url.startswith("//")):
                    raise GrafanaError("Use an absolute workspace path for dashboard links")
            for item in value.values():
                inspect_links(item, depth + 1)
        elif isinstance(value, list):
            if len(value) > 500:
                raise GrafanaError("Definition array exceeds its limit")
            for item in value:
                inspect_links(item, depth + 1)
    inspect_links(spec)
    missing = names - set(metric_names(client, row))
    if missing:
        raise GrafanaError("Unsupported or unobserved metrics: " + ", ".join(sorted(missing)[:10]))
    return spec


def owned(client, row, kind, resource):
    if resource is None:
        return
    metadata = resource.get("metadata", {})
    folder = metadata.get("annotations", {}).get("grafana.app/folder")
    if kind == "folder" and metadata.get("name") == row.folder_uid:
        return
    if kind == "folder" and folder != row.folder_uid:
        raise PermissionError("Managed folders must be immediate children of the configured root")
    # Nested folders must themselves be inside the configured root.
    if folder != row.folder_uid:
        parent = client.resource("folder", folder) if folder and UID.fullmatch(folder) else None
        if parent is None or parent.get("metadata", {}).get("annotations", {}).get("grafana.app/folder") != row.folder_uid:
            raise PermissionError("Resource is outside the configured iCheck-managed folder")


def resource_url(snapshot, kind, uid):
    return snapshot["public_url"].rstrip("/") + ("/d/" if kind == "dashboard" else "/dashboards/f/") + uid


def device_dashboard_links(db, principal, device_id, *, from_time="now-1h", to_time="now"):
    """Read saved native-template dashboards; no Grafana/device network request."""
    from urllib.parse import urlencode
    from ..models import DeviceConnection
    from .authorization_scope import require_device_access
    guard(principal)
    if not principal.permits("assets.read"):
        raise PermissionError("Device dashboard context requires assets.read")
    require_device_access(db, principal, device_id)
    time_pattern = r"(?:now(?:-\d+(?:s|m|h|d|w))?|\d{10,16})"
    if not all(isinstance(value, str) and re.fullmatch(time_pattern, value) for value in (from_time, to_time)):
        raise ValueError("Use a relative or epoch dashboard time range")
    plugins = {"snmp":"snmp", "https_api":"http", "node_exporter":"linux", "windows_exporter":"windows",
               "cadvisor":"containers", "vmware_exporter":"vmware"}
    connections = db.scalars(select(DeviceConnection).where(DeviceConnection.device_id == device_id,
        namespace_clause(DeviceConnection, principal))).all()
    targets = {"icheck-" + plugins[row.protocol] + "-" + row.id.replace("-", ""): row
               for row in connections if row.protocol in plugins}
    rows = db.scalars(select(GrafanaChange).join(GrafanaConnection, GrafanaConnection.id == GrafanaChange.connection_id).where(
        namespace_clause(GrafanaChange, principal), namespace_clause(GrafanaConnection, principal),
        GrafanaConnection.enabled.is_(True), GrafanaChange.resource_kind == "dashboard",
        GrafanaChange.resource_uid.in_(targets), GrafanaChange.status == "applied")
        .order_by(GrafanaChange.applied_at.desc(), GrafanaChange.id.desc()).limit(101)).all() if targets else []
    seen = set()
    links = []
    for row in rows[:100]:
        identity = (row.connection_id, row.resource_uid)
        if identity in seen or not row.applied_resource:
            continue
        seen.add(identity)
        target = targets[row.resource_uid]
        links.append({"change_id":row.id, "connection_id":target.id, "protocol":target.protocol,
            "title":row.definition.get("title", "Device metrics"), "resource_uid":row.resource_uid,
            "url":resource_url(row.connection_snapshot, "dashboard", row.resource_uid) + "?" + urlencode({
                "from":from_time, "to":to_time, "var-device":device_id, "var-connection":target.id}),
            "saved_at":row.applied_at.isoformat() if row.applied_at else None,
            "connection_enabled":target.enabled})
    return {"device_id":device_id, "dashboards":links, "has_more":len(rows)>100,
            "warning":WARNING, "boundary":"Last saved iCheck dashboard URLs; external edits and current collection health are not verified"}


def change_read(row):
    fields = {column.name: getattr(row, column.name) for column in row.__table__.columns
              if column.name not in {"tenant_id", "region_id", "connection_revision", "connection_snapshot"}}
    for name in ("created_at", "applied_at"):
        if fields.get(name) is not None:
            fields[name] = fields[name].isoformat()
    return {**fields, "review_url": "/dashboards?change=" + row.id,
            "resource_url": resource_url(row.connection_snapshot, row.resource_kind, row.resource_uid), "warning": WARNING}


def plan_document(row):
    return {"connection_id": row.connection_id, "revision": row.connection_revision,
        "connection": row.connection_snapshot, "kind": row.resource_kind, "uid": row.resource_uid,
        "folder": row.folder_uid, "definition": row.definition, "previous": row.previous_resource,
        "expected_version": row.expected_resource_version, "restore_of": row.restore_of_id}


def preview(db, identifier, payload, principal, *, restore_of=None):
    guard(principal)
    row = connection(db, identifier, principal)
    client = CLIENT(row)
    definition = validate_definition(payload.definition, row, client, kind=payload.resource_kind)
    root = client.resource("folder", row.folder_uid)
    if root is None:
        raise GrafanaError("The managed Grafana root folder must exist before proposing changes")
    folder = payload.folder_uid or row.folder_uid
    if payload.resource_kind == "folder" and folder != row.folder_uid:
        raise GrafanaError("Create or revise folders directly under the managed root; deeper nesting is unsupported")
    if folder != row.folder_uid:
        target = client.resource("folder", folder)
        owned(client, row, "folder", target)
        if target is None:
            raise GrafanaError("Target folder is unavailable; confirm its creation first")
    uid = payload.resource_uid or ("icheck-ai-" + digest([row.id, payload.resource_kind, folder, definition])[:24])
    previous = client.resource(payload.resource_kind, uid)
    owned(client, row, payload.resource_kind, previous)
    if previous is not None:
        if not payload.expected_resource_version or previous["metadata"]["resourceVersion"] != payload.expected_resource_version:
            raise GrafanaConflict("Existing resource needs its exact current version; get it and review a new proposal")
    elif payload.expected_resource_version:
        raise GrafanaConflict("The expected existing Grafana resource is absent")
    is_root_folder = payload.resource_kind == "folder" and uid == row.folder_uid
    if previous is not None and not is_root_folder and previous["metadata"].get("annotations", {}).get("grafana.app/folder") != folder:
        raise GrafanaError("Moving resources between folders is not part of this preview; create a reviewed copy")
    proposed = GrafanaChange(id=new_id(), tenant_id=row.tenant_id, region_id=row.region_id,
        connection_id=row.id, connection_revision=row.revision,
        connection_snapshot={"api_url": row.api_url, "public_url": row.public_url,
            "datasource_uid": row.datasource_uid, "folder_uid": row.folder_uid},
        resource_kind=payload.resource_kind, resource_uid=uid, folder_uid=folder,
        definition=definition, previous_resource=previous,
        expected_resource_version=payload.expected_resource_version,
        restore_of_id=restore_of, status="proposed", created_by=principal.subject)
    proposed.plan_hash = digest(plan_document(proposed))
    existing = db.scalar(select(GrafanaChange).where(GrafanaChange.plan_hash == proposed.plan_hash,
        GrafanaChange.status == "proposed", namespace_clause(GrafanaChange, principal)))
    if existing is not None:
        return change_read(existing)
    db.add(proposed)
    audit(db, proposed, principal, "change.proposed", {"resource_kind": proposed.resource_kind})
    db.commit()
    return change_read(proposed)


def matches(row, resource):
    if resource is None:
        return False
    metadata = resource.get("metadata", {})
    if metadata.get("name") != row.resource_uid or metadata.get("annotations", {}).get("icheck.app/change-id") != row.id:
        return False
    observed = clean_definition(resource.get("spec", {}))
    return all(observed.get(key) == value for key, value in row.definition.items())


def record_applied(db, row, principal, resource):
    # An inspection may finish while the original network call is returning.
    # Refresh/lock before finalizing, and never rewrite terminal receipts.
    row = change(db, row.id, principal, lock=True)
    if row.status == "applied":
        return change_read(row)
    if row.status not in {"applying", "unknown"}:
        raise GrafanaConflict("Proposal no longer permits completion of this admitted write")
    row.status = "applied"
    row.applied_resource = resource
    row.applied_at = utcnow()
    row.error_code = None
    audit(db, row, principal, "change.applied", {"resource_uid": row.resource_uid})
    db.commit()
    return change_read(row)


def confirm(db, identifier, payload, principal):
    guard(principal, "metrics.manage", human=True)
    row = change(db, identifier, principal, lock=True)
    if not secrets.compare_digest(row.plan_hash, payload.expected_plan_hash) or digest(plan_document(row)) != row.plan_hash:
        raise GrafanaConflict("The reviewed proposal changed; refresh and review it again")
    if row.status == "applied":
        return change_read(row)
    conn = connection(db, row.connection_id, principal, lock=True)
    if conn.revision != row.connection_revision and row.status == "proposed":
        raise GrafanaConflict("Connection/token revision changed; review a fresh proposal")
    current_binding = {"api_url": conn.api_url, "public_url": conn.public_url,
                       "datasource_uid": conn.datasource_uid, "folder_uid": conn.folder_uid}
    if current_binding != row.connection_snapshot:
        raise GrafanaConflict("The original Grafana resource binding changed; do not recover against another endpoint")
    client = CLIENT(conn)
    if row.status in {"applying", "unknown"}:
        # Response loss never grants permission to repeat an uncertain write.
        observed = client.resource(row.resource_kind, row.resource_uid)
        if matches(row, observed):
            return record_applied(db, row, principal, observed)
        row.status = "unknown"
        row.error_code = "write_outcome_unresolved"
        db.commit()
        return change_read(row)
    if row.status != "proposed":
        raise GrafanaConflict("Proposal is no longer awaiting confirmation")
    validate_definition(row.definition, conn, client, kind=row.resource_kind)
    current = client.resource(row.resource_kind, row.resource_uid)
    owned(client, conn, row.resource_kind, current)
    actual_version = current["metadata"]["resourceVersion"] if current is not None else None
    if actual_version != row.expected_resource_version or current != row.previous_resource:
        row.status = "conflict"
        row.error_code = "resource_changed_before_apply"
        db.commit()
        raise GrafanaConflict("Grafana was edited after preview; get its current version and propose again")
    parent = client.resource("folder", row.folder_uid)
    if parent is None:
        raise GrafanaConflict("The reviewed parent folder is unavailable")
    owned(client, conn, "folder", parent)
    metadata = {"name": row.resource_uid, "annotations": {
        **(current.get("metadata", {}).get("annotations", {}) if current else {}),
        "grafana.app/folder": row.folder_uid, "icheck.app/change-id": row.id}}
    if row.resource_kind == "folder" and row.resource_uid == conn.folder_uid:
        metadata["annotations"].pop("grafana.app/folder", None)
    if actual_version is not None:
        metadata["resourceVersion"] = actual_version
    document = {"metadata": metadata, "spec": row.definition}
    row.status = "applying"
    row.approved_by = principal.subject
    row.error_code = None
    audit(db, row, principal, "change.confirmed", {"plan_hash": row.plan_hash})
    db.commit()  # Durable admission before network I/O; no remote write inside a SQL retry.
    saved = False
    try:
        client.save(row.resource_kind, document, existing=current is not None)
        saved = True
        observed = client.resource(row.resource_kind, row.resource_uid)
        if not matches(row, observed):
            raise GrafanaOutcomeUnknown("Saved resource did not match the exact confirmed definition")
        return record_applied(db, row, principal, observed)
    except GrafanaConflict:
        status, code = "conflict", "remote_version_conflict"
    except (GrafanaOutcomeUnknown, OSError):
        status, code = "unknown", "write_outcome_requires_inspection"
    except GrafanaError:
        status = "unknown" if saved else "rejected"
        code = "verification_response_unavailable" if saved else "remote_request_rejected"
    row = change(db, row.id, principal, lock=True)
    if row.status == "applied":
        return change_read(row)
    if row.status not in {"applying", "unknown"}:
        raise GrafanaConflict("Proposal state changed during the admitted write")
    row.status, row.error_code = status, code
    db.commit()
    return change_read(row)


def restore_preview(db, identifier, principal):
    original = change(db, identifier, principal)
    if original.status != "applied" or original.previous_resource is None:
        raise GrafanaError("Only an applied revision with a retained previous definition can be restored")
    conn = connection(db, original.connection_id, principal)
    client = CLIENT(conn)
    current = client.resource(original.resource_kind, original.resource_uid)
    if current is None:
        raise GrafanaConflict("Current resource is absent; inspect Grafana before restoring")
    payload = GrafanaPreview(resource_kind=original.resource_kind, resource_uid=original.resource_uid,
        folder_uid=original.folder_uid, expected_resource_version=current["metadata"]["resourceVersion"],
        definition=original.previous_resource["spec"])
    return preview(db, conn.id, payload, principal, restore_of=original.id)


def read_resource(db, identifier, kind, uid, principal):
    if not UID.fullmatch(uid):
        raise GrafanaError("Invalid Grafana resource UID")
    row = connection(db, identifier, principal)
    client = CLIENT(row)
    resource = client.resource(kind, uid)
    if resource is None:
        raise LookupError("Grafana resource not found")
    owned(client, row, kind, resource)
    return {"resource": resource, "url": resource_url({"public_url": row.public_url}, kind, uid), "warning": WARNING}


def tools_for_ai(name, db, arguments, principal):
    guard(principal)
    if name == "grafana.connections.list":
        rows = db.scalars(select(GrafanaConnection).where(namespace_clause(GrafanaConnection, principal),
            GrafanaConnection.enabled.is_(True)).limit(20)).all()
        return {"connections": [{"id": r.id, "name": r.name, "datasource_uid": r.datasource_uid,
                                 "folder_uid": r.folder_uid} for r in rows],
            "metric_query_guidance": "datasource_uid is for Grafana definitions, not metrics.query_* backend_id. "
                "For this connection's samples use grafana.metrics.query with connection_id. "
                "For separately scoped iCheck metric queries, first call metrics.backends.list and use a returned backend_id. "
                "Do not infer a backend-to-Grafana mapping from these unrelated identifiers; ask if ambiguous.",
            "warning": WARNING}, []
    if name == "grafana.dashboard.restore.preview":
        return restore_preview(db, arguments["change_id"], principal), []
    if name == "grafana.changes.get":
        return change_read(change(db, arguments["change_id"], principal)), []
    if name == "grafana.dashboard.preview":
        payload = GrafanaPreview.model_validate({key: value for key, value in arguments.items() if key != "connection_id"})
        return preview(db, arguments["connection_id"], payload, principal), []
    row = connection(db, arguments["connection_id"], principal)
    client = CLIENT(row)
    if name == "grafana.health":
        return {**client.health(row.datasource_uid), "warning": WARNING}, []
    if name == "grafana.metrics.query":
        return query_samples(client, row, arguments), []
    if name == "grafana.metrics.discover":
        names = metric_names(client, row)
        query = arguments.get("filter", "").lower()
        selected = [value for value in names if query in value.lower()]
        # A requested metric such as `up` must not disappear behind hundreds
        # of alphabetically earlier substring matches such as *_updates_*.
        if query:
            selected.sort(key=lambda value: (value.lower() != query, not value.lower().startswith(query), value))
        limit = int(arguments.get("limit", 100))
        truncated = len(selected) > limit
        return {"metrics": selected[:limit], "truncated": truncated,
            "match_count": len(selected), "exact_match": next((value for value in selected if value.lower() == query), None),
            "next_action": ("No matching metric names were observed. Report the requested metric as unavailable; do not invent data or repeat identical discovery arguments."
                if not selected else "Use the returned exact metric when suitable. Otherwise narrow the substring filter or increase limit up to 200; do not repeat identical discovery arguments."
                if truncated else "Use the observed metric names to propose the requested dashboard; names alone do not prove sample freshness."),
            "warning": WARNING}, []
    if name in {"grafana.dashboards.search", "grafana.folders.search"}:
        kind = "folder" if name == "grafana.folders.search" else "dashboard"
        document = client.list_resources(kind, 100)
        items = document.get("items", [])
        result = []
        for item in items:
            try:
                owned(client, row, kind, item)
            except PermissionError:
                continue
            if arguments.get("query", "").lower() not in item.get("spec", {}).get("title", "").lower():
                continue
            uid = item["metadata"]["name"]
            result.append({"uid": uid, "title": item["spec"]["title"],
                "resource_version": item["metadata"]["resourceVersion"],
                "url": resource_url({"public_url": row.public_url}, kind, uid)})
        return {kind + "s": result[:20], "truncated": bool(document.get("metadata", {}).get("continue")) or len(result) > 20,
                "warning": WARNING}, []
    if name in {"grafana.dashboard.get", "grafana.dashboard.link", "grafana.folder.get"}:
        result = read_resource(db, row.id, "folder" if name == "grafana.folder.get" else "dashboard", arguments["uid"], principal)
        if name.endswith(".link"):
            params = {key: arguments[key] for key in ("from", "to") if arguments.get(key)}
            if arguments.get("device_id"):
                params["var-device"] = arguments["device_id"]
            return {"url": result["url"] + ("?" + urlencode(params) if params else ""), "warning": WARNING}, []
        return result, []
    raise GrafanaError("Unknown native Grafana tool")
