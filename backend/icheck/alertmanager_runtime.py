"""Bounded access to the root-provisioned, private native Alertmanager only."""
import ipaddress
import json
import math
import re
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler

import yaml
from prometheus_client.parser import text_string_to_metric_families
from .config import get_settings
from .metric_rule_runtime import NoRedirect, RuleRuntimeError


class AlertmanagerUnavailable(RuleRuntimeError):
    pass


class NativeAlertmanager:
    def __init__(self, actor):
        settings = get_settings()
        if not settings.metric_alertmanager_url or not settings.metric_rule_backend_id:
            raise AlertmanagerUnavailable("Native Alertmanager management is not provisioned")
        if (actor.tenant_id, actor.region_id) != (settings.metric_rule_tenant_id, settings.metric_rule_region_id):
            raise PermissionError("Native Alertmanager belongs to a different workspace")
        parsed = urlsplit(settings.metric_alertmanager_url)
        try:
            valid = ipaddress.ip_address(parsed.hostname or "").is_loopback and 1 <= (parsed.port or 80) <= 65535
        except ValueError:
            valid = False
        if (not valid or parsed.scheme != "http" or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
            raise AlertmanagerUnavailable("Native Alertmanager must use a provisioned literal loopback address")
        self.base = settings.metric_alertmanager_url.rstrip("/")
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def api(self, path, method="GET", body=None):
        if not (path in {"/-/ready", "/metrics", "/api/v2/status", "/api/v2/alerts", "/api/v2/silences"}
                or re.fullmatch(r"/api/v2/silence/[0-9a-f-]{36}", path)):
            raise ValueError("Unsupported native Alertmanager resource")
        if (method not in {"GET", "POST", "DELETE"} or (method == "POST" and path != "/api/v2/silences")
                or (method == "DELETE" and not path.startswith("/api/v2/silence/"))
                or (body is not None and method != "POST")):
            raise ValueError("Unsupported native Alertmanager operation")
        try:
            data = json.dumps(body, allow_nan=False).encode() if body is not None else None
            with self.opener.open(Request(self.base + path, data=data, method=method,
                    headers={"Content-Type": "application/json"}), timeout=3) as response:
                content = response.read(1_000_001)
                if len(content) > 1_000_000 or response.status != 200:
                    raise ValueError()
                if path in {"/-/ready", "/metrics"}:
                    return content.decode("utf-8")
                return json.loads(content) if content.strip() else None
        except (HTTPError, URLError, OSError, ValueError, HTTPException):
            raise AlertmanagerUnavailable("Alertmanager response is unavailable; inspect the retained request before repeating a change") from None


def name(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_. -]{1,128}", value) else "Hidden custom name"


def configuration_summary(raw):
    """Project allowlisted fields. Never return raw YAML, URLs or http_config."""
    if not isinstance(raw, str) or len(raw) > 256000 or any(isinstance(token, yaml.AliasToken) for token in yaml.scan(raw)):
        raise ValueError("Unbounded native configuration")
    document = yaml.safe_load(raw)
    if not isinstance(document, dict):
        raise ValueError("Invalid native configuration")
    receivers = document.get("receivers", [])
    if not isinstance(receivers, list) or len(receivers) > 100:
        raise ValueError("Too many native receivers")
    summaries = []
    for row in receivers:
        integrations = []
        for kind, values in row.items():
            if kind.endswith("_configs") and isinstance(values, list):
                integrations.append({"type": name(kind.removesuffix("_configs")), "count": len(values),
                    "send_resolved": [bool(value.get("send_resolved", False)) for value in values[:20]]})
        summaries.append({"name": name(row.get("name")), "integrations": integrations})
    routes = []
    def visit(row, parent, depth):
        if not isinstance(row, dict) or depth > 8 or len(routes) >= 100:
            raise ValueError("Unbounded routing tree")
        matchers = []
        allowed = {"severity", "alertname", "job", "icheck_tenant_id", "icheck_region_id", "icheck_metric_rule_id", "icheck_metric_rule_revision"}
        for matcher in row.get("matchers", []):
            if isinstance(matcher, str) and len(matcher) < 256 and matcher.split("=", 1)[0].strip(" !~") in allowed:
                matchers.append(matcher)
            else:
                matchers.append("Custom matcher (value hidden)")
        for kind in ("match", "match_re"):
            for key, value in (row.get(kind) or {}).items():
                matchers.append(f"{key}{'=~' if kind == 'match_re' else '='}{str(value)[:128]}" if key in allowed else "Custom matcher (value hidden)")
        index = len(routes)
        result = {"index": index, "parent": parent, "depth": depth, "receiver": name(row.get("receiver", "Inherited")),
            "matchers": matchers, "group_by": [name(item) for item in row.get("group_by", [])[:30]],
            "continue": bool(row.get("continue", False))}
        for field in ("group_wait", "group_interval", "repeat_interval"):
            value = row.get(field, "Inherited")
            result[field] = str(value) if re.fullmatch(r"[0-9wdhmsuy.]{1,40}", str(value)) else "Inherited"
        result["time_intervals_configured"] = bool(row.get("mute_time_intervals") or row.get("active_time_intervals"))
        routes.append(result)
        for child in row.get("routes", []):
            visit(child, index, depth + 1)
    visit(document.get("route", {}), None, 0)
    return {"receivers": summaries, "routes": routes, "inhibition_rules": len(document.get("inhibit_rules", [])),
        "configuration_editing": "Protected native configuration; destinations and credentials are never exposed here"}


def notification_counters(raw):
    rows = {}
    for family in text_string_to_metric_families(raw):
        for sample in family.samples:
            if sample.name not in {"alertmanager_notifications_total", "alertmanager_notifications_failed_total"}:
                continue
            if not math.isfinite(sample.value) or sample.value < 0:
                raise ValueError("Invalid notification counter")
            key = name(sample.labels.get("integration", "all"))
            row = rows.setdefault(key, {"integration": key, "attempts": 0, "failures": 0})
            row["failures" if sample.name.endswith("failed_total") else "attempts"] += sample.value
    return list(rows.values())
