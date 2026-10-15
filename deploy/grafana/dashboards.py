"""Baseline Grafana definitions; Prometheus remains the only metric store."""

DATASOURCE = {"type": "prometheus", "uid": "icheck-prometheus"}


def panel(number, title, expression, *, x=0, y=0, unit="short", instant=False):
    return {
        "id": number, "title": title, "type": "stat" if instant else "timeseries",
        "datasource": DATASOURCE,
        "gridPos": {"x": x, "y": y, "w": 12, "h": 8},
        "fieldConfig": {"defaults": {"unit": unit, "noValue": "No data"}, "overrides": []},
        "options": ({"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}}
                    if instant else {"legend": {"displayMode": "list", "placement": "bottom"},
                                     "tooltip": {"mode": "multi", "sort": "none"}}),
        "targets": [{"refId": "A", "expr": expression, "instant": instant,
                     "range": not instant, "legendFormat": "{{instance}} {{ifName}}",
                     "datasource": DATASOURCE}],
    }


def dashboard(uid, title, description, panels, *, icheck_url, variables=None, history="now-1h"):
    return {
        "metadata": {"name": uid, "annotations": {"grafana.app/folder": "icheck"}},
        "spec": {"title": title, "description": description, "schemaVersion": 41,
                 "editable": True, "tags": ["icheck", "engineering-preview"],
                 "timezone": "browser", "time": {"from": history, "to": "now"},
                 "refresh": "30s", "panels": panels,
                 "templating": {"list": variables or []}, "annotations": {"list": []},
                 "links": [{"type": "link", "title": "Back to iCheck", "url": icheck_url,
                            "targetBlank": False}]},
    }


def baseline_dashboards(*, icheck_url):
    overview = dashboard(
        "icheck-collection", "iCheck collection overview",
        "Real existing Prometheus targets. Exporter up is not proof of device metric collection. "
        "Missing device data is not healthy or zero. No collection jobs were added by this dashboard.",
        [panel(1, "Existing target scrape status", "up"),
         panel(2, "Samples per existing scrape", "scrape_samples_scraped", x=12),
         panel(3, "Prometheus retained series", "prometheus_tsdb_head_series", y=8),
         panel(4, "Existing scrape duration", "scrape_duration_seconds", x=12, y=8, unit="s")],
        icheck_url=icheck_url,
    )
    device = {"name": "device", "label": "Device ID", "type": "query",
              "datasource": DATASOURCE, "query": "label_values(ifOperStatus, icheck_device_id)",
              "definition": "label_values(ifOperStatus, icheck_device_id)", "refresh": 2,
              "includeAll": True, "allValue": ".*", "multi": False,
              "current": {"text": "All", "value": "$__all"}, "options": []}
    selector = '{icheck_device_id=~"${device:regex}"}'
    network = dashboard(
        "icheck-network", "iCheck network interfaces",
        "Observed standard IF-MIB metrics only. Retained history is not current collection. "
        "Empty panels mean no matching samples, not zero traffic or a healthy device. "
        "Device selection is a filter, not an authorization boundary.",
        [panel(1, "Interface operational state (1=up, 2=down)", "ifOperStatus" + selector),
         panel(2, "Incoming traffic", "8 * rate(ifHCInOctets" + selector + "[$__rate_interval])", x=12, unit="bps"),
         panel(3, "Outgoing traffic", "8 * rate(ifHCOutOctets" + selector + "[$__rate_interval])", y=8, unit="bps"),
         panel(4, "Interface error rate", "rate(ifInErrors" + selector + "[$__rate_interval]) + rate(ifOutErrors" + selector + "[$__rate_interval])", x=12, y=8, unit="ops"),
         panel(5, "Reported interface speed", "ifHighSpeed" + selector + " * 1000000", y=16, unit="bps"),
         panel(6, "Age of latest interface sample", "time() - timestamp(ifOperStatus" + selector + ")", x=12, y=16, unit="s", instant=True)],
        icheck_url=icheck_url, variables=[device], history="now-6h",
    )
    return [overview, network]
