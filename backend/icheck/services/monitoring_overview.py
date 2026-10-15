"""Configured monitoring inventory, including targets absent from discovery."""
from sqlalchemy import and_, case, func, literal, or_, select

from ..models import (Alert, AlertStatus, ArtifactVersion, CapabilityStudioSession,
    Device, DeviceConnection, DeviceMonitoringEnrollment, utcnow)
from .authorization_scope import device_scope_clause, has_global_scope, namespace_clause
from . import asset_health, monitoring, monitoring_templates

CATEGORIES = {
    "network": ("Network devices", ("switch", "router", "firewall", "wireless_controller", "wireless_access_point", "access_point", "load_balancer", "network")),
    "linux": ("Linux", ("linux", "linux_server")),
    "windows": ("Windows", ("windows", "windows_server")),
    "http": ("HTTP and API services", ("http", "https", "api", "http_service")),
    "containers": ("Containers", ("container", "containers", "kubernetes")),
    "vmware": ("VMware", ("vmware", "esxi", "vcenter")),
    "services": ("Other services", ("service",)),
    "other": ("Other resources", ()),
}


def _resource_category():
    # Resource kind wins, regardless of how many management/collection methods
    # it has. Legacy generic records retain a deterministic collector fallback.
    clauses = [(func.lower(Device.kind).in_(kinds), key) for key, (_, kinds) in CATEGORIES.items() if kinds]
    for key, protocols in (("linux", ["node_exporter"]), ("windows", ["windows_exporter", "wmi"]),
            ("containers", ["cadvisor"]), ("vmware", ["vmware_exporter"]), ("http", ["https_api"]), ("network", ["snmp"])):
        clauses.append((and_(func.lower(Device.kind).in_(["other", "server", "host"]), select(DeviceConnection.id).where(
            DeviceConnection.device_id == Device.id, DeviceConnection.tenant_id == Device.tenant_id,
            DeviceConnection.region_id == Device.region_id, DeviceConnection.protocol.in_(protocols)).exists()), key))
    return case(*clauses, else_="other")


def overview(db, principal, *, category=None, search="", offset=0, limit=25, backend_id=None):
    clauses = [device_scope_clause(principal)]
    if search:
        clauses.append(or_(Device.name.icontains(search, autoescape=True),
            Device.management_ip.icontains(search, autoescape=True),
            Device.kind.icontains(search, autoescape=True), Device.site.icontains(search, autoescape=True)))
    resources = select(Device.id.label("id"), Device.name.label("name"), literal("device").label("resource_type"),
        _resource_category().label("category")).where(*clauses)
    # HTTP/API endpoints are managed inventory resources too. The historical
    # Service Intelligence catalog has a retired GUI and is not reintroduced here.
    resources = resources.subquery()
    counts = {key: 0 for key in CATEGORIES}
    counts.update(dict(db.execute(select(resources.c.category, func.count()).group_by(resources.c.category)).all()))
    page = select(resources)
    if category: page = page.where(resources.c.category == category)
    page = db.execute(page.order_by(resources.c.name, resources.c.resource_type, resources.c.id).offset(offset).limit(limit)).all()
    device_ids = [row.id for row in page if row.resource_type == "device"]
    devices = {row.id: row for row in db.scalars(select(Device).where(device_scope_clause(principal), Device.id.in_(device_ids)))}
    # SSH access is not a monitored resource or a collection check. Future SSH
    # collectors must enroll a real monitoring check, not reuse an access record.
    rows = [(connection, devices[connection.device_id]) for connection in db.scalars(select(DeviceConnection).where(
        namespace_clause(DeviceConnection, principal), DeviceConnection.device_id.in_(device_ids),
        DeviceConnection.protocol.not_in(["ssh", "telnet"])).order_by(DeviceConnection.protocol, DeviceConnection.id))]
    connection_ids = [connection.id for connection, _ in rows]
    enrollments = {row.connection_id: row for row in db.scalars(select(DeviceMonitoringEnrollment).where(
        namespace_clause(DeviceMonitoringEnrollment, principal), DeviceMonitoringEnrollment.connection_id.in_(connection_ids))).all()}
    health = asset_health.device_health(db, principal, device_ids, backend_id=backend_id) if rows else {"items": [], "diagnostic": None}
    observations = {item["connection_id"]: item for device in health["items"] for item in device["connections"]}
    alerts = {}
    if principal.permits("alerts.read"):
        alerts = dict(db.execute(select(Alert.entity_id, func.count()).where(namespace_clause(Alert, principal),
            Alert.entity_type == "device", Alert.entity_id.in_(device_ids),
            Alert.source_retirement_id.is_(None),
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED])).group_by(Alert.entity_id)).all())
    links = {}
    if principal.permits("metrics.read") and has_global_scope(principal):
        from .grafana import device_dashboard_links
        for identifier in device_ids:
            for link in device_dashboard_links(db, principal, identifier)["dashboards"]:
                links.setdefault(link["connection_id"], []).append({"title": link["title"], "url": link["url"]})
    items = []
    now = utcnow()
    for connection, device in rows:
        enrollment = enrollments.get(connection.id)
        sample = observations.get(connection.id)
        disabled = not device.enabled or not connection.enabled or (enrollment is not None and not enrollment.enabled)
        authorized = False
        if connection.protocol in monitoring.SUPPORTED:
            preview = monitoring.monitoring_preview(db, principal, device.id, connection.id)
            authorized = preview.currently_authorized
        if disabled:
            state, reason = "disabled", "Monitoring is disabled. Retained observations are historical."
        elif connection.verification_status == "failed":
            state, reason = "failing", "Connection verification failed. Open the target to review its result."
        elif sample is not None and (authorized or connection.protocol not in monitoring.SUPPORTED):
            state = {"up": "enabled", "poll_failed": "failing", "stale": "stale"}.get(sample["state"], "unknown")
            reason = sample["reason"]
        elif authorized:
            state, reason = "unknown", "Monitoring is enabled; current scrape evidence is unavailable."
        else:
            state, reason = "pending", "Complete verification and enable monitoring from the target or Studio."
            if enrollment and monitoring._utc(enrollment.approved_until) <= now:
                reason = "Monitoring approval expired. Review and renew it from the target."
        version = db.get(ArtifactVersion, connection.configuration.get("monitoring_template_version_id")) if connection.configuration.get("monitoring_template_version_id") else None
        # Only return a reference to this namespace's bound template, never its
        # implementation, transport configuration, credentials or test output.
        if version and (version.tenant_id != principal.tenant_id or version.region_id != principal.region_id):
            version = None
        items.append({"device_id": device.id, "connection_id": connection.id, "name": device.name,
            "host": device.management_ip, "port": connection.port, "site": device.site,
            "protocol": connection.protocol,
            "adapter": connection.adapter_type, "state": state, "reason": reason,
            "currently_authorized": authorized, "interval_seconds": enrollment.schedule_seconds if enrollment else None,
            "enrollment_revision": enrollment.revision if enrollment else None,
            "last_observed_at": sample["observed_at"] if sample else None,
            "sample_age_seconds": sample["sample_age_seconds"] if sample else None,
            "observation_source": sample["source"] if sample else None,
            "device_alert_count": alerts.get(device.id, 0) if principal.permits("alerts.read") else None,
            "dashboards": links.get(connection.id, []), "template_version_id": version.id if version else None,
            "studio_url": f"/studio?artifact={version.artifact_id}&template_version={version.id}" if version else "/studio"})
    checks = {}
    for item in items: checks.setdefault(item["device_id"], []).append(item)
    items = []
    for row in page:
        device = devices[row.id]
        children = checks.get(device.id, [])
        states = {child["state"] for child in children}
        state = ("disabled" if not device.enabled else next((value for value in
            ["failing", "stale", "pending", "unknown", "enabled", "disabled"] if value in states), "not_monitored"))
        reason = ("No monitoring checks configured. Management access does not imply monitoring." if not children
            else f"{len(children)} monitoring check(s). Collection status does not imply every interface or service is healthy.")
        items.append({"id": device.id, "device_id": device.id, "resource_type": "service" if row.category in {"http", "services"} else "device", "name": device.name,
            "host": device.management_ip, "site": device.site, "kind": device.kind, "category": row.category,
            "state": state, "reason": reason, "checks": children,
            "device_alert_count": alerts.get(device.id, 0) if principal.permits("alerts.read") else None,
            "manage_url": f"/assets/devices?device={device.id}",
            "dashboards": list({link["url"]: link for child in children for link in child["dashboards"]}.values())})
    return {"items": items, "categories": [{"id": key, "label": label, "count": counts[key]} for key, (label, _) in CATEGORIES.items()],
        "total": counts[category] if category else sum(counts.values()), "offset": offset, "limit": limit,
        "checked_at": now, "diagnostic": health["diagnostic"],
        "boundary": "Counts are managed resources, once each. Collection checks are nested; SSH management access is not monitoring."}


def measurements(db, principal, device_id, connection_id, *, backend_id=None):
    _, connection = monitoring._connection(db, principal, device_id, connection_id)
    version_id = connection.configuration.get("monitoring_template_version_id")
    version = db.scalar(select(ArtifactVersion).where(ArtifactVersion.id == version_id,
        namespace_clause(ArtifactVersion, principal))) if version_id else None
    session = db.scalar(select(CapabilityStudioSession).where(namespace_clause(CapabilityStudioSession, principal),
        CapabilityStudioSession.artifact_id == version.artifact_id).order_by(CapabilityStudioSession.id).limit(1)) if version else None
    if not session:
        return {"fresh_samples_verified": False, "checked_at": utcnow(), "metric_evidence": [],
            "diagnostic": "No bound Studio monitoring template. Bind a template to verify its requested measurements."}
    state = monitoring_templates.verify_samples(db, principal, session.id, version.id, device_id, connection_id, backend_id)
    return {"fresh_samples_verified": state["fresh_samples_verified"], "checked_at": utcnow(),
        "metric_evidence": state.get("metric_evidence", []),
        "diagnostic": state.get("diagnostic") or (None if state["fresh_samples_verified"] else "Enable the tested template before checking current measurements.")}
