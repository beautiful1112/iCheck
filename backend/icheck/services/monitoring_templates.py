"""Compose the existing Studio, target test and monitoring approval lifecycles."""
from datetime import UTC
import json
import math
import re
from sqlalchemy import or_, select
from ..models import ArtifactVersion, ArtifactVersionStatus, Device, DeviceConnection, MetricBackend, GrafanaChange, utcnow
from ..device_schemas import DeviceHTTPConfigurationUpdate, DeviceSNMPConfigurationUpdate
from ..http_metrics import HTTPMonitorSpec, spec_hash
from ..monitoring_schemas import MonitoringApproval
from .authorization_scope import device_scope_clause, namespace_clause
from .artifact_lifecycle import lock_artifact_version
from .capability_pack_revocations import assert_artifact_version_not_revoked
from .collectors import _canonical_hash, artifact_version_content_material, publish_artifact_version
from .capability_studio import get_studio_session, _message
from .studio_generation import lock_studio_session
from .monitoring_template_contracts import SCHEMA, validate_contract, parse
from . import snmp_monitoring_templates as snmp_templates
from . import exporter_monitoring_templates as exporter_templates
from ..exporter_metrics import ExporterMonitorSpec,PROTOCOLS as EXPORTER_PROTOCOLS,health_metric,spec_hash as exporter_hash
from . import monitoring
from .devices import update_http_configuration, update_snmp_configuration


def _version(db, session, version_id, *, lock=False):
    version = lock_artifact_version(db, version_id) if lock else db.get(ArtifactVersion, version_id)
    if version is None or version.artifact_id != session.artifact_id or version.definition.get("schema") != SCHEMA:
        raise LookupError("Monitoring template version not found in this Studio artifact")
    if version.status not in {ArtifactVersionStatus.VALIDATED, ArtifactVersionStatus.PUBLISHED}:
        raise ValueError("Choose a validated or published template; restore old versions through version history first")
    assert_artifact_version_not_revoked(db, version.id)
    if not version.content_hash or version.content_hash != _canonical_hash(artifact_version_content_material(version)):
        raise ValueError("Monitoring template content no longer matches its validated version")
    validate_contract(version.definition, version.implementation, version.tests, version.collector_definition)
    return version, parse(version.definition)


def target_choices(db, principal, session_id=None, search=""):
    session = get_studio_session(db,session_id) if session_id else None
    version = db.get(ArtifactVersion,session.artifact_version_id) if session and session.artifact_version_id else None
    plugin=version.definition.get("plugin") if version else None
    protocol = "snmp" if plugin=="snmp" else EXPORTER_PROTOCOLS[plugin] if plugin in EXPORTER_PROTOCOLS else "https_api"
    query = select(Device, DeviceConnection).join(DeviceConnection, DeviceConnection.device_id == Device.id)
    query = query.where(device_scope_clause(principal), Device.enabled, DeviceConnection.enabled,
        DeviceConnection.protocol == protocol, DeviceConnection.tenant_id == Device.tenant_id,
        DeviceConnection.region_id == Device.region_id)
    search = search.strip()
    if len(search) > 200:
        raise ValueError("Target search must be at most 200 characters")
    if search:
        query = query.where(or_(Device.name.icontains(search, autoescape=True),
            Device.management_ip.icontains(search, autoescape=True)))
    rows = db.execute(query
        .order_by(Device.name, Device.id, DeviceConnection.id).limit(101)).all()
    return {"targets": [{"device_id": d.id, "connection_id": c.id, "name": d.name, "host": d.management_ip,
        "device_revision": d.revision, "credential_profile_ref": c.credential_profile_ref,
        "verification_status": c.verification_status} for d, c in rows[:100]], "has_more": len(rows) > 100}


def _bound(connection, template, version):
    if template.plugin in EXPORTER_PROTOCOLS:
        return (connection.protocol==EXPORTER_PROTOCOLS[template.plugin] and connection.port==template.port
            and connection.configuration.get("monitoring_template_version_id")==version.id
            and "exporter_monitor" in connection.configuration
            and exporter_hash(ExporterMonitorSpec.model_validate(connection.configuration["exporter_monitor"]))==exporter_hash(template.exporter_monitor))
    if template.plugin == "snmp":
        expected = snmp_templates.configuration(template.compiled_module,version.id)
        return (connection.protocol == "snmp" and all(connection.configuration.get(k)==v for k,v in expected.items())
            and snmp_templates.installed(template.compiled_module))
    return (connection.configuration.get("monitoring_template_version_id") == version.id
        and connection.port == template.port and "http_monitor" in connection.configuration
        and spec_hash(HTTPMonitorSpec.model_validate(connection.configuration["http_monitor"])) == spec_hash(template.http_monitor))


def binding_state(db, principal, session_id, version_id, device_id, connection_id):
    from .grafana import change_read
    session = get_studio_session(db, session_id)
    version, template = _version(db, session, version_id)
    device, connection = monitoring._connection(db, principal, device_id, connection_id)
    bound = _bound(connection, template, version)
    preview = monitoring.monitoring_preview(db, principal, device_id, connection_id)
    module_installed = template.plugin != "snmp" or snmp_templates.installed(template.compiled_module)
    if not module_installed: stage = "review_module_installation"
    elif not bound: stage = "select_and_test_target"
    elif connection.verification_status in {"pending", "running"}: stage = "testing"
    elif not preview.eligible: stage = "test_failed_or_stale"
    elif not preview.currently_authorized: stage = "tested_not_enabled"
    else: stage = "enabled_awaiting_fresh_samples"
    dashboard = None
    if preview.enrollment:
        for message in reversed(session.messages):
            ref = message.structured_content.get("monitoring_dashboard", {})
            if (ref.get("artifact_version_id") == version.id and ref.get("connection_id") == connection.id
                    and ref.get("enrollment_id") == preview.enrollment.id and ref.get("enrollment_revision") == preview.enrollment.revision):
                dashboard = db.scalar(select(GrafanaChange).where(GrafanaChange.id == ref.get("change_id"), namespace_clause(GrafanaChange, principal)))
                break
    return {"artifact_version_id": version.id, "version": version.version, "template": template.model_dump(by_alias=True),
        "expected_metrics": list(template.exporter_monitor.metrics()) if template.plugin in EXPORTER_PROTOCOLS else None,
        "device_id": device.id, "connection_id": connection.id, "host": device.management_ip,
        "port":connection.port,
        "device_revision": device.revision, "stage": stage, "bound_to_template": bound,
        "module_installed":module_installed,
        "target_test": connection.last_verification_evidence if bound else {}, "test_error": connection.last_verification_error if bound else None,
        "monitoring": preview.model_dump(mode="json"), "fresh_samples_verified": False,
        "dashboard_change_id": dashboard.id if dashboard else None,
        "dashboard_status": dashboard.status if dashboard else None,
        "grafana_dashboard_url": change_read(dashboard)["resource_url"]
            if dashboard and dashboard.status == "applied" else None}


def test_target(db, principal, session_id, payload):
    session = lock_studio_session(db, session_id)
    version, template = _version(db, session, payload.artifact_version_id, lock=True)
    if version.status == ArtifactVersionStatus.VALIDATED and (session.artifact_version_id != version.id or session.status != "validated"):
        raise ValueError("Studio candidate changed; review the exact current template before testing")
    monitoring._connection(db, principal, payload.device_id, payload.connection_id)
    if template.plugin == "snmp":
        if not snmp_templates.installed(template.compiled_module):
            raise ValueError("Review and install the exact compiled SNMP module before testing a device")
        configuration=DeviceSNMPConfigurationUpdate(expected_revision=payload.expected_device_revision,
            modules=[template.compiled_module["module_name"]],actor=payload.actor,reason=payload.reason)
        update_snmp_configuration(db,payload.device_id,payload.connection_id,configuration,actor=payload.actor,
            template_version_id=version.id,compiled_module=template.compiled_module,credential_profile_ref=payload.credential_profile_ref)
    elif template.plugin in EXPORTER_PROTOCOLS:
        from .devices import update_exporter_configuration
        update_exporter_configuration(db,payload.device_id,payload.connection_id,template.exporter_monitor,
            port=template.port,credential_profile_ref=payload.credential_profile_ref,expected_revision=payload.expected_device_revision,
            actor=payload.actor,version_id=version.id)
    else:
        configuration = DeviceHTTPConfigurationUpdate(expected_revision=payload.expected_device_revision,
            http_monitor=template.http_monitor, port=template.port, credential_profile_ref=payload.credential_profile_ref,
            actor=payload.actor, reason=payload.reason)
        update_http_configuration(db, payload.device_id, payload.connection_id, configuration,
            actor=payload.actor, template_version_id=version.id)
    return binding_state(db, principal, session_id, version.id, payload.device_id, payload.connection_id)


def enable_target(db, principal, session_id, payload):
    session = lock_studio_session(db, session_id)
    version, template = _version(db, session, payload.artifact_version_id, lock=True)
    device, connection = monitoring._connection(db, principal, payload.device_id, payload.connection_id, lock=True)
    if device.revision != payload.expected_device_revision or not _bound(connection, template, version):
        raise ValueError("Target/template changed; select and test the exact version again")
    preview = monitoring.monitoring_preview(db, principal, device.id, connection.id)
    if not preview.eligible or preview.preview_hash != payload.preview_hash:
        raise ValueError("Target test or monitoring preview changed; refresh and retest before enabling")
    if version.status == ArtifactVersionStatus.VALIDATED:
        if session.status != "validated" or session.artifact_version_id != version.id:
            raise ValueError("Studio candidate changed; review the exact current template before enabling")
        # Publication and collection intent commit in the existing approval's
        # single transaction. Invalid custody/arguments cannot partly publish.
        publish_artifact_version(db, version, payload.actor, commit=False)
        session.status = "published"; session.updated_at = utcnow()
        db.add(_message(session, role="system", content="Published the reviewed monitoring template and approved this tested target. Fresh samples remain to be verified.",
            structured_content={"artifact_version_id": version.id, "device_id": device.id, "connection_id": connection.id}))
    approval = MonitoringApproval.model_validate(payload.model_dump(exclude={"artifact_version_id", "device_id", "connection_id", "expected_device_revision"}))
    if template.plugin == "snmp" and (approval.modules != [template.compiled_module["module_name"]] or approval.collectors):
        raise ValueError("SNMP approval must bind this exact compiled module without additional collectors")
    if template.plugin in EXPORTER_PROTOCOLS and (approval.modules or approval.collectors!=template.exporter_monitor.collectors()):
        raise ValueError("Exporter approval must bind exactly the tested collector groups")
    monitoring.approve_monitoring(db, principal, device.id, connection.id, approval)
    return binding_state(db, principal, session_id, version.id, device.id, connection.id)


def module_preview(db, principal, session_id, version_id):
    from .. import snmp_install_client
    session=get_studio_session(db,session_id); version,template=_version(db,session,version_id)
    if template.plugin!="snmp": raise ValueError("Only SNMP templates install native modules")
    catalog=snmp_install_client.inspect_catalog(template.compiled_module)
    return {"artifact_version_id":version.id,"module_name":template.compiled_module["module_name"],
        "metric_names":[m["name"] for m in template.compiled_module["expected_metrics"]],
        "installed":catalog["installed"],"expected_catalog_sha256":catalog["catalog_sha256"],
        "preview_hash":_canonical_hash({"version":version.id,"content_hash":version.content_hash,
            "catalog_sha256":catalog["catalog_sha256"]}),"continuous_collection_enabled":False}


def install_module(db,principal,session_id,payload):
    from .. import snmp_install_client
    from .audit import record_audit_event
    preview=module_preview(db,principal,session_id,payload.artifact_version_id)
    if preview["preview_hash"]!=payload.preview_hash or preview["expected_catalog_sha256"]!=payload.expected_catalog_sha256:
        raise ValueError("SNMP install preview changed; review its catalog again")
    session=get_studio_session(db,session_id); version,template=_version(db,session,payload.artifact_version_id)
    if version.status == ArtifactVersionStatus.VALIDATED and (session.status!="validated" or session.artifact_version_id!=version.id):
        raise ValueError("Studio candidate changed; review the current SNMP version before installation")
    compiled=template.compiled_module
    # No database transaction lock is held over the bounded privileged channel.
    db.commit()
    result=snmp_install_client.install_module(compiled,payload.expected_catalog_sha256)
    record_audit_event(db,event_type="capability.snmp_module.installed",actor_type="user",actor_id=payload.actor,
        entity_type="artifact_version",entity_id=version.id,details={"module_name":compiled["module_name"],
            "module_sha256":compiled["module_sha256"],"catalog_sha256":result.get("catalog_sha256"),"reason":payload.reason})
    db.commit()
    return module_preview(db,principal,session_id,version.id)


def _vector_by_name(reply, expected, *, name_label="__name__"):
    if reply.result_type != "vector" or not isinstance(reply.result, list) or len(reply.result) > 100:
        raise ValueError("Invalid bounded monitoring evidence")
    result = {}
    for sample in reply.result:
        name = sample.get("metric", {}).get(name_label)
        value = sample.get("value")
        if name not in expected or name in result or not isinstance(value, list) or len(value) != 2:
            raise ValueError("Monitoring evidence is ambiguous or does not match the declared metric names")
        numeric = float(value[1])
        if not math.isfinite(numeric): raise ValueError("Monitoring evidence must be finite")
        result[name] = numeric
    return result


def verify_samples(db, principal, session_id, version_id, device_id, connection_id, backend_id=None):
    from ..metric_schemas import PrometheusInstantQuery
    from .metrics import query_instant, MetricQueryError, MetricBackendUnavailable
    state = binding_state(db, principal, session_id, version_id, device_id, connection_id)
    if not state["bound_to_template"] or not state["monitoring"]["currently_authorized"]:
        return state
    if not principal.permits("metrics.read"): raise PermissionError("Metric-read permission is required to verify collection")
    query = select(MetricBackend).where(namespace_clause(MetricBackend, principal), MetricBackend.enabled)
    if backend_id: query = query.where(MetricBackend.id == backend_id)
    backends = list(db.scalars(query.order_by(MetricBackend.id).limit(2)).all())
    if len(backends) != 1:
        return {**state, "diagnostic": "Choose one available Prometheus connection before verifying samples"}
    initial = monitoring.monitoring_target(db, principal, state["monitoring"]["enrollment"]["id"])
    if initial.exporter_monitor is not None:
        expected=list(initial.exporter_monitor.metrics())+[health_metric(initial.exporter_monitor)]
        if initial.exporter_monitor.plugin=="containers": expected.append("container_last_seen")
    elif initial.protocol == "snmp":
        expected=[m["name"] for m in state["template"]["compiled_module"]["expected_metrics"]]
    else:
        expected = [metric.name for metric in initial.http_monitor.metrics]
        expected += ["icheck_http_request_success", "icheck_http_status_code", "icheck_http_request_duration_seconds"]
        if initial.http_monitor.scheme == "https": expected.append("icheck_http_tls_expiry_timestamp_seconds")
    labels = {"job": "icheck_continuous", "icheck_tenant_id": principal.tenant_id, "icheck_region_id": principal.region_id,
        "icheck_device_id": device_id, "icheck_connection_id": connection_id, "icheck_enrollment_id": initial.enrollment_id,
        "icheck_enrollment_revision": str(initial.enrollment_revision)}
    filters = ",".join(key + "=" + json.dumps(value) for key, value in labels.items())
    selector = '{__name__=~' + json.dumps("|".join(re.escape(name) for name in expected)) + "," + filters + "}"
    def read(expression):
        return query_instant(db, backends[0], PrometheusInstantQuery(query=expression, timeout_seconds=3,
            limit=512 if initial.exporter_monitor and initial.exporter_monitor.plugin in {"containers","vmware"} else 100,
            actor=principal.subject), principal=principal)
    try:
        counts = _vector_by_name(read("count by (__name__) (" + selector + ")"), expected)
        stamps = {}
        # timestamp() drops the metric name. Also, timestamp(label_replace(...))
        # would measure expression evaluation time. Timestamp each raw selector
        # first, then attach its declared name; bounded chunks fit query limits.
        for offset in range(0, len(expected), 9):
            chunk = expected[offset:offset + 9]
            expression = " or ".join('label_replace(min(timestamp(' + name + '{' + filters + '})), "icheck_metric_name", '
                + json.dumps(name) + ', "", "")' for name in chunk)
            stamps.update(_vector_by_name(read(expression), chunk, name_label="icheck_metric_name"))
        health = read('up{' + filters + '}' if initial.protocol == "snmp" or initial.exporter_monitor is not None else
            'icheck_http_request_success{' + filters + '} and on(icheck_enrollment_id,icheck_enrollment_revision) (up{' + filters + '} == 1)')
        successful = (health.result_type == "vector" and len(health.result) == 1
            and all(health.result[0].get("metric", {}).get(key) == value for key, value in labels.items())
            and float(health.result[0]["value"][1]) == 1)
        if initial.exporter_monitor is not None:
            collectors=read(health_metric(initial.exporter_monitor)+'{'+filters+'}')
            seen={}
            if initial.exporter_monitor.plugin=="vmware":
                from ..vmware_metrics import LABEL
                spec=initial.exporter_monitor; label=LABEL[spec.vmware_scope]
                successful=successful and (collectors.result_type=="vector" and len(collectors.result)==1
                    and all(collectors.result[0].get("metric",{}).get(k)==v for k,v in labels.items())
                    and collectors.result[0].get("metric",{}).get(label)==spec.vmware_name
                    and bool(collectors.result[0].get("metric",{}).get("dc_name"))
                    and float(collectors.result[0]["value"][1]) in {0,1})
                datacenter=collectors.result[0].get("metric",{}).get("dc_name") if successful else None
                if spec.vmware_datacenter is not None: successful=successful and datacenter==spec.vmware_datacenter
                business=list(spec.metrics())+[health_metric(spec)]
                coverage=read('count by ('+label+', dc_name, __name__) ({__name__=~'+json.dumps("|".join(business))+','+filters+'})')
                seen={}
                for item in coverage.result if coverage.result_type=="vector" else []:
                    metric=item.get("metric",{}); name=metric.get("__name__")
                    if (name not in business or name in seen or metric.get(label)!=spec.vmware_name
                            or metric.get("dc_name")!=datacenter): raise ValueError("Invalid VMware selected-object evidence")
                    count=float(item["value"][1])
                    if not math.isfinite(count) or not 1<=count<=128 or not count.is_integer(): raise ValueError("Invalid VMware series count")
                    seen[name]=count
                successful=successful and set(seen)==set(business) and seen==counts
                if spec.vmware_scope=="vms" and "disk" in spec.groups:
                    disk=["vmware_vm_guest_disk_capacity","vmware_vm_guest_disk_free"]
                    coverage=read('count by (partition, __name__) ({__name__=~'+json.dumps("|".join(disk))+','+filters+'})')
                    partitions={name:set() for name in disk}
                    for item in coverage.result if coverage.result_type=="vector" else []:
                        metric=item.get("metric",{}); name=metric.get("__name__"); partition=metric.get("partition")
                        if (name not in disk or not partition or partition in partitions[name]
                                or float(item["value"][1])!=1): raise ValueError("Invalid VMware partition evidence")
                        partitions[name].add(partition)
                    successful=successful and (partitions[disk[0]]==partitions[disk[1]]
                        and all(len(partitions[name])==counts.get(name) for name in disk))
            elif initial.exporter_monitor.plugin=="containers":
                successful=successful and (collectors.result_type=="vector" and len(collectors.result)==1
                    and all(collectors.result[0].get("metric",{}).get(k)==v for k,v in labels.items())
                    and float(collectors.result[0]["value"][1])==0)
                business=list(initial.exporter_monitor.metrics())+["container_last_seen"]
                coverage=read('count by (id, __name__) ({__name__=~'+json.dumps("|".join(business))+','+filters+'})')
                containers={}
                for item in coverage.result if coverage.result_type=="vector" else []:
                    metric=item.get("metric",{}); identifier=metric.get("id"); name=metric.get("__name__")
                    if not identifier or identifier=="/" or name not in business: raise ValueError("Invalid container coverage evidence")
                    count=float(item["value"][1])
                    if not math.isfinite(count) or not 1<=count<=20000 or not count.is_integer(): raise ValueError("Invalid container series count")
                    if name in containers.setdefault(identifier,set()): raise ValueError("Duplicate container coverage evidence")
                    containers[identifier].add(name)
                successful=successful and (1<=len(containers)<=32 and all(names==set(business) for names in containers.values()))
            else:
                for item in collectors.result if collectors.result_type=="vector" else []:
                    metric=item.get("metric",{}); name=metric.get("collector")
                    if name in seen or not all(metric.get(k)==v for k,v in labels.items()): raise ValueError("Invalid collector health evidence")
                    seen[name]=float(item["value"][1])
                successful=successful and set(seen)==set(initial.exporter_monitor.collectors()) and all(x==1 for x in seen.values())
        current = monitoring.monitoring_target(db, principal, initial.enrollment_id)
        if initial.model_dump(exclude={"issued_at", "expires_at"}) != current.model_dump(exclude={"issued_at", "expires_at"}):
            raise ValueError("Monitoring authority changed during sample verification")
        approved = state["monitoring"]["enrollment"]["approved_at"]
        from datetime import datetime
        approved_at = datetime.fromisoformat(approved.replace("Z", "+00:00")).timestamp()
        now = utcnow().timestamp(); freshness = max(60, 3 * initial.schedule_seconds + initial.timeout_seconds)
        verified = (set(counts) == set(expected) == set(stamps) and all(1 <= count <= 20000 and count.is_integer() for count in counts.values())
            and all(approved_at - 1 <= stamp <= now + 5 and now - stamp <= freshness for stamp in stamps.values()) and successful)
        return {**state, "stage": "collecting" if verified else "enabled_awaiting_fresh_samples",
            "fresh_samples_verified": verified, "metric_evidence": [{"name": name, "series_count": int(counts[name]),
                "oldest_sample_timestamp": stamps.get(name)} for name in sorted(counts)],
            "diagnostic": None if verified else "Fresh successful samples for every declared metric are not yet available"}
    except (ValueError, LookupError, KeyError, IndexError, TypeError, MetricQueryError, MetricBackendUnavailable):
        return {**state, "fresh_samples_verified": False, "diagnostic": "Collection evidence is unavailable or its authority changed; refresh before retrying"}


def dashboard_proposal(db, principal, session_id, version_id, device_id, connection_id, grafana_connection_id, backend_id=None):
    from ..grafana_schemas import GrafanaPreview
    from . import grafana
    state = verify_samples(db, principal, session_id, version_id, device_id, connection_id, backend_id)
    if not state["fresh_samples_verified"]:
        raise ValueError("Verify fresh samples for this exact enrollment before proposing its dashboard")
    if state["dashboard_change_id"] and state["dashboard_status"] in {"proposed", "applying", "unknown", "applied"}:
        row = grafana.change(db, state["dashboard_change_id"], principal)
        if row.connection_id != grafana_connection_id:
            raise ValueError("A dashboard proposal already binds a different Grafana connection; inspect it first")
        return grafana.change_read(row)
    connection = grafana.connection(db, grafana_connection_id, principal)
    plugin=state["template"]["plugin"]
    uid = "icheck-" + plugin + "-" + connection_id.replace("-", "")
    names = ["icheck_http_request_success", "icheck_http_request_duration_seconds"] if plugin == "http" else []
    names += [metric["name"] for metric in state["metric_evidence"] if plugin=="snmp" or not metric["name"].startswith("icheck_")]
    filters = ','.join(key + '=' + json.dumps(value) for key, value in {"job": "icheck_continuous",
        "icheck_device_id": device_id, "icheck_connection_id": connection_id,
        "icheck_tenant_id": principal.tenant_id, "icheck_region_id": principal.region_id}.items())
    counters={m["name"] for m in state["template"].get("compiled_module",{}).get("expected_metrics",[]) if m["type"]=="counter"}
    if plugin in EXPORTER_PROTOCOLS:
        exporter=ExporterMonitorSpec.model_validate(state["template"]["exporter_monitor"])
        counters={name for name,kind in exporter.metrics().items() if kind=="counter"}
        names=list(exporter.metrics())
    def expression(name):
        query=name+"{"+filters+"}"
        if name in counters: return "rate("+query+"[5m])"
        if plugin=="vmware" and name=="vmware_vm_mem_usage_average": return query+" / 100"
        if plugin=="vmware" and name in {"vmware_host_memory_usage","vmware_host_memory_max","vmware_vm_memory_max"}: return query+" * 1024 * 1024"
        if plugin == "snmp" and name == "sysUpTime": return query+" / 100"
        return query
    panels = [{"id": index + 1, "title": name, "type": "timeseries", "targets": [{"refId": "A", "expr": expression(name), "range": True}],
        **({"fieldConfig":{"defaults":{"unit":"s"}}} if plugin=="snmp" and name=="sysUpTime" else
            {"fieldConfig":{"defaults":{"unit":"percent"}}} if plugin=="vmware" and name=="vmware_vm_mem_usage_average" else
            {"fieldConfig":{"defaults":{"unit":"bytes"}}} if plugin=="vmware" and name in {"vmware_host_memory_usage","vmware_host_memory_max","vmware_vm_memory_max","vmware_vm_guest_disk_capacity","vmware_vm_guest_disk_free","vmware_datastore_capacity_size","vmware_datastore_freespace_size"} else {}),
        "gridPos": {"x": (index % 2) * 12, "y": (index // 2) * 8, "w": 12, "h": 8}} for index, name in enumerate(names[:20])]
    if plugin in {"linux","windows"}:
        def metric(name): return name + "{" + filters + "}"
        derived = []
        if "memory" in exporter.groups:
            available = "node_memory_MemAvailable_bytes" if plugin == "linux" else "windows_memory_available_bytes"
            total = "node_memory_MemTotal_bytes" if plugin == "linux" else "windows_memory_physical_total_bytes"
            derived.append(("Memory in use", "100 * (1 - " + metric(available) + " / " + metric(total) + ")", "percent"))
        if "cpu" in exporter.groups:
            cpu = "node_cpu_seconds_total" if plugin == "linux" else "windows_cpu_time_total"
            idle = cpu + "{" + filters + ',mode="idle"}'
            derived.append(("CPU busy", "100 * (1 - avg(rate(" + idle + "[5m])))", "percent"))
        if "uptime" in exporter.groups:
            uptime = (metric("node_time_seconds") + " - " + metric("node_boot_time_seconds") if plugin == "linux"
                else "time() - " + metric("windows_system_boot_time_timestamp"))
            derived.append(("Uptime", uptime, "s"))
        for title, query, unit in derived:
            index = len(panels)
            panels.append({"id": index + 1, "title": title, "type": "timeseries",
                "targets": [{"refId": "A", "expr": query, "range": True}], "fieldConfig": {"defaults": {"unit": unit}},
                "gridPos": {"x": (index % 2) * 12, "y": (index // 2) * 8, "w": 12, "h": 8}})
    if plugin in {"containers","vmware"}:
        def metric(name,extra=""): return name+"{"+filters+extra+"}"
        derived=[]
        if plugin=="containers" and "cpu" in exporter.groups:
            derived.append(("Container CPU cores", "rate("+metric("container_cpu_usage_seconds_total",',cpu="total"')+"[5m])", "cores"))
        if plugin=="containers" and "memory" in exporter.groups:
            limit=metric("container_spec_memory_limit_bytes")
            derived.append(("Working set versus reported memory limit", "100 * "+metric("container_memory_working_set_bytes")+" / ("+limit+" > 0)", "percent"))
        if plugin=="containers" and "uptime" in exporter.groups:
            derived.append(("Container age", "time() - "+metric("container_start_time_seconds"), "s"))
        if plugin=="vmware":
            scope=exporter.vmware_scope
            if "cpu" in exporter.groups:
                used,total=("vmware_host_cpu_usage","vmware_host_cpu_max") if scope=="hosts" else ("vmware_vm_cpu_usagemhz_average","vmware_vm_max_cpu_usage")
                derived.append(("CPU usage versus reported maximum", "100 * "+metric(used)+" / ("+metric(total)+" > 0)", "percent"))
            if "memory" in exporter.groups and scope=="hosts":
                derived.append(("Host memory utilization", "100 * "+metric("vmware_host_memory_usage")+" / ("+metric("vmware_host_memory_max")+" > 0)", "percent"))
            if "disk" in exporter.groups and scope=="datastores":
                derived.append(("Datastore used capacity", "100 * (1 - "+metric("vmware_datastore_freespace_size")+" / ("+metric("vmware_datastore_capacity_size")+" > 0))", "percent"))
            if "uptime" in exporter.groups:
                boot="vmware_host_boot_timestamp_seconds" if scope=="hosts" else "vmware_vm_boot_timestamp_seconds"
                derived.append(("Object uptime", "time() - "+metric(boot), "s"))
        for title,query,unit in derived:
            index=len(panels)
            panels.append({"id":index+1,"title":title,"type":"timeseries","targets":[{"refId":"A","expr":query,"range":True}],
                "fieldConfig":{"defaults":{"unit":unit}},"gridPos":{"x":(index%2)*12,"y":(index//2)*8,"w":12,"h":8}})
    existing = grafana.CLIENT(connection).resource("dashboard", uid)
    definition = {"title": (plugin.upper()+" monitoring " + state["host"])[:255], "schemaVersion": 41, "panels": panels,
        "description": "Declared "+plugin.upper()+" measurements. Dashboard filters do not enforce device-level isolation. "
            + ("Panel limit excludes: " + ", ".join(names[20:]) if len(names) > 20 else ""), "time": {"from": "now-6h", "to": "now"}}
    from .monitoring_dashboard_merge import merge_panels
    definition = merge_panels(existing, definition)
    proposal = grafana.preview(db, connection.id, GrafanaPreview(resource_uid=uid, definition=definition,
        expected_resource_version=existing["metadata"]["resourceVersion"] if existing else None), principal)
    session = lock_studio_session(db, session_id)
    db.add(_message(session, role="system", content="Prepared a native Grafana dashboard proposal. Review and confirm it before Grafana changes.",
        structured_content={"monitoring_dashboard": {"artifact_version_id": version_id, "device_id": device_id,
            "connection_id": connection_id, "enrollment_id": state["monitoring"]["enrollment"]["id"],
            "enrollment_revision": state["monitoring"]["enrollment"]["revision"], "change_id": proposal["id"]}}))
    db.commit()
    return proposal
