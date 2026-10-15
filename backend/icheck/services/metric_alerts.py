"""Native Prometheus rule proposals and Alertmanager episode ingestion.

No SQL polling/evaluation loop is introduced. iCheck stores reviewed definitions,
notification receipts and inventory history, not another routine metric TSDB.
"""
import json
import math
import re
import secrets
from datetime import timedelta
from urllib.parse import urlencode
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from ..config import get_settings
from ..models import (AlertRule, AlertSeverity, MetricBackend, MetricRuleChange,
    DeviceMonitoringEnrollment, ArtifactVersion, GrafanaChange, GrafanaConnection, new_id, utcnow)
from ..metric_alert_schemas import MetricRuleDefinition, MetricRulePreview
from ..metric_rule_runtime import (NativeRuleRuntime, RuleRuntimeError, RuleRuntimeConflict,
    RuleRuntimeUnknown, catalog, digest)
from ..metric_schemas import PrometheusInstantQuery
from ..exporter_metrics import health_metric
from .authorization_scope import has_global_scope, namespace_clause
from .audit import record_audit_event
from .current_authority import current_human_authority
from . import monitoring, metrics, alerts

EVENT="metric.prometheus"
RUNTIME=NativeRuleRuntime


def guard(actor,*,human=False):
    permissions=("alerts.admin","metrics.manage","metrics.read","alerts.read") if human else ("alerts.read","metrics.read")
    if not has_global_scope(actor) or not actor.permits(*permissions):
        raise PermissionError("Metric-rule management requires the trusted workspace's global alert/metric permissions")
    development=get_settings().control_plane_auth_mode=="disabled" and actor.principal_type=="development" and actor.auth_method=="disabled"
    if human and not development and (actor.principal_type!="user" or actor.auth_method not in {"bearer","browser_session"}):
        raise PermissionError("Only a signed-in human can enable or restore a metric rule")


def current_authority(db,actor):
    guard(actor,human=True)
    if get_settings().control_plane_auth_mode=="disabled" and actor.principal_type=="development" and actor.auth_method=="disabled": return None
    return current_human_authority(db,actor,permissions=("alerts.admin","metrics.manage","metrics.read","alerts.read"),
        tenant_id=actor.tenant_id,region_id=actor.region_id)


def target_snapshot(target): return target.model_dump(mode="json",exclude={"issued_at","expires_at"})


def backend(db,actor,identifier,*,lock=False,allow_disabled=False):
    statement=select(MetricBackend).where(MetricBackend.id==identifier,namespace_clause(MetricBackend,actor)).execution_options(populate_existing=True)
    row=db.scalar(statement.with_for_update(read=True) if lock else statement)
    if row is None or (not row.enabled and not allow_disabled) or row.provider!="prometheus": raise LookupError("Prometheus backend not found or unavailable")
    return row


def supported_metrics(db,target):
    result={"up":"gauge"}
    if target.exporter_monitor:
        result.update(target.exporter_monitor.metrics()); result[health_metric(target.exporter_monitor)]="gauge"
        if target.exporter_monitor.plugin=="containers": result["container_last_seen"]="gauge"
    elif target.http_monitor:
        result.update({metric.name:metric.type for metric in target.http_monitor.metrics})
        result.update({"icheck_http_request_success":"gauge","icheck_http_status_code":"gauge","icheck_http_request_duration_seconds":"gauge"})
        if target.http_monitor.scheme=="https": result["icheck_http_tls_expiry_timestamp_seconds"]="gauge"
    else:
        # Only validated template-declared metrics, never guessed exporter names.
        from ..models import DeviceConnection
        connection=db.get(DeviceConnection,target.connection_id)
        version=db.get(ArtifactVersion,connection.configuration.get("monitoring_template_version_id")) if connection else None
        if version:
            for metric in version.definition.get("compiled_module",{}).get("expected_metrics",[]): result[metric["name"]]=metric["type"]
    return result


def expressions(definition,target):
    labels={"job":"icheck_continuous","icheck_tenant_id":target.tenant_id,"icheck_region_id":target.region_id,
        "icheck_device_id":target.device_id,"icheck_connection_id":target.connection_id,
        "icheck_enrollment_id":target.enrollment_id,"icheck_enrollment_revision":str(target.enrollment_revision)}
    selector=definition.metric+"{"+",".join(key+"="+json.dumps(value) for key,value in sorted(labels.items()))+"}"
    measurement="rate("+selector+f"[{definition.rate_window_seconds}s])" if definition.measurement=="rate" else selector
    value=definition.aggregation+"("+measurement+")"
    return selector,value,value+" "+definition.comparison+" "+format(definition.threshold,".17g"),labels


def dashboard_url(db,actor,target,metric):
    """Use a retained saved dashboard for this source, never a guessed URL."""
    from .grafana import resource_url
    plugin=target.exporter_monitor.plugin if target.exporter_monitor else "http" if target.http_monitor else "snmp"
    uid="icheck-"+plugin+"-"+target.connection_id.replace("-","")
    rows=db.scalars(select(GrafanaChange).join(GrafanaConnection,GrafanaConnection.id==GrafanaChange.connection_id).where(
        namespace_clause(GrafanaChange,actor),namespace_clause(GrafanaConnection,actor),GrafanaConnection.enabled,
        GrafanaChange.resource_kind=="dashboard",GrafanaChange.status=="applied")
        .order_by((GrafanaChange.resource_uid==uid).desc(),GrafanaChange.applied_at.desc(),GrafanaChange.id).limit(100)).all()
    seen=set()
    for row in rows:
        identity=(row.connection_id,row.resource_uid)
        if identity in seen: continue
        seen.add(identity)
        if not row.applied_resource: continue
        for panel in row.definition.get("panels",[]):
            for query in panel.get("targets",[]):
                expression=query.get("expr","")
                if (re.search(r"(?<![A-Za-z0-9_:])"+re.escape(metric)+r"\s*\{",expression)
                        and all(key+"="+json.dumps(value) in expression for key,value in {
                            "icheck_device_id":target.device_id,"icheck_connection_id":target.connection_id,
                            "icheck_tenant_id":target.tenant_id,"icheck_region_id":target.region_id}.items())):
                    return resource_url(row.connection_snapshot,"dashboard",row.resource_uid)+"?"+urlencode({"from":"now-1h","to":"now"})
    raise RuleRuntimeError("Save a Grafana dashboard containing this target's measurement in Capability Studio before enabling its alert")


def compile_rule(definition,target,rule_id,revision,dashboard):
    selector,value,expression,labels=expressions(definition,target)
    labels.update(icheck_metric_rule_id=rule_id,icheck_metric_rule_revision=str(revision),severity=definition.severity)
    return {"alert":"icheck_metric_"+rule_id.replace("-",""),"expr":expression,"for":f"{definition.hold_seconds}s",
        "labels":labels,"annotations":{"summary":definition.name,
            "description":f"{definition.aggregation} {definition.measurement} of {definition.metric} {definition.comparison} {definition.threshold:g}. Missing data and condition clearance do not prove infrastructure recovery.",
            "dashboard_url":dashboard,"investigation_url":"/?"+urlencode({"brief":f"Investigate metric alert {definition.name} for device {target.device_id}; inspect observed evidence and unknowns."})}}


def test_definition(db,definition,actor,*,lock=False):
    initial=monitoring.monitoring_target(db,actor,definition.enrollment_id)
    if lock:
        device,connection=monitoring._connection(db,actor,initial.device_id,initial.connection_id,lock=True)
        monitoring._credential(db,connection,lock=True)
        db.scalar(select(DeviceMonitoringEnrollment).where(DeviceMonitoringEnrollment.id==initial.enrollment_id).with_for_update())
    source=backend(db,actor,definition.backend_id,lock=lock)
    source_revision=source.revision
    available=supported_metrics(db,initial)
    if definition.metric not in available: raise RuleRuntimeError("Choose an actual metric declared by this approved monitoring enrollment")
    if (available[definition.metric]=="counter")!=(definition.measurement=="rate"):
        raise RuleRuntimeError("Counters require a rate window; gauges require their current value")
    selector,expression,_,_=expressions(definition,initial)
    def query(text):
        return metrics.query_instant(db,source,PrometheusInstantQuery(query=text,timeout_seconds=3,limit=5,actor=actor.subject),principal=actor)
    samples=query(expression); stamps=query("min(timestamp("+selector+"))")
    if samples.result_type!="vector" or stamps.result_type!="vector" or len(samples.result)!=1 or len(stamps.result)!=1:
        raise RuleRuntimeError("Actual measurement and source sample time are required before reviewing this rule")
    value=float(samples.result[0]["value"][1]); timestamp=float(stamps.result[0]["value"][1]); now=utcnow().timestamp()
    if not math.isfinite(value) or not math.isfinite(timestamp) or not now-max(60,3*initial.schedule_seconds+initial.timeout_seconds)<=timestamp<=now+5:
        raise RuleRuntimeError("Rule test requires finite, fresh actual measurement samples")
    current=monitoring.monitoring_target(db,actor,definition.enrollment_id)
    if target_snapshot(initial)!=target_snapshot(current) or backend(db,actor,definition.backend_id).revision!=source_revision:
        raise RuleRuntimeConflict("Metric source changed during the rule test")
    return initial,source,{"current_value":value,"oldest_sample_timestamp":timestamp,"rule_evaluator":"prometheus","notification_delivery_verified":False}


def rule_row(db,identifier,actor,*,lock=False):
    statement=select(AlertRule).where(AlertRule.id==identifier,AlertRule.event_type==EVENT,namespace_clause(AlertRule,actor)).execution_options(populate_existing=True)
    row=db.scalar(statement.with_for_update() if lock else statement)
    if row is None: raise LookupError("Native metric rule not found")
    return row


def sql_catalog(db,actor):
    rows=db.scalars(select(AlertRule).where(AlertRule.event_type==EVENT,AlertRule.enabled,namespace_clause(AlertRule,actor))).all()
    return catalog(row.conditions["compiled_rule"] for row in rows if row.conditions.get("revision",0)>0)


def plan(row):
    return {key:getattr(row,key) for key in ("rule_id","expected_revision","definition","target_snapshot","backend_revision","compiled_rule",
        "catalog_before","catalog_after","runtime_before_hash","runtime_binding","previous_definition","restore_of_id")}


def read_change(row):
    return {"id":row.id,"rule_id":row.rule_id,"revision":row.expected_revision+1,"definition":row.definition,"compiled_rule":row.compiled_rule,
        "previous_definition":row.previous_definition,"status":row.status,"plan_hash":row.plan_hash,"error_code":row.error_code,
        "created_at":row.created_at.isoformat(),"applied_at":row.applied_at.isoformat() if row.applied_at else None,"review_url":"/alerts/metric-rules?proposal="+row.id,
        "warning":"Prometheus evaluates this rule; source clearance and acknowledgement do not prove fault recovery. Notification delivery requires actual Alertmanager receipts."}


def change(db,identifier,actor,*,lock=False):
    statement=select(MetricRuleChange).where(MetricRuleChange.id==identifier,namespace_clause(MetricRuleChange,actor)).execution_options(populate_existing=True)
    row=db.scalar(statement.with_for_update() if lock else statement)
    if row is None: raise LookupError("Metric rule proposal not found")
    return row


def preview(db,payload,actor,*,restore_of=None):
    guard(actor); runtime=RUNTIME(); definition=payload.definition
    if not definition.enabled and not payload.rule_id:
        raise RuleRuntimeError("Withdrawal requires an existing applied rule; a new proposal is enabled only after human confirmation")
    runtime.guard(actor,definition.backend_id)
    with runtime.lock():
        before=runtime.read()
        if digest(before)!=digest(sql_catalog(db,actor)): raise RuleRuntimeConflict("Native catalog differs from retained applied rules; inspect any uncertain change first")
        if payload.rule_id:
            rule=rule_row(db,payload.rule_id,actor,lock=True)
            if definition.name!=rule.name: raise RuleRuntimeError("Rule name is its stable identity; revise the threshold without renaming it")
            previous=rule.conditions.get("definition")
            if not definition.enabled:
                if previous is None or {**definition.model_dump(mode="json"),"enabled":previous["enabled"]}!=previous:
                    raise RuleRuntimeError("Withdrawal must preserve the existing rule definition except enabled")
                target=SimpleNamespace(**rule.conditions["target_snapshot"])
                source=backend(db,actor,definition.backend_id,allow_disabled=True)
                evidence={"source_measurement_required":False,"rule_evaluator":"prometheus","notification_delivery_verified":False}
            else: target,source,evidence=test_definition(db,definition,actor)
        else:
            target,source,evidence=test_definition(db,definition,actor)
            if db.scalar(select(AlertRule.id).where(AlertRule.event_type==EVENT,namespace_clause(AlertRule,actor)).offset(99).limit(1)):
                raise RuleRuntimeError("Preview supports at most 100 metric rules")
            rule=AlertRule(id=new_id(),name=definition.name,event_type=EVENT,severity=AlertSeverity(definition.severity),enabled=False,
                conditions={"contract":"icheck.metric-rule/v1","revision":0},cooldown_seconds=0)
            db.add(rule)
            try: db.flush()
            except IntegrityError:
                db.rollback(); raise RuleRuntimeConflict("Rule name already exists; use its retained ID to revise it") from None
        revision=rule.conditions.get("revision",0)
        if payload.expected_revision!=revision: raise RuleRuntimeConflict("Rule revision changed after selection")
        dashboard=dashboard_url(db,actor,target,definition.metric) if definition.enabled else rule.conditions["compiled_rule"]["annotations"]["dashboard_url"]
        compiled=compile_rule(definition,target,rule.id,revision+1,dashboard)
        revised=[item for item in before["groups"][0]["rules"] if item["alert"]!=compiled["alert"]]
        if definition.enabled: revised.append(compiled)
        snapshot=rule.conditions["target_snapshot"] if not definition.enabled and payload.rule_id else target_snapshot(target)
        row=MetricRuleChange(id=new_id(),rule_id=rule.id,expected_revision=revision,definition=definition.model_dump(mode="json"),
            target_snapshot=snapshot,backend_revision=source.revision,compiled_rule=compiled,catalog_before=before,catalog_after=catalog(revised),
            runtime_before_hash=digest(before),runtime_binding=runtime.binding,previous_definition=rule.conditions.get("definition"),
            restore_of_id=restore_of,status="proposed",created_by=actor.subject)
        row.plan_hash=digest(plan(row)); db.add(row)
        record_audit_event(db,event_type="metric_rule.proposed",actor_type=actor.principal_type,actor_id=actor.subject,
            entity_type="metric_rule_change",entity_id=row.id,details={"rule_id":rule.id,"plan_hash":row.plan_hash})
        db.commit()
        return {**read_change(row),"test_evidence":evidence}


def finish(db,row,rule,actor):
    if rule.conditions.get("revision",0)!=row.expected_revision:
        raise RuleRuntimeConflict("A newer rule revision prevents completing this old write receipt")
    rule.enabled=row.definition["enabled"]; rule.severity=AlertSeverity(row.definition["severity"])
    rule.conditions={"contract":"icheck.metric-rule/v1","revision":row.expected_revision+1,"definition":row.definition,
        "target_snapshot":row.target_snapshot,"compiled_rule":row.compiled_rule,"applied_change_id":row.id}
    row.status="applied"; row.applied_at=utcnow(); row.error_code=None
    record_audit_event(db,event_type="metric_rule.applied",actor_type="user",actor_id=actor.subject,
        entity_type="metric_rule_change",entity_id=row.id,details={"rule_id":row.rule_id,"revision":row.expected_revision+1})
    db.commit(); return read_change(row)


def confirm(db,identifier,payload,actor):
    guard(actor,human=True); runtime=RUNTIME()
    with runtime.lock():
        row=change(db,identifier,actor,lock=True); rule=rule_row(db,row.rule_id,actor,lock=True)
        if not secrets.compare_digest(payload.expected_plan_hash,row.plan_hash) or digest(plan(row))!=row.plan_hash:
            raise RuleRuntimeConflict("Reviewed metric rule changed; refresh its exact preview")
        if runtime.binding!=row.runtime_binding: raise RuleRuntimeConflict("Native runtime binding changed; do not recover against another backend")
        if row.status=="applied": return read_change(row)
        if row.status in {"applying","unknown"}:
            current_authority(db,actor)
            if digest(runtime.read())==digest(row.catalog_after) and runtime.matches(row.catalog_after):
                return finish(db,row,rule,actor)
            row.status="unknown"; row.error_code="runtime_outcome_unresolved"; db.commit(); return read_change(row)
        if row.status!="proposed" or rule.conditions.get("revision",0)!=row.expected_revision:
            raise RuleRuntimeConflict("Rule is no longer awaiting this confirmation")
        if digest(runtime.read())!=row.runtime_before_hash or digest(sql_catalog(db,actor))!=digest(row.catalog_before):
            row.status="conflict"; row.error_code="catalog_changed"; db.commit(); raise RuleRuntimeConflict("Another rule changed the catalog; review a fresh proposal")
        definition=MetricRuleDefinition.model_validate(row.definition)
        if definition.enabled: target,source,_=test_definition(db,definition,actor,lock=True)
        else:
            target=SimpleNamespace(**row.target_snapshot)
            source=backend(db,actor,definition.backend_id,lock=True,allow_disabled=True)
        authority=current_authority(db,actor)
        if (definition.enabled and target_snapshot(target)!=row.target_snapshot) or source.revision!=row.backend_revision:
            raise RuleRuntimeConflict("Approved enrollment or metric backend changed; test and review again")
        if definition.enabled and dashboard_url(db,actor,target,definition.metric)!=row.compiled_rule["annotations"]["dashboard_url"]:
            raise RuleRuntimeConflict("Saved Grafana dashboard binding changed; review the new link")
        if authority: authority.assert_live(db)
        row.status="applying"; row.approved_by=actor.subject; db.commit()
        # Durable admission survives response loss. Reacquire current authority
        # and source locks after that commit, immediately before the native write.
        row=change(db,row.id,actor,lock=True); rule=rule_row(db,row.rule_id,actor,lock=True)
        try:
            if definition.enabled: target,source,_=test_definition(db,definition,actor,lock=True)
            authority=current_authority(db,actor)
            if definition.enabled:
                _,connection=monitoring._connection(db,actor,target.device_id,target.connection_id,lock=True)
                monitoring._credential(db,connection,lock=True)
                db.scalar(select(DeviceMonitoringEnrollment).where(DeviceMonitoringEnrollment.id==target.enrollment_id).with_for_update())
            source=backend(db,actor,definition.backend_id,lock=True,allow_disabled=not definition.enabled)
            if (definition.enabled and target_snapshot(target)!=row.target_snapshot) or source.revision!=row.backend_revision: raise RuleRuntimeConflict("Source changed before native write")
            def admit():
                if authority: authority.assert_live(db)
                if definition.enabled and target_snapshot(monitoring.monitoring_target(db,actor,definition.enrollment_id))!=row.target_snapshot:
                    raise RuleRuntimeConflict("Monitoring authority changed before installation")
                if definition.enabled and dashboard_url(db,actor,target,definition.metric)!=row.compiled_rule["annotations"]["dashboard_url"]:
                    raise RuleRuntimeConflict("Grafana binding changed before installation")
            runtime.write(row.catalog_after,row.runtime_before_hash,admit=admit)
            runtime.reload()
            if not runtime.matches(row.catalog_after): raise RuleRuntimeUnknown("Reloaded rules have not matched the confirmed definition")
            return finish(db,row,rule,actor)
        except (RuleRuntimeError,PermissionError,LookupError,metrics.MetricQueryError,metrics.MetricBackendUnavailable):
            row.status="unknown"; row.error_code="native_write_requires_inspection"; db.commit(); return read_change(row)


def restore_preview(db,identifier,actor):
    guard(actor); old=change(db,identifier,actor)
    if old.status!="applied" or old.previous_definition is None: raise RuleRuntimeError("Choose an applied revision with a retained prior definition")
    rule=rule_row(db,old.rule_id,actor)
    return preview(db,MetricRulePreview(definition=old.previous_definition,rule_id=rule.id,expected_revision=rule.conditions["revision"]),actor,restore_of=old.id)


def targets(db,actor):
    from ..models import Device
    guard(actor); snapshot=monitoring.monitoring_snapshot(db,actor)
    return {"backend_id":get_settings().metric_rule_backend_id,"targets":[{"enrollment_id":target.enrollment_id,"enrollment_revision":target.enrollment_revision,
        "device_id":target.device_id,"connection_id":target.connection_id,"name":db.get(Device,target.device_id).name,
        "host":target.host,"protocol":target.protocol,"metrics":[{"name":name,"type":kind} for name,kind in supported_metrics(db,target).items()]}
        for target in snapshot.targets[:100]],"has_more":len(snapshot.targets)>100}


def tools_for_ai(name,db,arguments,actor):
    guard(actor)
    if name=="alerts.metric_rules.targets": result=targets(db,actor)
    elif name=="alerts.metric_rule.preview": result=preview(db,MetricRulePreview.model_validate(arguments),actor)
    elif name=="alerts.metric_rule.change.get": result=read_change(change(db,arguments["change_id"],actor))
    else: raise RuleRuntimeError("Unsupported native metric-alert tool")
    from ..agent_schemas import InvestigationEvidenceCreate
    return result,[InvestigationEvidenceCreate(evidence_type="metric_rule",evidence_id=result.get("id","approved-monitoring-targets"),
        summary="A proposed rule is not installed; applied status is not proof of notification delivery or fault recovery.",observed_at=utcnow())]


def ingest(db,payload,actor):
    settings=get_settings()
    if (not settings.metric_alert_webhook_subject or actor.principal_type!="service" or actor.auth_method!="bearer"
            or actor.subject!=settings.metric_alert_webhook_subject or not actor.permits("alerts.emit")
            or payload.receiver!=settings.metric_alert_receiver or payload.truncatedAlerts):
        raise PermissionError("Only the provisioned complete Alertmanager notification receiver can ingest metric episodes")
    processed=[]
    for event in payload.alerts:
        identifier=event.labels.get("icheck_metric_rule_id"); revision=event.labels.get("icheck_metric_rule_revision")
        rule=rule_row(db,identifier,actor,lock=True)
        version=db.scalar(select(MetricRuleChange).where(MetricRuleChange.rule_id==rule.id,MetricRuleChange.status=="applied",
            namespace_clause(MetricRuleChange,actor),MetricRuleChange.expected_revision==int(revision)-1))
        if version is None: raise RuleRuntimeError("Notification does not match a retained applied metric-rule version")
        expected={"alertname":version.compiled_rule["alert"],**version.compiled_rule["labels"]}
        if any(event.labels.get(key)!=value for key,value in expected.items()): raise RuleRuntimeError("Notification labels do not match the approved rule and namespace")
        snapshot=version.target_snapshot
        if event.startsAt>utcnow()+timedelta(seconds=5): raise RuleRuntimeError("Notification starts in the future")
        if event.status=="firing":
            if not rule.enabled or rule.conditions.get("revision")!=int(revision): raise RuleRuntimeConflict("Firing notification belongs to a withdrawn or superseded rule")
            if target_snapshot(monitoring.monitoring_target(db,actor,snapshot["enrollment_id"]))!=snapshot:
                raise RuleRuntimeConflict("Metric source authority no longer matches this firing notification")
        elif event.endsAt<event.startsAt or event.endsAt>utcnow()+timedelta(seconds=5):
            raise RuleRuntimeError("Cleared notification time is invalid")
        dedup="metric:"+rule.id+":"+revision
        db.info["native_metric_alert_writer"]=True
        try:
            if event.status=="firing":
                row=alerts.upsert_alert(db,dedup_key=dedup,event_type=EVENT,severity=AlertSeverity(version.definition["severity"]),
                    title=version.definition["name"],description=version.compiled_rule["annotations"]["description"],entity_type="device",entity_id=snapshot["device_id"],
                    rule_id=rule.id,details={"metric_rule_id":rule.id,"metric_rule_revision":int(revision),"source":"prometheus_alertmanager",
                        "notification_receiver":payload.receiver,"notification_received_at":utcnow().isoformat(),
                        "dashboard_url":version.compiled_rule["annotations"]["dashboard_url"],"investigation_url":version.compiled_rule["annotations"]["investigation_url"],
                        "fault_recovery_verified":False},observed_at=event.startsAt)
            else:
                row=alerts.resolve_by_dedup_key(db,dedup,"Prometheus condition cleared; infrastructure recovery unverified",event.endsAt,
                    source_identity=(EVENT,"device",snapshot["device_id"],rule.id),source_quiet_verified=False)
        finally: db.info.pop("native_metric_alert_writer",None)
        processed.append({"rule_id":rule.id,"device_id":snapshot["device_id"],"alert_id":row.id if row else None,"source_status":event.status,"fault_recovery_verified":False})
    record_audit_event(db,event_type="metric_rule.notification.received",actor_type="service",actor_id=actor.subject,
        entity_type="alertmanager_receiver",entity_id=settings.metric_alert_receiver,details={"alert_count":len(processed),"episodes":processed})
    db.commit(); return {"accepted":len(processed),"episodes":processed,"evaluator":"prometheus","raw_notification_labels_or_urls_retained":False}
