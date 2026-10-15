"""Explicit continuous monitoring authority, independent of exporter custody."""
from datetime import UTC, timedelta
import hashlib
import ipaddress
import json

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from ..database import require_locking_transaction
from ..http_metrics import HTTPMonitorSpec, spec_hash
from ..exporter_metrics import ExporterMonitorSpec, PROTOCOLS, spec_hash as exporter_hash
from ..models import CredentialProfile, Device, DeviceConnection, DeviceMonitoringEnrollment, utcnow
from ..monitoring_schemas import (MonitoringApproval, MonitoringEnrollmentRead, MonitoringPreview,
    MonitoringSnapshot, MonitoringTarget, MonitoringWithdrawal)
from .audit import record_audit_event
from .authorization_scope import device_scope_clause, namespace_clause
from .control_plane_auth import PrincipalContext
from .trust_authority import lock_publisher_resource


SUPPORTED = {"snmp": "snmp_exporter", "windows_exporter": "windows_exporter", "https_api": "http_json", "node_exporter":"node_exporter", "cadvisor":"cadvisor", "vmware_exporter":"vmware_exporter"}
SNAPSHOT_LIMIT = 10000


def request_managed_snmp_monitoring(db, device, connection, *, actor):
    """Explicit onboarding intent; no target is issued before verification.

    This selects existing native gateway custody, never widens its sites, CIDRs,
    ports or modules. Legacy/external credentials retain the reviewed setup path.
    """
    from ..models import ManagedDeviceCredential
    if connection.protocol != 'snmp' or not connection.enabled:
        return None
    profile = _credential(db, connection, lock=True)
    if profile is None or profile.provider != 'managed_device':
        return None
    managed = db.scalar(select(ManagedDeviceCredential).where(ManagedDeviceCredential.credential_profile_id == profile.id))
    if managed is None or managed.kind != 'snmp_v2c':
        return None
    now = utcnow()
    enrollment = DeviceMonitoringEnrollment(connection_id=connection.id, revision=1, enabled=True,
        device_identity_revision=device.identity_revision, connection_fingerprint=_connection_fingerprint(connection),
        credential_profile_id=profile.id, credential_fingerprint=_credential_fingerprint(profile),
        gateway_profile='preview-snmp', modules=connection.configuration.get('modules', ['if_mib']),
        collectors=[], schedule_seconds=30, timeout_seconds=10, approved_at=now,
        approved_until=now + timedelta(hours=168), approved_by=actor)
    db.add(enrollment); db.flush()
    record_audit_event(db, event_type='device.monitoring.requested_onboarding', actor_type='user', actor_id=actor,
        entity_type='device_monitoring_enrollment', entity_id=enrollment.id,
        details={'device_id': device.id, 'connection_id': connection.id, 'verification_required': True,
            'gateway_profile': enrollment.gateway_profile, 'schedule_seconds': 30, 'timeout_seconds': 10,
            'approved_until': _utc(enrollment.approved_until).isoformat()})
    return enrollment


def _utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _connection_fingerprint(connection):
    return _hash({"id": connection.id, "protocol": connection.protocol, "adapter": connection.adapter_type,
        "port": connection.port, "credential": connection.credential_profile_ref,
        "selector": connection.worker_selector, "configuration": connection.configuration})


def _credential_fingerprint(profile, *, include_revision=False):
    if profile is None: return None
    value = {"id": profile.id, "name": profile.name, "provider": profile.provider,
        "ref": profile.secret_ref, "adapters": profile.allowed_adapters,
        "selector": profile.worker_selector, "enabled": profile.enabled}
    # Do not change legacy SNMP/Windows fingerprints or invalidate their grants.
    if include_revision: value["revision"] = profile.revision
    return _hash(value)


def _credential_revision_required(connection):
    return connection.protocol=="https_api" or bool(connection.configuration.get("exporter_monitor")) or (connection.protocol=="snmp" and bool(connection.configuration.get("monitoring_template_version_id")))


def http_evidence_matches(connection, profile, *, evidence=None):
    spec = HTTPMonitorSpec.model_validate(connection.configuration.get("http_monitor"))
    proof = connection.last_verification_evidence if evidence is None else evidence
    expected = sorted(metric.name for metric in spec.metrics)
    return (proof.get("check") == "http_metric_query" and proof.get("success") is True
        and proof.get("spec_hash") == spec_hash(spec) and proof.get("metric_names") == expected
        and proof.get("target_host") == connection.device.management_ip and proof.get("target_port") == connection.port
        and (spec.scheme != "https" or proof.get("tls_tested") is True)
        and (spec.mode == "probe" or (isinstance(proof.get("metric_samples"), int)
            and not isinstance(proof["metric_samples"], bool) and proof["metric_samples"] >= len(expected)))
        and (spec.auth_mode == "none" or (profile is not None and profile.provider == "managed_device"
            and proof.get("authentication_tested") is True and proof.get("credential_revision") == profile.revision)))


def _credential(db, connection, *, lock=False):
    if not connection.credential_profile_ref: return None
    query = select(CredentialProfile).where(or_(CredentialProfile.id == connection.credential_profile_ref,
        CredentialProfile.name == connection.credential_profile_ref)).execution_options(populate_existing=True)
    if lock: query = query.with_for_update(read=True)
    return db.scalar(query)


def _rows(db, principal, *, enrollment_id=None, limit=None, device_ids=None):
    visibility = device_scope_clause(principal)
    # The protected, single-purpose gateway is authorized by Collector scope,
    # not optional physical placement. Do not widen ordinary inventory readers.
    from ..config import get_settings
    subject = get_settings().managed_monitoring_gateway_subject
    sites = [str(site) for site in principal.authorization_scope.get('sites', []) if site]
    if subject and principal.principal_type == 'service' and principal.subject == subject and sites:
        visibility = or_(visibility, and_(namespace_clause(Device, principal), Device.site.is_(None),
            DeviceConnection.worker_selector['site'].as_string().in_(sites)))
    query = select(DeviceMonitoringEnrollment, DeviceConnection, Device, CredentialProfile).join(
        DeviceConnection, and_(DeviceConnection.id == DeviceMonitoringEnrollment.connection_id,
            DeviceConnection.tenant_id == DeviceMonitoringEnrollment.tenant_id,
            DeviceConnection.region_id == DeviceMonitoringEnrollment.region_id)).join(
        Device, and_(Device.id == DeviceConnection.device_id, Device.tenant_id == DeviceConnection.tenant_id,
            Device.region_id == DeviceConnection.region_id)).outerjoin(CredentialProfile, and_(
        CredentialProfile.id == DeviceMonitoringEnrollment.credential_profile_id,
        CredentialProfile.tenant_id == Device.tenant_id, CredentialProfile.region_id == Device.region_id)).where(
        visibility).execution_options(populate_existing=True)
    if enrollment_id: query = query.where(DeviceMonitoringEnrollment.id == enrollment_id)
    else:
        query = query.where(DeviceMonitoringEnrollment.enabled, DeviceMonitoringEnrollment.approved_until > utcnow(),
            Device.enabled, DeviceConnection.enabled, DeviceConnection.verification_status == "verified")
    query = query.order_by(DeviceMonitoringEnrollment.id)
    if device_ids is not None: query = query.where(Device.id.in_(device_ids))
    if limit is not None: query = query.limit(limit)
    return db.execute(query).all()


def _blockers(device, connection, profile):
    blockers = []
    if connection.protocol not in SUPPORTED or connection.adapter_type != SUPPORTED.get(connection.protocol):
        blockers.append("Choose a supported SNMP, HTTP/API, system, container or VMware connection")
    if connection.protocol == "https_api":
        try:
            if not http_evidence_matches(connection, profile):
                blockers.append("Test the current HTTP template and credential against this target before enabling collection")
        except ValueError:
            blockers.append("Save a valid HTTP/API monitoring template before testing and enabling collection")
    if connection.protocol=="snmp" and connection.configuration.get("monitoring_template_version_id"):
        from .snmp_monitoring_templates import evidence_matches
        if not evidence_matches(connection,profile):
            blockers.append("Test every requested metric with the current installed SNMP module and credential before enabling")
    if connection.protocol in {"node_exporter","cadvisor","vmware_exporter"} or connection.protocol=="windows_exporter" and "exporter_monitor" in connection.configuration:
        from .exporter_monitoring_templates import evidence_matches
        try:
            if not evidence_matches(connection,profile): blockers.append("Test every requested exporter metric and collector with the current template before enabling")
        except (ValueError,KeyError): blockers.append("Save a valid native exporter monitoring template before testing")
    if not device.enabled or not connection.enabled:
        blockers.append("Device and connection must be enabled")
    if connection.verification_status != "verified" or connection.last_verified_at is None:
        blockers.append("Verify this connection before approving continuous monitoring")
    elif _utc(connection.last_verified_at) > utcnow():
        blockers.append("Connection verification is future-dated")
    try:
        address = ipaddress.ip_address(device.management_ip)
        if address.is_unspecified or address.is_multicast:
            raise ValueError("Non-unicast target")
    except (ValueError, TypeError): blockers.append("Monitoring requires a unicast management IP")
    if not connection.port or not 1 <= connection.port <= 65535:
        blockers.append("Monitoring requires a valid connection port")
    if connection.credential_profile_ref:
        if profile is None or not profile.enabled or connection.adapter_type not in profile.allowed_adapters:
            blockers.append("Connection credential profile is unavailable or does not allow this adapter")
        elif any(connection.worker_selector.get(k) != v for k, v in profile.worker_selector.items()):
            blockers.append("Connection no longer satisfies its credential scope")
    if device.site and connection.worker_selector.get("site") != device.site:
        blockers.append("Connection site selector no longer matches device placement")
    return blockers


def _preview_hash(device, connection, profile):
    return _hash({"device": device.id, "identity_revision": device.identity_revision,
        "host": device.management_ip, "site": device.site, "enabled": device.enabled,
        "connection": _connection_fingerprint(connection), "connection_enabled": connection.enabled,
        "verification": connection.verification_status,
        "verified_at": _utc(connection.last_verified_at).isoformat() if connection.last_verified_at else None,
        "credential": _credential_fingerprint(profile, include_revision=_credential_revision_required(connection))})


def _target(row, *, issued):
    enrollment, connection, device, profile = row
    if connection.configuration.get("exporter_monitor"):
        from sqlalchemy.orm import object_session
        from ..models import ArtifactVersion,ArtifactVersionStatus
        from .exporter_monitoring_templates import validate_contract
        from .capability_pack_revocations import assert_artifact_version_not_revoked
        db=object_session(connection)
        try:
            version=db.get(ArtifactVersion,connection.configuration.get("monitoring_template_version_id"),populate_existing=True) if db else None
            if version is None or version.tenant_id!=device.tenant_id or version.region_id!=device.region_id or version.status not in {ArtifactVersionStatus.PUBLISHED,ArtifactVersionStatus.DEPRECATED}: return None
            validate_contract(version.definition,version.implementation,version.tests,version.collector_definition)
            assert_artifact_version_not_revoked(db,version.id)
            monitor=ExporterMonitorSpec.model_validate(connection.configuration["exporter_monitor"])
            if (version.definition["port"]!=connection.port or PROTOCOLS[monitor.plugin]!=connection.protocol
                    or exporter_hash(monitor)!=exporter_hash(ExporterMonitorSpec.model_validate(version.definition["exporter_monitor"]))
                    or enrollment.modules or enrollment.collectors!=monitor.collectors()): return None
        except (ValueError,KeyError,LookupError): return None
    if connection.protocol=="snmp" and connection.configuration.get("monitoring_template_version_id"):
        from sqlalchemy.orm import object_session
        from ..models import ArtifactVersion,ArtifactVersionStatus
        from .snmp_monitoring_templates import installed,configuration,validate_contract
        from .capability_pack_revocations import assert_artifact_version_not_revoked
        db=object_session(connection)
        try:
            version=db.get(ArtifactVersion,connection.configuration["monitoring_template_version_id"],populate_existing=True) if db else None
            if (version is None or version.tenant_id!=device.tenant_id or version.region_id!=device.region_id
                    or version.status not in {ArtifactVersionStatus.PUBLISHED,ArtifactVersionStatus.DEPRECATED}): return None
            validate_contract(version.definition,version.implementation,version.tests,version.collector_definition)
            assert_artifact_version_not_revoked(db,version.id)
            compiled=version.definition["compiled_module"]
            if not installed(compiled) or any(connection.configuration.get(k)!=v for k,v in configuration(compiled,version.id).items()): return None
            if enrollment.modules!=[compiled["module_name"]] or enrollment.collectors: return None
        except (ValueError,LookupError,KeyError,OSError): return None
    if connection.protocol == "https_api" and connection.configuration.get("monitoring_template_version_id"):
        # Templates are real registry consumers: unavailable/revoked or changed
        # contracts cannot keep collecting through a stale JSON reference.
        from sqlalchemy.orm import object_session
        from ..models import ArtifactVersion, ArtifactVersionStatus
        from .capability_pack_revocations import assert_artifact_version_not_revoked
        db = object_session(connection)
        version_id = connection.configuration["monitoring_template_version_id"]
        try:
            version = db.get(ArtifactVersion, version_id, populate_existing=True) if db else None
            if (version is None or version.tenant_id != device.tenant_id or version.region_id != device.region_id
                    or version.status not in {ArtifactVersionStatus.PUBLISHED, ArtifactVersionStatus.DEPRECATED}
                    or version.definition.get("schema") != "icheck.monitoring-template/v1"
                    or version.definition.get("port") != connection.port
                    or spec_hash(HTTPMonitorSpec.model_validate(version.definition["http_monitor"])) !=
                        spec_hash(HTTPMonitorSpec.model_validate(connection.configuration["http_monitor"]))):
                return None
            assert_artifact_version_not_revoked(db, version_id)
        except (ValueError, LookupError, KeyError):
            return None
    if (_blockers(device, connection, profile) or not enrollment.enabled
            or _utc(enrollment.approved_until) <= issued or _utc(enrollment.approved_at) > issued
            or enrollment.device_identity_revision != device.identity_revision
            or enrollment.connection_fingerprint != _connection_fingerprint(connection)
            or enrollment.credential_fingerprint != _credential_fingerprint(profile, include_revision=_credential_revision_required(connection))):
        return None
    return MonitoringTarget(enrollment_id=enrollment.id, enrollment_revision=enrollment.revision,
        tenant_id=device.tenant_id, region_id=device.region_id, device_id=device.id, connection_id=connection.id,
        device_identity_revision=device.identity_revision, protocol=connection.protocol,
        host=str(ipaddress.ip_address(device.management_ip)), port=connection.port,
        site=connection.worker_selector.get("site") or device.site or "",
        gateway_profile=enrollment.gateway_profile, credential_profile_id=enrollment.credential_profile_id,
        modules=enrollment.modules, collectors=enrollment.collectors, schedule_seconds=enrollment.schedule_seconds,
        timeout_seconds=enrollment.timeout_seconds, approved_until=_utc(enrollment.approved_until),
        issued_at=issued, expires_at=min(issued + timedelta(seconds=30), _utc(enrollment.approved_until)),
        http_monitor=HTTPMonitorSpec.model_validate(connection.configuration["http_monitor"]) if connection.protocol == "https_api" else None,
        credential_revision=profile.revision if _credential_revision_required(connection) and profile else None,
        snmp_module_sha256=connection.configuration.get("snmp_module_sha256") if connection.protocol=="snmp" and connection.configuration.get("monitoring_template_version_id") else None,
        exporter_monitor=ExporterMonitorSpec.model_validate(connection.configuration["exporter_monitor"]) if connection.configuration.get("exporter_monitor") else None)


def _connection(db, principal, device_id, connection_id, *, lock=False):
    query = select(Device).where(Device.id == device_id, device_scope_clause(principal)).execution_options(populate_existing=True)
    if lock: query = query.with_for_update()
    device = db.scalar(query)
    if device is None: raise LookupError("Device not found")
    query = select(DeviceConnection).where(DeviceConnection.id == connection_id, DeviceConnection.device_id == device.id,
        DeviceConnection.tenant_id == device.tenant_id, DeviceConnection.region_id == device.region_id).execution_options(populate_existing=True)
    if lock: query = query.with_for_update()
    connection = db.scalar(query)
    if connection is None: raise LookupError("Connection not found")
    return device, connection


def monitoring_preview(db, principal, device_id, connection_id):
    device, connection = _connection(db, principal, device_id, connection_id)
    profile = _credential(db, connection)
    enrollment = db.scalar(select(DeviceMonitoringEnrollment).where(DeviceMonitoringEnrollment.connection_id == connection.id)
        .execution_options(populate_existing=True))
    blockers = _blockers(device, connection, profile)
    warnings = []
    if connection.protocol != "https_api" and connection.last_verification_evidence.get("authentication_tested") is False:
        warnings.append("Preflight proved transport only, not exporter authentication or live metric health")
    if profile is None:
        warnings.append("No connection credential profile; gateway custody must explicitly permit this connection")
    return MonitoringPreview(device_id=device.id, connection_id=connection.id,
        preview_hash=_preview_hash(device, connection, profile), eligible=not blockers, blockers=blockers, warnings=warnings,
        enrollment=MonitoringEnrollmentRead.model_validate(enrollment) if enrollment else None,
        currently_authorized=enrollment is not None and _target((enrollment, connection, device, profile), issued=utcnow()) is not None)


def approve_monitoring(db: Session, principal: PrincipalContext, device_id: str, connection_id: str, payload: MonitoringApproval):
    require_locking_transaction(db, purpose="Continuous monitoring approval")
    lock_publisher_resource(db, "monitoring-connection", connection_id)
    device, connection = _connection(db, principal, device_id, connection_id, lock=True)
    profile = _credential(db, connection, lock=True)
    blockers = _blockers(device, connection, profile)
    if blockers: raise ValueError("; ".join(blockers))
    if payload.preview_hash != _preview_hash(device, connection, profile):
        raise ValueError("Monitoring preview changed; refresh before approval")
    if connection.protocol == "snmp" and (not payload.modules or payload.collectors):
        raise ValueError("SNMP enrollment requires modules and no Windows collectors")
    if connection.protocol == "snmp":
        from ..snmp_modules import validate_modules
        validate_modules(payload.modules)
    if connection.protocol == "windows_exporter" and payload.modules:
        raise ValueError("Windows enrollment cannot request SNMP modules")
    if connection.protocol == "https_api" and (payload.modules or payload.collectors):
        raise ValueError("HTTP enrollment uses its tested template, not SNMP modules or Windows collectors")
    enrollment = db.scalar(select(DeviceMonitoringEnrollment).where(DeviceMonitoringEnrollment.connection_id == connection.id)
        .with_for_update().execution_options(populate_existing=True))
    if payload.expected_revision != (enrollment.revision if enrollment else 0):
        raise ValueError("Monitoring enrollment revision changed; refresh before approval")
    if enrollment is None:
        enrollment = DeviceMonitoringEnrollment(connection_id=connection.id, revision=1)
        db.add(enrollment)
    else: enrollment.revision += 1
    enrollment.enabled = True
    enrollment.device_identity_revision = device.identity_revision
    enrollment.connection_fingerprint = _connection_fingerprint(connection)
    enrollment.credential_profile_id = profile.id if profile else None
    enrollment.credential_fingerprint = _credential_fingerprint(profile, include_revision=_credential_revision_required(connection))
    enrollment.gateway_profile = payload.gateway_profile
    enrollment.modules = payload.modules
    enrollment.collectors = payload.collectors
    enrollment.schedule_seconds = payload.schedule_seconds
    enrollment.timeout_seconds = payload.timeout_seconds
    enrollment.approved_by = payload.actor
    enrollment.approved_at = utcnow()
    enrollment.approved_until = enrollment.approved_at + timedelta(hours=payload.validity_hours)
    db.flush()
    record_audit_event(db, event_type="device.monitoring.approved", actor_type=principal.principal_type,
        actor_id=payload.actor, entity_type="device_monitoring_enrollment", entity_id=enrollment.id,
        details={"device_id": device.id, "connection_id": connection.id, "revision": enrollment.revision,
            "device_identity_revision": enrollment.device_identity_revision,
            "gateway_profile": enrollment.gateway_profile, "modules": enrollment.modules,
            "collectors": enrollment.collectors, "schedule_seconds": enrollment.schedule_seconds,
            "timeout_seconds": enrollment.timeout_seconds,
            "approved_until": _utc(enrollment.approved_until).isoformat(),
            "reason_sha256": _hash(payload.reason)})
    db.commit()
    db.refresh(enrollment)
    return enrollment


def withdraw_monitoring(db, principal, device_id, connection_id, payload: MonitoringWithdrawal):
    require_locking_transaction(db, purpose="Continuous monitoring withdrawal")
    lock_publisher_resource(db, "monitoring-connection", connection_id)
    _, connection = _connection(db, principal, device_id, connection_id, lock=True)
    enrollment = db.scalar(select(DeviceMonitoringEnrollment).where(DeviceMonitoringEnrollment.connection_id == connection.id)
        .with_for_update().execution_options(populate_existing=True))
    if enrollment is None: raise LookupError("Monitoring enrollment not found")
    if enrollment.revision != payload.expected_revision: raise ValueError("Monitoring enrollment revision changed; refresh before withdrawal")
    enrollment.enabled = False
    enrollment.revision += 1
    record_audit_event(db, event_type="device.monitoring.withdrawn", actor_type=principal.principal_type,
        actor_id=payload.actor, entity_type="device_monitoring_enrollment", entity_id=enrollment.id,
        details={"device_id": device_id, "connection_id": connection.id, "revision": enrollment.revision,
                 "reason_sha256": _hash(payload.reason)})
    db.commit()
    db.refresh(enrollment)
    return enrollment


def monitoring_snapshot(db, principal):
    # One bounded joined SELECT supplies a consistent statement snapshot,
    # including credential metadata. Never publish a truncated target set.
    rows = _rows(db, principal, limit=SNAPSHOT_LIMIT + 1)
    if len(rows) > SNAPSHOT_LIMIT: raise ValueError("Monitoring target snapshot exceeds the complete 10000-target bound")
    issued = utcnow()
    targets = [target for row in rows if (target := _target(row, issued=issued)) is not None]
    return MonitoringSnapshot(tenant_id=principal.tenant_id, region_id=principal.region_id,
        issued_at=issued, expires_at=issued + timedelta(seconds=30), targets=targets)


def monitoring_target(db, principal, enrollment_id):
    rows = _rows(db, principal, enrollment_id=enrollment_id)
    if not rows or (target := _target(rows[0], issued=utcnow())) is None:
        raise LookupError("Monitoring enrollment is unavailable or no longer authorized")
    return target
