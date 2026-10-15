from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, null, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..device_schemas import (
    DeviceConnectionInput,
    DeviceMetadataUpdate,
    DeviceOnboardCreate,
    DevicePreflightAssignment,
    DevicePreflightClaim,
    DevicePreflightComplete,
)
from ..models import (
    CollectorWorker,
    CollectorWorkerState,
    CredentialProfile,
    Device,
    DeviceConnection,
    DeviceConnectionPreflight,
    ManagedDeviceCredential,
    utcnow,
)
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets


PROTOCOL_ADAPTERS = {
    "snmp": "snmp_exporter",
    "https_api": "http_json",
    "ssh": "ssh",
    "windows_exporter": "windows_exporter",
    "node_exporter": "node_exporter",
    "cadvisor": "cadvisor",
    "vmware_exporter": "vmware_exporter",
    "winrm_https": "psrp_cim",
    "icmp": "icmp",
}

PROTOCOL_ACTIVATION_ADAPTERS = {
    protocol: frozenset({adapter})
    for protocol, adapter in PROTOCOL_ADAPTERS.items()
}
PROTOCOL_ACTIVATION_ADAPTERS["snmp"] = frozenset(
    {"snmp_exporter", "snmp_topology"}
)
PROTOCOL_ACTIVATION_ADAPTERS["ssh"] = frozenset(
    {"ssh", "ssh_command_sandbox"}
)
PROTOCOL_ACTIVATION_ADAPTERS["https_api"] = frozenset(
    {"http_json", "http_json_sandbox"}
)

DEFAULT_PORTS = {
    "snmp": 161,
    "https_api": 443,
    "ssh": 22,
    "windows_exporter": 9182,
    "node_exporter": 9100,
    "cadvisor": 8080,
    "vmware_exporter": 9272,
    "winrm_https": 5986,
    "icmp": None,
}


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _credential_profile(
    db: Session,
    reference: str,
) -> CredentialProfile | None:
    return db.scalar(
        select(CredentialProfile).where(
            or_(
                CredentialProfile.id == reference,
                CredentialProfile.name == reference,
            )
        )
    )


def _connection_values(
    db: Session,
    payload: DeviceConnectionInput,
    *,
    site: str | None,
    actor: str,
) -> dict[str, object]:
    adapter_type = PROTOCOL_ADAPTERS[payload.protocol]
    worker_selector = dict(payload.worker_selector)
    selector_site = worker_selector.get("site")
    if site and selector_site and selector_site != site:
        raise ValueError(
            "connection worker_selector site must match the device site"
        )
    if site:
        worker_selector.setdefault("site", site)
    elif worker_selector.get("site") == "":
        worker_selector.pop("site")
    assert_no_inline_secrets(worker_selector, "worker_selector")
    assert_no_inline_secrets(payload.configuration, "connection.configuration")
    if "studio_ssh_compatibility" in payload.configuration:
        raise ValueError("Change SSH compatibility through the reviewed device profile operation")
    mode = payload.configuration.get("verification_mode")
    if mode is not None and (payload.protocol != "ssh" or mode != "studio"):
        raise ValueError("Studio-only verification is supported only for SSH connections")
    if mode == "studio":
        credential = _credential_profile(db, payload.credential_profile_ref) if payload.credential_profile_ref else None
        managed = db.scalar(select(ManagedDeviceCredential).where(
            ManagedDeviceCredential.credential_profile_id == credential.id)) if credential else None
        if (managed is None or managed.kind != "ssh_password" or (site and managed.site != site)
                or credential.worker_selector != {"site": managed.site}
                or worker_selector not in ({}, {"site": managed.site})):
            raise ValueError("Native SSH needs a managed SSH password with a matching connection scope")
    if payload.protocol == "snmp":
        from ..snmp_modules import validate_modules
        validate_modules(payload.configuration.get("modules", ["if_mib"]))
    if payload.protocol == "https_api" and "http_monitor" in payload.configuration:
        from ..http_metrics import HTTPMonitorSpec
        HTTPMonitorSpec.model_validate(payload.configuration["http_monitor"])
    if payload.protocol in {"node_exporter","windows_exporter","cadvisor","vmware_exporter"} and "exporter_monitor" in payload.configuration:
        from ..exporter_metrics import ExporterMonitorSpec,PROTOCOLS
        monitor=ExporterMonitorSpec.model_validate(payload.configuration["exporter_monitor"])
        if PROTOCOLS[monitor.plugin]!=payload.protocol: raise ValueError("Exporter platform does not match the connection protocol")

    if payload.credential_profile_ref:
        profile = _credential_profile(db, payload.credential_profile_ref)
        if profile is None:
            raise ValueError(
                f"Credential profile {payload.credential_profile_ref!r} "
                "does not exist"
            )
        if not profile.enabled:
            raise ValueError(
                f"Credential profile {payload.credential_profile_ref!r} is disabled"
            )
        if adapter_type not in profile.allowed_adapters:
            raise ValueError(
                f"Credential profile {payload.credential_profile_ref!r} does not "
                f"allow adapter {adapter_type!r}"
            )
        # Blank physical placement is not an unscoped credential. Carry the
        # selected profile's exact worker labels without inventing a Site.
        if not site:
            for key, expected in profile.worker_selector.items():
                worker_selector.setdefault(key, expected)
        for key, expected in profile.worker_selector.items():
            if worker_selector.get(key) != expected:
                raise ValueError(
                    f"Connection worker_selector must include {key}={expected!r} "
                    f"for credential profile {payload.credential_profile_ref!r}"
                )
    assert_no_inline_secrets(worker_selector, "worker_selector")

    return {
        "protocol": payload.protocol,
        "adapter_type": adapter_type,
        "port": (
            payload.port
            if payload.port is not None
            else DEFAULT_PORTS[payload.protocol]
        ),
        "credential_profile_ref": payload.credential_profile_ref,
        "worker_selector": worker_selector,
        "configuration": payload.configuration,
        "enabled": payload.enabled,
        "verification_status": ("not_requested" if mode == "studio" else "pending") if payload.enabled else "disabled",
        # An explicit SQL NULL avoids the ORM's utcnow insert default.
        "next_verification_at": utcnow() if payload.enabled and mode != "studio" else null(),
        "created_by": actor,
    }


def onboard_device(db: Session, payload: DeviceOnboardCreate, *, commit: bool = True) -> Device:
    connection_values = [
        _connection_values(
            db,
            connection,
            site=payload.site,
            actor=payload.created_by,
        )
        for connection in payload.connections
    ]
    device = Device(
        name=payload.name,
        kind=payload.kind,
        management_ip=payload.management_ip,
        vendor=payload.vendor,
        model=payload.model,
        site=payload.site,
        location=payload.location.model_dump(exclude_none=True),
        labels=payload.labels,
        onboarding_status="pending_verification",
        enabled=payload.enabled,
        created_by=payload.created_by,
    )
    db.add(device)
    try:
        db.flush()
        connections = [
            DeviceConnection(device_id=device.id, **values)
            for values in connection_values
        ]
        db.add_all(connections)
        db.flush()
        if any(studio_ssh(connection) for connection in connections):
            _refresh_device_status(db, device.id)
        if payload.request_monitoring:
            from .monitoring import request_managed_snmp_monitoring
            for connection in connections:
                request_managed_snmp_monitoring(db, device, connection, actor=payload.created_by)
        record_audit_event(
            db,
            event_type="device.onboarded",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="device",
            entity_id=device.id,
            details={
                "kind": device.kind,
                "site": device.site,
                "management_ip": device.management_ip,
                "protocols": [item.protocol for item in connections],
                "credential_profile_count": sum(
                    item.credential_profile_ref is not None for item in connections
                ),
                "status": device.onboarding_status,
            },
        )
        if commit:
            db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Device name or management IP already exists") from exc
    return get_onboarded_device(db, device.id)


def get_onboarded_device(db: Session, device_id: str) -> Device:
    device = db.scalar(
        select(Device)
        .where(Device.id == device_id)
        .options(
            selectinload(Device.connections).selectinload(
                DeviceConnection.activations
            )
        )
        .execution_options(populate_existing=True)
    )
    if device is None:
        raise LookupError("Device not found")
    return device


def update_device_metadata(
    db: Session,
    device_id: str,
    payload: DeviceMetadataUpdate,
    *,
    actor: str,
) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise LookupError("Device not found")
    if device.revision != payload.expected_revision:
        raise ValueError("Device metadata changed; refresh before saving")

    previous = {
        "kind": device.kind,
        "vendor": device.vendor,
        "model": device.model,
        "labels": device.labels,
        "location": device.location,
    }
    proposed = {
        "kind": payload.kind,
        "vendor": payload.vendor,
        "model": payload.model,
        "labels": payload.labels,
        "location": payload.location.model_dump(exclude_none=True) if payload.location is not None else device.location,
    }
    changed_fields = sorted(
        field for field in proposed if previous[field] != proposed[field]
    )
    if not changed_fields:
        return get_onboarded_device(db, device_id)

    changed = db.execute(
        update(Device)
        .where(
            Device.id == device_id,
            Device.revision == payload.expected_revision,
        )
        .values(
            **proposed,
            revision=Device.revision + 1,
            updated_at=utcnow(),
        )
    )
    if changed.rowcount != 1:
        db.rollback()
        raise ValueError("Device metadata changed; refresh before saving")
    record_audit_event(
        db,
        event_type="device.metadata.updated",
        actor_type="user",
        actor_id=actor,
        entity_type="device",
        entity_id=device_id,
        details={
            "revision_before": payload.expected_revision,
            "revision_after": payload.expected_revision + 1,
            "changed_fields": changed_fields,
            "kind_before": previous["kind"],
            "kind_after": payload.kind,
            "label_keys_before": sorted(previous["labels"]),
            "label_keys_after": sorted(payload.labels),
        },
    )
    db.commit()
    return get_onboarded_device(db, device_id)


def _refresh_device_status(db: Session, device_id: str) -> Device:
    # SessionLocal disables autoflush: aggregate the edited connection state
    # within the same transaction rather than its pre-edit database values.
    db.flush()
    device = db.get(Device, device_id)
    if device is None:
        raise LookupError("Device not found")
    enabled_statuses = list(
        db.scalars(
            select(DeviceConnection.verification_status).where(
                DeviceConnection.device_id == device_id,
                DeviceConnection.enabled.is_(True),
            )
        ).all()
    )
    if not device.enabled or not enabled_statuses:
        status = "disabled"
    elif all(item == "not_requested" for item in enabled_statuses):
        status = "registered"
    elif all(item == "verified" for item in enabled_statuses):
        status = "verified"
    elif any(item == "running" for item in enabled_statuses):
        status = "verifying"
    elif all(item == "failed" for item in enabled_statuses):
        status = "verification_failed"
    elif "verified" in enabled_statuses and "failed" in enabled_statuses:
        status = "partially_verified"
    else:
        status = "pending_verification"
    device.onboarding_status = status
    device.updated_at = utcnow()
    return device


def studio_ssh(connection):
    return connection.protocol == "ssh" and connection.configuration.get("verification_mode") == "studio"


def add_native_ssh_connection(db, principal, device_id, payload):
    """Register an on-demand binding; no network I/O or Collector work is queued."""
    from ..database import require_locking_transaction
    from .authorization_scope import device_scope_clause
    require_locking_transaction(db, purpose="Register native SSH connection")
    device = db.scalar(select(Device).where(Device.id == device_id, device_scope_clause(principal))
        .with_for_update().execution_options(populate_existing=True))
    if device is None:
        raise LookupError("Device not found")
    if not device.enabled or device.revision != payload.expected_revision:
        raise ValueError("Device is disabled or changed; refresh before registering SSH")
    existing = db.scalars(select(DeviceConnection).where(DeviceConnection.device_id == device_id)).all()
    if any(row.protocol == "ssh" for row in existing):
        raise ValueError("An SSH connection already exists; the existing binding was not replaced")
    if len(existing) >= 8:
        raise ValueError("Device already has the maximum number of connections")
    values = _connection_values(db, DeviceConnectionInput(protocol="ssh", port=payload.port,
        credential_profile_ref=payload.credential_profile_ref, configuration={"verification_mode": "studio"}),
        site=device.site, actor=principal.subject)
    connection = DeviceConnection(device_id=device_id, **values)
    db.add(connection)
    device.revision += 1
    _refresh_device_status(db, device_id)
    record_audit_event(db, event_type="device.connection.registered", actor_type="user", actor_id=principal.subject,
        entity_type="device_connection", entity_id=connection.id,
        details={"device_id": device.id, "protocol": "ssh", "verification_mode": "studio", "network_contacted": False})
    db.commit()
    return get_onboarded_device(db, device_id)


def claim_device_preflights(
    db: Session,
    worker: CollectorWorker,
    payload: DevicePreflightClaim,
) -> list[DevicePreflightAssignment]:
    from .worker_registry import lock_worker_registry
    worker = lock_worker_registry(db, worker)
    if worker.state != CollectorWorkerState.ONLINE:
        raise ValueError("Only online workers can claim device preflights")

    now = utcnow()
    lease_expires_at = now + timedelta(seconds=payload.lease_seconds)
    eligible = or_(
        DeviceConnection.verification_status == "pending",
        and_(
            DeviceConnection.verification_status == "running",
            DeviceConnection.verification_lease_expires_at.is_not(None),
            DeviceConnection.verification_lease_expires_at < now,
        ),
    )
    candidates = db.scalars(
        select(DeviceConnection)
        .join(DeviceConnection.device)
        .where(
            Device.enabled.is_(True),
            DeviceConnection.enabled.is_(True),
            DeviceConnection.adapter_type.in_(worker.capabilities),
            eligible,
            or_(
                DeviceConnection.next_verification_at.is_(None),
                DeviceConnection.next_verification_at <= now,
            ),
        )
        .options(selectinload(DeviceConnection.device))
        .order_by(
            DeviceConnection.next_verification_at,
            DeviceConnection.created_at,
            DeviceConnection.id,
        )
        .limit(payload.max_assignments * 4)
    ).all()

    worker_labels = {
        **worker.labels,
        **({"site": worker.site} if worker.site else {}),
    }
    assignments: list[DevicePreflightAssignment] = []
    for candidate in candidates:
        if studio_ssh(candidate):
            continue
        if len(assignments) >= payload.max_assignments:
            break
        selected_revision = candidate.device.revision
        if any(
            worker_labels.get(key) != expected
            for key, expected in candidate.worker_selector.items()
        ):
            continue

        token = secrets.token_urlsafe(32)
        token_hash = _token_hash(token)
        claimed = db.execute(
            update(DeviceConnection)
            .execution_options(synchronize_session=False)
            .where(
                DeviceConnection.id == candidate.id,
                DeviceConnection.enabled.is_(True),
                DeviceConnection.device_id.in_(
                    select(Device.id).where(
                        Device.id == candidate.device_id,
                        Device.enabled.is_(True),
                        Device.revision == candidate.device.revision,
                    )
                ),
                eligible,
            )
            .values(
                verification_status="running",
                verification_worker_id=worker.id,
                verification_lease_token_hash=token_hash,
                verification_lease_expires_at=lease_expires_at,
                next_verification_at=None,
                updated_at=now,
            )
        )
        if claimed.rowcount != 1:
            continue

        # PostgreSQL can evaluate a correlated revision predicate from the
        # UPDATE statement's pre-wait snapshot. Re-read in a fresh statement
        # while this transaction still owns the connection row lock, before
        # creating a lease or returning a target to the worker.
        db.refresh(candidate.device)
        if (
            candidate.device.revision != selected_revision
            or not candidate.device.enabled
        ):
            db.execute(
                update(DeviceConnection)
                .execution_options(synchronize_session=False)
                .where(
                    DeviceConnection.id == candidate.id,
                    DeviceConnection.verification_lease_token_hash == token_hash,
                )
                .values(
                    verification_status="pending",
                    verification_worker_id=None,
                    verification_lease_token_hash=None,
                    verification_lease_expires_at=None,
                    next_verification_at=now,
                    updated_at=now,
                )
            )
            continue

        db.execute(
            update(DeviceConnectionPreflight)
            .where(
                DeviceConnectionPreflight.connection_id == candidate.id,
                DeviceConnectionPreflight.status == "running",
            )
            .values(
                status="expired",
                finished_at=now,
                error="Verification lease expired and was reassigned",
            )
        )
        preflight = DeviceConnectionPreflight(
            connection_id=candidate.id,
            worker_id=worker.id,
            status="running",
            lease_token_hash=token_hash,
            lease_expires_at=lease_expires_at,
            target_host=candidate.device.management_ip,
            site_snapshot=candidate.device.site,
            started_at=now,
        )
        db.add(preflight)
        db.flush()
        db.execute(
            update(Device)
            .where(Device.id == candidate.device_id)
            .values(onboarding_status="verifying", updated_at=now)
        )
        record_audit_event(
            db,
            event_type="device.connection.preflight.claimed",
            actor_type="worker",
            actor_id=worker.id,
            entity_type="device_connection",
            entity_id=candidate.id,
            details={
                "preflight_id": preflight.id,
                "device_id": candidate.device_id,
                "protocol": candidate.protocol,
                "adapter_type": candidate.adapter_type,
            },
        )
        assignments.append(
            DevicePreflightAssignment(
                preflight_id=preflight.id,
                lease_token=token,
                lease_expires_at=lease_expires_at,
                connection_id=candidate.id,
                device_id=candidate.device_id,
                device_name=candidate.device.name,
                target_host=candidate.device.management_ip or "",
                protocol=candidate.protocol,
                adapter_type=candidate.adapter_type,
                port=candidate.port,
                configuration=candidate.configuration,
                credential_profile_ref=candidate.credential_profile_ref,
                credential_provider=(p.provider if candidate.credential_profile_ref
                    and (p := _credential_profile(db, candidate.credential_profile_ref)) else None),
                credential_revision=p.revision if candidate.credential_profile_ref and p else None,
            )
        )
    worker.last_heartbeat_at = now
    db.commit()
    return assignments


def complete_device_preflight(
    db: Session,
    worker: CollectorWorker,
    preflight_id: str,
    payload: DevicePreflightComplete,
) -> DeviceConnectionPreflight:
    preflight = db.scalar(
        select(DeviceConnectionPreflight)
        .where(DeviceConnectionPreflight.id == preflight_id)
        .options(
            selectinload(DeviceConnectionPreflight.connection).selectinload(
                DeviceConnection.device
            )
        )
    )
    if preflight is None:
        raise LookupError("Device preflight not found")
    if preflight.worker_id != worker.id:
        raise ValueError("Device preflight belongs to another worker")
    if preflight.status != "running":
        raise ValueError("Device preflight is no longer active")
    if not secrets.compare_digest(
        preflight.lease_token_hash,
        _token_hash(payload.lease_token),
    ):
        raise ValueError("Invalid device preflight lease token")

    connection = preflight.connection
    if (
        connection.verification_worker_id != worker.id
        or connection.verification_lease_token_hash is None
        or not secrets.compare_digest(
            connection.verification_lease_token_hash,
            _token_hash(payload.lease_token),
        )
    ):
        raise ValueError("Device preflight lease is no longer owned by this worker")
    now = utcnow()
    if (
        connection.verification_lease_expires_at is None
        or _as_utc(connection.verification_lease_expires_at) < now
        or _as_utc(preflight.lease_expires_at) < now
    ):
        raise ValueError("Device preflight lease has expired")

    assert_no_inline_secrets(payload.evidence, "preflight.evidence")
    evidence_size = len(
        json.dumps(payload.evidence, separators=(",", ":")).encode("utf-8")
    )
    if evidence_size > 32_768:
        raise ValueError("preflight evidence exceeds 32768 bytes")

    # Only a currently leased, target-bound SNMP result can publish discovery.
    # Keep the operator alias unchanged and fence discovery after retargeting.
    evidence = dict(payload.evidence)
    evidence.pop("identity_revision", None)
    if connection.protocol in {"node_exporter","windows_exporter","cadvisor","vmware_exporter"} and "exporter_monitor" in connection.configuration and payload.status=="verified":
        from .exporter_monitoring_templates import evidence_matches
        p=_credential_profile(db,connection.credential_profile_ref) if connection.credential_profile_ref else None
        if preflight.target_host!=connection.device.management_ip or preflight.site_snapshot!=connection.device.site or not evidence_matches(connection,p,evidence=evidence):
            raise ValueError("Exporter metric test no longer matches the current target, template or credential")
    if connection.protocol == "snmp" and connection.configuration.get("monitoring_template_version_id") and payload.status=="verified":
        from .snmp_monitoring_templates import evidence_matches
        p=_credential_profile(db,connection.credential_profile_ref) if connection.credential_profile_ref else None
        if (preflight.target_host!=connection.device.management_ip or preflight.site_snapshot!=connection.device.site
                or not evidence_matches(connection,p,evidence=evidence)):
            raise ValueError("SNMP metric test no longer matches the target, template or credential")
    if connection.protocol == "https_api" and "http_monitor" in connection.configuration and payload.status == "verified":
        from .monitoring import http_evidence_matches
        p = _credential_profile(db, connection.credential_profile_ref) if connection.credential_profile_ref else None
        if (evidence.get("target_host") != preflight.target_host or preflight.target_host != connection.device.management_ip
                or preflight.site_snapshot != connection.device.site or evidence.get("target_port") != connection.port
                or not http_evidence_matches(connection, p, evidence=evidence)):
            raise ValueError("HTTP metric test no longer matches the current target, template or credential")
    if "discovered_name" in evidence:
        from ..snmp_modules import safe_sysname
        name = safe_sysname(evidence["discovered_name"])
        if (connection.protocol != "snmp" or payload.status != "verified" or not name
            or evidence.get("target_host") != preflight.target_host
            or preflight.target_host != connection.device.management_ip):
            raise ValueError("SNMP discovered name must be valid and bound to the current verified target")
        evidence["discovered_name"] = name
        evidence["identity_revision"] = connection.device.identity_revision

    completed = db.execute(
        update(DeviceConnection)
        .execution_options(synchronize_session=False)
        .where(
            DeviceConnection.id == connection.id,
            DeviceConnection.verification_status == "running",
            DeviceConnection.verification_worker_id == worker.id,
            DeviceConnection.verification_lease_token_hash == _token_hash(
                payload.lease_token
            ),
            DeviceConnection.verification_lease_expires_at >= now,
        )
        .values(
            verification_status=payload.status,
            last_verified_at=now,
            last_verification_error=payload.error,
            last_verification_worker_id=worker.id,
            last_verification_latency_ms=payload.latency_ms,
            last_verification_evidence=evidence,
            verification_worker_id=None,
            verification_lease_token_hash=None,
            verification_lease_expires_at=None,
            next_verification_at=None,
            updated_at=now,
        )
    )
    if completed.rowcount != 1:
        db.rollback()
        raise ValueError("Device preflight lease is no longer active")
    preflight.status = payload.status
    preflight.finished_at = now
    preflight.latency_ms = payload.latency_ms
    preflight.evidence = evidence
    preflight.error = payload.error
    worker.last_heartbeat_at = now
    _refresh_device_status(db, connection.device_id)
    record_audit_event(
        db,
        event_type="device.connection.preflight.completed",
        actor_type="worker",
        actor_id=worker.id,
        entity_type="device_connection",
        entity_id=connection.id,
        outcome=payload.status,
        details={
            "preflight_id": preflight.id,
            "device_id": connection.device_id,
            "protocol": connection.protocol,
            "latency_ms": payload.latency_ms,
            "evidence_fields": sorted(payload.evidence),
        },
    )
    db.commit()
    db.refresh(preflight)
    return preflight


def set_device_connection_enabled(db, principal, device_id, connection_id, payload):
    """Withdraw authority without deleting connection or observation history."""
    from ..database import require_locking_transaction
    from ..models import DeviceMonitoringEnrollment
    from .monitoring import _connection
    from .authorization_scope import request_actor
    from .trust_authority import lock_publisher_resource
    require_locking_transaction(db, purpose="Device connection state change")
    lock_publisher_resource(db, "monitoring-connection", connection_id)
    device, connection = _connection(db, principal, device_id, connection_id, lock=True)
    if device.revision != payload.expected_revision:
        raise ValueError("Device changed; refresh before changing connection state")
    if connection.enabled == payload.enabled:
        return get_onboarded_device(db, device_id)
    if payload.enabled and not device.enabled:
        raise ValueError("Enable the device before enabling a connection")
    if any(item.status == "active" for item in connection.activations):
        raise ValueError("Deactivate active collection capabilities before changing connection state")
    now = utcnow()
    connection.enabled = payload.enabled
    queue_verification = payload.enabled and not studio_ssh(connection)
    connection.verification_status = ("pending" if queue_verification else "not_requested") if payload.enabled else "disabled"
    connection.verification_worker_id = None
    connection.verification_lease_token_hash = None
    connection.verification_lease_expires_at = None
    connection.next_verification_at = now if queue_verification else None
    if payload.enabled:
        connection.last_verified_at = None
        connection.last_verification_latency_ms = None
        connection.last_verification_error = None
        connection.last_verification_evidence = {}
    connection.updated_at = now
    db.execute(update(DeviceConnectionPreflight).where(
        DeviceConnectionPreflight.connection_id == connection.id,
        DeviceConnectionPreflight.status == "running").values(
            status="expired", finished_at=now, error="Verification superseded by operator connection-state change"))
    enrollment = db.scalar(select(DeviceMonitoringEnrollment).where(
        DeviceMonitoringEnrollment.connection_id == connection.id).with_for_update()
        .execution_options(populate_existing=True))
    if enrollment is not None:
        enrollment.enabled = False
        enrollment.revision += 1
        enrollment.updated_at = now
    device.revision += 1
    _refresh_device_status(db, device_id)
    record_audit_event(db, event_type="device.connection.enabled" if payload.enabled else "device.connection.disabled",
        actor_type="user", actor_id=request_actor(principal, payload.actor),
        entity_type="device_connection", entity_id=connection.id,
        details={"device_id": device.id, "enabled": payload.enabled, "verification_queued": queue_verification,
                 "monitoring_requires_new_approval": True, "history_retained": True, "reason": payload.reason})
    db.commit()
    return get_onboarded_device(db, device_id)


def update_snmp_configuration(db, device_id, connection_id, payload, *, actor,
        template_version_id=None,compiled_module=None,credential_profile_ref=None):
    from ..snmp_modules import validate_modules
    from ..models import DeviceMonitoringEnrollment
    modules = validate_modules(payload.modules)
    connection = db.scalar(select(DeviceConnection).where(DeviceConnection.id == connection_id,
        DeviceConnection.device_id == device_id).with_for_update().execution_options(populate_existing=True))
    device = db.scalar(select(Device).where(Device.id == device_id).with_for_update().execution_options(populate_existing=True))
    if connection is None or device is None:
        raise LookupError("Device connection not found")
    if device.revision != payload.expected_revision:
        raise ValueError("Device changed; refresh before saving SNMP modules")
    if connection.protocol != "snmp" or not connection.enabled or not device.enabled:
        raise ValueError("Only enabled SNMP connections can be configured")
    now = utcnow()
    if (connection.verification_status == "running" and connection.verification_lease_expires_at
        and _as_utc(connection.verification_lease_expires_at) >= now):
        raise ValueError("Verification is running; wait before changing SNMP modules")
    if any(item.status == "active" for item in connection.activations):
        raise ValueError("Deactivate existing collection capabilities before changing SNMP modules")
    old_modules = connection.configuration.get("modules", ["if_mib"])
    config={**connection.configuration,"modules":modules}
    for key in ("monitoring_template_version_id","snmp_module_sha256","snmp_expected_metrics"):
        config.pop(key,None)
    if template_version_id:
        from .snmp_monitoring_templates import configuration,installed
        from ..models import ManagedDeviceCredential
        if not compiled_module or not installed(compiled_module):
            raise ValueError("Exact compiled SNMP module is not installed")
        reference=credential_profile_ref or connection.credential_profile_ref
        p=_credential_profile(db,reference) if reference else None
        managed=db.scalar(select(ManagedDeviceCredential).where(ManagedDeviceCredential.credential_profile_id==p.id)) if p else None
        if p is None or p.provider!="managed_device" or managed is None or managed.kind!="snmp_v2c":
            raise ValueError("SNMP monitoring templates require a protected SNMPv2c credential reference")
        config.update(configuration(compiled_module,template_version_id))
        values=_connection_values(db,DeviceConnectionInput(protocol="snmp",port=connection.port,
            configuration=config,worker_selector=connection.worker_selector,credential_profile_ref=reference),site=device.site,actor=actor)
        for key in ("configuration","credential_profile_ref","worker_selector"): setattr(connection,key,values[key])
    else:
        connection.configuration = config
    connection.verification_status = "pending"
    connection.verification_worker_id = None
    connection.verification_lease_token_hash = None
    connection.verification_lease_expires_at = None
    connection.next_verification_at = now
    connection.last_verification_error = None
    connection.updated_at = now
    db.execute(update(DeviceConnectionPreflight).where(DeviceConnectionPreflight.connection_id == connection.id,
        DeviceConnectionPreflight.status == "running").values(status="expired", finished_at=now,
            error="Expired verification superseded by SNMP configuration correction"))
    enrollment = db.scalar(select(DeviceMonitoringEnrollment).where(
        DeviceMonitoringEnrollment.connection_id == connection.id).with_for_update())
    if enrollment is not None:
        enrollment.enabled = False
        enrollment.revision += 1
        enrollment.updated_at = now
    device.revision += 1
    _refresh_device_status(db, device_id)
    record_audit_event(db, event_type="device.connection.snmp_configuration.updated", actor_type="user", actor_id=actor,
        entity_type="device_connection", entity_id=connection.id,
        details={"device_id": device.id, "old_modules": old_modules, "modules": modules,
            "verification_queued": True, "monitoring_requires_approval": True, "reason": payload.reason})
    db.commit()
    return get_onboarded_device(db, device_id)


def update_exporter_configuration(db,device_id,connection_id,monitor,*,port,credential_profile_ref,expected_revision,actor,version_id):
    from ..exporter_metrics import PROTOCOLS
    from ..models import DeviceMonitoringEnrollment,ManagedDeviceCredential
    from .exporter_monitoring_templates import configuration
    device=db.scalar(select(Device).where(Device.id==device_id).with_for_update().execution_options(populate_existing=True))
    connection=db.scalar(select(DeviceConnection).where(DeviceConnection.id==connection_id,DeviceConnection.device_id==device_id).with_for_update().execution_options(populate_existing=True))
    if device is None or connection is None: raise LookupError("Device connection not found")
    if device.revision!=expected_revision: raise ValueError("Device changed; refresh before saving the exporter template")
    if connection.protocol!=PROTOCOLS[monitor.plugin] or not device.enabled or not connection.enabled:
        raise ValueError("Exporter template requires an enabled matching platform connection")
    now=utcnow()
    if connection.verification_status=="running" and connection.verification_lease_expires_at and _as_utc(connection.verification_lease_expires_at)>=now:
        raise ValueError("Verification is running; wait before changing the exporter template")
    if any(a.status=="active" for a in connection.activations): raise ValueError("Deactivate legacy collectors before changing this exporter template")
    if monitor.auth_mode!="none":
        p=_credential_profile(db,credential_profile_ref or "")
        row=db.scalar(select(ManagedDeviceCredential).where(ManagedDeviceCredential.credential_profile_id==p.id)) if p else None
        if p is None or p.provider!="managed_device" or row is None or row.kind!=("http_basic" if monitor.auth_mode=="basic" else "https_token"):
            raise ValueError("Exporter authentication requires a compatible protected HTTP credential reference")
    config={**connection.configuration,**configuration(monitor,version_id)}
    values=_connection_values(db,DeviceConnectionInput(protocol=connection.protocol,port=port,configuration=config,
        worker_selector=connection.worker_selector,credential_profile_ref=credential_profile_ref if monitor.auth_mode!="none" else None),site=device.site,actor=actor)
    for key in ("port","configuration","credential_profile_ref","worker_selector"): setattr(connection,key,values[key])
    connection.verification_status="pending"; connection.next_verification_at=now; connection.last_verification_error=None
    connection.verification_worker_id=connection.verification_lease_token_hash=connection.verification_lease_expires_at=None
    db.execute(update(DeviceConnectionPreflight).where(DeviceConnectionPreflight.connection_id==connection.id,
        DeviceConnectionPreflight.status=="running").values(status="expired",finished_at=now,error="Superseded exporter verification"))
    enrollment=db.scalar(select(DeviceMonitoringEnrollment).where(DeviceMonitoringEnrollment.connection_id==connection.id).with_for_update())
    if enrollment: enrollment.enabled=False; enrollment.revision+=1
    device.revision+=1; _refresh_device_status(db,device_id)
    record_audit_event(db,event_type="device.connection.exporter_configuration.updated",actor_type="user",actor_id=actor,
        entity_type="device_connection",entity_id=connection.id,details={"monitoring_template_version_id":version_id,"plugin":monitor.plugin,
            "verification_queued":True,"monitoring_requires_approval":True})
    db.commit()
    return get_onboarded_device(db,device_id)


def update_http_configuration(db, device_id, connection_id, payload, *, actor, template_version_id=None):
    from ..models import DeviceMonitoringEnrollment, ManagedDeviceCredential
    from ..http_metrics import spec_hash
    device = db.scalar(select(Device).where(Device.id == device_id).with_for_update().execution_options(populate_existing=True))
    connection = db.scalar(select(DeviceConnection).where(DeviceConnection.id == connection_id,
        DeviceConnection.device_id == device_id).with_for_update().execution_options(populate_existing=True))
    if connection is None or device is None: raise LookupError("Device connection not found")
    if device.revision != payload.expected_revision: raise ValueError("Device changed; refresh before saving HTTP template")
    if connection.protocol != "https_api" or not connection.enabled or not device.enabled:
        raise ValueError("Only enabled HTTP/API connections can be configured")
    now = utcnow()
    if (connection.verification_status == "running" and connection.verification_lease_expires_at
            and _as_utc(connection.verification_lease_expires_at) >= now):
        raise ValueError("Verification is running; wait before changing the HTTP template")
    if any(item.status == "active" for item in connection.activations):
        raise ValueError("Deactivate existing collection capabilities before changing the HTTP template")
    spec = payload.http_monitor
    if spec.auth_mode != "none":
        p = _credential_profile(db, payload.credential_profile_ref or "")
        row = db.scalar(select(ManagedDeviceCredential).where(ManagedDeviceCredential.credential_profile_id == p.id)) if p else None
        if (spec.scheme != "https" or p is None or p.provider != "managed_device" or row is None
                or row.kind != ("http_basic" if spec.auth_mode == "basic" else "https_token")):
            raise ValueError("Authenticated HTTP templates need HTTPS and a compatible protected device credential")
    config = {**connection.configuration, "http_monitor": spec.model_dump()}
    # Only the template lifecycle can attach a verified immutable Artifact pin.
    # Manual form edits remove it rather than claiming the old version remains.
    config.pop("monitoring_template_version_id", None)
    if template_version_id: config["monitoring_template_version_id"] = template_version_id
    values = _connection_values(db, DeviceConnectionInput(protocol="https_api", port=payload.port,
        configuration=config, worker_selector=connection.worker_selector,
        credential_profile_ref=payload.credential_profile_ref), site=device.site, actor=actor)
    old = connection.configuration.get("http_monitor")
    for key in ("port", "configuration", "credential_profile_ref", "worker_selector"):
        setattr(connection, key, values[key])
    connection.verification_status = "pending"
    connection.verification_worker_id = connection.verification_lease_token_hash = connection.verification_lease_expires_at = None
    connection.next_verification_at = now
    connection.last_verification_error = None
    db.execute(update(DeviceConnectionPreflight).where(DeviceConnectionPreflight.connection_id == connection.id,
        DeviceConnectionPreflight.status == "running").values(status="expired", finished_at=now,
            error="Expired verification superseded by HTTP template change"))
    enrollment = db.scalar(select(DeviceMonitoringEnrollment).where(DeviceMonitoringEnrollment.connection_id == connection.id).with_for_update())
    if enrollment:
        enrollment.enabled = False; enrollment.revision += 1
    device.revision += 1
    _refresh_device_status(db, device_id)
    record_audit_event(db, event_type="device.connection.http_configuration.updated", actor_type="user", actor_id=actor,
        entity_type="device_connection", entity_id=connection.id,
        details={"device_id": device.id, "previous_template": old, "template": spec.model_dump(),
            "spec_hash": spec_hash(spec), "monitoring_template_version_id": template_version_id,
            "verification_queued": True, "monitoring_requires_approval": True})
    db.commit()
    return get_onboarded_device(db, device_id)


def retry_device_connection(
    db: Session,
    device_id: str,
    connection_id: str,
    *,
    actor: str,
    reason: str,
) -> Device:
    connection = db.scalar(
        select(DeviceConnection).where(
            DeviceConnection.id == connection_id,
            DeviceConnection.device_id == device_id,
        )
    )
    if connection is None:
        raise LookupError("Device connection not found")
    if not connection.enabled:
        raise ValueError("Disabled device connections cannot be verified")
    if studio_ssh(connection):
        raise ValueError("This SSH connection is on demand; review and test its exact tool and host key in Capability Studio")

    now = utcnow()
    previous_status = connection.verification_status
    if previous_status == "running":
        expires_at = connection.verification_lease_expires_at
        if expires_at is not None and _as_utc(expires_at) >= now:
            raise ValueError("Device connection verification is already running")
        db.execute(
            update(DeviceConnectionPreflight)
            .where(
                DeviceConnectionPreflight.connection_id == connection.id,
                DeviceConnectionPreflight.status == "running",
            )
            .values(
                status="expired",
                finished_at=now,
                error="Verification lease expired before operator retry",
            )
        )
    elif previous_status == "pending":
        raise ValueError("Device connection is already pending verification")

    connection.verification_status = "pending"
    connection.verification_worker_id = None
    connection.verification_lease_token_hash = None
    connection.verification_lease_expires_at = None
    connection.next_verification_at = now
    connection.last_verification_error = None
    connection.updated_at = now
    _refresh_device_status(db, device_id)
    record_audit_event(
        db,
        event_type="device.connection.preflight.retried",
        actor_type="user",
        actor_id=actor,
        entity_type="device_connection",
        entity_id=connection.id,
        details={
            "device_id": device_id,
            "protocol": connection.protocol,
            "previous_status": previous_status,
            "reason": reason,
        },
    )
    db.commit()
    return get_onboarded_device(db, device_id)
