"""Reviewed device target corrections without inheriting old verification."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..device_schemas import (
    DeviceIdentityCorrectionCommit,
    DeviceIdentityCorrectionConnection,
    DeviceIdentityCorrectionInput,
    DeviceIdentityCorrectionPreview,
)
from ..models import (
    CollectorDeployment,
    Device,
    DeviceConnection,
    DeviceConnectionActivation,
    DeviceConnectionPreflight,
    utcnow,
)
from .audit import record_audit_event
from .devices import _credential_profile, get_onboarded_device, studio_ssh


class IdentityCorrectionConflict(ValueError):
    """The preview is stale or a protected activity is still in progress."""


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _iso(value: datetime | None) -> str | None:
    normalized = _utc(value)
    return normalized.isoformat() if normalized else None


def _load_state(
    db: Session,
    device_id: str,
    *,
    lock: bool,
) -> tuple[Device, list[DeviceConnection], list[DeviceConnectionActivation], list[CollectorDeployment]]:
    connections_query = (
        select(DeviceConnection)
        .where(DeviceConnection.device_id == device_id)
        .order_by(DeviceConnection.id)
    )
    if lock:
        connections_query = connections_query.with_for_update()
    connections = list(db.scalars(connections_query).all())

    device_query = select(Device).where(Device.id == device_id)
    if lock:
        device_query = device_query.with_for_update()
    device = db.scalar(device_query.execution_options(populate_existing=True))
    if device is None:
        raise LookupError("Device not found")

    ids = [connection.id for connection in connections]
    activations = list(
        db.scalars(
            select(DeviceConnectionActivation)
            .where(DeviceConnectionActivation.connection_id.in_(ids))
            .order_by(DeviceConnectionActivation.id)
        ).all()
    ) if ids else []
    deployments_query = (
        select(CollectorDeployment)
        .where(
            CollectorDeployment.scope_device_id == device_id,
            CollectorDeployment.tenant_id == device.tenant_id,
            CollectorDeployment.region_id == device.region_id,
        )
        .order_by(CollectorDeployment.id)
    )
    if lock:
        deployments_query = deployments_query.with_for_update()
    deployments = list(db.scalars(deployments_query).all())
    return device, connections, activations, deployments


def _preview_from_state(
    db: Session,
    device: Device,
    connections: list[DeviceConnection],
    activations: list[DeviceConnectionActivation],
    deployments: list[CollectorDeployment],
    payload: DeviceIdentityCorrectionInput,
) -> DeviceIdentityCorrectionPreview:
    if device.revision != payload.expected_revision:
        raise IdentityCorrectionConflict(
            "Device changed; refresh before previewing a correction"
        )
    connection_ids = {connection.id for connection in connections}
    if set(payload.credential_profile_refs) - connection_ids:
        raise ValueError("credential_profile_refs contains an unknown connection")

    current = {
        "name": device.name,
        "management_ip": device.management_ip,
        "site": device.site,
    }
    proposed = {
        "name": payload.name,
        "management_ip": payload.management_ip,
        "site": payload.site,
    }
    now = utcnow()
    blockers: list[str] = []
    warnings: list[str] = []
    if current == proposed and not any(
        payload.credential_profile_refs.get(connection.id, connection.credential_profile_ref)
        != connection.credential_profile_ref
        for connection in connections
    ):
        blockers.append("No device identity or credential binding change was requested")

    duplicate = db.scalar(
        select(Device.id).where(
            Device.id != device.id,
            Device.tenant_id == device.tenant_id,
            Device.region_id == device.region_id,
            or_(
                Device.name == payload.name,
                Device.management_ip == payload.management_ip,
            ),
        ).limit(1)
    )
    if duplicate:
        blockers.append("Device name or management IP already exists")

    bindings: list[DeviceIdentityCorrectionConnection] = []
    for connection in connections:
        reference = payload.credential_profile_refs.get(
            connection.id, connection.credential_profile_ref
        )
        selector = dict(connection.worker_selector)
        if payload.site:
            selector["site"] = payload.site
        if reference:
            profile = _credential_profile(db, reference)
            if profile is None or not profile.enabled:
                blockers.append(
                    f"{connection.protocol}: credential profile is unavailable"
                )
            elif connection.adapter_type not in profile.allowed_adapters:
                blockers.append(
                    f"{connection.protocol}: credential profile does not allow the adapter"
                )
            else:
                if not payload.site:
                    selector = {**selector, **profile.worker_selector}
                if any(selector.get(key) != expected for key, expected in profile.worker_selector.items()):
                    blockers.append(f"{connection.protocol}: credential profile does not match the proposed site or worker selector")
        if connection.verification_status == "running":
            expires_at = _utc(connection.verification_lease_expires_at)
            if expires_at is None or expires_at >= now:
                blockers.append(
                    f"{connection.protocol}: preflight lease is still active"
                )
        bindings.append(
            DeviceIdentityCorrectionConnection(
                connection_id=connection.id,
                protocol=connection.protocol,
                current_credential_profile_ref=connection.credential_profile_ref,
                proposed_credential_profile_ref=reference,
                proposed_worker_selector=selector,
            )
        )

    for activation in activations:
        if activation.status == "active":
            blockers.append(
                f"Activation {activation.id} is active; deactivate it first"
            )
    for deployment in deployments:
        if deployment.enabled:
            blockers.append(
                f"Collector deployment {deployment.id} is enabled; disable it first"
            )
        if (_utc(deployment.lease_expires_at) or datetime.min.replace(tzinfo=UTC)) >= now:
            blockers.append(
                f"Collector deployment {deployment.id} has an in-flight run lease"
            )

    if device.management_ip != payload.management_ip:
        warnings.append("All connection verification will be reset for the new address")
    if device.site != payload.site:
        warnings.append("Connection worker selectors will move to the new site")
    warnings.append(
        "Existing preflight and collector history stays attached to this device; use a new device record for a different physical asset"
    )

    material = {
        "device_id": device.id,
        "revision": device.revision,
        "current": current,
        "proposed": proposed,
        "bindings": [binding.model_dump() for binding in bindings],
        "connections": [
            [connection.id, connection.verification_status,
             connection.verification_lease_token_hash,
             _iso(connection.verification_lease_expires_at)]
            for connection in connections
        ],
        "activations": [
            [activation.id, activation.status, activation.deployment_id]
            for activation in activations
        ],
        "deployments": [
            [deployment.id, deployment.enabled, _iso(deployment.lease_expires_at)]
            for deployment in deployments
        ],
        "blockers": blockers,
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return DeviceIdentityCorrectionPreview(
        device_id=device.id,
        expected_revision=device.revision,
        current=current,
        proposed=proposed,
        connections=bindings,
        blockers=blockers,
        warnings=warnings,
        preview_hash=digest,
        can_commit=not blockers,
    )


def preview_device_identity_correction(
    db: Session,
    device_id: str,
    payload: DeviceIdentityCorrectionInput,
) -> DeviceIdentityCorrectionPreview:
    state = _load_state(db, device_id, lock=False)
    return _preview_from_state(db, *state, payload)


def commit_device_identity_correction(
    db: Session,
    device_id: str,
    payload: DeviceIdentityCorrectionCommit,
    *,
    actor: str,
) -> Device:
    device, connections, activations, deployments = _load_state(
        db, device_id, lock=True
    )
    preview = _preview_from_state(db, device, connections, activations, deployments, payload)
    if preview.preview_hash != payload.preview_hash:
        raise IdentityCorrectionConflict(
            "Device correction preview changed; preview again before committing"
        )
    if preview.blockers:
        raise IdentityCorrectionConflict("; ".join(preview.blockers))

    now = utcnow()
    connection_ids = [connection.id for connection in connections]
    if connection_ids:
        db.execute(
            update(DeviceConnectionPreflight)
            .execution_options(synchronize_session=False)
            .where(
                DeviceConnectionPreflight.connection_id.in_(connection_ids),
                DeviceConnectionPreflight.target_host.is_(None),
                DeviceConnectionPreflight.site_snapshot.is_(None),
            )
            .values(target_host=device.management_ip, site_snapshot=device.site)
        )
        db.execute(
            update(DeviceConnectionPreflight)
            .execution_options(synchronize_session=False)
            .where(
                DeviceConnectionPreflight.connection_id.in_(connection_ids),
                DeviceConnectionPreflight.status == "running",
            )
            .values(
                status="expired",
                finished_at=now,
                error="Device identity corrected after preflight lease expired",
            )
        )

    for connection, binding in zip(connections, preview.connections, strict=True):
        reset = db.execute(
            update(DeviceConnection)
            .execution_options(synchronize_session=False)
            .where(
                DeviceConnection.id == connection.id,
                DeviceConnection.verification_status == connection.verification_status,
                DeviceConnection.verification_lease_token_hash
                == connection.verification_lease_token_hash,
            )
            .values(
                credential_profile_ref=binding.proposed_credential_profile_ref,
                worker_selector=binding.proposed_worker_selector,
                verification_status=("not_requested" if studio_ssh(connection) else "pending") if connection.enabled else "disabled",
                last_verified_at=None,
                last_verification_error=None,
                last_verification_worker_id=None,
                last_verification_latency_ms=None,
                last_verification_evidence={},
                verification_worker_id=None,
                verification_lease_token_hash=None,
                verification_lease_expires_at=None,
                next_verification_at=now if device.enabled and connection.enabled and not studio_ssh(connection) else None,
                updated_at=now,
            )
        )
        if reset.rowcount != 1:
            db.rollback()
            raise IdentityCorrectionConflict(
                "Device connection changed; preview the correction again"
            )

    old = preview.current
    try:
        changed = db.execute(
            update(Device)
            .execution_options(synchronize_session=False)
            .where(Device.id == device_id, Device.revision == payload.expected_revision)
            .values(
                name=payload.name,
                management_ip=payload.management_ip,
                site=payload.site,
                onboarding_status=(
                    ("registered" if all(not connection.enabled or studio_ssh(connection) for connection in connections)
                     else "pending_verification")
                    if device.enabled and any(connection.enabled for connection in connections)
                    else "disabled"
                ),
                revision=Device.revision + 1,
                identity_revision=Device.identity_revision + 1,
                updated_at=now,
            )
        )
    except IntegrityError as exc:
        db.rollback()
        raise IdentityCorrectionConflict(
            "Device name or management IP already exists"
        ) from exc
    if changed.rowcount != 1:
        db.rollback()
        raise IdentityCorrectionConflict("Device changed; preview the correction again")
    record_audit_event(
        db,
        event_type="device.identity.corrected",
        actor_type="user",
        actor_id=actor,
        entity_type="device",
        entity_id=device_id,
        details={
            "revision_before": payload.expected_revision,
            "revision_after": payload.expected_revision + 1,
            "identity_revision_before": device.identity_revision,
            "identity_revision_after": device.identity_revision + 1,
            "before": old,
            "after": preview.proposed,
            "credential_binding_changes": [
                item.connection_id for item in preview.connections
                if item.current_credential_profile_ref != item.proposed_credential_profile_ref
            ],
            "verification_reset_count": len(connections),
            "reason": payload.reason,
            "preview_hash": preview.preview_hash,
        },
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise IdentityCorrectionConflict(
            "Device name or management IP already exists"
        ) from exc
    return get_onboarded_device(db, device_id)
