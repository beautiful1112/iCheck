from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..models import (
    CollectorDeployment,
    CollectorDeploymentMode,
    CollectorRun,
    CollectorRunStatus,
    Device,
    DeviceConnection,
    DeviceConnectionActivation,
    utcnow,
)
from .audit import record_audit_event


TERMINAL_RUN_STATUSES = (
    CollectorRunStatus.SUCCEEDED,
    CollectorRunStatus.FAILED,
    CollectorRunStatus.CANCELLED,
)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def deployment_fingerprint_fields(
    *,
    artifact_version_id: str,
    target: dict[str, Any],
    configuration: dict[str, Any],
    worker_selector: dict[str, Any],
    execution_mode: CollectorDeploymentMode | str,
    schedule_seconds: int,
    credential_profile_ref: str | None,
) -> str:
    mode = (
        execution_mode.value
        if isinstance(execution_mode, CollectorDeploymentMode)
        else execution_mode
    )
    encoded = json.dumps(
        {
            "artifact_version_id": artifact_version_id,
            "target": target,
            "configuration": configuration,
            "worker_selector": worker_selector,
            "execution_mode": mode,
            "schedule_seconds": schedule_seconds,
            "credential_profile_ref": credential_profile_ref,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def deployment_fingerprint(deployment: CollectorDeployment) -> str:
    return deployment_fingerprint_fields(
        artifact_version_id=deployment.artifact_version_id,
        target=deployment.target,
        configuration=deployment.configuration,
        worker_selector=deployment.worker_selector,
        execution_mode=deployment.execution_mode,
        schedule_seconds=deployment.schedule_seconds,
        credential_profile_ref=deployment.credential_profile_ref,
    )


def _observe_run(
    activation: DeviceConnectionActivation,
    run: CollectorRun,
) -> None:
    if activation.last_run_id == run.id or run.finished_at is None:
        return
    activation.last_run_id = run.id
    activation.last_run_status = run.status.value
    activation.last_run_finished_at = run.finished_at
    if run.status == CollectorRunStatus.SUCCEEDED:
        activation.last_success_at = run.finished_at
        activation.consecutive_failures = 0
    else:
        activation.last_failure_at = run.finished_at
        activation.consecutive_failures += 1


def _runtime_evaluation(
    activation: DeviceConnectionActivation,
    deployment: CollectorDeployment | None,
    *,
    now: datetime,
) -> tuple[str, str]:
    if activation.status != "active":
        return "disabled", "Activation is deactivated."
    if deployment is None:
        return "drifted", "The approved collector deployment no longer exists."
    if not deployment.enabled:
        return "drifted", "The approved collector deployment is disabled."
    if not activation.expected_deployment_hash:
        return "drifted", "The activation predates deployment fingerprinting."
    if deployment_fingerprint(deployment) != activation.expected_deployment_hash:
        return "drifted", "Collector deployment differs from the approved plan."
    if deployment.execution_mode == CollectorDeploymentMode.ON_DEMAND:
        if activation.last_run_status in {
            CollectorRunStatus.FAILED.value,
            CollectorRunStatus.CANCELLED.value,
        }:
            return "on_demand_failed", "The latest on-demand run did not succeed."
        return "on_demand_ready", "Approved on-demand collector is ready."
    if activation.last_success_at is None:
        if activation.consecutive_failures:
            return "degraded", "Scheduled collection has not completed successfully."
        return "awaiting_first_run", "Waiting for the first successful collector run."
    if (
        activation.last_failure_at is not None
        and _as_utc(activation.last_failure_at)
        > _as_utc(activation.last_success_at)
    ):
        return "degraded", "The latest scheduled collector run did not succeed."
    stale_after = timedelta(seconds=max(deployment.schedule_seconds * 3, 300))
    if _as_utc(activation.last_success_at) + stale_after < now:
        return "stale", "No successful collection arrived within the freshness budget."
    return "healthy", "Scheduled collection is succeeding within its freshness budget."


def _verification_status(db: Session, device: Device) -> str:
    statuses = list(
        db.scalars(
            select(DeviceConnection.verification_status).where(
                DeviceConnection.device_id == device.id,
                DeviceConnection.enabled.is_(True),
            )
        ).all()
    )
    if not device.enabled or not statuses:
        return "disabled"
    if all(item == "verified" for item in statuses):
        return "verified"
    if any(item == "running" for item in statuses):
        return "verifying"
    if all(item == "failed" for item in statuses):
        return "verification_failed"
    if "verified" in statuses and "failed" in statuses:
        return "partially_verified"
    return "pending_verification"


def refresh_device_runtime_status(db: Session, device_id: str) -> Device:
    db.flush()
    device = db.get(Device, device_id)
    if device is None:
        raise LookupError("Device not found")
    verification_status = _verification_status(db, device)
    rows = db.execute(
        select(
            DeviceConnectionActivation.runtime_status,
            CollectorDeployment.execution_mode,
        )
        .select_from(DeviceConnection)
        .join(
            DeviceConnectionActivation,
            DeviceConnectionActivation.connection_id == DeviceConnection.id,
        )
        .outerjoin(
            CollectorDeployment,
            CollectorDeployment.id == DeviceConnectionActivation.deployment_id,
        )
        .where(
            DeviceConnection.device_id == device_id,
            DeviceConnection.enabled.is_(True),
            DeviceConnectionActivation.status == "active",
        )
    ).all()
    old_status = device.onboarding_status
    if verification_status != "verified":
        new_status = verification_status
    elif not rows:
        new_status = "verified"
    else:
        scheduled = [
            runtime_status
            for runtime_status, mode in rows
            if mode == CollectorDeploymentMode.SCHEDULED
        ]
        any_drift = any(
            runtime_status == "drifted"
            for runtime_status, _ in rows
        )
        if any_drift or any(
            item in {"degraded", "stale"} for item in scheduled
        ):
            new_status = "degraded"
        elif scheduled and all(item == "healthy" for item in scheduled):
            new_status = "active"
        else:
            new_status = "monitoring_configured"
    device.onboarding_status = new_status
    device.updated_at = utcnow()
    if old_status != new_status:
        record_audit_event(
            db,
            event_type="device.monitoring.status_changed",
            actor_type="system",
            actor_id="collector.reconciler",
            entity_type="device",
            entity_id=device.id,
            details={"from": old_status, "to": new_status},
        )
    return device


def _set_runtime_status(
    db: Session,
    activation: DeviceConnectionActivation,
    deployment: CollectorDeployment | None,
    *,
    now: datetime,
) -> None:
    previous = activation.runtime_status
    runtime_status, reason = _runtime_evaluation(
        activation,
        deployment,
        now=now,
    )
    activation.runtime_status = runtime_status
    activation.health_reason = reason
    activation.last_evaluated_at = now
    activation.updated_at = now
    if previous != runtime_status:
        record_audit_event(
            db,
            event_type="device.connection.runtime_status_changed",
            actor_type="system",
            actor_id="collector.reconciler",
            entity_type="device_connection",
            entity_id=activation.connection_id,
            details={
                "from": previous,
                "to": runtime_status,
                "deployment_id": activation.deployment_id,
            },
        )


def reconcile_completed_run(db: Session, run: CollectorRun) -> None:
    activation = db.scalar(
        select(DeviceConnectionActivation)
        .where(DeviceConnectionActivation.deployment_id == run.deployment_id)
        .options(
            selectinload(DeviceConnectionActivation.connection),
            selectinload(DeviceConnectionActivation.deployment),
        )
    )
    if activation is None:
        return
    _observe_run(activation, run)
    now = utcnow()
    _set_runtime_status(db, activation, activation.deployment, now=now)
    refresh_device_runtime_status(db, activation.connection.device_id)


def reconcile_activated_deployments(db: Session) -> int:
    now = utcnow()
    activations = list(
        db.scalars(
            select(DeviceConnectionActivation)
            .where(DeviceConnectionActivation.status == "active")
            .options(
                selectinload(DeviceConnectionActivation.connection),
                selectinload(DeviceConnectionActivation.deployment),
            )
        ).all()
    )
    device_ids: set[str] = set()
    for activation in activations:
        if activation.deployment_id:
            latest = db.scalar(
                select(CollectorRun)
                .where(
                    CollectorRun.deployment_id == activation.deployment_id,
                    CollectorRun.status.in_(TERMINAL_RUN_STATUSES),
                )
                .order_by(CollectorRun.finished_at.desc(), CollectorRun.id.desc())
                .limit(1)
            )
            if latest is not None:
                _observe_run(activation, latest)
        _set_runtime_status(db, activation, activation.deployment, now=now)
        device_ids.add(activation.connection.device_id)
    for device_id in device_ids:
        refresh_device_runtime_status(db, device_id)
    return len(activations)
