from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .activation_schemas import DeviceActivationPolicyCreate
from .models import (
    Artifact,
    ArtifactVersion,
    ArtifactVersionStatus,
    CollectorDeploymentMode,
    DeviceActivationPolicy,
)
from .services.activation import (
    create_activation_policy,
    publish_activation_policy,
    validate_activation_policy,
)


def _published_artifact_version(db: Session, artifact: Artifact) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(
            ArtifactVersion.artifact_id == artifact.id,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
        )
        .order_by(ArtifactVersion.version.desc())
    )
    if version is None:
        raise RuntimeError(f"Built-in artifact {artifact.name!r} has no published version")
    return version


def _ensure_policy(
    db: Session,
    *,
    artifact: Artifact,
    payload: dict[str, Any],
) -> DeviceActivationPolicy:
    existing = db.scalar(
        select(DeviceActivationPolicy)
        .where(
            DeviceActivationPolicy.name == payload["name"],
            DeviceActivationPolicy.status == ArtifactVersionStatus.PUBLISHED,
        )
        .order_by(DeviceActivationPolicy.version.desc())
    )
    if existing is not None:
        return existing

    version = _published_artifact_version(db, artifact)
    policy = create_activation_policy(
        db,
        DeviceActivationPolicyCreate.model_validate(
            {
                **payload,
                "artifact_version_id": version.id,
                "created_by": "system.bootstrap",
            }
        ),
    )
    validate_activation_policy(db, policy, "system.bootstrap")
    return publish_activation_policy(db, policy, "system.bootstrap")


def ensure_snmp_activation_policy(
    db: Session,
    artifact: Artifact,
) -> DeviceActivationPolicy:
    return _ensure_policy(
        db,
        artifact=artifact,
        payload={
            "name": "builtin-snmp-site-local",
            "protocol": "snmp",
            "target_template": {
                "exporter_url": "http://127.0.0.1:9116",
                "target": "${management_ip}",
            },
            "configuration_defaults": {},
            "worker_selector": {"site": "${site}"},
            "execution_mode": CollectorDeploymentMode.SCHEDULED,
            "schedule_seconds": 300,
        },
    )


def ensure_windows_exporter_activation_policy(
    db: Session,
    artifact: Artifact,
) -> DeviceActivationPolicy:
    return _ensure_policy(
        db,
        artifact=artifact,
        payload={
            "name": "builtin-windows-exporter",
            "protocol": "windows_exporter",
            "target_template": {
                "url": "http://${management_ip}:${port}/metrics",
            },
            "configuration_defaults": {},
            "worker_selector": {"site": "${site}"},
            "execution_mode": CollectorDeploymentMode.SCHEDULED,
            "schedule_seconds": 300,
        },
    )


def ensure_psrp_cim_activation_policy(
    db: Session,
    artifact: Artifact,
) -> DeviceActivationPolicy:
    return _ensure_policy(
        db,
        artifact=artifact,
        payload={
            "name": "builtin-psrp-cim-diagnostics",
            "protocol": "winrm_https",
            "target_template": {
                "host": "${management_ip}",
                "port": "${port}",
                "use_ssl": True,
            },
            "configuration_defaults": {},
            "worker_selector": {"site": "${site}"},
            "execution_mode": CollectorDeploymentMode.ON_DEMAND,
            "schedule_seconds": 300,
        },
    )


def ensure_builtin_activation_policies(
    db: Session,
    *,
    snmp_artifact: Artifact,
    windows_exporter_artifact: Artifact,
    psrp_cim_artifact: Artifact,
) -> list[DeviceActivationPolicy]:
    return [
        ensure_snmp_activation_policy(db, snmp_artifact),
        ensure_windows_exporter_activation_policy(db, windows_exporter_artifact),
        ensure_psrp_cim_activation_policy(db, psrp_cim_artifact),
    ]
