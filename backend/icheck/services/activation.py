from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..activation_schemas import (
    ActivationPolicyDraftUpdate,
    ActivationPlanRead,
    DeviceActivationPolicyCreate,
)
from ..collector_schemas import CollectorDeploymentCreate
from ..database import require_locking_transaction
from ..models import (
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    CollectorDeployment,
    CollectorDeploymentMode,
    Device,
    DeviceActivationPolicy,
    DeviceConnection,
    DeviceConnectionActivation,
    utcnow,
)
from ..schema_validation import validate_instance
from ..sandbox import POTENTIAL_SECRET_LITERAL
from .audit import record_audit_event
from .collectors import (
    SENSITIVE_KEYS,
    assert_no_inline_secrets,
    create_deployment,
    validate_deployment_payload,
)
from .devices import PROTOCOL_ACTIVATION_ADAPTERS
from .runtime_health import (
    deployment_fingerprint,
    refresh_device_runtime_status,
)


PLACEHOLDER_PATTERN = re.compile(r"\$\{([a-z_]+)\}")
ALLOWED_PLACEHOLDERS = {
    "device_id",
    "device_name",
    "management_ip",
    "port",
    "protocol",
    "site",
}


class ActivationPolicyRevisionConflict(RuntimeError):
    """A draft changed, became immutable, or lost an optimistic update race."""
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|token|api[ _-]?key|community|secret)\s*[:=]\s*\S+"
)


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _policy_version(db: Session, name: str) -> int:
    current = db.scalar(
        select(func.max(DeviceActivationPolicy.version)).where(
            DeviceActivationPolicy.name == name
        )
    )
    return int(current or 0) + 1


def _artifact_version(db: Session, version_id: str) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == version_id)
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
    )
    if version is None:
        raise LookupError("Artifact version not found")
    if version.artifact.kind != ArtifactKind.COLLECTOR:
        raise ValueError("Activation policies require a collector artifact")
    if version.collector_definition is None:
        raise ValueError("Collector definition is missing")
    return version


def _check_policy_artifact(
    db: Session,
    *,
    protocol: str,
    artifact_version_id: str,
    require_published: bool,
) -> ArtifactVersion:
    version = _artifact_version(db, artifact_version_id)
    allowed_adapters = PROTOCOL_ACTIVATION_ADAPTERS[protocol]
    definition = version.collector_definition
    if definition is None:
        raise ValueError("Collector definition is missing")
    if definition.adapter_type not in allowed_adapters:
        raise ValueError(
            f"Protocol {protocol!r} requires adapter in "
            f"{sorted(allowed_adapters)!r}, not {definition.adapter_type!r}"
        )
    if require_published and version.status != ArtifactVersionStatus.PUBLISHED:
        raise ValueError("Activation policies require a published collector version")
    return version


def _render_value(value: Any, context: dict[str, Any], path: str) -> Any:
    if isinstance(value, dict):
        return {
            key: _render_value(child, context, f"{path}.{key}")
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [
            _render_value(child, context, f"{path}[{index}]")
            for index, child in enumerate(value)
        ]
    if not isinstance(value, str):
        return value
    matches = PLACEHOLDER_PATTERN.findall(value)
    unknown = sorted(set(matches) - ALLOWED_PLACEHOLDERS)
    if unknown:
        raise ValueError(f"{path} uses unsupported placeholders: {unknown}")
    exact = PLACEHOLDER_PATTERN.fullmatch(value)
    if exact:
        rendered = context.get(exact.group(1))
        if rendered is None:
            raise ValueError(f"{path} requires unavailable {exact.group(1)!r}")
        return rendered
    result = value
    for name in matches:
        rendered = context.get(name)
        if rendered is None:
            raise ValueError(f"{path} requires unavailable {name!r}")
        result = result.replace(f"${{{name}}}", str(rendered))
    if "${" in result:
        raise ValueError(f"{path} contains an invalid placeholder")
    return result


def _template_context(
    *,
    device_id: str,
    device_name: str,
    management_ip: str,
    port: int | None,
    protocol: str,
    site: str,
) -> dict[str, Any]:
    return {
        "device_id": device_id,
        "device_name": device_name,
        "management_ip": management_ip,
        "port": port,
        "protocol": protocol,
        "site": site,
    }


def reject_inline_policy_credentials(
    policy: DeviceActivationPolicy | DeviceActivationPolicyCreate,
) -> None:
    """Keep operator-edited policy templates free of credential literals."""
    for field in ("target_template", "configuration_defaults", "worker_selector"):
        value = getattr(policy, field)
        assert_no_inline_secrets(value, field)
        document = json.dumps(value, ensure_ascii=False)
        if POTENTIAL_SECRET_LITERAL.search(document) or SECRET_ASSIGNMENT.search(document):
            raise ValueError(f"{field} appears to contain an inline credential")
    if policy.protocol == "https_api":
        url = policy.target_template.get("url")
        if isinstance(url, str):
            parsed = urlsplit(url)
            if parsed.username or parsed.password:
                raise ValueError("HTTPS API target cannot embed credentials")
            if any(
                key.lower().replace("-", "_") in SENSITIVE_KEYS
                for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
            ):
                raise ValueError("HTTPS API URL cannot contain credential query keys")


def validate_activation_policy_templates(
    db: Session,
    policy: DeviceActivationPolicy | DeviceActivationPolicyCreate,
) -> ArtifactVersion:
    """Run the same pure template/contract checks before preview or publication."""
    reject_inline_policy_credentials(policy)
    version = _check_policy_artifact(
        db,
        protocol=policy.protocol,
        artifact_version_id=policy.artifact_version_id,
        require_published=True,
    )
    definition = version.collector_definition
    if definition is None:
        raise ValueError("Collector definition is missing")
    context = _template_context(
        device_id="00000000-0000-0000-0000-000000000000",
        device_name="validation-device",
        management_ip="192.0.2.1",
        port=443,
        protocol=policy.protocol,
        site="VALIDATION",
    )
    target = _render_value(policy.target_template, context, "target_template")
    configuration = _render_value(
        policy.configuration_defaults, context, "configuration_defaults",
    )
    selector = _render_value(policy.worker_selector, context, "worker_selector")
    if not isinstance(target, dict) or not isinstance(configuration, dict):
        raise ValueError("Activation policy templates must render to objects")
    if not isinstance(selector, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in selector.items()
    ):
        raise ValueError("worker_selector must render to string key/value pairs")
    validate_instance(target, definition.target_schema, "activation target template")
    validate_instance(
        {**definition.defaults, **configuration},
        definition.config_schema,
        "activation configuration template",
    )
    if policy.protocol == "https_api":
        url = target.get("url")
        parsed = urlsplit(url) if isinstance(url, str) else None
        if parsed is None or parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("HTTPS API target must use an HTTPS URL")
        if parsed.username or parsed.password:
            raise ValueError("HTTPS API target cannot embed credentials")
    if (
        definition.adapter_type == "psrp_cim"
        and policy.execution_mode != CollectorDeploymentMode.ON_DEMAND
    ):
        raise ValueError("psrp_cim activation policies must use on_demand execution")
    return version


def create_activation_policy(
    db: Session,
    payload: DeviceActivationPolicyCreate,
) -> DeviceActivationPolicy:
    version = _check_policy_artifact(
        db,
        protocol=payload.protocol,
        artifact_version_id=payload.artifact_version_id,
        require_published=False,
    )
    reject_inline_policy_credentials(payload)
    definition = version.collector_definition
    if definition is None:
        raise ValueError("Collector definition is missing")
    policy = DeviceActivationPolicy(
        name=payload.name,
        version=_policy_version(db, payload.name),
        status=ArtifactVersionStatus.DRAFT,
        protocol=payload.protocol,
        adapter_type=definition.adapter_type,
        artifact_version_id=payload.artifact_version_id,
        target_template=payload.target_template,
        configuration_defaults=payload.configuration_defaults,
        worker_selector=payload.worker_selector,
        execution_mode=payload.execution_mode,
        schedule_seconds=payload.schedule_seconds,
        created_by=payload.created_by,
        updated_by=payload.created_by,
        updated_at=utcnow(),
    )
    db.add(policy)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="device.activation_policy.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="device_activation_policy",
            entity_id=policy.id,
            details={
                "name": policy.name,
                "version": policy.version,
                "protocol": policy.protocol,
                "artifact_version_id": policy.artifact_version_id,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Activation policy version already exists") from exc
    db.refresh(policy)
    return policy


def update_activation_policy_draft(
    db: Session,
    policy_id: str,
    payload: ActivationPolicyDraftUpdate,
) -> DeviceActivationPolicy:
    """Atomically revise only a draft, preserving its version and audit trail."""
    require_locking_transaction(db, purpose="Activation policy draft edits")
    policy = db.scalar(
        select(DeviceActivationPolicy)
        .where(DeviceActivationPolicy.id == policy_id)
        .with_for_update()
    )
    if policy is None:
        raise LookupError("Activation policy not found")
    if policy.status != ArtifactVersionStatus.DRAFT:
        raise ActivationPolicyRevisionConflict("Only draft activation policies can be edited")
    if policy.revision != payload.expected_revision:
        raise ActivationPolicyRevisionConflict("Activation policy draft revision changed")
    draft = payload.draft
    if draft.name != policy.name:
        raise ValueError("A policy name is stable; create a new policy for a rename")
    version = _check_policy_artifact(
        db, protocol=draft.protocol,
        artifact_version_id=draft.artifact_version_id,
        require_published=False,
    )
    reject_inline_policy_credentials(draft)
    definition = version.collector_definition
    if definition is None:
        raise ValueError("Collector definition is missing")
    old_content = {
        "protocol": policy.protocol,
        "adapter_type": policy.adapter_type,
        "artifact_version_id": policy.artifact_version_id,
        "target_template": policy.target_template,
        "configuration_defaults": policy.configuration_defaults,
        "worker_selector": policy.worker_selector,
        "execution_mode": policy.execution_mode.value,
        "schedule_seconds": policy.schedule_seconds,
    }
    new_content = {
        "protocol": draft.protocol,
        "adapter_type": definition.adapter_type,
        "artifact_version_id": draft.artifact_version_id,
        "target_template": draft.target_template,
        "configuration_defaults": draft.configuration_defaults,
        "worker_selector": draft.worker_selector,
        "execution_mode": draft.execution_mode.value,
        "schedule_seconds": draft.schedule_seconds,
    }
    changed_fields = sorted(
        key for key in old_content if old_content[key] != new_content[key]
    )
    if not changed_fields:
        return policy
    changed = db.execute(
        update(DeviceActivationPolicy)
        .where(
            DeviceActivationPolicy.id == policy.id,
            DeviceActivationPolicy.status == ArtifactVersionStatus.DRAFT,
            DeviceActivationPolicy.revision == payload.expected_revision,
        )
        .values(
            **{key: getattr(draft, key) for key in (
                "protocol", "artifact_version_id", "target_template",
                "configuration_defaults", "worker_selector", "execution_mode",
                "schedule_seconds",
            )},
            adapter_type=definition.adapter_type,
            revision=payload.expected_revision + 1,
            updated_by=payload.actor,
            updated_at=utcnow(),
        )
        .returning(DeviceActivationPolicy.id)
    ).scalar_one_or_none()
    if changed is None:
        db.rollback()
        raise ActivationPolicyRevisionConflict("Activation policy draft revision changed")
    record_audit_event(
        db,
        event_type="device.activation_policy.draft_updated",
        actor_type="user",
        actor_id=payload.actor,
        entity_type="device_activation_policy",
        entity_id=policy.id,
        details={
            "revision_before": payload.expected_revision,
            "revision_after": payload.expected_revision + 1,
            "changed_fields": changed_fields,
            "content_sha256_before": _canonical_hash(old_content),
            "content_sha256_after": _canonical_hash(new_content),
        },
    )
    db.commit()
    db.refresh(policy)
    return policy


def validate_activation_policy(
    db: Session,
    policy: DeviceActivationPolicy,
    actor: str,
    *,
    expected_revision: int | None = None,
) -> DeviceActivationPolicy:
    require_locking_transaction(db, purpose="Activation policy validation")
    db.refresh(policy, with_for_update=True)
    if policy.status != ArtifactVersionStatus.DRAFT:
        raise ValueError("Only draft activation policies can be validated")
    if expected_revision is None and policy.revision > 1:
        raise ActivationPolicyRevisionConflict(
            "Validation of an edited draft requires expected_revision"
        )
    if expected_revision is not None and expected_revision != policy.revision:
        raise ActivationPolicyRevisionConflict("Activation policy draft revision changed")
    validate_activation_policy_templates(db, policy)
    content = {
        "name": policy.name,
        "version": policy.version,
        "protocol": policy.protocol,
        "adapter_type": policy.adapter_type,
        "artifact_version_id": policy.artifact_version_id,
        "target_template": policy.target_template,
        "configuration_defaults": policy.configuration_defaults,
        "worker_selector": policy.worker_selector,
        "execution_mode": policy.execution_mode.value,
        "schedule_seconds": policy.schedule_seconds,
    }
    policy.content_hash = _canonical_hash(content)
    policy.status = ArtifactVersionStatus.VALIDATED
    policy.validated_at = utcnow()
    policy.validated_by = actor
    record_audit_event(
        db,
        event_type="device.activation_policy.validated",
        actor_type="user",
        actor_id=actor,
        entity_type="device_activation_policy",
        entity_id=policy.id,
        details={"content_hash": policy.content_hash},
    )
    db.commit()
    db.refresh(policy)
    return policy


def publish_activation_policy(
    db: Session,
    policy: DeviceActivationPolicy,
    actor: str,
) -> DeviceActivationPolicy:
    if policy.status != ArtifactVersionStatus.VALIDATED:
        raise ValueError("Only validated activation policies can be published")
    previous = db.scalars(
        select(DeviceActivationPolicy).where(
            DeviceActivationPolicy.name == policy.name,
            DeviceActivationPolicy.status == ArtifactVersionStatus.PUBLISHED,
        )
    ).all()
    for item in previous:
        item.status = ArtifactVersionStatus.DEPRECATED
    policy.status = ArtifactVersionStatus.PUBLISHED
    policy.published_at = utcnow()
    policy.published_by = actor
    record_audit_event(
        db,
        event_type="device.activation_policy.published",
        actor_type="user",
        actor_id=actor,
        entity_type="device_activation_policy",
        entity_id=policy.id,
        details={"deprecated_policy_ids": [item.id for item in previous]},
    )
    db.commit()
    db.refresh(policy)
    return policy


def _connection(
    db: Session,
    device_id: str,
    connection_id: str,
    *,
    lock: bool = False,
) -> DeviceConnection:
    query = (
        select(DeviceConnection)
        .where(
            DeviceConnection.id == connection_id,
            DeviceConnection.device_id == device_id,
        )
        .options(
            selectinload(DeviceConnection.device),
            selectinload(DeviceConnection.activations).selectinload(
                DeviceConnectionActivation.policy
            ),
        )
    )
    if lock:
        query = query.with_for_update()
    connection = db.scalar(query)
    if connection is None:
        raise LookupError("Device connection not found")
    return connection


def _activation_policy(db: Session, policy_id: str) -> DeviceActivationPolicy:
    policy = db.get(DeviceActivationPolicy, policy_id)
    if policy is None:
        raise LookupError("Activation policy not found")
    return policy


def _merge_selector(
    policy_selector: dict[str, str],
    connection_selector: dict[str, str],
) -> dict[str, str]:
    merged = dict(policy_selector)
    for key, value in connection_selector.items():
        if key in merged and merged[key] != value:
            raise ValueError(
                f"Activation policy worker selector conflicts on {key!r}"
            )
        merged[key] = value
    return merged


def _deployment_name(
    device: Device,
    connection: DeviceConnection,
    policy: DeviceActivationPolicy,
) -> str:
    base = f"onboard-{device.name}-{connection.protocol}-{policy.id[:8]}"
    return base[:255]


def _build_activation_plan(
    db: Session,
    connection: DeviceConnection,
    policy: DeviceActivationPolicy,
    *,
    actor: str,
) -> tuple[ActivationPlanRead, CollectorDeploymentCreate]:
    if not connection.enabled or not connection.device.enabled:
        raise ValueError("Device and connection must be enabled before activation")
    if connection.verification_status != "verified":
        raise ValueError("Only verified device connections can be activated")
    if policy.status != ArtifactVersionStatus.PUBLISHED:
        raise ValueError("Only published activation policies can be used")
    if policy.protocol != connection.protocol:
        raise ValueError("Activation policy protocol does not match the connection")
    if policy.adapter_type not in PROTOCOL_ACTIVATION_ADAPTERS[connection.protocol]:
        raise ValueError("Activation policy adapter is incompatible with the connection")
    version = _check_policy_artifact(
        db,
        protocol=policy.protocol,
        artifact_version_id=policy.artifact_version_id,
        require_published=True,
    )
    device = connection.device
    if not device.management_ip or not device.site:
        raise ValueError("Activation requires device management IP and site")
    context = _template_context(
        device_id=device.id,
        device_name=device.name,
        management_ip=device.management_ip,
        port=connection.port,
        protocol=connection.protocol,
        site=device.site,
    )
    target = _render_value(policy.target_template, context, "target_template")
    policy_configuration = _render_value(
        policy.configuration_defaults,
        context,
        "configuration_defaults",
    )
    policy_selector = _render_value(
        policy.worker_selector,
        context,
        "worker_selector",
    )
    if not isinstance(target, dict) or not isinstance(policy_configuration, dict):
        raise ValueError("Activation templates must render to objects")
    if not isinstance(policy_selector, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in policy_selector.items()
    ):
        raise ValueError("worker_selector must render to string key/value pairs")
    configuration = {**policy_configuration, **connection.configuration}
    worker_selector = _merge_selector(
        policy_selector,
        connection.worker_selector,
    )
    deployment = CollectorDeploymentCreate(
        name=_deployment_name(device, connection, policy),
        artifact_version_id=policy.artifact_version_id,
        scope_device_id=device.id,
        scope_device_identity_revision=device.identity_revision,
        target_classification="registered_device",
        scope_site=device.site,
        target=target,
        configuration=configuration,
        worker_selector=worker_selector,
        execution_mode=policy.execution_mode,
        credential_profile_ref=connection.credential_profile_ref,
        schedule_seconds=policy.schedule_seconds,
        enabled=True,
        created_by=actor,
    )
    validated_version, credential_ref = validate_deployment_payload(db, deployment)
    definition = validated_version.collector_definition
    if definition is None:
        raise ValueError("Collector definition is missing")
    warnings: list[str] = []
    evidence = connection.last_verification_evidence
    if evidence.get("authentication_tested") is False:
        warnings.append(
            "Preflight verified transport only; collector authentication is unproven."
        )
    if policy.execution_mode == CollectorDeploymentMode.ON_DEMAND:
        warnings.append("On-demand deployment will not run until explicitly triggered.")
    plan_content = {
        "policy_id": policy.id,
        "policy_content_hash": policy.content_hash,
        "connection_id": connection.id,
        "scope_device_identity_revision": device.identity_revision,
        "target_classification": deployment.target_classification,
        "verification_time": (
            connection.last_verified_at.isoformat()
            if connection.last_verified_at
            else None
        ),
        "deployment_name": deployment.name,
        "artifact_version_id": deployment.artifact_version_id,
        "target": deployment.target,
        "configuration": deployment.configuration,
        "worker_selector": deployment.worker_selector,
        "execution_mode": deployment.execution_mode.value,
        "schedule_seconds": deployment.schedule_seconds,
        "credential_profile_ref": credential_ref,
    }
    plan = ActivationPlanRead(
        policy_id=policy.id,
        policy_name=policy.name,
        policy_version=policy.version,
        connection_id=connection.id,
        scope_device_identity_revision=device.identity_revision,
        target_classification="registered_device",
        deployment_name=deployment.name,
        artifact_version_id=deployment.artifact_version_id,
        artifact_name=version.artifact.name,
        artifact_version=version.version,
        target=deployment.target,
        configuration=deployment.configuration,
        worker_selector=deployment.worker_selector,
        execution_mode=deployment.execution_mode,
        schedule_seconds=deployment.schedule_seconds,
        credential_profile_ref=credential_ref,
        warnings=warnings,
        plan_hash=_canonical_hash(plan_content),
    )
    return plan, deployment


def preview_activation(
    db: Session,
    device_id: str,
    connection_id: str,
    policy_id: str,
) -> ActivationPlanRead:
    connection = _connection(db, device_id, connection_id)
    policy = _activation_policy(db, policy_id)
    plan, _ = _build_activation_plan(
        db,
        connection,
        policy,
        actor="activation.preview",
    )
    return plan


def _restore_approved_deployment(
    deployment: CollectorDeployment,
    payload: CollectorDeploymentCreate,
    *,
    credential_profile_ref: str | None,
    now: datetime,
) -> None:
    deployment.artifact_version_id = payload.artifact_version_id
    deployment.scope_device_identity_revision = payload.scope_device_identity_revision
    deployment.target_classification = payload.target_classification
    deployment.external_source_reason = payload.external_source_reason
    deployment.target = payload.target
    deployment.configuration = payload.configuration
    deployment.worker_selector = payload.worker_selector
    deployment.execution_mode = payload.execution_mode
    deployment.credential_profile_ref = credential_profile_ref
    deployment.schedule_seconds = payload.schedule_seconds
    deployment.enabled = True
    deployment.next_run_at = (
        now
        if payload.execution_mode == CollectorDeploymentMode.SCHEDULED
        else None
    )
    deployment.updated_at = now


def approve_activation(
    db: Session,
    device_id: str,
    connection_id: str,
    policy_id: str,
    *,
    expected_plan_hash: str,
    actor: str,
    reason: str,
) -> tuple[DeviceConnectionActivation, CollectorDeployment]:
    connection = _connection(db, device_id, connection_id, lock=True)
    policy = _activation_policy(db, policy_id)
    plan, deployment_payload = _build_activation_plan(
        db,
        connection,
        policy,
        actor=actor,
    )
    if not secrets.compare_digest(plan.plan_hash, expected_plan_hash):
        raise ValueError("Activation plan changed; preview and approve it again")

    existing = next(
        (
            item
            for item in connection.activations
            if item.capability_key == policy.name
        ),
        None,
    )
    if existing is not None and existing.status == "active":
        if existing.plan_hash == plan.plan_hash and existing.policy_id == policy.id:
            deployment = db.get(CollectorDeployment, existing.deployment_id)
            if deployment is None:
                raise LookupError("Active collector deployment not found")
            expected_hash = deployment_fingerprint(deployment)
            if (
                existing.expected_deployment_hash == expected_hash
                and deployment.enabled
            ):
                return existing, deployment

    now = utcnow()
    replaced_deployment_id: str | None = None
    replaced_run_in_flight = False
    if (
        existing is not None
        and existing.plan_hash == plan.plan_hash
        and existing.policy_id == policy.id
        and existing.deployment_id is not None
    ):
        deployment = db.get(CollectorDeployment, existing.deployment_id)
        if deployment is None:
            raise LookupError("Collector deployment not found")
        _restore_approved_deployment(
            deployment,
            deployment_payload,
            credential_profile_ref=plan.credential_profile_ref,
            now=now,
        )
        activation = existing
    else:
        deployment = create_deployment(db, deployment_payload, commit=False)
        if existing is None:
            activation = DeviceConnectionActivation(
                connection_id=connection.id,
                capability_key=policy.name,
                policy_id=policy.id,
                deployment_id=deployment.id,
                status="active",
                plan_hash=plan.plan_hash,
                expected_deployment_hash=deployment_fingerprint(deployment),
                approved_by=actor,
                approval_reason=reason,
                activated_at=now,
            )
            db.add(activation)
        else:
            activation = existing
            previous_deployment = (
                db.get(CollectorDeployment, existing.deployment_id)
                if existing.deployment_id is not None
                else None
            )
            if previous_deployment is not None:
                replaced_deployment_id = previous_deployment.id
                replaced_run_in_flight = (
                    previous_deployment.lease_expires_at is not None
                    and _as_utc(previous_deployment.lease_expires_at) >= now
                )
                previous_deployment.enabled = False
                previous_deployment.next_run_at = None
                previous_deployment.updated_at = now
            activation.capability_key = policy.name
            activation.policy_id = policy.id
            activation.deployment_id = deployment.id
            activation.plan_hash = plan.plan_hash
    activation.status = "active"
    activation.expected_deployment_hash = deployment_fingerprint(deployment)
    activation.runtime_status = (
        "on_demand_ready"
        if deployment.execution_mode == CollectorDeploymentMode.ON_DEMAND
        else "awaiting_first_run"
    )
    activation.consecutive_failures = 0
    activation.last_run_id = None
    activation.last_run_status = None
    activation.last_run_finished_at = None
    activation.last_success_at = None
    activation.last_failure_at = None
    activation.last_evaluated_at = now
    activation.health_reason = (
        "Approved on-demand collector is ready."
        if deployment.execution_mode == CollectorDeploymentMode.ON_DEMAND
        else "Waiting for the first successful collector run."
    )
    activation.approved_by = actor
    activation.approval_reason = reason
    activation.activated_at = now
    activation.deactivated_at = None
    activation.deactivated_by = None
    activation.deactivation_reason = None
    activation.last_error = None
    activation.updated_at = now
    db.flush()
    refresh_device_runtime_status(db, device_id)
    record_audit_event(
        db,
        event_type="device.connection.activation.approved",
        actor_type="user",
        actor_id=actor,
        entity_type="device_connection",
        entity_id=connection.id,
        details={
            "policy_id": policy.id,
            "activation_id": activation.id,
            "capability_key": activation.capability_key,
            "deployment_id": deployment.id,
            "replaced_deployment_id": replaced_deployment_id,
            "replaced_run_in_flight": replaced_run_in_flight,
            "plan_hash": plan.plan_hash,
            "reason": reason,
            "warnings": plan.warnings,
        },
    )
    db.commit()
    db.refresh(activation)
    db.refresh(deployment)
    return activation, deployment


def deactivate_connection(
    db: Session,
    device_id: str,
    connection_id: str,
    *,
    activation_id: str | None = None,
    actor: str,
    reason: str,
) -> tuple[DeviceConnectionActivation, CollectorDeployment]:
    connection = _connection(db, device_id, connection_id, lock=True)
    active = [item for item in connection.activations if item.status == "active"]
    if activation_id is None:
        if len(active) > 1:
            raise ValueError(
                "Connection has multiple active capabilities; specify activation_id"
            )
        activation = active[0] if active else None
    else:
        activation = next(
            (item for item in connection.activations if item.id == activation_id),
            None,
        )
    if activation is None or activation.deployment_id is None:
        raise LookupError("Connection has no activated collector deployment")
    if activation.status != "active":
        raise ValueError("Connection activation is not active")
    deployment = db.get(CollectorDeployment, activation.deployment_id)
    if deployment is None:
        raise LookupError("Collector deployment not found")
    now = utcnow()
    lease_active = (
        deployment.lease_expires_at is not None
        and _as_utc(deployment.lease_expires_at) >= now
    )
    deployment.enabled = False
    deployment.next_run_at = None
    deployment.updated_at = now
    activation.status = "deactivated"
    activation.runtime_status = "disabled"
    activation.last_evaluated_at = now
    activation.health_reason = "Activation is deactivated."
    activation.deactivated_at = now
    activation.deactivated_by = actor
    activation.deactivation_reason = reason
    activation.updated_at = now
    db.flush()
    refresh_device_runtime_status(db, device_id)
    record_audit_event(
        db,
        event_type="device.connection.activation.deactivated",
        actor_type="user",
        actor_id=actor,
        entity_type="device_connection",
        entity_id=connection.id,
        details={
            "activation_id": activation.id,
            "capability_key": activation.capability_key,
            "deployment_id": deployment.id,
            "reason": reason,
            "run_in_flight": lease_active,
        },
    )
    db.commit()
    db.refresh(activation)
    db.refresh(deployment)
    return activation, deployment


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
