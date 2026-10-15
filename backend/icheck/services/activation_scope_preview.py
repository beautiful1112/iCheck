"""Read-only, current-state scope explanation for a sealed AI policy suggestion.

This is not policy validation, publication, preflight, or an activation plan.
The model sees neither management IP nor credential reference; this service
resolves those values only after generation for an authorized human reviewer.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..activation_schemas import (
    ActivationDraftScopePreview,
    ActivationProposalScopePreview,
    DeviceActivationPolicyCreate,
)
from ..collector_schemas import CollectorDeploymentCreate
from ..models import (
    ActivationPolicyProposal, CollectorWorker, CollectorWorkerState,
    CredentialProfile, Device,
)
from .activation import (
    _canonical_hash, _check_policy_artifact, _merge_selector, _render_value,
    _template_context, reject_inline_policy_credentials,
    validate_activation_policy_templates,
)
from .activation_proposals import _saved_result
from .collectors import validate_deployment_payload


WORKER_SCAN_LIMIT = 1000
FRESH_HEARTBEAT = timedelta(seconds=90)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def preview_proposal_scope(
    db: Session, row: ActivationPolicyProposal, *, device: Device | None,
) -> ActivationProposalScopePreview:
    """Explain the saved suggestion against current device/profile/Worker state."""
    result = _saved_result(row)  # Refuse a changed or non-terminal snapshot.
    draft = result.draft
    if row.device_id is not None and (device is None or device.id != row.device_id):
        raise ValueError("A device-bound proposal can only be previewed for its original device")
    if draft.protocol != row.protocol or draft.artifact_version_id != row.artifact_version_id:
        raise ValueError("Stored activation proposal context mismatch")
    return ActivationProposalScopePreview(
        proposal_id=row.id,
        proposal_sha256=row.result_sha256,
        **_preview_scope_details(
            db, draft=draft, device=device, source="saved AI suggestion",
        ),
    )


def preview_draft_scope(
    db: Session, draft: DeviceActivationPolicyCreate, *, device: Device | None,
) -> ActivationDraftScopePreview:
    """Explain the exact current editor payload without saving or publishing it."""
    reject_inline_policy_credentials(draft)
    blockers: list[str] = []
    try:
        validate_activation_policy_templates(db, draft)
    except (LookupError, ValueError) as exc:
        blockers.append(str(exc))
    return ActivationDraftScopePreview(
        draft_sha256=_canonical_hash(draft.model_dump(mode="json")),
        **_preview_scope_details(
            db, draft=draft, device=device, source="current editor draft",
            initial_blockers=blockers,
        ),
    )


def _preview_scope_details(
    db: Session,
    *,
    draft: DeviceActivationPolicyCreate,
    device: Device | None,
    source: str,
    initial_blockers: list[str] | None = None,
) -> dict[str, Any]:
    blockers = list(initial_blockers or [])
    warnings = [
        f"Advisory current-state view of the {source}; it grants no publication or deployment authority.",
        "Final activation still requires policy validation/publication, verified connection preflight, exact plan review and approval.",
        "This check cannot prove vendor authentication, endpoint reachability, Worker outbound host allowlisting or a future successful run.",
    ]
    version = None
    adapter_type = None
    try:
        version = _check_policy_artifact(
            db, protocol=draft.protocol,
            artifact_version_id=draft.artifact_version_id,
            require_published=True,
        )
        adapter_type = version.collector_definition.adapter_type
    except (LookupError, ValueError) as exc:
        blockers.append(str(exc))

    connection = None
    if device is None:
        blockers.append("Choose an authorized device to resolve a concrete target, credential and Worker scope.")
    else:
        connection = next(
            (item for item in device.connections if item.protocol == draft.protocol),
            None,
        )
        if connection is None:
            blockers.append("The device has no connection for the proposal protocol.")
        else:
            if not device.enabled or not connection.enabled:
                blockers.append("The device and connection must both be enabled.")
            if connection.verification_status != "verified":
                blockers.append("The device connection has not passed verification.")
            if not device.management_ip or not device.site or connection.port is None:
                blockers.append("Device management IP, site and connection port are required to render scope.")

    default_credential_ref = (
        version.collector_definition.credential_profile_ref if version is not None else None
    )
    credential_ref = (
        connection.credential_profile_ref
        if connection is not None and connection.credential_profile_ref
        else default_credential_ref
    )
    credential_source = (
        "connection" if connection and connection.credential_profile_ref
        else "collector_default" if credential_ref else "none"
    )
    profile = db.scalar(select(CredentialProfile).where(or_(
        CredentialProfile.id == credential_ref,
        CredentialProfile.name == credential_ref,
    ))) if credential_ref else None
    if credential_ref and profile is None:
        blockers.append("The referenced credential profile is unavailable in this namespace.")
    if profile is not None and not profile.enabled:
        blockers.append("The referenced credential profile is disabled.")
    if (
        profile is not None and adapter_type is not None
        and adapter_type not in profile.allowed_adapters
    ):
        blockers.append("The credential profile does not allow this collector adapter.")

    target = None
    policy_selector = None
    effective_selector = None
    worker_count = fresh_count = None
    scan_truncated = False
    if connection is not None and device is not None and (
        device.management_ip and device.site and connection.port is not None
    ):
        context = _template_context(
            device_id=device.id, device_name=device.name,
            management_ip=device.management_ip, port=connection.port,
            protocol=draft.protocol, site=device.site,
        )
        try:
            target = _render_value(draft.target_template, context, "target_template")
            configuration = _render_value(
                draft.configuration_defaults, context, "configuration_defaults",
            )
            policy_selector = _render_value(
                draft.worker_selector, context, "worker_selector",
            )
            if not isinstance(target, dict) or not isinstance(configuration, dict):
                raise ValueError("Rendered target and configuration must be objects")
            if not isinstance(policy_selector, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in policy_selector.items()
            ):
                raise ValueError("Rendered Worker selector must contain string pairs")
            effective_selector = _merge_selector(
                policy_selector, connection.worker_selector,
            )
            payload = CollectorDeploymentCreate(
                name=f"scope-preview-{_canonical_hash(draft.model_dump(mode='json'))[:16]}",
                artifact_version_id=draft.artifact_version_id,
                scope_device_id=device.id,
                scope_device_identity_revision=device.identity_revision,
                target_classification="registered_device",
                scope_site=device.site,
                target=target,
                configuration={**configuration, **connection.configuration},
                worker_selector=effective_selector,
                execution_mode=draft.execution_mode,
                credential_profile_ref=connection.credential_profile_ref,
                schedule_seconds=draft.schedule_seconds,
                created_by=draft.created_by,
            )
            validate_deployment_payload(db, payload)
        except (LookupError, ValueError, ValidationError) as exc:
            blockers.append(str(exc))
        if effective_selector is not None and adapter_type is not None:
            registered = list(db.scalars(select(CollectorWorker).where(
                CollectorWorker.state == CollectorWorkerState.ONLINE,
            ).order_by(CollectorWorker.id).limit(WORKER_SCAN_LIMIT + 1)).all())
            scan_truncated = len(registered) > WORKER_SCAN_LIMIT
            worker_count = fresh_count = 0
            fresh_after = datetime.now(UTC) - FRESH_HEARTBEAT
            for worker in registered[:WORKER_SCAN_LIMIT]:
                labels = {**worker.labels, **({"site": worker.site} if worker.site else {})}
                if adapter_type not in worker.capabilities or any(
                    labels.get(key) != value for key, value in effective_selector.items()
                ):
                    continue
                worker_count += 1
                if _as_utc(worker.last_heartbeat_at) >= fresh_after:
                    fresh_count += 1
            if fresh_count == 0:
                warnings.append("No fresh registered Worker in the bounded scan currently matches the adapter and effective selector.")
            if scan_truncated:
                warnings.append("Worker scan reached its 1,000-record cap; counts are partial and cannot prove fleet-wide absence.")

    return dict(
        evaluated_at=datetime.now(UTC), advisory_only=True,
        device_id=device.id if device else None,
        connection_id=connection.id if connection else None,
        protocol=draft.protocol, artifact_version_id=draft.artifact_version_id,
        adapter_type=adapter_type,
        rendered_target=target,
        policy_worker_selector=policy_selector,
        connection_worker_selector=dict(connection.worker_selector) if connection else None,
        effective_worker_selector=effective_selector,
        credential_profile_ref=credential_ref,
        credential_source=credential_source,
        credential_profile_enabled=profile.enabled if profile else None,
        credential_adapter_allowed=(
            adapter_type in profile.allowed_adapters
            if profile is not None and adapter_type is not None else None
        ),
        credential_worker_selector=dict(profile.worker_selector) if profile else None,
        registered_worker_matches_in_scan=worker_count,
        fresh_worker_matches_in_scan=fresh_count,
        worker_scan_truncated=scan_truncated,
        blockers=list(dict.fromkeys(blockers)), warnings=warnings,
    )
