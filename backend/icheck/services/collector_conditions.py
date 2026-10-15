"""Origin-bound condition measurements; no independent closure authority."""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..collector_condition_schemas import COLLECTOR_CONDITION_V1, CollectorConditionDefinition, CollectorConditionObservation, condition_definitions, evaluate_condition
from ..config import get_settings
from ..models import (Alert, ArtifactKind, ArtifactVersion, ArtifactVersionStatus, AuditEvent,
    CollectionEnvelope, CollectorConditionAdmission, CollectorConditionReceipt, CollectorConditionSource,
    CollectorDefinition, CollectorDeployment, CollectorRun, CollectorRunStatus, CollectorWorker,
    CredentialProfile, Device, Endpoint, KnowledgeEntity, new_id, utcnow)
from ..worker_auth import authenticate_worker
from .alert_conditions import as_utc, latest_alert, lock_condition, observation_disposition, pin_identity, record_observation
from .alerts import resolve_by_dedup_key, upsert_alert
from .collector_condition_authority import PREFIX, collector_condition_writer
from .worker_mtls import verify_worker_peer


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _snapshot(db, run, observation, *, authorization=None, peer=None, accepted_context=None, nowait=False):
    """Take/refetch exact source rows after deployment/run locks.

    Capture authenticates the current Worker. Projection compares these
    current pins to the sealed capture; a payload cannot supply origin fields.
    """
    from .collectors import (_assignment_hash, _deployment_device_identity_current,
        artifact_version_content_material, artifact_content_hash)
    deployment = db.scalar(select(CollectorDeployment).where(CollectorDeployment.id == run.deployment_id)
        .with_for_update(nowait=nowait).execution_options(populate_existing=True))
    run = db.scalar(select(CollectorRun).where(CollectorRun.id == run.id)
        .with_for_update(nowait=nowait).execution_options(populate_existing=True))
    if deployment is None or run is None or run.status not in {CollectorRunStatus.RUNNING, CollectorRunStatus.SUCCEEDED}:
        raise ValueError("Collector condition run is unavailable or unsuccessful")
    if (run.execution_admitted_at is None or not run.assignment_sha256
        or run.artifact_version_id != deployment.artifact_version_id or not deployment.enabled):
        raise ValueError("Collector conditions require exact admitted current run ownership")
    worker = db.scalar(select(CollectorWorker).where(CollectorWorker.id == run.worker_id)
        .with_for_update(nowait=nowait).execution_options(populate_existing=True))
    if worker is None:
        raise ValueError("Collector condition Worker is unavailable")
    if accepted_context is None:
        authenticate_worker(worker, authorization)
        mode = get_settings().worker_mtls_mode
        if peer is not None and mode == "disabled":
            raise ValueError("Collector condition cannot label disabled mTLS as verified")
        verify_worker_peer(db, worker, peer, kind="collector", mode=mode)
    if deployment.scope_device_id is not None:
        device = db.scalar(select(Device).where(Device.id == deployment.scope_device_id)
            .with_for_update(nowait=nowait).execution_options(populate_existing=True))
        if device is None:
            raise ValueError("Collector condition Device is unavailable")
    if (deployment.target_classification not in {"registered_device", "external_source"}
        or not _deployment_device_identity_current(db, deployment)
        or _assignment_hash(deployment) != run.assignment_sha256):
        raise ValueError("Collector condition target/assignment identity has drifted")
    labels = {**worker.labels, **({"site": worker.site} if worker.site else {})}
    if worker.labels.get("io_supervisor_v1") is not True or any(labels.get(key) != value for key, value in deployment.worker_selector.items()):
        raise ValueError("Collector condition Worker selector has drifted")
    if deployment.target_classification == "external_source" and worker.labels.get("execution_admission_v1") is not True:
        raise ValueError("Collector condition external Worker admission capability has drifted")
    if deployment.scope_device_id is not None and worker.site != deployment.scope_site:
        raise ValueError("Collector condition Worker site has drifted")
    version = db.scalar(select(ArtifactVersion).where(ArtifactVersion.id == run.artifact_version_id)
        .with_for_update(nowait=nowait).execution_options(populate_existing=True))
    definition = db.scalar(select(CollectorDefinition).where(CollectorDefinition.artifact_version_id == version.id)
        .with_for_update(nowait=nowait).execution_options(populate_existing=True)) if version else None
    if (version is None or definition is None or version.artifact.kind != ArtifactKind.COLLECTOR
        or version.status != ArtifactVersionStatus.PUBLISHED or not version.content_hash):
        raise ValueError("Collector condition version is not published")
    if accepted_context is None and artifact_content_hash(kind=version.artifact.kind, definition=version.definition,
        implementation=version.implementation, tests=version.tests, collector_definition=definition) != version.content_hash:
        raise ValueError("Collector condition published version integrity has drifted")
    definitions = condition_definitions(version.definition)
    condition = next((item for item in definitions if item.key == observation.condition_key), None)
    if condition is None:
        raise ValueError("Condition key is not declared by the immutable Collector version")
    credential = None
    ref = deployment.credential_profile_ref or definition.credential_profile_ref
    grant = None
    if ref:
        profile = db.scalar(select(CredentialProfile).where(
            (CredentialProfile.id == ref) | (CredentialProfile.name == ref))
            .with_for_update(nowait=nowait).execution_options(populate_existing=True))
        if profile is None or not profile.enabled or definition.adapter_type not in profile.allowed_adapters:
            raise ValueError("Collector condition credential profile is unavailable")
        if any(labels.get(key) != value for key, value in profile.worker_selector.items()):
            raise ValueError("Collector condition credential Worker selector has drifted")
        grant = db.scalar(select(AuditEvent).where(AuditEvent.event_type == "credential.grant.issued",
            AuditEvent.entity_type == "collector_run", AuditEvent.entity_id == run.id,
            AuditEvent.actor_id == worker.id, AuditEvent.details["profile_id"].as_string() == profile.id,
            AuditEvent.details["profile_revision"].as_integer() == profile.revision,
            AuditEvent.details["adapter_type"].as_string() == definition.adapter_type)
            .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id).limit(1))
        if grant is None:
            raise ValueError("Collector condition requires a matching issued credential grant")
        credential = {"profile_id": profile.id, "profile_revision": profile.revision, "provider": profile.provider}
    entity_id = observation.entity_id
    if entity_id is None and condition.entity_type == "device":
        entity_id = deployment.scope_device_id
    if not entity_id:
        raise ValueError("Collector condition requires a bound entity ID")
    entity_pin = {"id": entity_id, "type": condition.entity_type}
    if condition.entity_type == "device":
        entity = db.scalar(select(Device).where(Device.id == entity_id).with_for_update(nowait=nowait).execution_options(populate_existing=True))
        if entity is None or not entity.enabled or (deployment.scope_device_id is not None and entity.id != deployment.scope_device_id) or (
            deployment.scope_site is not None and entity.site != deployment.scope_site):
            raise ValueError("Collector condition Device exceeds current source scope")
        entity_pin |= {"identity_revision": entity.identity_revision, "site": entity.site}
    elif condition.entity_type == "endpoint":
        from .knowledge_projection import _endpoint_in_scope
        entity = db.scalar(select(Endpoint).where(Endpoint.id == entity_id).with_for_update(nowait=nowait).execution_options(populate_existing=True))
        if entity is None:
            raise ValueError("Collector condition Endpoint is unavailable")
        _endpoint_in_scope(db, deployment, entity.id)
        entity_pin |= {"mac_address": entity.mac_address}
    elif condition.entity_type == "knowledge_entity":
        entity = db.scalar(select(KnowledgeEntity).where(KnowledgeEntity.id == entity_id)
            .with_for_update(nowait=nowait).execution_options(populate_existing=True))
        if entity is None or not entity.active or (
            deployment.scope_device_id is not None and entity.scope_device_id != deployment.scope_device_id) or (
            deployment.scope_site is not None and entity.scope_site != deployment.scope_site):
            raise ValueError("Collector condition knowledge entity exceeds current source scope")
        entity_pin |= {"namespace": entity.namespace, "external_key": entity.external_key,
            "scope_device_id": entity.scope_device_id, "scope_site": entity.scope_site}
    elif deployment.target_classification != "external_source":
        raise ValueError("External conditions require a reviewed external-source deployment")
    context = {
        "version_content_hash": version.content_hash,
        "version_material": artifact_version_content_material(version),
        "definition": condition.model_dump(mode="json"),
        "assignment_sha256": run.assignment_sha256,
        "deployment": {"id": deployment.id, "artifact_version_id": version.id, "target": deployment.target,
            "configuration": deployment.configuration, "worker_selector": deployment.worker_selector,
            "scope_device_id": deployment.scope_device_id, "scope_device_identity_revision": deployment.scope_device_identity_revision,
            "scope_site": deployment.scope_site, "target_classification": deployment.target_classification,
            "credential_profile_ref": ref, "external_source_reason": deployment.external_source_reason},
        "credential_profile": credential, "entity": entity_pin,
        "worker": {"id": worker.id, "token_issued_at": as_utc(worker.token_issued_at).isoformat(),
            "mtls_revision": worker.mtls_revision, "mtls_fingerprint_sha256": worker.mtls_fingerprint_sha256,
            "mtls_subject_sha256": worker.mtls_subject_sha256, "mtls_serial_sha256": worker.mtls_serial_sha256},
        "independently_verified": False, "authorizes_incident_closure": False,
    }
    if accepted_context is not None and canonical(context) != canonical(accepted_context["pins"]):
        raise ValueError("Collector condition provenance changed after envelope acceptance")
    return context, condition, grant


def seal_condition_envelope(db, run, envelope, *, authorization, peer, source_label=None):
    if envelope.type != COLLECTOR_CONDITION_V1:
        return
    from .collectors import assert_no_inline_secrets
    observation = CollectorConditionObservation.model_validate(envelope.payload)
    if envelope.subject is not None:
        if observation.entity_id is not None and observation.entity_id != envelope.subject:
            raise ValueError("Collector condition subject disagrees with entity ID")
        observation.entity_id = observation.entity_id or envelope.subject
    pins, _condition, grant = _snapshot(db, run, observation, authorization=authorization, peer=peer)
    now = utcnow()
    if as_utc(envelope.observed_at) > now+timedelta(minutes=5):
        raise ValueError("Collector condition exceeds the five-minute future clock bound")
    if grant is not None:
        if as_utc(grant.occurred_at) > as_utc(envelope.observed_at):
            raise ValueError("Collector condition observation precedes its credential grant")
        expires = as_utc(datetime.fromisoformat(grant.details["expires_at"]))
        if as_utc(envelope.observed_at) >= expires:
            raise ValueError("Collector condition observation exceeds its credential grant lifetime")
    if as_utc(envelope.observed_at) < as_utc(run.execution_admitted_at):
        raise ValueError("Collector condition observation precedes execution admission")
    context = {"pins": pins, "credential_grant_audit_id": grant.id if grant else None,
        "worker_auth_method": "bearer+verified_proxy_mtls" if peer else "bearer_only",
        "source_label": source_label or envelope.source, "accepted_at": now.isoformat()}
    assert_no_inline_secrets(context)
    payload = canonical(observation.model_dump(mode="json"))
    if len(payload) > 32768 or len(canonical(context)) > 131072:
        raise ValueError("Collector condition acceptance context exceeds its size bound")
    db.add(CollectorConditionAdmission(envelope_id=envelope.id, run_id=run.id,
        deployment_id=run.deployment_id, artifact_version_id=run.artifact_version_id, worker_id=run.worker_id,
        credential_grant_audit_id=grant.id if grant else None,
        observed_at=as_utc(envelope.observed_at), payload=payload, context=context))
    db.flush()


def validate_condition_duplicate(db, run, envelope, *, authorization, peer):
    """A duplicate response still requires fresh origin authentication."""
    admission = db.scalar(select(CollectorConditionAdmission).where(
        CollectorConditionAdmission.envelope_id == envelope.id))
    if admission is None:
        raise ValueError("Collector condition retry has no sealed acceptance provenance")
    observation = CollectorConditionObservation.model_validate(json.loads(admission.payload))
    pins, _definition, _grant = _snapshot(db, run, observation, authorization=authorization, peer=peer)
    if canonical(pins) != canonical(admission.context["pins"]):
        raise ValueError("Collector condition retry origin changed after acceptance")


def project_condition(db: Session, envelope: CollectionEnvelope) -> dict:
    admission = db.scalar(select(CollectorConditionAdmission).where(CollectorConditionAdmission.envelope_id == envelope.id))
    if admission is None:
        raise ValueError("Collector condition envelope has no sealed acceptance provenance")
    previous = db.scalar(select(CollectorConditionReceipt).where(CollectorConditionReceipt.admission_id == admission.id))
    if previous is not None:
        return previous.result
    observation = CollectorConditionObservation.model_validate(json.loads(admission.payload))
    sealed_observation = CollectorConditionObservation.model_validate(envelope.payload)
    if envelope.subject is not None:
        if sealed_observation.entity_id is not None and sealed_observation.entity_id != envelope.subject:
            raise ValueError("Collector condition subject has drifted")
        sealed_observation.entity_id = sealed_observation.entity_id or envelope.subject
    if canonical(sealed_observation.model_dump(mode="json")) != admission.payload or as_utc(envelope.observed_at) != as_utc(admission.observed_at):
        raise ValueError("Collector condition accepted measurement has drifted")
    run = db.get(CollectorRun, admission.run_id)
    if run is None or run.id != envelope.run_id:
        raise ValueError("Collector condition accepted run is unavailable")
    # Another projector may commit a receipt while this caller waits. Serialize
    # on the same deployment/run order as ingress, then repeat the immutable
    # receipt lookup before doing any domain mutation.
    db.scalar(select(CollectorDeployment).where(CollectorDeployment.id == admission.deployment_id)
        .with_for_update().execution_options(populate_existing=True))
    run = db.scalar(select(CollectorRun).where(CollectorRun.id == admission.run_id)
        .with_for_update().execution_options(populate_existing=True))
    previous = db.scalar(select(CollectorConditionReceipt).where(CollectorConditionReceipt.admission_id == admission.id))
    if previous is not None:
        return previous.result
    if admission.credential_grant_audit_id is not None:
        original_grant = db.get(AuditEvent, admission.credential_grant_audit_id)
        credential = admission.context["pins"]["credential_profile"]
        if (original_grant is None or credential is None or original_grant.event_type != "credential.grant.issued"
            or original_grant.actor_id != admission.worker_id or original_grant.entity_type != "collector_run"
            or original_grant.entity_id != admission.run_id or original_grant.details.get("profile_id") != credential["profile_id"]
            or original_grant.details.get("profile_revision") != credential["profile_revision"]):
            raise ValueError("Collector condition original credential grant is unavailable or changed")
    # Recognize a retired generation using only its retained sealed material,
    # before requiring the old deployment/credential/Worker to be current.
    sealed_pins = admission.context["pins"]
    sealed_definition = CollectorConditionDefinition.model_validate(sealed_pins["definition"])
    sealed_credential = sealed_pins["credential_profile"]
    sealed_context = {key: sealed_pins[key] for key in ("definition", "version_content_hash", "version_material",
        "assignment_sha256", "deployment", "credential_profile", "entity")}
    sealed_predicates = dict(tenant_id=admission.tenant_id, region_id=admission.region_id,
        deployment_id=admission.deployment_id, artifact_version_id=admission.artifact_version_id,
        assignment_sha256=sealed_pins["assignment_sha256"],
        credential_identity="none" if sealed_credential is None else f'{sealed_credential["profile_id"]}:{sealed_credential["profile_revision"]}',
        condition_key=sealed_definition.key, entity_type=sealed_pins["entity"]["type"], entity_id=sealed_pins["entity"]["id"])
    if (sealed_pins["deployment"]["id"] != admission.deployment_id
        or sealed_pins["deployment"]["artifact_version_id"] != admission.artifact_version_id
        or sealed_pins["worker"]["id"] != admission.worker_id
        or run.deployment_id != admission.deployment_id or run.artifact_version_id != admission.artifact_version_id
        or run.worker_id != admission.worker_id or sealed_definition.key != observation.condition_key
        or sealed_definition.entity_type != sealed_pins["entity"]["type"]
        or (observation.entity_id is not None and observation.entity_id != sealed_pins["entity"]["id"])):
        raise ValueError("Collector condition sealed source identity is invalid")
    from .source_retirements import retirement_for_source
    existing_source = db.scalar(select(CollectorConditionSource).filter_by(**sealed_predicates))
    if existing_source and retirement_for_source(db, existing_source.id, namespace=(admission.tenant_id, admission.region_id)):
        source = db.scalar(select(CollectorConditionSource).filter_by(**sealed_predicates)
            .with_for_update().execution_options(populate_existing=True))
        retirement = retirement_for_source(db, source.id, namespace=(admission.tenant_id, admission.region_id))
        if retirement is None or canonical(source.context) != canonical(sealed_context):
            raise ValueError("Retired Collector source provenance is unavailable or changed")
        return _retired_receipt(db, source, admission, observation, sealed_definition, retirement)
    pins, definition, _grant = _snapshot(db, run, observation, accepted_context=admission.context)
    if run.deployment_id != admission.deployment_id or run.artifact_version_id != admission.artifact_version_id or run.worker_id != admission.worker_id:
        raise ValueError("Collector condition accepted run ownership has drifted")
    identity = pins["entity"]
    credential = pins["credential_profile"]
    credential_identity = "none" if credential is None else f'{credential["profile_id"]}:{credential["profile_revision"]}'
    source_context = {key: pins[key] for key in ("definition", "version_content_hash", "version_material",
        "assignment_sha256", "deployment", "credential_profile", "entity")}
    predicates = dict(tenant_id=admission.tenant_id, region_id=admission.region_id,
        deployment_id=admission.deployment_id, artifact_version_id=admission.artifact_version_id,
        assignment_sha256=pins["assignment_sha256"], credential_identity=credential_identity,
        condition_key=definition.key, entity_type=identity["type"], entity_id=identity["id"])
    if db.get_bind().dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif db.get_bind().dialect.name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise ValueError("Collector condition projection requires PostgreSQL or SQLite")
    source_id = new_id()
    db.execute(insert(CollectorConditionSource).values(**predicates, id=source_id,
        dedup_key=PREFIX+source_id, context=source_context, created_at=utcnow()).on_conflict_do_nothing(
            index_elements=list(predicates)))
    source = db.scalar(select(CollectorConditionSource).filter_by(**predicates)
        .with_for_update().execution_options(populate_existing=True))
    if source is None or canonical(source.context) != canonical(source_context):
        raise ValueError("Collector condition source generation has drifted")
    # Recheck AFTER the conflicting source mutex; a pre-lock lookup is not a
    # snapshot fence. Native receipt writers acquire the same mutex too.
    retirement = retirement_for_source(db, source.id, namespace=(admission.tenant_id, admission.region_id))
    if retirement is not None:
        return _retired_receipt(db, source, admission, observation, definition, retirement)
    key = source.dedup_key
    state = lock_condition(db, key)
    source_identity = definition.event_type, definition.entity_type, identity["id"], None
    if state.event_type is not None:
        pin_identity(state, source_identity)
    active = evaluate_condition(definition, observation)
    if utcnow()-as_utc(admission.observed_at) > timedelta(seconds=definition.max_age_seconds):
        active = None
    verdict = "unknown" if active is None else "active" if active else "quiet"
    disposition = observation_disposition(state, admission.observed_at, active=active)
    same_time = db.scalar(select(CollectorConditionReceipt).where(CollectorConditionReceipt.source_id == source.id,
        CollectorConditionReceipt.observed_at == admission.observed_at).order_by(CollectorConditionReceipt.created_at).limit(1))
    if same_time is not None:
        old_admission = db.get(CollectorConditionAdmission, same_time.admission_id)
        if old_admission is None:
            raise ValueError("Collector condition comparison history is unavailable")
        if disposition != "stale":
            if old_admission.payload != admission.payload:
                disposition = "conflict"
            elif state.state != "conflict":
                disposition = "duplicate"
                verdict = same_time.verdict
                active = None if verdict == "unknown" else verdict == "active"
    with collector_condition_writer(db, key):
        if disposition == "conflict":
            alert = latest_alert(db, state)
            pin_identity(state, source_identity)
            # Existing conflict is a retry, not another mutable watermark write.
            if state.state != "conflict":
                record_observation(state, admission.observed_at, active=active, disposition="conflict", alert=alert)
                db.flush()
        elif active is True:
            alert = upsert_alert(db, dedup_key=key, event_type=definition.event_type,
                severity=definition.severity, title=definition.title, description="Versioned collector condition observation",
                entity_type=definition.entity_type, entity_id=identity["id"], observed_at=admission.observed_at,
                details={"measurement": observation.value, "unit": definition.unit, "quality": observation.quality,
                    "source_id": source.id, "admission_id": admission.id, "independently_verified": False,
                    "authorizes_incident_closure": False})
        elif active is False:
            alert = resolve_by_dedup_key(db, key, "iCheck collector condition evaluator", admission.observed_at,
                source_identity=source_identity)
            # A strictly newer quiet poll advances the condition even when no
            # open Alert remains. Keep the known episode pointer in its sealed
            # receipt; NULL is only appropriate before the first Alert exists.
            alert = alert or latest_alert(db, state)
        else:
            from .alert_conditions import observe_unknown_condition
            observe_unknown_condition(db, key, admission.observed_at, source_identity=source_identity)
            alert = latest_alert(db, state)
    receipt_id = new_id()
    result = {"contract": COLLECTOR_CONDITION_V1, "receipt_id": receipt_id, "admission_id": admission.id,
        "source_id": source.id, "verdict": verdict, "condition_state": state.state, "observation_disposition": disposition,
        "alert_id": alert.id if alert else None, "alert_status": alert.status.value if alert else None,
        "occurrence_count": alert.occurrence_count if alert else 0,
        "independently_verified": False, "authorizes_incident_closure": False}
    db.add(CollectorConditionReceipt(id=receipt_id, admission_id=admission.id, source_id=source.id,
        condition_state_id=state.id, alert_id=alert.id if alert else None, observed_at=admission.observed_at,
        verdict=verdict, disposition=disposition, result=result))
    db.flush()
    return result


def _retired_receipt(db, source, admission, observation, definition, retirement):
    from ..models import AlertConditionState
    state = db.scalar(select(AlertConditionState).where(AlertConditionState.tenant_id == source.tenant_id,
        AlertConditionState.region_id == source.region_id, AlertConditionState.dedup_key == source.dedup_key)
        .with_for_update().execution_options(populate_existing=True))
    if state is None or state.id != retirement.old_state_snapshot["id"]:
        raise ValueError("Retired Collector condition watermark is unavailable")
    alert = db.get(Alert, state.latest_alert_id) if state.latest_alert_id else None
    active = evaluate_condition(definition, observation)
    verdict = "unknown" if active is None else "active" if active else "quiet"
    receipt_id = new_id()
    result = {"contract": COLLECTOR_CONDITION_V1, "receipt_id": receipt_id, "admission_id": admission.id,
        "source_id": source.id, "verdict": verdict, "condition_state": state.state, "observation_disposition": "retired",
        "alert_id": state.latest_alert_id, "alert_status": alert.status.value if alert else None,
        "occurrence_count": alert.occurrence_count if alert else 0, "retirement_id": retirement.id,
        "source_retired": True, "independently_verified": False, "authorizes_incident_closure": False}
    db.add(CollectorConditionReceipt(id=receipt_id, admission_id=admission.id, source_id=source.id,
        condition_state_id=state.id, alert_id=state.latest_alert_id, observed_at=admission.observed_at,
        verdict=verdict, disposition="retired", result=result))
    db.flush()
    return result
