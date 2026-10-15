from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql.elements import ColumnElement

from ..models import (
    ArtifactVersion,
    CollectionEnvelope,
    CollectorDeployment,
    CollectorRun,
    Device,
    Endpoint,
    EndpointAttachment,
    EnvelopeKind,
    IPAddressObservation,
    KnowledgeEntity,
    KnowledgeProjection,
    KnowledgeProjectionStatus,
    KnowledgeProjectionWorker,
    KnowledgeProjectionWorkerState,
    KnowledgeRelationship,
    WirelessClientSession,
    utcnow,
)
from ..projection_schemas import (
    ALERT_EVENT_V1,
    DEVICE_ADJACENCY_SNAPSHOT_V1,
    KNOWLEDGE_ENTITY_V1,
    KNOWLEDGE_RELATIONSHIP_V1,
    NETWORK_OBSERVATION_V1,
    NETWORK_OBSERVATION_V2,
    SUPPORTED_PROJECTION_CONTRACTS,
    WIRELESS_SNAPSHOT_V1,
    AlertEventProjection,
    DeviceAdjacencySnapshotProjection,
    KnowledgeEntityProjection,
    KnowledgeEntityReference,
    KnowledgeRelationshipProjection,
    NetworkObservationProjection,
    NetworkObservationProjectionV2,
    ProjectionAssignment,
    ProjectionHealth,
    WirelessSnapshotProjection,
)
from ..schemas import NetworkObservationBatch
from ..network_binding_schemas import NetworkObservationBatchV2
from ..collector_condition_schemas import COLLECTOR_CONDITION_V1
from ..service_indicator_schemas import ArtifactIndicatorEnvelope
from .alerts import upsert_alert
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .inventory import ingest_network_observations, ingest_wireless_snapshot
from .indicator_artifacts import (
    ARTIFACT_INDICATOR_CONTRACT,
    publish_collector_indicator_envelope,
)


class ProjectionPermanentError(ValueError):
    """The immutable envelope cannot succeed without changing its content."""


class ProjectionLeaseLost(RuntimeError):
    """A stale worker must roll back all domain writes and leave the new lease intact."""


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def register_projection_worker(
    db: Session,
    *,
    name: str,
) -> KnowledgeProjectionWorker:
    normalized = name.strip()
    if not normalized:
        raise ValueError("Projection worker name is required")
    worker = db.scalar(
        select(KnowledgeProjectionWorker).where(
            KnowledgeProjectionWorker.name == normalized
        )
    )
    now = utcnow()
    if worker is None:
        worker = KnowledgeProjectionWorker(
            name=normalized,
            state=KnowledgeProjectionWorkerState.ONLINE,
            last_heartbeat_at=now,
        )
        db.add(worker)
    else:
        worker.state = KnowledgeProjectionWorkerState.ONLINE
        worker.last_heartbeat_at = now
    db.commit()
    db.refresh(worker)
    return worker


def heartbeat_projection_worker(
    db: Session,
    worker: KnowledgeProjectionWorker,
) -> KnowledgeProjectionWorker:
    worker.last_heartbeat_at = utcnow()
    if worker.state == KnowledgeProjectionWorkerState.OFFLINE:
        worker.state = KnowledgeProjectionWorkerState.ONLINE
    db.commit()
    db.refresh(worker)
    return worker


def claim_projections(
    db: Session,
    worker: KnowledgeProjectionWorker,
    *,
    limit: int,
    lease_seconds: int,
) -> list[ProjectionAssignment]:
    if worker.state != KnowledgeProjectionWorkerState.ONLINE:
        raise ValueError("Projection worker is not online")
    if not 1 <= limit <= 100:
        raise ValueError("Projection claim limit must be between 1 and 100")
    if not 15 <= lease_seconds <= 3600:
        raise ValueError("Projection lease must be between 15 and 3600 seconds")

    now = utcnow()
    worker.last_heartbeat_at = now
    ready = and_(
        KnowledgeProjection.status.in_(
            [
                KnowledgeProjectionStatus.PENDING,
                KnowledgeProjectionStatus.RETRY,
            ]
        ),
        KnowledgeProjection.next_attempt_at <= now,
    )
    abandoned = and_(
        KnowledgeProjection.status == KnowledgeProjectionStatus.PROCESSING,
        KnowledgeProjection.lease_expires_at.is_not(None),
        KnowledgeProjection.lease_expires_at <= now,
    )
    projections = list(
        db.scalars(
            select(KnowledgeProjection)
            .where(or_(ready, abandoned))
            .order_by(
                KnowledgeProjection.next_attempt_at,
                KnowledgeProjection.created_at,
                KnowledgeProjection.id,
            )
            .with_for_update(skip_locked=True)
            .limit(limit)
        ).all()
    )

    assignments: list[ProjectionAssignment] = []
    for projection in projections:
        if (
            projection.status == KnowledgeProjectionStatus.PROCESSING
            and projection.attempt_count >= projection.max_attempts
        ):
            message = "Projection lease expired at the maximum attempt count"
            projection.status = KnowledgeProjectionStatus.DEAD_LETTER
            projection.error_type = "ProjectionLeaseExpired"
            projection.error_sha256 = hashlib.sha256(
                message.encode("utf-8")
            ).hexdigest()
            projection.result_summary = {}
            projection.completed_at = now
            _clear_lease(projection)
            continue
        token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(seconds=lease_seconds)
        projection.status = KnowledgeProjectionStatus.PROCESSING
        projection.attempt_count += 1
        projection.lease_worker_id = worker.id
        projection.lease_token_hash = _token_hash(token)
        projection.lease_expires_at = expires_at
        projection.completed_at = None
        assignments.append(
            ProjectionAssignment(
                projection_id=projection.id,
                envelope_id=projection.envelope_id,
                lease_token=token,
                lease_expires_at=expires_at,
            )
        )
    db.commit()
    return assignments


def _active_projection(
    db: Session,
    assignment: ProjectionAssignment,
    worker: KnowledgeProjectionWorker,
) -> KnowledgeProjection:
    projection = db.scalar(
        select(KnowledgeProjection)
        .where(KnowledgeProjection.id == assignment.projection_id)
        .options(
            selectinload(KnowledgeProjection.envelope)
            .selectinload(CollectionEnvelope.run)
            .selectinload(CollectorRun.deployment)
        )
    )
    if projection is None:
        raise LookupError("Knowledge projection not found")
    if projection.status != KnowledgeProjectionStatus.PROCESSING:
        raise ValueError("Knowledge projection is not processing")
    if projection.lease_worker_id != worker.id:
        raise ValueError("Knowledge projection belongs to another worker")
    if not projection.lease_token_hash or not hmac.compare_digest(
        projection.lease_token_hash,
        _token_hash(assignment.lease_token),
    ):
        raise ValueError("Knowledge projection lease token is invalid")
    if (
        projection.lease_expires_at is None
        or _as_utc(projection.lease_expires_at) <= utcnow()
    ):
        raise ValueError("Knowledge projection lease expired")
    if projection.envelope.id != assignment.envelope_id:
        raise ValueError("Knowledge projection envelope binding changed")
    return projection


def _device_in_scope(
    db: Session,
    deployment: CollectorDeployment,
    device_id: str,
) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise LookupError("Referenced projection device was not found")
    if (
        deployment.scope_device_id is not None
        and deployment.scope_device_id != device.id
    ):
        raise ProjectionPermanentError(
            "Projection device exceeds the deployment device scope"
        )
    if deployment.scope_site is not None and deployment.scope_site != device.site:
        raise ProjectionPermanentError(
            "Projection device exceeds the deployment site scope"
        )
    return device


def _endpoint_in_scope(
    db: Session,
    deployment: CollectorDeployment,
    endpoint_id: str,
) -> Endpoint:
    endpoint = db.get(Endpoint, endpoint_id)
    if endpoint is None:
        raise LookupError("Referenced projection endpoint was not found")
    if deployment.scope_device_id is None and deployment.scope_site is None:
        return endpoint

    if deployment.scope_device_id is not None:
        device_ids = {deployment.scope_device_id}
    else:
        device_ids = set(
            db.scalars(
                select(Device.id).where(Device.site == deployment.scope_site)
            ).all()
        )
    if not device_ids:
        raise ProjectionPermanentError(
            "Projection endpoint has no devices inside the deployment scope"
        )
    linked = any(
        (
            db.scalar(
                select(func.count())
                .select_from(model)
                .where(
                    model.endpoint_id == endpoint.id,
                    collector_column.in_(device_ids),
                )
            )
            or 0
        )
        > 0
        for model, collector_column in (
            (IPAddressObservation, IPAddressObservation.collector_device_id),
            (EndpointAttachment, EndpointAttachment.collector_device_id),
            (WirelessClientSession, WirelessClientSession.controller_id),
        )
    )
    if not linked:
        raise ProjectionPermanentError(
            "Projection endpoint exceeds the deployment scope"
        )
    return endpoint


def _generic_projection_identity(
    db: Session,
    deployment: CollectorDeployment,
) -> tuple[str, str, str | None, str | None]:
    version = db.get(ArtifactVersion, deployment.artifact_version_id)
    if version is None:
        raise LookupError("Projection Artifact version was not found")
    if deployment.scope_device_id is not None:
        _device_in_scope(db, deployment, deployment.scope_device_id)
        scope_key = f"device:{deployment.scope_device_id}"
    elif deployment.scope_site is not None:
        scope_key = f"site:{deployment.scope_site}"
    else:
        raise ProjectionPermanentError(
            "Generic knowledge projection requires device or site deployment scope"
        )
    return (
        f"artifact:{version.artifact_id}",
        scope_key,
        deployment.scope_device_id,
        deployment.scope_site,
    )


def _newer_observation(
    *,
    observed_at: datetime,
    envelope_id: str,
    current_observed_at: datetime,
    current_envelope_id: str | None,
) -> bool:
    observed = _as_utc(observed_at)
    current = _as_utc(current_observed_at)
    return observed > current or (
        observed == current
        and (current_envelope_id is None or envelope_id > current_envelope_id)
    )


def _upsert_knowledge_entity(
    db: Session,
    *,
    namespace: str,
    scope_key: str,
    scope_device_id: str | None,
    scope_site: str | None,
    reference: KnowledgeEntityReference,
    envelope: CollectionEnvelope,
    authoritative: KnowledgeEntityProjection | None = None,
) -> tuple[KnowledgeEntity, bool, bool]:
    entity = db.scalar(
        select(KnowledgeEntity).where(
            KnowledgeEntity.namespace == namespace,
            KnowledgeEntity.scope_key == scope_key,
            KnowledgeEntity.entity_type == reference.entity_type,
            KnowledgeEntity.external_key == reference.external_key,
        )
    )
    if entity is None:
        entity = KnowledgeEntity(
            namespace=namespace,
            scope_key=scope_key,
            scope_device_id=scope_device_id,
            scope_site=scope_site,
            entity_type=reference.entity_type,
            external_key=reference.external_key,
            display_name=reference.display_name or reference.external_key,
            status=authoritative.status if authoritative else None,
            active=authoritative.active if authoritative else True,
            attributes=authoritative.attributes if authoritative else {},
            first_seen=envelope.observed_at,
            last_seen=envelope.observed_at,
            observed_at=envelope.observed_at,
            last_envelope_id=envelope.id if authoritative else None,
        )
        db.add(entity)
        db.flush()
        return entity, True, True

    if _as_utc(envelope.observed_at) < _as_utc(entity.first_seen):
        entity.first_seen = envelope.observed_at
    if _as_utc(envelope.observed_at) > _as_utc(entity.last_seen):
        entity.last_seen = envelope.observed_at
    updated = False
    if authoritative is not None and _newer_observation(
        observed_at=envelope.observed_at,
        envelope_id=envelope.id,
        current_observed_at=entity.observed_at,
        current_envelope_id=entity.last_envelope_id,
    ):
        entity.display_name = authoritative.display_name or authoritative.external_key
        entity.status = authoritative.status
        entity.active = authoritative.active
        entity.attributes = authoritative.attributes
        entity.observed_at = envelope.observed_at
        entity.last_envelope_id = envelope.id
        updated = True
    db.flush()
    return entity, False, updated


def _project_knowledge_entity(
    db: Session,
    envelope: CollectionEnvelope,
    deployment: CollectorDeployment,
) -> dict[str, Any]:
    payload = KnowledgeEntityProjection.model_validate(envelope.payload)
    namespace, scope_key, scope_device_id, scope_site = (
        _generic_projection_identity(db, deployment)
    )
    entity, created, updated = _upsert_knowledge_entity(
        db,
        namespace=namespace,
        scope_key=scope_key,
        scope_device_id=scope_device_id,
        scope_site=scope_site,
        reference=payload,
        envelope=envelope,
        authoritative=payload,
    )
    return {
        "contract": KNOWLEDGE_ENTITY_V1,
        "entity_id": entity.id,
        "entity_type": entity.entity_type,
        "created": created,
        "updated": updated,
    }


def _project_knowledge_relationship(
    db: Session,
    envelope: CollectionEnvelope,
    deployment: CollectorDeployment,
) -> dict[str, Any]:
    payload = KnowledgeRelationshipProjection.model_validate(envelope.payload)
    namespace, scope_key, scope_device_id, scope_site = (
        _generic_projection_identity(db, deployment)
    )
    source, source_created, _ = _upsert_knowledge_entity(
        db,
        namespace=namespace,
        scope_key=scope_key,
        scope_device_id=scope_device_id,
        scope_site=scope_site,
        reference=payload.source,
        envelope=envelope,
    )
    target, target_created, _ = _upsert_knowledge_entity(
        db,
        namespace=namespace,
        scope_key=scope_key,
        scope_device_id=scope_device_id,
        scope_site=scope_site,
        reference=payload.target,
        envelope=envelope,
    )
    relationship, created, updated = _upsert_knowledge_relationship_record(
        db,
        namespace=namespace,
        scope_key=scope_key,
        scope_device_id=scope_device_id,
        scope_site=scope_site,
        payload=payload,
        source=source,
        target=target,
        envelope=envelope,
    )
    return {
        "contract": KNOWLEDGE_RELATIONSHIP_V1,
        "relationship_id": relationship.id,
        "relationship_type": relationship.relationship_type,
        "source_entity_id": relationship.source_entity_id,
        "target_entity_id": relationship.target_entity_id,
        "entities_created": int(source_created) + int(target_created),
        "created": created,
        "updated": updated,
    }


def _upsert_knowledge_relationship_record(
    db: Session,
    *,
    namespace: str,
    scope_key: str,
    scope_device_id: str | None,
    scope_site: str | None,
    payload: KnowledgeRelationshipProjection,
    source: KnowledgeEntity,
    target: KnowledgeEntity,
    envelope: CollectionEnvelope,
) -> tuple[KnowledgeRelationship, bool, bool]:
    source_id, target_id = source.id, target.id
    if not payload.directed and source_id > target_id:
        source_id, target_id = target_id, source_id
    relationship = db.scalar(
        select(KnowledgeRelationship).where(
            KnowledgeRelationship.namespace == namespace,
            KnowledgeRelationship.scope_key == scope_key,
            KnowledgeRelationship.relationship_type == payload.relationship_type,
            KnowledgeRelationship.source_entity_id == source_id,
            KnowledgeRelationship.target_entity_id == target_id,
            KnowledgeRelationship.directed.is_(payload.directed),
        )
    )
    created = relationship is None
    updated = False
    if relationship is None:
        relationship = KnowledgeRelationship(
            namespace=namespace,
            scope_key=scope_key,
            scope_device_id=scope_device_id,
            scope_site=scope_site,
            relationship_type=payload.relationship_type,
            source_entity_id=source_id,
            target_entity_id=target_id,
            directed=payload.directed,
            active=payload.active,
            attributes=payload.attributes,
            first_seen=envelope.observed_at,
            last_seen=envelope.observed_at,
            observed_at=envelope.observed_at,
            last_envelope_id=envelope.id,
        )
        db.add(relationship)
        updated = True
    else:
        if _as_utc(envelope.observed_at) < _as_utc(relationship.first_seen):
            relationship.first_seen = envelope.observed_at
        if _as_utc(envelope.observed_at) > _as_utc(relationship.last_seen):
            relationship.last_seen = envelope.observed_at
        if _newer_observation(
            observed_at=envelope.observed_at,
            envelope_id=envelope.id,
            current_observed_at=relationship.observed_at,
            current_envelope_id=relationship.last_envelope_id,
        ):
            relationship.active = payload.active
            relationship.attributes = payload.attributes
            relationship.observed_at = envelope.observed_at
            relationship.last_envelope_id = envelope.id
            updated = True
    db.flush()
    return relationship, created, updated


def _project_device_adjacency_snapshot(
    db: Session,
    envelope: CollectionEnvelope,
    deployment: CollectorDeployment,
) -> dict[str, Any]:
    payload = DeviceAdjacencySnapshotProjection.model_validate(envelope.payload)
    namespace, scope_key, scope_device_id, scope_site = (
        _generic_projection_identity(db, deployment)
    )
    local_projection = KnowledgeEntityProjection(
        entity_type="network.device",
        external_key=payload.local_device_key,
        display_name=payload.local_display_name or payload.local_device_key,
        status="observed",
        active=True,
        attributes={"role": "local"},
    )
    local, local_created, _ = _upsert_knowledge_entity(
        db,
        namespace=namespace,
        scope_key=scope_key,
        scope_device_id=scope_device_id,
        scope_site=scope_site,
        reference=local_projection,
        envelope=envelope,
        authoritative=local_projection,
    )
    grouped: dict[str, dict[str, Any]] = {}
    for neighbor in payload.neighbors:
        group = grouped.setdefault(
            neighbor.remote_device_key,
            {
                "display_name": (
                    neighbor.remote_system_name or neighbor.remote_device_key
                ),
                "management_ip": neighbor.management_ip,
                "links": [],
            },
        )
        group["links"].append(
            {
                "local_port": neighbor.local_port,
                "remote_port": neighbor.remote_port,
            }
        )

    relationship_type = f"network.l2_neighbor.{payload.protocol}"
    current_relationship_ids: set[str] = set()
    entities_created = int(local_created)
    relationships_created = 0
    relationships_updated = 0
    for remote_key in sorted(grouped):
        group = grouped[remote_key]
        attributes = (
            {"management_ip": group["management_ip"]}
            if group["management_ip"] is not None
            else {}
        )
        remote_projection = KnowledgeEntityProjection(
            entity_type="network.device",
            external_key=remote_key,
            display_name=group["display_name"],
            status="observed",
            active=True,
            attributes=attributes,
        )
        remote, remote_created, _ = _upsert_knowledge_entity(
            db,
            namespace=namespace,
            scope_key=scope_key,
            scope_device_id=scope_device_id,
            scope_site=scope_site,
            reference=remote_projection,
            envelope=envelope,
            authoritative=remote_projection,
        )
        entities_created += int(remote_created)
        relationship_payload = KnowledgeRelationshipProjection(
            relationship_type=relationship_type,
            source=local_projection,
            target=remote_projection,
            directed=False,
            active=True,
            attributes={
                "protocol": payload.protocol,
                "links": sorted(
                    group["links"],
                    key=lambda item: (item["local_port"], item["remote_port"]),
                ),
            },
        )
        relationship, created, updated = _upsert_knowledge_relationship_record(
            db,
            namespace=namespace,
            scope_key=scope_key,
            scope_device_id=scope_device_id,
            scope_site=scope_site,
            payload=relationship_payload,
            source=local,
            target=remote,
            envelope=envelope,
        )
        current_relationship_ids.add(relationship.id)
        relationships_created += int(created)
        relationships_updated += int(updated)

    relationships_closed = 0
    inactive_entity_ids: set[str] = set()
    if payload.complete_snapshot:
        existing = db.scalars(
            select(KnowledgeRelationship).where(
                KnowledgeRelationship.namespace == namespace,
                KnowledgeRelationship.scope_key == scope_key,
                KnowledgeRelationship.relationship_type == relationship_type,
                KnowledgeRelationship.active.is_(True),
                or_(
                    KnowledgeRelationship.source_entity_id == local.id,
                    KnowledgeRelationship.target_entity_id == local.id,
                ),
            )
        ).all()
        for relationship in existing:
            if relationship.id in current_relationship_ids:
                continue
            if not _newer_observation(
                observed_at=envelope.observed_at,
                envelope_id=envelope.id,
                current_observed_at=relationship.observed_at,
                current_envelope_id=relationship.last_envelope_id,
            ):
                continue
            relationship.active = False
            relationship.observed_at = envelope.observed_at
            relationship.last_envelope_id = envelope.id
            relationships_closed += 1
            inactive_entity_ids.add(
                relationship.target_entity_id
                if relationship.source_entity_id == local.id
                else relationship.source_entity_id
            )
        db.flush()

    entities_deactivated = 0
    for entity_id in inactive_entity_ids:
        active_relationships = db.scalar(
            select(func.count())
            .select_from(KnowledgeRelationship)
            .where(
                KnowledgeRelationship.namespace == namespace,
                KnowledgeRelationship.scope_key == scope_key,
                KnowledgeRelationship.active.is_(True),
                or_(
                    KnowledgeRelationship.source_entity_id == entity_id,
                    KnowledgeRelationship.target_entity_id == entity_id,
                ),
            )
        ) or 0
        entity = db.get(KnowledgeEntity, entity_id)
        if (
            active_relationships == 0
            and entity is not None
            and _newer_observation(
                observed_at=envelope.observed_at,
                envelope_id=envelope.id,
                current_observed_at=entity.observed_at,
                current_envelope_id=entity.last_envelope_id,
            )
        ):
            entity.active = False
            entity.status = "absent"
            entity.observed_at = envelope.observed_at
            entity.last_envelope_id = envelope.id
            entities_deactivated += 1
    db.flush()
    return {
        "contract": DEVICE_ADJACENCY_SNAPSHOT_V1,
        "protocol": payload.protocol,
        "complete_snapshot": payload.complete_snapshot,
        "neighbors_received": len(payload.neighbors),
        "relationships_received": len(grouped),
        "relationships_created": relationships_created,
        "relationships_updated": relationships_updated,
        "relationships_closed": relationships_closed,
        "entities_created": entities_created,
        "entities_deactivated": entities_deactivated,
    }


def _project_network(
    db: Session,
    envelope: CollectionEnvelope,
    deployment: CollectorDeployment,
) -> dict[str, Any]:
    deployment = db.scalar(select(CollectorDeployment).where(CollectorDeployment.id == deployment.id)
        .with_for_update().execution_options(populate_existing=True))
    if deployment is None or not deployment.enabled:
        raise ProjectionPermanentError("Network projection deployment is unavailable")
    is_v2 = envelope.type == NETWORK_OBSERVATION_V2
    payload_model = NetworkObservationProjectionV2 if is_v2 else NetworkObservationProjection
    payload = payload_model.model_validate(envelope.payload)
    collector_device_id = (
        payload.collector_device_id or deployment.scope_device_id
    )
    if deployment.scope_site is not None and collector_device_id is None:
        raise ProjectionPermanentError(
            "Site-scoped network projection requires collector_device_id"
        )
    if collector_device_id is not None:
        _device_in_scope(db, deployment, collector_device_id)
    observation = payload.to_domain(
        observed_at=envelope.observed_at,
        collector_device_id=collector_device_id,
    )
    result = ingest_network_observations(
        db,
        (NetworkObservationBatchV2 if is_v2 else NetworkObservationBatch)(observations=[observation]),
        commit=False,
    )
    if collector_device_id is not None:
        _device_in_scope(db, deployment, collector_device_id)
    if deployment.scope_device_id is not None:
        from .collectors import _deployment_device_identity_current
        if not _deployment_device_identity_current(db, deployment):
            raise ProjectionPermanentError("Network projection registered-device identity has drifted")
    return {
        "contract": envelope.type,
        "observations_received": result.observations_received,
        "endpoints_created": result.endpoints_created,
        "endpoints_updated": result.endpoints_updated,
        "ip_observations_written": result.ip_observations_written,
        "attachments_written": result.attachments_written,
        "alert_count": len(result.alert_ids),
        "network_dispositions": result.network_dispositions,
    }


def _project_wireless(
    db: Session,
    envelope: CollectionEnvelope,
    deployment: CollectorDeployment,
) -> dict[str, Any]:
    payload = WirelessSnapshotProjection.model_validate(envelope.payload)
    controller_id = payload.controller_id or deployment.scope_device_id
    if controller_id is None:
        raise ProjectionPermanentError(
            "Wireless projection requires controller_id or device scope"
        )
    _device_in_scope(db, deployment, controller_id)
    result = ingest_wireless_snapshot(
        db,
        payload.to_domain(
            observed_at=envelope.observed_at,
            controller_id=controller_id,
        ),
        commit=False,
    )
    # Ingestion refreshes and locks the controller after any wait. A concurrent
    # site move must still fit the current deployment scope before committing.
    _device_in_scope(db, deployment, controller_id)
    return {
        "contract": WIRELESS_SNAPSHOT_V1,
        "observations_received": result.observations_received,
        "endpoints_created": result.endpoints_created,
        "endpoints_updated": result.endpoints_updated,
        "ip_observations_written": result.ip_observations_written,
        "wireless_sessions_written": result.wireless_sessions_written,
        "sessions_closed": result.sessions_closed,
        "alert_count": len(result.alert_ids),
        "snapshot_disposition": result.snapshot_disposition,
    }


def _project_alert(
    db: Session,
    envelope: CollectionEnvelope,
    deployment: CollectorDeployment,
) -> dict[str, Any]:
    event = AlertEventProjection.model_validate(envelope.payload).to_domain(
        observed_at=envelope.observed_at,
        subject=envelope.subject,
    )
    if event.entity_type in {"device", "collector_device"}:
        _device_in_scope(db, deployment, event.entity_id)
    elif event.entity_type in {"endpoint", "terminal"}:
        _endpoint_in_scope(db, deployment, event.entity_id)
    elif deployment.scope_device_id is not None or deployment.scope_site is not None:
        raise ProjectionPermanentError(
            "Scoped projection cannot emit an unscoped Alert entity type"
        )
    alert = upsert_alert(
        db,
        dedup_key=event.dedup_key
        or (
            f"collector:{envelope.source}:{event.event_type}:"
            f"{event.entity_type}:{event.entity_id}"
        ),
        event_type=event.event_type,
        severity=event.severity,
        title=event.title,
        description=event.description,
        entity_type=event.entity_type,
        entity_id=event.entity_id,
        details=event.details,
        observed_at=event.observed_at,
    )
    db.flush()
    return {
        "contract": ALERT_EVENT_V1,
        "alert_id": alert.id if alert else None,
        "alert_status": alert.status.value if alert else None,
        "occurrence_count": alert.occurrence_count if alert else 0,
        "observation_disposition": getattr(alert, "_observation_disposition", "stale"),
    }


def _clear_lease(projection: KnowledgeProjection) -> None:
    projection.lease_worker_id = None
    projection.lease_token_hash = None
    projection.lease_expires_at = None


def _finish_projection(
    db: Session,
    projection: KnowledgeProjection,
    *,
    worker: KnowledgeProjectionWorker,
    assignment: ProjectionAssignment,
    status: KnowledgeProjectionStatus,
    result_summary: dict[str, Any],
) -> KnowledgeProjection:
    now = utcnow()
    result = db.execute(
        update(KnowledgeProjection)
        .where(
            KnowledgeProjection.id == projection.id,
            KnowledgeProjection.status == KnowledgeProjectionStatus.PROCESSING,
            KnowledgeProjection.lease_worker_id == worker.id,
            KnowledgeProjection.lease_token_hash
            == _token_hash(assignment.lease_token),
            KnowledgeProjection.lease_expires_at > now,
        )
        .values(
            status=status,
            result_summary=result_summary,
            error_type=None,
            error_sha256=None,
            completed_at=now,
            lease_worker_id=None,
            lease_token_hash=None,
            lease_expires_at=None,
            updated_at=now,
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        raise ProjectionLeaseLost(
            "Knowledge projection lease changed before commit"
        )
    db.commit()
    db.expire_all()
    refreshed = db.get(KnowledgeProjection, projection.id)
    if refreshed is None:
        raise LookupError("Knowledge projection disappeared after completion")
    return refreshed


def _record_projection_failure(
    db: Session,
    *,
    projection_id: str,
    worker_id: str,
    lease_token: str,
    permanent: bool,
    error: Exception,
) -> KnowledgeProjection:
    db.rollback()
    projection = db.get(KnowledgeProjection, projection_id)
    if projection is None:
        raise LookupError("Knowledge projection disappeared after failure")
    if (
        projection.status != KnowledgeProjectionStatus.PROCESSING
        or projection.lease_worker_id != worker_id
        or not projection.lease_token_hash
        or not hmac.compare_digest(
            projection.lease_token_hash,
            _token_hash(lease_token),
        )
        or projection.lease_expires_at is None
        or _as_utc(projection.lease_expires_at) <= utcnow()
    ):
        raise ProjectionLeaseLost(
            "Knowledge projection lease changed before failure commit"
        )
    message = str(error) or type(error).__name__
    projection.error_type = type(error).__name__[:255]
    projection.error_sha256 = hashlib.sha256(message.encode("utf-8")).hexdigest()
    projection.result_summary = {}
    projection.completed_at = utcnow() if permanent else None
    _clear_lease(projection)
    if permanent or projection.attempt_count >= projection.max_attempts:
        projection.status = KnowledgeProjectionStatus.DEAD_LETTER
        projection.completed_at = utcnow()
    else:
        projection.status = KnowledgeProjectionStatus.RETRY
        delay_seconds = min(300, 2 ** min(projection.attempt_count, 8))
        projection.next_attempt_at = utcnow() + timedelta(seconds=delay_seconds)
    db.commit()
    db.refresh(projection)
    return projection


def process_projection_assignment(
    db: Session,
    worker: KnowledgeProjectionWorker,
    assignment: ProjectionAssignment,
) -> KnowledgeProjection:
    projection = _active_projection(db, assignment, worker)
    envelope = projection.envelope
    deployment = envelope.run.deployment
    contract = (envelope.kind, envelope.type)
    if contract not in SUPPORTED_PROJECTION_CONTRACTS:
        return _finish_projection(
            db,
            projection,
            worker=worker,
            assignment=assignment,
            status=KnowledgeProjectionStatus.IGNORED,
            result_summary={
                "reason": "unsupported_contract",
                "envelope_kind": envelope.kind.value,
                "envelope_type": envelope.type,
            },
        )

    try:
        assert_no_inline_secrets(
            envelope.payload,
            f"collection_envelope.{envelope.id}.payload",
        )
        if envelope.type == KNOWLEDGE_ENTITY_V1:
            summary = _project_knowledge_entity(db, envelope, deployment)
        elif envelope.type == COLLECTOR_CONDITION_V1:
            from .collector_conditions import project_condition
            summary = project_condition(db, envelope)
        elif envelope.type == KNOWLEDGE_RELATIONSHIP_V1:
            summary = _project_knowledge_relationship(db, envelope, deployment)
        elif envelope.type == DEVICE_ADJACENCY_SNAPSHOT_V1:
            summary = _project_device_adjacency_snapshot(db, envelope, deployment)
        elif envelope.type in {NETWORK_OBSERVATION_V1, NETWORK_OBSERVATION_V2}:
            summary = _project_network(db, envelope, deployment)
        elif envelope.type == WIRELESS_SNAPSHOT_V1:
            summary = _project_wireless(db, envelope, deployment)
        elif envelope.type == ARTIFACT_INDICATOR_CONTRACT:
            publication, observation_id = publish_collector_indicator_envelope(
                db,
                envelope,
                deployment,
                ArtifactIndicatorEnvelope.model_validate(envelope.payload),
            )
            summary = {
                "contract_version": ARTIFACT_INDICATOR_CONTRACT,
                "publication_id": publication.id,
                "observation_id": observation_id,
            }
        else:
            summary = _project_alert(db, envelope, deployment)
        return _finish_projection(
            db,
            projection,
            worker=worker,
            assignment=assignment,
            status=KnowledgeProjectionStatus.SUCCEEDED,
            result_summary=summary,
        )
    except ProjectionLeaseLost:
        db.rollback()
        raise
    except (ProjectionPermanentError, ValidationError, ValueError) as exc:
        return _record_projection_failure(
            db,
            projection_id=projection.id,
            worker_id=worker.id,
            lease_token=assignment.lease_token,
            permanent=True,
            error=exc,
        )
    except Exception as exc:
        return _record_projection_failure(
            db,
            projection_id=projection.id,
            worker_id=worker.id,
            lease_token=assignment.lease_token,
            permanent=False,
            error=exc,
        )


def retry_projection(
    db: Session,
    projection: KnowledgeProjection,
    *,
    actor: str,
    reason: str,
) -> KnowledgeProjection:
    if projection.status not in {
        KnowledgeProjectionStatus.DEAD_LETTER,
        KnowledgeProjectionStatus.IGNORED,
    }:
        raise ValueError("Only ignored or dead-letter projections can be retried")
    assert_no_inline_secrets(reason, "projection retry reason")
    previous_status = projection.status.value
    projection.status = KnowledgeProjectionStatus.PENDING
    projection.attempt_count = 0
    projection.next_attempt_at = utcnow()
    projection.completed_at = None
    projection.result_summary = {}
    projection.error_type = None
    projection.error_sha256 = None
    _clear_lease(projection)
    record_audit_event(
        db,
        event_type="knowledge_projection.retried",
        actor_type="user",
        actor_id=actor,
        entity_type="knowledge_projection",
        entity_id=projection.id,
        details={
            "previous_status": previous_status,
            "reason": reason,
            "envelope_id": projection.envelope_id,
        },
    )
    db.commit()
    db.refresh(projection)
    return projection


def projection_to_dict(projection: KnowledgeProjection) -> dict[str, Any]:
    envelope = projection.envelope
    return {
        "id": projection.id,
        "envelope_id": projection.envelope_id,
        "envelope_kind": envelope.kind,
        "envelope_type": envelope.type,
        "envelope_source": envelope.source,
        "envelope_subject": envelope.subject,
        "envelope_observed_at": envelope.observed_at,
        "status": projection.status,
        "attempt_count": projection.attempt_count,
        "max_attempts": projection.max_attempts,
        "next_attempt_at": projection.next_attempt_at,
        "lease_worker_id": projection.lease_worker_id,
        "lease_expires_at": projection.lease_expires_at,
        "result_summary": projection.result_summary,
        "error_type": projection.error_type,
        "error_sha256": projection.error_sha256,
        "completed_at": projection.completed_at,
        "created_at": projection.created_at,
        "updated_at": projection.updated_at,
    }


def projection_scope_query(
    deployment_scope: ColumnElement[bool] | None = None,
):
    query = (
        select(KnowledgeProjection)
        .join(KnowledgeProjection.envelope)
        .join(CollectionEnvelope.run)
        .join(CollectorRun.deployment)
        .options(selectinload(KnowledgeProjection.envelope))
    )
    if deployment_scope is not None:
        query = query.where(deployment_scope)
    return query


def projection_health(
    db: Session,
    *,
    deployment_scope: ColumnElement[bool] | None = None,
) -> ProjectionHealth:
    now = utcnow()
    base = (
        select(KnowledgeProjection.status, func.count(KnowledgeProjection.id))
        .join(KnowledgeProjection.envelope)
        .join(CollectionEnvelope.run)
        .join(CollectorRun.deployment)
    )
    if deployment_scope is not None:
        base = base.where(deployment_scope)
    counts = {
        status: count
        for status, count in db.execute(
            base.group_by(KnowledgeProjection.status)
        ).all()
    }

    oldest_query = (
        select(func.min(KnowledgeProjection.next_attempt_at))
        .join(KnowledgeProjection.envelope)
        .join(CollectionEnvelope.run)
        .join(CollectorRun.deployment)
        .where(
            KnowledgeProjection.status.in_(
                [
                    KnowledgeProjectionStatus.PENDING,
                    KnowledgeProjectionStatus.RETRY,
                ]
            ),
            KnowledgeProjection.next_attempt_at <= now,
        )
    )
    completed_query = (
        select(func.count(KnowledgeProjection.id))
        .join(KnowledgeProjection.envelope)
        .join(CollectionEnvelope.run)
        .join(CollectorRun.deployment)
        .where(
            KnowledgeProjection.status.in_(
                [
                    KnowledgeProjectionStatus.SUCCEEDED,
                    KnowledgeProjectionStatus.IGNORED,
                ]
            ),
            KnowledgeProjection.completed_at >= now - timedelta(hours=1),
        )
    )
    if deployment_scope is not None:
        oldest_query = oldest_query.where(deployment_scope)
        completed_query = completed_query.where(deployment_scope)
    oldest = db.scalar(oldest_query)
    stale_before = now - timedelta(seconds=90)
    workers_total = db.scalar(
        select(func.count()).select_from(KnowledgeProjectionWorker)
    ) or 0
    workers_online = db.scalar(
        select(func.count())
        .select_from(KnowledgeProjectionWorker)
        .where(
            KnowledgeProjectionWorker.state
            == KnowledgeProjectionWorkerState.ONLINE,
            KnowledgeProjectionWorker.last_heartbeat_at >= stale_before,
        )
    ) or 0
    workers_stale = db.scalar(
        select(func.count())
        .select_from(KnowledgeProjectionWorker)
        .where(
            or_(
                KnowledgeProjectionWorker.state
                != KnowledgeProjectionWorkerState.ONLINE,
                KnowledgeProjectionWorker.last_heartbeat_at < stale_before,
            )
        )
    ) or 0
    oldest_age = (
        max(0.0, (now - _as_utc(oldest)).total_seconds())
        if oldest is not None
        else None
    )
    return ProjectionHealth(
        workers_total=workers_total,
        workers_online=workers_online,
        workers_stale=workers_stale,
        pending=counts.get(KnowledgeProjectionStatus.PENDING, 0),
        processing=counts.get(KnowledgeProjectionStatus.PROCESSING, 0),
        retry=counts.get(KnowledgeProjectionStatus.RETRY, 0),
        succeeded=counts.get(KnowledgeProjectionStatus.SUCCEEDED, 0),
        ignored=counts.get(KnowledgeProjectionStatus.IGNORED, 0),
        dead_letter=counts.get(KnowledgeProjectionStatus.DEAD_LETTER, 0),
        oldest_ready_age_seconds=oldest_age,
        completed_last_hour=db.scalar(completed_query) or 0,
    )
