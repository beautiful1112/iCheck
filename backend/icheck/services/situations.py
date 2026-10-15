from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.orm import Session, aliased

from ..database import require_locking_transaction
from ..models import (
    Alert,
    AlertSeverity,
    AlertStatus,
    EndpointAttachment,
    Investigation,
    KnowledgeEntity,
    KnowledgeRelationship,
    ServiceCatalogComponent,
    ServiceCatalogEntry,
    Situation,
    SituationAlert,
    SituationEvent,
    SituationStatus,
    WirelessClientSession,
    utcnow,
)
from .audit import record_audit_event

if TYPE_CHECKING:
    from ..auth import PrincipalContext


CORRELATION_VERSION = "same_entity/v1"
EVIDENCE_CORRELATION_VERSION = "reviewed_service/v2"
TOPOLOGY_CORRELATION_VERSION = "qualified_topology/v3"
CROSS_ENTITY_WINDOW = timedelta(minutes=15)
CROSS_ENTITY_CONFIDENCE = 0.85
TOPOLOGY_CORRELATION_CONFIDENCE = 0.70
TOPOLOGY_EVIDENCE_MAX_AGE = timedelta(minutes=15)
TOPOLOGY_EVIDENCE_FUTURE_SKEW = timedelta(minutes=5)
MAX_CORRELATION_SERVICES = 32
MAX_CORRELATION_CANDIDATE_ROWS = 128
MAX_TOPOLOGY_EVIDENCE_ROWS = 128
MAX_CROSS_ENTITY_ALERTS = 100
TOPOLOGY_RELATIONSHIP_TYPES = {
    "network.link",
    "network.l2_neighbor.cdp",
    "network.l2_neighbor.lldp",
}
DEVICE_ENTITY_TYPES = {"device", "collector_device"}
ENDPOINT_ENTITY_TYPES = {"endpoint", "terminal"}
SEVERITY_RANK = {
    AlertSeverity.INFO: 10,
    AlertSeverity.WARNING: 50,
    AlertSeverity.CRITICAL: 100,
}


@dataclass(frozen=True)
class _TopologyEvidence:
    evidence_type: str
    evidence_id: str
    relationship_type: str
    neighbor_node_type: str
    neighbor_entity_id: str
    observed_at: datetime
    last_envelope_id: str | None = None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def situation_correlation_key(entity_type: str, entity_id: str) -> str:
    document = {
        "correlation_version": CORRELATION_VERSION,
        "entity_type": entity_type,
        "entity_id": entity_id,
    }
    return hashlib.sha256(
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _advisory_lock(db: Session, correlation_key: str) -> None:
    bind = db.get_bind()
    if bind.dialect.name != "postgresql":
        return
    lock_id = int(correlation_key[:16], 16)
    if lock_id >= 2**63:
        lock_id -= 2**64
    db.execute(select(func.pg_advisory_xact_lock(lock_id)))


def _advisory_lock_token(db: Session, token: str) -> None:
    _advisory_lock(db, hashlib.sha256(token.encode("utf-8")).hexdigest())


def _component_node_type(entity_type: str) -> str | None:
    if entity_type in DEVICE_ENTITY_TYPES:
        return "device"
    if entity_type in ENDPOINT_ENTITY_TYPES:
        return "endpoint"
    if entity_type == "knowledge_entity":
        return "knowledge_entity"
    return None


def _same_entity_clause(alert: Alert):
    node_type = _component_node_type(alert.entity_type)
    if node_type == "device":
        entity_types = DEVICE_ENTITY_TYPES
    elif node_type == "endpoint":
        entity_types = ENDPOINT_ENTITY_TYPES
    else:
        entity_types = {alert.entity_type}
    return and_(
        Alert.entity_type.in_(entity_types),
        Alert.entity_id == alert.entity_id,
    )


def _correlation_service_bindings(
    db: Session,
    alert: Alert,
) -> list[tuple[ServiceCatalogComponent, ServiceCatalogEntry]]:
    node_type = _component_node_type(alert.entity_type)
    if node_type is None:
        return []
    rows = list(
        db.execute(
            select(ServiceCatalogComponent, ServiceCatalogEntry)
            .join(
                ServiceCatalogEntry,
                ServiceCatalogEntry.id == ServiceCatalogComponent.service_id,
            )
            .where(
                ServiceCatalogComponent.node_type == node_type,
                ServiceCatalogComponent.entity_id == alert.entity_id,
                ServiceCatalogComponent.required.is_(True),
                ServiceCatalogEntry.status == "active",
            )
            .order_by(
                ServiceCatalogEntry.criticality,
                ServiceCatalogEntry.service_key,
                ServiceCatalogComponent.id,
            )
            .with_for_update()
            .limit(MAX_CORRELATION_SERVICES + 1)
        ).all()
    )
    if len(rows) > MAX_CORRELATION_SERVICES:
        return []
    return rows


def _active_same_entity_situation(
    db: Session,
    alert: Alert,
) -> Situation | None:
    return db.scalar(
        select(Situation)
        .join(SituationAlert, SituationAlert.situation_id == Situation.id)
        .join(Alert, Alert.id == SituationAlert.alert_id)
        .where(
            Situation.status != SituationStatus.RESOLVED.value,
            _same_entity_clause(alert),
        )
        .order_by(Situation.created_at, Situation.id)
        # Other source writers already own their own Alert row. Locking joined
        # Alert/member rows here would invert the source -> parent lock order.
        .with_for_update(of=Situation)
        .execution_options(populate_existing=True)
        .limit(1)
    )


def _shared_service_candidate(
    db: Session,
    alert: Alert,
    bindings: list[tuple[ServiceCatalogComponent, ServiceCatalogEntry]],
) -> tuple[Situation, dict[str, Any]] | None:
    if not bindings:
        return None
    target_component = aliased(ServiceCatalogComponent)
    target_type_match = or_(
        and_(
            target_component.node_type == "device",
            Alert.entity_type.in_(DEVICE_ENTITY_TYPES),
        ),
        and_(
            target_component.node_type == "endpoint",
            Alert.entity_type.in_(ENDPOINT_ENTITY_TYPES),
        ),
        and_(
            target_component.node_type == "knowledge_entity",
            Alert.entity_type == "knowledge_entity",
        ),
    )
    lower = _as_utc(alert.last_seen) - CROSS_ENTITY_WINDOW
    upper = _as_utc(alert.last_seen) + CROSS_ENTITY_WINDOW
    candidates: dict[str, list[tuple[Any, ...]]] = {}
    row_count = 0
    for source_component, service in bindings:
        rows = list(
            db.execute(
                select(Situation, Alert, target_component)
                .join(
                    SituationAlert,
                    SituationAlert.situation_id == Situation.id,
                )
                .join(Alert, Alert.id == SituationAlert.alert_id)
                .join(
                    target_component,
                    and_(
                        target_component.service_id == service.id,
                        target_component.entity_id == Alert.entity_id,
                    ),
                )
                .where(
                    Situation.status != SituationStatus.RESOLVED.value,
                    Situation.alert_count < MAX_CROSS_ENTITY_ALERTS,
                    Alert.status != AlertStatus.RESOLVED,
                    Alert.source_retirement_id.is_(None),
                    Alert.last_seen >= lower,
                    Alert.last_seen <= upper,
                    target_component.required.is_(True),
                    target_type_match,
                )
                .order_by(Situation.id, Alert.id, target_component.id)
                .with_for_update(of=Situation)
                .execution_options(populate_existing=True)
                .limit(MAX_CORRELATION_CANDIDATE_ROWS + 1)
            ).all()
        )
        row_count += len(rows)
        if row_count > MAX_CORRELATION_CANDIDATE_ROWS:
            return None
        for situation, target_alert, target_binding in rows:
            candidates.setdefault(situation.id, []).append(
                (
                    situation,
                    target_alert,
                    source_component,
                    target_binding,
                    service,
                )
            )
    if len(candidates) != 1:
        return None
    evidence_rows = next(iter(candidates.values()))
    evidence_rows.sort(
        key=lambda item: (
            item[4].criticality,
            item[4].service_key,
            item[1].id,
            item[3].id,
        )
    )
    situation, target_alert, source_component, target_component_row, service = (
        evidence_rows[0]
    )
    locked = db.scalar(
        select(Situation)
        .where(
            Situation.id == situation.id,
            Situation.status != SituationStatus.RESOLVED.value,
            Situation.alert_count < MAX_CROSS_ENTITY_ALERTS,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if locked is None:
        return None
    evidence = {
        "contract": "icheck.situation-correlation-evidence/v1",
        "evidence_type": "reviewed_service_component",
        "service_id": service.id,
        "service_revision": service.revision,
        "source_component_id": source_component.id,
        "target_component_id": target_component_row.id,
        "source_entity_type": _component_node_type(alert.entity_type),
        "source_entity_id": alert.entity_id,
        "target_entity_type": _component_node_type(target_alert.entity_type),
        "target_entity_id": target_alert.entity_id,
        "catalog_observed_at": service.updated_at.isoformat(),
        "correlation_window_seconds": int(CROSS_ENTITY_WINDOW.total_seconds()),
    }
    return locked, evidence


def _topology_evidence(
    db: Session,
    alert: Alert,
) -> list[_TopologyEvidence]:
    node_type = _component_node_type(alert.entity_type)
    if node_type is None:
        return []
    lower = _as_utc(alert.last_seen) - TOPOLOGY_EVIDENCE_MAX_AGE
    upper = _as_utc(alert.last_seen) + TOPOLOGY_EVIDENCE_FUTURE_SKEW
    evidence: list[_TopologyEvidence] = []

    if node_type == "knowledge_entity":
        source_active = db.scalar(
            select(KnowledgeEntity.active).where(
                KnowledgeEntity.id == alert.entity_id
            )
        )
        if source_active is not True:
            return []
        relationships = list(
            db.scalars(
                select(KnowledgeRelationship)
                .where(
                    or_(
                        KnowledgeRelationship.source_entity_id == alert.entity_id,
                        KnowledgeRelationship.target_entity_id == alert.entity_id,
                    ),
                    KnowledgeRelationship.relationship_type.in_(
                        TOPOLOGY_RELATIONSHIP_TYPES
                    ),
                    KnowledgeRelationship.directed.is_(False),
                    KnowledgeRelationship.active.is_(True),
                    KnowledgeRelationship.last_seen >= lower,
                    KnowledgeRelationship.last_seen <= upper,
                )
                .order_by(
                    KnowledgeRelationship.last_seen.desc(),
                    KnowledgeRelationship.id,
                )
                .with_for_update()
                .limit(MAX_TOPOLOGY_EVIDENCE_ROWS + 1)
            ).all()
        )
        if len(relationships) > MAX_TOPOLOGY_EVIDENCE_ROWS:
            return []
        neighbor_ids = {
            (
                item.target_entity_id
                if item.source_entity_id == alert.entity_id
                else item.source_entity_id
            )
            for item in relationships
        }
        active_neighbors = set(
            db.scalars(
                select(KnowledgeEntity.id).where(
                    KnowledgeEntity.id.in_(neighbor_ids),
                    KnowledgeEntity.active.is_(True),
                )
            ).all()
        ) if neighbor_ids else set()
        for item in relationships:
            neighbor_id = (
                item.target_entity_id
                if item.source_entity_id == alert.entity_id
                else item.source_entity_id
            )
            if neighbor_id not in active_neighbors:
                continue
            evidence.append(
                _TopologyEvidence(
                    evidence_type="knowledge_relationship",
                    evidence_id=item.id,
                    relationship_type=item.relationship_type,
                    neighbor_node_type="knowledge_entity",
                    neighbor_entity_id=neighbor_id,
                    observed_at=item.last_seen,
                    last_envelope_id=item.last_envelope_id,
                )
            )
    elif node_type in {"device", "endpoint"}:
        attachment_clause = (
            EndpointAttachment.collector_device_id == alert.entity_id
            if node_type == "device"
            else EndpointAttachment.endpoint_id == alert.entity_id
        )
        attachments = list(
            db.scalars(
                select(EndpointAttachment)
                .where(
                    attachment_clause,
                    EndpointAttachment.collector_device_id.is_not(None),
                    EndpointAttachment.active.is_(True),
                    EndpointAttachment.last_seen >= lower,
                    EndpointAttachment.last_seen <= upper,
                )
                .order_by(EndpointAttachment.last_seen.desc(), EndpointAttachment.id)
                .with_for_update()
                .limit(MAX_TOPOLOGY_EVIDENCE_ROWS + 1)
            ).all()
        )
        wireless_clause = (
            WirelessClientSession.controller_id == alert.entity_id
            if node_type == "device"
            else WirelessClientSession.endpoint_id == alert.entity_id
        )
        sessions = list(
            db.scalars(
                select(WirelessClientSession)
                .where(
                    wireless_clause,
                    WirelessClientSession.active.is_(True),
                    WirelessClientSession.last_seen >= lower,
                    WirelessClientSession.last_seen <= upper,
                )
                .order_by(
                    WirelessClientSession.last_seen.desc(),
                    WirelessClientSession.id,
                )
                .with_for_update()
                .limit(MAX_TOPOLOGY_EVIDENCE_ROWS + 1)
            ).all()
        )
        if (
            len(attachments) > MAX_TOPOLOGY_EVIDENCE_ROWS
            or len(sessions) > MAX_TOPOLOGY_EVIDENCE_ROWS
            or len(attachments) + len(sessions) > MAX_TOPOLOGY_EVIDENCE_ROWS
        ):
            return []
        for item in attachments:
            evidence.append(
                _TopologyEvidence(
                    evidence_type="endpoint_attachment",
                    evidence_id=item.id,
                    relationship_type="network.endpoint_attachment",
                    neighbor_node_type=(
                        "endpoint" if node_type == "device" else "device"
                    ),
                    neighbor_entity_id=(
                        item.endpoint_id
                        if node_type == "device"
                        else item.collector_device_id or ""
                    ),
                    observed_at=item.last_seen,
                )
            )
        for item in sessions:
            evidence.append(
                _TopologyEvidence(
                    evidence_type="wireless_session",
                    evidence_id=item.id,
                    relationship_type="network.wireless_session",
                    neighbor_node_type=(
                        "endpoint" if node_type == "device" else "device"
                    ),
                    neighbor_entity_id=(
                        item.endpoint_id
                        if node_type == "device"
                        else item.controller_id
                    ),
                    observed_at=item.last_seen,
                )
            )

    return sorted(
        evidence,
        key=lambda item: (
            _as_utc(item.observed_at),
            item.evidence_type,
            item.evidence_id,
        ),
        reverse=True,
    )


def _fresh_topology_candidate(
    db: Session,
    alert: Alert,
    evidence: list[_TopologyEvidence],
) -> tuple[Situation, dict[str, Any]] | None:
    if not evidence:
        return None
    by_neighbor: dict[tuple[str, str], list[_TopologyEvidence]] = {}
    for item in evidence:
        by_neighbor.setdefault(
            (item.neighbor_node_type, item.neighbor_entity_id), []
        ).append(item)
    clauses = []
    device_ids = {
        entity_id
        for (node_type, entity_id) in by_neighbor
        if node_type == "device"
    }
    endpoint_ids = {
        entity_id
        for (node_type, entity_id) in by_neighbor
        if node_type == "endpoint"
    }
    knowledge_ids = {
        entity_id
        for (node_type, entity_id) in by_neighbor
        if node_type == "knowledge_entity"
    }
    if device_ids:
        clauses.append(
            and_(
                Alert.entity_type.in_(DEVICE_ENTITY_TYPES),
                Alert.entity_id.in_(device_ids),
            )
        )
    if endpoint_ids:
        clauses.append(
            and_(
                Alert.entity_type.in_(ENDPOINT_ENTITY_TYPES),
                Alert.entity_id.in_(endpoint_ids),
            )
        )
    if knowledge_ids:
        clauses.append(
            and_(
                Alert.entity_type == "knowledge_entity",
                Alert.entity_id.in_(knowledge_ids),
            )
        )
    if not clauses:
        return None
    lower = _as_utc(alert.last_seen) - CROSS_ENTITY_WINDOW
    upper = _as_utc(alert.last_seen) + CROSS_ENTITY_WINDOW
    rows = list(
        db.execute(
            select(Situation, Alert)
            .join(SituationAlert, SituationAlert.situation_id == Situation.id)
            .join(Alert, Alert.id == SituationAlert.alert_id)
            .where(
                Situation.status != SituationStatus.RESOLVED.value,
                Situation.alert_count < MAX_CROSS_ENTITY_ALERTS,
                Alert.status != AlertStatus.RESOLVED,
                Alert.source_retirement_id.is_(None),
                Alert.last_seen >= lower,
                Alert.last_seen <= upper,
                or_(*clauses),
            )
            .order_by(Situation.id, Alert.id)
            .with_for_update(of=Situation)
            .execution_options(populate_existing=True)
            .limit(MAX_CORRELATION_CANDIDATE_ROWS + 1)
        ).all()
    )
    if len(rows) > MAX_CORRELATION_CANDIDATE_ROWS:
        return None
    candidates: dict[str, list[tuple[Situation, Alert, _TopologyEvidence]]] = {}
    for situation, target_alert in rows:
        target_type = _component_node_type(target_alert.entity_type)
        if target_type is None:
            continue
        for item in by_neighbor.get((target_type, target_alert.entity_id), []):
            candidates.setdefault(situation.id, []).append(
                (situation, target_alert, item)
            )
    if len(candidates) != 1:
        return None
    evidence_rows = next(iter(candidates.values()))
    evidence_rows.sort(
        key=lambda item: (
            -_as_utc(item[2].observed_at).timestamp(),
            item[1].id,
            item[2].evidence_type,
            item[2].evidence_id,
        )
    )
    situation, target_alert, selected = evidence_rows[0]
    locked = db.scalar(
        select(Situation)
        .where(
            Situation.id == situation.id,
            Situation.status != SituationStatus.RESOLVED.value,
            Situation.alert_count < MAX_CROSS_ENTITY_ALERTS,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if locked is None:
        return None
    frozen = {
        "contract": "icheck.situation-correlation-evidence/v1",
        "evidence_type": "fresh_topology_adjacency",
        "topology_evidence_type": selected.evidence_type,
        "topology_evidence_id": selected.evidence_id,
        "topology_relationship_type": selected.relationship_type,
        "topology_observed_at": _as_utc(selected.observed_at).isoformat(),
        "topology_last_envelope_id": selected.last_envelope_id,
        "source_entity_type": _component_node_type(alert.entity_type),
        "source_entity_id": alert.entity_id,
        "target_entity_type": _component_node_type(target_alert.entity_type),
        "target_entity_id": target_alert.entity_id,
        "target_alert_id": target_alert.id,
        "correlation_window_seconds": int(CROSS_ENTITY_WINDOW.total_seconds()),
        "max_topology_age_seconds": int(
            TOPOLOGY_EVIDENCE_MAX_AGE.total_seconds()
        ),
        "causal_claim": False,
    }
    return locked, frozen


def _document_hash(document: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _append_event(
    db: Session,
    situation: Situation,
    *,
    event_type: str,
    actor: str,
    details: dict[str, Any] | None = None,
) -> SituationEvent:
    situation.event_sequence += 1
    event = SituationEvent(
        situation_id=situation.id,
        sequence=situation.event_sequence,
        event_type=event_type,
        actor=actor,
        details=details or {},
    )
    db.add(event)
    db.flush()
    from .workflow_runtime import enqueue_situation_integration_events

    enqueue_situation_integration_events(db, event)
    return event


def append_situation_event(
    db: Session,
    situation: Situation,
    *,
    event_type: str,
    actor: str,
    details: dict[str, Any] | None = None,
) -> SituationEvent:
    return _append_event(
        db,
        situation,
        event_type=event_type,
        actor=actor,
        details=details,
    )


def _bounded_title(value: str) -> str:
    normalized = " ".join(value.split())
    if len(normalized) <= 255:
        return normalized
    return normalized[:252].rstrip() + "..."


def _recompute_situation(
    db: Session,
    situation: Situation,
    *,
    actor: str,
    resolve_when_quiet: bool = True,
) -> None:
    # Callers own the Situation row lock. Persist their Alert/membership edits
    # before refreshing the projection: identity-map values loaded before a
    # lock wait must not override newer committed Alert truth.
    db.flush()
    rows = list(
        db.execute(
            select(Alert, SituationAlert)
            .join(SituationAlert, SituationAlert.alert_id == Alert.id)
            .where(SituationAlert.situation_id == situation.id)
            .order_by(Alert.last_seen.desc(), Alert.id)
            .execution_options(populate_existing=True)
        ).all()
    )
    alerts = [alert for alert, _membership in rows]
    membership_count = db.scalar(
        select(func.count(SituationAlert.id)).where(
            SituationAlert.situation_id == situation.id
        )
    ) or 0
    if not alerts or len(alerts) != membership_count:
        raise RuntimeError("Situation must retain every correlated Alert")
    active = [item for item in alerts if item.status != AlertStatus.RESOLVED and item.source_retirement_id is None]
    considered = active or alerts
    primary = sorted(
        considered,
        key=lambda item: (
            SEVERITY_RANK[item.severity],
            _as_utc(item.last_seen),
            item.id,
        ),
        reverse=True,
    )[0]
    previous_status = situation.status
    previous_severity = situation.severity
    situation.alert_count = len(alerts)
    situation.active_alert_count = len(active)
    situation.occurrence_count = sum(item.occurrence_count for item in alerts)
    situation.correlation_confidence = min(
        membership.correlation_confidence for _alert, membership in rows
    )
    correlation_reasons = {
        membership.correlation_reason for _alert, membership in rows
    }
    if "fresh_topology_adjacency" in correlation_reasons:
        situation.correlation_version = TOPOLOGY_CORRELATION_VERSION
    elif correlation_reasons - {"same_entity"}:
        situation.correlation_version = EVIDENCE_CORRELATION_VERSION
    else:
        situation.correlation_version = CORRELATION_VERSION
    situation.first_seen = min(
        alerts,
        key=lambda item: _as_utc(item.first_seen),
    ).first_seen
    situation.last_seen = max(
        alerts,
        key=lambda item: _as_utc(item.last_seen),
    ).last_seen
    situation.severity = primary.severity
    situation.priority_score = (
        0
        if not active
        else SEVERITY_RANK[primary.severity]
        + min(len(active) * 5, 25)
        + min(situation.occurrence_count, 20)
    )
    related = f" (+{len(active) - 1} related)" if len(active) > 1 else ""
    situation.title = _bounded_title(primary.title + related)
    entity_count = len(
        {
            (
                _component_node_type(item.entity_type) or item.entity_type,
                item.entity_id,
            )
            for item in alerts
        }
    )
    if entity_count == 1:
        location = (
            f"on {situation.primary_entity_type} {situation.primary_entity_id}"
        )
    elif "fresh_topology_adjacency" in correlation_reasons:
        location = (
            f"across {entity_count} evidence-linked adjacent entities; primary "
            f"{situation.primary_entity_type} {situation.primary_entity_id}"
        )
    else:
        location = (
            f"across {entity_count} reviewed service components; primary "
            f"{situation.primary_entity_type} {situation.primary_entity_id}"
        )
    situation.summary = (
        f"{len(active)} active of {len(alerts)} correlated alerts; "
        f"{situation.occurrence_count} total occurrences {location}."
    )
    if active and situation.status == SituationStatus.RESOLVED.value:
        situation.status = SituationStatus.OPEN.value
        situation.resolved_at = None
        situation.resolved_by = None
        situation.acknowledged_at = None
        situation.acknowledged_by = None
        details = {"reason": "correlated_alerts_active", "causal_claim": False}
        _append_event(
            db,
            situation,
            event_type="situation.reopened",
            actor=actor,
            details=details,
        )
        record_audit_event(
            db,
            event_type="situation.reopened",
            actor_type="system",
            actor_id=actor,
            entity_type="situation",
            entity_id=situation.id,
            details=details,
        )
    if (resolve_when_quiet and not active
        and situation.status != SituationStatus.RESOLVED.value):
        situation.status = SituationStatus.RESOLVED.value
        situation.resolved_at = utcnow()
        situation.resolved_by = actor
        details = {
            "reason": "all_alerts_resolved_or_superseded" if any(item.source_retirement_id for item in alerts) else "all_alerts_resolved",
            "resolution_basis": "collector_source_projection/v2" if any(item.source_retirement_id for item in alerts) else "correlated_alert_state_projection/v1",
            "independently_verified": False,
            "authorizes_ai_closure": False,
        }
        _append_event(
            db,
            situation,
            event_type="situation.resolved",
            actor=actor,
            details=details,
        )
        record_audit_event(
            db,
            event_type="situation.resolved",
            actor_type="system",
            actor_id=actor,
            entity_type="situation",
            entity_id=situation.id,
            details=details,
        )
    if previous_severity != situation.severity and previous_status != "":
        _append_event(
            db,
            situation,
            event_type="situation.severity_changed",
            actor=actor,
            details={
                "from": previous_severity.value,
                "to": situation.severity.value,
            },
        )
    situation.updated_at = utcnow()


def correlate_alert(
    db: Session,
    alert: Alert,
    *,
    actor: str = "iCheck situation correlator",
) -> Situation | None:
    # Retirement preserves the measured episode and its existing membership;
    # that historical episode must not participate in a fresh correlation.
    if alert.source_retirement_id is not None:
        return None
    membership = db.scalar(
        select(SituationAlert)
        .where(SituationAlert.alert_id == alert.id)
        .with_for_update()
    )
    if membership is not None:
        situation = db.scalar(
            select(Situation)
            .where(Situation.id == membership.situation_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if situation is None:
            raise RuntimeError("Situation membership references a missing Situation")
        previous_state = (membership.severity_snapshot, membership.status_snapshot)
        membership.severity_snapshot = alert.severity.value
        membership.status_snapshot = alert.status.value
        membership.occurrence_count_snapshot = alert.occurrence_count
        membership.last_seen = alert.last_seen
        membership.updated_at = utcnow()
        if previous_state != (
            membership.severity_snapshot,
            membership.status_snapshot,
        ):
            _append_event(
                db,
                situation,
                event_type="alert.state_changed",
                actor=actor,
                details={
                    "alert_id": alert.id,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                },
            )
        _recompute_situation(db, situation, actor=actor)
        return situation

    if alert.status == AlertStatus.RESOLVED:
        return None

    bindings = _correlation_service_bindings(db, alert)
    topology_evidence = _topology_evidence(db, alert)
    correlation_key = situation_correlation_key(
        alert.entity_type,
        alert.entity_id,
    )
    lock_tokens = {
        (
            f"entity:{_component_node_type(alert.entity_type) or alert.entity_type}:"
            f"{alert.entity_id}"
        ),
        *(f"service:{service.id}" for _component, service in bindings),
        *(
            f"topology:{item.evidence_type}:{item.evidence_id}"
            for item in topology_evidence
        ),
    }
    for token in sorted(lock_tokens):
        _advisory_lock_token(db, token)

    situation = _active_same_entity_situation(db, alert)
    correlation_reason = "same_entity"
    correlation_confidence = 1.0
    correlation_evidence: dict[str, Any] = {}
    if situation is None:
        cross_entity = _shared_service_candidate(db, alert, bindings)
        if cross_entity is not None:
            situation, correlation_evidence = cross_entity
            correlation_reason = "shared_service_component"
            correlation_confidence = CROSS_ENTITY_CONFIDENCE
    if situation is None:
        topology_candidate = _fresh_topology_candidate(
            db,
            alert,
            topology_evidence,
        )
        if topology_candidate is not None:
            situation, correlation_evidence = topology_candidate
            correlation_reason = "fresh_topology_adjacency"
            correlation_confidence = TOPOLOGY_CORRELATION_CONFIDENCE
    if situation is None:
        _advisory_lock(db, correlation_key)
        situation = db.scalar(
            select(Situation)
            .where(
                Situation.correlation_key == correlation_key,
                Situation.status != SituationStatus.RESOLVED.value,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    created = situation is None
    if situation is None:
        situation = Situation(
            correlation_key=correlation_key,
            correlation_version=CORRELATION_VERSION,
            status=SituationStatus.OPEN.value,
            severity=alert.severity,
            priority_score=SEVERITY_RANK[alert.severity] + 6,
            title=_bounded_title(alert.title),
            summary=(
                f"1 active of 1 correlated alerts; {alert.occurrence_count} "
                f"total occurrences on {alert.entity_type} {alert.entity_id}."
            ),
            primary_entity_type=alert.entity_type,
            primary_entity_id=alert.entity_id,
            alert_count=1,
            active_alert_count=1,
            occurrence_count=alert.occurrence_count,
            correlation_confidence=1.0,
            first_seen=alert.first_seen,
            last_seen=alert.last_seen,
        )
        db.add(situation)
        db.flush()
        _append_event(
            db,
            situation,
            event_type="situation.created",
            actor=actor,
            details={
                "correlation_version": CORRELATION_VERSION,
                "reason": "same_entity",
            },
        )
        record_audit_event(
            db,
            event_type="situation.created",
            actor_type="system",
            actor_id=actor,
            entity_type="situation",
            entity_id=situation.id,
            details={
                "correlation_version": CORRELATION_VERSION,
                "primary_entity_type": alert.entity_type,
                "primary_entity_id": alert.entity_id,
            },
        )
    elif situation.status == SituationStatus.ACKNOWLEDGED.value:
        situation.status = SituationStatus.OPEN.value
        _append_event(
            db,
            situation,
            event_type="situation.attention_reopened",
            actor=actor,
            details={
                "reason": "new_correlated_alert",
                "correlation_reason": correlation_reason,
            },
        )

    membership = SituationAlert(
        situation_id=situation.id,
        alert_id=alert.id,
        role="symptom",
        correlation_reason=correlation_reason,
        correlation_confidence=correlation_confidence,
        correlation_evidence=correlation_evidence,
        severity_snapshot=alert.severity.value,
        status_snapshot=alert.status.value,
        occurrence_count_snapshot=alert.occurrence_count,
        first_seen=alert.first_seen,
        last_seen=alert.last_seen,
    )
    db.add(membership)
    db.flush()
    _append_event(
        db,
        situation,
        event_type="alert.attached",
        actor=actor,
        details={
            "alert_id": alert.id,
            "event_type": alert.event_type,
            "reason": correlation_reason,
            "confidence": correlation_confidence,
            "correlation_evidence_type": correlation_evidence.get(
                "evidence_type"
            ),
            "correlation_evidence_sha256": (
                _document_hash(correlation_evidence)
                if correlation_evidence
                else None
            ),
        },
    )
    _recompute_situation(db, situation, actor=actor)
    if created:
        db.flush()
    return situation


def acknowledge_situation(
    db: Session,
    situation: Situation,
    *,
    actor: str,
    reason: str | None = None,
    principal: PrincipalContext | None = None,
) -> Situation:
    situation = _lock_situation_lifecycle(db, situation, principal=principal)
    if situation.status == SituationStatus.RESOLVED.value:
        raise ValueError("A resolved Situation cannot be acknowledged")
    if situation.status == SituationStatus.ACKNOWLEDGED.value:
        return situation
    situation.status = SituationStatus.ACKNOWLEDGED.value
    situation.acknowledged_at = utcnow()
    situation.acknowledged_by = actor
    situation.updated_at = utcnow()
    _append_event(
        db,
        situation,
        event_type="situation.acknowledged",
        actor=actor,
        details={"reason": reason or "operator_acknowledged"},
    )
    record_audit_event(
        db,
        event_type="situation.acknowledged",
        actor_type="user",
        actor_id=actor,
        entity_type="situation",
        entity_id=situation.id,
        details={"reason": reason or "operator_acknowledged"},
    )
    return situation


def _lock_situation_lifecycle(
    db: Session, situation: Situation, *, principal: PrincipalContext | None = None
) -> Situation:
    """Serialize supported lifecycle writers without locking Alert rows.

    Alert ingestion may already own an Alert lock before correlation takes the
    parent lock. Taking those locks in reverse here would deadlock. Fresh reads
    after the parent wait and correlator reopen handling establish the ordering.
    """
    require_locking_transaction(db, purpose="Situation lifecycle mutations")
    if any(
        isinstance(row, (Alert, SituationAlert))
        for row in (*db.new, *db.dirty, *db.deleted)
    ):
        raise ValueError("Persist pending Alert state or membership changes before lifecycle mutations")
    if db.is_modified(situation, include_collections=False):
        raise ValueError("Persist pending Situation changes before lifecycle mutations")
    with db.no_autoflush:
        current = db.scalar(
            select(Situation)
            .where(
                Situation.id == situation.id,
                Situation.tenant_id == situation.tenant_id,
                Situation.region_id == situation.region_id,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    if current is None:
        raise ValueError("Situation is no longer available in this namespace")
    # Membership/scope may change while the request waits on the row lock.
    # Re-evaluate full access with a fresh READ COMMITTED statement afterward.
    if principal is not None:
        from .authorization_scope import require_situation_access

        require_situation_access(db, principal, current.id)
    return current


def resolve_situation(
    db: Session,
    situation: Situation,
    *,
    actor: str,
    reason: str | None = None,
    principal: PrincipalContext | None = None,
) -> Situation:
    situation = _lock_situation_lifecycle(db, situation, principal=principal)
    membership_count, alert_count, active_count, _occurrence_count = db.execute(
        select(
            func.count(SituationAlert.id),
            func.count(Alert.id),
            func.count(Alert.id).filter(and_(Alert.status != AlertStatus.RESOLVED, Alert.source_retirement_id.is_(None))),
            func.coalesce(func.sum(Alert.occurrence_count), 0),
        )
        .select_from(SituationAlert)
        .outerjoin(Alert, SituationAlert.alert_id == Alert.id)
        .where(SituationAlert.situation_id == situation.id)
    ).one()
    if not membership_count or alert_count != membership_count:
        raise ValueError("Situation resolution requires every correlated Alert to be available")
    if active_count:
        raise ValueError(
            "A Situation cannot resolve while correlated Alerts remain active"
        )
    if situation.status == SituationStatus.RESOLVED.value:
        return situation
    # Refresh title/summary/severity as well as counters, without substituting
    # the correlator's automatic state-projection event for this manual action.
    _recompute_situation(db, situation, actor=actor, resolve_when_quiet=False)
    situation.status = SituationStatus.RESOLVED.value
    situation.priority_score = 0
    situation.resolved_at = utcnow()
    situation.resolved_by = actor
    situation.updated_at = utcnow()
    details = {
        "reason": reason or "operator_resolution",
        "resolution_basis": "manual_alert_state_check/v1",
        "alert_count": alert_count,
        "active_alert_count": 0,
        "independently_verified": False,
        "authorizes_ai_closure": False,
    }
    _append_event(
        db,
        situation,
        event_type="situation.resolved",
        actor=actor,
        details=details,
    )
    record_audit_event(
        db,
        event_type="situation.resolved",
        actor_type="user",
        actor_id=actor,
        entity_type="situation",
        entity_id=situation.id,
        details=details,
    )
    return situation


def record_situation_investigation(
    db: Session,
    situation: Situation,
    investigation: Investigation,
    *,
    actor: str,
) -> None:
    _append_event(
        db,
        situation,
        event_type="investigation.created",
        actor=actor,
        details={"investigation_id": investigation.id},
    )
    situation.updated_at = utcnow()


def reconcile_uncorrelated_alerts(db: Session, *, limit: int = 1000) -> int:
    alerts = list(
        db.scalars(
            select(Alert)
            .where(
                Alert.status != AlertStatus.RESOLVED,
                Alert.source_retirement_id.is_(None),
                ~exists(
                    select(SituationAlert.id).where(
                        SituationAlert.alert_id == Alert.id
                    )
                ),
            )
            .order_by(Alert.first_seen, Alert.id)
            .limit(limit)
        ).all()
    )
    for alert in alerts:
        correlate_alert(db, alert)
    return len(alerts)
