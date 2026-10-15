from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from pydantic import TypeAdapter
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID
from ..models import (
    AgentToolRegistration,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    CollectionEnvelope,
    CollectorDeployment,
    Investigation,
    InvestigationToolCall,
    ServiceIndicatorArtifactBinding,
    ServiceIndicatorArtifactPublication,
    ServiceIndicatorDefinition,
    ServiceCatalogComponent,
    WorkflowScheduleActivation,
    WorkflowScheduleEvent,
    utcnow,
)
from ..schema_validation import validate_instance
from ..service_indicator_schemas import (
    ARTIFACT_INDICATOR_CONTRACT,
    ArtifactIndicatorEnvelope,
    ServiceIndicatorArtifactBindingCreate,
    ServiceIndicatorArtifactBindingRead,
    ServiceIndicatorArtifactBindingUpdate,
    ServiceIndicatorObservationCreate,
)
from .audit import record_audit_event
from .authorization_scope import service_component_scope_clause
from .control_plane_auth import PrincipalContext
from .service_indicators import ingest_observation
from .workflow_runtime import assert_workflow_runtime_compatible


ARTIFACT_INDICATOR_SOURCE_TYPES = {"api", "collector", "business_system"}


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _schema_at_path(schema: dict[str, Any], path: str) -> dict[str, Any]:
    current: Any = schema
    for part in path.split("."):
        properties = current.get("properties") if isinstance(current, dict) else None
        if not isinstance(properties, dict) or part not in properties:
            raise ValueError(
                f"Indicator output path {path!r} is absent from Tool output schema"
            )
        current = properties[part]
    if not isinstance(current, dict):
        raise ValueError(f"Indicator output path {path!r} is invalid")
    return current


def _schema_types(schema: dict[str, Any]) -> set[str]:
    value = schema.get("type")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()


def _validate_dimension_schema(schema: dict[str, Any], path: str) -> None:
    if "object" not in _schema_types(schema):
        raise ValueError(f"Indicator dimensions path {path!r} must be an object")
    if any(
        keyword in schema
        for keyword in (
            "allOf",
            "anyOf",
            "oneOf",
            "not",
            "patternProperties",
            "unevaluatedProperties",
        )
    ):
        raise ValueError(
            f"Indicator dimensions path {path!r} must use a direct string-object schema"
        )
    properties = schema.get("properties", {})
    if not isinstance(properties, dict) or any(
        not isinstance(item, dict) or "string" not in _schema_types(item)
        for item in properties.values()
    ):
        raise ValueError(
            f"Indicator dimensions path {path!r} must contain only strings"
        )
    additional = schema.get("additionalProperties", False)
    if additional is not False and not (
        isinstance(additional, dict) and "string" in _schema_types(additional)
    ):
        raise ValueError(
            f"Indicator dimensions path {path!r} must contain only strings"
        )


def _validate_workflow_mapping(
    tool: AgentToolRegistration,
    mapping: dict[str, str],
) -> None:
    value_path = mapping["value"]
    if not _schema_types(_schema_at_path(tool.output_schema, value_path)).intersection(
        {"integer", "number"}
    ):
        raise ValueError(f"Indicator value path {value_path!r} must be numeric")
    observed_path = mapping.get("observed_at")
    if observed_path:
        schema = _schema_at_path(tool.output_schema, observed_path)
        if "string" not in _schema_types(schema) or schema.get("format") != "date-time":
            raise ValueError(
                f"Indicator observed_at path {observed_path!r} must be date-time"
            )
    dimensions_path = mapping.get("dimensions")
    if dimensions_path:
        _validate_dimension_schema(
            _schema_at_path(tool.output_schema, dimensions_path),
            dimensions_path,
        )


def _validate_source(definition: ServiceIndicatorDefinition, producer_kind: str) -> None:
    if not definition.enabled:
        raise ValueError("A disabled indicator cannot activate Artifact publication")
    if definition.source_type not in ARTIFACT_INDICATOR_SOURCE_TYPES:
        raise ValueError(
            "Artifact publication requires an api, collector, or business_system source"
        )
    if definition.source_type == "collector" and producer_kind != "collector":
        raise ValueError("A collector indicator requires a Collector producer")


def _validate_collector_service_scope(
    db: Session,
    definition: ServiceIndicatorDefinition,
    deployment: CollectorDeployment,
) -> None:
    authorization_scope: dict[str, Any] = {}
    if deployment.scope_device_id:
        authorization_scope["device_ids"] = [deployment.scope_device_id]
    if deployment.scope_site:
        authorization_scope["sites"] = [deployment.scope_site]
    if not authorization_scope:
        raise ValueError("Indicator Collector deployment must have device or site scope")
    deployment_principal = PrincipalContext(
        principal_id=None,
        subject="collector.deployment.scope",
        principal_type="service",
        permissions=frozenset(),
        role_names=(),
        authorization_scope=authorization_scope,
        auth_method="internal",
        tenant_id=deployment.tenant_id or DEFAULT_TENANT_ID,
        region_id=deployment.region_id or DEFAULT_REGION_ID,
        tenant_slug=deployment.tenant_id or DEFAULT_TENANT_ID,
        region_code=deployment.region_id or DEFAULT_REGION_ID,
    )
    overlap = db.scalar(
        select(func.count(ServiceCatalogComponent.id)).where(
            ServiceCatalogComponent.service_id == definition.service_id,
            service_component_scope_clause(deployment_principal),
        )
    ) or 0
    if overlap == 0:
        raise ValueError(
            "Indicator Collector deployment does not overlap the service scope"
        )


def _producer_tool(
    db: Session,
    version: ArtifactVersion,
    tool_name: str,
) -> AgentToolRegistration:
    dependencies = version.definition.get("tool_dependencies", [])
    dependency = next(
        (item for item in dependencies if item.get("name") == tool_name), None
    )
    if dependency is None:
        raise ValueError("Indicator producer Tool must be a pinned Workflow dependency")
    tool = db.scalar(
        select(AgentToolRegistration).where(
            AgentToolRegistration.name == tool_name,
            AgentToolRegistration.enabled.is_(True),
        )
    )
    if tool is None:
        raise ValueError("Indicator producer Tool is unavailable")
    if not tool.read_only:
        raise ValueError("Indicator producer Tool must be read-only")
    return tool


def validate_artifact_indicator_binding(
    db: Session,
    definition: ServiceIndicatorDefinition,
    payload: ServiceIndicatorArtifactBindingCreate,
) -> ArtifactVersion:
    _validate_source(definition, payload.producer_kind)
    version = db.get(ArtifactVersion, payload.artifact_version_id)
    if version is None:
        raise LookupError("Artifact version not found")
    if version.status != ArtifactVersionStatus.PUBLISHED:
        raise ValueError("Only a published Artifact version can produce indicators")
    if payload.producer_kind == "collector":
        if version.artifact.kind != ArtifactKind.COLLECTOR:
            raise ValueError("Collector producer requires a Collector Artifact")
        collector = version.collector_definition
        if collector is None or "observation" not in set(collector.output_kinds or []):
            raise ValueError(
                "Collector producer must declare observation output"
            )
    else:
        spec, _report = assert_workflow_runtime_compatible(db, version)
        if spec.trigger.trigger_type != "schedule":
            raise ValueError("Indicator Workflow producer must use a schedule trigger")
        tool = _producer_tool(db, version, payload.producer_tool_name or "")
        _validate_workflow_mapping(tool, payload.output_mapping)
    return version


def binding_to_read(
    binding: ServiceIndicatorArtifactBinding,
) -> ServiceIndicatorArtifactBindingRead:
    return ServiceIndicatorArtifactBindingRead(
        id=binding.id,
        definition_id=binding.definition_id,
        artifact_version_id=binding.artifact_version_id,
        artifact_name=binding.artifact_version.artifact.name,
        artifact_version=binding.artifact_version.version,
        producer_kind=binding.producer_kind,
        binding_key=binding.binding_key,
        producer_tool_name=binding.producer_tool_name,
        output_mapping=dict(binding.output_mapping or {}),
        enabled=binding.enabled,
        revision=binding.revision,
        created_by=binding.created_by,
        updated_by=binding.updated_by,
        created_at=binding.created_at,
        updated_at=binding.updated_at,
    )


def create_artifact_indicator_binding(
    db: Session,
    definition: ServiceIndicatorDefinition,
    payload: ServiceIndicatorArtifactBindingCreate,
    *,
    actor: str,
) -> ServiceIndicatorArtifactBinding:
    locked = db.scalar(
        select(ServiceIndicatorDefinition)
        .where(ServiceIndicatorDefinition.id == definition.id)
        .with_for_update()
    )
    if locked is None:
        raise LookupError("Service indicator not found")
    if locked.revision != payload.expected_indicator_revision:
        raise ValueError("Service indicator revision conflict; reload before updating")
    version = validate_artifact_indicator_binding(db, locked, payload)
    existing = db.scalar(
        select(ServiceIndicatorArtifactBinding).where(
            ServiceIndicatorArtifactBinding.definition_id == locked.id
        )
    )
    if existing is not None:
        raise ValueError("Service indicator Artifact binding already exists")
    binding = ServiceIndicatorArtifactBinding(
        definition_id=locked.id,
        artifact_version_id=version.id,
        producer_kind=payload.producer_kind,
        binding_key=payload.binding_key,
        producer_tool_name=payload.producer_tool_name,
        output_mapping=payload.output_mapping,
        enabled=True,
        revision=1,
        created_by=actor,
        updated_by=actor,
    )
    try:
        db.add(binding)
        db.flush()
        record_audit_event(
            db,
            event_type="service_indicator.artifact_binding_created",
            actor_type="user",
            actor_id=actor,
            entity_type="service_indicator_artifact_binding",
            entity_id=binding.id,
            details={
                "definition_id": locked.id,
                "service_id": locked.service_id,
                "artifact_version_id": version.id,
                "producer_kind": binding.producer_kind,
                "binding_key": binding.binding_key,
                "producer_tool_name": binding.producer_tool_name,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Service indicator Artifact binding conflicts") from exc
    db.refresh(binding)
    return binding


def update_artifact_indicator_binding(
    db: Session,
    binding: ServiceIndicatorArtifactBinding,
    payload: ServiceIndicatorArtifactBindingUpdate,
    *,
    actor: str,
) -> ServiceIndicatorArtifactBinding:
    locked = db.scalar(
        select(ServiceIndicatorArtifactBinding)
        .where(ServiceIndicatorArtifactBinding.id == binding.id)
        .with_for_update()
    )
    if locked is None:
        raise LookupError("Service indicator Artifact binding not found")
    if locked.revision != payload.expected_revision:
        raise ValueError("Artifact binding revision conflict; reload before updating")
    if locked.enabled == payload.enabled:
        return locked
    if payload.enabled:
        create_payload = ServiceIndicatorArtifactBindingCreate(
            expected_indicator_revision=locked.definition.revision,
            artifact_version_id=locked.artifact_version_id,
            producer_kind=locked.producer_kind,
            binding_key=locked.binding_key,
            producer_tool_name=locked.producer_tool_name,
            output_mapping=dict(locked.output_mapping or {}),
            actor=actor,
        )
        validate_artifact_indicator_binding(db, locked.definition, create_payload)
    locked.enabled = payload.enabled
    locked.revision += 1
    locked.updated_by = actor
    locked.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="service_indicator.artifact_binding_updated",
        actor_type="user",
        actor_id=actor,
        entity_type="service_indicator_artifact_binding",
        entity_id=locked.id,
        details={"enabled": locked.enabled, "revision": locked.revision},
    )
    db.commit()
    db.refresh(locked)
    return locked


def get_artifact_indicator_binding(
    db: Session,
    definition_id: str,
) -> ServiceIndicatorArtifactBinding:
    binding = db.scalar(
        select(ServiceIndicatorArtifactBinding).where(
            ServiceIndicatorArtifactBinding.definition_id == definition_id
        )
    )
    if binding is None:
        raise LookupError("Service indicator Artifact binding not found")
    return binding


def list_artifact_indicator_publications(
    db: Session,
    binding: ServiceIndicatorArtifactBinding,
    *,
    limit: int,
) -> list[ServiceIndicatorArtifactPublication]:
    return list(
        db.scalars(
            select(ServiceIndicatorArtifactPublication)
            .where(ServiceIndicatorArtifactPublication.binding_id == binding.id)
            .order_by(ServiceIndicatorArtifactPublication.created_at.desc())
            .limit(limit)
        ).all()
    )


def _extract_path(document: Any, path: str) -> Any:
    current = document
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise ValueError(f"Indicator result path {path!r} is missing")
        current = current[part]
    return current


def _record_publication(
    db: Session,
    *,
    binding: ServiceIndicatorArtifactBinding,
    observation_id: str,
    collection_envelope_id: str | None = None,
    investigation_id: str | None = None,
    source_tool_call_id: str | None = None,
) -> ServiceIndicatorArtifactPublication:
    publication = ServiceIndicatorArtifactPublication(
        binding_id=binding.id,
        observation_id=observation_id,
        artifact_version_id=binding.artifact_version_id,
        binding_revision=binding.revision,
        producer_kind=binding.producer_kind,
        collection_envelope_id=collection_envelope_id,
        investigation_id=investigation_id,
        source_tool_call_id=source_tool_call_id,
    )
    db.add(publication)
    db.flush()
    record_audit_event(
        db,
        event_type="service_indicator.artifact_observation_published",
        actor_type="service",
        actor_id=f"indicator.{binding.producer_kind}",
        entity_type="service_indicator_artifact_publication",
        entity_id=publication.id,
        details={
            "binding_id": binding.id,
            "definition_id": binding.definition_id,
            "observation_id": observation_id,
            "artifact_version_id": binding.artifact_version_id,
            "binding_revision": binding.revision,
            "producer_kind": binding.producer_kind,
        },
    )
    return publication


def publish_collector_indicator_envelope(
    db: Session,
    envelope: CollectionEnvelope,
    deployment: CollectorDeployment,
    payload: ArtifactIndicatorEnvelope,
) -> tuple[ServiceIndicatorArtifactPublication, str]:
    if not envelope.idempotency_key:
        raise ValueError("Indicator observation envelopes require idempotency_key")
    binding = db.scalar(
        select(ServiceIndicatorArtifactBinding)
        .where(
            ServiceIndicatorArtifactBinding.artifact_version_id
            == deployment.artifact_version_id,
            ServiceIndicatorArtifactBinding.producer_kind == "collector",
            ServiceIndicatorArtifactBinding.binding_key == payload.binding_key,
        )
        .with_for_update()
    )
    if binding is None:
        raise ValueError("No Artifact indicator binding matches this envelope")
    if not binding.enabled:
        raise ValueError("Artifact indicator binding is disabled")
    definition = db.scalar(
        select(ServiceIndicatorDefinition)
        .where(ServiceIndicatorDefinition.id == binding.definition_id)
        .with_for_update()
    )
    if definition is None:
        raise LookupError("Service indicator not found")
    _validate_source(definition, "collector")
    _validate_collector_service_scope(db, definition, deployment)
    existing = db.scalar(
        select(ServiceIndicatorArtifactPublication).where(
            ServiceIndicatorArtifactPublication.binding_id == binding.id,
            ServiceIndicatorArtifactPublication.collection_envelope_id == envelope.id,
        )
    )
    if existing is not None:
        return existing, existing.observation_id
    identity = "|".join(
        [binding.artifact_version_id, envelope.source, envelope.idempotency_key]
    )
    source_id = f"collector:{hashlib.sha256(identity.encode()).hexdigest()}"
    observation = ingest_observation(
        db,
        definition,
        ServiceIndicatorObservationCreate(
            source_observation_id=source_id,
            value=payload.value,
            measurement_quality=payload.measurement_quality,
            dimensions=payload.dimensions,
            evidence_ref=f"collection-envelope:{envelope.id}",
            observed_at=envelope.observed_at,
            actor="knowledge.projection.worker",
        ),
        actor="knowledge.projection.worker",
        commit=False,
    )
    publication = _record_publication(
        db,
        binding=binding,
        observation_id=observation.id,
        collection_envelope_id=envelope.id,
    )
    return publication, observation.id


def sync_workflow_indicator_publications(
    db: Session,
    investigation: Investigation,
) -> list[ServiceIndicatorArtifactPublication]:
    if investigation.status != "completed" or not investigation.workflow_artifact_version_id:
        return []
    if not investigation.workflow_schedule_event_id:
        return []
    schedule_event = db.get(
        WorkflowScheduleEvent,
        investigation.workflow_schedule_event_id,
    )
    if schedule_event is None:
        raise ValueError("Indicator Workflow schedule occurrence is unavailable")
    activation = db.get(WorkflowScheduleActivation, schedule_event.activation_id)
    if (
        activation is None
        or activation.artifact_version_id
        != investigation.workflow_artifact_version_id
    ):
        raise ValueError("Indicator Workflow schedule provenance does not match")
    bindings = list(
        db.scalars(
            select(ServiceIndicatorArtifactBinding)
            .where(
                ServiceIndicatorArtifactBinding.artifact_version_id
                == investigation.workflow_artifact_version_id,
                ServiceIndicatorArtifactBinding.producer_kind == "workflow",
                ServiceIndicatorArtifactBinding.enabled.is_(True),
            )
            .order_by(ServiceIndicatorArtifactBinding.id)
            .with_for_update()
        ).all()
    )
    publications: list[ServiceIndicatorArtifactPublication] = []
    for binding in bindings:
        existing = db.scalar(
            select(ServiceIndicatorArtifactPublication).where(
                ServiceIndicatorArtifactPublication.binding_id == binding.id,
                ServiceIndicatorArtifactPublication.investigation_id
                == investigation.id,
            )
        )
        if existing is not None:
            publications.append(existing)
            continue
        definition = db.scalar(
            select(ServiceIndicatorDefinition)
            .where(ServiceIndicatorDefinition.id == binding.definition_id)
            .with_for_update()
        )
        if definition is None:
            raise LookupError("Service indicator not found")
        _validate_source(definition, "workflow")
        calls = list(
            db.scalars(
                select(InvestigationToolCall)
                .join(
                    AgentToolRegistration,
                    AgentToolRegistration.id == InvestigationToolCall.tool_id,
                )
                .where(
                    InvestigationToolCall.investigation_id == investigation.id,
                    InvestigationToolCall.status == "succeeded",
                    AgentToolRegistration.name == binding.producer_tool_name,
                )
                .order_by(InvestigationToolCall.finished_at, InvestigationToolCall.id)
            ).all()
        )
        if len(calls) != 1:
            raise ValueError(
                "Indicator Workflow requires exactly one successful producer Tool call"
            )
        call = calls[0]
        tool = _producer_tool(
            db,
            binding.artifact_version,
            binding.producer_tool_name or "",
        )
        if call.tool_id != tool.id or not call.result_hash:
            raise ValueError("Indicator producer Tool call provenance is invalid")
        validate_instance(
            call.result,
            tool.output_schema,
            "indicator producer Tool result",
        )
        mapping = dict(binding.output_mapping or {})
        value = _extract_path(call.result, mapping["value"])
        observed_at = call.finished_at or investigation.finished_at or utcnow()
        if "observed_at" in mapping:
            observed_at = TypeAdapter(datetime).validate_python(
                _extract_path(call.result, mapping["observed_at"])
            )
        dimensions: dict[str, str] = {}
        if "dimensions" in mapping:
            raw_dimensions = _extract_path(call.result, mapping["dimensions"])
            if not isinstance(raw_dimensions, dict):
                raise ValueError("Indicator dimensions result must be an object")
            dimensions = raw_dimensions
        observation = ingest_observation(
            db,
            definition,
            ServiceIndicatorObservationCreate(
                source_observation_id=f"workflow:{binding.id}:{investigation.id}",
                value=value,
                measurement_quality="measured",
                dimensions=dimensions,
                evidence_ref=f"investigation-tool-call:{call.id}",
                observed_at=_as_utc(observed_at),
                actor="agent.workflow",
            ),
            actor="agent.workflow",
            commit=False,
        )
        publications.append(
            _record_publication(
                db,
                binding=binding,
                observation_id=observation.id,
                investigation_id=investigation.id,
                source_tool_call_id=call.id,
            )
        )
    return publications
