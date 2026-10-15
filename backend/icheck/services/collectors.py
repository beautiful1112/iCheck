from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlsplit

from sqlalchemy import exists, func, or_, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql.elements import ColumnElement

from ..collector_schemas import (
    ArtifactCreate,
    ArtifactVersionCreate,
    CollectionEnvelopeBatch,
    CollectorAssignment,
    CollectorDeploymentCreate,
    CredentialGrantRead,
    CredentialProfileCreate,
    CredentialProfileRotate,
    CollectorLeaseClaim,
    CollectorRunAdmit,
    CollectorRunComplete,
    CollectorWorkerHeartbeat,
    CollectorWorkerRegister,
    EnvelopeIngestResult,
)
from ..command_profiles import get_ssh_command_profile
from ..device_preflight_worker import PREFLIGHT_ONLY_ADAPTERS
from ..credentials import validate_secret_reference
from ..database import (
    DEFAULT_REGION_ID,
    DEFAULT_TENANT_ID,
    require_locking_transaction,
    session_namespace,
)
from ..models import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    CollectionEnvelope,
    CollectorCanaryRollout,
    CollectorDefinition,
    CollectorDeployment,
    CollectorDeploymentMode,
    CollectorRun,
    CollectorRunStatus,
    CollectorWorker,
    CollectorWorkerState,
    CredentialProfile,
    Device,
    EnvelopeKind,
    KnowledgeProjection,
    utcnow,
)
from ..schema_validation import validate_instance, validate_schema
from ..sandbox import (
    SandboxExecutor,
    default_sandbox_executor,
    validate_sandbox_implementation,
)
from ..worker_auth import issue_worker_token
from ..worker_mtls import WorkerPeerIdentity
from .audit import record_audit_event
from .worker_mtls import apply_registration_identity
from .runtime_health import (
    reconcile_activated_deployments,
    reconcile_completed_run,
)


SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "community",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _canonical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _assignment_hash(deployment: CollectorDeployment) -> str:
    definition = deployment.artifact_version.collector_definition
    return _canonical_hash({
        "deployment_id": deployment.id,
        "artifact_version_id": deployment.artifact_version_id,
        "target": deployment.target,
        "configuration": deployment.configuration,
        "worker_selector": deployment.worker_selector,
        "credential_profile_ref": (
            deployment.credential_profile_ref
            or (definition.credential_profile_ref if definition else None)
        ),
        "target_classification": deployment.target_classification,
        "scope_device_id": deployment.scope_device_id,
        "scope_device_identity_revision": deployment.scope_device_identity_revision,
        "scope_site": deployment.scope_site,
        "external_source_reason": deployment.external_source_reason,
    })


def _collector_content_material(definition: Any | None) -> dict[str, Any] | None:
    if definition is None:
        return None
    mode = definition.mode
    if hasattr(mode, "value"):
        mode = mode.value
    output_kinds = [
        item.value if hasattr(item, "value") else item
        for item in definition.output_kinds
    ]
    return {
        "adapter_type": definition.adapter_type,
        "mode": mode,
        "output_kinds": output_kinds,
        "credential_profile_ref": definition.credential_profile_ref,
        "config_schema": definition.config_schema,
        "target_schema": definition.target_schema,
        "defaults": definition.defaults,
    }


def artifact_content_material(
    *,
    kind: ArtifactKind,
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
    collector_definition: Any | None,
) -> dict[str, Any]:
    return {
        "kind": kind.value,
        "definition": definition,
        "implementation": implementation,
        "tests": tests,
        "collector": _collector_content_material(collector_definition),
    }


def artifact_content_hash(
    *,
    kind: ArtifactKind,
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
    collector_definition: Any | None,
) -> str:
    return _canonical_hash(
        artifact_content_material(
            kind=kind,
            definition=definition,
            implementation=implementation,
            tests=tests,
            collector_definition=collector_definition,
        )
    )


def artifact_version_content_material(version: ArtifactVersion) -> dict[str, Any]:
    return artifact_content_material(
        kind=version.artifact.kind,
        definition=version.definition,
        implementation=version.implementation,
        tests=version.tests,
        collector_definition=version.collector_definition,
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def assert_no_inline_secrets(value: Any, path: str = "value") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            is_reference = normalized.endswith("_ref") or normalized.endswith(
                "_reference"
            )
            if normalized in SENSITIVE_KEYS and child not in (None, "", [], {}):
                if not is_reference:
                    raise ValueError(
                        f"{path}.{key} contains an inline secret; use a secret reference"
                    )
            assert_no_inline_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_inline_secrets(child, f"{path}[{index}]")


def _collector_definition_from_payload(
    version: ArtifactVersion,
    payload: ArtifactVersionCreate,
) -> CollectorDefinition | None:
    definition = payload.collector_definition
    if definition is None:
        return None
    return CollectorDefinition(
        artifact_version=version,
        adapter_type=definition.adapter_type,
        mode=definition.mode,
        output_kinds=[item.value for item in definition.output_kinds],
        credential_profile_ref=definition.credential_profile_ref,
        config_schema=definition.config_schema,
        target_schema=definition.target_schema,
        defaults=definition.defaults,
    )


def artifact_query():
    return (
        select(Artifact)
        .options(
            selectinload(Artifact.versions).selectinload(
                ArtifactVersion.collector_definition
            )
        )
        .execution_options(populate_existing=True)
    )


def create_artifact(
    db: Session,
    payload: ArtifactCreate,
    *,
    commit: bool = True,
) -> Artifact:
    from .artifact_lifecycle import lock_artifact_identities
    lock_artifact_identities(db, writable=[(payload.kind, payload.name)])
    assert_no_inline_secrets(payload.labels, "labels")
    assert_no_inline_secrets(payload.initial_version.definition, "definition")
    assert_no_inline_secrets(
        payload.initial_version.implementation, "implementation"
    )
    assert_no_inline_secrets(payload.initial_version.tests, "tests")

    artifact = Artifact(
        name=payload.name,
        kind=payload.kind,
        description=payload.description,
        owner=payload.owner,
        labels=payload.labels,
    )
    version = ArtifactVersion(
        artifact=artifact,
        version=1,
        definition=payload.initial_version.definition,
        implementation=payload.initial_version.implementation,
        tests=payload.initial_version.tests,
        created_by=payload.initial_version.created_by,
    )
    collector_definition = _collector_definition_from_payload(
        version, payload.initial_version
    )
    db.add(artifact)
    if collector_definition is not None:
        db.add(collector_definition)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="artifact.created",
            actor_type="user",
            actor_id=payload.initial_version.created_by,
            entity_type="artifact",
            entity_id=artifact.id,
            details={"kind": payload.kind.value, "version": 1},
        )
        if commit:
            db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "An artifact with this kind and name already exists"
        ) from exc
    return get_artifact(db, artifact.id)


def get_artifact(db: Session, artifact_id: str) -> Artifact:
    artifact = db.scalar(
        artifact_query().where(Artifact.id == artifact_id)
    )
    if artifact is None:
        raise LookupError("Artifact not found")
    return artifact


def create_artifact_version(
    db: Session,
    artifact: Artifact,
    payload: ArtifactVersionCreate,
    *,
    commit: bool = True,
) -> Artifact:
    from .artifact_lifecycle import lock_artifact_identities, prepare_artifact_mutation
    prepare_artifact_mutation(db, purpose="Artifact version creation")
    artifact = get_artifact(db, artifact.id)
    lock_artifact_identities(db, writable=[(artifact.kind, artifact.name)])
    if artifact.kind == ArtifactKind.COLLECTOR:
        if payload.collector_definition is None:
            raise ValueError(
                "collector artifacts require a collector_definition"
            )
    elif payload.collector_definition is not None:
        raise ValueError(
            "collector_definition is only valid for collector artifacts"
        )

    assert_no_inline_secrets(payload.definition, "definition")
    assert_no_inline_secrets(payload.implementation, "implementation")
    assert_no_inline_secrets(payload.tests, "tests")
    latest_version = (
        db.scalar(
            select(func.max(ArtifactVersion.version)).where(
                ArtifactVersion.artifact_id == artifact.id
            )
        )
        or 0
    )
    version = ArtifactVersion(
        artifact_id=artifact.id,
        version=latest_version + 1,
        definition=payload.definition,
        implementation=payload.implementation,
        tests=payload.tests,
        created_by=payload.created_by,
    )
    collector_definition = _collector_definition_from_payload(version, payload)
    db.add(version)
    if collector_definition is not None:
        db.add(collector_definition)
    artifact.updated_at = utcnow()
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="artifact.version.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="artifact_version",
            entity_id=version.id,
            details={"artifact_id": artifact.id, "version": version.version},
        )
        if commit:
            db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Artifact version could not be created") from exc
    return get_artifact(db, artifact.id)


def validate_artifact_version(
    db: Session,
    version: ArtifactVersion,
    actor: str,
    *,
    sandbox_executor: SandboxExecutor | None = None,
    commit: bool = True,
) -> ArtifactVersion:
    from .artifact_lifecycle import lock_artifact_version, prepare_artifact_mutation
    prepare_artifact_mutation(db, purpose="Artifact validation")
    version = lock_artifact_version(db, version.id)
    if version.status != ArtifactVersionStatus.DRAFT:
        raise ValueError("Only draft artifact versions can be validated")
    if version.artifact.kind == ArtifactKind.COLLECTOR:
        definition = version.collector_definition
        if definition is None:
            raise ValueError("Collector definition is missing")
        if not definition.output_kinds:
            raise ValueError("Collector must declare at least one output kind")
        invalid_kinds = set(definition.output_kinds) - {
            item.value for item in EnvelopeKind
        }
        if invalid_kinds:
            raise ValueError(
                f"Unsupported collector output kinds: {sorted(invalid_kinds)}"
            )
        from ..collector_condition_schemas import condition_definitions
        conditions = condition_definitions(version.definition)
        if conditions and EnvelopeKind.OBSERVATION.value not in definition.output_kinds:
            raise ValueError("Collector conditions require observation output kind")
        if conditions:
            version.definition = {**version.definition,
                "condition_contracts": [item.model_dump(mode="json") for item in conditions]}
        assert_no_inline_secrets(definition.defaults, "collector.defaults")
        validate_schema(definition.target_schema, "collector.target_schema")
        validate_schema(definition.config_schema, "collector.config_schema")
        if definition.adapter_type == "ssh_command_sandbox":
            profile = get_ssh_command_profile(
                definition.defaults.get("command_profile")
            )
            configuration_properties = definition.config_schema.get(
                "properties"
            )
            required_configuration = definition.config_schema.get("required")
            if (
                not isinstance(configuration_properties, dict)
                or configuration_properties.get("command_profile")
                != {"const": profile.key}
                or not isinstance(required_configuration, list)
                or "command_profile" not in required_configuration
                or definition.config_schema.get("additionalProperties")
                is not False
            ):
                raise ValueError(
                    "ssh_command_sandbox config_schema must require and pin "
                    "the default command_profile with const and reject "
                    "additional properties"
                )
            target_properties = definition.target_schema.get("properties")
            required_target = definition.target_schema.get("required")
            host_schema = (
                target_properties.get("host")
                if isinstance(target_properties, dict)
                else None
            )
            if (
                not isinstance(target_properties, dict)
                or set(target_properties) - {"host", "port"}
                or not isinstance(host_schema, dict)
                or host_schema.get("type") != "string"
                or not isinstance(host_schema.get("minLength"), int)
                or not isinstance(host_schema.get("maxLength"), int)
                or host_schema["minLength"] < 1
                or host_schema["maxLength"] > 255
                or required_target != ["host"]
                or definition.target_schema.get("additionalProperties")
                is not False
            ):
                raise ValueError(
                    "ssh_command_sandbox target_schema must require only a "
                    "bounded host and optional port"
                )
        runtime = version.implementation.get("runtime")
        adapter = version.implementation.get("adapter")
        if (definition.adapter_type == "http_metrics" or version.definition.get("schema") == "icheck.monitoring-template/v1") and runtime != "prometheus_gateway_v1":
            raise ValueError("HTTP monitoring templates require the declarative Prometheus gateway runtime")
        if adapter != definition.adapter_type:
            raise ValueError(
                "Collector implementation adapter must match collector_definition"
            )
        if runtime == "prometheus_gateway_v1":
            from .monitoring_template_contracts import validate_contract
            validation_report = validate_contract(version.definition, version.implementation, version.tests, definition)
        elif runtime == "builtin":
            if set(version.implementation) != {"runtime", "adapter"}:
                raise ValueError(
                    "Built-in implementation requires exactly runtime and adapter"
                )
            validation_report = {
                "runtime": "builtin",
                "isolation": "trusted_builtin",
                "tests_declared": len(version.tests),
            }
        elif runtime == "python_sandbox_v1":
            validate_sandbox_implementation(version.implementation)
            executor = sandbox_executor or default_sandbox_executor()
            validation_report = executor.validate(
                version.implementation,
                version.tests,
                definition.output_kinds,
            )
        else:
            raise ValueError(f"Unsupported collector runtime: {runtime!r}")
        if version.definition.get("schema") == "icheck.snmp-exporter-proposal/v1":
            from .snmp_exporter_proposals import (
                validate_snmp_exporter_proposal_contract,
            )

            validation_report = validate_snmp_exporter_proposal_contract(
                version.definition,
                version.implementation,
                version.tests,
                definition,
            )
        elif version.definition.get("schema") == "icheck.snmp-exporter-attested/v1":
            from .snmp_exporter_attestations import (
                validate_snmp_exporter_attested_contract,
            )

            validation_report = validate_snmp_exporter_attested_contract(
                db,
                version,
            )
    elif version.artifact.kind == ArtifactKind.WORKFLOW:
        from .workflow_templates import validate_workflow_artifact_contract

        validation_report = validate_workflow_artifact_contract(
            db,
            version.definition,
            version.implementation,
            version.tests,
        )
    elif version.artifact.kind == ArtifactKind.TOPOLOGY:
        from .topology_views import validate_topology_artifact_contract

        validation_report = validate_topology_artifact_contract(
            db,
            version.definition,
            version.implementation,
            version.tests,
        )
    elif version.artifact.kind == ArtifactKind.VISUALIZATION:
        from .service_indicator_visualizations import (
            validate_visualization_artifact_contract,
        )

        validation_report = validate_visualization_artifact_contract(
            db,
            version.definition,
            version.implementation,
            version.tests,
        )
    elif version.artifact.kind == ArtifactKind.REPORT:
        if (
            version.definition.get("format_version")
            in {"icheck.service-health-report/v1", "icheck.service-health-report/v2"}
        ):
            from .service_health_reports import (
                validate_service_report_artifact_contract,
            )

            validation_report = validate_service_report_artifact_contract(
                db,
                version.definition,
                version.implementation,
                version.tests,
            )
        else:
            validation_report = {
                "runtime": "declarative",
                "isolation": "not_executable",
                "tests_declared": len(version.tests),
            }
    elif version.artifact.kind == ArtifactKind.TOOL:
        if version.definition.get("format_version") == "icheck.mcp-extension/v1":
            from .mcp_extensions import validate_extension_contract
            validation_report = validate_extension_contract(version.definition, version.implementation,
                version.tests, sandbox_executor=sandbox_executor)
        else:
            from .tool_skills import validate_tool_artifact_contract
            validation_report = validate_tool_artifact_contract(
                version.definition, version.implementation, version.tests)
    elif version.artifact.kind == ArtifactKind.SKILL:
        from .tool_skills import validate_skill_artifact_contract

        validation_report = validate_skill_artifact_contract(
            db,
            version.definition,
            version.implementation,
            version.tests,
        )
    else:
        validation_report = {
            "runtime": "declarative",
            "isolation": "not_executable",
            "tests_declared": len(version.tests),
        }

    version.content_hash = _canonical_hash(
        artifact_version_content_material(version)
    )
    version.validation_report = validation_report
    version.status = ArtifactVersionStatus.VALIDATED
    version.validated_at = utcnow()
    version.validated_by = actor
    record_audit_event(
        db,
        event_type="artifact.version.validated",
        actor_type="user",
        actor_id=actor,
        entity_type="artifact_version",
        entity_id=version.id,
        details={
            "artifact_id": version.artifact_id,
            "content_hash": version.content_hash,
            "runtime": validation_report["runtime"],
            "sandbox_test_count": len(validation_report.get("tests", [])),
        },
    )
    if commit:
        db.commit()
        db.refresh(version)
    else:
        db.flush()
    return version


def publish_artifact_version(
    db: Session,
    version: ArtifactVersion,
    actor: str,
    *,
    commit: bool = True,
    canary_promotion: bool = False,
) -> ArtifactVersion:
    from .artifact_lifecycle import assert_version_retirement_allowed, lock_artifact_version, prepare_artifact_mutation
    prepare_artifact_mutation(db, purpose="Artifact publication")
    version = lock_artifact_version(db, version.id)
    from .capability_pack_revocations import (
        assert_artifact_version_not_revoked,
    )

    assert_artifact_version_not_revoked(db, version.id)
    from .snmp_exporter_proposals import assert_artifact_publication_ready

    assert_artifact_publication_ready(version.definition)
    from .snmp_exporter_attestations import (
        assert_snmp_exporter_attested_publication_ready,
    )

    assert_snmp_exporter_attested_publication_ready(
        db,
        version,
        canary_promotion=canary_promotion,
    )
    if version.status != ArtifactVersionStatus.VALIDATED:
        raise ValueError("Only validated artifact versions can be published")
    if not canary_promotion:
        rollout = db.scalar(
            select(CollectorCanaryRollout.id).where(
                CollectorCanaryRollout.candidate_version_id == version.id
            )
        )
        if rollout is not None:
            raise ValueError(
                "A canary-managed candidate must be published through rollout promotion"
            )
    previous = db.scalars(
        select(ArtifactVersion).where(
            ArtifactVersion.artifact_id == version.artifact_id,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
        ).execution_options(populate_existing=True)
    ).all()
    assert_version_retirement_allowed(db, [item.id for item in previous])
    for item in previous:
        item.status = ArtifactVersionStatus.DEPRECATED
    version.status = ArtifactVersionStatus.PUBLISHED
    version.published_at = utcnow()
    version.published_by = actor
    record_audit_event(
        db,
        event_type="artifact.version.published",
        actor_type="user",
        actor_id=actor,
        entity_type="artifact_version",
        entity_id=version.id,
        details={
            "artifact_id": version.artifact_id,
            "deprecated_version_ids": [item.id for item in previous],
        },
    )
    if commit:
        try:
            db.commit()
        except DBAPIError:
            db.rollback()
            raise
        db.refresh(version)
    else:
        db.flush()
    return version


def validate_deployment_payload(
    db: Session,
    payload: CollectorDeploymentCreate,
    *,
    allowed_statuses: set[ArtifactVersionStatus] | None = None,
) -> tuple[ArtifactVersion, str | None]:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == payload.artifact_version_id)
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
    )
    if version is None:
        raise LookupError("Artifact version not found")
    if version.artifact.kind != ArtifactKind.COLLECTOR:
        raise ValueError("Only collector artifacts can be deployed")
    if (version.implementation.get("runtime") == "prometheus_gateway_v1"
            or (version.collector_definition and version.collector_definition.adapter_type == "http_metrics")):
        raise ValueError("Prometheus monitoring templates use device target tests and monitoring approval, not SQL collector deployments")
    allowed_statuses = allowed_statuses or {ArtifactVersionStatus.PUBLISHED}
    if version.status not in allowed_statuses:
        allowed = ", ".join(sorted(item.value for item in allowed_statuses))
        raise ValueError(f"Collector version status must be one of: {allowed}")
    if version.collector_definition is None:
        raise ValueError("Collector definition is missing")
    assert_no_inline_secrets(payload.target, "target")
    assert_no_inline_secrets(payload.configuration, "configuration")
    assert_no_inline_secrets(payload.worker_selector, "worker_selector")
    definition = version.collector_definition
    validate_instance(
        payload.target,
        definition.target_schema,
        "collector target",
    )
    validate_instance(
        {**definition.defaults, **payload.configuration},
        definition.config_schema,
        "collector configuration",
    )
    credential_ref = (
        payload.credential_profile_ref
        or definition.credential_profile_ref
    )
    if (
        definition.adapter_type == "psrp_cim"
        and payload.execution_mode != CollectorDeploymentMode.ON_DEMAND
    ):
        raise ValueError("psrp_cim deployments must use on_demand execution")
    if (
        definition.adapter_type in {"psrp_cim", "ssh_command_sandbox"}
        and not credential_ref
    ):
        raise ValueError(
            f"{definition.adapter_type} deployments require a "
            "credential_profile_ref"
        )
    if credential_ref:
        profile = db.scalar(
            select(CredentialProfile).where(
                or_(
                    CredentialProfile.id == credential_ref,
                    CredentialProfile.name == credential_ref,
                )
            )
        )
        if profile is None:
            raise ValueError(
                f"Credential profile {credential_ref!r} does not exist"
            )
        if not profile.enabled:
            raise ValueError(
                f"Credential profile {credential_ref!r} is disabled"
            )
        if definition.adapter_type not in profile.allowed_adapters:
            raise ValueError(
                f"Credential profile {credential_ref!r} does not allow "
                f"adapter {definition.adapter_type!r}"
            )
        for key, expected in profile.worker_selector.items():
            if payload.worker_selector.get(key) != expected:
                raise ValueError(
                    f"Deployment worker_selector must include {key}={expected!r} "
                    f"for credential profile {credential_ref!r}"
                )

    scoped_device_id = payload.scope_device_id or payload.target.get("device_id")
    classification = payload.target_classification
    generated = (
        isinstance(version.artifact.labels, dict)
        and version.artifact.labels.get("generated") is True
    )
    if generated and classification is None:
        raise ValueError(
            "Studio-generated Collectors require an explicit target_classification"
        )
    if classification == "registered_device" and not scoped_device_id:
        raise ValueError("Registered-device targets require scope_device_id")
    if classification == "external_source":
        if scoped_device_id:
            raise ValueError("External-source targets cannot declare a device ID")
        reason = (payload.external_source_reason or "").strip()
        if len(reason) < 10:
            raise ValueError("External-source targets require an operator reason")
        assert_no_inline_secrets({"reason": reason}, "external_source_reason")
    elif payload.external_source_reason is not None:
        raise ValueError("external_source_reason requires external_source classification")

    return version, credential_ref


def _target_hosts(target: dict[str, Any]) -> set[str]:
    hosts: set[str] = set()
    for key in ("url", "exporter_url"):
        value = target.get(key)
        if not isinstance(value, str):
            continue
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Collector target {key} must be an HTTP(S) URL")
        if key == "url":
            try:
                hosts.add(str(ipaddress.ip_address(parsed.hostname)))
            except ValueError:
                hosts.add(parsed.hostname.lower())
    for key in ("host", "target"):
        value = target.get(key)
        if isinstance(value, str) and value.strip():
            host = value.strip()
            try:
                host = str(ipaddress.ip_address(host.strip("[]")))
            except ValueError:
                if host.startswith("[") and "]:" in host:
                    host = host[1:host.index("]")]
                elif host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
                    host = host.rsplit(":", 1)[0]
            hosts.add(host.lower())
    return hosts


class CollectorTargetBusy(RuntimeError):
    """An inventory writer currently owns an external target identity fence."""


def _lock_external_target_hosts(
    db: Session, deployment: CollectorDeployment, *, nowait: bool = False,
) -> None:
    """Fence an absent inventory host against concurrent Device identity writes.

    The PostgreSQL Device trigger takes these same transaction-scoped keys on
    INSERT/DELETE and identity changes. Acquire keys in numeric order to avoid
    cycles when a Collector target names multiple hosts.
    """
    if deployment.target_classification != "external_source":
        return
    if db.get_bind().dialect.name != "postgresql":
        return  # SQLite serializes writers; it is not concurrency acceptance.
    require_locking_transaction(db, purpose="External Collector target review")
    namespace = session_namespace(db) or (
        deployment.tenant_id or DEFAULT_TENANT_ID,
        deployment.region_id or DEFAULT_REGION_ID,
    )
    keys = set()
    for host in _target_hosts(deployment.target):
        material = "|".join(("icheck.device-host/v1", *namespace, host))
        keys.add(db.scalar(text("SELECT hashtextextended(:material, 0)"), {
            "material": material,
        }))
    for key in sorted(keys):
        if nowait:
            if not db.scalar(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": key}):
                raise CollectorTargetBusy("External Collector target identity is busy")
        else:
            db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})


def _generated_registered_target_matches_device(
    target: dict[str, Any], device: Any,
) -> bool:
    """A generated direct-device target must name only the bound inventory endpoint.

    API proxies and DNS aliases not represented by the Device name belong to
    the external-source path until an independent alias review exists.
    """
    hosts = _target_hosts(target)
    if not hosts:
        return False
    known_hosts = {str(device.management_ip).lower(), str(device.name).lower()}
    return hosts.issubset(known_hosts)


def _target_host_conflict(
    db: Session,
    deployment: CollectorDeployment,
    *,
    scoped_device: Any | None = None,
) -> bool:
    hosts = _target_hosts(deployment.target)
    if not hosts:
        return False
    if scoped_device is not None:
        for host in hosts:
            try:
                normalized_ip = str(ipaddress.ip_address(host))
            except ValueError:
                continue
            if normalized_ip != scoped_device.management_ip:
                return True
    namespace = (
        (scoped_device.tenant_id, scoped_device.region_id)
        if scoped_device is not None
        else session_namespace(db) or (
            deployment.tenant_id or DEFAULT_TENANT_ID,
            deployment.region_id or DEFAULT_REGION_ID,
        )
    )
    matched_ids = set(db.scalars(
        select(Device.id).where(
            Device.tenant_id == namespace[0],
            Device.region_id == namespace[1],
            or_(
                Device.management_ip.in_(hosts),
                func.lower(Device.name).in_(hosts),
            ),
        )
    ).all())
    return any(
        matched_id != scoped_device.id if scoped_device is not None else True
        for matched_id in matched_ids
    )


def create_deployment(
    db: Session,
    payload: CollectorDeploymentCreate,
    *,
    commit: bool = True,
    allowed_statuses: set[ArtifactVersionStatus] | None = None,
) -> CollectorDeployment:
    version, credential_ref = validate_deployment_payload(
        db,
        payload,
        allowed_statuses=allowed_statuses,
    )
    scope_device_id = (
        payload.scope_device_id
        or (
            str(payload.target["device_id"])
            if payload.target.get("device_id")
            else None
        )
    )
    target_device_id = payload.target.get("device_id")
    if (
        payload.scope_device_id is not None
        and target_device_id is not None
        and str(target_device_id) != payload.scope_device_id
    ):
        raise ValueError("Deployment target.device_id does not match scope_device_id")
    device = None
    if scope_device_id is not None:
        if payload.scope_device_identity_revision is None:
            raise ValueError(
                "Device-scoped deployments require scope_device_identity_revision"
            )
        device = db.scalar(
            select(Device).where(Device.id == scope_device_id).with_for_update()
        )
        if device is None:
            raise LookupError("Scoped device not found")
        namespace = session_namespace(db)
        if namespace is not None and (
            device.tenant_id, device.region_id
        ) != namespace:
            raise LookupError("Scoped device not found in the selected namespace")
        if device.identity_revision != payload.scope_device_identity_revision:
            raise ValueError(
                "Device identity changed; preview the deployment against the current device"
            )
        if payload.enabled and not device.enabled:
            raise ValueError("Cannot enable a deployment for a disabled device")
    elif payload.scope_device_identity_revision is not None:
        raise ValueError(
            "scope_device_identity_revision requires scope_device_id"
        )

    deployment_values = payload.model_dump()
    deployment_values["credential_profile_ref"] = credential_ref
    deployment_values["scope_device_id"] = scope_device_id
    scope_site = (
        payload.scope_site
        or (
            str(payload.worker_selector["site"])
            if payload.worker_selector.get("site")
            else None
        )
        or (
            str(payload.target["site"])
            if payload.target.get("site")
            else None
        )
    )
    if device is not None:
        site_hints = (
            payload.scope_site,
            payload.worker_selector.get("site"),
            payload.target.get("site"),
        )
        if any(hint is not None and str(hint) != device.site for hint in site_hints):
            raise ValueError("Deployment site does not match the scoped device")
        scope_site = device.site
    deployment_values["scope_site"] = scope_site
    deployment = CollectorDeployment(**deployment_values)
    _lock_external_target_hosts(db, deployment)
    if payload.target_classification is not None and _target_host_conflict(
        db, deployment, scoped_device=device,
    ):
        raise ValueError(
            "Collector target resolves to a different registered device; review the target binding"
        )
    if (
        isinstance(version.artifact.labels, dict)
        and version.artifact.labels.get("generated") is True
        and payload.target_classification == "registered_device"
        and not _generated_registered_target_matches_device(payload.target, device)
    ):
        raise ValueError(
            "Generated registered-device target host must match the Device management IP "
            "or name; classify unrelated API endpoints as external sources"
        )
    db.add(deployment)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="collector.deployment.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="collector_deployment",
            entity_id=deployment.id,
            details={
                "artifact_version_id": version.id,
                "execution_mode": deployment.execution_mode.value,
                "credential_profile_configured": credential_ref is not None,
                "scope_device_identity_revision": (
                    deployment.scope_device_identity_revision
                ),
                "target_classification": deployment.target_classification,
                "external_source_reason_sha256": (
                    hashlib.sha256(deployment.external_source_reason.encode()).hexdigest()
                    if deployment.external_source_reason else None
                ),
            },
        )
        if commit:
            db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Collector deployment name already exists") from exc
    if commit:
        db.refresh(deployment)
    return deployment


def _deployment_device_identity_current(
    db: Session, deployment: CollectorDeployment
) -> bool:
    if deployment.target_classification == "legacy_unreviewed":
        return False
    artifact = deployment.artifact_version.artifact
    generated = (
        isinstance(artifact.labels, dict)
        and artifact.labels.get("generated") is True
    )
    if generated and deployment.target_classification not in {
        "registered_device", "external_source",
    }:
        return False
    if deployment.scope_device_id is None:
        if deployment.target_classification == "registered_device":
            return False
        if deployment.target_classification == "external_source":
            if not deployment.external_source_reason or len(
                deployment.external_source_reason.strip()
            ) < 10:
                return False
            try:
                _lock_external_target_hosts(db, deployment)
                return not _target_host_conflict(db, deployment)
            except ValueError:
                return False
        return deployment.scope_device_identity_revision is None
    if deployment.target_classification == "external_source":
        return False
    state = db.execute(
        select(
            Device.id,
            Device.name,
            Device.identity_revision,
            Device.site,
            Device.enabled,
            Device.management_ip,
            Device.tenant_id,
            Device.region_id,
        ).where(
            Device.id == deployment.scope_device_id,
            Device.tenant_id == deployment.tenant_id,
            Device.region_id == deployment.region_id,
        )
    ).one_or_none()
    if state is None:
        return False
    try:
        host_conflict = _target_host_conflict(db, deployment, scoped_device=state)
        direct_host_current = (
            not generated
            or deployment.target_classification != "registered_device"
            or _generated_registered_target_matches_device(deployment.target, state)
        )
    except ValueError:
        return False
    return bool(
        deployment.scope_device_identity_revision is not None
        and deployment.scope_device_identity_revision > 0
        and state.identity_revision == deployment.scope_device_identity_revision
        and state.site == deployment.scope_site
        and state.enabled
        and not host_conflict
        and direct_host_current
    )


def trigger_deployment(
    db: Session,
    deployment_id: str,
    *,
    actor: str,
    reason: str,
    actor_type: Literal["agent", "service", "user"] = "user",
) -> CollectorDeployment:
    deployment = db.scalar(
        select(CollectorDeployment)
        .where(CollectorDeployment.id == deployment_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if deployment is None:
        raise LookupError("Collector deployment not found")
    if deployment.execution_mode != CollectorDeploymentMode.ON_DEMAND:
        raise ValueError("Only on-demand deployments can be triggered")
    if not deployment.enabled:
        raise ValueError("Collector deployment is disabled")
    if not _deployment_device_identity_current(db, deployment):
        raise ValueError("Device identity changed; review and redeploy the collector")
    now = utcnow()
    if (
        deployment.lease_expires_at is not None
        and _as_utc(deployment.lease_expires_at) >= now
    ):
        raise ValueError("Collector deployment is already running")
    deployment.next_run_at = now
    deployment.updated_at = now
    record_audit_event(
        db,
        event_type="collector.deployment.triggered",
        actor_type=actor_type,
        actor_id=actor,
        entity_type="collector_deployment",
        entity_id=deployment.id,
        details={"reason": reason},
    )
    db.commit()
    db.refresh(deployment)
    return deployment


def register_worker(
    db: Session,
    payload: CollectorWorkerRegister,
    *,
    peer_identity: WorkerPeerIdentity | None = None,
    mtls_mode: Literal["disabled", "optional", "required"] = "disabled",
) -> tuple[CollectorWorker, str]:
    require_locking_transaction(db, purpose="Collector Worker registration")
    worker = db.scalar(
        select(CollectorWorker).where(CollectorWorker.name == payload.name)
        .with_for_update().execution_options(populate_existing=True)
    )
    now = utcnow()
    access_token, access_token_hash = issue_worker_token()
    rotated = worker is not None
    if worker is None:
        worker = CollectorWorker(
            **payload.model_dump(),
            auth_token_hash=access_token_hash,
            token_issued_at=now,
        )
        db.add(worker)
        db.flush()
        apply_registration_identity(
            db,
            worker,
            peer_identity,
            kind="collector",
            mode=mtls_mode,
        )
    else:
        apply_registration_identity(
            db,
            worker,
            peer_identity,
            kind="collector",
            mode=mtls_mode,
        )
        worker.site = payload.site
        worker.capabilities = payload.capabilities
        worker.labels = payload.labels
        if worker.state != CollectorWorkerState.DRAINING:
            worker.state = CollectorWorkerState.ONLINE
        worker.auth_token_hash = access_token_hash
        worker.token_issued_at = now
        worker.updated_at = now
    worker.last_heartbeat_at = now
    db.flush()
    record_audit_event(
        db,
        event_type="collector.worker.registered",
        actor_type="worker",
        actor_id=worker.name,
        entity_type="collector_worker",
        entity_id=worker.id,
        details={
            "token_rotated": rotated,
            "site": worker.site,
            "mtls_bound": worker.mtls_fingerprint_sha256 is not None,
            "mtls_revision": worker.mtls_revision,
        },
    )
    db.commit()
    db.refresh(worker)
    return worker, access_token


def create_credential_profile(
    db: Session,
    payload: CredentialProfileCreate,
) -> CredentialProfile:
    if "ai_provider" in payload.allowed_adapters:
        from .ai_catalog_mutex import catalog_lock
        catalog_lock(db)
    if payload.provider in {"managed_device", "managed_ai"}:
        raise ValueError("Use the dedicated secure credential setup for managed credentials")
    assert_no_inline_secrets(payload.worker_selector, "worker_selector")
    secret_ref = validate_secret_reference(payload.provider, payload.secret_ref)
    profile = CredentialProfile(
        **payload.model_dump(exclude={"secret_ref"}),
        secret_ref=secret_ref,
    )
    db.add(profile)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="credential.profile.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="credential_profile",
            entity_id=profile.id,
            details={
                "provider": profile.provider,
                "allowed_adapters": profile.allowed_adapters,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Credential profile name already exists") from exc
    db.refresh(profile)
    return profile


def rotate_credential_profile(
    db: Session,
    profile: CredentialProfile,
    payload: CredentialProfileRotate,
) -> CredentialProfile:
    if "ai_provider" in profile.allowed_adapters:
        from .ai_catalog_mutex import catalog_lock
        catalog_lock(db)
    if profile.provider in {"managed_device", "managed_ai"}:
        raise ValueError("Use the dedicated secure credential setup to rotate managed credentials")
    secret_ref = validate_secret_reference(profile.provider, payload.secret_ref)
    if secret_ref == profile.secret_ref:
        raise ValueError("Credential reference rotation must change the reference")
    old_ref_hash = _token_hash(profile.secret_ref)
    new_ref_hash = _token_hash(secret_ref)
    rotated = db.execute(
        update(CredentialProfile)
        .execution_options(synchronize_session=False)
        .where(
            CredentialProfile.id == profile.id,
            CredentialProfile.revision == payload.expected_revision,
        )
        .values(
            secret_ref=secret_ref,
            revision=payload.expected_revision + 1,
            updated_at=utcnow(),
        )
    )
    if rotated.rowcount != 1:
        db.rollback()
        raise ValueError("Credential profile revision conflict")
    record_audit_event(
        db,
        event_type="credential.profile.rotated",
        actor_type="user",
        actor_id=payload.actor,
        entity_type="credential_profile",
        entity_id=profile.id,
        details={
            "provider": profile.provider,
            "previous_revision": payload.expected_revision,
            "revision": payload.expected_revision + 1,
            "previous_ref_sha256": old_ref_hash,
            "new_ref_sha256": new_ref_hash,
            "reason_sha256": _token_hash(payload.reason),
        },
    )
    db.commit()
    db.refresh(profile)
    return profile


def heartbeat_worker(
    db: Session,
    worker: CollectorWorker,
    payload: CollectorWorkerHeartbeat,
) -> CollectorWorker:
    from .worker_registry import lock_worker_registry
    worker = lock_worker_registry(db, worker)
    requested_state = CollectorWorkerState(payload.state)
    if not (
        worker.state == CollectorWorkerState.DRAINING
        and requested_state == CollectorWorkerState.ONLINE
    ):
        worker.state = requested_state
    if payload.capabilities is not None:
        worker.capabilities = list(dict.fromkeys(payload.capabilities))
    if payload.labels is not None:
        worker.labels = payload.labels
    worker.last_heartbeat_at = utcnow()
    worker.updated_at = utcnow()
    db.commit()
    db.refresh(worker)
    return worker


def claim_deployments(
    db: Session,
    worker: CollectorWorker,
    payload: CollectorLeaseClaim,
) -> list[CollectorAssignment]:
    require_locking_transaction(db, purpose="Collector lease claims")
    from .worker_registry import lock_worker_registry
    worker = lock_worker_registry(db, worker)
    if worker.state != CollectorWorkerState.ONLINE:
        raise ValueError("Only online workers can claim deployments")
    # Only updated Linux Workers can bind adapter children to the parent
    # lifetime. Never hand an unmarked Worker a Collector deployment lease.
    if worker.labels.get("io_supervisor_v1") is not True:
        return []
    reconcile_activated_deployments(db)
    from .canary_rollouts import reconcile_timed_out_rollouts

    reconcile_timed_out_rollouts(db, commit=False)
    now = utcnow()
    lease_expires_at = now + timedelta(seconds=payload.lease_seconds)
    candidates = db.scalars(
        select(CollectorDeployment)
        .join(CollectorDeployment.artifact_version)
        .join(ArtifactVersion.collector_definition)
        .where(
            CollectorDeployment.enabled.is_(True),
            CollectorDeployment.next_run_at.is_not(None),
            CollectorDeployment.next_run_at <= now,
            or_(
                CollectorDeployment.lease_expires_at.is_(None),
                CollectorDeployment.lease_expires_at < now,
            ),
            or_(
                ArtifactVersion.status.in_(
                    [
                        ArtifactVersionStatus.PUBLISHED,
                        ArtifactVersionStatus.DEPRECATED,
                    ]
                ),
                (
                    (ArtifactVersion.status == ArtifactVersionStatus.VALIDATED)
                    & exists(
                        select(CollectorCanaryRollout.id).where(
                            CollectorCanaryRollout.deployment_id
                            == CollectorDeployment.id,
                            CollectorCanaryRollout.status == "running",
                        )
                    )
                ),
            ),
            CollectorDefinition.adapter_type.in_(worker.capabilities),
            CollectorDefinition.adapter_type.not_in(PREFLIGHT_ONLY_ADAPTERS),
        )
        .options(
            selectinload(CollectorDeployment.artifact_version).selectinload(
                ArtifactVersion.artifact
            ),
            selectinload(CollectorDeployment.artifact_version).selectinload(
                ArtifactVersion.collector_definition
            ),
        )
        .order_by(CollectorDeployment.next_run_at, CollectorDeployment.id)
        .limit(payload.max_assignments * 4)
    ).all()

    assignments: list[CollectorAssignment] = []
    for candidate in candidates:
        if len(assignments) >= payload.max_assignments:
            break
        worker_labels = {
            **worker.labels,
            **({"site": worker.site} if worker.site else {}),
        }
        if any(
            worker_labels.get(key) != expected
            for key, expected in candidate.worker_selector.items()
        ):
            continue
        if candidate.scope_device_id is not None and worker.site != candidate.scope_site:
            continue
        if (
            candidate.target_classification == "external_source"
            and worker.labels.get("execution_admission_v1") is not True
        ):
            continue
        token = secrets.token_urlsafe(32)
        token_hash = _token_hash(token)
        previous_last_started_at = candidate.last_started_at
        claimed = db.execute(
            update(CollectorDeployment)
            .execution_options(synchronize_session=False)
            .where(
                CollectorDeployment.id == candidate.id,
                CollectorDeployment.enabled.is_(True),
                CollectorDeployment.next_run_at.is_not(None),
                CollectorDeployment.next_run_at <= now,
                or_(
                    CollectorDeployment.lease_expires_at.is_(None),
                    CollectorDeployment.lease_expires_at < now,
                ),
            )
            .values(
                lease_worker_id=worker.id,
                lease_token_hash=token_hash,
                lease_expires_at=lease_expires_at,
                last_started_at=now,
                updated_at=now,
            )
        )
        if claimed.rowcount != 1:
            continue

        # The UPDATE may wait on a deployment edit while retaining an older
        # PostgreSQL statement snapshot. Reload the exact row after the wait;
        # otherwise the Worker could receive the old target or selector.
        candidate = db.scalar(
            select(CollectorDeployment)
            .where(CollectorDeployment.id == candidate.id)
            .options(
                selectinload(CollectorDeployment.artifact_version).selectinload(
                    ArtifactVersion.artifact
                ),
                selectinload(CollectorDeployment.artifact_version).selectinload(
                    ArtifactVersion.collector_definition
                ),
            )
            .execution_options(populate_existing=True)
        )
        if candidate is None:
            raise RuntimeError("Claimed Collector deployment disappeared")
        # The winning UPDATE replaced an expired lease. Finalize its old run
        # even when a later selector or identity check refuses this new claim;
        # otherwise no lease remains for the background sweeper to discover.
        from .collector_lease_reconciliation import cancel_abandoned_runs

        cancel_abandoned_runs(db, candidate, now=now)
        if (
            not candidate.enabled
            or any(worker_labels.get(key) != expected
                for key, expected in candidate.worker_selector.items())
            or (candidate.scope_device_id is not None
                and worker.site != candidate.scope_site)
            or (candidate.target_classification == "external_source"
                and worker.labels.get("execution_admission_v1") is not True)
        ):
            db.execute(
                update(CollectorDeployment)
                .execution_options(synchronize_session=False)
                .where(
                    CollectorDeployment.id == candidate.id,
                    CollectorDeployment.lease_token_hash == token_hash,
                )
                .values(
                    lease_worker_id=None,
                    lease_token_hash=None,
                    lease_expires_at=None,
                    last_started_at=previous_last_started_at,
                    updated_at=now,
                )
            )
            continue

        # Read the Device and external host inventory in a new statement after
        # winning the row lock, before issuing the Worker token.
        if not _deployment_device_identity_current(db, candidate):
            db.execute(
                update(CollectorDeployment)
                .execution_options(synchronize_session=False)
                .where(
                    CollectorDeployment.id == candidate.id,
                    CollectorDeployment.lease_token_hash == token_hash,
                )
                .values(
                    enabled=False,
                    next_run_at=None,
                    lease_worker_id=None,
                    lease_token_hash=None,
                    lease_expires_at=None,
                    last_started_at=previous_last_started_at,
                    updated_at=now,
                )
            )
            record_audit_event(
                db,
                event_type="collector.deployment.identity_stale",
                actor_type="service",
                actor_id="collector.lease_claim",
                entity_type="collector_deployment",
                entity_id=candidate.id,
                outcome="failure",
                details={
                    "scope_device_id": candidate.scope_device_id,
                    "scope_device_identity_revision": (
                        candidate.scope_device_identity_revision
                    ),
                },
            )
            continue

        run = CollectorRun(
            deployment_id=candidate.id,
            artifact_version_id=candidate.artifact_version_id,
            worker_id=worker.id,
            lease_token_hash=token_hash,
            assignment_sha256=_assignment_hash(candidate),
            target_classification_snapshot=candidate.target_classification,
            status=CollectorRunStatus.RUNNING,
            started_at=now,
        )
        db.add(run)
        db.flush()
        record_audit_event(
            db,
            event_type="collector.run.claimed",
            actor_type="worker",
            actor_id=worker.id,
            entity_type="collector_run",
            entity_id=run.id,
            details={
                "deployment_id": candidate.id,
                "artifact_version_id": candidate.artifact_version_id,
            },
        )
        version = candidate.artifact_version
        definition = version.collector_definition
        if definition is None:
            raise RuntimeError("Published collector has no collector definition")
        assignments.append(
            CollectorAssignment(
                run_id=run.id,
                lease_token=token,
                assignment_sha256=run.assignment_sha256,
                lease_expires_at=lease_expires_at,
                deployment_id=candidate.id,
                deployment_name=candidate.name,
                artifact_id=version.artifact.id,
                artifact_name=version.artifact.name,
                artifact_version_id=version.id,
                artifact_version=version.version,
                adapter_type=definition.adapter_type,
                mode=definition.mode,
                output_kinds=definition.output_kinds,
                target=candidate.target,
                configuration=candidate.configuration,
                definition=version.definition,
                implementation=version.implementation,
                defaults=definition.defaults,
                credential_profile_ref=(
                    candidate.credential_profile_ref
                    or definition.credential_profile_ref
                ),
            )
        )
    worker.last_heartbeat_at = now
    db.commit()
    return assignments


def _cancel_reviewed_run_for_drift(
    db: Session, run: CollectorRun, *, external: bool,
    worker_scope: bool = False,
) -> None:
    """Revoke a reviewed external or Device-bound lease before stale I/O continues."""
    now = utcnow()
    deployment = run.deployment
    reason_code = (
        "worker_scope_changed" if worker_scope else
        "target_ownership_drift" if external else "device_target_drift"
    )
    subject = "External Collector" if external else "Device Collector"
    run.status = CollectorRunStatus.CANCELLED
    run.finished_at = now
    run.error = (
        f"{subject} Worker scope changed after claim" if worker_scope
        else f"{subject} target ownership changed after claim"
    )
    run.stats = {"cancel_reason": reason_code}
    if not worker_scope:
        deployment.enabled = False
        deployment.next_run_at = None
    deployment.lease_worker_id = None
    deployment.lease_token_hash = None
    deployment.lease_expires_at = None
    deployment.last_finished_at = now
    deployment.updated_at = now
    reconcile_completed_run(db, run)
    from .canary_rollouts import reconcile_canary_run

    reconcile_canary_run(db, run)
    record_audit_event(
        db,
        event_type=(
            "collector.run.cancelled_worker_scope" if worker_scope
            else "collector.run.cancelled_target_drift"
        ),
        actor_type="service",
        actor_id="collector.execution_admission",
        entity_type="collector_run",
        entity_id=run.id,
        outcome="failure",
        details={
            "deployment_id": deployment.id,
            "assignment_sha256": run.assignment_sha256,
            "target_classification_at_claim": run.target_classification_snapshot,
            "reason_code": reason_code,
        },
    )
    db.commit()


def _active_run_for_token(
    db: Session, run_id: str, lease_token: str, *, require_admitted: bool = True,
) -> CollectorRun:
    require_locking_transaction(db, purpose="Collector run mutations")
    run = db.scalar(
        select(CollectorRun)
        .where(CollectorRun.id == run_id)
        .options(selectinload(CollectorRun.deployment))
    )
    if run is None:
        raise LookupError("Collector run not found")
    # All run mutations take the deployment row before the run row. This
    # serializes late Worker calls with expiry reconciliation and reassignment.
    # External runs subsequently take the host key for inventory revalidation.
    deployment = db.scalar(
        select(CollectorDeployment)
        .where(CollectorDeployment.id == run.deployment_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if deployment is None:
        raise LookupError("Collector deployment not found")
    run = db.scalar(
        select(CollectorRun)
        .where(CollectorRun.id == run_id)
        .options(selectinload(CollectorRun.deployment))
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if run is None:
        raise LookupError("Collector run not found")
    external = (
        run.target_classification_snapshot == "external_source"
        or deployment.target_classification == "external_source"
    )
    device_scoped = (
        run.target_classification_snapshot == "registered_device"
        or deployment.target_classification == "registered_device"
        or deployment.scope_device_id is not None
    )
    token_hash = _token_hash(lease_token)
    if run.status != CollectorRunStatus.RUNNING:
        raise ValueError("Collector run is no longer active")
    if not secrets.compare_digest(run.lease_token_hash, token_hash):
        raise ValueError("Invalid collector lease token")
    deployment = run.deployment
    if (
        deployment.lease_worker_id != run.worker_id
        or deployment.lease_token_hash is None
        or not secrets.compare_digest(deployment.lease_token_hash, token_hash)
    ):
        raise ValueError("Collector lease is no longer owned by this run")
    if (
        deployment.lease_expires_at is None
        or _as_utc(deployment.lease_expires_at) < utcnow()
    ):
        raise ValueError("Collector lease has expired")
    if run.worker.labels.get("io_supervisor_v1") is not True:
        raise ValueError("Collector Worker requires supervised adapter I/O")
    if external or device_scoped:
        if (
            not run.assignment_sha256
            or run.assignment_sha256 != _assignment_hash(deployment)
            or not deployment.enabled
            or not _deployment_device_identity_current(db, deployment)
        ):
            _cancel_reviewed_run_for_drift(db, run, external=external)
            subject = "External Collector" if external else "Device Collector"
            raise ValueError(f"{subject} target ownership changed; run cancelled")
        worker = run.worker
        worker_labels = {
            **worker.labels,
            **({"site": worker.site} if worker.site else {}),
        }
        if (
            (external and worker.labels.get("execution_admission_v1") is not True)
            or any(worker_labels.get(key) != expected
                for key, expected in deployment.worker_selector.items())
            or (deployment.scope_device_id is not None
                and worker.site != deployment.scope_site)
        ):
            _cancel_reviewed_run_for_drift(
                db, run, external=external, worker_scope=True,
            )
            subject = "External Collector" if external else "Device Collector"
            raise ValueError(f"{subject} Worker scope changed; run cancelled")
        if require_admitted and run.execution_admitted_at is None:
            subject = "External Collector" if external else "Device Collector"
            raise ValueError(f"{subject} run requires execution admission")
    return run


def admit_run_execution(
    db: Session,
    run_id: str,
    payload: CollectorRunAdmit,
) -> CollectorRun:
    run = _active_run_for_token(
        db, run_id, payload.lease_token, require_admitted=False,
    )
    if run.assignment_sha256 != payload.assignment_sha256:
        raise ValueError("Collector assignment differs from the claimed run")
    if run.execution_admitted_at is None:
        run.execution_admitted_at = utcnow()
        record_audit_event(
            db,
            event_type="collector.run.execution_admitted",
            actor_type="worker",
            actor_id=run.worker_id,
            entity_type="collector_run",
            entity_id=run.id,
            details={
                "deployment_id": run.deployment_id,
                "assignment_sha256": run.assignment_sha256,
                "target_classification": run.target_classification_snapshot,
            },
        )
    db.commit()
    db.refresh(run)
    return run


def renew_run_lease(
    db: Session,
    run_id: str,
    lease_token: str,
    lease_seconds: int,
) -> CollectorRun:
    require_locking_transaction(db, purpose="Collector Worker registry and lease renewal")
    from .worker_registry import lock_worker_registry
    worker_id = db.scalar(select(CollectorRun.worker_id).where(CollectorRun.id == run_id))
    worker = db.get(CollectorWorker, worker_id) if worker_id else None
    if worker is None:
        raise LookupError("Collector Worker not found")
    lock_worker_registry(db, worker)
    run = _active_run_for_token(db, run_id, lease_token)
    now = utcnow()
    run.deployment.lease_expires_at = now + timedelta(seconds=lease_seconds)
    run.deployment.updated_at = now
    run.worker.last_heartbeat_at = now
    db.commit()
    db.refresh(run)
    return run


def issue_credential_grant(
    db: Session,
    run_id: str,
    lease_token: str,
) -> CredentialGrantRead:
    """Authorize worker-local resolution for the lifetime of an active run."""

    run = _active_run_for_token(db, run_id, lease_token)
    deployment = run.deployment
    version = db.scalar(
        select(ArtifactVersion)
        .where(
            ArtifactVersion.id
            == (run.artifact_version_id or deployment.artifact_version_id)
        )
        .options(selectinload(ArtifactVersion.collector_definition))
    )
    if version is None or version.collector_definition is None:
        raise ValueError("Collector definition is unavailable")
    definition = version.collector_definition
    credential_ref = (
        deployment.credential_profile_ref
        or definition.credential_profile_ref
    )
    if not credential_ref:
        raise ValueError("Collector run has no credential profile")
    profile = db.scalar(
        select(CredentialProfile).where(
            or_(
                CredentialProfile.id == credential_ref,
                CredentialProfile.name == credential_ref,
            )
        )
    )
    if profile is None or not profile.enabled:
        raise ValueError("Credential profile is unavailable")
    if definition.adapter_type not in profile.allowed_adapters:
        raise ValueError("Credential profile no longer allows this adapter")
    worker_labels = {
        **run.worker.labels,
        **({"site": run.worker.site} if run.worker.site else {}),
    }
    if any(
        worker_labels.get(key) != expected
        for key, expected in profile.worker_selector.items()
    ):
        raise ValueError("Worker no longer matches the credential profile scope")
    expires_at = deployment.lease_expires_at
    if expires_at is None:
        raise ValueError("Collector lease has no expiry")
    record_audit_event(
        db,
        event_type="credential.grant.issued",
        actor_type="worker",
        actor_id=run.worker_id,
        entity_type="collector_run",
        entity_id=run.id,
        details={
            "profile_id": profile.id,
            "profile_revision": profile.revision,
            "provider": profile.provider,
            "adapter_type": definition.adapter_type,
            "deployment_id": deployment.id,
            "expires_at": _as_utc(expires_at).isoformat(),
        },
    )
    db.commit()
    return CredentialGrantRead(
        profile_id=profile.id,
        profile_name=profile.name,
        provider=profile.provider,
        secret_ref=profile.secret_ref,
        adapter_type=definition.adapter_type,
        deployment_id=deployment.id,
        expires_at=_as_utc(expires_at),
        profile_revision=profile.revision,
    )


def ingest_envelopes(
    db: Session,
    run_id: str,
    payload: CollectionEnvelopeBatch,
    *,
    worker_authorization: str | None = None,
    peer_identity=None,
) -> EnvelopeIngestResult:
    run = _active_run_for_token(db, run_id, payload.lease_token)
    definition = run.deployment.artifact_version.collector_definition
    if definition is None:
        raise ValueError("Collector run has no immutable CollectorDefinition")
    allowed_kinds = set(definition.output_kinds)
    for index, item in enumerate(payload.envelopes):
        from ..collector_condition_schemas import COLLECTOR_CONDITION_V1
        if item.type == COLLECTOR_CONDITION_V1 and item.kind != EnvelopeKind.OBSERVATION:
            raise ValueError("Collector condition contract requires observation kind")
        if item.type != COLLECTOR_CONDITION_V1 and item.source.startswith("icheck-condition:"):
            raise ValueError("Collector condition envelope source namespace is reserved")
        if item.kind.value not in allowed_kinds:
            raise ValueError(
                f"Envelope kind {item.kind.value} is not declared by the CollectorDefinition"
            )
        assert_no_inline_secrets(
            item.payload,
            f"envelopes[{index}].payload",
        )
    from .canary_rollouts import record_canary_envelope_batch

    if record_canary_envelope_batch(db, run, payload.envelopes):
        accepted = len(payload.envelopes)
        run.records_received += accepted
        db.commit()
        return EnvelopeIngestResult(
            received=accepted,
            accepted=accepted,
            duplicates=0,
        )
    accepted = 0
    duplicates = 0
    # Python's legacy SQLite transaction mode does not begin a transaction
    # for SELECT/SAVEPOINT. Releasing the first savepoint would otherwise
    # commit an item that a later batch failure must roll back.
    if db.get_bind().dialect.name == "sqlite":
        connection = db.connection()
        if not connection.connection.dbapi_connection.in_transaction:
            connection.exec_driver_sql("BEGIN")
    for item in payload.envelopes:
        envelope = CollectionEnvelope(run_id=run.id, **item.model_dump())
        is_condition = item.type == COLLECTOR_CONDITION_V1
        if is_condition:
            envelope.source = f"icheck-condition:{run.tenant_id}:{run.region_id}:{run.id}"
            if item.idempotency_key:
                previous = db.scalar(select(CollectionEnvelope).where(CollectionEnvelope.source == envelope.source,
                    CollectionEnvelope.idempotency_key == item.idempotency_key))
                if previous is not None:
                    from .collector_conditions import canonical, validate_condition_duplicate
                    if (previous.run_id != run.id or previous.type != item.type or previous.kind != item.kind
                        or previous.subject != item.subject or _as_utc(previous.observed_at) != _as_utc(item.observed_at)
                        or canonical(previous.payload) != canonical(item.payload)):
                        raise ValueError("Collector condition idempotency key was reused for a different observation")
                    validate_condition_duplicate(db, run, previous,
                        authorization=worker_authorization, peer=peer_identity)
                    duplicates += 1
                    continue
        try:
            with db.begin_nested():
                db.add(envelope)
                db.flush()
                from .collector_conditions import seal_condition_envelope
                seal_condition_envelope(db, run, envelope, authorization=worker_authorization,
                    peer=peer_identity, source_label=item.source)
                db.add(KnowledgeProjection(envelope_id=envelope.id))
                db.flush()
            accepted += 1
        except IntegrityError:
            if is_condition:
                raise ValueError("Collector condition acceptance failed its database invariants")
            duplicates += 1
    run.records_received += accepted
    db.commit()
    return EnvelopeIngestResult(
        received=len(payload.envelopes),
        accepted=accepted,
        duplicates=duplicates,
    )


def complete_run(
    db: Session,
    run_id: str,
    payload: CollectorRunComplete,
) -> CollectorRun:
    run = _active_run_for_token(db, run_id, payload.lease_token)
    now = utcnow()
    run.status = payload.status
    run.error = payload.error
    run.stats = payload.stats
    run.finished_at = now
    deployment = run.deployment
    deployment.last_finished_at = now
    if deployment.execution_mode == CollectorDeploymentMode.ON_DEMAND:
        deployment.next_run_at = None
    else:
        deployment.next_run_at = now + timedelta(
            seconds=deployment.schedule_seconds
        )
    deployment.lease_worker_id = None
    deployment.lease_token_hash = None
    deployment.lease_expires_at = None
    deployment.updated_at = now
    reconcile_completed_run(db, run)
    from .canary_rollouts import reconcile_canary_run

    reconcile_canary_run(db, run)
    record_audit_event(
        db,
        event_type="collector.run.completed",
        actor_type="worker",
        actor_id=run.worker_id,
        entity_type="collector_run",
        entity_id=run.id,
        details={
            "deployment_id": deployment.id,
            "status": payload.status.value,
            "records_received": run.records_received,
        },
    )
    db.commit()
    db.refresh(run)
    return run


def collector_health(
    db: Session,
    *,
    deployment_scope: ColumnElement[bool] | None = None,
    worker_scope: ColumnElement[bool] | None = None,
) -> dict[str, int]:
    now = utcnow()
    stale_before = now - timedelta(seconds=90)
    hour_ago = now - timedelta(hours=1)
    deployment_filters = [deployment_scope] if deployment_scope is not None else []
    worker_filters = [worker_scope] if worker_scope is not None else []
    run_filters = (
        [CollectorRun.deployment.has(deployment_scope)]
        if deployment_scope is not None
        else []
    )
    workers_total = (
        db.scalar(
            select(func.count())
            .select_from(CollectorWorker)
            .where(*worker_filters)
        )
        or 0
    )
    workers_online = (
        db.scalar(
            select(func.count())
            .select_from(CollectorWorker)
            .where(
                CollectorWorker.state == CollectorWorkerState.ONLINE,
                CollectorWorker.last_heartbeat_at >= stale_before,
                *worker_filters,
            )
        )
        or 0
    )
    workers_stale = (
        db.scalar(
            select(func.count())
            .select_from(CollectorWorker)
            .where(
                CollectorWorker.last_heartbeat_at < stale_before,
                *worker_filters,
            )
        )
        or 0
    )
    deployments_total = (
        db.scalar(
            select(func.count())
            .select_from(CollectorDeployment)
            .where(*deployment_filters)
        )
        or 0
    )
    deployments_enabled = (
        db.scalar(
            select(func.count())
            .select_from(CollectorDeployment)
            .where(
                CollectorDeployment.enabled.is_(True),
                *deployment_filters,
            )
        )
        or 0
    )
    deployments_leased = (
        db.scalar(
            select(func.count())
            .select_from(CollectorDeployment)
            .where(
                CollectorDeployment.lease_expires_at >= now,
                *deployment_filters,
            )
        )
        or 0
    )
    deployments_due = (
        db.scalar(
            select(func.count())
            .select_from(CollectorDeployment)
            .where(
                CollectorDeployment.enabled.is_(True),
                CollectorDeployment.next_run_at.is_not(None),
                CollectorDeployment.next_run_at <= now,
                or_(
                    CollectorDeployment.lease_expires_at.is_(None),
                    CollectorDeployment.lease_expires_at < now,
                ),
                *deployment_filters,
            )
        )
        or 0
    )
    running_runs = (
        db.scalar(
            select(func.count())
            .select_from(CollectorRun)
            .where(
                CollectorRun.status == CollectorRunStatus.RUNNING,
                *run_filters,
            )
        )
        or 0
    )
    failed_runs_last_hour = (
        db.scalar(
            select(func.count())
            .select_from(CollectorRun)
            .where(
                CollectorRun.status == CollectorRunStatus.FAILED,
                CollectorRun.finished_at >= hour_ago,
                *run_filters,
            )
        )
        or 0
    )
    return {
        "workers_total": workers_total,
        "workers_online": workers_online,
        "workers_stale": workers_stale,
        "deployments_total": deployments_total,
        "deployments_enabled": deployments_enabled,
        "deployments_leased": deployments_leased,
        "deployments_due": deployments_due,
        "running_runs": running_runs,
        "failed_runs_last_hour": failed_runs_last_hour,
    }
