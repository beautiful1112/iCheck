"""Continuous, exact-version execution-health evidence; never change authority."""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer, selectinload

from ..config import get_settings
from ..database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, NamespaceViolation, require_locking_transaction, session_namespace, set_session_namespace
from ..models import (
    AgentActionProposal, AlertSeverity, Artifact, ArtifactKind, ArtifactVersion, ArtifactVersionStatus, GovernedChangePlan,
    CapabilityQualityAssessment, CapabilityQualityPolicy, CollectorRun,
    Investigation, InvestigationToolCall, new_id, utcnow,
)
from ..quality_schemas import QualityPolicyCreate, QualityPolicySettings, QualityPolicyStateRead, QualityPolicyUpdate
from .alerts import resolve_by_dedup_key, upsert_alert
from .alert_conditions import observe_unknown_condition
from .audit import record_audit_event
from .collectors import artifact_version_content_material
from .artifact_lifecycle import artifact_identities_for_versions, lock_artifact_identities
from .capability_pack_revocations import assert_artifact_version_not_revoked


MAX_SAMPLES = 2000
MAX_POLICIES = 1000
SUPPORTED_KINDS = {ArtifactKind.COLLECTOR, ArtifactKind.TOOL, ArtifactKind.SKILL, ArtifactKind.WORKFLOW}
EVIDENCE_SCOPES = {"execution_health": "execution_health_not_correctness", "remediation_outcome": "remediation_outcome_not_authority"}


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _namespace(db: Session) -> tuple[str, str]:
    namespace = session_namespace(db)
    if namespace is None:
        if get_settings().control_plane_auth_mode == "required":
            raise NamespaceViolation("Quality evaluation requires an explicit namespace")
        namespace = (DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
    # Also protect downstream Alert/Situation helpers in non-enforcing sessions.
    if not db.info.get("namespace_enforced"):
        set_session_namespace(db, *namespace)
    return namespace


def _query(db: Session, model):
    tenant_id, region_id = _namespace(db)
    return select(model).where(model.tenant_id == tenant_id, model.region_id == region_id)


def _version(db: Session, version_id: str) -> ArtifactVersion:
    tenant_id, region_id = _namespace(db)
    version = db.scalar(_query(db, ArtifactVersion).join(Artifact).where(
        ArtifactVersion.id == version_id, Artifact.tenant_id == tenant_id, Artifact.region_id == region_id,
    ).options(selectinload(ArtifactVersion.artifact), selectinload(ArtifactVersion.collector_definition)).execution_options(populate_existing=True))
    if version is None:
        raise LookupError("Quality Artifact version not found")
    return version


def _validate_version(db: Session, version: ArtifactVersion, expected_hash: str) -> None:
    assert_artifact_version_not_revoked(db, version.id)
    if version.artifact.kind not in SUPPORTED_KINDS:
        raise ValueError("This Artifact kind has no version-pinned execution evidence")
    if version.status != ArtifactVersionStatus.PUBLISHED or not version.published_at:
        raise ValueError("Quality policies require a published Artifact version")
    if version.content_hash != expected_hash or digest(artifact_version_content_material(version)) != expected_hash:
        raise ValueError("Quality Artifact content hash does not match its immutable material")
    if version.artifact.kind == ArtifactKind.COLLECTOR:
        definition = version.collector_definition
        if definition is None or not definition.output_kinds or version.implementation.get("adapter") != definition.adapter_type:
            raise ValueError("Collector execution contract is invalid")
    elif version.artifact.kind == ArtifactKind.TOOL:
        from .tool_skills import validate_tool_artifact_contract
        validate_tool_artifact_contract(version.definition, version.implementation, version.tests)
    elif version.artifact.kind == ArtifactKind.SKILL:
        from .tool_skills import assert_skill_runtime_compatible
        assert_skill_runtime_compatible(db, version)
    else:
        from .workflow_runtime import assert_workflow_runtime_compatible
        assert_workflow_runtime_compatible(db, version)


def policy_snapshot(policy: CapabilityQualityPolicy) -> dict:
    return {
        "format_version": "icheck.capability-quality-policy/v1",
        "policy_id": policy.id, "tenant_id": policy.tenant_id, "region_id": policy.region_id,
        "artifact_version_id": policy.artifact_version_id, "content_hash": policy.content_hash,
        "revision": policy.revision,
        **{key: getattr(policy, key) for key in QualityPolicySettings.model_fields},
    }


def assessment_material(assessment: CapabilityQualityAssessment) -> dict:
    fields = ("id", "tenant_id", "region_id", "policy_id", "artifact_version_id", "policy_revision",
        "policy_sha256", "content_hash", "evidence_scope", "status", "reasons", "sample_count", "failed_count", "failure_ppm",
        "p95_ms", "latest_sample_at", "scan_truncated", "evidence_sha256", "evaluated_at", "valid_until", "evaluated_by")
    return {field: as_utc(value).isoformat() if isinstance(value := getattr(assessment, field), datetime) else value for field in fields}


def _lock_quality_version(db: Session, version_id: str) -> None:
    identities = artifact_identities_for_versions(db, [version_id])
    lock_artifact_identities(db, readable=identities)
    if artifact_identities_for_versions(db, [version_id]) != identities:
        raise ValueError("Quality Artifact identity changed during locking")


def get_policy(db: Session, policy_id: str, *, lock: bool = False) -> CapabilityQualityPolicy:
    query = _query(db, CapabilityQualityPolicy).where(CapabilityQualityPolicy.id == policy_id).execution_options(populate_existing=True)
    if lock:
        require_locking_transaction(db, purpose="Quality policy mutations")
        # Publication/revocation fence precedes the policy mutex for every
        # writer/evaluator. The version binding is immutable through the API.
        version_id = db.scalar(query.with_only_columns(CapabilityQualityPolicy.artifact_version_id))
        if version_id is None:
            raise LookupError("Quality policy not found")
        _lock_quality_version(db, version_id)
        query = query.with_for_update()
    policy = db.scalar(query)
    if policy is None:
        raise LookupError("Quality policy not found")
    if lock and policy.artifact_version_id != version_id:
        raise ValueError("Quality policy version changed during locking")
    return policy


def list_policies(db: Session, *, offset: int = 0, limit: int = MAX_POLICIES, artifact_version_id: str | None = None, evidence_mode: str | None = None) -> list[CapabilityQualityPolicy]:
    query = _query(db, CapabilityQualityPolicy)
    if artifact_version_id:
        query = query.where(CapabilityQualityPolicy.artifact_version_id == artifact_version_id)
    if evidence_mode:
        query = query.where(CapabilityQualityPolicy.evidence_mode == evidence_mode)
    return list(db.scalars(query.order_by(CapabilityQualityPolicy.created_at, CapabilityQualityPolicy.id).offset(offset).limit(limit)).all())


def _audit_policy(db: Session, policy: CapabilityQualityPolicy, actor: str, reason: str, previous: dict | None) -> None:
    record_audit_event(db, event_type="capability.quality.policy_updated" if previous else "capability.quality.policy_created",
        actor_type="user", actor_id=actor, entity_type="capability_quality_policy", entity_id=policy.id,
        details={"previous": previous, "current": policy_snapshot(policy), "reason_sha256": digest(reason)})


def _validate_mode(version: ArtifactVersion, payload: QualityPolicySettings) -> None:
    if payload.evidence_mode == "remediation_outcome":
        spec = version.definition.get("spec", {})
        if version.artifact.kind != ArtifactKind.TOOL or spec.get("read_only") is not False or not spec.get("change_contract"):
            raise ValueError("Outcome quality requires a published governed state-changing Tool")


def create_policy(db: Session, payload: QualityPolicyCreate, *, actor: str) -> CapabilityQualityPolicy:
    require_locking_transaction(db, purpose="Quality policy creation")
    _lock_quality_version(db, str(payload.artifact_version_id))
    version = _version(db, str(payload.artifact_version_id))
    _validate_version(db, version, payload.expected_content_hash)
    _validate_mode(version, payload)
    if version.artifact.kind != ArtifactKind.COLLECTOR and payload.min_records_per_run:
        raise ValueError("Minimum record count applies only to Collectors")
    namespace = _namespace(db)
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": f"icheck.quality-policy-limit:{namespace[0]}:{namespace[1]}"})
    if len(list_policies(db)) >= MAX_POLICIES:
        raise ValueError("Namespace quality policy limit reached")
    values = payload.model_dump(exclude={"artifact_version_id", "expected_content_hash", "reason"})
    policy = CapabilityQualityPolicy(**values, artifact_version_id=version.id, content_hash=version.content_hash,
        tenant_id=namespace[0], region_id=namespace[1], revision=1, created_by=actor, updated_by=actor)
    db.add(policy)
    try:
        db.flush()
        _audit_policy(db, policy, actor, payload.reason, None)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("A quality policy already exists for this exact version") from exc
    db.refresh(policy)
    return policy


def update_policy(db: Session, policy_id: str, payload: QualityPolicyUpdate, *, actor: str) -> CapabilityQualityPolicy:
    policy = get_policy(db, policy_id, lock=True)
    if policy.revision != payload.expected_revision:
        raise ValueError("Quality policy revision conflict")
    version = _version(db, policy.artifact_version_id)
    _validate_mode(version, payload)
    if version.artifact.kind != ArtifactKind.COLLECTOR and payload.min_records_per_run:
        raise ValueError("Minimum record count applies only to Collectors")
    previous = policy_snapshot(policy)
    for key, value in payload.model_dump(exclude={"expected_revision", "reason"}).items():
        setattr(policy, key, value)
    policy.revision += 1
    policy.updated_by = actor
    policy.updated_at = utcnow()
    policy.next_evaluation_at = utcnow()
    _audit_policy(db, policy, actor, payload.reason, previous)
    db.commit()
    db.refresh(policy)
    return policy


def _runtime_rows(db: Session, policy: CapabilityQualityPolicy, kind: ArtifactKind, cutoff: datetime):
    if policy.evidence_mode == "remediation_outcome" and kind != ArtifactKind.TOOL:
        return []  # Contract drift is recorded; never query the wrong runtime shape.
    if kind == ArtifactKind.COLLECTOR:
        model, version_field = CollectorRun, CollectorRun.artifact_version_id
    elif kind == ArtifactKind.TOOL:
        model, version_field = InvestigationToolCall, InvestigationToolCall.artifact_version_id
    else:
        model = Investigation
        version_field = model.skill_artifact_version_id if kind == ArtifactKind.SKILL else model.workflow_artifact_version_id
    # Active old runs must not disappear merely because their start left the
    # window. Missing terminal times/future times are invalid, not silent success.
    query = _query(db, model)
    conditions = [model.finished_at >= cutoff, model.finished_at.is_(None)]
    bound = MAX_SAMPLES
    if policy.evidence_mode == "remediation_outcome":
        from .remediation_quality import MAX_OUTCOME_SAMPLES
        bound = MAX_OUTCOME_SAMPLES
        query = query.options(defer(model.arguments), defer(model.result), defer(model.error))
        query = query.outerjoin(AgentActionProposal, (AgentActionProposal.tool_call_id == model.id)
            & (AgentActionProposal.tenant_id == policy.tenant_id) & (AgentActionProposal.region_id == policy.region_id))
        query = query.outerjoin(GovernedChangePlan, (GovernedChangePlan.action_proposal_id == AgentActionProposal.id)
            & (GovernedChangePlan.tenant_id == policy.tenant_id) & (GovernedChangePlan.region_id == policy.region_id))
        conditions.extend([GovernedChangePlan.status.in_(["awaiting_postcheck", "awaiting_rollback_check"]), GovernedChangePlan.updated_at >= cutoff])
    query = query.where(version_field == policy.artifact_version_id, or_(*conditions)).order_by(model.started_at.desc(), model.id).limit(bound + 1)
    return list(db.scalars(query).all())


def _observe(rows, policy: CapabilityQualityPolicy, kind: ArtifactKind, now: datetime):
    samples = []
    reasons: list[str] = []
    latest_terminal = None
    for row in rows[:MAX_SAMPLES]:
        started = as_utc(row.started_at) if row.started_at else None
        finished = as_utc(row.finished_at) if row.finished_at else None
        status = row.status.value if hasattr(row.status, "value") else row.status
        # Time awaiting queue dispatch or human approval is not Tool execution.
        if kind in {ArtifactKind.SKILL, ArtifactKind.WORKFLOW} and status in {"pending", "waiting_approval"}:
            continue
        if kind == ArtifactKind.TOOL:
            pinned_hash = row.artifact_content_hash
        elif kind in {ArtifactKind.SKILL, ArtifactKind.WORKFLOW}:
            snapshot = row.skill_snapshot if kind == ArtifactKind.SKILL else row.workflow_snapshot
            pinned_hash = snapshot.get("content_hash") if isinstance(snapshot, dict) else None
        else:
            pinned_hash = policy.content_hash  # CollectorRun owns its exact version FK.
        pinned_hash = pinned_hash if isinstance(pinned_hash, str) and re.fullmatch(r"[0-9a-f]{64}", pinned_hash) else None
        known_statuses = {"running", "succeeded", "failed", "cancelled"} if kind in {ArtifactKind.COLLECTOR, ArtifactKind.TOOL} else {"running", "completed", "escalated", "failed", "cancelled"}
        unknown_status = status not in known_statuses
        status = status if not unknown_status else "invalid"
        active = status in {"pending", "running", "waiting_approval"}
        invalid = (started is None or started > now or (finished is not None and (finished < started or finished > now))
            or (not active and finished is None) or pinned_hash != policy.content_hash or unknown_status)
        duration = max(0, math.ceil(((finished or now) - started).total_seconds() * 1000)) if started else 0
        if active and not invalid and duration <= policy.max_p95_ms:
            continue
        success = (status == "succeeded" if kind in {ArtifactKind.COLLECTOR, ArtifactKind.TOOL} else status == "completed") and not invalid
        records = row.records_received if kind == ArtifactKind.COLLECTOR else None
        if records is not None and records < policy.min_records_per_run:
            success = False
        if invalid:
            reasons.append("invalid_or_unpinned_runtime_evidence")
        if active:
            success = False
            reasons.append("execution_overdue")
        if finished is not None and finished <= now:
            latest_terminal = max(latest_terminal, finished) if latest_terminal else finished
        # No arguments, results, objectives, errors, targets or model prose.
        samples.append({"source": kind.value, "id": row.id, "status": status, "passed": success,
            "started_at": started.isoformat() if started else None,
            "finished_at": finished.isoformat() if finished else None,
            "duration_ms": duration, "records_received": records, "content_hash": pinned_hash})
    return samples, list(dict.fromkeys(reasons)), latest_terminal


def evaluate_policy(db: Session, policy_id: str, *, actor: str, reason: str | None = None,
                    now: datetime | None = None, commit: bool = True) -> CapabilityQualityAssessment:
    now = as_utc(now or utcnow())
    policy = get_policy(db, policy_id, lock=True)
    version = _version(db, policy.artifact_version_id)
    reasons: list[str] = []
    rows = []
    if policy.enabled:
        try:
            _validate_version(db, version, policy.content_hash)
            _validate_mode(version, QualityPolicySettings.model_validate(policy))
        except (KeyError, TypeError, ValueError):
            reasons.append("artifact_contract_drift")
        rows = _runtime_rows(db, policy, version.artifact.kind, now - timedelta(minutes=policy.window_minutes))
    bound = MAX_SAMPLES
    if policy.evidence_mode == "remediation_outcome":
        from .remediation_quality import MAX_OUTCOME_SAMPLES, observe_outcomes
        bound = MAX_OUTCOME_SAMPLES
        samples, observation_reasons, latest = observe_outcomes(db, rows, policy, now)
    else:
        samples, observation_reasons, latest = _observe(rows, policy, version.artifact.kind, now)
    reasons.extend(observation_reasons)
    truncated = len(rows) > bound
    if truncated:
        reasons.append("evidence_scan_limit_exceeded")
    failures = sum(not sample["passed"] for sample in samples)
    count = len(samples)
    failure_ppm = (failures * 1000000 + count - 1) // count if count else None
    durations = sorted(sample["duration_ms"] for sample in samples)
    p95 = durations[(count * 95 + 99) // 100 - 1] if count else None
    if failure_ppm is not None and failures * 1000000 > policy.max_failure_ppm * count:
        reasons.append("failure_rate_exceeded")
    if p95 is not None and p95 > policy.max_p95_ms:
        reasons.append("latency_p95_exceeded")
    if policy.enabled and count < policy.min_samples:
        reasons.append("insufficient_samples")
    if policy.enabled and (latest is None or (now - latest).total_seconds() > policy.max_sample_age_seconds):
        reasons.append("runtime_evidence_stale")
    hard_failures = set(reasons) - {"insufficient_samples", "runtime_evidence_stale"}
    status = "disabled" if not policy.enabled else "degraded" if hard_failures else "insufficient_data" if reasons else "healthy"
    snapshot = policy_snapshot(policy)
    namespace = _namespace(db)
    valid_until = now + timedelta(seconds=2 * policy.evaluation_interval_seconds)
    if status == "healthy" and latest is not None:
        # A long polling interval must not make stale terminal evidence healthy.
        valid_until = min(valid_until, latest + timedelta(seconds=policy.max_sample_age_seconds))
    assessment = CapabilityQualityAssessment(id=new_id(), policy_id=policy.id, artifact_version_id=version.id,
        tenant_id=namespace[0], region_id=namespace[1], policy_revision=policy.revision,
        policy_snapshot=snapshot, policy_sha256=digest(snapshot), content_hash=policy.content_hash,
        evidence_scope=EVIDENCE_SCOPES[policy.evidence_mode],
        status=status, reasons=list(dict.fromkeys(reasons)), sample_count=count, failed_count=failures,
        failure_ppm=failure_ppm, p95_ms=p95, latest_sample_at=latest, scan_truncated=truncated,
        evidence_manifest=samples, evidence_sha256=digest(samples), evaluated_at=now,
        valid_until=valid_until, evaluated_by=actor)
    assessment.assessment_sha256 = digest(assessment_material(assessment))
    db.add(assessment)
    db.flush()
    previous = db.scalar(_query(db, CapabilityQualityAssessment).where(
        CapabilityQualityAssessment.id == policy.last_assessment_id,
        CapabilityQualityAssessment.policy_id == policy.id,
    ).execution_options(populate_existing=True)) if policy.last_assessment_id else None
    # Keep historical assessments/audits, but an evaluator that waited cannot
    # make an older verdict current or erase same-time adverse evidence.
    conservative_rank = {"disabled": 0, "healthy": 1, "insufficient_data": 2, "degraded": 3}
    if (previous is None or now > as_utc(previous.evaluated_at)
        or (now == as_utc(previous.evaluated_at)
            and conservative_rank[status] > conservative_rank[previous.status])):
        policy.last_assessment_id = assessment.id
        policy.next_evaluation_at = now + timedelta(seconds=policy.evaluation_interval_seconds) if policy.enabled else None
    key = f"capability-quality:{policy.id}"
    source_identity = ("capability.quality.degraded", "artifact_version", version.id, None)
    if policy.alert_on_degradation and status == "degraded":
        upsert_alert(db, dedup_key=key, event_type="capability.quality.degraded", severity=AlertSeverity.WARNING,
            title="Capability quality degraded", description="Version-pinned runtime evidence failed the configured quality gates; this is not a remediation authorization.",
            entity_type="artifact_version", entity_id=version.id,
            details={"policy_id": policy.id, "assessment_id": assessment.id, "artifact_version_id": version.id,
                "reasons": assessment.reasons, "sample_count": count, "failed_count": failures,
                "evidence_sha256": assessment.evidence_sha256}, observed_at=now)
    elif status in {"healthy", "disabled"} or not policy.alert_on_degradation:
        resolve_by_dedup_key(db, key, actor, now, source_identity=source_identity)
    else:
        # Uncertainty is itself newer evidence. Retain its watermark so that
        # an older healthy evaluation cannot later clear a degradation episode.
        observe_unknown_condition(db, key, now, source_identity=source_identity)
    record_audit_event(db, event_type="capability.quality.assessed", actor_type="system" if actor.startswith("system.") else "user",
        actor_id=actor, entity_type="capability_quality_assessment", entity_id=assessment.id,
        details={"policy_id": policy.id, "policy_revision": policy.revision, "status": status,
            "policy_sha256": assessment.policy_sha256, "evidence_sha256": assessment.evidence_sha256,
            "reason_sha256": digest(reason) if reason else None})
    if commit:
        db.commit()
        db.refresh(assessment)
    return assessment


def list_assessments(db: Session, policy_id: str, *, limit: int = 50) -> list[CapabilityQualityAssessment]:
    get_policy(db, policy_id)
    return list(db.scalars(_query(db, CapabilityQualityAssessment).where(CapabilityQualityAssessment.policy_id == policy_id)
        .order_by(CapabilityQualityAssessment.evaluated_at.desc(), CapabilityQualityAssessment.id.desc()).limit(limit)).all())


def get_assessment(db: Session, assessment_id: str) -> CapabilityQualityAssessment:
    assessment = db.scalar(_query(db, CapabilityQualityAssessment).where(CapabilityQualityAssessment.id == assessment_id))
    if assessment is None:
        raise LookupError("Quality assessment not found")
    get_policy(db, assessment.policy_id)
    return assessment


def policy_state(db: Session, policy: CapabilityQualityPolicy, *, now: datetime | None = None) -> QualityPolicyStateRead:
    now = as_utc(now or utcnow())
    assessment = db.scalar(_query(db, CapabilityQualityAssessment).where(
        CapabilityQualityAssessment.id == policy.last_assessment_id, CapabilityQualityAssessment.policy_id == policy.id,
    )) if policy.last_assessment_id else None
    current = bool(assessment and as_utc(assessment.evaluated_at) <= now and assessment.policy_revision == policy.revision
        and assessment.policy_sha256 == digest(policy_snapshot(policy))
        and digest(assessment.policy_snapshot) == assessment.policy_sha256
        and digest(assessment.evidence_manifest) == assessment.evidence_sha256
        and digest(assessment_material(assessment)) == assessment.assessment_sha256)
    if current and policy.enabled:
        try:
            _validate_version(db, _version(db, policy.artifact_version_id), policy.content_hash)
            if assessment.status == "healthy" and policy.evidence_mode == "remediation_outcome":
                from .remediation_quality import assert_outcome_manifest_current
                assert_outcome_manifest_current(db, assessment, now=now)
        except (KeyError, TypeError, LookupError, ValueError):
            current = False
    state = assessment.status if current else "needs_evaluation"
    if current and as_utc(assessment.valid_until) <= now:
        state = "expired"
        current = False
    if not policy.enabled:
        state = "disabled"  # Configuration state, never a current-health claim.
    return QualityPolicyStateRead(as_of=now, policy=policy, latest_assessment=assessment, current=current, state=state)
