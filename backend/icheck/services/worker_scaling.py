from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, exists, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import require_locking_transaction
from ..models import (
    AIModelConfig,
    AIProviderConfig,
    AgentExecution,
    AgentExecutionStatus,
    AgentWorker,
    AgentWorkerState,
    ArtifactVersion,
    ArtifactVersionStatus,
    CollectorCanaryRollout,
    CollectorDefinition,
    CollectorDeployment,
    CollectorWorker,
    CollectorWorkerState,
    Investigation,
    WorkerScalingDecision,
    WorkerScalingApplicationEvent,
    WorkerScalingPolicy,
    WorkerScalingPool,
    utcnow,
)
from ..scaling_schemas import (
    ScalingApplicationEventCreate,
    ScalingPolicyCreate,
    ScalingPolicyUpdate,
)
from .audit import record_audit_event


@dataclass(frozen=True)
class PoolObservation:
    queue_depth: int
    oldest_queue_age_seconds: float | None
    current_replicas: int
    ready_replicas: int
    busy_replicas: int
    stale_replicas: int


def list_scaling_policies(db: Session) -> list[WorkerScalingPolicy]:
    return list(
        db.scalars(
            select(WorkerScalingPolicy).order_by(
                WorkerScalingPolicy.pool,
                WorkerScalingPolicy.name,
            )
        ).all()
    )


def get_scaling_policy(db: Session, policy_id: str) -> WorkerScalingPolicy:
    policy = db.get(WorkerScalingPolicy, policy_id)
    if policy is None:
        raise LookupError("Worker scaling policy not found")
    return policy


def _locked_scaling_policy(db: Session, policy_id: str) -> WorkerScalingPolicy:
    # Serialize manual/controller evaluations with policy edits and each other.
    # A cached policy may have been disabled or revised since the prior cycle.
    require_locking_transaction(db, purpose="Scaling policy evaluation and edits")
    policy = db.scalar(select(WorkerScalingPolicy)
        .where(WorkerScalingPolicy.id == policy_id)
        .with_for_update().execution_options(populate_existing=True))
    if policy is None:
        raise LookupError("Worker scaling policy not found")
    return policy


def create_scaling_policy(
    db: Session,
    payload: ScalingPolicyCreate,
    *,
    actor: str,
) -> WorkerScalingPolicy:
    values = payload.model_dump(exclude={"reason"})
    values["pool"] = WorkerScalingPool(values["pool"])
    policy = WorkerScalingPolicy(
        **values,
        revision=1,
        created_by=actor,
        updated_by=actor,
        update_reason=payload.reason,
    )
    db.add(policy)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="scaling.policy.created",
            actor_type="user",
            actor_id=actor,
            entity_type="worker_scaling_policy",
            entity_id=policy.id,
            details={
                "name": policy.name,
                "pool": policy.pool.value,
                "min_replicas": policy.min_replicas,
                "max_replicas": policy.max_replicas,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Scaling policy name already exists for this pool") from exc
    db.refresh(policy)
    return policy


def update_scaling_policy(
    db: Session,
    policy: WorkerScalingPolicy,
    payload: ScalingPolicyUpdate,
    *,
    actor: str,
) -> WorkerScalingPolicy:
    policy = _locked_scaling_policy(db, policy.id)
    if policy.revision != payload.expected_revision:
        raise ValueError("Scaling policy revision conflict")
    values = payload.model_dump(exclude={"expected_revision", "reason"})
    values["pool"] = WorkerScalingPool(values["pool"])
    for key, value in values.items():
        setattr(policy, key, value)
    policy.revision += 1
    policy.updated_by = actor
    policy.update_reason = payload.reason
    policy.updated_at = utcnow()
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="scaling.policy.updated",
            actor_type="user",
            actor_id=actor,
            entity_type="worker_scaling_policy",
            entity_id=policy.id,
            details={
                "revision": policy.revision,
                "enabled": policy.enabled,
                "min_replicas": policy.min_replicas,
                "max_replicas": policy.max_replicas,
                "reason": payload.reason,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Scaling policy name already exists for this pool") from exc
    db.refresh(policy)
    return policy


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _matches_selector(
    selector: dict[str, str],
    labels: dict[str, object],
    *,
    site: str | None = None,
) -> bool:
    available = {str(key): str(value) for key, value in labels.items()}
    if site:
        available.setdefault("site", site)
    return all(available.get(key) == value for key, value in selector.items())


def _oldest_age(now: datetime, values: list[datetime]) -> float | None:
    if not values:
        return None
    return round(max(0.0, (now - min(_as_utc(item) for item in values)).total_seconds()), 3)


def _collector_observation(
    db: Session,
    policy: WorkerScalingPolicy,
    now: datetime,
) -> PoolObservation:
    due_rows = db.execute(
        select(CollectorDeployment, CollectorDefinition.adapter_type)
        .join(ArtifactVersion, ArtifactVersion.id == CollectorDeployment.artifact_version_id)
        .join(CollectorDefinition, CollectorDefinition.artifact_version_id == ArtifactVersion.id)
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
                and_(
                    ArtifactVersion.status == ArtifactVersionStatus.VALIDATED,
                    exists(
                        select(CollectorCanaryRollout.id).where(
                            CollectorCanaryRollout.deployment_id
                            == CollectorDeployment.id,
                            CollectorCanaryRollout.status == "running",
                        )
                    ),
                ),
            ),
        )
    ).all()
    capabilities = set(policy.required_capabilities or [])
    due = [
        deployment
        for deployment, adapter_type in due_rows
        if (not capabilities or adapter_type in capabilities)
        and _matches_selector(
            policy.selector or {},
            deployment.worker_selector or {},
            site=deployment.scope_site,
        )
    ]
    workers = [
        worker
        for worker in db.scalars(select(CollectorWorker)).all()
        if _matches_selector(
            policy.selector or {}, worker.labels or {}, site=worker.site
        )
        and (
            not capabilities
            or capabilities.issubset(set(worker.capabilities or []))
        )
    ]
    heartbeat_cutoff = now - timedelta(seconds=policy.heartbeat_timeout_seconds)
    fresh = [
        worker
        for worker in workers
        if _as_utc(worker.last_heartbeat_at) >= heartbeat_cutoff
        and worker.state != CollectorWorkerState.OFFLINE
    ]
    ready = [worker for worker in fresh if worker.state == CollectorWorkerState.ONLINE]
    stale = [
        worker
        for worker in workers
        if worker.state != CollectorWorkerState.OFFLINE
        and _as_utc(worker.last_heartbeat_at) < heartbeat_cutoff
    ]
    busy_ids = set(
        db.scalars(
            select(CollectorDeployment.lease_worker_id).where(
                CollectorDeployment.lease_worker_id.is_not(None),
                CollectorDeployment.lease_expires_at.is_not(None),
                CollectorDeployment.lease_expires_at >= now,
            )
        ).all()
    )
    fresh_ids = {worker.id for worker in fresh}
    return PoolObservation(
        queue_depth=len(due),
        oldest_queue_age_seconds=_oldest_age(
            now,
            [item.next_run_at for item in due if item.next_run_at is not None],
        ),
        current_replicas=len(fresh),
        ready_replicas=len(ready),
        busy_replicas=len(busy_ids & fresh_ids),
        stale_replicas=len(stale),
    )


def _agent_observation(
    db: Session,
    policy: WorkerScalingPolicy,
    now: datetime,
) -> PoolObservation:
    eligible = or_(
        AgentExecution.status == AgentExecutionStatus.QUEUED,
        and_(
            AgentExecution.status == AgentExecutionStatus.RUNNING,
            AgentExecution.lease_expires_at.is_not(None),
            AgentExecution.lease_expires_at < now,
        ),
    )
    rows = db.execute(
        select(AgentExecution, AIProviderConfig.provider_type)
        .join(Investigation, Investigation.id == AgentExecution.investigation_id)
        .join(AIModelConfig, AIModelConfig.id == Investigation.model_id)
        .join(AIProviderConfig, AIProviderConfig.id == AIModelConfig.provider_id)
        .where(
            eligible,
            Investigation.status == "running",
            AgentExecution.cancellation_requested_at.is_(None),
        )
    ).all()
    capabilities = set(policy.required_capabilities or [])
    queued = [
        execution
        for execution, provider_type in rows
        if not capabilities or provider_type in capabilities
    ]
    workers = [
        worker
        for worker in db.scalars(select(AgentWorker)).all()
        if not capabilities
        or capabilities.issubset(set(worker.capabilities or []))
    ]
    heartbeat_cutoff = now - timedelta(seconds=policy.heartbeat_timeout_seconds)
    fresh = [
        worker
        for worker in workers
        if _as_utc(worker.last_heartbeat_at) >= heartbeat_cutoff
        and worker.state != AgentWorkerState.OFFLINE
    ]
    ready = [worker for worker in fresh if worker.state == AgentWorkerState.ONLINE]
    stale = [
        worker
        for worker in workers
        if worker.state != AgentWorkerState.OFFLINE
        and _as_utc(worker.last_heartbeat_at) < heartbeat_cutoff
    ]
    busy_ids = set(
        db.scalars(
            select(AgentExecution.worker_id).where(
                AgentExecution.status == AgentExecutionStatus.RUNNING,
                AgentExecution.worker_id.is_not(None),
                AgentExecution.lease_expires_at.is_not(None),
                AgentExecution.lease_expires_at >= now,
            )
        ).all()
    )
    fresh_ids = {worker.id for worker in fresh}
    return PoolObservation(
        queue_depth=len(queued),
        oldest_queue_age_seconds=_oldest_age(
            now, [item.created_at for item in queued]
        ),
        current_replicas=len(fresh),
        ready_replicas=len(ready),
        busy_replicas=len(busy_ids & fresh_ids),
        stale_replicas=len(stale),
    )


def observe_pool(
    db: Session,
    policy: WorkerScalingPolicy,
    *,
    now: datetime | None = None,
) -> PoolObservation:
    checked_at = _as_utc(now or utcnow())
    if policy.pool == WorkerScalingPool.COLLECTOR:
        return _collector_observation(db, policy, checked_at)
    if policy.pool == WorkerScalingPool.AGENT:
        return _agent_observation(db, policy, checked_at)
    raise ValueError(f"Unsupported worker scaling pool {policy.pool!r}")


def evaluate_scaling_policy(
    db: Session,
    policy: WorkerScalingPolicy,
    *,
    actor: str,
    now: datetime | None = None,
    commit: bool = True,
) -> WorkerScalingDecision:
    policy = _locked_scaling_policy(db, policy.id)
    checked_at = _as_utc(now or utcnow())
    observation = observe_pool(db, policy, now=checked_at)
    reasons: list[str] = []
    current = observation.current_replicas
    if not policy.enabled:
        desired = current
        reasons.append("policy_disabled")
    else:
        demand = math.ceil(
            observation.queue_depth / policy.target_queue_per_replica
        )
        demand = max(demand, observation.busy_replicas, policy.min_replicas)
        if observation.queue_depth > 0:
            demand = max(demand, 1)
            reasons.append("queue_backlog")
        if (
            observation.oldest_queue_age_seconds is not None
            and observation.oldest_queue_age_seconds
            > policy.queue_age_target_seconds
        ):
            demand = max(demand, current + policy.scale_out_step)
            reasons.append("queue_age_target_exceeded")
        raw_desired = max(policy.min_replicas, min(policy.max_replicas, demand))
        desired = min(raw_desired, current + policy.scale_out_step)
        desired = max(desired, current - policy.scale_in_step)
        desired = max(policy.min_replicas, min(policy.max_replicas, desired))
        if desired != raw_desired:
            reasons.append("bounded_step")
        latest = db.scalar(
            select(WorkerScalingDecision)
            .where(WorkerScalingDecision.policy_id == policy.id)
            .order_by(WorkerScalingDecision.observed_at.desc(), WorkerScalingDecision.id.desc())
            .limit(1)
        )
        if (
            latest is not None
            and latest.desired_replicas != current
            and checked_at - _as_utc(latest.observed_at)
            < timedelta(seconds=policy.cooldown_seconds)
            and desired != latest.desired_replicas
        ):
            desired = max(
                policy.min_replicas,
                min(policy.max_replicas, latest.desired_replicas),
            )
            reasons.append("cooldown_holds_previous_recommendation")
        if observation.stale_replicas:
            reasons.append("stale_workers_excluded")
        if not reasons:
            reasons.append("within_target")
    direction = (
        "scale_out"
        if desired > current
        else "scale_in"
        if desired < current
        else "hold"
    )
    decision = WorkerScalingDecision(
        policy_id=policy.id,
        policy_revision=policy.revision,
        queue_depth=observation.queue_depth,
        oldest_queue_age_seconds=observation.oldest_queue_age_seconds,
        current_replicas=current,
        ready_replicas=observation.ready_replicas,
        busy_replicas=observation.busy_replicas,
        stale_replicas=observation.stale_replicas,
        desired_replicas=desired,
        direction=direction,
        reasons=list(dict.fromkeys(reasons)),
        observed_at=checked_at,
        created_by=actor,
    )
    db.add(decision)
    db.flush()
    record_audit_event(
        db,
        event_type="scaling.policy.evaluated",
        actor_type="user" if not actor.startswith("system.") else "system",
        actor_id=actor,
        entity_type="worker_scaling_decision",
        entity_id=decision.id,
        details={
            "policy_id": policy.id,
            "policy_revision": policy.revision,
            "pool": policy.pool.value,
            "queue_depth": decision.queue_depth,
            "current_replicas": current,
            "desired_replicas": desired,
            "direction": direction,
            "reasons": decision.reasons,
        },
    )
    if commit:
        db.commit()
        db.refresh(decision)
    return decision


def list_scaling_decisions(
    db: Session,
    *,
    policy_id: str | None = None,
    limit: int = 100,
) -> list[WorkerScalingDecision]:
    query = select(WorkerScalingDecision)
    if policy_id is not None:
        query = query.where(WorkerScalingDecision.policy_id == policy_id)
    return list(
        db.scalars(
            query.order_by(WorkerScalingDecision.observed_at.desc()).limit(limit)
        ).all()
    )


_APPLICATION_TRANSITIONS: dict[str | None, set[str]] = {
    None: {"accepted", "rejected"},
    "accepted": {"applying", "applied", "failed"},
    "applying": {"applied", "failed"},
    "applied": set(),
    "failed": set(),
    "rejected": set(),
}
_ACTIVE_APPLICATION_STATUSES = {"accepted", "applying", "applied"}


def _same_application_event(
    event: WorkerScalingApplicationEvent,
    decision_id: str,
    payload: ScalingApplicationEventCreate,
) -> bool:
    return (
        event.decision_id == decision_id
        and event.status == payload.status
        and event.observed_replicas == payload.observed_replicas
        and event.detail_code == payload.detail_code
        and event.error_sha256 == payload.error_sha256
    )


def record_scaling_application_event(
    db: Session,
    decision: WorkerScalingDecision,
    payload: ScalingApplicationEventCreate,
    *,
    provider_subject: str,
    actor: str,
) -> WorkerScalingApplicationEvent:
    existing = db.scalar(
        select(WorkerScalingApplicationEvent).where(
            WorkerScalingApplicationEvent.provider_subject == provider_subject,
            WorkerScalingApplicationEvent.idempotency_key
            == payload.idempotency_key,
        )
    )
    if existing is not None:
        if _same_application_event(existing, decision.id, payload):
            return existing
        raise ValueError(
            "Capacity-provider idempotency key was reused with different content"
        )

    latest_decision_id = db.scalar(
        select(WorkerScalingDecision.id)
        .where(WorkerScalingDecision.policy_id == decision.policy_id)
        .order_by(
            WorkerScalingDecision.observed_at.desc(),
            WorkerScalingDecision.id.desc(),
        )
        .limit(1)
    )
    if (
        payload.status in _ACTIVE_APPLICATION_STATUSES
        and latest_decision_id != decision.id
    ):
        raise ValueError(
            "Only the latest scaling decision may be accepted or applied"
        )

    previous = db.scalar(
        select(WorkerScalingApplicationEvent)
        .where(
            WorkerScalingApplicationEvent.decision_id == decision.id,
            WorkerScalingApplicationEvent.provider_subject == provider_subject,
        )
        .order_by(
            WorkerScalingApplicationEvent.created_at.desc(),
            WorkerScalingApplicationEvent.id.desc(),
        )
        .limit(1)
    )
    previous_status = previous.status if previous is not None else None
    if payload.status not in _APPLICATION_TRANSITIONS[previous_status]:
        raise ValueError(
            "Invalid capacity-provider application transition "
            f"{previous_status or 'new'} -> {payload.status}"
        )

    event = WorkerScalingApplicationEvent(
        decision_id=decision.id,
        provider_subject=provider_subject,
        idempotency_key=payload.idempotency_key,
        status=payload.status,
        observed_replicas=payload.observed_replicas,
        detail_code=payload.detail_code,
        error_sha256=payload.error_sha256,
        created_by=actor,
    )
    db.add(event)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="scaling.application.reported",
            actor_type="capacity_provider",
            actor_id=actor,
            entity_type="worker_scaling_application_event",
            entity_id=event.id,
            details={
                "decision_id": decision.id,
                "policy_id": decision.policy_id,
                "provider_subject": provider_subject,
                "status": event.status,
                "observed_replicas": event.observed_replicas,
                "detail_code": event.detail_code,
                "error_sha256": event.error_sha256,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        concurrent = db.scalar(
            select(WorkerScalingApplicationEvent).where(
                WorkerScalingApplicationEvent.provider_subject
                == provider_subject,
                WorkerScalingApplicationEvent.idempotency_key
                == payload.idempotency_key,
            )
        )
        if (
            concurrent is not None
            and _same_application_event(concurrent, decision.id, payload)
        ):
            return concurrent
        raise ValueError(
            "Capacity-provider idempotency key already exists"
        ) from exc
    db.refresh(event)
    return event


def list_scaling_application_events(
    db: Session,
    *,
    decision_id: str | None = None,
    provider_subject: str | None = None,
    limit: int = 100,
) -> list[WorkerScalingApplicationEvent]:
    query = select(WorkerScalingApplicationEvent)
    if decision_id is not None:
        query = query.where(
            WorkerScalingApplicationEvent.decision_id == decision_id
        )
    if provider_subject is not None:
        query = query.where(
            WorkerScalingApplicationEvent.provider_subject == provider_subject
        )
    return list(
        db.scalars(
            query.order_by(
                WorkerScalingApplicationEvent.created_at.desc(),
                WorkerScalingApplicationEvent.id.desc(),
            ).limit(limit)
        ).all()
    )
