from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import stat
import subprocess
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .config import get_settings
from .database import SessionLocal, require_locking_transaction, session_namespace
from .models import (
    AgentExecution,
    AgentExecutionStatus,
    AgentWorker,
    AgentWorkerState,
    CollectorDeployment,
    CollectorWorker,
    CollectorWorkerState,
    DeviceConnectionPreflight,
    WorkerScalingApplicationEvent,
    WorkerScalingDecision,
    WorkerScalingPolicy,
    WorkerScalingPool,
    utcnow,
)
from .scaling_schemas import ScalingApplicationEventCreate
from .services.worker_scaling import _locked_scaling_policy, record_scaling_application_event
from .worker_namespace import (
    add_worker_namespace_arguments,
    bind_worker_namespace,
    parse_worker_namespace,
)


LOGGER = logging.getLogger("icheck.systemd_capacity_provider")
CONFIG_FORMAT = "icheck.systemd-capacity/v1"
INSTANCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,126}$")
NODE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,126}$")
CAPACITY_UNIT_PATTERN = re.compile(
    r"icheck-(?:collector|agent)-capacity@[A-Za-z0-9][A-Za-z0-9_.-]{0,126}\.service\Z"
)
CAPACITY_ACCOUNT = "icheck-capacity"
TERMINAL_APPLICATION_STATUSES = {"applied", "failed", "rejected"}


class SystemdCapacityError(RuntimeError):
    def __init__(self, detail_code: str, diagnostic: str) -> None:
        super().__init__(detail_code)
        self.detail_code = detail_code
        self.diagnostic = diagnostic


class SystemdCapacityPolicyMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pool: Literal["collector", "agent"]
    policy_name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    instances: list[str] = Field(min_length=1, max_length=1000)

    @field_validator("instances")
    @classmethod
    def validate_instances(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values):
            raise ValueError("capacity instance names must be unique")
        if any(INSTANCE_PATTERN.fullmatch(value) is None for value in values):
            raise ValueError("capacity instance name is invalid")
        return values


class SystemdCapacityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format_version: Literal[
        "icheck.systemd-capacity/v1"
    ] = CONFIG_FORMAT
    policies: list[SystemdCapacityPolicyMapping] = Field(
        min_length=1,
        max_length=1000,
    )

    @model_validator(mode="after")
    def validate_unique_bindings(self) -> "SystemdCapacityConfig":
        policy_keys = [
            (mapping.pool, mapping.policy_name) for mapping in self.policies
        ]
        if len(set(policy_keys)) != len(policy_keys):
            raise ValueError("capacity policy mappings must be unique")
        instances = [
            (mapping.pool, instance)
            for mapping in self.policies
            for instance in mapping.instances
        ]
        if len(set(instances)) != len(instances):
            raise ValueError("a systemd capacity instance may belong to one policy")
        return self

    def mapping_for(
        self,
        policy: WorkerScalingPolicy,
    ) -> SystemdCapacityPolicyMapping | None:
        pool = policy.pool.value
        return next(
            (
                mapping
                for mapping in self.policies
                if mapping.pool == pool and mapping.policy_name == policy.name
            ),
            None,
        )


def load_capacity_config(
    path: str,
    *,
    require_root_owner: bool = True,
) -> SystemdCapacityConfig:
    config_path = Path(path)
    if not config_path.is_absolute():
        raise ValueError("systemd capacity config path must be absolute")
    metadata = config_path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("systemd capacity config must be a regular file")
    if metadata.st_mode & 0o022:
        raise ValueError("systemd capacity config must not be group/world writable")
    if require_root_owner and metadata.st_uid != 0:
        raise ValueError("systemd capacity config must be owned by root")
    if require_root_owner:
        for parent in config_path.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("systemd capacity config ancestry must be root-owned and non-writable")
    if metadata.st_size > 65536:
        raise ValueError("systemd capacity config exceeds 64 KiB")
    with config_path.open("r", encoding="utf-8") as handle:
        document = json.load(handle)
    return SystemdCapacityConfig.model_validate(document)


def systemd_unit_name(pool: str, instance: str) -> str:
    if pool not in {"collector", "agent"}:
        raise ValueError("unsupported capacity pool")
    if INSTANCE_PATTERN.fullmatch(instance) is None:
        raise ValueError("invalid capacity instance")
    return f"icheck-{pool}-capacity@{instance}.service"


def capacity_worker_name(pool: str, instance: str) -> str:
    if pool not in {"collector", "agent"}:
        raise ValueError("unsupported capacity pool")
    if INSTANCE_PATTERN.fullmatch(instance) is None:
        raise ValueError("invalid capacity instance")
    return f"capacity-{pool}-{instance}"


def render_capacity_polkit_rule(config: SystemdCapacityConfig) -> str:
    """Render an operator-installed rule, not a runtime privilege escalation.

    Exact configured instance names are authorized. This never authorizes a
    template wildcard, restart, unit-file changes, transient-unit creation or
    an unrelated system service. The provider has no root fallback.
    """
    units = sorted(systemd_unit_name(mapping.pool, instance)
                   for mapping in config.policies for instance in mapping.instances)
    return (
        "// Generated from a protected iCheck capacity configuration.\n"
        "// Install as root before broader local rules; regenerate after reviewed config changes.\n"
        "polkit.addRule(function(action, subject) {\n"
        f"    if (subject.user !== {json.dumps(CAPACITY_ACCOUNT)}) return;\n"
        "    if (action.id !== 'org.freedesktop.systemd1.manage-units') {\n"
        "        if (action.id.indexOf('org.freedesktop.systemd1.') === 0) return polkit.Result.NO;\n"
        "        return;\n"
        "    }\n"
        f"    var units = {json.dumps(units)};\n"
        "    var verb = action.lookup('verb');\n"
        "    var unit = action.lookup('unit');\n"
        "    if ((verb === 'start' || verb === 'stop') && units.indexOf(unit) !== -1) {\n"
        "        return polkit.Result.YES;\n"
        "    }\n"
        "    return polkit.Result.NO;\n"
        "});\n"
    )


class SystemdRunner:
    def __init__(
        self,
        *,
        systemctl_path: str = "/usr/bin/systemctl",
        timeout_seconds: int = 30,
    ) -> None:
        if not os.path.isabs(systemctl_path):
            raise ValueError("systemctl path must be absolute")
        if timeout_seconds < 1 or timeout_seconds > 60:
            raise ValueError("systemctl timeout must be between 1 and 60 seconds")
        self.systemctl_path = systemctl_path
        self.timeout_seconds = timeout_seconds

    def _run(self, action: str, unit: str) -> subprocess.CompletedProcess[str]:
        if action not in {"is-active", "start", "stop"} or CAPACITY_UNIT_PATTERN.fullmatch(unit) is None:
            raise SystemdCapacityError(
                "systemd.unit_not_allowed",
                f"unit rejected: {unit}",
            )
        try:
            return subprocess.run(
                [self.systemctl_path, "--no-ask-password", action, unit],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SystemdCapacityError(
                "systemd.command_unavailable",
                f"{action}:{unit}:{type(exc).__name__}",
            ) from exc

    def is_active(self, unit: str) -> bool:
        result = self._run("is-active", unit)
        if result.returncode == 0:
            return True
        if result.returncode in {3, 4}:
            return False
        raise SystemdCapacityError(
            "systemd.inspect_failed",
            f"is-active:{unit}:{result.returncode}:{result.stderr[:1000]}",
        )

    def start(self, unit: str) -> None:
        result = self._run("start", unit)
        if result.returncode != 0:
            raise SystemdCapacityError(
                "systemd.start_failed",
                f"start:{unit}:{result.returncode}:{result.stderr[:1000]}",
            )

    def stop(self, unit: str) -> None:
        result = self._run("stop", unit)
        if result.returncode != 0:
            raise SystemdCapacityError(
                "systemd.stop_failed",
                f"stop:{unit}:{result.returncode}:{result.stderr[:1000]}",
            )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _latest_application(
    db: Session,
    decision_id: str,
    provider_subject: str,
) -> WorkerScalingApplicationEvent | None:
    return db.scalar(
        select(WorkerScalingApplicationEvent)
        .where(
            WorkerScalingApplicationEvent.decision_id == decision_id,
            WorkerScalingApplicationEvent.provider_subject == provider_subject,
        )
        .order_by(
            WorkerScalingApplicationEvent.created_at.desc(),
            WorkerScalingApplicationEvent.id.desc(),
        )
        .limit(1)
    )


def _record_application(
    db: Session,
    decision: WorkerScalingDecision,
    *,
    provider_subject: str,
    status: Literal[
        "accepted",
        "applying",
        "applied",
        "failed",
        "rejected",
    ],
    observed_replicas: int,
    detail_code: str,
    error_sha256: str | None = None,
) -> WorkerScalingApplicationEvent:
    suffix = f":{error_sha256[:16]}" if error_sha256 else ""
    payload = ScalingApplicationEventCreate(
        idempotency_key=f"{decision.id}:{status}{suffix}",
        status=status,
        observed_replicas=observed_replicas,
        detail_code=detail_code,
        error_sha256=error_sha256,
    )
    return record_scaling_application_event(
        db,
        decision,
        payload,
        provider_subject=provider_subject,
        actor=provider_subject,
    )


def _active_instances(
    runner: SystemdRunner,
    mapping: SystemdCapacityPolicyMapping,
) -> list[str]:
    return [
        instance
        for instance in mapping.instances
        if runner.is_active(systemd_unit_name(mapping.pool, instance))
    ]


def _worker_for_instance(
    db: Session,
    mapping: SystemdCapacityPolicyMapping,
    instance: str,
    *,
    lock: bool = False,
) -> CollectorWorker | AgentWorker | None:
    name = capacity_worker_name(mapping.pool, instance)
    model = CollectorWorker if mapping.pool == "collector" else AgentWorker
    query = select(model).where(model.name == name).execution_options(populate_existing=True)
    if lock:
        query = query.with_for_update()
    return db.scalar(query)


def _worker_matches_policy(
    worker: CollectorWorker | AgentWorker,
    policy: WorkerScalingPolicy,
) -> bool:
    required = set(policy.required_capabilities or [])
    if not required.issubset(set(worker.capabilities or [])):
        return False
    if policy.pool == WorkerScalingPool.AGENT:
        return True
    assert isinstance(worker, CollectorWorker)
    labels = {str(key): str(value) for key, value in (worker.labels or {}).items()}
    if worker.site:
        labels.setdefault("site", worker.site)
    return all(labels.get(key) == value for key, value in (policy.selector or {}).items())


def _worker_is_healthy(
    worker: CollectorWorker | AgentWorker | None,
    policy: WorkerScalingPolicy,
    *,
    now: datetime,
) -> bool:
    if worker is None or not _worker_matches_policy(worker, policy):
        return False
    if worker.state.value != "online":
        return False
    cutoff = now - timedelta(seconds=policy.heartbeat_timeout_seconds)
    return cutoff <= _as_utc(worker.last_heartbeat_at) <= now


def _worker_has_active_lease(
    db: Session,
    worker: CollectorWorker | AgentWorker,
    *,
    now: datetime,
) -> bool:
    if isinstance(worker, CollectorWorker):
        deployment_count = db.scalar(
            select(func.count(CollectorDeployment.id)).where(
                CollectorDeployment.lease_worker_id == worker.id,
                CollectorDeployment.lease_expires_at.is_not(None),
                CollectorDeployment.lease_expires_at >= now,
            )
        )
        preflight_count = db.scalar(
            select(func.count(DeviceConnectionPreflight.id)).where(
                DeviceConnectionPreflight.worker_id == worker.id,
                DeviceConnectionPreflight.status == "running",
                DeviceConnectionPreflight.lease_expires_at >= now,
            )
        )
        return bool((deployment_count or 0) + (preflight_count or 0))
    execution_count = db.scalar(
        select(func.count(AgentExecution.id)).where(
            AgentExecution.worker_id == worker.id,
            AgentExecution.status == AgentExecutionStatus.RUNNING,
            AgentExecution.lease_expires_at.is_not(None),
            AgentExecution.lease_expires_at >= now,
        )
    )
    return bool(execution_count or 0)


def _set_worker_state(
    worker: CollectorWorker | AgentWorker,
    state: str,
) -> None:
    if isinstance(worker, CollectorWorker):
        worker.state = CollectorWorkerState(state)
    else:
        worker.state = AgentWorkerState(state)
    worker.updated_at = utcnow()


def _application_timed_out(
    db: Session,
    decision_id: str,
    provider_subject: str,
    *,
    now: datetime,
    timeout_seconds: int,
) -> bool:
    started = db.scalar(
        select(func.min(WorkerScalingApplicationEvent.created_at)).where(
            WorkerScalingApplicationEvent.decision_id == decision_id,
            WorkerScalingApplicationEvent.provider_subject == provider_subject,
            WorkerScalingApplicationEvent.status.in_(["accepted", "applying"]),
        )
    )
    return bool(
        started is not None
        and now - _as_utc(started) > timedelta(seconds=timeout_seconds)
    )


def _fail_application(
    db: Session,
    decision: WorkerScalingDecision,
    *,
    provider_subject: str,
    observed_replicas: int,
    error: SystemdCapacityError,
) -> WorkerScalingApplicationEvent:
    error_hash = hashlib.sha256(error.diagnostic.encode("utf-8")).hexdigest()
    LOGGER.error(
        "decision=%s detail=%s error_sha256=%s",
        decision.id,
        error.detail_code,
        error_hash,
    )
    return _record_application(
        db,
        decision,
        provider_subject=provider_subject,
        status="failed",
        observed_replicas=observed_replicas,
        detail_code=error.detail_code,
        error_sha256=error_hash,
    )


def _fenced_inputs(
    db: Session, decision: WorkerScalingDecision, policy: WorkerScalingPolicy,
    mapping: SystemdCapacityPolicyMapping | None,
    config_loader: Callable[[], SystemdCapacityConfig] | None,
) -> tuple[WorkerScalingDecision, WorkerScalingPolicy]:
    """Fence one bounded host operation with the current policy mutex.

    Scaling recommendations and policy edits use this same row mutex. Reacquire
    after every commit; a receipt is not continuing authorization for old inputs.
    """
    policy = _locked_scaling_policy(db, policy.id)
    current = _latest_decision(db, policy.id)
    if current is None or current.id != decision.id:
        raise SystemdCapacityError("systemd.decision_superseded", "decision is not current")
    decision = current
    if not policy.enabled:
        raise SystemdCapacityError("systemd.policy_disabled", "policy is disabled")
    if decision.policy_revision != policy.revision:
        raise SystemdCapacityError("systemd.policy_revision_stale", "policy revision changed")
    if mapping is None:
        raise SystemdCapacityError("systemd.policy_not_mapped", "policy mapping is absent")
    if mapping.pool != policy.pool.value or mapping.policy_name != policy.name:
        raise SystemdCapacityError("systemd.policy_mapping_changed", "policy mapping binding changed")
    if config_loader is not None:
        try:
            current_mapping = config_loader().mapping_for(policy)
        except (OSError, ValueError) as exc:
            raise SystemdCapacityError("systemd.policy_mapping_unavailable", type(exc).__name__) from exc
        if current_mapping != mapping:
            raise SystemdCapacityError("systemd.policy_mapping_changed", "protected mapping changed")
    if not policy.min_replicas <= decision.desired_replicas <= policy.max_replicas:
        raise SystemdCapacityError("systemd.capacity_out_of_bounds", "decision exceeds current policy bounds")
    if decision.desired_replicas > len(mapping.instances):
        raise SystemdCapacityError("systemd.capacity_exceeds_allowlist", "decision exceeds configured instances")
    if _as_utc(decision.observed_at) > utcnow():
        raise SystemdCapacityError("systemd.decision_clock_invalid", "decision observation is in the future")
    return decision, policy


def _reconcile_decision(
    db: Session,
    decision: WorkerScalingDecision,
    policy: WorkerScalingPolicy,
    mapping: SystemdCapacityPolicyMapping | None,
    *,
    provider_subject: str,
    runner: SystemdRunner,
    apply_timeout_seconds: int,
    now: datetime | None = None,
    config_loader: Callable[[], SystemdCapacityConfig] | None = None,
) -> WorkerScalingApplicationEvent:
    checked_at = _as_utc(now or utcnow())
    latest = _latest_application(db, decision.id, provider_subject)
    if latest is not None and latest.status in TERMINAL_APPLICATION_STATUSES:
        return latest

    def fence():
        leader = db.info.get("capacity_leader_connection")
        if db.get_bind().dialect.name == "postgresql":
            if leader is None or not leader.in_transaction():
                raise RuntimeError("Capacity leader transaction is not held")
            # Detect an expired/killed leader connection before another host
            # operation. PostgreSQL cannot make external systemd I/O atomic.
            leader.scalar(text("SELECT 1"))
        current_decision, current_policy = _fenced_inputs(db, decision, policy, mapping, config_loader)
        if _application_timed_out(db, current_decision.id, provider_subject,
                now=max(checked_at, utcnow()), timeout_seconds=apply_timeout_seconds):
            raise SystemdCapacityError("systemd.convergence_timeout", "application deadline expired")
        return current_decision, current_policy

    try:
        decision, policy = fence()
        assert mapping is not None
        active = _active_instances(runner, mapping)
    except SystemdCapacityError as exc:
        db.rollback()
        if latest is None:
            LOGGER.error("decision=%s detail=%s", decision.id, exc.detail_code)
            return _record_application(
                db,
                decision,
                provider_subject=provider_subject,
                status="rejected",
                observed_replicas=0,
                detail_code=exc.detail_code,
            )
        return _fail_application(
            db,
            decision,
            provider_subject=provider_subject,
            observed_replicas=latest.observed_replicas,
            error=exc,
        )

    target = set(mapping.instances[: decision.desired_replicas])
    try:
        if latest is None:
            latest = _record_application(db, decision, provider_subject=provider_subject,
                status="accepted", observed_replicas=len(active), detail_code="systemd.decision_accepted")
        decision, policy = fence()
        if latest.status == "accepted":
            latest = _record_application(db, decision, provider_subject=provider_subject,
                status="applying", observed_replicas=len(active), detail_code="systemd.reconciling")
        for instance in mapping.instances:
            if instance not in target:
                continue
            decision, policy = fence()
            if runner.is_active(systemd_unit_name(mapping.pool, instance)):
                worker = _worker_for_instance(db, mapping, instance, lock=True)
                if worker is not None and worker.state.value == "draining":
                    _set_worker_state(worker, "online")
            else:
                runner.start(systemd_unit_name(mapping.pool, instance))
            db.commit()

        for instance in reversed(mapping.instances):
            if instance in target:
                continue
            decision, policy = fence()
            unit = systemd_unit_name(mapping.pool, instance)
            if not runner.is_active(unit):
                worker = _worker_for_instance(db, mapping, instance, lock=True)
                if (worker is not None and worker.state.value == "draining"
                        and not _worker_has_active_lease(db, worker, now=utcnow())):
                    _set_worker_state(worker, "offline")
                db.commit()
                continue
            worker = _worker_for_instance(db, mapping, instance, lock=True)
            if worker is None:
                raise SystemdCapacityError(
                    "systemd.worker_identity_unverified",
                    f"missing worker for {mapping.pool}:{instance}",
                )
            _set_worker_state(worker, "draining")
            # Publish drain before checking leases. Admission and renewal take
            # this registry mutex before lease rows, so no late claim can pass.
            db.commit()
            decision, policy = fence()
            worker = _worker_for_instance(db, mapping, instance, lock=True)
            if worker is None or worker.state.value != "draining":
                raise SystemdCapacityError("systemd.worker_drain_changed", "drain barrier changed")
            if _worker_has_active_lease(db, worker, now=utcnow()):
                db.commit()
                continue
            if runner.is_active(unit):
                runner.stop(unit)
            if runner.is_active(unit):
                raise SystemdCapacityError("systemd.stop_not_confirmed", "unit remains active after stop")
            _set_worker_state(worker, "offline")
            db.commit()

        decision, policy = fence()
        active = _active_instances(runner, mapping)
        active_set = set(active)
        healthy = all(
            _worker_is_healthy(
                _worker_for_instance(db, mapping, instance, lock=True),
                policy,
                now=utcnow(),
            )
            for instance in sorted(target)
        )
        if active_set == target and healthy:
            decision, policy = fence()
            return _record_application(
                db,
                decision,
                provider_subject=provider_subject,
                status="applied",
                observed_replicas=len(active),
                detail_code="systemd.capacity_converged",
            )
        if _application_timed_out(
            db,
            decision.id,
            provider_subject,
            now=max(checked_at, utcnow()),
            timeout_seconds=apply_timeout_seconds,
        ):
            raise SystemdCapacityError(
                "systemd.convergence_timeout",
                f"active={sorted(active_set)} target={sorted(target)} healthy={healthy}",
            )
        db.commit()
        db.refresh(latest)
        return latest
    except SystemdCapacityError as exc:
        db.rollback()
        return _fail_application(
            db,
            decision,
            provider_subject=provider_subject,
            observed_replicas=len(active),
            error=exc,
        )


def _latest_decision(
    db: Session,
    policy_id: str,
) -> WorkerScalingDecision | None:
    return db.scalar(
        select(WorkerScalingDecision)
        .where(WorkerScalingDecision.policy_id == policy_id)
        .order_by(
            WorkerScalingDecision.observed_at.desc(),
            WorkerScalingDecision.id.desc(),
        )
        .limit(1)
        .execution_options(populate_existing=True)
    )


@contextmanager
def _provider_lock(db: Session, *, tenant_id: str, region_id: str) -> Iterator[bool]:
    require_locking_transaction(db, purpose="Capacity leader election and host operations")
    if db.get_bind().dialect.name != "postgresql":
        yield True
        return
    if session_namespace(db) != (tenant_id, region_id):
        raise ValueError("Capacity controller namespace differs from its bound session")
    key = f"icheck.systemd-capacity:{tenant_id}:{region_id}"
    if db.info.get("capacity_leader_key") == key:
        yield True
        return
    # Business Session commits must not release leadership. Retain a separate
    # transaction/connection for the whole cycle, using an xact lock rather
    # than leaking a session-level advisory lock into a connection pool.
    bind = db.get_bind()
    engine = getattr(bind, "engine", bind)
    with engine.connect() as leader:
        acquired = bool(leader.scalar(text(
            "SELECT pg_try_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": key}))
        if not acquired:
            yield False
            return
        db.info["capacity_leader_key"] = key
        db.info["capacity_leader_connection"] = leader
        try:
            yield True
        finally:
            db.info.pop("capacity_leader_key", None)
            db.info.pop("capacity_leader_connection", None)
            try:
                leader.rollback()
            except BaseException:
                # Never return an uncertain leader transaction to a shared pool.
                leader.invalidate()
                raise


def reconcile_decision(
    db: Session, decision: WorkerScalingDecision, policy: WorkerScalingPolicy,
    mapping: SystemdCapacityPolicyMapping | None, *, provider_subject: str,
    runner: SystemdRunner, apply_timeout_seconds: int, now: datetime | None = None,
    config_loader: Callable[[], SystemdCapacityConfig] | None = None,
) -> WorkerScalingApplicationEvent | None:
    require_locking_transaction(db, purpose="Capacity decisions and host operations")
    namespace = session_namespace(db)
    if db.get_bind().dialect.name == "postgresql" and namespace is None:
        raise ValueError("Capacity controller requires its bound namespace")
    if not 30 <= apply_timeout_seconds <= 3600:
        raise ValueError("Capacity timeout must be between 30 and 3600 seconds")
    if not provider_subject.startswith("systemd:") or NODE_PATTERN.fullmatch(provider_subject[8:]) is None:
        raise ValueError("Capacity provider requires a bounded systemd identity")
    with _provider_lock(db, tenant_id=namespace[0] if namespace else "sqlite",
                        region_id=namespace[1] if namespace else "sqlite") as acquired:
        if not acquired:
            db.rollback()
            return None
        return _reconcile_decision(db, decision, policy, mapping, provider_subject=provider_subject,
            runner=runner, apply_timeout_seconds=apply_timeout_seconds, now=now, config_loader=config_loader)


def reconcile_once(
    db: Session,
    config: SystemdCapacityConfig,
    *,
    tenant_id: str,
    region_id: str,
    provider_subject: str,
    runner: SystemdRunner,
    apply_timeout_seconds: int,
    config_loader: Callable[[], SystemdCapacityConfig] | None = None,
) -> int:
    with _provider_lock(db, tenant_id=tenant_id, region_id=region_id) as acquired:
        if not acquired:
            db.rollback()
            return 0
        reconciled = 0
        policies = list(db.scalars(select(WorkerScalingPolicy)
            .order_by(WorkerScalingPolicy.id).limit(1000)
            .execution_options(populate_existing=True)).all())
        for policy in policies:
            decision = _latest_decision(db, policy.id)
            if decision is None:
                continue
            event = reconcile_decision(
                db,
                decision,
                policy,
                config.mapping_for(policy),
                provider_subject=provider_subject,
                runner=runner,
                apply_timeout_seconds=apply_timeout_seconds,
                config_loader=config_loader,
            )
            if event is None:
                continue
            reconciled += 1
            LOGGER.info(
                "policy=%s decision=%s status=%s observed=%s desired=%s",
                policy.id,
                decision.id,
                event.status,
                event.observed_replicas,
                decision.desired_replicas,
            )
        return reconciled


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reconcile iCheck worker capacity with allowlisted systemd units"
    )
    add_worker_namespace_arguments(parser)
    parser.add_argument(
        "--config",
        default=os.environ.get(
            "ICHECK_SYSTEMD_CAPACITY_CONFIG",
            "/etc/icheck-workers/capacity/systemd-capacity.json",
        ),
    )
    parser.add_argument(
        "--node-id",
        default=os.environ.get("ICHECK_SYSTEMD_CAPACITY_NODE_ID"),
    )
    parser.add_argument(
        "--systemctl-path",
        default=os.environ.get(
            "ICHECK_SYSTEMD_CAPACITY_SYSTEMCTL_PATH",
            "/usr/bin/systemctl",
        ),
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=float(
            os.environ.get("ICHECK_SYSTEMD_CAPACITY_POLL_SECONDS", "15")
        ),
    )
    parser.add_argument(
        "--apply-timeout-seconds",
        type=int,
        default=int(
            os.environ.get("ICHECK_SYSTEMD_CAPACITY_APPLY_TIMEOUT_SECONDS", "300")
        ),
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--render-polkit", action="store_true",
                        help="Print the exact-instance rule for root to review and install; do not run a controller")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: Any) -> None:
    if not args.node_id or NODE_PATTERN.fullmatch(args.node_id) is None:
        parser.error("--node-id must be a bounded systemd provider identity")
    if args.poll_seconds < 5 or args.poll_seconds > 300:
        parser.error("--poll-seconds must be between 5 and 300")
    if args.apply_timeout_seconds < 30 or args.apply_timeout_seconds > 3600:
        parser.error("--apply-timeout-seconds must be between 30 and 3600")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("ICHECK_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = _parser()
    args = parser.parse_args()
    if args.render_polkit:
        try:
            rule = render_capacity_polkit_rule(load_capacity_config(args.config))
        except (OSError, ValueError) as exc:
            parser.exit(1, f"Capacity policy rendering failed ({type(exc).__name__}).\n")
        print(rule, end="")
        return 0
    if os.geteuid() == 0:
        parser.error("Run the controller under the isolated unprivileged icheck-capacity account, not root")
    _validate_args(parser, args)
    namespace = parse_worker_namespace(parser, args)
    settings = get_settings()
    if not settings.database_url.startswith(
        ("postgresql://", "postgresql+psycopg://")
    ):
        parser.error("the systemd capacity provider requires PostgreSQL")
    runner = SystemdRunner(systemctl_path=args.systemctl_path)
    provider_subject = f"systemd:{args.node_id}"

    while True:
        try:
            config = load_capacity_config(args.config)
            with SessionLocal() as db:
                bind_worker_namespace(db, namespace)
                reconciled = reconcile_once(
                    db,
                    config,
                    tenant_id=namespace.tenant_id,
                    region_id=namespace.region_id,
                    provider_subject=provider_subject,
                    runner=runner,
                    apply_timeout_seconds=args.apply_timeout_seconds,
                    config_loader=lambda: load_capacity_config(args.config),
                )
        except Exception as exc:
            digest = hashlib.sha256(
                f"{type(exc).__name__}:{exc}".encode("utf-8")
            ).hexdigest()
            LOGGER.error(
                "capacity reconciliation cycle failed type=%s error_sha256=%s",
                type(exc).__name__,
                digest,
            )
            if args.once:
                return 1
            reconciled = 0
        if args.once:
            return 0
        if not reconciled:
            LOGGER.debug("no scaling decisions reconciled")
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
