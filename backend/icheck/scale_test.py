from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import queue
import resource
import threading
import time
from collections import Counter
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .database import (
    DEFAULT_REGION_ID,
    DEFAULT_TENANT_ID,
    set_session_namespace,
)
from .collector_schemas import (
    CollectionEnvelopeBatch,
    CollectionEnvelopeInput,
    CollectorLeaseClaim,
    CollectorRunAdmit,
    CollectorRunComplete,
)
from .models import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    CollectionEnvelope,
    CollectorDefinition,
    CollectorDeployment,
    CollectorMode,
    CollectorRun,
    CollectorRunStatus,
    CollectorWorker,
    CollectorWorkerState,
    Device,
    Endpoint,
    EnvelopeKind,
    KnowledgeProjection,
    KnowledgeProjectionStatus,
    KnowledgeProjectionWorker,
    utcnow,
)
from .projection_schemas import NETWORK_OBSERVATION_V1, ProjectionAssignment
from .services.alerts import ensure_default_rules
from .services.collectors import (
    admit_run_execution,
    claim_deployments,
    complete_run,
    ingest_envelopes,
)
from .services.knowledge_projection import (
    ProjectionLeaseLost,
    claim_projections,
    process_projection_assignment,
    register_projection_worker,
)


MIGRATIONS_DIRECTORY = Path(__file__).resolve().parents[1] / "migrations"


def expected_schema_head() -> str:
    """Pin one installed migration graph for the whole scale run."""
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIRECTORY))
    heads = ScriptDirectory.from_config(config).get_heads()
    if len(heads) != 1:
        raise ValueError(f"Scale harness requires one Alembic head, found {len(heads)}")
    return heads[0]


def _bind_scale_namespace(db: Session) -> None:
    set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)


@dataclass(frozen=True)
class ScaleConfig:
    database_url: str
    run_prefix: str
    targets: int = 1000
    collector_workers: int = 2
    projection_workers: int = 2
    batch_size: int = 20
    projection_batch_size: int = 50
    lease_seconds: int = 120
    schedule_seconds: int = 3600
    timeout_seconds: int = 300
    series_per_target: int = 8
    max_projection_lag_seconds: float = 60.0
    min_worker_share: float = 0.05
    allow_sqlite_smoke: bool = False


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * quantile))))
    return round(ordered[index], 6)


def latency_summary(values: list[float]) -> dict[str, float | None]:
    return {
        "min": round(min(values), 6) if values else None,
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": round(max(values), 6) if values else None,
    }


def _error_fingerprint(exc: Exception) -> str:
    message = str(exc) or type(exc).__name__
    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return f"{type(exc).__name__}:{digest}"


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _engine(database_url: str) -> Engine:
    options: dict[str, Any] = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            options["poolclass"] = StaticPool
    return create_engine(database_url, **options)


def _database_size(engine: Engine) -> int | None:
    if engine.dialect.name != "postgresql":
        return None
    with engine.connect() as connection:
        value = connection.scalar(
            select(func.pg_database_size(func.current_database()))
        )
    return int(value) if value is not None else None


def _verify_dedicated_database(
    session_factory: sessionmaker[Session],
    *,
    engine: Engine,
    allow_sqlite_smoke: bool,
    schema_head: str,
) -> None:
    if engine.dialect.name != "postgresql" and not allow_sqlite_smoke:
        raise ValueError(
            "Representative scale evidence requires PostgreSQL; "
            "use --allow-sqlite-smoke only for a non-representative smoke run"
        )
    with engine.connect() as connection:
        if engine.dialect.name != "sqlite" or not allow_sqlite_smoke:
            head = connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one_or_none()
            if head != schema_head:
                raise ValueError(
                    f"Scale database must be migrated to {schema_head}; "
                    f"found {head or 'no Alembic head'}"
                )
    with session_factory() as db:
        _bind_scale_namespace(db)
        counts = {
            "artifacts": db.scalar(select(func.count()).select_from(Artifact)) or 0,
            "devices": db.scalar(select(func.count()).select_from(Device)) or 0,
            "deployments": (
                db.scalar(select(func.count()).select_from(CollectorDeployment)) or 0
            ),
            "projections": (
                db.scalar(select(func.count()).select_from(KnowledgeProjection)) or 0
            ),
        }
    if any(counts.values()):
        raise ValueError(
            "Scale test refuses a non-empty database; provide a dedicated "
            f"migration-only database (found {counts})"
        )


def _mac_for(index: int) -> str:
    value = index + 1
    return "02:00:%02x:%02x:%02x:%02x" % (
        (value >> 24) & 0xFF,
        (value >> 16) & 0xFF,
        (value >> 8) & 0xFF,
        value & 0xFF,
    )


def _ip_for(index: int) -> str:
    base = int(ipaddress.ip_address("10.64.0.1"))
    return str(ipaddress.ip_address(base + index))


def _setup_scale_data(
    session_factory: sessionmaker[Session],
    config: ScaleConfig,
) -> tuple[
    dict[str, dict[str, Any]],
    list[str],
    list[str],
]:
    now = utcnow()
    due_at = now
    content_hash = hashlib.sha256(
        f"{config.run_prefix}:collector".encode("utf-8")
    ).hexdigest()
    with session_factory() as db:
        _bind_scale_namespace(db)
        ensure_default_rules(db)
        artifact = Artifact(
            name=f"{config.run_prefix}-collector",
            kind=ArtifactKind.COLLECTOR,
            description="Synthetic M1 scheduler and knowledge-projection load",
            owner="scale-test",
            labels={"scale_test": config.run_prefix},
        )
        version = ArtifactVersion(
            artifact=artifact,
            version=1,
            status=ArtifactVersionStatus.PUBLISHED,
            definition={"purpose": "M1 scale evidence"},
            implementation={"runtime": "synthetic"},
            tests=[],
            validation_report={"scale_harness": True},
            content_hash=content_hash,
            created_by="scale-test",
            validated_at=now,
            validated_by="scale-test",
            published_at=now,
            published_by="scale-test",
        )
        db.add(artifact)
        db.add(version)
        db.flush()
        db.add(
            CollectorDefinition(
                artifact_version_id=version.id,
                adapter_type="scale_synthetic",
                mode=CollectorMode.POLL,
                output_kinds=[EnvelopeKind.OBSERVATION.value],
                target_schema={"type": "object"},
                config_schema={"type": "object"},
                defaults={},
            )
        )

        targets: dict[str, dict[str, Any]] = {}
        devices: list[Device] = []
        deployments: list[CollectorDeployment] = []
        for index in range(config.targets):
            device = Device(
                name=f"{config.run_prefix}-target-{index:05d}",
                kind="switch",
                site="SCALE",
                labels={"scale_test": config.run_prefix},
                created_by="scale-test",
            )
            devices.append(device)
            db.add(device)
        db.flush()
        for index, device in enumerate(devices):
            deployment = CollectorDeployment(
                name=f"{config.run_prefix}-deployment-{index:05d}",
                artifact_version_id=version.id,
                scope_device_id=device.id,
                scope_device_identity_revision=device.identity_revision,
                scope_site="SCALE",
                target={"synthetic_index": index},
                configuration={},
                worker_selector={"site": "SCALE"},
                schedule_seconds=config.schedule_seconds,
                enabled=True,
                created_by="scale-test",
                next_run_at=due_at,
                created_at=due_at,
            )
            deployments.append(deployment)
            db.add(deployment)
        db.flush()
        for index, deployment in enumerate(deployments):
            targets[deployment.id] = {
                "index": index,
                "device_id": devices[index].id,
                "mac_address": _mac_for(index),
                "ip_address": _ip_for(index),
            }

        collector_ids: list[str] = []
        for index in range(config.collector_workers):
            worker = CollectorWorker(
                name=f"{config.run_prefix}-collector-worker-{index + 1}",
                site="SCALE",
                capabilities=["scale_synthetic"],
                labels={"scale_test": config.run_prefix, "io_supervisor_v1": True},
                auth_token_hash=hashlib.sha256(
                    f"{config.run_prefix}:collector:{index}".encode("utf-8")
                ).hexdigest(),
                state=CollectorWorkerState.ONLINE,
            )
            db.add(worker)
            db.flush()
            collector_ids.append(worker.id)
        db.commit()

    projection_ids: list[str] = []
    with session_factory() as db:
        _bind_scale_namespace(db)
        for index in range(config.projection_workers):
            worker = register_projection_worker(
                db,
                name=f"{config.run_prefix}-projection-worker-{index + 1}",
            )
            projection_ids.append(worker.id)
    return targets, collector_ids, projection_ids


def _collector_envelope(
    *,
    prefix: str,
    target: dict[str, Any],
) -> CollectionEnvelopeInput:
    index = int(target["index"])
    return CollectionEnvelopeInput(
        kind=EnvelopeKind.OBSERVATION,
        type=NETWORK_OBSERVATION_V1,
        source=f"scale:{prefix}",
        subject=str(target["mac_address"]),
        observed_at=utcnow(),
        idempotency_key=f"target:{index}:cycle:1",
        payload={
            "mac_address": target["mac_address"],
            "ip_address": target["ip_address"],
            "source": "arp",
            "collector_device_id": target["device_id"],
            "interface_name": f"Ethernet1/{(index % 48) + 1}",
            "vlan_id": (index % 4000) + 1,
            "hostname": f"synthetic-endpoint-{index:05d}",
            "raw_data": {"scale_test": True},
        },
    )


def _successful_run_count(
    db: Session,
    *,
    prefix: str,
) -> int:
    return (
        db.scalar(
            select(func.count(CollectorRun.id))
            .join(CollectorRun.deployment)
            .where(
                CollectorDeployment.name.like(f"{prefix}-deployment-%"),
                CollectorRun.status == CollectorRunStatus.SUCCEEDED,
            )
        )
        or 0
    )


def _terminal_projection_count(
    db: Session,
    *,
    prefix: str,
) -> int:
    return (
        db.scalar(
            select(func.count(KnowledgeProjection.id))
            .join(KnowledgeProjection.envelope)
            .join(CollectionEnvelope.run)
            .join(CollectorRun.deployment)
            .where(
                CollectorDeployment.name.like(f"{prefix}-deployment-%"),
                KnowledgeProjection.status.in_(
                    [
                        KnowledgeProjectionStatus.SUCCEEDED,
                        KnowledgeProjectionStatus.IGNORED,
                        KnowledgeProjectionStatus.DEAD_LETTER,
                    ]
                ),
            )
        )
        or 0
    )


def _prepare_collector_reassignment(
    session_factory: sessionmaker[Session],
    config: ScaleConfig,
    collector_ids: list[str],
):
    with session_factory() as db:
        _bind_scale_namespace(db)
        first = db.get(CollectorWorker, collector_ids[0])
        second = db.get(CollectorWorker, collector_ids[1])
        if first is None or second is None:
            raise RuntimeError("Collector scale workers disappeared")
        stale = claim_deployments(
            db,
            first,
            CollectorLeaseClaim(max_assignments=1, lease_seconds=15),
        )
        if len(stale) != 1:
            raise RuntimeError("Unable to create the collector failure assignment")
        deployment = db.get(CollectorDeployment, stale[0].deployment_id)
        if deployment is None:
            raise RuntimeError("Collector failure deployment disappeared")
        deployment.lease_expires_at = utcnow() - timedelta(seconds=1)
        deployment.next_run_at = utcnow() - timedelta(seconds=600)
        db.commit()
        replacement = claim_deployments(
            db,
            second,
            CollectorLeaseClaim(max_assignments=1, lease_seconds=config.lease_seconds),
        )
        if (
            len(replacement) != 1
            or replacement[0].deployment_id != stale[0].deployment_id
        ):
            raise RuntimeError("Expired Collector lease was not reassigned")
        try:
            ingest_envelopes(
                db,
                stale[0].run_id,
                CollectionEnvelopeBatch(
                    lease_token=stale[0].lease_token,
                    envelopes=[
                        _collector_envelope(
                            prefix=config.run_prefix,
                            target={
                                "index": -1,
                                "device_id": deployment.scope_device_id,
                                "mac_address": "02:ff:ff:ff:ff:ff",
                                "ip_address": "10.255.255.254",
                            },
                        )
                    ],
                ),
            )
        except ValueError:
            pass
        else:
            raise RuntimeError("Stale Collector lease was able to ingest")
        return replacement[0]


def _run_collectors(
    session_factory: sessionmaker[Session],
    config: ScaleConfig,
    *,
    targets: dict[str, dict[str, Any]],
    collector_ids: list[str],
    initial_replacement: Any,
    smoke_seed_each_worker: bool = False,
) -> tuple[dict[str, int], list[str]]:
    stop = threading.Event()
    errors: queue.Queue[str] = queue.Queue()
    counts: Counter[str] = Counter()
    counts_lock = threading.Lock()
    deadline = time.monotonic() + config.timeout_seconds
    initial_by_worker: dict[str, list[Any]] = {
        worker_id: [] for worker_id in collector_ids
    }
    initial_by_worker[collector_ids[1]] = [initial_replacement]
    if smoke_seed_each_worker:
        # A ten-target SQLite smoke can finish before a late thread is
        # scheduled. Reserve one real claim for each remaining worker; the
        # PostgreSQL representative run keeps natural scheduling/distribution.
        for index, worker_id in enumerate(collector_ids):
            if index == 1:
                continue
            with session_factory() as db:
                _bind_scale_namespace(db)
                worker = db.get(CollectorWorker, worker_id)
                if worker is None:
                    raise RuntimeError("Collector smoke worker disappeared")
                assignments = claim_deployments(
                    db,
                    worker,
                    CollectorLeaseClaim(
                        max_assignments=1,
                        lease_seconds=config.lease_seconds,
                    ),
                )
                if len(assignments) != 1:
                    raise RuntimeError("Collector smoke cannot seed each worker")
                initial_by_worker[worker_id] = assignments

    # SQLite ignores FOR UPDATE/SKIP LOCKED. Its non-representative smoke
    # must serialize claim plus processing, not overwrite another lease.
    # Native PostgreSQL retains actual concurrent scheduling and row locks.
    transaction_lock = threading.Lock() if smoke_seed_each_worker else nullcontext()

    def worker_loop(worker_id: str, initial: list[Any]) -> None:
        pending = list(initial)
        while not stop.is_set() and time.monotonic() < deadline:
            with transaction_lock, session_factory() as db:
                _bind_scale_namespace(db)
                worker = db.get(CollectorWorker, worker_id)
                if worker is None:
                    errors.put(f"Collector worker {worker_id} disappeared")
                    stop.set()
                    return
                assignments = pending
                pending = []
                if not assignments:
                    assignments = claim_deployments(
                        db,
                        worker,
                        CollectorLeaseClaim(
                            max_assignments=config.batch_size,
                            lease_seconds=config.lease_seconds,
                        ),
                    )
                if not assignments:
                    if _successful_run_count(db, prefix=config.run_prefix) >= config.targets:
                        return
                    time.sleep(0.01)
                    continue
                try:
                    for assignment in assignments:
                        target = targets[assignment.deployment_id]
                        admit_run_execution(
                            db,
                            assignment.run_id,
                            CollectorRunAdmit(
                                lease_token=assignment.lease_token,
                                assignment_sha256=assignment.assignment_sha256,
                            ),
                        )
                        result = ingest_envelopes(
                            db,
                            assignment.run_id,
                            CollectionEnvelopeBatch(
                                lease_token=assignment.lease_token,
                                envelopes=[
                                    _collector_envelope(
                                        prefix=config.run_prefix,
                                        target=target,
                                    )
                                ],
                            ),
                        )
                        if result.accepted != 1 or result.duplicates != 0:
                            raise RuntimeError(
                                f"Unexpected envelope result {result.model_dump()}"
                            )
                        complete_run(
                            db,
                            assignment.run_id,
                            CollectorRunComplete(
                                lease_token=assignment.lease_token,
                                status=CollectorRunStatus.SUCCEEDED,
                                stats={"synthetic": True},
                            ),
                        )
                        with counts_lock:
                            counts[worker.name] += 1
                except Exception as exc:
                    db.rollback()
                    errors.put(_error_fingerprint(exc))
                    stop.set()
                    return
        if time.monotonic() >= deadline:
            errors.put("Collector phase exceeded its timeout")
            stop.set()

    threads = [
        threading.Thread(
            target=worker_loop,
            args=(
                worker_id,
                initial_by_worker[worker_id],
            ),
            name=f"collector-scale-{index + 1}",
        )
        for index, worker_id in enumerate(collector_ids)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return dict(counts), list(errors.queue)


def _prepare_projection_reassignment(
    session_factory: sessionmaker[Session],
    config: ScaleConfig,
    projection_ids: list[str],
) -> ProjectionAssignment:
    with session_factory() as db:
        _bind_scale_namespace(db)
        first = db.get(KnowledgeProjectionWorker, projection_ids[0])
        second = db.get(KnowledgeProjectionWorker, projection_ids[1])
        if first is None or second is None:
            raise RuntimeError("Projection scale workers disappeared")
        stale = claim_projections(db, first, limit=1, lease_seconds=15)
        if len(stale) != 1:
            raise RuntimeError("Unable to create the projection failure assignment")
        projection = db.get(KnowledgeProjection, stale[0].projection_id)
        if projection is None:
            raise RuntimeError("Projection failure row disappeared")
        projection.lease_expires_at = utcnow() - timedelta(seconds=1)
        projection.next_attempt_at = utcnow() - timedelta(seconds=600)
        db.commit()
        replacement = claim_projections(
            db,
            second,
            limit=1,
            lease_seconds=config.lease_seconds,
        )
        if (
            len(replacement) != 1
            or replacement[0].projection_id != stale[0].projection_id
        ):
            raise RuntimeError("Expired projection lease was not reassigned")
        try:
            process_projection_assignment(db, first, stale[0])
        except (ValueError, ProjectionLeaseLost):
            pass
        else:
            raise RuntimeError("Stale projection lease was able to commit")
        return replacement[0]


def _run_projections(
    session_factory: sessionmaker[Session],
    config: ScaleConfig,
    *,
    projection_ids: list[str],
    initial_replacement: ProjectionAssignment,
    smoke_seed_each_worker: bool = False,
) -> tuple[dict[str, int], list[str]]:
    stop = threading.Event()
    errors: queue.Queue[str] = queue.Queue()
    counts: Counter[str] = Counter()
    counts_lock = threading.Lock()
    deadline = time.monotonic() + config.timeout_seconds
    initial_by_worker: dict[str, list[ProjectionAssignment]] = {
        worker_id: [] for worker_id in projection_ids
    }
    initial_by_worker[projection_ids[1]] = [initial_replacement]
    if smoke_seed_each_worker:
        for index, worker_id in enumerate(projection_ids):
            if index == 1:
                continue
            with session_factory() as db:
                _bind_scale_namespace(db)
                worker = db.get(KnowledgeProjectionWorker, worker_id)
                if worker is None:
                    raise RuntimeError("Projection smoke worker disappeared")
                assignments = claim_projections(
                    db,
                    worker,
                    limit=1,
                    lease_seconds=config.lease_seconds,
                )
                if len(assignments) != 1:
                    raise RuntimeError("Projection smoke cannot seed each worker")
                initial_by_worker[worker_id] = assignments

    transaction_lock = threading.Lock() if smoke_seed_each_worker else nullcontext()

    def worker_loop(worker_id: str, initial: list[ProjectionAssignment]) -> None:
        pending = list(initial)
        while not stop.is_set() and time.monotonic() < deadline:
            with transaction_lock, session_factory() as db:
                _bind_scale_namespace(db)
                worker = db.get(KnowledgeProjectionWorker, worker_id)
                if worker is None:
                    errors.put(f"Projection worker {worker_id} disappeared")
                    stop.set()
                    return
                assignments = pending
                pending = []
                if not assignments:
                    assignments = claim_projections(
                        db,
                        worker,
                        limit=config.projection_batch_size,
                        lease_seconds=config.lease_seconds,
                    )
                if not assignments:
                    if _terminal_projection_count(
                        db,
                        prefix=config.run_prefix,
                    ) >= config.targets:
                        return
                    time.sleep(0.01)
                    continue
                try:
                    for assignment in assignments:
                        result = process_projection_assignment(
                            db,
                            worker,
                            assignment,
                        )
                        if result.status != KnowledgeProjectionStatus.SUCCEEDED:
                            raise RuntimeError(
                                f"Projection {result.id} ended as {result.status.value}"
                            )
                        with counts_lock:
                            counts[worker.name] += 1
                except ProjectionLeaseLost:
                    continue
                except Exception as exc:
                    db.rollback()
                    errors.put(_error_fingerprint(exc))
                    stop.set()
                    return
        if time.monotonic() >= deadline:
            errors.put("Projection phase exceeded its timeout")
            stop.set()

    threads = [
        threading.Thread(
            target=worker_loop,
            args=(
                worker_id,
                initial_by_worker[worker_id],
            ),
            name=f"projection-scale-{index + 1}",
        )
        for index, worker_id in enumerate(projection_ids)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return dict(counts), list(errors.queue)


def _collect_report(
    session_factory: sessionmaker[Session],
    config: ScaleConfig,
    *,
    engine: Engine,
    schema_head: str,
    started_at: datetime,
    wall_seconds: float,
    cpu_seconds: float,
    start_db_size: int | None,
    collector_distribution: dict[str, int],
    projection_distribution: dict[str, int],
    errors: list[str],
) -> dict[str, Any]:
    with session_factory() as db:
        _bind_scale_namespace(db)
        runs = db.execute(
            select(
                CollectorRun.status,
                CollectorRun.started_at,
                CollectorRun.finished_at,
                CollectorDeployment.created_at,
            )
            .join(CollectorRun.deployment)
            .where(CollectorDeployment.name.like(f"{config.run_prefix}-deployment-%"))
        ).all()
        projections = db.scalars(
            select(KnowledgeProjection)
            .join(KnowledgeProjection.envelope)
            .join(CollectionEnvelope.run)
            .join(CollectorRun.deployment)
            .where(
                CollectorDeployment.name.like(f"{config.run_prefix}-deployment-%")
            )
        ).all()
        endpoint_count = (
            db.scalar(
                select(func.count(Endpoint.id)).where(
                    Endpoint.hostname.like("synthetic-endpoint-%")
                )
            )
            or 0
        )

    succeeded_runs = [row for row in runs if row.status == CollectorRunStatus.SUCCEEDED]
    cancelled_runs = [row for row in runs if row.status == CollectorRunStatus.CANCELLED]
    collection_queue_lag = [
        max(0.0, (_as_utc(row.started_at) - _as_utc(row.created_at)).total_seconds())
        for row in succeeded_runs
    ]
    collection_duration = [
        max(0.0, (_as_utc(row.finished_at) - _as_utc(row.started_at)).total_seconds())
        for row in succeeded_runs
        if row.finished_at is not None
    ]
    projection_lag = [
        max(
            0.0,
            (_as_utc(item.completed_at) - _as_utc(item.created_at)).total_seconds(),
        )
        for item in projections
        if item.completed_at is not None
    ]
    projection_status = Counter(item.status.value for item in projections)
    projection_retry_count = sum(max(0, item.attempt_count - 1) for item in projections)
    series = {
        (target_index, metric_index)
        for target_index in range(config.targets)
        for metric_index in range(config.series_per_target)
    }
    max_rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    end_db_size = _database_size(engine)
    throughput = len(succeeded_runs) / wall_seconds if wall_seconds > 0 else 0.0
    collector_shares = {
        name: count / config.targets
        for name, count in collector_distribution.items()
    }
    projection_shares = {
        name: count / config.targets
        for name, count in projection_distribution.items()
    }
    gates = {
        "collector_success_exact": len(succeeded_runs) == config.targets,
        "one_endpoint_per_target": endpoint_count == config.targets,
        "projection_success_exact": (
            projection_status[KnowledgeProjectionStatus.SUCCEEDED.value]
            == config.targets
        ),
        "projection_queue_drained": sum(
            projection_status[name]
            for name in ("pending", "processing", "retry")
        )
        == 0,
        "no_projection_dead_letters": (
            projection_status[KnowledgeProjectionStatus.DEAD_LETTER.value] == 0
        ),
        "collector_reassignment_observed": len(cancelled_runs) >= 1,
        "projection_reassignment_observed": projection_retry_count >= 1,
        "all_collector_workers_used": (
            len(collector_shares) == config.collector_workers
            and all(
                share >= config.min_worker_share
                for share in collector_shares.values()
            )
        ),
        "all_projection_workers_used": (
            len(projection_shares) == config.projection_workers
            and all(
                share >= config.min_worker_share
                for share in projection_shares.values()
            )
        ),
        "projection_p95_within_limit": (
            (percentile(projection_lag, 0.95) or 0.0)
            <= config.max_projection_lag_seconds
        ),
        "no_worker_errors": not errors,
    }
    return {
        "format_version": "icheck.scale-report/v1",
        "run_prefix": config.run_prefix,
        "started_at": started_at.isoformat(),
        "finished_at": utcnow().isoformat(),
        "representative": engine.dialect.name == "postgresql",
        "database_backend": engine.dialect.name,
        "schema_head": schema_head,
        "configuration": {
            "targets": config.targets,
            "collector_workers": config.collector_workers,
            "projection_workers": config.projection_workers,
            "collector_batch_size": config.batch_size,
            "projection_batch_size": config.projection_batch_size,
            "lease_seconds": config.lease_seconds,
            "configured_schedule_seconds": config.schedule_seconds,
            "timeout_seconds": config.timeout_seconds,
            "series_per_target": config.series_per_target,
            "max_projection_lag_seconds": config.max_projection_lag_seconds,
            "min_worker_share": config.min_worker_share,
            "sqlite_smoke_seeded_workers": engine.dialect.name == "sqlite",
            "sqlite_smoke_serialized_iterations": engine.dialect.name == "sqlite",
        },
        "results": {
            "wall_seconds": round(wall_seconds, 6),
            "process_cpu_seconds": round(cpu_seconds, 6),
            "process_cpu_percent_of_one_core": round(
                (cpu_seconds / wall_seconds * 100.0) if wall_seconds > 0 else 0.0,
                3,
            ),
            "max_rss_mb": round(max_rss_mb, 3),
            "database_size_before_bytes": start_db_size,
            "database_size_after_bytes": end_db_size,
            "database_growth_bytes": (
                end_db_size - start_db_size
                if end_db_size is not None and start_db_size is not None
                else None
            ),
            "successful_target_cycles": len(succeeded_runs),
            "cancelled_reassigned_runs": len(cancelled_runs),
            "target_cycles_per_second": round(throughput, 3),
            "achieved_full_cycle_seconds": round(
                config.targets / throughput if throughput > 0 else 0.0,
                6,
            ),
            "collector_distribution": collector_distribution,
            "collector_worker_shares": collector_shares,
            "projection_distribution": projection_distribution,
            "projection_worker_shares": projection_shares,
            "collection_queue_lag_seconds": latency_summary(collection_queue_lag),
            "collection_run_duration_seconds": latency_summary(collection_duration),
            "projection_lag_seconds": latency_summary(projection_lag),
            "projection_status": dict(projection_status),
            "projection_retry_count": projection_retry_count,
            "endpoint_count": endpoint_count,
            "simulated_time_series_cardinality": len(series),
            "cardinality_method": (
                "unique (target_index, metric_index) label sets; "
                "no time-series samples are written to PostgreSQL"
            ),
            "timeout_count": sum("timeout" in item.lower() for item in errors),
            "worker_errors": errors,
        },
        "gates": gates,
        "passed": all(gates.values()),
    }


def run_scale_test(config: ScaleConfig) -> dict[str, Any]:
    if config.targets < 10 or config.targets > 100_000:
        raise ValueError("targets must be between 10 and 100000")
    if config.collector_workers < 2 or config.projection_workers < 2:
        raise ValueError("at least two Collector and two Projection Workers are required")
    if not 1 <= config.batch_size <= 20:
        raise ValueError("collector batch size must be between 1 and 20")
    if not 1 <= config.projection_batch_size <= 100:
        raise ValueError("projection batch size must be between 1 and 100")
    if not 15 <= config.lease_seconds <= 3600:
        raise ValueError("lease seconds must be between 15 and 3600")
    if config.timeout_seconds < 30:
        raise ValueError("timeout seconds must be at least 30")
    if not 0 < config.min_worker_share <= 0.5:
        raise ValueError("minimum worker share must be greater than 0 and at most 0.5")
    if not config.run_prefix or len(config.run_prefix) > 64:
        raise ValueError("run prefix must contain 1 to 64 characters")

    schema_head = expected_schema_head()
    engine = _engine(config.database_url)
    session_factory = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )
    _verify_dedicated_database(
        session_factory,
        engine=engine,
        allow_sqlite_smoke=config.allow_sqlite_smoke,
        schema_head=schema_head,
    )
    start_db_size = _database_size(engine)
    started_at = utcnow()
    started_wall = time.monotonic()
    started_cpu = time.process_time()
    targets, collector_ids, projection_ids = _setup_scale_data(
        session_factory,
        config,
    )
    initial_collector = _prepare_collector_reassignment(
        session_factory,
        config,
        collector_ids,
    )
    collector_distribution, collector_errors = _run_collectors(
        session_factory,
        config,
        targets=targets,
        collector_ids=collector_ids,
        initial_replacement=initial_collector,
        smoke_seed_each_worker=engine.dialect.name == "sqlite",
    )
    if collector_errors:
        raise RuntimeError(f"Collector scale phase failed: {collector_errors}")
    initial_projection = _prepare_projection_reassignment(
        session_factory,
        config,
        projection_ids,
    )
    projection_distribution, projection_errors = _run_projections(
        session_factory,
        config,
        projection_ids=projection_ids,
        initial_replacement=initial_projection,
        smoke_seed_each_worker=engine.dialect.name == "sqlite",
    )
    wall_seconds = time.monotonic() - started_wall
    cpu_seconds = time.process_time() - started_cpu
    return _collect_report(
        session_factory,
        config,
        engine=engine,
        schema_head=schema_head,
        started_at=started_at,
        wall_seconds=wall_seconds,
        cpu_seconds=cpu_seconds,
        start_db_size=start_db_size,
        collector_distribution=collector_distribution,
        projection_distribution=projection_distribution,
        errors=[*collector_errors, *projection_errors],
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run iCheck's real scheduler/projection path against a dedicated "
            "M1 scale-test database"
        )
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("ICHECK_SCALE_DATABASE_URL"),
        help="Dedicated migrated database; never defaults to ICHECK_DATABASE_URL",
    )
    parser.add_argument(
        "--acknowledge-dedicated-database",
        action="store_true",
        help="Required acknowledgement that the database is disposable and empty",
    )
    parser.add_argument(
        "--run-prefix",
        default=f"scale-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}",
    )
    parser.add_argument("--targets", type=int, default=1000)
    parser.add_argument("--collector-workers", type=int, default=2)
    parser.add_argument("--projection-workers", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--projection-batch-size", type=int, default=50)
    parser.add_argument("--lease-seconds", type=int, default=120)
    parser.add_argument("--schedule-seconds", type=int, default=3600)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--series-per-target", type=int, default=8)
    parser.add_argument("--max-projection-lag-seconds", type=float, default=60.0)
    parser.add_argument("--min-worker-share", type=float, default=0.05)
    parser.add_argument("--allow-sqlite-smoke", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    if not args.database_url:
        parser.error(
            "--database-url or ICHECK_SCALE_DATABASE_URL is required; "
            "the application database is never used implicitly"
        )
    if not args.acknowledge_dedicated_database:
        parser.error("--acknowledge-dedicated-database is required")
    try:
        report = run_scale_test(
            ScaleConfig(
                database_url=args.database_url,
                run_prefix=args.run_prefix,
                targets=args.targets,
                collector_workers=args.collector_workers,
                projection_workers=args.projection_workers,
                batch_size=args.batch_size,
                projection_batch_size=args.projection_batch_size,
                lease_seconds=args.lease_seconds,
                schedule_seconds=args.schedule_seconds,
                timeout_seconds=args.timeout_seconds,
                series_per_target=args.series_per_target,
                max_projection_lag_seconds=args.max_projection_lag_seconds,
                min_worker_share=args.min_worker_share,
                allow_sqlite_smoke=args.allow_sqlite_smoke,
            )
        )
    except Exception as exc:
        parser.exit(2, f"scale test failed: {type(exc).__name__}: {exc}\n")
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
