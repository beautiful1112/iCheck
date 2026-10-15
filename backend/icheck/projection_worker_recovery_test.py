"""Process-kill recovery probe for the real PostgreSQL Projection Worker.

Only a fresh, migrated icheck_projection_recovery_* database is accepted. This
is one controlled envelope, not a representative collector capacity test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from .collector_schemas import CollectionEnvelopeBatch, CollectorLeaseClaim, CollectorRunAdmit, CollectorRunComplete
from .database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, set_session_namespace
from .models import (
    CollectorRunStatus,
    CollectorWorker,
    Endpoint,
    IPAddressObservation,
    KnowledgeProjection,
    KnowledgeProjectionStatus,
    KnowledgeProjectionWorker,
    utcnow,
)
from .scale_test import ScaleConfig, _collector_envelope, _setup_scale_data, expected_schema_head
from .services.collectors import admit_run_execution, claim_deployments, complete_run, ingest_envelopes


DATABASE_URL_ENV = "ICHECK_PROJECTION_RECOVERY_DATABASE_URL"
REPORT_FORMAT = "icheck.projection-worker-recovery-report/v1"


def _dsn(database_url: str) -> str:
    if database_url.startswith("postgresql+psycopg://"):
        return "postgresql://" + database_url.removeprefix("postgresql+psycopg://")
    if database_url.startswith("postgresql://"):
        return database_url
    raise ValueError("Projection recovery requires PostgreSQL")


def _verify_dedicated_database(database_url: str) -> str:
    with psycopg.connect(_dsn(database_url)) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT current_database(), role.rolsuper, role.rolbypassrls,
                          database.datdba = role.oid
                   FROM pg_database AS database
                   JOIN pg_roles AS role ON role.rolname = current_user
                   WHERE database.datname = current_database()"""
            )
            name, superuser, bypass_rls, database_owner = cursor.fetchone()
            if not name.startswith("icheck_projection_recovery_"):
                raise ValueError(
                    "Projection recovery requires an icheck_projection_recovery_ database"
                )
            if superuser or bypass_rls or database_owner:
                raise ValueError("Projection recovery requires a non-owner, non-RLS-bypass role")
            cursor.execute("SELECT version_num FROM alembic_version")
            if cursor.fetchone()[0] != expected_schema_head():
                raise ValueError("Projection recovery requires this checkout's Alembic head")
            cursor.execute("SELECT count(*) FROM tenants")
            if cursor.fetchone()[0] != 1:
                raise ValueError("Projection recovery requires only the migration-seeded tenant")
            cursor.execute("SELECT count(*) FROM regions")
            if cursor.fetchone()[0] != 1:
                raise ValueError("Projection recovery requires only the migration-seeded region")
            cursor.execute(
                "SELECT set_config('icheck.tenant_id', %s, true), "
                "set_config('icheck.region_id', %s, true)",
                (DEFAULT_TENANT_ID, DEFAULT_REGION_ID),
            )
            for table in (
                "artifacts", "devices", "collector_deployments", "collector_runs",
                "collection_envelopes", "knowledge_projections", "endpoints",
            ):
                cursor.execute(f"SELECT count(*) FROM {table}")
                if cursor.fetchone()[0]:
                    raise ValueError("Projection recovery refuses a non-empty database")
    return name


def _seed(session_factory: sessionmaker[Session], database_url: str) -> tuple[str, str, str]:
    config = ScaleConfig(
        database_url=database_url,
        run_prefix="projection-recovery",
        targets=1,
        collector_workers=1,
        projection_workers=0,
        lease_seconds=15,
    )
    targets, collector_ids, _ = _setup_scale_data(session_factory, config)
    deployment_id, target = next(iter(targets.items()))
    with session_factory() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        worker = db.get(CollectorWorker, collector_ids[0])
        assert worker is not None
        assignments = claim_deployments(
            db, worker, CollectorLeaseClaim(max_assignments=1, lease_seconds=15)
        )
        if len(assignments) != 1 or assignments[0].deployment_id != deployment_id:
            raise RuntimeError("Expected exactly one collector assignment")
        assignment = assignments[0]
        admit_run_execution(db, assignment.run_id, CollectorRunAdmit(
            lease_token=assignment.lease_token, assignment_sha256=assignment.assignment_sha256,
        ))
        result = ingest_envelopes(
            db,
            assignment.run_id,
            CollectionEnvelopeBatch(
                lease_token=assignment.lease_token,
                envelopes=[_collector_envelope(prefix=config.run_prefix, target=target)],
            ),
        )
        if (result.accepted, result.duplicates) != (1, 0):
            raise RuntimeError("Expected one new network envelope")
        complete_run(
            db,
            assignment.run_id,
            CollectorRunComplete(
                lease_token=assignment.lease_token,
                status=CollectorRunStatus.SUCCEEDED,
                stats={"controlled_recovery_fixture": True},
            ),
        )
        projection = db.scalar(select(KnowledgeProjection))
        if projection is None:
            raise RuntimeError("Collector ingest did not enqueue a projection")
        old = utcnow() - timedelta(days=1)
        db.add(Endpoint(mac_address=target["mac_address"], first_seen=old, last_seen=old))
        db.commit()
        return projection.id, target["mac_address"], target["ip_address"]


def _worker_environment(database_url: str, application_name: str) -> dict[str, str]:
    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR")
        if key in os.environ
    }
    env.update({
        "ICHECK_DATABASE_URL": database_url,
        "ICHECK_AUTO_CREATE_SCHEMA": "false",
        "ICHECK_ENVIRONMENT": "development",
        "ICHECK_TENANT_ID": DEFAULT_TENANT_ID,
        "ICHECK_REGION_ID": DEFAULT_REGION_ID,
        "PGAPPNAME": application_name,
    })
    return env


def _worker_command(name: str) -> list[str]:
    return [
        sys.executable, "-m", "icheck.projection_worker",
        "--name", name, "--batch-size", "1", "--lease-seconds", "15",
        "--poll-seconds", "0.2", "--once",
    ]


def _wait_for_first_blocked(
    session_factory: sessionmaker[Session], projection_id: str, first: subprocess.Popen[str]
) -> tuple[str, datetime]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if first.poll() is not None:
            raise RuntimeError("First Projection Worker exited before it blocked")
        with session_factory() as db:
            set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
            projection = db.get(KnowledgeProjection, projection_id)
            # The waiting backend is identified by libpq's PGAPPNAME, not by PID.
            blocked = db.execute(text(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE application_name = 'icheck-projection-recovery-first' "
                "AND wait_event_type = 'Lock'"
            )).scalar_one()
            if (
                projection is not None
                and projection.status == KnowledgeProjectionStatus.PROCESSING
                and projection.lease_worker_id is not None
                and projection.lease_expires_at is not None
                and blocked == 1
            ):
                return projection.lease_worker_id, projection.lease_expires_at
        time.sleep(0.1)
    raise TimeoutError("First Projection Worker never blocked on the endpoint row")


def _wait_for_expiry(session_factory: sessionmaker[Session], projection_id: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with session_factory() as db:
            set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
            projection = db.get(KnowledgeProjection, projection_id)
            if projection is None or projection.lease_expires_at is None:
                raise RuntimeError("Projection lost its lease record")
            expiry = projection.lease_expires_at
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            if expiry < datetime.now(UTC):
                return
        time.sleep(0.2)
    raise TimeoutError("Projection lease did not expire after process loss")


def _result(
    session_factory: sessionmaker[Session], projection_id: str,
    mac_address: str, ip_address: str, first_worker_id: str,
) -> dict[str, Any]:
    with session_factory() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        projection = db.get(KnowledgeProjection, projection_id)
        endpoints = db.scalars(select(Endpoint).where(Endpoint.mac_address == mac_address)).all()
        addresses = db.scalars(select(IPAddressObservation).where(
            IPAddressObservation.ip_address == ip_address
        )).all()
        workers = db.scalars(select(KnowledgeProjectionWorker)).all()
        gates = {
            "projection_succeeded": (
                projection is not None
                and projection.status == KnowledgeProjectionStatus.SUCCEEDED
            ),
            "natural_lease_reclaim": projection is not None and projection.attempt_count == 2,
            "distinct_worker_processes": (
                len(workers) == 2
                and any(worker.id == first_worker_id for worker in workers)
            ),
            "lease_cleared": (
                projection is not None
                and projection.lease_worker_id is None
                and projection.lease_token_hash is None
            ),
            "single_endpoint": len(endpoints) == 1,
            "single_ip_observation": (
                len(addresses) == 1
                and len(endpoints) == 1
                and addresses[0].endpoint_id == endpoints[0].id
            ),
            "no_dead_letter": projection is not None and projection.error_type is None,
        }
        return {
            "projection_status": projection.status.value if projection else None,
            "attempts": projection.attempt_count if projection else None,
            "worker_count": len(workers),
            "endpoint_count": len(endpoints),
            "ip_observation_count": len(addresses),
            "result_summary": projection.result_summary if projection else None,
            "gates": gates,
        }


def run_projection_recovery_test(database_url: str) -> dict[str, Any]:
    database_name = _verify_dedicated_database(database_url)
    engine = create_engine(database_url, pool_pre_ping=True)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    first: subprocess.Popen[str] | None = None
    blocker: psycopg.Connection[Any] | None = None
    started = time.monotonic()
    try:
        projection_id, mac_address, ip_address = _seed(session_factory, database_url)
        blocker = psycopg.connect(_dsn(database_url))
        with blocker.cursor() as cursor:
            cursor.execute(
                "SELECT set_config('icheck.tenant_id', %s, true), "
                "set_config('icheck.region_id', %s, true)",
                (DEFAULT_TENANT_ID, DEFAULT_REGION_ID),
            )
            cursor.execute(
                "SELECT id FROM endpoints WHERE mac_address = %s FOR UPDATE",
                (mac_address,),
            )
            if cursor.fetchone() is None:
                raise RuntimeError("Fixture endpoint is missing")
        first = subprocess.Popen(
            _worker_command("projection-recovery-before-kill"),
            cwd="/tmp",
            env=_worker_environment(database_url, "icheck-projection-recovery-first"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        first_worker_id, _ = _wait_for_first_blocked(session_factory, projection_id, first)
        first.kill()
        first.wait(timeout=10)
        if first.returncode != -signal.SIGKILL:
            raise RuntimeError("First Projection Worker was not killed by SIGKILL")
        blocker.rollback()
        blocker.close()
        blocker = None
        _wait_for_expiry(session_factory, projection_id)
        second = subprocess.run(
            _worker_command("projection-recovery-after-kill"),
            cwd="/tmp",
            env=_worker_environment(database_url, "icheck-projection-recovery-second"),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        if second.returncode:
            digest = hashlib.sha256(second.stderr.encode("utf-8")).hexdigest()
            raise RuntimeError(f"Replacement Projection Worker failed; stderr SHA-256 {digest}")
        result = _result(session_factory, projection_id, mac_address, ip_address, first_worker_id)
        gates = {
            "first_worker_sigkill": first.returncode == -signal.SIGKILL,
            "replacement_worker_exited_cleanly": second.returncode == 0,
            **result.pop("gates"),
        }
        return {
            "format_version": REPORT_FORMAT,
            "database_backend": "postgresql",
            "database_name": database_name,
            "runtime_role_non_owner_non_bypass": True,
            "fixture": "one_controlled_network_observation",
            "lease_expiry": "natural_15_second_lease",
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "result": result,
            "gates": gates,
            "passed": all(gates.values()),
        }
    finally:
        if first is not None and first.poll() is None:
            first.kill()
            first.wait(timeout=10)
        if blocker is not None:
            blocker.rollback()
            blocker.close()
        engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-dedicated-database", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    database_url = os.environ.get(DATABASE_URL_ENV)
    if not database_url:
        parser.error(f"{DATABASE_URL_ENV} is required; no application fallback exists")
    if not args.acknowledge_dedicated_database:
        parser.error("--acknowledge-dedicated-database is required")
    try:
        report = run_projection_recovery_test(database_url)
    except Exception as exc:
        detail = (
            str(exc)
            if isinstance(exc, ValueError) and str(exc).startswith("Projection recovery")
            else ""
        )
        parser.exit(
            2,
            f"projection recovery test failed: {type(exc).__name__}"
            f"{': ' + detail if detail else ''}\n",
        )
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
