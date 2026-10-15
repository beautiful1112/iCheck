"""Namespace-pinned controller for Collector Workers lost after lease claim."""

from __future__ import annotations

import argparse
import logging
import os
import time

from sqlalchemy.orm import Session

from .config import get_settings
from .database import SessionLocal
from .services.collector_lease_reconciliation import (
    MAX_LEASE_BATCH,
    reconcile_expired_leases,
    reconcile_orphan_runs,
)
from .worker_namespace import (
    WorkerNamespace,
    add_worker_namespace_arguments,
    bind_worker_namespace,
    parse_worker_namespace,
)


LOGGER = logging.getLogger("icheck.collector_lease_reconciler")


def reconcile_once(db: Session, *, limit: int = MAX_LEASE_BATCH) -> int:
    expired = reconcile_expired_leases(db, limit=limit)
    db.commit()
    orphaned = reconcile_orphan_runs(db, limit=limit)
    db.commit()
    return expired + orphaned


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("ICHECK_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = argparse.ArgumentParser(
        description="Finalize expired leases and orphaned Collector runs in one tenant/region"
    )
    add_worker_namespace_arguments(parser)
    parser.add_argument(
        "--poll-seconds", type=float,
        default=float(os.environ.get("ICHECK_COLLECTOR_LEASE_POLL_SECONDS", "15")),
    )
    parser.add_argument("--batch-size", type=int, default=MAX_LEASE_BATCH)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not 5 <= args.poll_seconds <= 300:
        parser.error("--poll-seconds must be between 5 and 300")
    if not 1 <= args.batch_size <= MAX_LEASE_BATCH:
        parser.error(f"--batch-size must be between 1 and {MAX_LEASE_BATCH}")
    namespace: WorkerNamespace = parse_worker_namespace(parser, args)
    if not get_settings().database_url.startswith(
        ("postgresql://", "postgresql+psycopg://")
    ):
        parser.error("the continuous lease reconciler requires PostgreSQL")

    while True:
        with SessionLocal() as db:
            bind_worker_namespace(db, namespace)
            count = reconcile_once(db, limit=args.batch_size)
        if count:
            LOGGER.info("finalized %s expired leases or orphaned Collector runs", count)
        if args.once:
            return 0
        if count < args.batch_size:
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
