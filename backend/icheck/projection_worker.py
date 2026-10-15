from __future__ import annotations

import argparse
import logging
import os
import time
from typing import Any

from .config import get_settings
from .database import SessionLocal
from .models import KnowledgeProjectionWorker
from .services.knowledge_projection import (
    ProjectionLeaseLost,
    claim_projections,
    process_projection_assignment,
    register_projection_worker,
)
from .worker_namespace import (
    add_worker_namespace_arguments,
    bind_worker_namespace,
    parse_worker_namespace,
)


LOGGER = logging.getLogger("icheck.projection_worker")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Project normalized collector envelopes into iCheck knowledge"
    )
    add_worker_namespace_arguments(parser)
    parser.add_argument(
        "--name",
        default=os.environ.get("ICHECK_PROJECTION_WORKER_NAME"),
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=int(os.environ.get("ICHECK_PROJECTION_WORKER_BATCH_SIZE", "20")),
    )
    parser.add_argument(
        "--lease-seconds",
        type=int,
        default=int(os.environ.get("ICHECK_PROJECTION_WORKER_LEASE_SECONDS", "120")),
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=float(os.environ.get("ICHECK_PROJECTION_WORKER_POLL_SECONDS", "1")),
    )
    parser.add_argument("--once", action="store_true")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: Any) -> None:
    if not args.name or not args.name.strip():
        parser.error("--name or ICHECK_PROJECTION_WORKER_NAME is required")
    if not 1 <= args.batch_size <= 100:
        parser.error("--batch-size must be between 1 and 100")
    if not 15 <= args.lease_seconds <= 3600:
        parser.error("--lease-seconds must be between 15 and 3600")
    if args.poll_seconds <= 0 or args.poll_seconds > 60:
        parser.error("--poll-seconds must be greater than 0 and at most 60")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("ICHECK_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = _parser()
    args = parser.parse_args()
    _validate_args(parser, args)
    namespace = parse_worker_namespace(parser, args)
    settings = get_settings()
    if not settings.database_url.startswith(
        ("postgresql://", "postgresql+psycopg://")
    ):
        parser.error(
            "the projection worker requires PostgreSQL for safe multi-worker leases"
        )

    with SessionLocal() as db:
        bind_worker_namespace(db, namespace)
        worker = register_projection_worker(db, name=args.name)
        worker_id = worker.id

    while True:
        with SessionLocal() as db:
            bind_worker_namespace(db, namespace)
            worker = db.get(KnowledgeProjectionWorker, worker_id)
            if worker is None:
                raise RuntimeError("Projection worker registration disappeared")
            assignments = claim_projections(
                db,
                worker,
                limit=args.batch_size,
                lease_seconds=args.lease_seconds,
            )
            for assignment in assignments:
                try:
                    result = process_projection_assignment(db, worker, assignment)
                except ProjectionLeaseLost:
                    LOGGER.warning(
                        "projection=%s lease was reassigned before commit",
                        assignment.projection_id,
                    )
                    continue
                LOGGER.info(
                    "projection=%s envelope=%s status=%s attempt=%s",
                    result.id,
                    result.envelope_id,
                    result.status.value,
                    result.attempt_count,
                )
        if args.once:
            return 0
        if not assignments:
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
