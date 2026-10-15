from __future__ import annotations

import argparse
import logging
import os
import time
from typing import Any

from .config import get_settings
from .credentials import build_server_credential_providers
from .database import SessionLocal
from .models import EcosystemTransportWorker
from .services.ecosystem_transport import (
    EcosystemTransportLeaseLost,
    claim_transport_jobs,
    process_transport_assignment,
    reconcile_automatic_gossip_jobs,
    reconcile_automatic_witness_jobs,
    register_transport_worker,
)
from .worker_namespace import (
    add_worker_namespace_arguments,
    bind_worker_namespace,
    parse_worker_namespace,
)


LOGGER = logging.getLogger("icheck.ecosystem_transport_worker")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Deliver signed iCheck ecosystem envelopes over HTTPS"
    )
    add_worker_namespace_arguments(parser)
    parser.add_argument(
        "--name",
        default=os.environ.get("ICHECK_ECOSYSTEM_TRANSPORT_WORKER_NAME"),
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=int(
            os.environ.get(
                "ICHECK_ECOSYSTEM_TRANSPORT_WORKER_BATCH_SIZE",
                "20",
            )
        ),
    )
    parser.add_argument(
        "--lease-seconds",
        type=int,
        default=int(
            os.environ.get(
                "ICHECK_ECOSYSTEM_TRANSPORT_WORKER_LEASE_SECONDS",
                "120",
            )
        ),
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=float(
            os.environ.get(
                "ICHECK_ECOSYSTEM_TRANSPORT_WORKER_POLL_SECONDS",
                "1",
            )
        ),
    )
    parser.add_argument("--once", action="store_true")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: Any) -> None:
    if not args.name or not args.name.strip():
        parser.error(
            "--name or ICHECK_ECOSYSTEM_TRANSPORT_WORKER_NAME is required"
        )
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
            "the ecosystem transport worker requires PostgreSQL for "
            "safe multi-worker leases"
        )
    if not settings.ecosystem_transport_allowed_host_list:
        parser.error(
            "ICHECK_ECOSYSTEM_TRANSPORT_ALLOWED_HOSTS must not be empty"
        )
    credential_providers = build_server_credential_providers(
        settings=settings
    )

    with SessionLocal() as db:
        bind_worker_namespace(db, namespace)
        worker = register_transport_worker(db, name=args.name)
        worker_id = worker.id

    while True:
        with SessionLocal() as db:
            bind_worker_namespace(db, namespace)
            worker = db.get(EcosystemTransportWorker, worker_id)
            if worker is None:
                raise RuntimeError("Transport worker registration disappeared")
            created = reconcile_automatic_witness_jobs(db)
            if created:
                LOGGER.info("queued automatic witness jobs=%s", created)
            gossip_created = reconcile_automatic_gossip_jobs(db)
            if gossip_created:
                LOGGER.info(
                    "queued automatic gossip jobs=%s",
                    gossip_created,
                )
            processed = 0
            for _ in range(args.batch_size):
                # Acquire a lease just before its I/O, not for a batch waiting
                # behind up to 100 bounded HTTPS requests. Each attempt receives
                # its full lease budget regardless of prior delivery latency.
                assignments = claim_transport_jobs(
                    db, worker, limit=1, lease_seconds=args.lease_seconds,
                )
                if not assignments:
                    break
                assignment = assignments[0]
                processed += 1
                try:
                    result = process_transport_assignment(
                        db,
                        worker,
                        assignment,
                        credential_providers=credential_providers,
                    )
                except EcosystemTransportLeaseLost:
                    LOGGER.warning(
                        "transport_job=%s lease was reassigned before commit",
                        assignment.job_id,
                    )
                    continue
                LOGGER.info(
                    "transport_job=%s status=%s attempt=%s",
                    result.id,
                    result.status.value,
                    result.attempt_count,
                )
        if args.once:
            return 0
        if not processed:
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
