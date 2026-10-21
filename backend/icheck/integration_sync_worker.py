"""Native, namespace-bound controller for explicitly enabled inventory schedules."""
import argparse
import logging
import math
import os
import time

from .config import get_settings
from .database import SessionLocal
from .services import integration_scheduling as scheduling
from .worker_namespace import add_worker_namespace_arguments, bind_worker_namespace, parse_worker_namespace

LOGGER = logging.getLogger("icheck.integration_sync_worker")


def dispatch_once(namespace):
    with SessionLocal() as db:
        bind_worker_namespace(db, namespace)
        claim = scheduling.claim_due(db)
    if claim is None:
        return False
    try:
        with SessionLocal() as db:
            bind_worker_namespace(db, namespace)
            return scheduling.execute(db, claim)
    except Exception:
        # Do not log exception text: DB/transport exceptions may contain secrets.
        LOGGER.error("Integration batch failed; recording a bounded retry state")
        with SessionLocal() as db:
            bind_worker_namespace(db, namespace)
            scheduling.record_worker_failure(db, claim)
        return False


def main():
    parser = argparse.ArgumentParser(description="Run approved monitoring integration schedules")
    add_worker_namespace_arguments(parser)
    parser.add_argument("--poll-seconds", type=float, default=2)
    parser.add_argument("--once", action="store_true", help="Process at most one manifest or 250-host batch")
    args = parser.parse_args()
    if not math.isfinite(args.poll_seconds) or not 0 < args.poll_seconds <= 60:
        parser.error("--poll-seconds must be finite, greater than zero and at most 60")
    namespace = parse_worker_namespace(parser, args)
    if not get_settings().database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        parser.error("Background integration synchronization requires PostgreSQL row locks")
    logging.basicConfig(level=os.environ.get("ICHECK_LOG_LEVEL", "INFO"))
    while True:
        processed = dispatch_once(namespace)
        if args.once:
            return 0
        if not processed:
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
