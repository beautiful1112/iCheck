"""Native namespace-bound reader for explicitly enabled external alert feeds."""
import argparse
import logging
import math
import time

from .config import get_settings
from .database import SessionLocal
from .services.integration_alerts import poll_once
from .worker_namespace import add_worker_namespace_arguments, bind_worker_namespace, parse_worker_namespace

LOGGER = logging.getLogger("icheck.integration_alert_worker")


def dispatch_once(namespace):
    with SessionLocal() as db:
        bind_worker_namespace(db, namespace)
        try:
            return poll_once(db)
        except Exception:
            db.rollback()
            LOGGER.error("External alert batch failed; no partial progress committed")
            return False


def main():
    parser = argparse.ArgumentParser(description="Read approved external alert feeds")
    add_worker_namespace_arguments(parser)
    parser.add_argument("--poll-seconds", type=float, default=2)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not math.isfinite(args.poll_seconds) or not 0 < args.poll_seconds <= 60:
        parser.error("--poll-seconds must be finite and between 0 and 60")
    if not get_settings().database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        parser.error("External alert synchronization requires PostgreSQL row locks")
    namespace = parse_worker_namespace(parser, args)
    logging.basicConfig(level=logging.INFO)
    while True:
        processed = dispatch_once(namespace)
        if args.once:
            return 0
        if not processed:
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
