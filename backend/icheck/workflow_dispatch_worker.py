from __future__ import annotations

import argparse
import logging
import os
import time
from typing import Any

from .config import get_settings
from .database import SessionLocal
from .services.workflow_runtime import (
    dispatch_situation_integration_events,
    dispatch_workflow_schedule_events,
    dispatch_workflow_trigger_events,
    enqueue_due_workflow_schedules,
)
from .services.alert_investigation import dispatch_alert_investigations
from .worker_namespace import (
    add_worker_namespace_arguments,
    bind_worker_namespace,
    parse_worker_namespace,
)


LOGGER = logging.getLogger("icheck.workflow_dispatch_worker")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Dispatch durable workflow schedules, alert triggers, and "
            "Situation integration outbox events"
        )
    )
    add_worker_namespace_arguments(parser)
    parser.add_argument(
        "--batch-size",
        type=int,
        default=int(
            os.environ.get("ICHECK_WORKFLOW_DISPATCH_BATCH_SIZE", "20")
        ),
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=float(
            os.environ.get("ICHECK_WORKFLOW_DISPATCH_POLL_SECONDS", "2")
        ),
    )
    parser.add_argument("--once", action="store_true")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: Any) -> None:
    if not 1 <= args.batch_size <= 100:
        parser.error("--batch-size must be between 1 and 100")
    if args.poll_seconds <= 0 or args.poll_seconds > 60:
        parser.error("--poll-seconds must be greater than 0 and at most 60")


def dispatch_once(*, batch_size: int, namespace: Any) -> int:
    with SessionLocal() as db:
        bind_worker_namespace(db, namespace)
        enqueued = enqueue_due_workflow_schedules(
            db,
            limit=max(100, batch_size),
        )
        scheduled = dispatch_workflow_schedule_events(
            db,
            limit=batch_size,
        )
        triggered = dispatch_workflow_trigger_events(
            db,
            limit=batch_size,
        )
        integrations = dispatch_situation_integration_events(
            db,
            limit=batch_size,
        )
        automatic = dispatch_alert_investigations(db, limit=batch_size)
    dispatched = scheduled + triggered + integrations + automatic
    if enqueued or dispatched:
        LOGGER.info(
            "workflow schedules_enqueued=%s dispatched=%s",
            enqueued,
            dispatched,
        )
    return enqueued + dispatched


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
            "the workflow dispatch worker requires PostgreSQL for durable "
            "outbox concurrency"
        )

    while True:
        processed = dispatch_once(
            batch_size=args.batch_size,
            namespace=namespace,
        )
        if args.once:
            return 0
        if not processed:
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
