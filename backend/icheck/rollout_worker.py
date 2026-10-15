from __future__ import annotations

import argparse
import logging
import os
import time
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .config import get_settings
from .database import SessionLocal, require_locking_transaction, session_namespace
from .models import CollectorFleetRollout
from .services.fleet_rollout_automation import reconcile_automatic_rollout
from .worker_namespace import (
    add_worker_namespace_arguments,
    bind_worker_namespace,
    parse_worker_namespace,
)


LOGGER = logging.getLogger("icheck.rollout_worker")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Advance health-gated iCheck collector rollout rings"
    )
    add_worker_namespace_arguments(parser)
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=float(os.environ.get("ICHECK_ROLLOUT_WORKER_POLL_SECONDS", "15")),
    )
    parser.add_argument("--once", action="store_true")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: Any) -> None:
    if args.poll_seconds < 5 or args.poll_seconds > 300:
        parser.error("--poll-seconds must be between 5 and 300")


def _try_leader_lock(db: Session, *, tenant_id: str, region_id: str) -> bool:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return True
    lock_key = f"icheck.rollout:{tenant_id}:{region_id}"
    return bool(
        db.scalar(
            text("SELECT pg_try_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": lock_key},
        )
    )


def evaluate_once(db: Session, *, tenant_id: str, region_id: str) -> int:
    require_locking_transaction(db, purpose="Rollout leader election and progression")
    if session_namespace(db) != (tenant_id, region_id):
        raise ValueError("Rollout controller namespace differs from its bound session")
    if not _try_leader_lock(db, tenant_id=tenant_id, region_id=region_id):
        db.rollback()
        return 0
    rollout_ids = list(
        db.scalars(
            select(CollectorFleetRollout.id)
            .where(
                CollectorFleetRollout.progression_mode == "automatic",
                CollectorFleetRollout.automation_state.in_(("armed", "observing")),
                CollectorFleetRollout.status.in_(("planned", "running")),
            )
            .order_by(CollectorFleetRollout.created_at, CollectorFleetRollout.id)
            .limit(100)
        ).all()
    )
    for rollout_id in rollout_ids:
        reconcile_automatic_rollout(
            db,
            rollout_id,
            actor="system.rollout-controller",
            commit=False,
        )
    db.commit()
    return len(rollout_ids)


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
            "the rollout worker requires PostgreSQL advisory-lock leader election"
        )

    while True:
        with SessionLocal() as db:
            bind_worker_namespace(db, namespace)
            evaluated = evaluate_once(
                db,
                tenant_id=namespace.tenant_id,
                region_id=namespace.region_id,
            )
        if args.once:
            return 0
        if not evaluated:
            LOGGER.debug("no automatic fleet rollouts evaluated by this replica")
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
