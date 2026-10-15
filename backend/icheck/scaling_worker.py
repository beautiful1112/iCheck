from __future__ import annotations

import argparse
import logging
import os
import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from .config import get_settings
from .database import SessionLocal, require_locking_transaction, session_namespace
from .services.worker_scaling import (
    evaluate_scaling_policy,
    list_scaling_policies,
)
from .worker_namespace import (
    add_worker_namespace_arguments,
    bind_worker_namespace,
    parse_worker_namespace,
)


LOGGER = logging.getLogger("icheck.scaling_worker")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate regional iCheck worker autoscaling policies"
    )
    add_worker_namespace_arguments(parser)
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=float(os.environ.get("ICHECK_SCALING_WORKER_POLL_SECONDS", "15")),
    )
    parser.add_argument("--once", action="store_true")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: Any) -> None:
    if args.poll_seconds < 5 or args.poll_seconds > 300:
        parser.error("--poll-seconds must be between 5 and 300")


def _try_leader_lock(db: Session, *, tenant_id: str, region_id: str) -> bool:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return True
    lock_key = f"icheck.scaling:{tenant_id}:{region_id}"
    acquired = db.scalar(
        text("SELECT pg_try_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": lock_key},
    )
    return bool(acquired)


def evaluate_once(db: Session, *, tenant_id: str, region_id: str) -> int:
    require_locking_transaction(db, purpose="Scaling leader election and recommendations")
    if session_namespace(db) != (tenant_id, region_id):
        raise ValueError("Scaling controller namespace differs from its bound session")
    if not _try_leader_lock(db, tenant_id=tenant_id, region_id=region_id):
        db.rollback()
        return 0
    decisions = [
        evaluate_scaling_policy(
            db,
            policy,
            actor="system.scaling-controller",
            commit=False,
        )
        for policy in sorted(list_scaling_policies(db), key=lambda policy: policy.id)
    ]
    db.commit()
    for decision in decisions:
        LOGGER.info(
            "policy=%s current=%s desired=%s direction=%s queue=%s",
            decision.policy_id,
            decision.current_replicas,
            decision.desired_replicas,
            decision.direction,
            decision.queue_depth,
        )
    return len(decisions)


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
            "the scaling worker requires PostgreSQL advisory-lock leader election"
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
            LOGGER.debug("no scaling policies evaluated by this replica")
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
