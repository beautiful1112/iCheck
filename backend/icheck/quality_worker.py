"""Regional control-plane quality controller; no remote actuation or credentials."""
from __future__ import annotations

import argparse
import logging
import os
import time

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .config import get_settings
from .database import SessionLocal, require_locking_transaction, session_namespace
from .models import CapabilityQualityPolicy, utcnow
from .services.capability_quality import MAX_POLICIES, evaluate_policy
from .worker_namespace import add_worker_namespace_arguments, bind_worker_namespace, parse_worker_namespace


LOGGER = logging.getLogger("icheck.quality_worker")


def evaluate_once(db: Session) -> int:
    require_locking_transaction(db, purpose="Quality leader election and assessments")
    namespace = session_namespace(db)
    if namespace is None:
        raise ValueError("Quality controller requires a bound namespace")
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        acquired = db.scalar(text("SELECT pg_try_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": f"icheck.quality:{namespace[0]}:{namespace[1]}"})
        if not acquired:
            db.rollback()
            return 0
    now = utcnow()
    ids = list(db.scalars(select(CapabilityQualityPolicy.id).where(
        CapabilityQualityPolicy.tenant_id == namespace[0], CapabilityQualityPolicy.region_id == namespace[1],
        CapabilityQualityPolicy.next_evaluation_at <= now,
    ).order_by(CapabilityQualityPolicy.next_evaluation_at, CapabilityQualityPolicy.id).limit(MAX_POLICIES)).all())
    for policy_id in ids:
        evaluate_policy(db, policy_id, actor="system.quality-controller", now=now, commit=False)
    db.commit()
    return len(ids)


def main() -> int:
    logging.basicConfig(level=os.environ.get("ICHECK_LOG_LEVEL", "INFO"))
    parser = argparse.ArgumentParser(description="Continuously evaluate namespace-local capability execution health")
    add_worker_namespace_arguments(parser)
    parser.add_argument("--poll-seconds", type=float, default=30)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not 5 <= args.poll_seconds <= 300:
        parser.error("--poll-seconds must be between 5 and 300")
    namespace = parse_worker_namespace(parser, args)
    if not get_settings().database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        parser.error("the continuous quality worker requires PostgreSQL leader election")
    while True:
        with SessionLocal() as db:
            bind_worker_namespace(db, namespace)
            count = evaluate_once(db)
        if count:
            LOGGER.info("assessed %s due capability policies", count)
        if args.once:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
