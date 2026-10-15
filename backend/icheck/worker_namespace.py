from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from .database import set_session_namespace, validate_session_namespace


@dataclass(frozen=True)
class WorkerNamespace:
    tenant_id: str
    region_id: str


def add_worker_namespace_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("ICHECK_TENANT_ID"),
        help="Tenant UUID this worker is permanently assigned to",
    )
    parser.add_argument(
        "--region-id",
        default=os.environ.get("ICHECK_REGION_ID"),
        help="Region UUID this worker is permanently assigned to",
    )


def parse_worker_namespace(
    parser: argparse.ArgumentParser,
    args: Any,
) -> WorkerNamespace:
    tenant_id = _canonical_uuid(parser, "tenant-id", args.tenant_id)
    region_id = _canonical_uuid(parser, "region-id", args.region_id)
    return WorkerNamespace(tenant_id=tenant_id, region_id=region_id)


def bind_worker_namespace(
    db: Session,
    namespace: WorkerNamespace,
    *,
    validate: bool = True,
) -> None:
    set_session_namespace(db, namespace.tenant_id, namespace.region_id)
    if validate:
        validate_session_namespace(db)


def _canonical_uuid(
    parser: argparse.ArgumentParser,
    option: str,
    value: str | None,
) -> str:
    if not value:
        variable = option.replace("-", "_").upper()
        parser.error(f"--{option} or ICHECK_{variable} is required")
    try:
        return str(UUID(value))
    except (TypeError, ValueError) as exc:
        parser.error(f"--{option} must be a UUID")
        raise AssertionError("argparse exits") from exc
