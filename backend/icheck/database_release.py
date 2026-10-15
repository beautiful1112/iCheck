"""Operator-only migrations from an installed wheel, without a source checkout."""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import sys

from alembic import command
from alembic.config import Config


def migration_config() -> Config:
    # Resolve the wheel's sibling package, not a cwd-relative path or an
    # independently imported generic 'migrations' module on sys.path.
    scripts = Path(__file__).resolve().parent.parent / "migrations"
    if not (scripts / "env.py").is_file() or not (scripts / "versions").is_dir():
        raise RuntimeError("Installed migration bundle is incomplete")
    config = Config(stdout=sys.stdout)
    config.set_main_option("script_location", str(scripts))
    # env.py obtains the database URL from iCheck settings and retains all
    # namespace visibility, ownership-drain and immutable-history guards.
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("heads", help="Read the installed migration head without a database connection")
    commands.add_parser("current", help="Read the configured database revision")
    upgrade = commands.add_parser("upgrade", help="Apply installed migrations with a dedicated migration role")
    upgrade.add_argument("--revision", default="head")
    upgrade.add_argument("--acknowledge-drained", action="store_true",
        help="Confirm backup and coordinated API/Worker drain before upgrading; not a software drain check")
    from .worker_database_roles import PROFILES
    grants = commands.add_parser("worker-grants", help="Inspect or explicitly provision a reviewed internal Worker database role")
    grants.add_argument("--profile", choices=sorted(PROFILES), required=True)
    grants.add_argument("--role", required=True, help="Existing restricted PostgreSQL login; no role is created")
    grants.add_argument("--apply", action="store_true", help="Grant the exact profile using a separate protected owner connection")
    grants.add_argument("--acknowledge-grants", action="store_true")
    grants.add_argument("--acknowledge-drained", action="store_true")
    args = parser.parse_args(argv)
    if args.operation != "heads" and not os.environ.get("ICHECK_DATABASE_URL", "").strip():
        parser.error("Set ICHECK_DATABASE_URL explicitly; the migration CLI does not use a default database")
    if args.operation == "upgrade" and not args.acknowledge_drained:
        parser.error("upgrade requires --acknowledge-drained after backup and coordinated API/Worker drain")
    if args.operation == "worker-grants" and args.apply and not (args.acknowledge_grants and args.acknowledge_drained):
        parser.error("Worker grant application requires --acknowledge-grants and --acknowledge-drained")
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s %(message)s")
    logging.getLogger("alembic").setLevel(logging.INFO)
    try:
        if args.operation == "worker-grants":
            from .worker_database_roles import inspect_worker_grants
            report = inspect_worker_grants(os.environ["ICHECK_DATABASE_URL"],
                profile=args.profile, role=args.role, apply=args.apply)
            print(json.dumps(report, sort_keys=True))
            return 0 if report["complete"] else 1
        config = migration_config()
        if args.operation == "heads":
            command.heads(config)
        elif args.operation == "current":
            command.current(config)
        else:
            command.upgrade(config, args.revision)
    except Exception as error:
        # Connection/driver exceptions may contain URLs, SQL parameters or
        # credentials. Never emit their bodies or a traceback from this CLI.
        print(f"Database command failed ({type(error).__name__}). Check migration prerequisites and database state before retrying.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
