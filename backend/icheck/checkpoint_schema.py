"""Owner-provisioned LangGraph tables and read-only runtime schema checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import psycopg
from langgraph.checkpoint.postgres import PostgresSaver
from psycopg import sql


OWNER_URL_ENV = "ICHECK_CHECKPOINT_SCHEMA_OWNER_URL"
DEFAULT_LOCK_TIMEOUT_MS = 5000
MAX_LOCK_TIMEOUT_MS = 300000
RUNTIME_ROLE_PATTERN = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
SCHEMA = "public"
SUPPORTED_SAVER_MIGRATION_VERSION = 9
# SHA-256 of the installed PostgresSaver.MIGRATIONS joined with NUL bytes.
# A same-count SQL rewrite is still a new schema/grant contract for review.
SUPPORTED_SAVER_MIGRATIONS_SHA256 = (
    "98d38ed91d4a57a2fb066323f26f2902efcb01f483e09f3ff2be31304a799d35"
)
DATA_TABLES = ("checkpoints", "checkpoint_blobs", "checkpoint_writes")
SOURCE_TABLES = ("regions", "investigations", "agent_executions")
FORBIDDEN_TABLE_PRIVILEGES = ("TRUNCATE", "REFERENCES", "TRIGGER")
NAMESPACE_POLICY = "icheck_checkpoint_namespace_isolation"
NAMESPACE_EXPRESSION = (
    "tenant_id = current_setting('icheck.tenant_id', true) "
    "AND region_id = current_setting('icheck.region_id', true)"
)
# PostgreSQL's normalized pg_get_expr() form for the reviewed varchar(36)
# policy. An engine/parser change must be reviewed rather than silently
# accepting a widened policy (for example, one containing OR TRUE).
CANONICAL_NAMESPACE_EXPRESSION = (
    "(((tenant_id)::text = current_setting('icheck.tenant_id'::text, true)) "
    "AND ((region_id)::text = current_setting('icheck.region_id'::text, true)))"
)
TABLE_PRIVILEGES = {
    "checkpoint_migrations": ("SELECT",),
    "checkpoints": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "checkpoint_blobs": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "checkpoint_writes": ("SELECT", "INSERT", "UPDATE", "DELETE"),
}
REQUIRED_COLUMNS = {
    "checkpoint_migrations": {"v"},
    "checkpoints": {
        "thread_id", "checkpoint_ns", "checkpoint_id", "parent_checkpoint_id",
        "type", "checkpoint", "metadata", "tenant_id", "region_id",
    },
    "checkpoint_blobs": {
        "thread_id", "checkpoint_ns", "channel", "version", "type", "blob",
        "tenant_id", "region_id",
    },
    "checkpoint_writes": {
        "thread_id", "checkpoint_ns", "checkpoint_id", "task_id",
        "task_path", "idx", "channel", "type", "blob", "tenant_id",
        "region_id",
    },
}
REQUIRED_INDEX_TABLES = {
    "checkpoints_thread_id_idx": "checkpoints",
    "checkpoint_blobs_thread_id_idx": "checkpoint_blobs",
    "checkpoint_writes_thread_id_idx": "checkpoint_writes",
}


def postgres_dsn(database_url: str) -> str:
    if database_url.startswith("postgresql+psycopg://"):
        return "postgresql://" + database_url.removeprefix(
            "postgresql+psycopg://"
        )
    if database_url.startswith(("postgresql://", "postgres://")):
        return database_url
    raise ValueError("LangGraph checkpoints require a PostgreSQL URL")


def _lock_timeout_setting(value: int) -> str:
    if (
        isinstance(value, bool) or not isinstance(value, int)
        or value < 100 or value > MAX_LOCK_TIMEOUT_MS
    ):
        raise ValueError(
            f"Checkpoint lock timeout must be 100-{MAX_LOCK_TIMEOUT_MS} ms"
        )
    return f"{value}ms"


def _version() -> int:
    installed = len(PostgresSaver.MIGRATIONS) - 1
    digest = hashlib.sha256(
        "\0".join(PostgresSaver.MIGRATIONS).encode("utf-8")
    ).hexdigest()
    if (
        installed != SUPPORTED_SAVER_MIGRATION_VERSION
        or digest != SUPPORTED_SAVER_MIGRATIONS_SHA256
    ):
        raise RuntimeError(
            "Installed PostgresSaver migration contract changed; review checkpoint grants"
        )
    return installed


def _restricted_runtime_role(cursor: psycopg.Cursor, role: str) -> None:
    cursor.execute(
        "SELECT r.rolcanlogin, r.rolsuper, r.rolbypassrls, r.rolcreatedb, "
        "r.rolcreaterole, r.rolreplication, d.datdba = r.oid, "
        "EXISTS (SELECT 1 FROM pg_roles elevated WHERE "
        "(elevated.rolsuper OR elevated.rolbypassrls "
        "OR elevated.rolcreatedb OR elevated.rolcreaterole "
        "OR elevated.rolreplication "
        "OR elevated.oid = d.datdba) "
        "AND elevated.oid <> r.oid "
        "AND pg_has_role(r.oid, elevated.oid, 'MEMBER')) "
        "FROM pg_roles r CROSS JOIN pg_database d "
        "WHERE r.rolname = %s AND d.datname = current_database()",
        (role,),
    )
    row = cursor.fetchone()
    if row is None or not row[0] or any(row[1:]):
        raise RuntimeError(
            "Checkpoint runtime role must be a non-owner, non-privileged login"
        )
    cursor.execute(
        "SELECT has_database_privilege(%s, current_database(), 'CREATE')",
        (role,),
    )
    if cursor.fetchone()[0]:
        raise RuntimeError(
            "Checkpoint runtime role must not have database CREATE"
        )


def _schema_and_role(connection: psycopg.Connection, role: str) -> None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        if cursor.fetchone()[0] != SCHEMA:
            raise RuntimeError("LangGraph checkpoint search_path must resolve to public")
        _restricted_runtime_role(cursor, role)
        cursor.execute(
            "SELECT has_schema_privilege(%s, 'public', 'USAGE'), "
            "has_schema_privilege(%s, 'public', 'CREATE')",
            (role, role),
        )
        has_usage, has_create = cursor.fetchone()
        if has_create:
            raise RuntimeError("Checkpoint runtime role must not have schema CREATE")
        if not has_usage:
            raise RuntimeError("Checkpoint runtime role needs public schema USAGE")
        cursor.execute(
            "SELECT pg_has_role(%s, n.nspowner, 'MEMBER') "
            "FROM pg_namespace n WHERE n.nspname = 'public'", (role,)
        )
        if cursor.fetchone()[0]:
            raise RuntimeError(
                "Checkpoint runtime role must not be a member of the schema owner"
            )


def _owner_source_preflight(cursor: psycopg.Cursor) -> None:
    cursor.execute(
        "SELECT has_schema_privilege(current_user, 'public', 'CREATE')"
    )
    if not cursor.fetchone()[0]:
        raise RuntimeError("Checkpoint owner requires CREATE on public schema")
    cursor.execute(
        "SELECT has_database_privilege(current_user, current_database(), 'TEMP')"
    )
    if not cursor.fetchone()[0]:
        raise RuntimeError("Checkpoint owner requires TEMP on database for namespace ownership mapping")
    for table in SOURCE_TABLES:
        cursor.execute(
            "SELECT has_table_privilege(current_user, %s, 'SELECT')",
            (f"public.{table}",),
        )
        if not cursor.fetchone()[0]:
            raise RuntimeError(f"Checkpoint owner requires SELECT on {table}")


def _check_saver_index(
    cursor: psycopg.Cursor, index_name: str, *, allow_missing: bool,
) -> None:
    qualified = f"public.{index_name}"
    cursor.execute("SELECT to_regclass(%s)", (qualified,))
    relation = cursor.fetchone()[0]
    if relation is None:
        if allow_missing:
            return
        raise RuntimeError(
            f"Missing, invalid or unexpected LangGraph checkpoint index: {index_name}"
        )
    cursor.execute(
        "SELECT tn.nspname, t.relname, am.amname, "
        "i.indisvalid, i.indisready, i.indisunique, i.indisprimary, "
        "i.indnkeyatts, i.indnatts, i.indpred IS NULL, "
        "i.indexprs IS NULL, pg_get_indexdef(i.indexrelid, 1, true) "
        "FROM pg_index AS i "
        "JOIN pg_class AS idx ON idx.oid = i.indexrelid "
        "JOIN pg_class AS t ON t.oid = i.indrelid "
        "JOIN pg_namespace AS tn ON tn.oid = t.relnamespace "
        "JOIN pg_am AS am ON am.oid = idx.relam "
        "WHERE i.indexrelid = to_regclass(%s)",
        (qualified,),
    )
    row = cursor.fetchone()
    expected = (
        SCHEMA, REQUIRED_INDEX_TABLES[index_name], "btree",
        True, True, False, False, 1, 1, True, True, "thread_id",
    )
    if row != expected:
        raise RuntimeError(
            f"Missing, invalid or unexpected LangGraph checkpoint index: {index_name}"
        )


def _orphan_inventory(
    cursor: psycopg.Cursor, *, namespace_count: int,
    orphan_count: int, conflict_count: int,
) -> dict[str, Any]:
    table_rows: dict[str, dict[str, int]] = {}
    for table in DATA_TABLES:
        qualified = sql.Identifier(SCHEMA, table)
        cursor.execute(
            sql.SQL(
                "SELECT count(*), "
                "count(*) FILTER (WHERE c.tenant_id IS NULL "
                "OR c.region_id IS NULL), "
                "count(*) FILTER (WHERE c.tenant_id IS NOT NULL "
                "AND c.region_id IS NOT NULL AND NOT EXISTS ("
                "SELECT 1 FROM pg_temp.icheck_checkpoint_candidates AS o "
                "WHERE o.thread_id = c.thread_id "
                "AND o.tenant_id = c.tenant_id "
                "AND o.region_id = c.region_id)) "
                "FROM {} AS c"
            ).format(qualified)
        )
        total, unassigned, mismatched = cursor.fetchone()
        table_rows[table] = {
            "rows": total,
            "unassigned_rows": unassigned,
            "unmatched_namespace_rows": mismatched,
        }
    cursor.execute(
        "SELECT t.thread_id FROM pg_temp.icheck_checkpoint_threads AS t "
        "LEFT JOIN pg_temp.icheck_checkpoint_candidates AS c "
        "ON c.thread_id = t.thread_id "
        "WHERE c.thread_id IS NULL ORDER BY t.thread_id LIMIT 20"
    )
    orphan_samples = [
        hashlib.sha256(row[0].encode("utf-8")).hexdigest()
        for row in cursor.fetchall()
    ]
    cursor.execute(
        "SELECT count(*) FROM pg_temp.icheck_checkpoint_threads"
    )
    thread_count = cursor.fetchone()[0]
    cursor.execute("SELECT current_database(), current_user")
    database_name, owner_role = cursor.fetchone()
    return {
        "format_version": "icheck.checkpoint-orphan-audit/v1",
        "database_name": database_name,
        "owner_role": owner_role,
        "registered_regions": namespace_count,
        "thread_count": thread_count,
        "orphan_thread_count": orphan_count,
        "conflicting_thread_count": conflict_count,
        "orphan_thread_sha256_sample": orphan_samples,
        "tables": table_rows,
        "database_changes_committed": False,
    }


def _install_namespace_isolation(
    connection: psycopg.Connection, *, audit_only: bool = False
) -> dict[str, Any] | None:
    """Backfill known graph threads and fail closed on orphaned legacy data."""
    with connection.cursor() as cursor:
        for table in DATA_TABLES:
            qualified = sql.Identifier(SCHEMA, table)
            # A later owner rerun must see every existing row even when FORCE
            # RLS was already installed. This DDL takes a table lock and rolls
            # back together with the audit if any row cannot be attributed.
            cursor.execute(
                sql.SQL("ALTER TABLE {} DISABLE ROW LEVEL SECURITY")
                .format(qualified)
            )
            for field in ("tenant_id", "region_id"):
                cursor.execute(
                    sql.SQL("ALTER TABLE {} ADD COLUMN IF NOT EXISTS {} varchar(36)")
                    .format(qualified, sql.Identifier(field))
                )

        # Source tables retain iCheck's own tenant/region RLS. A checkpoint
        # owner needs only SELECT on the region registry and the two source
        # tables, not BYPASSRLS or ownership of the application schema.
        cursor.execute(
            "CREATE TEMP TABLE icheck_checkpoint_threads ("
            "thread_id text PRIMARY KEY) ON COMMIT DROP"
        )
        cursor.execute(
            "CREATE TEMP TABLE icheck_checkpoint_candidates ("
            "thread_id text NOT NULL, tenant_id varchar(36) NOT NULL, "
            "region_id varchar(36) NOT NULL, "
            "PRIMARY KEY (thread_id, tenant_id, region_id)) ON COMMIT DROP"
        )
        for table in DATA_TABLES:
            cursor.execute(
                sql.SQL(
                    "INSERT INTO pg_temp.icheck_checkpoint_threads (thread_id) "
                    "SELECT DISTINCT thread_id FROM {} ON CONFLICT DO NOTHING"
                ).format(sql.Identifier(SCHEMA, table))
            )
        cursor.execute(
            "SELECT tenant_id, id FROM public.regions ORDER BY tenant_id, id"
        )
        namespaces = cursor.fetchall()
        for tenant_id, region_id in namespaces:
            cursor.execute(
                "SELECT set_config('icheck.tenant_id', %s, true), "
                "set_config('icheck.region_id', %s, true)",
                (tenant_id, region_id),
            )
            cursor.execute(
                "INSERT INTO pg_temp.icheck_checkpoint_candidates "
                "(thread_id, tenant_id, region_id) "
                "SELECT t.thread_id, i.tenant_id, i.region_id "
                "FROM public.investigations AS i "
                "JOIN pg_temp.icheck_checkpoint_threads AS t ON t.thread_id = i.id "
                "ON CONFLICT DO NOTHING"
            )
            cursor.execute(
                "INSERT INTO pg_temp.icheck_checkpoint_candidates "
                "(thread_id, tenant_id, region_id) "
                "SELECT t.thread_id, i.tenant_id, i.region_id "
                "FROM public.agent_executions AS e "
                "JOIN public.investigations AS i ON i.id = e.investigation_id "
                "JOIN pg_temp.icheck_checkpoint_threads AS t "
                "ON split_part(t.thread_id, ':', 2) = e.id "
                "WHERE split_part(t.thread_id, ':', 1) IN "
                "('agent-runtime-reason', 'agent-runtime-tool') "
                "AND split_part(t.thread_id, ':', 3) <> '' "
                "ON CONFLICT DO NOTHING"
            )
        cursor.execute(
            "SELECT set_config('icheck.tenant_id', '', true), "
            "set_config('icheck.region_id', '', true)"
        )
        cursor.execute(
            "SELECT count(*) FROM ("
            "SELECT thread_id FROM pg_temp.icheck_checkpoint_candidates "
            "GROUP BY thread_id HAVING count(*) > 1) AS conflicting"
        )
        conflict_count = cursor.fetchone()[0]
        if conflict_count and not audit_only:
            raise RuntimeError("Checkpoint thread has conflicting tenant ownership")
        cursor.execute(
            "SELECT count(*) FROM pg_temp.icheck_checkpoint_threads AS t "
            "LEFT JOIN pg_temp.icheck_checkpoint_candidates AS c "
            "ON c.thread_id = t.thread_id "
            "WHERE c.thread_id IS NULL"
        )
        missing = cursor.fetchone()[0]
        if audit_only:
            return _orphan_inventory(
                cursor, namespace_count=len(namespaces),
                orphan_count=missing, conflict_count=conflict_count,
            )
        if missing:
            raise RuntimeError(
                f"Checkpoint tables have {missing} orphaned threads across "
                f"{len(namespaces)} registered regions"
            )

        for table in DATA_TABLES:
            qualified = sql.Identifier(SCHEMA, table)
            cursor.execute(
                sql.SQL(
                    "UPDATE {} AS c SET tenant_id = o.tenant_id, "
                    "region_id = o.region_id "
                    "FROM pg_temp.icheck_checkpoint_candidates AS o "
                    "WHERE c.thread_id = o.thread_id "
                    "AND c.tenant_id IS NULL AND c.region_id IS NULL"
                ).format(qualified)
            )
            cursor.execute(
                sql.SQL(
                    "SELECT 1 FROM {} AS c "
                    "LEFT JOIN pg_temp.icheck_checkpoint_candidates AS o "
                    "ON o.thread_id = c.thread_id "
                    "WHERE c.tenant_id IS DISTINCT FROM o.tenant_id "
                    "OR c.region_id IS DISTINCT FROM o.region_id LIMIT 1"
                ).format(qualified)
            )
            if cursor.fetchone() is not None:
                raise RuntimeError(
                    f"Checkpoint table {table} has orphaned or misattributed threads"
                )
            for field in ("tenant_id", "region_id"):
                cursor.execute(
                    sql.SQL(
                        "ALTER TABLE {} ALTER COLUMN {} SET DEFAULT "
                        "NULLIF(current_setting({}, true), ''), "
                        "ALTER COLUMN {} SET NOT NULL"
                    ).format(
                        qualified, sql.Identifier(field),
                        sql.Literal(f"icheck.{field}"), sql.Identifier(field),
                    )
                )
            cursor.execute(
                sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY")
                .format(qualified)
            )
            cursor.execute(
                sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY")
                .format(qualified)
            )
            cursor.execute(
                sql.SQL("DROP POLICY IF EXISTS {} ON {}")
                .format(sql.Identifier(NAMESPACE_POLICY), qualified)
            )
            cursor.execute(
                sql.SQL(
                    "CREATE POLICY {} ON {} FOR ALL TO PUBLIC "
                    "USING ({}) WITH CHECK ({})"
                ).format(
                    sql.Identifier(NAMESPACE_POLICY), qualified,
                    sql.SQL(NAMESPACE_EXPRESSION),
                    sql.SQL(NAMESPACE_EXPRESSION),
                )
            )
    return None


def _check_namespace_isolation(
    cursor: psycopg.Cursor, table: str,
) -> None:
    qualified = f"{SCHEMA}.{table}"
    cursor.execute(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
        "WHERE oid = to_regclass(%s)", (qualified,)
    )
    if cursor.fetchone() != (True, True):
        raise RuntimeError(f"Checkpoint table {table} requires forced RLS")
    cursor.execute(
        "SELECT polcmd, polpermissive, polroles, "
        "pg_get_expr(polqual, polrelid), "
        "pg_get_expr(polwithcheck, polrelid) "
        "FROM pg_policy WHERE polrelid = to_regclass(%s)", (qualified,)
    )
    policies = cursor.fetchall()
    if len(policies) != 1:
        raise RuntimeError(f"Checkpoint table {table} requires one RLS policy")
    command, permissive, roles, using, checking = policies[0]
    if (
        command != "*" or not permissive or list(roles) != [0]
        or using != CANONICAL_NAMESPACE_EXPRESSION
        or checking != CANONICAL_NAMESPACE_EXPRESSION
    ):
        raise RuntimeError(f"Checkpoint table {table} has unexpected RLS policy")
    for field in ("tenant_id", "region_id"):
        cursor.execute(
            "SELECT is_nullable, column_default FROM information_schema.columns "
            "WHERE table_schema = %s AND table_name = %s "
            "AND column_name = %s", (SCHEMA, table, field)
        )
        row = cursor.fetchone()
        if (
            row is None or row[0] != "NO" or row[1] is None
            or f"icheck.{field}" not in row[1]
            or "current_setting" not in row[1]
        ):
            raise RuntimeError(
                f"Checkpoint table {table} lacks scoped {field} default"
            )


def _check_schema(connection: psycopg.Connection, role: str) -> dict[str, Any]:
    _schema_and_role(connection, role)
    with connection.cursor() as cursor:
        for table, privileges in TABLE_PRIVILEGES.items():
            qualified = f"{SCHEMA}.{table}"
            cursor.execute("SELECT to_regclass(%s)", (qualified,))
            if cursor.fetchone()[0] is None:
                raise RuntimeError(f"Missing LangGraph checkpoint table: {table}")
            cursor.execute(
                "SELECT pg_has_role(%s, relowner, 'MEMBER') FROM pg_class "
                "WHERE oid = to_regclass(%s)",
                (role, qualified),
            )
            if cursor.fetchone()[0]:
                raise RuntimeError(
                    f"Checkpoint runtime role must not own or inherit table: {table}"
                )
            for privilege in privileges:
                cursor.execute(
                    "SELECT has_table_privilege(%s, %s, %s)",
                    (role, qualified, privilege),
                )
                if not cursor.fetchone()[0]:
                    raise RuntimeError(
                        f"Checkpoint runtime role lacks {privilege} on {table}"
                    )
            for privilege in FORBIDDEN_TABLE_PRIVILEGES:
                cursor.execute(
                    "SELECT has_table_privilege(%s, %s, %s)",
                    (role, qualified, privilege),
                )
                if cursor.fetchone()[0]:
                    raise RuntimeError(
                        f"Checkpoint runtime role must not have {privilege} "
                        f"on {table}"
                    )
            cursor.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = %s",
                (SCHEMA, table),
            )
            columns = {row[0] for row in cursor.fetchall()}
            missing = REQUIRED_COLUMNS[table] - columns
            if missing:
                raise RuntimeError(
                    f"LangGraph checkpoint table {table} lacks required columns"
                )
            if table in DATA_TABLES:
                _check_namespace_isolation(cursor, table)
        for privilege in ("INSERT", "UPDATE", "DELETE"):
            cursor.execute(
                "SELECT has_table_privilege(%s, %s, %s)",
                (role, "public.checkpoint_migrations", privilege),
            )
            if cursor.fetchone()[0]:
                raise RuntimeError(
                    "Checkpoint runtime role must not modify migration history"
                )
        for index in REQUIRED_INDEX_TABLES:
            _check_saver_index(cursor, index, allow_missing=False)
        cursor.execute("SELECT max(v) FROM public.checkpoint_migrations")
        installed = cursor.fetchone()[0]
        if installed != _version():
            raise RuntimeError(
                "LangGraph checkpoint migrations do not match the installed saver"
            )
        cursor.execute("SELECT current_database()")
        database_name = cursor.fetchone()[0]
    return {
        "schema": SCHEMA,
        "database_name": database_name,
        "runtime_role": role,
        "saver_migration_version": installed,
        "runtime_schema_create": False,
        "runtime_migration_history_write": False,
        "namespace_rls": True,
        "table_count": len(TABLE_PRIVILEGES),
    }


def verify_checkpoint_schema(database_url: str) -> dict[str, Any]:
    """Fail closed before graph traffic without running PostgresSaver DDL."""
    with psycopg.connect(postgres_dsn(database_url)) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_user")
            role = cursor.fetchone()[0]
        return _check_schema(connection, role)


def prepare_checkpoint_schema(
    owner_database_url: str, *, runtime_role: str,
    lock_timeout_ms: int = DEFAULT_LOCK_TIMEOUT_MS,
) -> dict[str, Any]:
    """Run the installed saver's migrations as owner, then grant DML only."""
    if RUNTIME_ROLE_PATTERN.fullmatch(runtime_role) is None:
        raise ValueError("Checkpoint runtime role has an invalid identifier")
    lock_timeout = _lock_timeout_setting(lock_timeout_ms)
    # A newer saver may contain DDL or grants this owner workflow has not
    # reviewed. Reject it before opening the DDL-capable connection.
    _version()
    dsn = postgres_dsn(owner_database_url)
    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT set_config('lock_timeout', %s, true)",
                (lock_timeout,),
            )
            cursor.execute("SELECT current_user, current_schema()")
            owner, schema = cursor.fetchone()
            if schema != SCHEMA or owner == runtime_role:
                raise RuntimeError(
                    "Checkpoint setup requires a separate owner in public schema"
                )
            _owner_source_preflight(cursor)
            _restricted_runtime_role(cursor, runtime_role)
            cursor.execute(
                "SELECT has_schema_privilege(%s, 'public', 'CREATE')",
                (runtime_role,),
            )
            if cursor.fetchone()[0]:
                raise RuntimeError(
                    "Checkpoint runtime role must not have schema CREATE"
                )
            # CREATE INDEX CONCURRENTLY IF NOT EXISTS will skip a same-name
            # invalid or wrong index. Refuse that state before saver DDL.
            for index in REQUIRED_INDEX_TABLES:
                _check_saver_index(cursor, index, allow_missing=True)

    with PostgresSaver.from_conn_string(dsn) as saver:
        # The installed saver uses an autocommit connection, including for
        # CREATE INDEX CONCURRENTLY. Bound lock waits on that connection too;
        # the subsequent namespace/RLS phase remains one separate transaction.
        with saver.conn.cursor() as cursor:
            cursor.execute(
                "SELECT set_config('lock_timeout', %s, false)",
                (lock_timeout,),
            )
        saver.setup()
    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT set_config('lock_timeout', %s, true)",
                (lock_timeout,),
            )
        _install_namespace_isolation(connection)
        with connection.cursor() as cursor:
            cursor.execute(
                sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
                    sql.Identifier(runtime_role)
                )
            )
            cursor.execute(
                sql.SQL("GRANT SELECT ON TABLE public.checkpoint_migrations TO {}")
                .format(sql.Identifier(runtime_role))
            )
            for table in DATA_TABLES:
                cursor.execute(
                    sql.SQL(
                        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{} TO {}"
                    ).format(sql.Identifier(table), sql.Identifier(runtime_role))
                )
        report = _check_schema(connection, runtime_role)
    return report


def audit_checkpoint_orphans(
    owner_database_url: str, *, lock_timeout_ms: int = DEFAULT_LOCK_TIMEOUT_MS,
) -> dict[str, Any]:
    """Inventory orphaned graph threads without committing DDL or deletes."""
    lock_timeout = _lock_timeout_setting(lock_timeout_ms)
    with psycopg.connect(postgres_dsn(owner_database_url)) as connection:
        # A single snapshot keeps source ownership and per-table row counts
        # consistent if an Investigation changes while the audit is running.
        connection.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config('lock_timeout', %s, true)",
                    (lock_timeout,),
                )
                cursor.execute("SELECT current_schema()")
                if cursor.fetchone()[0] != SCHEMA:
                    raise RuntimeError(
                        "Checkpoint audit search_path must resolve to public"
                    )
                _owner_source_preflight(cursor)
                for table in DATA_TABLES:
                    cursor.execute(
                        "SELECT pg_get_userbyid(relowner) FROM pg_class "
                        "WHERE oid = to_regclass(%s)",
                        (f"public.{table}",),
                    )
                    row = cursor.fetchone()
                    if row is None or row[0] != connection.info.user:
                        raise RuntimeError(
                            "Checkpoint audit requires the data-table owner"
                        )
            report = _install_namespace_isolation(connection, audit_only=True)
            assert report is not None
            return report
        finally:
            # ALTER TABLE DISABLE RLS and temporary mapping tables are only
            # transactional scan machinery; never commit them in audit mode.
            connection.rollback()


def audit_main() -> int:
    parser = argparse.ArgumentParser(
        description="Inventory orphaned checkpoint threads without deleting data"
    )
    parser.add_argument("--acknowledge-schema-lock", action="store_true")
    parser.add_argument(
        "--lock-timeout-ms", type=int, default=DEFAULT_LOCK_TIMEOUT_MS
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    owner_url = os.environ.get(OWNER_URL_ENV)
    if not owner_url:
        parser.error(f"{OWNER_URL_ENV} is required; application URL is not a fallback")
    if not args.acknowledge_schema_lock:
        parser.error("--acknowledge-schema-lock is required")
    try:
        report = audit_checkpoint_orphans(
            owner_url, lock_timeout_ms=args.lock_timeout_ms
        )
    except (ValueError, RuntimeError, psycopg.Error) as exc:
        parser.exit(2, f"checkpoint orphan audit failed: {type(exc).__name__}\n")
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-database-ddl", action="store_true")
    parser.add_argument("--runtime-role", required=True)
    parser.add_argument(
        "--lock-timeout-ms", type=int, default=DEFAULT_LOCK_TIMEOUT_MS
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    owner_url = os.environ.get(OWNER_URL_ENV)
    if not owner_url:
        parser.error(f"{OWNER_URL_ENV} is required; application URL is not a fallback")
    if not args.acknowledge_database_ddl:
        parser.error("--acknowledge-database-ddl is required")
    try:
        report = prepare_checkpoint_schema(
            owner_url, runtime_role=args.runtime_role,
            lock_timeout_ms=args.lock_timeout_ms,
        )
    except (ValueError, RuntimeError, psycopg.Error) as exc:
        parser.exit(2, f"checkpoint schema setup failed: {type(exc).__name__}\n")
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
