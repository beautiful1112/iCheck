"""Fence Collector leases against old API and Worker binaries.

Revision ID: q5s7u9w1y3a6
Revises: p4r6t8v0x2z5
"""

from alembic import op
import sqlalchemy as sa


revision = "q5s7u9w1y3a6"
down_revision = "p4r6t8v0x2z5"
branch_labels = depends_on = None

LEASE_FUNCTION = "icheck_require_supervised_collector_lease"
LEASE_TRIGGER = "icheck_supervised_collector_lease"
WORKER_FUNCTION = "icheck_preserve_supervised_collector_worker"
WORKER_TRIGGER = "icheck_supervised_collector_worker"


def _require_drained() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        for table in ("collector_deployments", "collector_runs", "collector_workers"):
            if connection.execute(sa.text(
                "SELECT row_security_active(:table)"
            ), {"table": table}).scalar_one():
                raise RuntimeError(
                    "Supervised Collector lease migration requires an unrestricted migration role"
                )
        # Claims lock deployments before inserting runs. Hold both table locks
        # through the revision commit so the drain check and trigger install
        # have no allocation window.
        op.execute(sa.text("SET LOCAL lock_timeout = '10s'"))
        op.execute(sa.text(
            "LOCK TABLE collector_deployments, collector_runs "
            "IN SHARE ROW EXCLUSIVE MODE"
        ))
    elif connection.dialect.name != "sqlite":
        raise RuntimeError("Supervised Collector lease fence requires PostgreSQL or SQLite")
    active_leases = connection.execute(sa.text(
        "SELECT COUNT(*) FROM collector_deployments "
        "WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL"
    )).scalar_one()
    running = connection.execute(sa.text(
        "SELECT COUNT(*) FROM collector_runs WHERE status = 'RUNNING'"
    )).scalar_one()
    if active_leases or running:
        raise RuntimeError(
            "Drain all Collector leases and running runs before supervised-I/O upgrade"
        )


def upgrade() -> None:
    _require_drained()
    if op.get_bind().dialect.name == "sqlite":
        return  # SQLite has a single writer; API admission is its code gate.
    op.execute(sa.text(f"""
        CREATE FUNCTION {LEASE_FUNCTION}() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE supervised boolean;
        BEGIN
            IF NEW.lease_worker_id IS NULL AND NEW.lease_token_hash IS NULL THEN
                RETURN NEW;
            END IF;
            IF NEW.lease_worker_id IS NULL OR NEW.lease_token_hash IS NULL THEN
                RAISE EXCEPTION 'Collector lease requires both Worker and token'
                    USING ERRCODE = '23514';
            END IF;
            SELECT json_typeof(w.labels -> 'io_supervisor_v1') = 'boolean'
                   AND (w.labels ->> 'io_supervisor_v1') = 'true'
                INTO supervised
                FROM collector_workers AS w
                WHERE w.id = NEW.lease_worker_id
                  AND w.tenant_id = NEW.tenant_id
                  AND w.region_id = NEW.region_id
                FOR SHARE;
            IF supervised IS DISTINCT FROM TRUE THEN
                RAISE EXCEPTION 'Collector lease requires supervised Worker'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END; $$
    """))
    op.execute(sa.text(
        f"CREATE TRIGGER {LEASE_TRIGGER} BEFORE INSERT OR UPDATE OF "
        "lease_worker_id, lease_token_hash, lease_expires_at "
        "ON collector_deployments FOR EACH ROW "
        f"EXECUTE FUNCTION {LEASE_FUNCTION}()"
    ))
    op.execute(sa.text(f"""
        CREATE FUNCTION {WORKER_FUNCTION}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF json_typeof(NEW.labels -> 'io_supervisor_v1') = 'boolean'
               AND (NEW.labels ->> 'io_supervisor_v1') = 'true' THEN
                RETURN NEW;
            END IF;
            IF EXISTS (
                SELECT 1 FROM collector_deployments AS d
                WHERE d.lease_worker_id = OLD.id
                  AND d.tenant_id = OLD.tenant_id
                  AND d.region_id = OLD.region_id
                  AND d.lease_token_hash IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'Drain Collector leases before removing Worker supervision'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END; $$
    """))
    op.execute(sa.text(
        f"CREATE TRIGGER {WORKER_TRIGGER} BEFORE UPDATE OF labels "
        "ON collector_workers FOR EACH ROW "
        f"EXECUTE FUNCTION {WORKER_FUNCTION}()"
    ))


def downgrade() -> None:
    _require_drained()
    if op.get_bind().dialect.name == "sqlite":
        return
    op.execute(sa.text(f"DROP TRIGGER {WORKER_TRIGGER} ON collector_workers"))
    op.execute(sa.text(f"DROP FUNCTION {WORKER_FUNCTION}()"))
    op.execute(sa.text(f"DROP TRIGGER {LEASE_TRIGGER} ON collector_deployments"))
    op.execute(sa.text(f"DROP FUNCTION {LEASE_FUNCTION}()"))
