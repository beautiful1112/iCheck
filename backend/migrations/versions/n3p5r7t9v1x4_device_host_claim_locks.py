"""Fence Collector external-host review against Device inventory phantoms.

Revision ID: n3p5r7t9v1x4
Revises: m2o4q6s8u0w3
"""

from alembic import op
import sqlalchemy as sa


revision = "n3p5r7t9v1x4"
down_revision = "m2o4q6s8u0w3"
branch_labels = depends_on = None

FUNCTION = "icheck_lock_device_host_claims"
TRIGGER = "icheck_device_host_claim_locks"


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        return  # SQLite has one writer; PostgreSQL is the concurrency target.
    if dialect != "postgresql":
        raise RuntimeError("Device host claim locks require PostgreSQL or SQLite")
    op.execute(sa.text(f"""
        CREATE FUNCTION {FUNCTION}() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            resources text[] := ARRAY[]::text[];
            lock_key bigint;
        BEGIN
            IF TG_OP = 'UPDATE' THEN
                IF OLD.tenant_id IS NOT DISTINCT FROM NEW.tenant_id
                   AND OLD.region_id IS NOT DISTINCT FROM NEW.region_id
                   AND OLD.name IS NOT DISTINCT FROM NEW.name
                   AND OLD.management_ip IS NOT DISTINCT FROM NEW.management_ip
                THEN
                    RETURN NEW;
                END IF;
            END IF;
            IF TG_OP <> 'INSERT' THEN
                resources := array_append(resources,
                    'icheck.device-host/v1|' || OLD.tenant_id || '|' ||
                    OLD.region_id || '|' || lower(OLD.name));
                IF OLD.management_ip IS NOT NULL THEN
                    resources := array_append(resources,
                        'icheck.device-host/v1|' || OLD.tenant_id || '|' ||
                        OLD.region_id || '|' || lower(OLD.management_ip));
                END IF;
            END IF;
            IF TG_OP <> 'DELETE' THEN
                resources := array_append(resources,
                    'icheck.device-host/v1|' || NEW.tenant_id || '|' ||
                    NEW.region_id || '|' || lower(NEW.name));
                IF NEW.management_ip IS NOT NULL THEN
                    resources := array_append(resources,
                        'icheck.device-host/v1|' || NEW.tenant_id || '|' ||
                        NEW.region_id || '|' || lower(NEW.management_ip));
                END IF;
            END IF;
            FOR lock_key IN
                SELECT DISTINCT hashtextextended(item.resource, 0)
                FROM unnest(resources) AS item(resource)
                ORDER BY 1
            LOOP
                PERFORM pg_advisory_xact_lock(lock_key);
            END LOOP;
            IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
            RETURN NEW;
        END; $$
    """))
    op.execute(sa.text(
        f"CREATE TRIGGER {TRIGGER} BEFORE INSERT OR UPDATE OR DELETE ON devices "
        f"FOR EACH ROW EXECUTE FUNCTION {FUNCTION}()"
    ))


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        return
    if dialect != "postgresql":
        raise RuntimeError("Device host claim locks require PostgreSQL or SQLite")
    active = op.get_bind().execute(sa.text(
        "SELECT COUNT(*) FROM collector_deployments "
        "WHERE target_classification = 'external_source'"
    )).scalar_one()
    if active:
        raise RuntimeError(
            "Cannot remove Device host locks while external-source Collectors exist"
        )
    op.execute(sa.text(f"DROP TRIGGER {TRIGGER} ON devices"))
    op.execute(sa.text(f"DROP FUNCTION {FUNCTION}()"))
