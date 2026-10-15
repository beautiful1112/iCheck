"""Scoped explicit continuous monitoring intents; no monitoring credentials."""
from alembic import op
import sqlalchemy as sa

revision = "h5k7m9p1r3t6"
down_revision = "g4j6l8n0p2r5"
branch_labels = depends_on = None
TABLE = "device_monitoring_enrollments"


def upgrade():
    op.create_table(TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("connection_id", sa.String(36), sa.ForeignKey("device_connections.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("device_identity_revision", sa.Integer(), nullable=False),
        sa.Column("connection_fingerprint", sa.String(64), nullable=False),
        sa.Column("credential_profile_id", sa.String(36)),
        sa.Column("credential_fingerprint", sa.String(64)),
        sa.Column("gateway_profile", sa.String(63), nullable=False),
        sa.Column("modules", sa.JSON(), nullable=False),
        sa.Column("collectors", sa.JSON(), nullable=False),
        sa.Column("schedule_seconds", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("approved_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.UniqueConstraint("tenant_id", "region_id", "connection_id", name="uq_monitoring_connection"),
        sa.CheckConstraint("revision >= 1", name="ck_monitoring_revision"),
        sa.CheckConstraint("schedule_seconds BETWEEN 15 AND 3600", name="ck_monitoring_schedule"),
        sa.CheckConstraint("timeout_seconds BETWEEN 1 AND 30 AND timeout_seconds < schedule_seconds", name="ck_monitoring_timeout"),
    )
    for column in ("connection_id", "enabled", "approved_until", "tenant_id", "region_id"):
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY"))
        predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))
        op.execute(sa.text("""CREATE FUNCTION icheck_monitoring_enrollment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM device_connections c JOIN devices d ON d.id=c.device_id
            WHERE c.id=NEW.connection_id AND c.tenant_id=NEW.tenant_id AND c.region_id=NEW.region_id
              AND d.tenant_id=NEW.tenant_id AND d.region_id=NEW.region_id) THEN
            RAISE EXCEPTION 'Monitoring enrollment requires a same-namespace connection';
          END IF;
          IF TG_OP='UPDATE' AND (NEW.id<>OLD.id OR NEW.connection_id<>OLD.connection_id
            OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id OR NEW.revision<>OLD.revision+1) THEN
            RAISE EXCEPTION 'Monitoring enrollment identity is immutable and revision must advance';
          END IF;
          RETURN NEW;
        END $$"""))
        op.execute(sa.text(f"CREATE TRIGGER icheck_monitoring_enrollment_guard BEFORE INSERT OR UPDATE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION icheck_monitoring_enrollment_guard()"))


def downgrade():
    if op.get_bind().execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade populated monitoring enrollment history")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER icheck_monitoring_enrollment_guard ON {TABLE}"))
        op.execute(sa.text("DROP FUNCTION icheck_monitoring_enrollment_guard()"))
    op.drop_table(TABLE)
