"""Opt-in durable background synchronization; existing connections stay manual."""
from alembic import op
import sqlalchemy as sa

revision = "d7j9l1n3p5s8"
down_revision = "c6i8k0m2p4r7"
branch_labels = depends_on = None
TABLE = "monitoring_integration_schedules"


def upgrade():
    op.create_table(TABLE,
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("connection_id", sa.String(36), sa.ForeignKey("monitoring_integration_connections.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("connection_revision", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True)),
        sa.Column("active_run_id", sa.String(36), sa.ForeignKey("monitoring_integration_syncs.id", ondelete="RESTRICT")),
        sa.Column("lease_token", sa.String(36)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(64)),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("revision > 0 AND connection_revision > 0", name="ck_integration_schedule_revision"),
        sa.CheckConstraint("interval_seconds >= 300 AND interval_seconds <= 86400", name="ck_integration_schedule_interval"),
        sa.CheckConstraint("retention_days >= 7 AND retention_days <= 365", name="ck_integration_schedule_retention"),
        sa.CheckConstraint("failures >= 0", name="ck_integration_schedule_failures"))
    for field in ("tenant_id", "region_id", "next_run_at"):
        op.create_index(f"ix_{TABLE}_{field}", TABLE, [field])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))


def downgrade():
    if op.get_bind().execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot discard saved integration schedules or their history")
    op.drop_table(TABLE)
