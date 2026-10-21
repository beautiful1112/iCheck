"""Durable source inventory and bounded resumable synchronization."""
from alembic import op
import sqlalchemy as sa

revision = "c6i8k0m2p4r7"
down_revision = "b5h7j9l1n3q6"
branch_labels = depends_on = None
TABLES = ("monitoring_integration_syncs", "monitoring_integration_resources")


def namespace_columns():
    return [sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
            sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002")]


def upgrade():
    op.create_table(TABLES[0], *namespace_columns(),
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("connection_id", sa.String(36), sa.ForeignKey("monitoring_integration_connections.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("connection_revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("host_ids", sa.JSON(), nullable=True),
        sa.Column("cursor", sa.Integer(), nullable=False), sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("observed", sa.Integer(), nullable=False), sa.Column("error_code", sa.String(64)),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("status IN ('in_progress','completed','failed','superseded')", name="ck_integration_sync_status"),
        sa.CheckConstraint("cursor >= 0 AND cursor <= total AND total <= 10000 AND observed >= 0 AND observed <= cursor", name="ck_integration_sync_progress"))
    op.create_table(TABLES[1], *namespace_columns(),
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("connection_id", sa.String(36), sa.ForeignKey("monitoring_integration_connections.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("connection_revision", sa.Integer(), nullable=False),
        sa.Column("remote_id", sa.String(20), nullable=False), sa.Column("name", sa.String(255), nullable=False),
        sa.Column("monitoring_enabled", sa.Boolean(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_id", sa.String(36), sa.ForeignKey("monitoring_integration_syncs.id", ondelete="RESTRICT"), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "connection_id", "remote_id", name="uq_integration_resource_identity"))
    for table in TABLES:
        for field in ("tenant_id", "region_id", "connection_id"):
            op.create_index(f"ix_{table}_{field}", table, [field])
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate})"))


def downgrade():
    for table in TABLES:
        if op.get_bind().execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Cannot discard imported inventory or synchronization history")
    for table in reversed(TABLES):
        op.drop_table(table)
