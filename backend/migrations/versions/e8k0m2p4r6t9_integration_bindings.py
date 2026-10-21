"""Reviewed source-to-asset identity links; no asset creation or collection."""
from alembic import op
import sqlalchemy as sa

revision = "e8k0m2p4r6t9"
down_revision = "d7j9l1n3p5s8"
branch_labels = depends_on = None
TABLE = "monitoring_integration_bindings"


def upgrade():
    op.create_table(TABLE,
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("resource_id", sa.String(36), sa.ForeignKey("monitoring_integration_resources.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("connection_id", sa.String(36), sa.ForeignKey("monitoring_integration_connections.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="RESTRICT")),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("connection_revision", sa.Integer(), nullable=False),
        sa.Column("source_name", sa.String(255), nullable=False),
        sa.Column("device_identity_revision", sa.Integer()),
        sa.Column("reviewed_by", sa.String(255), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "connection_id", "device_id", name="uq_integration_binding_device"),
        sa.CheckConstraint("revision > 0 AND connection_revision > 0", name="ck_integration_binding_revision"))
    for field in ("tenant_id", "region_id", "connection_id"):
        op.create_index(f"ix_{TABLE}_{field}", TABLE, [field])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))


def downgrade():
    if op.get_bind().execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot discard reviewed integration bindings or unlink history")
    op.drop_table(TABLE)
