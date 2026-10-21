"""Namespace-scoped external monitoring connections and encrypted API tokens."""
from alembic import op
import sqlalchemy as sa

revision = "b5h7j9l1n3q6"
down_revision = "a4g6i8k0m2p5"
branch_labels = depends_on = None
TABLE = "monitoring_integration_connections"


def upgrade():
    op.create_table(TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("api_url", sa.String(2048), nullable=False),
        sa.Column("group_ids", sa.JSON(), nullable=False),
        sa.Column("encrypted_token", sa.LargeBinary(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_test_status", sa.String(32)),
        sa.Column("last_test_error", sa.String(64)),
        sa.Column("last_test_at", sa.DateTime(timezone=True)),
        sa.Column("last_test_revision", sa.Integer()),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "name", name="uq_monitoring_integration_name"),
        sa.CheckConstraint("revision > 0", name="ck_monitoring_integration_revision"),
        sa.CheckConstraint("provider = 'zabbix'", name="ck_monitoring_integration_provider"),
    )
    for column in ("tenant_id", "region_id"):
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))


def downgrade():
    if op.get_bind().execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot discard integration connections or credential custody")
    op.drop_table(TABLE)
