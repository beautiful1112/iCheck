"""Workspace search configuration, encrypted key and bounded daily admission."""
from alembic import op
import sqlalchemy as sa

revision = "y2e4g6i8k0m3"
down_revision = "x1d3f5h7j9l2"
branch_labels = depends_on = None
TABLE = "research_settings"


def upgrade():
    op.create_table(TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("searxng_url", sa.String(2048)),
        sa.Column("encrypted_secret", sa.LargeBinary()),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("daily_limit", sa.Integer(), nullable=False),
        sa.Column("quota_day", sa.String(10), nullable=False),
        sa.Column("calls_today", sa.Integer(), nullable=False),
        sa.Column("last_test_status", sa.String(32)),
        sa.Column("last_test_at", sa.DateTime(timezone=True)),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", name="uq_research_namespace"),
        sa.CheckConstraint("provider IN ('brave', 'searxng')", name="ck_research_provider"),
        sa.CheckConstraint("revision > 0", name="ck_research_revision"),
        sa.CheckConstraint("daily_limit BETWEEN 1 AND 10000 AND calls_today >= 0", name="ck_research_limit"))
    for column in ("tenant_id", "region_id"):
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))


def downgrade():
    if op.get_bind().execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot discard saved research configuration or credential custody")
    op.drop_table(TABLE)
