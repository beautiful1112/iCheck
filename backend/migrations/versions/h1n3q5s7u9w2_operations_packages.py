"""Local portable-operation installation receipts; no execution authority."""
from alembic import op
import sqlalchemy as sa

revision = "h1n3q5s7u9w2"
down_revision = "g0m2p4r6t8v1"
branch_labels = depends_on = None
TABLE = "operations_package_installations"


def upgrade():
    op.create_table(TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("digest_sha256", sa.String(64), nullable=False),
        sa.Column("package", sa.JSON(), nullable=False),
        sa.Column("bindings", sa.JSON(), nullable=False),
        sa.Column("artifact_version_ids", sa.JSON(), nullable=False),
        sa.Column("installed_by", sa.String(255), nullable=False),
        sa.Column("installed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "name", "version", name="uq_operations_package_version"))
    for field in ("tenant_id", "region_id"):
        op.create_index(f"ix_{TABLE}_{field}", TABLE, [field])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))


def downgrade():
    if op.get_bind().execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot discard portable package receipts")
    op.drop_table(TABLE)
