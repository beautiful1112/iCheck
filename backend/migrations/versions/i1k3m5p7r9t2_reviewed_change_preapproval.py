"""Exact-scope, reviewed change preapproval envelopes (preview only)."""
from alembic import op
import sqlalchemy as sa

revision = "i1k3m5p7r9t2"
down_revision = "h0j2k4m6p8r1"
branch_labels = None
depends_on = None


def upgrade():
    table = "change_preapproval_policies"
    op.create_table(table,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("tool_artifact_version_id", sa.String(36), sa.ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("tool_content_hash", sa.String(64), nullable=False),
        sa.Column("target_device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("target_site", sa.String(128), nullable=False),
        sa.Column("alert_event_type", sa.String(128), nullable=False),
        sa.Column("arguments_template", sa.JSON(), nullable=False),
        sa.Column("max_alert_age_seconds", sa.Integer(), nullable=False),
        sa.Column("max_actions_per_alert", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_by_principal_id", sa.String(36), sa.ForeignKey("control_plane_principals.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("reviewed_by_principal_id", sa.String(36), sa.ForeignKey("control_plane_principals.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_sha256", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "name", name="uq_change_preapproval_namespace_name"),
        sa.CheckConstraint("status IN ('draft', 'reviewed', 'revoked')", name="ck_change_preapproval_status"),
        sa.CheckConstraint("revision > 0", name="ck_change_preapproval_revision"),
        sa.CheckConstraint("max_alert_age_seconds BETWEEN 60 AND 3600", name="ck_change_preapproval_alert_age"),
        sa.CheckConstraint("max_actions_per_alert BETWEEN 1 AND 3", name="ck_change_preapproval_action_limit"),
    )
    for field in ("tenant_id", "region_id", "tool_artifact_version_id", "target_device_id"):
        op.create_index(f"ix_{table}_{field}", table, [field])
    op.create_index("ix_change_preapproval_lookup", table, ["tenant_id", "region_id", "tool_artifact_version_id", "status"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} "
            "USING (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true)) "
            "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true))"))


def downgrade():
    bind = op.get_bind()
    table = "change_preapproval_policies"
    if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
        raise RuntimeError("Preapproval policy downgrade requires visibility of all namespaces")
    if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade reviewed change preapproval policy history")
    op.drop_table(table)
