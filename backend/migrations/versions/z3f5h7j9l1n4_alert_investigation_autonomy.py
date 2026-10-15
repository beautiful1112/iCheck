"""Standing read-only alert policy and durable investigation continuation."""
from alembic import op
import sqlalchemy as sa

revision = "z3f5h7j9l1n4"
down_revision = "y2e4g6i8k0m3"
branch_labels = depends_on = None


def _namespace():
    return [sa.Column("tenant_id", sa.String(36), nullable=False,
                      server_default="00000000-0000-0000-0000-000000000001"),
            sa.Column("region_id", sa.String(36), nullable=False,
                      server_default="00000000-0000-0000-0000-000000000002")]


def upgrade():
    if op.get_bind().dialect.name == "sqlite":
        # Recreating this table would temporarily break existing cross-table
        # custody triggers. SQLite supports additive nullable REFERENCES columns.
        op.add_column("investigations", sa.Column("execution_mode", sa.String(24), nullable=False, server_default="standard"))
        op.execute(sa.text("ALTER TABLE investigations ADD COLUMN parent_investigation_id VARCHAR(36) "
                           "CONSTRAINT fk_investigation_parent REFERENCES investigations(id) ON DELETE RESTRICT"))
        op.create_index("ix_investigations_parent_investigation_id", "investigations", ["parent_investigation_id"])
    else:
        with op.batch_alter_table("investigations") as batch:
            batch.add_column(sa.Column("execution_mode", sa.String(24), nullable=False, server_default="standard"))
            batch.add_column(sa.Column("parent_investigation_id", sa.String(36), nullable=True))
            batch.create_foreign_key("fk_investigation_parent", "investigations", ["parent_investigation_id"], ["id"], ondelete="RESTRICT")
            batch.create_index("ix_investigations_parent_investigation_id", ["parent_investigation_id"])
    op.create_table("alert_investigation_policies",
        sa.Column("id", sa.String(36), primary_key=True), *_namespace(),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("severities", sa.JSON(), nullable=False),
        sa.Column("daily_limit", sa.Integer(), nullable=False),
        sa.Column("max_concurrent", sa.Integer(), nullable=False),
        sa.Column("cooldown_seconds", sa.Integer(), nullable=False),
        sa.Column("max_alert_age_seconds", sa.Integer(), nullable=False),
        sa.Column("paused_until", sa.DateTime(timezone=True)),
        sa.Column("enabled_at", sa.DateTime(timezone=True)),
        sa.Column("authorized_by_principal_id", sa.String(36), sa.ForeignKey("control_plane_principals.id", ondelete="RESTRICT")),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dispatcher_seen_at", sa.DateTime(timezone=True)),
        sa.Column("dispatcher_status", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", name="uq_alert_investigation_policy_namespace"))
    op.create_table("alert_investigation_events",
        sa.Column("id", sa.String(36), primary_key=True), *_namespace(),
        sa.Column("policy_id", sa.String(36), sa.ForeignKey("alert_investigation_policies.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id", ondelete="RESTRICT")),
        sa.Column("group_key", sa.String(600), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("reason", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "alert_id", name="uq_alert_investigation_event"))
    op.create_index("ix_alert_investigation_group", "alert_investigation_events", ["tenant_id", "region_id", "group_key", "created_at"])
    op.create_index("ix_alert_investigation_run", "alert_investigation_events", ["tenant_id", "region_id", "investigation_id"])
    op.create_table("investigation_capability_requests",
        sa.Column("id", sa.String(36), primary_key=True), *_namespace(),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("suggested_tools", sa.JSON(), nullable=False),
        sa.Column("studio_session_id", sa.String(36), sa.ForeignKey("capability_studio_sessions.id", ondelete="RESTRICT")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_investigation_capability_requests_investigation_id", "investigation_capability_requests", ["investigation_id"])
    for table in ("alert_investigation_policies", "alert_investigation_events", "investigation_capability_requests"):
        for column in ("tenant_id", "region_id"):
            op.create_index(f"ix_{table}_{column}", table, [column])
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate})"))


def downgrade():
    tables = ("investigation_capability_requests", "alert_investigation_events", "alert_investigation_policies")
    for table in tables:
        if op.get_bind().execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Cannot discard automatic investigation policy or history")
    if op.get_bind().execute(sa.text("SELECT 1 FROM investigations WHERE execution_mode <> 'standard' OR parent_investigation_id IS NOT NULL LIMIT 1")).first():
        raise RuntimeError("Cannot discard diagnostic boundaries or continuation history")
    for table in tables:
        op.drop_table(table)
    if op.get_bind().dialect.name == "sqlite":
        op.drop_index("ix_investigations_parent_investigation_id", table_name="investigations")
        op.execute(sa.text("ALTER TABLE investigations DROP COLUMN parent_investigation_id"))
        op.execute(sa.text("ALTER TABLE investigations DROP COLUMN execution_mode"))
    else:
        with op.batch_alter_table("investigations") as batch:
            batch.drop_index("ix_investigations_parent_investigation_id")
            batch.drop_constraint("fk_investigation_parent", type_="foreignkey")
            batch.drop_column("parent_investigation_id")
            batch.drop_column("execution_mode")
