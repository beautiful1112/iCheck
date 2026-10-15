"""Durable per-Alert preapproval budget claims (no execution authority)."""
from alembic import op
import sqlalchemy as sa

revision = "j2l4n6p8r0t3"
down_revision = "i1k3m5p7r9t2"
branch_labels = None
depends_on = None


def upgrade():
    table = "change_preapproval_budget_claims"
    op.create_table(table,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("policy_id", sa.String(36), sa.ForeignKey("change_preapproval_policies.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("change_plan_id", sa.String(36), sa.ForeignKey("governed_change_plans.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("policy_review_sha256", sa.String(64), nullable=False),
        sa.Column("plan_hash", sa.String(64), nullable=False),
        sa.Column("policy_limit_snapshot", sa.Integer(), nullable=False),
        sa.Column("claimed_by", sa.String(255), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "change_plan_id", name="uq_change_preapproval_budget_plan"),
        sa.CheckConstraint("policy_limit_snapshot BETWEEN 1 AND 3", name="ck_change_preapproval_budget_limit"),
    )
    for field in ("tenant_id", "region_id", "policy_id", "alert_id", "change_plan_id"):
        op.create_index(f"ix_{table}_{field}", table, [field])
    op.create_index("ix_change_preapproval_budget_alert", table, ["tenant_id", "region_id", "alert_id"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} "
            "USING (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true)) "
            "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true))"))
        op.execute(sa.text("CREATE FUNCTION icheck_reject_preapproval_budget_mutation() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Preapproval budget claims are immutable'; END; $$"))
        op.execute(sa.text(f"CREATE TRIGGER icheck_immutable_preapproval_budget "
            f"BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW "
            "EXECUTE FUNCTION icheck_reject_preapproval_budget_mutation()"))
    elif op.get_bind().dialect.name == "sqlite":
        for operation in ("UPDATE", "DELETE"):
            op.execute(sa.text(f"CREATE TRIGGER icheck_immutable_preapproval_budget_{operation.lower()} "
                f"BEFORE {operation} ON {table} BEGIN "
                "SELECT RAISE(ABORT, 'Preapproval budget claims are immutable'); END"))


def downgrade():
    bind = op.get_bind()
    table = "change_preapproval_budget_claims"
    if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
        raise RuntimeError("Preapproval budget downgrade requires visibility of all namespaces")
    if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade preapproval budget claim history")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER icheck_immutable_preapproval_budget ON {table}"))
    op.drop_table(table)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_reject_preapproval_budget_mutation()"))
