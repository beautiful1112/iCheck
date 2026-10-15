"""Immutable reviewed execution grants and per-action authorization receipts."""
from alembic import op
import sqlalchemy as sa

revision = "s7u9w1y3a5c8"
down_revision = "r6t8v0x2z4b7"
branch_labels = depends_on = None

GRANTS = "change_preapproval_execution_grants"
AUTHORIZATIONS = "change_preapproval_authorizations"


def namespace_columns():
    return [sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("region_id", sa.String(36), nullable=False)]


def foreign(name, target):
    return sa.Column(name, sa.String(36), sa.ForeignKey(target, ondelete="RESTRICT"), nullable=False)


def upgrade():
    op.create_table(GRANTS, *namespace_columns(),
        foreign("policy_id", "change_preapproval_policies.id"),
        sa.Column("policy_review_sha256", sa.String(64), nullable=False),
        foreign("quality_policy_id", "capability_quality_policies.id"),
        sa.Column("quality_policy_sha256", sa.String(64), nullable=False),
        foreign("qualification_assessment_id", "capability_quality_assessments.id"),
        sa.Column("qualification_assessment_sha256", sa.String(64), nullable=False),
        sa.Column("acceptance_reference", sa.String(1024), nullable=False),
        foreign("granted_by_principal_id", "control_plane_principals.id"),
        sa.Column("granted_by", sa.String(255), nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "policy_id", "policy_review_sha256", name="uq_preapproval_execution_grant_review"),
        sa.CheckConstraint("expires_at > granted_at", name="ck_preapproval_execution_grant_expiry"))
    op.create_table(AUTHORIZATIONS, *namespace_columns(),
        foreign("grant_id", GRANTS + ".id"),
        foreign("budget_claim_id", "change_preapproval_budget_claims.id"),
        foreign("action_proposal_id", "agent_action_proposals.id"),
        sa.Column("action_plan_hash", sa.String(64), nullable=False),
        sa.Column("change_plan_hash", sa.String(64), nullable=False),
        foreign("assessment_id", "capability_quality_assessments.id"),
        sa.Column("assessment_sha256", sa.String(64), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "action_proposal_id", name="uq_preapproval_authorization_proposal"),
        sa.UniqueConstraint("tenant_id", "region_id", "budget_claim_id", name="uq_preapproval_authorization_claim"))
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(sa.text("CREATE FUNCTION icheck_reject_preapproval_authority_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Preapproval authority history is immutable'; END; $$"))
    for table, fields in ((GRANTS, ("policy_id", "quality_policy_id")), (AUTHORIZATIONS, ("grant_id", "action_proposal_id"))):
        for field in ("tenant_id", "region_id", *fields):
            op.create_index(f"ix_{table}_{field}", table, [field])
        if dialect == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true)) WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true))"))
            op.execute(sa.text(f"CREATE TRIGGER icheck_immutable_preapproval_authority BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_reject_preapproval_authority_mutation()"))
        elif dialect == "sqlite":
            for operation in ("UPDATE", "DELETE"):
                op.execute(sa.text(f"CREATE TRIGGER icheck_immutable_{table}_{operation.lower()} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT, 'Preapproval authority history is immutable'); END"))


def downgrade():
    bind = op.get_bind()
    for table in (AUTHORIZATIONS, GRANTS):
        if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
            raise RuntimeError("Preapproval authority downgrade requires visibility of all namespaces")
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Cannot downgrade preapproval authority history")
    op.drop_table(AUTHORIZATIONS)
    op.drop_table(GRANTS)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_reject_preapproval_authority_mutation()"))
