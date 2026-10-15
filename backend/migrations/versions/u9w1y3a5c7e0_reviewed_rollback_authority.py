"""Distinct immutable rollback grants, revocations and one-slot parent receipts."""
from alembic import op
import sqlalchemy as sa

revision = "u9w1y3a5c7e0"
down_revision = "t8v0x2z4b6d9"
branch_labels = depends_on = None

GRANTS = "change_rollback_execution_grants"
REVOCATIONS = "change_rollback_grant_revocations"
AUTHORIZATIONS = "change_rollback_authorizations"


def namespace():
    return [sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("region_id", sa.String(36), nullable=False)]


def foreign(name, target):
    return sa.Column(name, sa.String(36), sa.ForeignKey(target, ondelete="RESTRICT"), nullable=False)


def upgrade():
    op.create_table(GRANTS, *namespace(), foreign("primary_grant_id", "change_preapproval_execution_grants.id"),
        sa.Column("settings_snapshot", sa.JSON(), nullable=False), sa.Column("dependency_snapshot", sa.JSON(), nullable=False),
        sa.Column("qualification_manifest", sa.JSON(), nullable=False), sa.Column("qualification_sha256", sa.String(64), nullable=False),
        sa.Column("acceptance_reference", sa.String(1024), nullable=False),
        foreign("granted_by_principal_id", "control_plane_principals.id"), sa.Column("granted_by", sa.String(255), nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "primary_grant_id", name="uq_rollback_execution_primary_grant"),
        sa.CheckConstraint("expires_at > granted_at", name="ck_rollback_execution_grant_expiry"))
    op.create_table(REVOCATIONS, *namespace(), foreign("grant_id", GRANTS + ".id"),
        sa.Column("revoked_by", sa.String(255), nullable=False), foreign("revoked_by_principal_id", "control_plane_principals.id"),
        sa.Column("reason", sa.String(512), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "grant_id", name="uq_rollback_grant_revocation"))
    op.create_table(AUTHORIZATIONS, *namespace(), foreign("grant_id", GRANTS + ".id"),
        foreign("primary_authorization_id", "change_preapproval_authorizations.id"),
        foreign("parent_change_plan_id", "governed_change_plans.id"), foreign("rollback_proposal_id", "agent_action_proposals.id"),
        sa.Column("action_plan_hash", sa.String(64), nullable=False), sa.Column("failure_snapshot", sa.JSON(), nullable=False),
        sa.Column("evidence_manifest", sa.JSON(), nullable=False), sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "parent_change_plan_id", name="uq_rollback_authorization_parent"),
        sa.UniqueConstraint("tenant_id", "region_id", "rollback_proposal_id", name="uq_rollback_authorization_proposal"))
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(sa.text("CREATE FUNCTION icheck_reject_rollback_authority_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Rollback authority history is immutable'; END; $$"))
    for table, fields in ((GRANTS, ("primary_grant_id",)), (REVOCATIONS, ("grant_id",)),
        (AUTHORIZATIONS, ("grant_id", "parent_change_plan_id", "rollback_proposal_id"))):
        for field in ("tenant_id", "region_id", *fields):
            op.create_index(f"ix_{table}_{field}", table, [field])
        if dialect == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true)) WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true))"))
            op.execute(sa.text(f"CREATE TRIGGER icheck_immutable_rollback_authority BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_reject_rollback_authority_mutation()"))
        elif dialect == "sqlite":
            for operation in ("UPDATE", "DELETE"):
                op.execute(sa.text(f"CREATE TRIGGER icheck_immutable_{table}_{operation.lower()} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT, 'Rollback authority history is immutable'); END"))


def downgrade():
    bind = op.get_bind()
    for table in (AUTHORIZATIONS, REVOCATIONS, GRANTS):
        if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
            raise RuntimeError("Rollback authority downgrade requires visibility of all namespaces")
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Cannot downgrade rollback authority history")
    for table in (AUTHORIZATIONS, REVOCATIONS, GRANTS):
        op.drop_table(table)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_reject_rollback_authority_mutation()"))
