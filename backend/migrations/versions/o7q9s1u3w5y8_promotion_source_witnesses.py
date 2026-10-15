"""Target-local source checkpoint pins, witness policy and sealed admission evidence."""
from alembic import op
import sqlalchemy as sa

revision = "o7q9s1u3w5y8"
down_revision = "n6p8r0t2v4x7"
branch_labels = depends_on = None
POLICY = "capability_promotion_source_witness_policy"
BINDINGS = "capability_promotion_source_checkpoint_bindings"
DECISIONS = "capability_promotion_source_witness_decisions"
TABLES = (POLICY, BINDINGS, DECISIONS)


def _namespace():
    return [sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002")]


def upgrade():
    op.create_table(POLICY, sa.Column("id", sa.String(36), primary_key=True), *_namespace(),
        sa.Column("required_quorum", sa.Integer(), nullable=False), sa.Column("witness_ids", sa.JSON(), nullable=False),
        sa.Column("max_attestation_age_hours", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", name="uq_promotion_source_witness_policy_namespace"),
        sa.CheckConstraint("required_quorum BETWEEN 0 AND 16", name="ck_promotion_source_witness_quorum"),
        sa.CheckConstraint("max_attestation_age_hours BETWEEN 1 AND 720", name="ck_promotion_source_witness_age"))
    op.create_table(BINDINGS, *_namespace(),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("capability_promotion_sources.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("log_id", sa.String(36), nullable=False), sa.Column("epoch", sa.Integer(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False), sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("epoch > 0", name="ck_promotion_source_checkpoint_epoch"))
    op.create_table(DECISIONS, sa.Column("id", sa.String(36), primary_key=True), *_namespace(),
        sa.Column("receipt_id", sa.String(36), sa.ForeignKey("capability_promotion_receipts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("checkpoint_statement_digest_sha256", sa.String(64), nullable=False),
        sa.Column("evidence_digest_sha256", sa.String(64), nullable=False),
        sa.Column("policy_snapshot", sa.JSON(), nullable=False), sa.Column("witness_evidence", sa.JSON(), nullable=False),
        sa.Column("accepted_by", sa.String(255), nullable=False), sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("receipt_id", name="uq_promotion_source_witness_decision_receipt"))
    for table in TABLES:
        for field in ("tenant_id", "region_id"):
            op.create_index(f"ix_{table}_{field}", table, [field])
    op.create_index(f"ix_{DECISIONS}_receipt_id", DECISIONS, ["receipt_id"])
    if op.get_bind().dialect.name == "postgresql":
        for table in TABLES:
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} "
                "USING (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true)) "
                "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true))"))
        op.execute(sa.text("CREATE FUNCTION icheck_guard_promotion_source_witness_decision() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'Promotion source witness decisions are immutable'; END; $$"))
        op.execute(sa.text(f"CREATE TRIGGER icheck_immutable_promotion_source_witness_decision BEFORE UPDATE OR DELETE ON {DECISIONS} "
            "FOR EACH ROW EXECUTE FUNCTION icheck_guard_promotion_source_witness_decision()"))
    elif op.get_bind().dialect.name == "sqlite":
        for operation in ("UPDATE", "DELETE"):
            op.execute(sa.text(f"CREATE TRIGGER icheck_promotion_source_witness_{operation.lower()} BEFORE {operation} ON {DECISIONS} "
                "BEGIN SELECT RAISE(ABORT, 'Promotion source witness decisions are immutable'); END"))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        if any(bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar() for table in TABLES):
            raise RuntimeError("Promotion witness downgrade requires visibility of all namespaces")
        bind.execute(sa.text("LOCK TABLE " + ", ".join(sorted(TABLES)) + " IN ACCESS EXCLUSIVE MODE"))
    if any(bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first() for table in TABLES):
        raise RuntimeError("Cannot downgrade recorded promotion witness policy, binding or decision evidence")
    for table in reversed(TABLES):
        op.drop_table(table)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_promotion_source_witness_decision()"))
