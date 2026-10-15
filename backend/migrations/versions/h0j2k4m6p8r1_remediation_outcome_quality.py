"""Explicit outcome quality and causally phase-bound verification calls."""
from alembic import op
import sqlalchemy as sa

revision = "h0j2k4m6p8r1"
down_revision = "g9h1j3l5n7q0"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("capability_quality_policies") as batch:
        batch.add_column(sa.Column("evidence_mode", sa.String(32), nullable=False, server_default="execution_health"))
        batch.create_check_constraint("ck_quality_policy_mode", "evidence_mode IN ('execution_health', 'remediation_outcome')")
    with op.batch_alter_table("capability_quality_assessments") as batch:
        batch.add_column(sa.Column("evidence_scope", sa.String(64), nullable=False, server_default="execution_health_not_correctness"))
        batch.create_check_constraint("ck_quality_assessment_scope", "evidence_scope IN ('execution_health_not_correctness', 'remediation_outcome_not_authority')")
    with op.batch_alter_table("investigation_tool_calls") as batch:
        batch.add_column(sa.Column("governed_change_plan_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("governed_stage", sa.String(16), nullable=True))
        batch.create_foreign_key("fk_tool_call_governed_plan", "governed_change_plans", ["governed_change_plan_id"], ["id"], ondelete="RESTRICT")
        batch.create_check_constraint("ck_tool_call_governed_stage", "(governed_change_plan_id IS NULL AND governed_stage IS NULL) OR (governed_change_plan_id IS NOT NULL AND governed_stage IS NOT NULL AND governed_stage IN ('precheck', 'dry_run', 'postcheck'))")
        batch.create_unique_constraint("uq_tool_call_governed_stage", ["governed_change_plan_id", "governed_stage"])
        batch.create_index("ix_investigation_tool_calls_governed_change_plan_id", ["governed_change_plan_id"])


def downgrade():
    bind = op.get_bind()
    tables = ("capability_quality_policies", "capability_quality_assessments", "investigation_tool_calls")
    if bind.dialect.name == "postgresql":
        for table in tables:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Outcome quality downgrade requires visibility of all namespaces")
    if bind.execute(sa.text("SELECT 1 FROM capability_quality_policies WHERE evidence_mode <> 'execution_health' LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade remediation outcome policy history")
    if bind.execute(sa.text("SELECT 1 FROM investigation_tool_calls WHERE governed_change_plan_id IS NOT NULL LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade phase-bound change execution history")
    assessments = sa.table("capability_quality_assessments", sa.column("policy_snapshot", sa.JSON()), sa.column("evidence_scope", sa.String()))
    if bind.execute(sa.select(sa.literal(1)).select_from(assessments).where(sa.or_(
        assessments.c.evidence_scope != "execution_health_not_correctness",
        assessments.c.policy_snapshot["evidence_mode"].as_string().is_not(None),
    )).limit(1)).first():
        raise RuntimeError("Cannot downgrade mode-bound assessment history")
    with op.batch_alter_table("investigation_tool_calls") as batch:
        batch.drop_index("ix_investigation_tool_calls_governed_change_plan_id")
        batch.drop_constraint("uq_tool_call_governed_stage", type_="unique")
        batch.drop_constraint("ck_tool_call_governed_stage", type_="check")
        batch.drop_constraint("fk_tool_call_governed_plan", type_="foreignkey")
        batch.drop_column("governed_stage")
        batch.drop_column("governed_change_plan_id")
    with op.batch_alter_table("capability_quality_assessments") as batch:
        batch.drop_constraint("ck_quality_assessment_scope", type_="check")
        batch.drop_column("evidence_scope")
    with op.batch_alter_table("capability_quality_policies") as batch:
        batch.drop_constraint("ck_quality_policy_mode", type_="check")
        batch.drop_column("evidence_mode")
