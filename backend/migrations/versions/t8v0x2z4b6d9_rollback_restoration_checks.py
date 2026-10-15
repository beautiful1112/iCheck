"""Phase-bound, read-only rollback restoration checks; preserve old contracts."""
from alembic import op
import sqlalchemy as sa

revision = "t8v0x2z4b6d9"
down_revision = "s7u9w1y3a5c8"
branch_labels = depends_on = None


def _constraints(include_restoration):
    stage = ", 'rollback_check'" if include_restoration else ""
    status = ", 'awaiting_rollback_check'" if include_restoration else ""
    return (
        ("investigation_tool_calls", "ck_tool_call_governed_stage",
         "(governed_change_plan_id IS NULL AND governed_stage IS NULL) OR "
         "(governed_change_plan_id IS NOT NULL AND governed_stage IS NOT NULL AND "
         f"governed_stage IN ('precheck', 'dry_run', 'postcheck'{stage}))"),
        ("governed_change_evidence", "ck_governed_change_evidence_stage",
         f"stage IN ('precheck', 'dry_run', 'postcheck', 'rollback'{stage})"),
        ("governed_change_plans", "ck_governed_change_plan_status",
         "status IN ('awaiting_evidence', 'ready_for_approval', 'approved', 'rejected', "
         "'executing', 'awaiting_postcheck', 'verified', 'rollback_required', "
         f"'rolled_back', 'rollback_failed'{status})"),
    )


def _replace(include_restoration):
    for table, name, condition in _constraints(include_restoration):
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(name, type_="check")
            batch.create_check_constraint(name, condition)


def upgrade():
    _replace(True)


def downgrade():
    bind = op.get_bind()
    tables = ("agent_tool_registrations", "artifact_versions", "governed_change_plans",
              "governed_change_evidence", "investigation_tool_calls")
    for table in tables:
        if bind.dialect.name == "postgresql" and bind.execute(
            sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
            raise RuntimeError("Restoration downgrade requires visibility of all namespaces")
    for table, condition in (
        ("governed_change_plans", "status = 'awaiting_rollback_check'"),
        ("governed_change_evidence", "stage = 'rollback_check'"),
        ("investigation_tool_calls", "governed_stage = 'rollback_check'"),
    ):
        if bind.execute(sa.text(f"SELECT 1 FROM {table} WHERE {condition} LIMIT 1")).first():
            raise RuntimeError("Cannot downgrade rollback restoration history")
    for table, field, path in (
        ("agent_tool_registrations", "change_contract", ("rollback_check",)),
        ("artifact_versions", "definition", ("spec", "change_contract", "rollback_check")),
        ("governed_change_plans", "tool_contract_snapshot", ("steps", "rollback_check")),
    ):
        source = sa.table(table, sa.column(field, sa.JSON()))
        value = source.c[field]
        for part in path:
            value = value[part]
        if bind.execute(sa.select(sa.literal(1)).select_from(source).where(
            value.as_string().is_not(None)).limit(1)).first():
            raise RuntimeError("Cannot downgrade configured rollback restoration contracts")
    _replace(False)
