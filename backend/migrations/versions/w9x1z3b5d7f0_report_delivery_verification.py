"""bind report receipts to workflow verification and repair late namespaces

Revision ID: w9x1z3b5d7f0
Revises: v8w0y2a4c6e9
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "w9x1z3b5d7f0"
down_revision: str | None = "v8w0y2a4c6e9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LATE_TABLES = (
    ("investigation_visualization_proposals", "investigations", "investigation_id"),
    ("investigation_visualization_proposal_evidence", "investigation_visualization_proposals", "proposal_id"),
    ("report_delivery_receipts", "investigations", "investigation_id"),
)


def upgrade() -> None:
    for table, parent, reference in LATE_TABLES:
        for column, default in (
            ("tenant_id", "00000000-0000-0000-0000-000000000001"),
            ("region_id", "00000000-0000-0000-0000-000000000002"),
        ):
            op.add_column(table, sa.Column(
                column, sa.String(36), nullable=False, server_default=default,
            ))
            op.create_index(f"ix_{table}_{column}", table, [column])
            op.execute(sa.text(
                f'UPDATE "{table}" SET "{column}" = '
                f'(SELECT "{column}" FROM "{parent}" '
                f'WHERE "{parent}".id = "{table}"."{reference}")'
            ))
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
            op.execute(sa.text(
                f'CREATE POLICY icheck_namespace_isolation ON "{table}" '
                "USING (tenant_id = current_setting('icheck.tenant_id', true) "
                "AND region_id = current_setting('icheck.region_id', true)) "
                "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
                "AND region_id = current_setting('icheck.region_id', true))"
            ))
    with op.batch_alter_table("report_delivery_receipts") as batch:
        batch.add_column(sa.Column("verification_tool_call_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_foreign_key(
            "fk_report_delivery_receipt_verification_call", "investigation_tool_calls",
            ["verification_tool_call_id"], ["id"], ondelete="RESTRICT",
        )
        batch.create_index("ix_report_delivery_receipts_verification_tool_call_id", ["verification_tool_call_id"])
        batch.create_check_constraint(
            "ck_report_delivery_receipt_verification_complete",
            "(verification_tool_call_id IS NULL AND verified_at IS NULL) OR "
            "(verification_tool_call_id IS NOT NULL AND verified_at IS NOT NULL)",
        )


def downgrade() -> None:
    with op.batch_alter_table("report_delivery_receipts") as batch:
        batch.drop_constraint("ck_report_delivery_receipt_verification_complete", type_="check")
        batch.drop_index("ix_report_delivery_receipts_verification_tool_call_id")
        batch.drop_constraint("fk_report_delivery_receipt_verification_call", type_="foreignkey")
        batch.drop_column("verified_at")
        batch.drop_column("verification_tool_call_id")
    for table, _parent, _reference in reversed(LATE_TABLES):
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(f'DROP POLICY icheck_namespace_isolation ON "{table}"'))
            op.execute(sa.text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))
        for column in ("region_id", "tenant_id"):
            op.drop_index(f"ix_{table}_{column}", table_name=table)
            op.drop_column(table, column)
