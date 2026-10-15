"""bind exact service report versions to workflow schedules

Revision ID: u7v9x1z3b5d8
Revises: t6u8w0y2a4c7
Create Date: 2026-10-01 00:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "u7v9x1z3b5d8"
down_revision: str | None = "t6u8w0y2a4c7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("workflow_schedule_activations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "report_artifact_version_id",
                sa.String(length=36),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column("report_input_key", sa.String(length=128), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_workflow_schedule_report_artifact_version_id",
            "artifact_versions",
            ["report_artifact_version_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_check_constraint(
            "ck_workflow_schedule_report_binding_complete",
            "(report_artifact_version_id IS NULL AND report_input_key IS NULL) OR "
            "(report_artifact_version_id IS NOT NULL AND report_input_key IS NOT NULL)",
        )
        batch_op.create_index(
            "ix_workflow_schedule_activations_report_artifact_version_id",
            ["report_artifact_version_id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("workflow_schedule_activations") as batch_op:
        batch_op.drop_index(
            "ix_workflow_schedule_activations_report_artifact_version_id"
        )
        batch_op.drop_constraint(
            "ck_workflow_schedule_report_binding_complete",
            type_="check",
        )
        batch_op.drop_constraint(
            "fk_workflow_schedule_report_artifact_version_id",
            type_="foreignkey",
        )
        batch_op.drop_column("report_input_key")
        batch_op.drop_column("report_artifact_version_id")
