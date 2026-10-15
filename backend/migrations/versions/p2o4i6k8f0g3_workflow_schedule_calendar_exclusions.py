"""add governed workflow schedule calendar exclusions

Revision ID: p2o4i6k8f0g3
Revises: o1n3h5j7e9f2
Create Date: 2026-09-30 21:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "p2o4i6k8f0g3"
down_revision: str | None = "o1n3h5j7e9f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("workflow_schedule_activations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "exclusion_windows",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[]'"),
            )
        )
        batch_op.add_column(
            sa.Column(
                "excluded_runs",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.add_column(
            sa.Column(
                "last_excluded_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "revision",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )
        batch_op.create_check_constraint(
            "ck_workflow_schedule_exclusion_counters",
            "excluded_runs >= 0 AND revision > 0",
        )

    with op.batch_alter_table("workflow_schedule_events") as batch_op:
        batch_op.add_column(
            sa.Column("skip_reason", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "exclusion_window_id",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch_op.drop_constraint(
            "ck_workflow_schedule_event_status",
            type_="check",
        )
        batch_op.create_check_constraint(
            "ck_workflow_schedule_event_status",
            "status IN ('pending', 'processing', 'succeeded', 'failed', 'skipped')",
        )
        batch_op.create_check_constraint(
            "ck_workflow_schedule_event_skip_metadata",
            "(status = 'skipped' AND skip_reason = 'calendar_exclusion' "
            "AND exclusion_window_id IS NOT NULL) OR "
            "(status <> 'skipped' AND skip_reason IS NULL "
            "AND exclusion_window_id IS NULL)",
        )


def downgrade() -> None:
    op.execute(
        sa.text("DELETE FROM workflow_schedule_events WHERE status = 'skipped'")
    )
    with op.batch_alter_table("workflow_schedule_events") as batch_op:
        batch_op.drop_constraint(
            "ck_workflow_schedule_event_skip_metadata",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_workflow_schedule_event_status",
            type_="check",
        )
        batch_op.create_check_constraint(
            "ck_workflow_schedule_event_status",
            "status IN ('pending', 'processing', 'succeeded', 'failed')",
        )
        batch_op.drop_column("exclusion_window_id")
        batch_op.drop_column("skip_reason")

    with op.batch_alter_table("workflow_schedule_activations") as batch_op:
        batch_op.drop_constraint(
            "ck_workflow_schedule_exclusion_counters",
            type_="check",
        )
        batch_op.drop_column("revision")
        batch_op.drop_column("last_excluded_at")
        batch_op.drop_column("excluded_runs")
        batch_op.drop_column("exclusion_windows")
