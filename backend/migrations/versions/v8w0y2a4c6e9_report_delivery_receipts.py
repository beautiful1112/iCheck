"""persist exact report delivery contracts and receipts

Revision ID: v8w0y2a4c6e9
Revises: u7v9x1z3b5d8
Create Date: 2026-10-01 01:15:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "v8w0y2a4c6e9"
down_revision: str | None = "u7v9x1z3b5d8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("workflow_schedule_activations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "report_delivery_tool_name",
                sa.String(length=255),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "report_delivery_tool_argument",
                sa.String(length=128),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "report_delivery_provider_key",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "report_delivery_receipt_mapping",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
        batch_op.create_check_constraint(
            "ck_workflow_schedule_delivery_receipt_complete",
            "(report_delivery_tool_name IS NULL "
            "AND report_delivery_tool_argument IS NULL "
            "AND report_delivery_provider_key IS NULL) OR "
            "(report_delivery_tool_name IS NOT NULL "
            "AND report_delivery_tool_argument IS NOT NULL "
            "AND report_delivery_provider_key IS NOT NULL)",
        )
        batch_op.create_index(
            "ix_workflow_schedule_activations_report_delivery_provider_key",
            ["report_delivery_provider_key"],
        )

    op.create_table(
        "report_delivery_receipts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("schedule_event_id", sa.String(length=36), nullable=False),
        sa.Column("activation_id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column(
            "workflow_artifact_version_id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column("workflow_content_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "report_artifact_version_id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column("report_content_hash", sa.String(length=64), nullable=False),
        sa.Column("provider_key", sa.String(length=64), nullable=False),
        sa.Column("delivery_tool_name", sa.String(length=255), nullable=False),
        sa.Column("delivery_id", sa.String(length=255), nullable=False),
        sa.Column("delivery_url", sa.String(length=2048), nullable=True),
        sa.Column("delivery_status", sa.String(length=128), nullable=True),
        sa.Column("source_tool_call_id", sa.String(length=36), nullable=False),
        sa.Column(
            "delivered_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["schedule_event_id"],
            ["workflow_schedule_events.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["activation_id"],
            ["workflow_schedule_activations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["report_artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["source_tool_call_id"],
            ["investigation_tool_calls.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "schedule_event_id",
            name="uq_report_delivery_receipt_schedule_event",
        ),
        sa.UniqueConstraint(
            "activation_id",
            "provider_key",
            "delivery_id",
            name="uq_report_delivery_receipt_provider_id",
        ),
        sa.UniqueConstraint(
            "source_tool_call_id",
            name="uq_report_delivery_receipt_tool_call",
        ),
    )
    for column in (
        "schedule_event_id",
        "activation_id",
        "investigation_id",
        "workflow_artifact_version_id",
        "report_artifact_version_id",
        "provider_key",
        "delivery_tool_name",
        "delivery_id",
        "delivery_status",
        "source_tool_call_id",
        "delivered_at",
        "created_at",
    ):
        op.create_index(
            f"ix_report_delivery_receipts_{column}",
            "report_delivery_receipts",
            [column],
        )


def downgrade() -> None:
    op.drop_table("report_delivery_receipts")
    with op.batch_alter_table("workflow_schedule_activations") as batch_op:
        batch_op.drop_index(
            "ix_workflow_schedule_activations_report_delivery_provider_key"
        )
        batch_op.drop_constraint(
            "ck_workflow_schedule_delivery_receipt_complete",
            type_="check",
        )
        batch_op.drop_column("report_delivery_receipt_mapping")
        batch_op.drop_column("report_delivery_provider_key")
        batch_op.drop_column("report_delivery_tool_argument")
        batch_op.drop_column("report_delivery_tool_name")
