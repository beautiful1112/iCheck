"""governed change plans and evidence gates

Revision ID: f6a1c7d9e304
Revises: f5d9a3c1b628
Create Date: 2026-09-29 09:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "f6a1c7d9e304"
down_revision: str | None = "f5d9a3c1b628"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "agent_tool_registrations",
        sa.Column("change_contract", sa.JSON(), nullable=True),
    )
    op.create_table(
        "governed_change_plans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("action_proposal_id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("contract_version", sa.String(length=64), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("risk_class", sa.String(length=16), nullable=False),
        sa.Column("tool_contract_snapshot", sa.JSON(), nullable=False),
        sa.Column("target_snapshot", sa.JSON(), nullable=False),
        sa.Column("authorization_scope_snapshot", sa.JSON(), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "maintenance_window_start",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "maintenance_window_end",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("approved_plan_hash", sa.String(length=64), nullable=True),
        sa.Column("policy_evaluation", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "revision > 0",
            name="ck_governed_change_plan_revision",
        ),
        sa.CheckConstraint(
            "risk_class IN ('low', 'medium', 'high', 'critical')",
            name="ck_governed_change_plan_risk_class",
        ),
        sa.CheckConstraint(
            "status IN ('awaiting_evidence', 'ready_for_approval', 'approved', "
            "'rejected', 'executing', 'awaiting_postcheck', 'verified', "
            "'rollback_required', 'rolled_back', 'rollback_failed')",
            name="ck_governed_change_plan_status",
        ),
        sa.CheckConstraint(
            "maintenance_window_end IS NULL OR maintenance_window_start IS NOT NULL",
            name="ck_governed_change_plan_window_start",
        ),
        sa.CheckConstraint(
            "maintenance_window_end IS NULL OR "
            "maintenance_window_end > maintenance_window_start",
            name="ck_governed_change_plan_window_order",
        ),
        sa.ForeignKeyConstraint(
            ["action_proposal_id"],
            ["agent_action_proposals.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_governed_change_plan_queue",
        "governed_change_plans",
        ["status", "maintenance_window_start"],
    )
    for column in (
        "investigation_id",
        "status",
        "risk_class",
        "maintenance_window_start",
        "maintenance_window_end",
        "plan_hash",
    ):
        op.create_index(
            f"ix_governed_change_plans_{column}",
            "governed_change_plans",
            [column],
        )
    op.create_index(
        "ix_governed_change_plans_action_proposal_id",
        "governed_change_plans",
        ["action_proposal_id"],
        unique=True,
    )

    op.create_table(
        "governed_change_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("change_plan_id", sa.String(length=36), nullable=False),
        sa.Column("stage", sa.String(length=16), nullable=False),
        sa.Column("tool_call_id", sa.String(length=36), nullable=False),
        sa.Column("tool_id", sa.String(length=36), nullable=False),
        sa.Column("arguments_hash", sa.String(length=64), nullable=False),
        sa.Column("result_hash", sa.String(length=64), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("evidence_snapshot", sa.JSON(), nullable=False),
        sa.Column("recorded_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "stage IN ('precheck', 'dry_run', 'postcheck', 'rollback')",
            name="ck_governed_change_evidence_stage",
        ),
        sa.ForeignKeyConstraint(
            ["change_plan_id"],
            ["governed_change_plans.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tool_call_id"],
            ["investigation_tool_calls.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tool_id"],
            ["agent_tool_registrations.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("change_plan_id", "stage", "tool_id"):
        op.create_index(
            f"ix_governed_change_evidence_{column}",
            "governed_change_evidence",
            [column],
        )
    op.create_index(
        "ix_governed_change_evidence_tool_call_id",
        "governed_change_evidence",
        ["tool_call_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("governed_change_evidence")
    op.drop_table("governed_change_plans")
    op.drop_column("agent_tool_registrations", "change_contract")
