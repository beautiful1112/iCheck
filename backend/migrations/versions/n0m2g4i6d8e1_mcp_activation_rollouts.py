"""add MCP canary rollout and circuit-breaker state

Revision ID: n0m2g4i6d8e1
Revises: m9l1f3h5c7d0
Create Date: 2026-09-30 16:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "n0m2g4i6d8e1"
down_revision: str | None = "m9l1f3h5c7d0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("mcp_tool_activations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "rollout_state",
                sa.String(length=16),
                nullable=False,
                server_default="full",
            )
        )
        batch_op.add_column(
            sa.Column(
                "traffic_percent",
                sa.Integer(),
                nullable=False,
                server_default="100",
            )
        )
        batch_op.add_column(
            sa.Column(
                "minimum_successful_calls",
                sa.Integer(),
                nullable=False,
                server_default="3",
            )
        )
        batch_op.add_column(
            sa.Column(
                "maximum_failed_calls",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )
        batch_op.add_column(
            sa.Column(
                "circuit_failure_threshold",
                sa.Integer(),
                nullable=False,
                server_default="3",
            )
        )
        batch_op.add_column(
            sa.Column(
                "successful_calls",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.add_column(
            sa.Column(
                "failed_calls",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.add_column(
            sa.Column(
                "consecutive_failures",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.add_column(
            sa.Column(
                "circuit_state",
                sa.String(length=16),
                nullable=False,
                server_default="closed",
            )
        )
        batch_op.add_column(
            sa.Column("last_call_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("last_failure_sha256", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(
            sa.Column("circuit_opened_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("promoted_by", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column("promotion_reason", sa.Text(), nullable=True)
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
            "ck_mcp_tool_activation_rollout_state",
            "rollout_state IN ('canary', 'full', 'blocked')",
        )
        batch_op.create_check_constraint(
            "ck_mcp_tool_activation_circuit_state",
            "circuit_state IN ('closed', 'open')",
        )
        batch_op.create_check_constraint(
            "ck_mcp_tool_activation_traffic_percent",
            "traffic_percent > 0 AND traffic_percent <= 100",
        )
        batch_op.create_check_constraint(
            "ck_mcp_tool_activation_health_thresholds",
            "minimum_successful_calls > 0 AND maximum_failed_calls >= 0 "
            "AND circuit_failure_threshold > 0",
        )
        batch_op.create_check_constraint(
            "ck_mcp_tool_activation_health_counters",
            "successful_calls >= 0 AND failed_calls >= 0 "
            "AND consecutive_failures >= 0 AND revision > 0",
        )
        batch_op.create_index(
            "ix_mcp_tool_activations_rollout_state",
            ["rollout_state"],
        )
        batch_op.create_index(
            "ix_mcp_tool_activations_circuit_state",
            ["circuit_state"],
        )


def downgrade() -> None:
    with op.batch_alter_table("mcp_tool_activations") as batch_op:
        batch_op.drop_index("ix_mcp_tool_activations_circuit_state")
        batch_op.drop_index("ix_mcp_tool_activations_rollout_state")
        batch_op.drop_constraint(
            "ck_mcp_tool_activation_health_counters",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_mcp_tool_activation_health_thresholds",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_mcp_tool_activation_traffic_percent",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_mcp_tool_activation_circuit_state",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_mcp_tool_activation_rollout_state",
            type_="check",
        )
        for column in (
            "revision",
            "promotion_reason",
            "promoted_by",
            "promoted_at",
            "circuit_opened_at",
            "last_failure_sha256",
            "last_failure_at",
            "last_success_at",
            "last_call_at",
            "circuit_state",
            "consecutive_failures",
            "failed_calls",
            "successful_calls",
            "circuit_failure_threshold",
            "maximum_failed_calls",
            "minimum_successful_calls",
            "traffic_percent",
            "rollout_state",
        ):
            batch_op.drop_column(column)
