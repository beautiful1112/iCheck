"""agent profiles and model placement policy

Revision ID: b2d4f6a8c013
Revises: a1c3e5f7b902
Create Date: 2026-09-29 18:00:00.000000
"""

from collections.abc import Sequence
from datetime import UTC, datetime

from alembic import op
import sqlalchemy as sa


revision: str = "b2d4f6a8c013"
down_revision: str | None = "a1c3e5f7b902"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("ai_provider_configs") as batch_op:
        batch_op.add_column(
            sa.Column(
                "privacy_tier",
                sa.String(length=16),
                nullable=False,
                server_default="external",
            )
        )
        batch_op.add_column(
            sa.Column(
                "data_residency",
                sa.String(length=64),
                nullable=False,
                server_default="unspecified",
            )
        )
        batch_op.create_check_constraint(
            "ck_ai_provider_privacy_tier",
            "privacy_tier IN ('external', 'private', 'local')",
        )

    with op.batch_alter_table("ai_model_configs") as batch_op:
        batch_op.add_column(
            sa.Column(
                "cost_class",
                sa.String(length=16),
                nullable=False,
                server_default="standard",
            )
        )
        batch_op.create_check_constraint(
            "ck_ai_model_cost_class",
            "cost_class IN ('low', 'standard', 'premium')",
        )

    op.create_table(
        "agent_profiles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("role_instructions", sa.Text(), nullable=False),
        sa.Column("escalation_instructions", sa.Text(), nullable=False),
        sa.Column("route_purpose", sa.String(length=128), nullable=False),
        sa.Column("tool_policy", sa.String(length=32), nullable=False),
        sa.Column("allowed_tool_names", sa.JSON(), nullable=False),
        sa.Column("minimum_provider_privacy", sa.String(length=16), nullable=False),
        sa.Column("allowed_data_residencies", sa.JSON(), nullable=False),
        sa.Column("allowed_model_cost_classes", sa.JSON(), nullable=False),
        sa.Column("max_iterations", sa.Integer(), nullable=False),
        sa.Column("max_tool_calls", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("token_budget", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("update_reason", sa.String(length=4000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "tool_policy IN ('permission_scoped', 'allowlist')",
            name="ck_agent_profile_tool_policy",
        ),
        sa.CheckConstraint(
            "minimum_provider_privacy IN ('external', 'private', 'local')",
            name="ck_agent_profile_provider_privacy",
        ),
        sa.CheckConstraint("max_iterations > 0", name="ck_agent_profile_iterations"),
        sa.CheckConstraint("max_tool_calls > 0", name="ck_agent_profile_tools"),
        sa.CheckConstraint("timeout_seconds > 0", name="ck_agent_profile_timeout"),
        sa.CheckConstraint("token_budget > 0", name="ck_agent_profile_tokens"),
        sa.CheckConstraint("revision > 0", name="ck_agent_profile_revision"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_agent_profiles_name",
        "agent_profiles",
        ["name"],
        unique=True,
    )
    op.create_index(
        "ix_agent_profiles_route_purpose",
        "agent_profiles",
        ["route_purpose"],
        unique=False,
    )
    op.create_index(
        "ix_agent_profiles_enabled",
        "agent_profiles",
        ["enabled"],
        unique=False,
    )
    now = datetime.now(UTC)
    profile_table = sa.table(
        "agent_profiles",
        sa.column("id", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("role_instructions", sa.Text),
        sa.column("escalation_instructions", sa.Text),
        sa.column("route_purpose", sa.String),
        sa.column("tool_policy", sa.String),
        sa.column("allowed_tool_names", sa.JSON),
        sa.column("minimum_provider_privacy", sa.String),
        sa.column("allowed_data_residencies", sa.JSON),
        sa.column("allowed_model_cost_classes", sa.JSON),
        sa.column("max_iterations", sa.Integer),
        sa.column("max_tool_calls", sa.Integer),
        sa.column("timeout_seconds", sa.Integer),
        sa.column("token_budget", sa.Integer),
        sa.column("enabled", sa.Boolean),
        sa.column("revision", sa.Integer),
        sa.column("created_by", sa.String),
        sa.column("updated_by", sa.String),
        sa.column("update_reason", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        profile_table,
        [
            {
                "id": "20000000-0000-4000-8000-000000000001",
                "name": "l1-operator",
                "description": "Default bounded AI L1 infrastructure operator.",
                "role_instructions": (
                    "Act as the L1 infrastructure operator. Diagnose from persisted "
                    "evidence, prefer the least invasive eligible Tool, distinguish "
                    "fact from hypothesis, and never claim success without verification."
                ),
                "escalation_instructions": (
                    "Escalate when evidence is insufficient, scope or permissions are "
                    "missing, the budget is exhausted, or a safe next diagnostic step "
                    "is unavailable."
                ),
                "route_purpose": "investigation",
                "tool_policy": "permission_scoped",
                "allowed_tool_names": [],
                "minimum_provider_privacy": "external",
                "allowed_data_residencies": [],
                "allowed_model_cost_classes": ["low", "standard", "premium"],
                "max_iterations": 100,
                "max_tool_calls": 500,
                "timeout_seconds": 3600,
                "token_budget": 10_000_000,
                "enabled": True,
                "revision": 1,
                "created_by": "system.migration",
                "updated_by": "system.migration",
                "update_reason": "Built-in bounded L1 AgentProfile.",
                "created_at": now,
                "updated_at": now,
            }
        ],
    )

    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(
            sa.Column("agent_profile_id", sa.String(length=36), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "agent_profile_snapshot",
                sa.JSON(),
                nullable=False,
                server_default="{}",
            )
        )
        batch_op.create_foreign_key(
            "fk_investigation_agent_profile",
            "agent_profiles",
            ["agent_profile_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_investigations_agent_profile_id",
            ["agent_profile_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_index("ix_investigations_agent_profile_id")
        batch_op.drop_constraint(
            "fk_investigation_agent_profile",
            type_="foreignkey",
        )
        batch_op.drop_column("agent_profile_snapshot")
        batch_op.drop_column("agent_profile_id")

    op.drop_index("ix_agent_profiles_enabled", table_name="agent_profiles")
    op.drop_index("ix_agent_profiles_route_purpose", table_name="agent_profiles")
    op.drop_index("ix_agent_profiles_name", table_name="agent_profiles")
    op.drop_table("agent_profiles")

    with op.batch_alter_table("ai_model_configs") as batch_op:
        batch_op.drop_constraint("ck_ai_model_cost_class", type_="check")
        batch_op.drop_column("cost_class")

    with op.batch_alter_table("ai_provider_configs") as batch_op:
        batch_op.drop_constraint("ck_ai_provider_privacy_tier", type_="check")
        batch_op.drop_column("data_residency")
        batch_op.drop_column("privacy_tier")
