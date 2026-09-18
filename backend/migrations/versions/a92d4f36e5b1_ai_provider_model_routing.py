"""ai_provider_model_routing

Revision ID: a92d4f36e5b1
Revises: 5d4064870a1b
Create Date: 2026-09-18 05:20:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a92d4f36e5b1"
down_revision: Union[str, Sequence[str], None] = "5d4064870a1b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ai_provider_configs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("provider_type", sa.String(length=64), nullable=False),
        sa.Column("base_url", sa.String(length=2048), nullable=False),
        sa.Column("auth_type", sa.String(length=32), nullable=False),
        sa.Column(
            "credential_profile_ref",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column("request_timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_health_status", sa.String(length=32), nullable=True),
        sa.Column("last_health_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "request_timeout_seconds > 0",
            name="ck_ai_provider_timeout_positive",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ai_provider_configs_enabled"),
        "ai_provider_configs",
        ["enabled"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_provider_configs_name"),
        "ai_provider_configs",
        ["name"],
        unique=True,
    )
    op.create_index(
        op.f("ix_ai_provider_configs_provider_type"),
        "ai_provider_configs",
        ["provider_type"],
        unique=False,
    )

    op.create_table(
        "ai_model_configs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("provider_id", sa.String(length=36), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("model_name", sa.String(length=255), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("context_window", sa.Integer(), nullable=True),
        sa.Column("max_output_tokens", sa.Integer(), nullable=True),
        sa.Column("default_parameters", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "context_window IS NULL OR context_window > 0",
            name="ck_ai_model_context_positive",
        ),
        sa.CheckConstraint(
            "max_output_tokens IS NULL OR max_output_tokens > 0",
            name="ck_ai_model_output_positive",
        ),
        sa.ForeignKeyConstraint(
            ["provider_id"],
            ["ai_provider_configs.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provider_id",
            "model_name",
            name="uq_ai_model_provider_name",
        ),
    )
    op.create_index(
        op.f("ix_ai_model_configs_display_name"),
        "ai_model_configs",
        ["display_name"],
        unique=True,
    )
    op.create_index(
        op.f("ix_ai_model_configs_enabled"),
        "ai_model_configs",
        ["enabled"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_model_configs_model_name"),
        "ai_model_configs",
        ["model_name"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_model_configs_provider_id"),
        "ai_model_configs",
        ["provider_id"],
        unique=False,
    )

    op.create_table(
        "ai_model_routes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("purpose", sa.String(length=128), nullable=False),
        sa.Column("primary_model_id", sa.String(length=36), nullable=False),
        sa.Column("fallback_model_ids", sa.JSON(), nullable=False),
        sa.Column("max_iterations", sa.Integer(), nullable=False),
        sa.Column("max_tool_calls", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("token_budget", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "max_iterations > 0",
            name="ck_ai_route_iterations_positive",
        ),
        sa.CheckConstraint(
            "max_tool_calls > 0",
            name="ck_ai_route_tools_positive",
        ),
        sa.CheckConstraint(
            "timeout_seconds > 0",
            name="ck_ai_route_timeout_positive",
        ),
        sa.CheckConstraint(
            "token_budget > 0",
            name="ck_ai_route_tokens_positive",
        ),
        sa.ForeignKeyConstraint(
            ["primary_model_id"],
            ["ai_model_configs.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ai_model_routes_enabled"),
        "ai_model_routes",
        ["enabled"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_model_routes_primary_model_id"),
        "ai_model_routes",
        ["primary_model_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_model_routes_purpose"),
        "ai_model_routes",
        ["purpose"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_ai_model_routes_purpose"),
        table_name="ai_model_routes",
    )
    op.drop_index(
        op.f("ix_ai_model_routes_primary_model_id"),
        table_name="ai_model_routes",
    )
    op.drop_index(
        op.f("ix_ai_model_routes_enabled"),
        table_name="ai_model_routes",
    )
    op.drop_table("ai_model_routes")
    op.drop_index(
        op.f("ix_ai_model_configs_provider_id"),
        table_name="ai_model_configs",
    )
    op.drop_index(
        op.f("ix_ai_model_configs_model_name"),
        table_name="ai_model_configs",
    )
    op.drop_index(
        op.f("ix_ai_model_configs_enabled"),
        table_name="ai_model_configs",
    )
    op.drop_index(
        op.f("ix_ai_model_configs_display_name"),
        table_name="ai_model_configs",
    )
    op.drop_table("ai_model_configs")
    op.drop_index(
        op.f("ix_ai_provider_configs_provider_type"),
        table_name="ai_provider_configs",
    )
    op.drop_index(
        op.f("ix_ai_provider_configs_name"),
        table_name="ai_provider_configs",
    )
    op.drop_index(
        op.f("ix_ai_provider_configs_enabled"),
        table_name="ai_provider_configs",
    )
    op.drop_table("ai_provider_configs")
