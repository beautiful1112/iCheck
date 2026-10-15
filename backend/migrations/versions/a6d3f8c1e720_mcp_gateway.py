"""governed MCP server and tool activation records

Revision ID: a6d3f8c1e720
Revises: f4a8c1d6e290
Create Date: 2026-09-24 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a6d3f8c1e720"
down_revision: Union[str, Sequence[str], None] = "f4a8c1d6e290"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mcp_servers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("endpoint_url", sa.String(length=2048), nullable=False),
        sa.Column("protocol_version", sa.String(length=32), nullable=False),
        sa.Column("credential_profile_ref", sa.String(length=255), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_health_status", sa.String(length=32), nullable=True),
        sa.Column("last_health_error", sa.Text(), nullable=True),
        sa.Column("last_tool_count", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for column, unique in [
        ("name", True),
        ("enabled", False),
        ("last_health_status", False),
    ]:
        op.create_index(
            op.f(f"ix_mcp_servers_{column}"),
            "mcp_servers",
            [column],
            unique=unique,
        )

    op.create_table(
        "mcp_tool_activations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("server_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=False),
        sa.Column("tool_registration_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("tool_name", sa.String(length=255), nullable=False),
        sa.Column("mcp_tool_name", sa.String(length=255), nullable=False),
        sa.Column("contract_sha256", sa.String(length=64), nullable=False),
        sa.Column("input_schema_sha256", sa.String(length=64), nullable=False),
        sa.Column("output_schema_sha256", sa.String(length=64), nullable=False),
        sa.Column("activated_by", sa.String(length=255), nullable=False),
        sa.Column("activation_reason", sa.Text(), nullable=False),
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deactivated_by", sa.String(length=255), nullable=True),
        sa.Column("deactivation_reason", sa.Text(), nullable=True),
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["server_id"], ["mcp_servers.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tool_registration_id"],
            ["agent_tool_registrations.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('active', 'inactive')",
            name="ck_mcp_tool_activation_status",
        ),
        sa.UniqueConstraint(
            "artifact_version_id",
            name="uq_mcp_tool_activation_artifact_version",
        ),
    )
    for column in [
        "server_id",
        "artifact_version_id",
        "tool_registration_id",
        "status",
        "tool_name",
    ]:
        op.create_index(
            op.f(f"ix_mcp_tool_activations_{column}"),
            "mcp_tool_activations",
            [column],
            unique=False,
        )
    op.create_index(
        "uq_mcp_tool_active_name",
        "mcp_tool_activations",
        ["tool_name"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
        sqlite_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_mcp_tool_active_name",
        table_name="mcp_tool_activations",
    )
    for column in reversed(
        [
            "server_id",
            "artifact_version_id",
            "tool_registration_id",
            "status",
            "tool_name",
        ]
    ):
        op.drop_index(
            op.f(f"ix_mcp_tool_activations_{column}"),
            table_name="mcp_tool_activations",
        )
    op.drop_table("mcp_tool_activations")
    for column in reversed(["name", "enabled", "last_health_status"]):
        op.drop_index(
            op.f(f"ix_mcp_servers_{column}"),
            table_name="mcp_servers",
        )
    op.drop_table("mcp_servers")
