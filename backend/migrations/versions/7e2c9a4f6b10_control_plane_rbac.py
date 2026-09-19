"""control_plane_rbac

Revision ID: 7e2c9a4f6b10
Revises: c5b7a1d9e204
Create Date: 2026-09-19 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "7e2c9a4f6b10"
down_revision: Union[str, Sequence[str], None] = "c5b7a1d9e204"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "control_plane_principals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("principal_type", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for column, unique in [
        ("subject", True),
        ("principal_type", False),
        ("enabled", False),
    ]:
        op.create_index(
            op.f(f"ix_control_plane_principals_{column}"),
            "control_plane_principals",
            [column],
            unique=unique,
        )

    op.create_table(
        "control_plane_roles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("permissions", sa.JSON(), nullable=False),
        sa.Column("system", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_control_plane_roles_name"),
        "control_plane_roles",
        ["name"],
        unique=True,
    )
    op.create_index(
        op.f("ix_control_plane_roles_system"),
        "control_plane_roles",
        ["system"],
        unique=False,
    )

    op.create_table(
        "control_plane_role_bindings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("role_id", sa.String(length=36), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["control_plane_principals.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"], ["control_plane_roles.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "principal_id", "role_id", name="uq_control_plane_role_binding"
        ),
    )
    for column in ["principal_id", "role_id"]:
        op.create_index(
            op.f(f"ix_control_plane_role_bindings_{column}"),
            "control_plane_role_bindings",
            [column],
            unique=False,
        )

    op.create_table(
        "control_plane_access_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("token_prefix", sa.String(length=32), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=255), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["control_plane_principals.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    for column, unique in [
        ("principal_id", False),
        ("token_prefix", True),
        ("expires_at", False),
        ("revoked_at", False),
    ]:
        op.create_index(
            op.f(f"ix_control_plane_access_tokens_{column}"),
            "control_plane_access_tokens",
            [column],
            unique=unique,
        )


def downgrade() -> None:
    for column in ["revoked_at", "expires_at", "token_prefix", "principal_id"]:
        op.drop_index(
            op.f(f"ix_control_plane_access_tokens_{column}"),
            table_name="control_plane_access_tokens",
        )
    op.drop_table("control_plane_access_tokens")
    for column in ["role_id", "principal_id"]:
        op.drop_index(
            op.f(f"ix_control_plane_role_bindings_{column}"),
            table_name="control_plane_role_bindings",
        )
    op.drop_table("control_plane_role_bindings")
    for column in ["system", "name"]:
        op.drop_index(
            op.f(f"ix_control_plane_roles_{column}"),
            table_name="control_plane_roles",
        )
    op.drop_table("control_plane_roles")
    for column in ["enabled", "principal_type", "subject"]:
        op.drop_index(
            op.f(f"ix_control_plane_principals_{column}"),
            table_name="control_plane_principals",
        )
    op.drop_table("control_plane_principals")
