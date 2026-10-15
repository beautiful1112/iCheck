"""browser_sessions

Revision ID: d28f5b9e3c74
Revises: b17e4c8d2a63
Create Date: 2026-09-20 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d28f5b9e3c74"
down_revision: Union[str, Sequence[str], None] = "b17e4c8d2a63"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "control_plane_browser_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("token_prefix", sa.String(length=32), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["control_plane_principals.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column, unique in [
        ("principal_id", False),
        ("token_prefix", True),
        ("token_hash", True),
        ("expires_at", False),
        ("revoked_at", False),
    ]:
        op.create_index(
            op.f(f"ix_control_plane_browser_sessions_{column}"),
            "control_plane_browser_sessions",
            [column],
            unique=unique,
        )


def downgrade() -> None:
    for column in [
        "revoked_at",
        "expires_at",
        "token_hash",
        "token_prefix",
        "principal_id",
    ]:
        op.drop_index(
            op.f(f"ix_control_plane_browser_sessions_{column}"),
            table_name="control_plane_browser_sessions",
        )
    op.drop_table("control_plane_browser_sessions")
