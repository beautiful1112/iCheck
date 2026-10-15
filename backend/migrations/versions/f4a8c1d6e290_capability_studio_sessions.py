"""capability studio sessions

Revision ID: f4a8c1d6e290
Revises: e39a7c2d5f81
Create Date: 2026-09-21 07:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f4a8c1d6e290"
down_revision: Union[str, Sequence[str], None] = "e39a7c2d5f81"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "capability_studio_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("artifact_kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("route_purpose", sa.String(length=128), nullable=False),
        sa.Column("route_id", sa.String(length=36), nullable=True),
        sa.Column("model_id", sa.String(length=36), nullable=True),
        sa.Column("brief", sa.Text(), nullable=False),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("sample_document", sa.JSON(), nullable=False),
        sa.Column("current_spec", sa.JSON(), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=True),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=True),
        sa.Column("tokens_used", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in [
        "title",
        "artifact_kind",
        "status",
        "route_purpose",
        "artifact_id",
        "artifact_version_id",
        "created_by",
    ]:
        op.create_index(
            op.f(f"ix_capability_studio_sessions_{column}"),
            "capability_studio_sessions",
            [column],
            unique=False,
        )
    op.create_table(
        "capability_studio_messages",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("structured_content", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["capability_studio_sessions.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_capability_studio_messages_session_id"),
        "capability_studio_messages",
        ["session_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_capability_studio_messages_role"),
        "capability_studio_messages",
        ["role"],
        unique=False,
    )
    op.create_index(
        "ix_capability_studio_message_session_created",
        "capability_studio_messages",
        ["session_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_capability_studio_message_session_created",
        table_name="capability_studio_messages",
    )
    op.drop_index(
        op.f("ix_capability_studio_messages_role"),
        table_name="capability_studio_messages",
    )
    op.drop_index(
        op.f("ix_capability_studio_messages_session_id"),
        table_name="capability_studio_messages",
    )
    op.drop_table("capability_studio_messages")
    for column in reversed(
        [
            "title",
            "artifact_kind",
            "status",
            "route_purpose",
            "artifact_id",
            "artifact_version_id",
            "created_by",
        ]
    ):
        op.drop_index(
            op.f(f"ix_capability_studio_sessions_{column}"),
            table_name="capability_studio_sessions",
        )
    op.drop_table("capability_studio_sessions")
