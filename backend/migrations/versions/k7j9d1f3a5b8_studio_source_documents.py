"""add bounded Collector Studio source documents

Revision ID: k7j9d1f3a5b8
Revises: j6h8c0e2f4a7
Create Date: 2026-09-29 20:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "k7j9d1f3a5b8"
down_revision: str | None = "j6h8c0e2f4a7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("capability_studio_sessions") as batch_op:
        batch_op.add_column(sa.Column("source_context", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("source_document_name", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "source_document_media_type",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "source_document_sha256",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column("source_document_bytes", sa.Integer(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("source_context_bytes", sa.Integer(), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "source_document_redaction_count",
                sa.Integer(),
                nullable=True,
            )
        )
        batch_op.create_check_constraint(
            "ck_capability_studio_source_document_complete",
            "(source_context IS NULL AND source_document_name IS NULL AND "
            "source_document_media_type IS NULL AND source_document_sha256 IS NULL "
            "AND source_document_bytes IS NULL AND source_context_bytes IS NULL "
            "AND source_document_redaction_count IS NULL) OR "
            "(source_context IS NOT NULL AND source_document_name IS NOT NULL AND "
            "source_document_media_type IS NOT NULL AND source_document_sha256 IS NOT NULL "
            "AND source_document_bytes > 0 AND source_context_bytes > 0 "
            "AND source_document_redaction_count >= 0)",
        )


def downgrade() -> None:
    with op.batch_alter_table("capability_studio_sessions") as batch_op:
        batch_op.drop_constraint(
            "ck_capability_studio_source_document_complete",
            type_="check",
        )
        batch_op.drop_column("source_document_redaction_count")
        batch_op.drop_column("source_context_bytes")
        batch_op.drop_column("source_document_bytes")
        batch_op.drop_column("source_document_sha256")
        batch_op.drop_column("source_document_media_type")
        batch_op.drop_column("source_document_name")
        batch_op.drop_column("source_context")
