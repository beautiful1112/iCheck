"""capability ecosystem transparency chain

Revision ID: k1a3c5d7f902
Revises: j0f2b4c6e891
Create Date: 2026-09-30 02:30:00.000000
"""

from collections.abc import Sequence
from datetime import UTC, datetime

from alembic import op
import sqlalchemy as sa


revision: str = "k1a3c5d7f902"
down_revision: str | None = "j0f2b4c6e891"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    state = op.create_table(
        "capability_transparency_state",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("last_sequence", sa.Integer(), nullable=False),
        sa.Column("head_digest_sha256", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.bulk_insert(
        state,
        [
            {
                "id": "global",
                "last_sequence": 0,
                "head_digest_sha256": "0" * 64,
                "updated_at": datetime.now(UTC),
            }
        ],
    )
    op.create_table(
        "capability_transparency_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column(
            "previous_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "record_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column(
            "subject_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "sequence > 0",
            name="ck_capability_transparency_sequence_positive",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "record_digest_sha256",
            name="uq_capability_transparency_record_digest",
        ),
        sa.UniqueConstraint(
            "sequence",
            name="uq_capability_transparency_record_sequence",
        ),
    )
    op.create_index(
        "ix_capability_transparency_records_event_type",
        "capability_transparency_records",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        "ix_capability_transparency_records_record_digest_sha256",
        "capability_transparency_records",
        ["record_digest_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_capability_transparency_records_sequence",
        "capability_transparency_records",
        ["sequence"],
        unique=False,
    )
    op.create_index(
        "ix_capability_transparency_records_subject_digest_sha256",
        "capability_transparency_records",
        ["subject_digest_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_capability_transparency_event_time",
        "capability_transparency_records",
        ["event_type", "occurred_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("capability_transparency_records")
    op.drop_table("capability_transparency_state")
