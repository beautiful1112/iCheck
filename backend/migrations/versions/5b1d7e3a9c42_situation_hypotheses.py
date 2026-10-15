"""persist evidence-linked situation hypothesis revisions

Revision ID: 5b1d7e3a9c42
Revises: 4a9e1c7b5d30
Create Date: 2026-09-27 15:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "5b1d7e3a9c42"
down_revision: str | None = "4a9e1c7b5d30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "situation_hypotheses",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("situation_id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("statement_hash", sa.String(length=64), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("current_confidence", sa.Float(), nullable=False),
        sa.Column("revision_count", sa.Integer(), nullable=False),
        sa.Column("source_model_id", sa.String(length=36), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("reviewed_by", sa.String(length=255), nullable=True),
        sa.Column("review_reason", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('candidate', 'proposed', 'accepted', 'rejected', 'superseded')",
            name="ck_situation_hypothesis_status",
        ),
        sa.CheckConstraint(
            "current_confidence >= 0 AND current_confidence <= 1",
            name="ck_situation_hypothesis_confidence",
        ),
        sa.CheckConstraint(
            "revision_count >= 0",
            name="ck_situation_hypothesis_revision_count",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["situation_id"], ["situations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "investigation_id",
            "statement_hash",
            name="uq_situation_hypothesis_investigation_statement",
        ),
    )
    for column in ("situation_id", "investigation_id", "statement_hash", "status"):
        op.create_index(
            op.f(f"ix_situation_hypotheses_{column}"),
            "situation_hypotheses",
            [column],
        )
    op.create_index(
        "ix_situation_hypothesis_queue",
        "situation_hypotheses",
        ["situation_id", "status", "current_confidence"],
    )

    op.create_table(
        "situation_hypothesis_revisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=36), nullable=False),
        sa.Column("checkpoint_id", sa.String(length=36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("iteration", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "revision > 0", name="ck_situation_hypothesis_revision"
        ),
        sa.CheckConstraint(
            "iteration >= 0", name="ck_situation_hypothesis_iteration"
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_situation_hypothesis_revision_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["checkpoint_id"],
            ["investigation_checkpoints.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["hypothesis_id"], ["situation_hypotheses.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "hypothesis_id",
            "checkpoint_id",
            name="uq_situation_hypothesis_checkpoint",
        ),
        sa.UniqueConstraint(
            "hypothesis_id",
            "revision",
            name="uq_situation_hypothesis_revision",
        ),
    )
    op.create_index(
        op.f("ix_situation_hypothesis_revisions_hypothesis_id"),
        "situation_hypothesis_revisions",
        ["hypothesis_id"],
    )
    op.create_index(
        op.f("ix_situation_hypothesis_revisions_checkpoint_id"),
        "situation_hypothesis_revisions",
        ["checkpoint_id"],
    )

    op.create_table(
        "situation_hypothesis_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("revision_id", sa.String(length=36), nullable=False),
        sa.Column("investigation_evidence_id", sa.String(length=36), nullable=False),
        sa.Column("stance", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "stance IN ('supporting', 'contradicting')",
            name="ck_situation_hypothesis_evidence_stance",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_evidence_id"],
            ["investigation_evidence.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["revision_id"],
            ["situation_hypothesis_revisions.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "revision_id",
            "investigation_evidence_id",
            name="uq_situation_hypothesis_evidence",
        ),
    )
    op.create_index(
        op.f("ix_situation_hypothesis_evidence_revision_id"),
        "situation_hypothesis_evidence",
        ["revision_id"],
    )
    op.create_index(
        op.f("ix_situation_hypothesis_evidence_investigation_evidence_id"),
        "situation_hypothesis_evidence",
        ["investigation_evidence_id"],
    )


def downgrade() -> None:
    op.drop_table("situation_hypothesis_evidence")
    op.drop_table("situation_hypothesis_revisions")
    op.drop_table("situation_hypotheses")
