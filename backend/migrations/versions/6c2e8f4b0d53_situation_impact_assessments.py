"""persist governed situation impact assessments

Revision ID: 6c2e8f4b0d53
Revises: 5b1d7e3a9c42
Create Date: 2026-09-27 17:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "6c2e8f4b0d53"
down_revision: str | None = "5b1d7e3a9c42"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "situation_impact_assessments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("situation_id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("checkpoint_id", sa.String(length=36), nullable=False),
        sa.Column("contract_version", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("impact_level", sa.String(length=16), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("affected_node_ids", sa.JSON(), nullable=False),
        sa.Column("uncertainty", sa.JSON(), nullable=False),
        sa.Column("source_model_id", sa.String(length=36), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("reviewed_by", sa.String(length=255), nullable=True),
        sa.Column("review_reason", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('proposed', 'accepted', 'rejected')",
            name="ck_situation_impact_assessment_status",
        ),
        sa.CheckConstraint(
            "impact_level IN ('unknown', 'none', 'low', 'medium', 'high', 'critical')",
            name="ck_situation_impact_assessment_level",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_situation_impact_assessment_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["checkpoint_id"],
            ["investigation_checkpoints.id"],
            ondelete="CASCADE",
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
            name="uq_situation_impact_assessment_investigation",
        ),
    )
    for column in (
        "situation_id",
        "investigation_id",
        "checkpoint_id",
        "status",
        "impact_level",
    ):
        op.create_index(
            op.f(f"ix_situation_impact_assessments_{column}"),
            "situation_impact_assessments",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_situation_impact_assessment_queue",
        "situation_impact_assessments",
        ["situation_id", "status", "impact_level"],
    )

    op.create_table(
        "situation_impact_assessment_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("investigation_evidence_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["situation_impact_assessments.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_evidence_id"],
            ["investigation_evidence.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "assessment_id",
            "investigation_evidence_id",
            name="uq_situation_impact_assessment_evidence",
        ),
    )
    op.create_index(
        op.f("ix_situation_impact_assessment_evidence_assessment_id"),
        "situation_impact_assessment_evidence",
        ["assessment_id"],
    )
    op.create_index(
        op.f("ix_situation_impact_assessment_evidence_investigation_evidence_id"),
        "situation_impact_assessment_evidence",
        ["investigation_evidence_id"],
    )


def downgrade() -> None:
    op.drop_table("situation_impact_assessment_evidence")
    op.drop_table("situation_impact_assessments")
