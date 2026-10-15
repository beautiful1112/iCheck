"""artifact historical replay cases and runs

Revision ID: b7e4a2c9d130
Revises: a6d3f8c1e720
Create Date: 2026-09-24 15:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b7e4a2c9d130"
down_revision: Union[str, Sequence[str], None] = "a6d3f8c1e720"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "artifact_replay_cases",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("source_label", sa.String(length=255), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("input_envelopes", sa.JSON(), nullable=False),
        sa.Column("expected_envelopes", sa.JSON(), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=False),
        sa.Column("expected_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["artifact_id"], ["artifacts.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "artifact_id",
            "name",
            name="uq_artifact_replay_case_name",
        ),
    )
    op.create_index(
        op.f("ix_artifact_replay_cases_artifact_id"),
        "artifact_replay_cases",
        ["artifact_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_artifact_replay_cases_name"),
        "artifact_replay_cases",
        ["name"],
        unique=False,
    )

    op.create_table(
        "artifact_replay_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("actual_sha256", sa.String(length=64), nullable=True),
        sa.Column("mismatch_count", sa.Integer(), nullable=False),
        sa.Column("report", sa.JSON(), nullable=False),
        sa.Column("executed_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('passed', 'failed', 'error')",
            name="ck_artifact_replay_run_status",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["artifact_replay_cases.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ["case_id", "artifact_version_id", "status"]:
        op.create_index(
            op.f(f"ix_artifact_replay_runs_{column}"),
            "artifact_replay_runs",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_artifact_replay_run_case_created",
        "artifact_replay_runs",
        ["case_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_artifact_replay_run_case_created",
        table_name="artifact_replay_runs",
    )
    for column in reversed(["case_id", "artifact_version_id", "status"]):
        op.drop_index(
            op.f(f"ix_artifact_replay_runs_{column}"),
            table_name="artifact_replay_runs",
        )
    op.drop_table("artifact_replay_runs")
    op.drop_index(
        op.f("ix_artifact_replay_cases_name"),
        table_name="artifact_replay_cases",
    )
    op.drop_index(
        op.f("ix_artifact_replay_cases_artifact_id"),
        table_name="artifact_replay_cases",
    )
    op.drop_table("artifact_replay_cases")
