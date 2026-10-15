"""add failed-runtime Capability Studio revision sessions

Revision ID: b8f0a2c4d689
Revises: a7e9f1b3c578
Create Date: 2026-09-29 23:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "b8f0a2c4d689"
down_revision: str | None = "a7e9f1b3c578"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


SESSIONS = "capability_studio_sessions"
RUNS = "collector_runs"


def _create_session_constraints() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(SESSIONS) as batch:
            batch.create_unique_constraint(
                "uq_capability_studio_revision_source",
                [
                    "tenant_id",
                    "region_id",
                    "revision_source_type",
                    "revision_source_id",
                ],
            )
            batch.create_check_constraint(
                "ck_capability_studio_revision_source_type",
                "revision_source_type IS NULL OR revision_source_type IN "
                "('collector_run', 'artifact_replay_run', 'agent_execution')",
            )
            batch.create_check_constraint(
                "ck_capability_studio_revision_source_complete",
                "(revision_source_type IS NULL AND revision_source_id IS NULL AND "
                "revision_source_artifact_version_id IS NULL AND "
                "revision_evidence_sha256 IS NULL) OR "
                "(revision_source_type IS NOT NULL AND revision_source_id IS NOT NULL "
                "AND revision_source_artifact_version_id IS NOT NULL AND "
                "revision_evidence_sha256 IS NOT NULL)",
            )
        return
    op.create_unique_constraint(
        "uq_capability_studio_revision_source",
        SESSIONS,
        ["tenant_id", "region_id", "revision_source_type", "revision_source_id"],
    )
    op.create_check_constraint(
        "ck_capability_studio_revision_source_type",
        SESSIONS,
        "revision_source_type IS NULL OR revision_source_type IN "
        "('collector_run', 'artifact_replay_run', 'agent_execution')",
    )
    op.create_check_constraint(
        "ck_capability_studio_revision_source_complete",
        SESSIONS,
        "(revision_source_type IS NULL AND revision_source_id IS NULL AND "
        "revision_source_artifact_version_id IS NULL AND "
        "revision_evidence_sha256 IS NULL) OR "
        "(revision_source_type IS NOT NULL AND revision_source_id IS NOT NULL "
        "AND revision_source_artifact_version_id IS NOT NULL AND "
        "revision_evidence_sha256 IS NOT NULL)",
    )


def _drop_session_constraints() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(SESSIONS) as batch:
            batch.drop_constraint(
                "ck_capability_studio_revision_source_complete", type_="check"
            )
            batch.drop_constraint(
                "ck_capability_studio_revision_source_type", type_="check"
            )
            batch.drop_constraint(
                "uq_capability_studio_revision_source", type_="unique"
            )
        return
    op.drop_constraint(
        "ck_capability_studio_revision_source_complete", SESSIONS, type_="check"
    )
    op.drop_constraint(
        "ck_capability_studio_revision_source_type", SESSIONS, type_="check"
    )
    op.drop_constraint(
        "uq_capability_studio_revision_source", SESSIONS, type_="unique"
    )


def upgrade() -> None:
    op.add_column(
        RUNS,
        sa.Column("artifact_version_id", sa.String(length=36), nullable=True),
    )
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(RUNS) as batch:
            batch.create_foreign_key(
                "fk_collector_runs_artifact_version_id",
                "artifact_versions",
                ["artifact_version_id"],
                ["id"],
                ondelete="SET NULL",
            )
    else:
        op.create_foreign_key(
            "fk_collector_runs_artifact_version_id",
            RUNS,
            "artifact_versions",
            ["artifact_version_id"],
            ["id"],
            ondelete="SET NULL",
        )
    op.create_index(
        f"ix_{RUNS}_artifact_version_id", RUNS, ["artifact_version_id"]
    )

    op.add_column(
        SESSIONS,
        sa.Column("revision_source_type", sa.String(length=32), nullable=True),
    )
    op.add_column(
        SESSIONS,
        sa.Column("revision_source_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        SESSIONS,
        sa.Column(
            "revision_source_artifact_version_id",
            sa.String(length=36),
            nullable=True,
        ),
    )
    op.add_column(
        SESSIONS,
        sa.Column("revision_evidence_sha256", sa.String(length=64), nullable=True),
    )
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(SESSIONS) as batch:
            batch.create_foreign_key(
                "fk_capability_studio_revision_artifact_version_id",
                "artifact_versions",
                ["revision_source_artifact_version_id"],
                ["id"],
                ondelete="SET NULL",
            )
    else:
        op.create_foreign_key(
            "fk_capability_studio_revision_artifact_version_id",
            SESSIONS,
            "artifact_versions",
            ["revision_source_artifact_version_id"],
            ["id"],
            ondelete="SET NULL",
        )
    for column in (
        "revision_source_type",
        "revision_source_id",
        "revision_source_artifact_version_id",
    ):
        op.create_index(op.f(f"ix_{SESSIONS}_{column}"), SESSIONS, [column])
    _create_session_constraints()


def downgrade() -> None:
    _drop_session_constraints()
    for column in (
        "revision_source_artifact_version_id",
        "revision_source_id",
        "revision_source_type",
    ):
        op.drop_index(op.f(f"ix_{SESSIONS}_{column}"), table_name=SESSIONS)
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(SESSIONS) as batch:
            batch.drop_constraint(
                "fk_capability_studio_revision_artifact_version_id",
                type_="foreignkey",
            )
    else:
        op.drop_constraint(
            "fk_capability_studio_revision_artifact_version_id",
            SESSIONS,
            type_="foreignkey",
        )
    for column in (
        "revision_evidence_sha256",
        "revision_source_artifact_version_id",
        "revision_source_id",
        "revision_source_type",
    ):
        op.drop_column(SESSIONS, column)

    op.drop_index(f"ix_{RUNS}_artifact_version_id", table_name=RUNS)
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(RUNS) as batch:
            batch.drop_constraint(
                "fk_collector_runs_artifact_version_id", type_="foreignkey"
            )
    else:
        op.drop_constraint(
            "fk_collector_runs_artifact_version_id", RUNS, type_="foreignkey"
        )
    op.drop_column(RUNS, "artifact_version_id")
