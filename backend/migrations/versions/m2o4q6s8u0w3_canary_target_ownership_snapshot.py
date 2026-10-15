"""Persist a reviewable ownership snapshot on each new Collector canary.

Historical canaries are left without a digest. Their start-time ownership
cannot be reconstructed safely from a deployment that may have changed.

Revision ID: m2o4q6s8u0w3
Revises: l1n3p5r7t9v2
"""

from alembic import op
import sqlalchemy as sa


revision = "m2o4q6s8u0w3"
down_revision = "l1n3p5r7t9v2"
branch_labels = depends_on = None


CONSTRAINT = "ck_collector_canary_target_ownership_hash"


def upgrade() -> None:
    op.add_column("collector_canary_rollouts", sa.Column(
        "target_classification", sa.String(length=32), nullable=True,
    ))
    op.add_column("collector_canary_rollouts", sa.Column(
        "scope_device_id", sa.String(length=36), nullable=True,
    ))
    op.add_column("collector_canary_rollouts", sa.Column(
        "scope_device_identity_revision", sa.Integer(), nullable=True,
    ))
    op.add_column("collector_canary_rollouts", sa.Column(
        "scope_site", sa.String(length=128), nullable=True,
    ))
    op.add_column("collector_canary_rollouts", sa.Column(
        "external_source_reason", sa.Text(), nullable=True,
    ))
    op.add_column("collector_canary_rollouts", sa.Column(
        "target_ownership_sha256", sa.String(length=64), nullable=True,
    ))
    with op.batch_alter_table("collector_canary_rollouts") as batch:
        batch.create_check_constraint(
            CONSTRAINT,
            "target_ownership_sha256 IS NULL OR length(target_ownership_sha256) = 64",
        )


def downgrade() -> None:
    connection = op.get_bind()
    snapshotted = connection.execute(sa.text(
        "SELECT COUNT(*) FROM collector_canary_rollouts WHERE "
        "target_ownership_sha256 IS NOT NULL OR target_classification IS NOT NULL "
        "OR scope_device_id IS NOT NULL OR scope_device_identity_revision IS NOT NULL "
        "OR scope_site IS NOT NULL OR external_source_reason IS NOT NULL"
    )).scalar_one()
    if snapshotted:
        raise RuntimeError("Cannot discard reviewed Collector canary ownership snapshots")
    with op.batch_alter_table("collector_canary_rollouts") as batch:
        batch.drop_constraint(CONSTRAINT, type_="check")
        batch.drop_column("target_ownership_sha256")
        batch.drop_column("external_source_reason")
        batch.drop_column("scope_site")
        batch.drop_column("scope_device_identity_revision")
        batch.drop_column("scope_device_id")
        batch.drop_column("target_classification")
