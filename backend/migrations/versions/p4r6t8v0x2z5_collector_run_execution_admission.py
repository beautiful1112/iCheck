"""Bind Worker execution admission to the exact Collector claim.

Revision ID: p4r6t8v0x2z5
Revises: n3p5r7t9v1x4
"""

from alembic import op
import sqlalchemy as sa


revision = "p4r6t8v0x2z5"
down_revision = "n3p5r7t9v1x4"
branch_labels = depends_on = None

CONSTRAINT = "ck_collector_run_assignment_hash"


def upgrade() -> None:
    connection = op.get_bind()
    leased_external = connection.execute(sa.text(
        "SELECT COUNT(*) FROM collector_deployments "
        "WHERE target_classification = 'external_source' "
        "AND lease_token_hash IS NOT NULL"
    )).scalar_one()
    if leased_external:
        raise RuntimeError(
            "Drain external-source Collector leases before execution-admission upgrade"
        )
    op.add_column("collector_runs", sa.Column(
        "assignment_sha256", sa.String(length=64), nullable=True,
    ))
    op.add_column("collector_runs", sa.Column(
        "target_classification_snapshot", sa.String(length=32), nullable=True,
    ))
    op.add_column("collector_runs", sa.Column(
        "execution_admitted_at", sa.DateTime(timezone=True), nullable=True,
    ))
    with op.batch_alter_table("collector_runs") as batch:
        batch.create_check_constraint(
            CONSTRAINT,
            "assignment_sha256 IS NULL OR length(assignment_sha256) = 64",
        )


def downgrade() -> None:
    snapshotted = op.get_bind().execute(sa.text(
        "SELECT COUNT(*) FROM collector_runs WHERE assignment_sha256 IS NOT NULL "
        "OR target_classification_snapshot IS NOT NULL "
        "OR execution_admitted_at IS NOT NULL"
    )).scalar_one()
    if snapshotted:
        raise RuntimeError("Cannot discard Collector run execution-admission evidence")
    with op.batch_alter_table("collector_runs") as batch:
        batch.drop_constraint(CONSTRAINT, type_="check")
        batch.drop_column("execution_admitted_at")
        batch.drop_column("target_classification_snapshot")
        batch.drop_column("assignment_sha256")
