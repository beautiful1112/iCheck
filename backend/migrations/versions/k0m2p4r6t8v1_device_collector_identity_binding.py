"""Bind device-scoped collector deployments to an identity revision.

Revision ID: k0m2p4r6t8v1
Revises: j9l1n3p5r7t0
"""

from alembic import op
import sqlalchemy as sa


revision = "k0m2p4r6t8v1"
down_revision = "j9l1n3p5r7t0"
branch_labels = depends_on = None


CONSTRAINT = "ck_collector_deployment_identity_binding"
RULE = (
    "(scope_device_id IS NULL AND scope_device_identity_revision IS NULL) "
    "OR (scope_device_id IS NOT NULL AND scope_device_identity_revision >= 0)"
)


def upgrade() -> None:
    active_leases = op.get_bind().execute(sa.text(
        "SELECT COUNT(*) FROM collector_deployments "
        "WHERE scope_device_id IS NOT NULL "
        "AND lease_expires_at >= CURRENT_TIMESTAMP"
    )).scalar_one()
    if active_leases:
        raise RuntimeError(
            "Drain active device-scoped Collector leases before identity binding migration"
        )
    op.add_column(
        "devices",
        sa.Column("identity_revision", sa.Integer(), nullable=False, server_default="1"),
    )
    op.add_column(
        "collector_deployments",
        sa.Column("scope_device_identity_revision", sa.Integer(), nullable=True),
    )
    # Legacy targets were never reviewed against a device identity epoch.
    # Epoch 0 is a non-runnable sentinel; approval creates a fresh binding.
    op.execute(sa.text(
        "UPDATE collector_deployments "
        "SET scope_device_identity_revision = 0, enabled = false, next_run_at = NULL, "
        "lease_worker_id = NULL, lease_token_hash = NULL, lease_expires_at = NULL "
        "WHERE scope_device_id IS NOT NULL"
    ))
    with op.batch_alter_table("collector_deployments") as batch:
        batch.create_check_constraint(CONSTRAINT, RULE)


def downgrade() -> None:
    connection = op.get_bind()
    corrected = connection.execute(sa.text(
        "SELECT COUNT(*) FROM devices WHERE identity_revision <> 1"
    )).scalar_one()
    bound = connection.execute(sa.text(
        "SELECT COUNT(*) FROM collector_deployments "
        "WHERE scope_device_id IS NOT NULL"
    )).scalar_one()
    if corrected or bound:
        raise RuntimeError("Cannot discard device collector identity bindings")
    with op.batch_alter_table("collector_deployments") as batch:
        batch.drop_constraint(CONSTRAINT, type_="check")
        batch.drop_column("scope_device_identity_revision")
    op.drop_column("devices", "identity_revision")
