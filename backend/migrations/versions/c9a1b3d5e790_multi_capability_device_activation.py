"""allow multiple governed capabilities per device connection

Revision ID: c9a1b3d5e790
Revises: b8f0a2c4d689
Create Date: 2026-09-30 01:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c9a1b3d5e790"
down_revision: str | None = "b8f0a2c4d689"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


TABLE = "device_connection_activations"


def upgrade() -> None:
    op.add_column(
        TABLE,
        sa.Column("capability_key", sa.String(length=255), nullable=True),
    )
    op.execute(
        sa.text(
            "UPDATE device_connection_activations "
            "SET capability_key = ("
            "SELECT name FROM device_activation_policies "
            "WHERE device_activation_policies.id = "
            "device_connection_activations.policy_id"
            ")"
        )
    )
    missing = op.get_bind().execute(
        sa.text(
            "SELECT id FROM device_connection_activations "
            "WHERE capability_key IS NULL LIMIT 1"
        )
    ).first()
    if missing is not None:
        raise RuntimeError("Cannot derive capability_key for an activation")
    with op.batch_alter_table(TABLE) as batch:
        batch.alter_column(
            "capability_key",
            existing_type=sa.String(length=255),
            nullable=False,
        )
        batch.drop_constraint(
            "uq_device_connection_activation",
            type_="unique",
        )
        batch.create_unique_constraint(
            "uq_device_connection_activation_capability",
            ["connection_id", "capability_key"],
        )
    op.create_index(
        f"ix_{TABLE}_capability_key",
        TABLE,
        ["capability_key"],
    )


def downgrade() -> None:
    duplicate = op.get_bind().execute(
        sa.text(
            "SELECT connection_id FROM device_connection_activations "
            "GROUP BY connection_id HAVING COUNT(*) > 1 LIMIT 1"
        )
    ).first()
    if duplicate is not None:
        raise RuntimeError(
            "Cannot downgrade while a connection has multiple activation records"
        )
    op.drop_index(f"ix_{TABLE}_capability_key", table_name=TABLE)
    with op.batch_alter_table(TABLE) as batch:
        batch.drop_constraint(
            "uq_device_connection_activation_capability",
            type_="unique",
        )
        batch.create_unique_constraint(
            "uq_device_connection_activation",
            ["connection_id"],
        )
        batch.drop_column("capability_key")
