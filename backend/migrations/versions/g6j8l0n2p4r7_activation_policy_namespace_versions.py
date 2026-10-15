"""Keep activation policy names and versions local to each namespace.

Revision ID: g6j8l0n2p4r7
Revises: f5h7j9l1n3p6
"""

from alembic import op
import sqlalchemy as sa


revision = "g6j8l0n2p4r7"
down_revision = "f5h7j9l1n3p6"
branch_labels = depends_on = None

TABLE = "device_activation_policies"


def upgrade() -> None:
    with op.batch_alter_table(TABLE) as batch:
        batch.create_unique_constraint(
            "uq_device_activation_policy_namespace_version",
            ["tenant_id", "region_id", "name", "version"],
        )
        batch.drop_constraint(
            "uq_device_activation_policy_version", type_="unique",
        )


def downgrade() -> None:
    duplicate = op.get_bind().execute(sa.text(
        f"SELECT name, version FROM {TABLE} GROUP BY name, version "
        "HAVING COUNT(*) > 1 LIMIT 1"
    )).first()
    if duplicate:
        raise RuntimeError(
            "Cannot restore global activation policy names while duplicate "
            "versions exist across namespaces"
        )
    with op.batch_alter_table(TABLE) as batch:
        batch.create_unique_constraint(
            "uq_device_activation_policy_version", ["name", "version"],
        )
        batch.drop_constraint(
            "uq_device_activation_policy_namespace_version", type_="unique",
        )
