"""Allow optimistic, audited edits to activation policy drafts.

Revision ID: f5h7j9l1n3p6
Revises: e4g6i8k0m2n5
"""

from alembic import op
import sqlalchemy as sa


revision = "f5h7j9l1n3p6"
down_revision = "e4g6i8k0m2n5"
branch_labels = depends_on = None

TABLE = "device_activation_policies"


def upgrade() -> None:
    with op.batch_alter_table(TABLE) as batch:
        batch.add_column(sa.Column(
            "revision", sa.Integer(), nullable=False, server_default="1",
        ))
        batch.add_column(sa.Column("updated_by", sa.String(255), nullable=True))
        batch.add_column(sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=True,
        ))
        batch.create_check_constraint(
            "ck_device_activation_policy_revision_positive", "revision > 0",
        )


def downgrade() -> None:
    changed = op.get_bind().execute(sa.text(
        f"SELECT 1 FROM {TABLE} WHERE revision > 1 LIMIT 1"
    )).first()
    if changed:
        raise RuntimeError("Cannot discard activation policy draft edit revisions")
    with op.batch_alter_table(TABLE) as batch:
        batch.drop_constraint(
            "ck_device_activation_policy_revision_positive", type_="check",
        )
        batch.drop_column("updated_at")
        batch.drop_column("updated_by")
        batch.drop_column("revision")
