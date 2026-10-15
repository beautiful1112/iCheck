"""Separate reusable package approval from device access setup."""
from alembic import op
import sqlalchemy as sa

revision = "x1d3f5h7j9l2"
down_revision = "w0c2e4g6i8k1"
branch_labels = depends_on = None


def upgrade():
    # No backfill: existing installations retain their exact reviewed targets.
    op.add_column("managed_extension_installations", sa.Column("target_policy", sa.JSON(), nullable=True))
    op.add_column("managed_extension_installations", sa.Column("previous_target_policy", sa.JSON(), nullable=True))


def downgrade():
    rows = op.get_bind().execute(sa.text(
        "SELECT target_policy, previous_target_policy FROM managed_extension_installations"))
    if any(any(value not in (None, "null") for value in row) for row in rows):
        raise RuntimeError("Reusable package approvals must be retained; restore a backup for downgrade")
    op.drop_column("managed_extension_installations", "previous_target_policy")
    op.drop_column("managed_extension_installations", "target_policy")
