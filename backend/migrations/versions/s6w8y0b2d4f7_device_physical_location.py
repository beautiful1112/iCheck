"""Optional structured device placement; preserve all existing Site values."""
from alembic import op
import sqlalchemy as sa

revision = "s6w8y0b2d4f7"
down_revision = "r5v7x9z1c3e6"
branch_labels = depends_on = None


def upgrade():
    op.add_column("devices", sa.Column("location", sa.JSON(), nullable=False, server_default="{}"))


def downgrade():
    if op.get_bind().execute(sa.text("SELECT 1 FROM devices WHERE CAST(location AS TEXT) NOT IN ('{}', 'null') LIMIT 1")).first():
        raise RuntimeError("Cannot discard populated device locations")
    op.drop_column("devices", "location")
