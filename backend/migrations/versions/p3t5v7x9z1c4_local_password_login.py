"""Add local human passwords without changing API or worker credentials."""
from alembic import op
import sqlalchemy as sa

revision = "p3t5v7x9z1c4"
down_revision = "o2s4u6w8y0b3"
branch_labels = depends_on = None

TABLE = "control_plane_principals"
SESSIONS = "control_plane_browser_sessions"
CONSTRAINT = "ck_control_plane_browser_session_source"


def _source_constraint(password: bool) -> str:
    sources = "'unknown', 'local_token', 'local_password'" if password else "'unknown', 'local_token'"
    return (
        f"(auth_source IN ({sources}) AND federated_identity_id IS NULL) OR "
        "(auth_source IN ('oidc', 'trusted_proxy') AND federated_identity_id IS NOT NULL)"
    )


def upgrade() -> None:
    op.add_column(TABLE, sa.Column("password_hash", sa.String(255), nullable=True))
    op.add_column(TABLE, sa.Column("password_failed_attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column(TABLE, sa.Column("password_locked_until", sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table(SESSIONS) as batch:
        batch.drop_constraint(CONSTRAINT, type_="check")
        batch.create_check_constraint(CONSTRAINT, _source_constraint(True))


def downgrade() -> None:
    # Historical provenance must not be relabelled as token authentication.
    if op.get_bind().scalar(sa.text(f"SELECT count(*) FROM {SESSIONS} WHERE auth_source='local_password'")):
        raise RuntimeError("Remove password session history explicitly before downgrading")
    with op.batch_alter_table(SESSIONS) as batch:
        batch.drop_constraint(CONSTRAINT, type_="check")
        batch.create_check_constraint(CONSTRAINT, _source_constraint(False))
    op.drop_column(TABLE, "password_locked_until")
    op.drop_column(TABLE, "password_failed_attempts")
    op.drop_column(TABLE, "password_hash")
