"""Durable, exact-target OAuth recovery custody; never fabricate proof."""
from alembic import op
import sqlalchemy as sa

revision = "l9p1s3u5w7y0"
down_revision = "k8n0q2s4u6w9"
branch_labels = depends_on = None


def _visible_bind():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        if bind.execute(sa.text("SELECT row_security_active('mcp_servers')")).scalar() is not False:
            raise RuntimeError("OAuth recovery migration requires all-namespace visibility")
    elif bind.dialect.name != "sqlite":
        raise RuntimeError("OAuth recovery migration requires PostgreSQL or SQLite")
    return bind


def upgrade():
    _visible_bind()
    op.add_column("mcp_servers", sa.Column("oauth_recovery_custody", sa.JSON(none_as_null=True), nullable=True))


def downgrade():
    bind = _visible_bind()
    # Completed recovery is still security history, not disposable UI state.
    if bind.execute(sa.text("SELECT 1 FROM mcp_servers WHERE oauth_recovery_custody IS NOT NULL LIMIT 1")).first():
        raise RuntimeError("Retained OAuth recovery custody prevents downgrade")
    op.drop_column("mcp_servers", "oauth_recovery_custody")
