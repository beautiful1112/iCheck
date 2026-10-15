"""Pin the original OAuth cleanup target across retries and profile edits."""
from alembic import op
import sqlalchemy as sa

revision = "j7m9p1r3t5v8"
down_revision = "i6l8n0q2s4u7"
branch_labels = depends_on = None


def upgrade():
    op.add_column("mcp_servers", sa.Column("oauth_revocation_intent", sa.JSON(), nullable=True))
    # No guessed cleanup intent for a legacy pending revoke.


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active('mcp_servers')")).scalar():
        raise RuntimeError("OAuth cleanup downgrade requires all-namespace visibility")
    if bind.execute(sa.text("SELECT 1 FROM mcp_servers WHERE oauth_revocation_intent IS NOT NULL LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade retained OAuth cleanup custody")
    op.drop_column("mcp_servers", "oauth_revocation_intent")
