"""Consent generations and secret-free credential observations, not grants."""
from alembic import op
import sqlalchemy as sa

revision = "i6l8n0q2s4u7"
down_revision = "h5k7m9p1r3t6"
branch_labels = depends_on = None


def upgrade():
    op.add_column("mcp_servers", sa.Column("oauth_generation", sa.String(32), nullable=True))
    op.add_column("mcp_servers", sa.Column("oauth_bundle_version", sa.Integer(), nullable=True))
    op.add_column("mcp_servers", sa.Column("oauth_credential_observation", sa.JSON(), nullable=True))
    op.add_column("mcp_oauth_transactions", sa.Column("oauth_generation", sa.String(32), nullable=True))
    # Existing consent has no proven generation binding. Do not fabricate one.


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and bind.execute(sa.text(
        "SELECT row_security_active('mcp_servers')"
    )).scalar():
        raise RuntimeError("OAuth custody downgrade requires all-namespace visibility")
    if (bind.execute(sa.text("SELECT 1 FROM mcp_servers WHERE oauth_generation IS NOT NULL OR oauth_bundle_version IS NOT NULL OR oauth_credential_observation IS NOT NULL LIMIT 1")).first()
        or bind.execute(sa.text("SELECT 1 FROM mcp_oauth_transactions WHERE oauth_generation IS NOT NULL LIMIT 1")).first()):
        raise RuntimeError("Cannot downgrade generation-bound OAuth custody")
    for column in ("oauth_credential_observation", "oauth_bundle_version", "oauth_generation"):
        op.drop_column("mcp_servers", column)
    op.drop_column("mcp_oauth_transactions", "oauth_generation")
