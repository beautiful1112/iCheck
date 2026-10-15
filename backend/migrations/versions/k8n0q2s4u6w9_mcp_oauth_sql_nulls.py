"""Canonical SQL NULL for absent OAuth observation and cleanup custody."""
from alembic import op
import sqlalchemy as sa

revision = "k8n0q2s4u6w9"
down_revision = "j7m9p1r3t5v8"
branch_labels = depends_on = None


def _visible_bind():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        if bind.execute(sa.text("SELECT row_security_active('mcp_servers')")).scalar() is not False:
            raise RuntimeError("OAuth null normalization requires all-namespace visibility")
    elif bind.dialect.name != "sqlite":
        raise RuntimeError("OAuth null normalization requires PostgreSQL or SQLite")
    return bind


def upgrade():
    bind = _visible_bind()
    kind = "json_typeof" if bind.dialect.name == "postgresql" else "json_type"
    # JSON literal null and SQL NULL both decode to Python None. Only the
    # literal needs repair: preserve objects (even invalid custody), scalars,
    # nested nulls and unrelated server metadata. Never fabricate an intent.
    bind.execute(sa.text(f"""UPDATE mcp_servers SET
        oauth_credential_observation = CASE
            WHEN {kind}(oauth_credential_observation)='null' THEN NULL
            ELSE oauth_credential_observation END,
        oauth_revocation_intent = CASE
            WHEN {kind}(oauth_revocation_intent)='null' THEN NULL
            ELSE oauth_revocation_intent END
        WHERE {kind}(oauth_credential_observation)='null'
           OR {kind}(oauth_revocation_intent)='null'"""))


def downgrade():
    # A representation repair has no inverse: do not recreate false retained
    # custody. Earlier migrations still guard genuine intent/generation history.
    _visible_bind()
