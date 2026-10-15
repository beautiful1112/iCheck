"""Retain admitted OAuth code-redemption attempts and exact private targets."""
from alembic import op
import sqlalchemy as sa

revision = "m0q2t4v6x8z1"
down_revision = "l9p1s3u5w7y0"
branch_labels = depends_on = None
TABLE = "mcp_oauth_consent_attempts"


def _visible():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        if bind.execute(sa.text("SELECT row_security_active('mcp_servers')")).scalar() is not False:
            raise RuntimeError("Consent custody migration requires all-namespace visibility")
    elif bind.dialect.name != "sqlite":
        raise RuntimeError("Consent custody requires PostgreSQL or SQLite")
    return bind


def upgrade():
    bind = _visible()
    op.add_column("mcp_oauth_transactions", sa.Column("consent_snapshot", sa.JSON(none_as_null=True), nullable=True))
    op.create_table(TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("server_id", sa.String(36), nullable=False),
        sa.Column("transaction_id", sa.String(36), nullable=False),
        sa.Column("generation", sa.String(32), nullable=False),
        sa.Column("previous_generation", sa.String(32), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("issuer", sa.String(2048), nullable=False),
        sa.Column("client_id", sa.String(2048), nullable=False),
        sa.Column("resource", sa.String(2048), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("target", sa.JSON(), nullable=False),
        sa.Column("target_version", sa.Integer(), nullable=False),
        sa.Column("stored_version", sa.Integer(), nullable=True),
        sa.Column("actor_id", sa.String(255), nullable=False),
        sa.Column("admitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("failure_code", sa.String(64), nullable=True),
        sa.Column("refresh_token_received", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.UniqueConstraint("tenant_id", "region_id", "transaction_id", name="uq_mcp_oauth_consent_transaction"),
        sa.UniqueConstraint("tenant_id", "region_id", "server_id", "generation", name="uq_mcp_oauth_consent_generation"),
        sa.CheckConstraint("status IN ('redemption_admitted','storage_admitted','connected','superseded','outcome_unknown','compensation_pending','compensation_acknowledged','stored_unpublished','revoked')", name="ck_mcp_oauth_consent_status"),
        sa.CheckConstraint("target_version >= 0 AND (stored_version IS NULL OR stored_version = target_version + 1)", name="ck_mcp_oauth_consent_version"),
        sa.CheckConstraint("status NOT IN ('connected','superseded','revoked','stored_unpublished') OR stored_version IS NOT NULL", name="ck_mcp_oauth_consent_receipt"),
    )
    op.create_index("ix_mcp_oauth_consent_history", TABLE, ["tenant_id", "region_id", "server_id", "admitted_at", "id"])
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY"))
    predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
    op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))
    op.execute(sa.text(f"""CREATE FUNCTION icheck_consent_custody_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Consent custody cannot be deleted'; END IF;
      IF ROW(NEW.id,NEW.tenant_id,NEW.region_id,NEW.server_id,NEW.transaction_id,NEW.generation,
             NEW.previous_generation,NEW.issuer,NEW.client_id,NEW.resource,NEW.snapshot::jsonb,
             NEW.target::jsonb,NEW.target_version,NEW.actor_id,NEW.admitted_at)
         IS DISTINCT FROM
         ROW(OLD.id,OLD.tenant_id,OLD.region_id,OLD.server_id,OLD.transaction_id,OLD.generation,
             OLD.previous_generation,OLD.issuer,OLD.client_id,OLD.resource,OLD.snapshot::jsonb,
             OLD.target::jsonb,OLD.target_version,OLD.actor_id,OLD.admitted_at)
      THEN RAISE EXCEPTION 'Original consent custody is immutable'; END IF;
      IF OLD.stored_version IS NOT NULL AND NEW.stored_version IS DISTINCT FROM OLD.stored_version
      THEN RAISE EXCEPTION 'Stored consent version cannot be replaced'; END IF;
      IF OLD.refresh_token_received AND NOT NEW.refresh_token_received
      THEN RAISE EXCEPTION 'Received consent token custody cannot be erased'; END IF;
      IF NEW.status <> OLD.status AND NOT (
           (OLD.status='redemption_admitted' AND NEW.status IN ('storage_admitted','outcome_unknown','compensation_pending')) OR
           (OLD.status='storage_admitted' AND NEW.status IN ('connected','outcome_unknown','stored_unpublished','compensation_pending')) OR
           (OLD.status='compensation_pending' AND NEW.status='compensation_acknowledged') OR
           (OLD.status='connected' AND NEW.status IN ('superseded','revoked')))
      THEN RAISE EXCEPTION 'Consent custody transition is not authorized'; END IF;
      RETURN NEW;
    END $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_consent_custody_guard BEFORE UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION icheck_consent_custody_guard()"))


def downgrade():
    bind = _visible()
    if bind.dialect.name == "postgresql" and bind.execute(sa.text(
            "SELECT row_security_active('mcp_oauth_consent_attempts')")).scalar() is not False:
        raise RuntimeError("Consent custody downgrade requires all-namespace visibility")
    if (bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first()
            or bind.execute(sa.text("SELECT 1 FROM mcp_oauth_transactions WHERE consent_snapshot IS NOT NULL LIMIT 1")).first()):
        raise RuntimeError("Retained consent custody prevents downgrade")
    op.drop_table(TABLE)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_consent_custody_guard()"))
    op.drop_column("mcp_oauth_transactions", "consent_snapshot")
