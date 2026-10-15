"""Encrypted, namespace-local OpenRouter credentials and outbound approvals."""
from alembic import op
import sqlalchemy as sa

revision = "q4u6w8y0b2d5"
down_revision = "p3t5v7x9z1c4"
branch_labels = depends_on = None
TABLE = "ai_managed_connections"


def upgrade():
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False,
                  server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False,
                  server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("provider_id", sa.String(36), sa.ForeignKey("ai_provider_configs.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("credential_profile_id", sa.String(36), sa.ForeignKey("credential_profiles.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("preset", sa.String(32), nullable=False),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=False),
        sa.Column("outbound_enabled", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "provider_id", name="uq_ai_managed_provider"),
        sa.UniqueConstraint("credential_profile_id", name="uq_ai_managed_credential"),
        sa.CheckConstraint("revision > 0", name="ck_ai_managed_revision"),
        sa.CheckConstraint("preset = 'openrouter'", name="ck_ai_managed_preset"),
    )
    for name in ("tenant_id", "region_id"):
        op.create_index(f"ix_{TABLE}_{name}", TABLE, [name])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))
        op.execute(sa.text("""CREATE FUNCTION icheck_guard_ai_managed_connection() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Managed AI custody cannot be deleted'; END IF;
            IF TG_OP = 'UPDATE' AND (
                NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                OR NEW.region_id IS DISTINCT FROM OLD.region_id OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
                OR NEW.credential_profile_id IS DISTINCT FROM OLD.credential_profile_id
                OR NEW.preset IS DISTINCT FROM OLD.preset OR NEW.created_by IS DISTINCT FROM OLD.created_by
                OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.revision <> OLD.revision + 1
            ) THEN RAISE EXCEPTION 'Managed AI custody binding/revision is immutable'; END IF;
            IF NOT EXISTS (SELECT 1 FROM ai_provider_configs p WHERE p.id=NEW.provider_id
                AND p.tenant_id=NEW.tenant_id AND p.region_id=NEW.region_id)
                OR NOT EXISTS (SELECT 1 FROM credential_profiles c WHERE c.id=NEW.credential_profile_id
                AND c.tenant_id=NEW.tenant_id AND c.region_id=NEW.region_id)
            THEN RAISE EXCEPTION 'Managed AI custody namespace mismatch'; END IF;
            RETURN NEW;
        END; $$"""))
        op.execute(sa.text(f"CREATE TRIGGER icheck_ai_managed_connection_guard BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION icheck_guard_ai_managed_connection()"))


def downgrade():
    if op.get_bind().execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot discard managed AI credential custody")
    op.drop_table(TABLE)
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_ai_managed_connection()"))
