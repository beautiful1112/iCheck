"""Managed device credentials and replay-safe human onboarding receipts."""
from alembic import op
import sqlalchemy as sa
revision = "r5v7x9z1c3e6"
down_revision = "q4u6w8y0b2d5"
branch_labels = depends_on = None


def namespace_columns():
    return [sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
            sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002")]


def upgrade():
    op.create_table("managed_device_credentials", *namespace_columns(),
        sa.Column("credential_profile_id", sa.String(36), sa.ForeignKey("credential_profiles.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False), sa.Column("site", sa.String(128), nullable=False),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=False), sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("credential_profile_id", name="uq_managed_device_profile"),
        sa.CheckConstraint("revision > 0", name="ck_managed_device_revision"))
    op.create_table("device_onboarding_receipts", *namespace_columns(),
        sa.Column("preview_hash", sa.String(64), nullable=False), sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("device_ids", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "preview_hash", name="uq_device_onboarding_receipt"))
    for table in ("managed_device_credentials", "device_onboarding_receipts"):
        for column in ("tenant_id", "region_id"):
            op.create_index(f"ix_{table}_{column}", table, [column])
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate})"))
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("""CREATE FUNCTION icheck_guard_managed_device_credential() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Managed device custody cannot be deleted'; END IF;
        IF TG_OP='UPDATE' AND (NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
          OR NEW.region_id IS DISTINCT FROM OLD.region_id OR NEW.credential_profile_id IS DISTINCT FROM OLD.credential_profile_id
          OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.site IS DISTINCT FROM OLD.site
          OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.revision <> OLD.revision+1)
          THEN RAISE EXCEPTION 'Managed device credential binding/revision is immutable'; END IF;
        IF NOT EXISTS(SELECT 1 FROM credential_profiles p WHERE p.id=NEW.credential_profile_id
          AND p.tenant_id=NEW.tenant_id AND p.region_id=NEW.region_id AND p.provider='managed_device'
          AND p.secret_ref='managed-device://'||NEW.id)
          THEN RAISE EXCEPTION 'Managed device credential namespace mismatch'; END IF;
        RETURN NEW; END; $$"""))
        op.execute(sa.text("CREATE TRIGGER icheck_managed_device_guard BEFORE INSERT OR UPDATE OR DELETE ON managed_device_credentials FOR EACH ROW EXECUTE FUNCTION icheck_guard_managed_device_credential()"))


def downgrade():
    for table in ("managed_device_credentials", "device_onboarding_receipts"):
        if op.get_bind().execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Cannot discard device credential custody or approved onboarding history")
        op.drop_table(table)
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_managed_device_credential()"))
