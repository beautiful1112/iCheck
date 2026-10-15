"""Encrypted, namespace-scoped configuration backup custody for native extensions."""
from alembic import op
import sqlalchemy as sa

revision = "v9b1d3f5h7j0"
down_revision = "u8z0b2d4f6h9"
branch_labels = depends_on = None


def upgrade():
    op.create_table("extension_configuration_backups",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("artifact_version_id", sa.String(36), sa.ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("connection_id", sa.String(36), sa.ForeignKey("device_connections.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("tool_name", sa.String(64), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("byte_count", sa.Integer(), nullable=False),
        sa.Column("encrypted_body", sa.LargeBinary(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("byte_count BETWEEN 1 AND 1000000", name="ck_extension_backup_size"))
    for column in ("tenant_id", "region_id", "artifact_version_id", "device_id", "connection_id"):
        op.create_index("ix_extension_configuration_backups_" + column, "extension_configuration_backups", [column])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("ALTER TABLE extension_configuration_backups ENABLE ROW LEVEL SECURITY"))
        predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON extension_configuration_backups USING ({predicate}) WITH CHECK ({predicate})"))
        op.execute(sa.text("""CREATE FUNCTION icheck_guard_extension_backup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP != 'INSERT' THEN RAISE EXCEPTION 'Configuration backup history is immutable'; END IF;
            IF NOT EXISTS(SELECT 1 FROM devices d JOIN device_connections c ON c.device_id=d.id
                WHERE d.id=NEW.device_id AND c.id=NEW.connection_id AND d.tenant_id=NEW.tenant_id
                AND d.region_id=NEW.region_id AND c.tenant_id=NEW.tenant_id AND c.region_id=NEW.region_id)
                OR NOT EXISTS(SELECT 1 FROM artifact_versions v WHERE v.id=NEW.artifact_version_id
                    AND v.tenant_id=NEW.tenant_id AND v.region_id=NEW.region_id)
                THEN RAISE EXCEPTION 'Configuration backup namespace or target mismatch'; END IF;
            RETURN NEW; END; $$"""))
        op.execute(sa.text("CREATE TRIGGER icheck_extension_backup_guard BEFORE INSERT OR UPDATE OR DELETE ON extension_configuration_backups FOR EACH ROW EXECUTE FUNCTION icheck_guard_extension_backup()"))


def downgrade():
    if op.get_bind().execute(sa.text("SELECT 1 FROM extension_configuration_backups LIMIT 1")).first():
        raise RuntimeError("Retained encrypted configuration backups block downgrade")
    op.drop_table("extension_configuration_backups")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_extension_backup()"))
