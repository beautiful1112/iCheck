"""Reviewed native MCP installations and selected-target test receipts."""
from alembic import op
import sqlalchemy as sa

revision = "w0c2e4g6i8k1"
down_revision = "v9b1d3f5h7j0"
branch_labels = depends_on = None


def namespace():
    return [sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002")]


def upgrade():
    op.create_table("managed_extension_installations", sa.Column("id", sa.String(36), primary_key=True), *namespace(),
        sa.Column("artifact_id", sa.String(36), sa.ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("active_version_id", sa.String(36), sa.ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("previous_version_id", sa.String(36), sa.ForeignKey("artifact_versions.id", ondelete="RESTRICT")),
        sa.Column("revision", sa.Integer(), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("bindings", sa.JSON(), nullable=False), sa.Column("previous_bindings", sa.JSON(), nullable=False),
        sa.Column("tool_ids", sa.JSON(), nullable=False), sa.Column("last_health_status", sa.String(32), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True)), sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "artifact_id", name="uq_managed_extension_artifact"),
        sa.CheckConstraint("revision > 0", name="ck_managed_extension_revision"))
    op.create_table("managed_extension_tests", sa.Column("id", sa.String(36), primary_key=True), *namespace(),
        sa.Column("request_key", sa.String(36), nullable=False),
        sa.Column("artifact_version_id", sa.String(36), sa.ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("version_hash", sa.String(64), nullable=False), sa.Column("tool_name", sa.String(64), nullable=False),
        sa.Column("binding", sa.JSON(), nullable=False), sa.Column("status", sa.String(16), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False), sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("tenant_id", "region_id", "request_key", name="uq_managed_extension_test_request"),
        sa.CheckConstraint("status IN ('running','succeeded','failed')", name="ck_managed_extension_test_status"))
    for table, link in (("managed_extension_installations", "artifact_id"), ("managed_extension_tests", "artifact_version_id")):
        for column in ("tenant_id", "region_id", link):
            op.create_index(f"ix_{table}_{column}", table, [column])
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            scope = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING ({scope}) WITH CHECK ({scope})"))
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("""CREATE FUNCTION icheck_guard_extension_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Extension test history is retained'; END IF;
            IF TG_OP='UPDATE' AND (OLD.status!='running' OR NEW.id!=OLD.id OR NEW.tenant_id!=OLD.tenant_id
                OR NEW.region_id!=OLD.region_id OR NEW.request_key!=OLD.request_key
                OR NEW.artifact_version_id!=OLD.artifact_version_id OR NEW.version_hash!=OLD.version_hash
                OR NEW.tool_name!=OLD.tool_name OR NEW.binding::jsonb!=OLD.binding::jsonb
                OR NEW.created_by!=OLD.created_by OR NEW.created_at!=OLD.created_at)
                THEN RAISE EXCEPTION 'Reviewed extension test identity and terminal result are immutable'; END IF;
            IF NOT EXISTS(SELECT 1 FROM artifact_versions v WHERE v.id=NEW.artifact_version_id
                AND v.tenant_id=NEW.tenant_id AND v.region_id=NEW.region_id)
                THEN RAISE EXCEPTION 'Extension test namespace mismatch'; END IF;
            RETURN NEW; END; $$"""))
        op.execute(sa.text("CREATE TRIGGER icheck_extension_test_guard BEFORE INSERT OR UPDATE OR DELETE ON managed_extension_tests FOR EACH ROW EXECUTE FUNCTION icheck_guard_extension_test()"))
        op.execute(sa.text("""CREATE FUNCTION icheck_guard_extension_installation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Extension installation history is retained'; END IF;
            IF NOT EXISTS(SELECT 1 FROM artifact_versions v WHERE v.id=NEW.active_version_id AND v.artifact_id=NEW.artifact_id
                AND v.tenant_id=NEW.tenant_id AND v.region_id=NEW.region_id)
                OR (NEW.previous_version_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM artifact_versions v
                    WHERE v.id=NEW.previous_version_id AND v.artifact_id=NEW.artifact_id
                    AND v.tenant_id=NEW.tenant_id AND v.region_id=NEW.region_id))
                THEN RAISE EXCEPTION 'Extension installation version or namespace mismatch'; END IF;
            IF TG_OP='UPDATE' AND (NEW.id!=OLD.id OR NEW.artifact_id!=OLD.artifact_id OR NEW.tenant_id!=OLD.tenant_id
                OR NEW.region_id!=OLD.region_id OR NEW.created_by!=OLD.created_by OR NEW.revision<OLD.revision)
                THEN RAISE EXCEPTION 'Extension installation identity is immutable'; END IF;
            RETURN NEW; END; $$"""))
        op.execute(sa.text("CREATE TRIGGER icheck_extension_installation_guard BEFORE INSERT OR UPDATE OR DELETE ON managed_extension_installations FOR EACH ROW EXECUTE FUNCTION icheck_guard_extension_installation()"))


def downgrade():
    for table in ("managed_extension_installations", "managed_extension_tests"):
        if op.get_bind().execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Retained extension installations/tests block downgrade")
    op.drop_table("managed_extension_installations")
    op.drop_table("managed_extension_tests")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_extension_test()"))
        op.execute(sa.text("DROP FUNCTION icheck_guard_extension_installation()"))
