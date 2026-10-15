"""Native Grafana connection custody and retained confirmed dashboard changes."""
from alembic import op
import sqlalchemy as sa

revision = "t7x9z1c3e5g8"
down_revision = "s6w8y0b2d4f7"
branch_labels = depends_on = None


def namespace_columns():
    return [sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002")]


def upgrade():
    op.create_table("grafana_connections", *namespace_columns(),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("api_url", sa.String(2048), nullable=False),
        sa.Column("public_url", sa.String(2048), nullable=False),
        sa.Column("datasource_uid", sa.String(64), nullable=False),
        sa.Column("folder_uid", sa.String(64), nullable=False),
        sa.Column("encrypted_token", sa.LargeBinary(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("shared_dataset_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "name", name="uq_grafana_connection_name"),
        sa.CheckConstraint("revision > 0", name="ck_grafana_connection_revision"))
    op.create_table("grafana_changes", *namespace_columns(),
        sa.Column("connection_id", sa.String(36), sa.ForeignKey("grafana_connections.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("connection_revision", sa.Integer(), nullable=False),
        sa.Column("connection_snapshot", sa.JSON(), nullable=False),
        sa.Column("resource_kind", sa.String(16), nullable=False),
        sa.Column("resource_uid", sa.String(64), nullable=False),
        sa.Column("folder_uid", sa.String(64), nullable=False),
        sa.Column("definition", sa.JSON(), nullable=False),
        sa.Column("previous_resource", sa.JSON(), nullable=True),
        sa.Column("expected_resource_version", sa.String(128), nullable=True),
        sa.Column("plan_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("applied_resource", sa.JSON(), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("restore_of_id", sa.String(36), sa.ForeignKey("grafana_changes.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("resource_kind IN ('dashboard','folder')", name="ck_grafana_change_kind"),
        sa.CheckConstraint("status IN ('proposed','applying','applied','conflict','unknown','rejected')", name="ck_grafana_change_status"))
    for table in ("grafana_connections", "grafana_changes"):
        for column in ("tenant_id", "region_id"):
            op.create_index(f"ix_{table}_{column}", table, [column])
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate})"))
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("""CREATE FUNCTION icheck_guard_grafana_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Grafana proposal/history cannot be discarded'; END IF;
            IF NOT EXISTS(SELECT 1 FROM grafana_connections c WHERE c.id=NEW.connection_id
                AND c.tenant_id=NEW.tenant_id AND c.region_id=NEW.region_id)
                THEN RAISE EXCEPTION 'Grafana connection namespace mismatch'; END IF;
            IF NEW.restore_of_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM grafana_changes p
                WHERE p.id=NEW.restore_of_id AND p.connection_id=NEW.connection_id
                AND p.tenant_id=NEW.tenant_id AND p.region_id=NEW.region_id)
                THEN RAISE EXCEPTION 'Grafana restore namespace mismatch'; END IF;
            IF TG_OP='UPDATE' AND (
                NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                OR NEW.region_id IS DISTINCT FROM OLD.region_id OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
                OR NEW.connection_revision IS DISTINCT FROM OLD.connection_revision
                OR NEW.connection_snapshot::jsonb IS DISTINCT FROM OLD.connection_snapshot::jsonb
                OR NEW.resource_kind IS DISTINCT FROM OLD.resource_kind OR NEW.resource_uid IS DISTINCT FROM OLD.resource_uid
                OR NEW.folder_uid IS DISTINCT FROM OLD.folder_uid OR NEW.definition::jsonb IS DISTINCT FROM OLD.definition::jsonb
                OR NEW.previous_resource::jsonb IS DISTINCT FROM OLD.previous_resource::jsonb
                OR NEW.expected_resource_version IS DISTINCT FROM OLD.expected_resource_version
                OR NEW.plan_hash IS DISTINCT FROM OLD.plan_hash OR NEW.restore_of_id IS DISTINCT FROM OLD.restore_of_id
                OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at IS DISTINCT FROM OLD.created_at
                OR OLD.status IN ('applied','conflict','rejected'))
                THEN RAISE EXCEPTION 'Reviewed Grafana plan or terminal history is immutable'; END IF;
            RETURN NEW;
        END; $$"""))
        op.execute(sa.text("CREATE TRIGGER icheck_grafana_change_guard BEFORE INSERT OR UPDATE OR DELETE ON grafana_changes FOR EACH ROW EXECUTE FUNCTION icheck_guard_grafana_change()"))


def downgrade():
    # Secrets and rollback history must not silently disappear in a binary rollback.
    for table in ("grafana_changes", "grafana_connections"):
        if op.get_bind().execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Retained Grafana custody/history blocks downgrade")
        op.drop_table(table)
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_grafana_change()"))
