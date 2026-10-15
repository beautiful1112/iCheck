"""Retain reviewed native Prometheus rule versions and uncertain outcomes."""
from alembic import op
import sqlalchemy as sa

revision="u8z0b2d4f6h9"
down_revision="t7x9z1c3e5g8"
branch_labels=depends_on=None


def upgrade():
    op.create_table("metric_rule_changes",
        sa.Column("id",sa.String(36),primary_key=True),
        sa.Column("tenant_id",sa.String(36),nullable=False,server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id",sa.String(36),nullable=False,server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("rule_id",sa.String(36),sa.ForeignKey("alert_rules.id",ondelete="RESTRICT"),nullable=False),
        sa.Column("expected_revision",sa.Integer(),nullable=False),
        sa.Column("definition",sa.JSON(),nullable=False),
        sa.Column("target_snapshot",sa.JSON(),nullable=False),
        sa.Column("backend_revision",sa.Integer(),nullable=False),
        sa.Column("compiled_rule",sa.JSON(),nullable=False),
        sa.Column("catalog_before",sa.JSON(),nullable=False),
        sa.Column("catalog_after",sa.JSON(),nullable=False),
        sa.Column("runtime_before_hash",sa.String(64),nullable=False),
        sa.Column("runtime_binding",sa.JSON(),nullable=False),
        sa.Column("plan_hash",sa.String(64),nullable=False),
        sa.Column("status",sa.String(16),nullable=False),
        sa.Column("previous_definition",sa.JSON(),nullable=True),
        sa.Column("restore_of_id",sa.String(36),sa.ForeignKey("metric_rule_changes.id",ondelete="RESTRICT"),nullable=True),
        sa.Column("approved_by",sa.String(255),nullable=True),
        sa.Column("error_code",sa.String(64),nullable=True),
        sa.Column("created_by",sa.String(255),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),
        sa.Column("applied_at",sa.DateTime(timezone=True),nullable=True),
        sa.CheckConstraint("status IN ('proposed','applying','applied','conflict','unknown','rejected')",name="ck_metric_rule_change_status"),
        sa.CheckConstraint("expected_revision >= 0",name="ck_metric_rule_expected_revision"))
    for column in ("tenant_id","region_id","rule_id","plan_hash","status"):
        op.create_index("ix_metric_rule_changes_"+column,"metric_rule_changes",[column])
    if op.get_bind().dialect.name=="postgresql":
        op.execute(sa.text("ALTER TABLE metric_rule_changes ENABLE ROW LEVEL SECURITY"))
        predicate="tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON metric_rule_changes USING ({predicate}) WITH CHECK ({predicate})"))
        fixed=("id","tenant_id","region_id","rule_id","expected_revision","definition","target_snapshot","backend_revision","compiled_rule",
            "catalog_before","catalog_after","runtime_before_hash","runtime_binding","plan_hash","previous_definition","restore_of_id","created_by","created_at")
        json_fields={"definition","target_snapshot","compiled_rule","catalog_before","catalog_after","runtime_binding","previous_definition"}
        predicate=" OR ".join("NEW."+key+("::jsonb" if key in json_fields else "")+" IS DISTINCT FROM OLD."+key+("::jsonb" if key in json_fields else "") for key in fixed)
        op.execute(sa.text("""CREATE FUNCTION icheck_guard_metric_rule_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Metric rule history cannot be discarded'; END IF;
            IF NOT EXISTS(SELECT 1 FROM alert_rules r WHERE r.id=NEW.rule_id AND r.event_type='metric.prometheus'
                AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id) THEN RAISE EXCEPTION 'Metric rule namespace mismatch'; END IF;
            IF NEW.restore_of_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM metric_rule_changes p WHERE p.id=NEW.restore_of_id
                AND p.rule_id=NEW.rule_id AND p.tenant_id=NEW.tenant_id AND p.region_id=NEW.region_id)
                THEN RAISE EXCEPTION 'Metric rule restore identity mismatch'; END IF;
            IF TG_OP='UPDATE' AND ("""+predicate+""" OR OLD.status IN ('applied','conflict','rejected'))
                THEN RAISE EXCEPTION 'Reviewed metric rule plan and terminal history are immutable'; END IF;
            RETURN NEW; END; $$"""))
        op.execute(sa.text("CREATE TRIGGER icheck_metric_rule_change_guard BEFORE INSERT OR UPDATE OR DELETE ON metric_rule_changes FOR EACH ROW EXECUTE FUNCTION icheck_guard_metric_rule_change()"))


def downgrade():
    if op.get_bind().execute(sa.text("SELECT 1 FROM metric_rule_changes LIMIT 1")).first():
        raise RuntimeError("Retained metric rule proposals/history block downgrade")
    op.drop_table("metric_rule_changes")
    if op.get_bind().dialect.name=="postgresql": op.execute(sa.text("DROP FUNCTION icheck_guard_metric_rule_change()"))
