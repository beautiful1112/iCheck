"""Sealed exact-call citation bindings, not inferred legacy associations."""
from alembic import op
import sqlalchemy as sa

revision = "v0x2z4b6d8f1"
down_revision = "u9w1y3a5c7e0"
branch_labels = depends_on = None
TABLE = "investigation_tool_evidence_bindings"


def upgrade():
    op.create_table(TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("region_id", sa.String(36), nullable=False),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("tool_call_id", sa.String(36), sa.ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("call_snapshot", sa.JSON(), nullable=False),
        sa.Column("reference_snapshot", sa.JSON(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tool_call_id", name="uq_tool_evidence_binding_call"),
        sa.CheckConstraint("length(CAST(call_snapshot AS TEXT)) <= 4096", name="ck_tool_binding_call_size"),
        sa.CheckConstraint("length(CAST(reference_snapshot AS TEXT)) <= 1048576", name="ck_tool_binding_reference_size"))
    for field in ("tenant_id", "region_id", "investigation_id", "tool_call_id"):
        op.create_index(f"ix_{TABLE}_{field}", TABLE, [field])
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)) WITH CHECK (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))"))
        op.execute(sa.text("""CREATE FUNCTION icheck_guard_tool_evidence_binding() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'Tool citation bindings are immutable'; END IF;
            IF jsonb_typeof(NEW.call_snapshot::jsonb) <> 'object'
                OR jsonb_typeof(NEW.reference_snapshot::jsonb) <> 'array' THEN
                RAISE EXCEPTION 'Tool citation binding has invalid shape'; END IF;
            IF jsonb_array_length(NEW.reference_snapshot::jsonb) > 100
                OR (SELECT count(DISTINCT value->>'id') FROM jsonb_array_elements(NEW.reference_snapshot::jsonb))
                    <> jsonb_array_length(NEW.reference_snapshot::jsonb)
                OR NOT EXISTS (SELECT 1 FROM investigation_tool_calls c
                    WHERE c.id=NEW.tool_call_id AND c.investigation_id=NEW.investigation_id
                    AND c.tenant_id=NEW.tenant_id AND c.region_id=NEW.region_id
                    AND c.status='succeeded' AND c.result_hash=NEW.call_snapshot->>'result_hash'
                    AND c.call_hash=NEW.call_snapshot->>'call_hash' AND c.tool_id=NEW.call_snapshot->>'tool_id'
                    AND c.finished_at=(NEW.call_snapshot->>'finished_at')::timestamptz)
                OR EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.reference_snapshot::jsonb) r
                    WHERE jsonb_typeof(r) <> 'object' OR NOT EXISTS
                        (SELECT 1 FROM investigation_evidence e WHERE e.id=r->>'id'
                        AND e.investigation_id=NEW.investigation_id AND e.tenant_id=NEW.tenant_id AND e.region_id=NEW.region_id
                        AND e.evidence_type=r->>'evidence_type' AND e.evidence_id=r->>'evidence_id'
                        AND e.observed_at IS NOT DISTINCT FROM (r->>'observed_at')::timestamptz
                        AND e.created_at=(r->>'created_at')::timestamptz)) THEN
                RAISE EXCEPTION 'Tool citation binding does not match its result or namespace references';
            END IF; RETURN NEW; END; $$"""))
        op.execute(sa.text(f"CREATE TRIGGER icheck_guard_tool_evidence_binding BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION icheck_guard_tool_evidence_binding()"))
    elif dialect == "sqlite":
        for operation in ("UPDATE", "DELETE"):
            op.execute(sa.text(f"CREATE TRIGGER icheck_immutable_tool_evidence_{operation.lower()} BEFORE {operation} ON {TABLE} BEGIN SELECT RAISE(ABORT, 'Tool citation bindings are immutable'); END"))
        op.execute(sa.text(f"""CREATE TRIGGER icheck_guard_tool_evidence_insert BEFORE INSERT ON {TABLE}
            WHEN json_type(NEW.call_snapshot) <> 'object' OR json_type(NEW.reference_snapshot) <> 'array'
            OR json_array_length(NEW.reference_snapshot)>100
            OR (SELECT count(DISTINCT json_extract(value,'$.id')) FROM json_each(NEW.reference_snapshot))<>json_array_length(NEW.reference_snapshot)
            OR NOT EXISTS (SELECT 1 FROM investigation_tool_calls c
                WHERE c.id=NEW.tool_call_id AND c.investigation_id=NEW.investigation_id
                AND c.tenant_id=NEW.tenant_id AND c.region_id=NEW.region_id AND c.status='succeeded'
                AND c.result_hash=json_extract(NEW.call_snapshot,'$.result_hash')
                AND c.call_hash=json_extract(NEW.call_snapshot,'$.call_hash')
                AND c.tool_id=json_extract(NEW.call_snapshot,'$.tool_id')
                AND julianday(c.finished_at)=julianday(json_extract(NEW.call_snapshot,'$.finished_at')))
            OR EXISTS (SELECT 1 FROM json_each(NEW.reference_snapshot) r WHERE r.type<>'object'
                OR NOT EXISTS (SELECT 1 FROM investigation_evidence e
                    WHERE e.id=json_extract(r.value,'$.id') AND e.investigation_id=NEW.investigation_id
                    AND e.tenant_id=NEW.tenant_id AND e.region_id=NEW.region_id
                    AND e.evidence_type=json_extract(r.value,'$.evidence_type') AND e.evidence_id=json_extract(r.value,'$.evidence_id')
                    AND julianday(e.observed_at) IS julianday(json_extract(r.value,'$.observed_at'))
                    AND julianday(e.created_at)=julianday(json_extract(r.value,'$.created_at'))))
            BEGIN SELECT RAISE(ABORT, 'Tool citation binding does not match its result or namespace references'); END"""))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": TABLE}).scalar():
        raise RuntimeError("Tool citation downgrade requires visibility of all namespaces")
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade recorded Tool citation history")
    op.drop_table(TABLE)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_tool_evidence_binding()"))
