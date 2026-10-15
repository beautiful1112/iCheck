"""Immutable report reader admissions and exact retained domain references."""
from alembic import op
import sqlalchemy as sa

revision = "i3k5m7o9q1s4"
down_revision = "h2j4l6n8p0r3"
branch_labels = depends_on = None
ADMISSIONS = "report_proof_admissions"
REFERENCES = "report_instance_proof_references"
PARENTS = ("service_report_instances", "report_attachments", "agent_executions",
    "collector_source_replacement_requests", "collector_source_retirements", "situation_closure_receipts")


def _visible_drained(bind):
    if bind.dialect.name == "postgresql":
        if any(bind.execute(sa.text("SELECT row_security_active(:table)"), {"table":table}).scalar() for table in PARENTS):
            raise RuntimeError("Retained report migration requires all-namespace visibility")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE " + ", ".join(PARENTS) + " IN ACCESS EXCLUSIVE MODE"))
    if bind.execute(sa.text("SELECT 1 FROM agent_executions WHERE lease_token_hash IS NOT NULL OR status='RUNNING' LIMIT 1")).first():
        raise RuntimeError("Drain API and Agent ownership before retained report migration")


def _namespace_columns():
    return [sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002")]


def _native_guards():
    op.execute(sa.text("""CREATE FUNCTION icheck_report_proof_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE r service_report_instances%ROWTYPE; item jsonb; found_reference boolean; pid text; target text; domain_table text;
    BEGIN
        IF TG_TABLE_NAME='service_report_instances' THEN
            IF TG_OP='UPDATE' AND OLD.snapshot->>'format_version'='icheck.service-health-report-render/v2' THEN
                IF to_jsonb(NEW)<>to_jsonb(OLD) THEN RAISE EXCEPTION 'Retained proof report is immutable'; END IF;
                RETURN NEW;
            END IF;
            RETURN NEW;
        END IF;
        IF TG_OP='DELETE' THEN
            IF EXISTS(SELECT 1 FROM service_report_instances WHERE id=OLD.instance_id) THEN
                RAISE EXCEPTION 'Retained report metadata cannot be removed while its report exists'; END IF;
            RETURN OLD;
        END IF;
        IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'Retained report admission/reference is immutable'; END IF;
        SELECT * INTO r FROM service_report_instances WHERE id=NEW.instance_id
            AND tenant_id=NEW.tenant_id AND region_id=NEW.region_id;
        IF r.id IS NULL OR r.snapshot->>'format_version' IS DISTINCT FROM 'icheck.service-health-report-render/v2'
            THEN RAISE EXCEPTION 'Retained report parent or namespace is invalid'; END IF;
        IF TG_TABLE_NAME='report_proof_admissions' THEN
            pid:=NEW.principal_id;
            IF NEW.reader_snapshot::jsonb IS DISTINCT FROM (r.snapshot::jsonb->'initiating_reader')
                OR NEW.reader_snapshot->>'principal_id' IS DISTINCT FROM pid
                OR NEW.reader_snapshot->>'subject' IS DISTINCT FROM r.created_by
                OR NEW.reader_snapshot->>'principal_type' NOT IN ('user','service')
                OR NOT EXISTS(SELECT 1 FROM control_plane_principals WHERE id=pid AND tenant_id=NEW.tenant_id
                    AND subject=r.created_by AND enabled AND principal_type=NEW.reader_snapshot->>'principal_type')
                OR NOT icheck_source_actor_permission(pid,NEW.tenant_id,NEW.region_id,'services.read')
                OR NOT icheck_source_actor_permission(pid,NEW.tenant_id,NEW.region_id,'alerts.read')
                THEN RAISE EXCEPTION 'Retained report initiating reader is invalid'; END IF;
        ELSE
            found_reference:=false;
            FOR item IN SELECT value FROM jsonb_array_elements(r.snapshot::jsonb->'spec'->'retained_proofs') LOOP
                IF item->>'section_key'<>NEW.section_key THEN CONTINUE; END IF;
                IF NEW.replacement_request_id IS NOT NULL THEN
                    target:=NEW.replacement_request_id; domain_table:='collector_source_replacement_requests';
                    found_reference:=item->>'reference_kind'='source_replacement_request' AND item->>'reference_id'=target;
                ELSIF NEW.retirement_id IS NOT NULL THEN
                    target:=NEW.retirement_id; domain_table:='collector_source_retirements';
                    found_reference:=item->>'reference_kind'='source_retirement' AND item->>'reference_id'=target;
                ELSE target:=NEW.closure_receipt_id; domain_table:='situation_closure_receipts';
                    found_reference:=item->>'reference_kind'='situation_closure_receipt' AND item->>'reference_id'=target;
                END IF;
                EXIT;
            END LOOP;
            IF found_reference IS DISTINCT FROM true THEN RAISE EXCEPTION 'Retained report reference differs from its exact selector'; END IF;
            EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I WHERE id=$1 AND tenant_id=$2 AND region_id=$3)',domain_table)
                INTO found_reference USING target,NEW.tenant_id,NEW.region_id;
            IF NOT found_reference THEN RAISE EXCEPTION 'Retained report reference crosses namespace'; END IF;
        END IF;
        RETURN NEW;
    END $$"""))
    op.execute(sa.text("""CREATE FUNCTION icheck_report_proof_complete() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE r service_report_instances%ROWTYPE; count_refs integer; item jsonb; selector jsonb; recorded jsonb;
        q collector_source_replacement_requests%ROWTYPE; retirement collector_source_retirements%ROWTYPE;
        closure situation_closure_receipts%ROWTYPE; expected jsonb;
    BEGIN
        IF TG_TABLE_NAME='service_report_instances' THEN r:=NEW;
        ELSE SELECT * INTO r FROM service_report_instances WHERE id=NEW.instance_id; END IF;
        IF r.id IS NULL OR r.snapshot->>'format_version' IS DISTINCT FROM 'icheck.service-health-report-render/v2' THEN RETURN NEW; END IF;
        IF jsonb_typeof(r.snapshot::jsonb->'spec'->'retained_proofs') IS DISTINCT FROM 'array'
            OR jsonb_typeof(r.snapshot::jsonb->'retained_proofs') IS DISTINCT FROM 'array'
            OR jsonb_typeof(r.snapshot::jsonb->'spec'->'indicators') IS DISTINCT FROM 'array'
            OR jsonb_typeof(r.snapshot::jsonb->'sections') IS DISTINCT FROM 'array'
            OR r.snapshot::jsonb->'spec'->'proof_contract_version' IS DISTINCT FROM '2'::jsonb
            OR r.snapshot::jsonb->'historical' IS DISTINCT FROM 'true'::jsonb
            OR r.snapshot::jsonb->'grants_future_authority' IS DISTINCT FROM 'false'::jsonb
            THEN RAISE EXCEPTION 'Retained report proof shape or historical-only flags are invalid'; END IF;
        count_refs:=jsonb_array_length(r.snapshot::jsonb->'spec'->'retained_proofs');
        IF count_refs NOT BETWEEN 1 AND 20 OR jsonb_array_length(r.snapshot::jsonb->'retained_proofs')<>count_refs
            OR jsonb_array_length(r.snapshot::jsonb->'spec'->'indicators')>12
            OR count_refs+jsonb_array_length(r.snapshot::jsonb->'spec'->'indicators')>20
            OR jsonb_array_length(r.snapshot::jsonb->'sections')<>jsonb_array_length(r.snapshot::jsonb->'spec'->'indicators')
            OR NOT EXISTS(SELECT 1 FROM report_proof_admissions WHERE instance_id=r.id AND tenant_id=r.tenant_id AND region_id=r.region_id)
            OR (SELECT count(*) FROM report_instance_proof_references WHERE instance_id=r.id AND tenant_id=r.tenant_id AND region_id=r.region_id)<>count_refs
            THEN RAISE EXCEPTION 'Retained report proof admission/references must commit atomically'; END IF;
        FOR item IN SELECT value FROM jsonb_array_elements(r.snapshot::jsonb->'retained_proofs') LOOP
            SELECT value INTO selector FROM jsonb_array_elements(r.snapshot::jsonb->'spec'->'retained_proofs')
                WHERE value->>'section_key'=item->>'section_key';
            recorded:=item->'recorded';
            IF selector IS NULL OR item->>'title' IS DISTINCT FROM selector->>'title'
                OR item->>'reference_kind' IS DISTINCT FROM selector->>'reference_kind'
                OR item->>'reference_id' IS DISTINCT FROM selector->>'reference_id'
                OR recorded->>'id' IS DISTINCT FROM selector->>'reference_id'
                OR item->'historical' IS DISTINCT FROM 'true'::jsonb
                OR item->'grants_future_authority' IS DISTINCT FROM 'false'::jsonb
                OR item->'remediation_causality_proven' IS DISTINCT FROM 'false'::jsonb
                OR item->'physical_truth_automatically_verified' IS DISTINCT FROM 'false'::jsonb
                THEN RAISE EXCEPTION 'Retained report proof selector or non-authorizing flags differ'; END IF;
            IF selector->>'reference_kind'='source_replacement_request' THEN
                SELECT * INTO q FROM collector_source_replacement_requests WHERE id=selector->>'reference_id'
                    AND tenant_id=r.tenant_id AND region_id=r.region_id;
                expected:=(to_jsonb(q)-ARRAY['tenant_id','region_id','created_at','expires_at']) ||
                    jsonb_build_object('authorizes_source_retirement',false,'authorizes_incident_closure',false);
                IF q.id IS NULL OR recorded-ARRAY['created_at','expires_at'] IS DISTINCT FROM expected
                    OR (recorded->>'created_at')::timestamptz IS DISTINCT FROM q.created_at
                    OR (recorded->>'expires_at')::timestamptz IS DISTINCT FROM q.expires_at
                    THEN RAISE EXCEPTION 'Retained report replacement material differs from its immutable record'; END IF;
            ELSIF selector->>'reference_kind'='source_retirement' THEN
                SELECT * INTO retirement FROM collector_source_retirements WHERE id=selector->>'reference_id'
                    AND tenant_id=r.tenant_id AND region_id=r.region_id;
                IF retirement.id IS NULL OR recorded IS DISTINCT FROM retirement.result::jsonb
                    THEN RAISE EXCEPTION 'Retained report retirement material differs from its immutable record'; END IF;
            ELSIF selector->>'reference_kind'='situation_closure_receipt' THEN
                SELECT * INTO closure FROM situation_closure_receipts WHERE id=selector->>'reference_id'
                    AND tenant_id=r.tenant_id AND region_id=r.region_id;
                expected:=(to_jsonb(closure)-ARRAY['tenant_id','region_id','committed_at','ownership_id']) ||
                    jsonb_build_object('historical',true,'grants_future_authority',false,
                        'remediation_causality_proven',false,'physical_truth_automatically_verified',false);
                IF closure.id IS NULL OR recorded-'committed_at' IS DISTINCT FROM expected
                    OR (recorded->>'committed_at')::timestamptz IS DISTINCT FROM closure.committed_at
                    THEN RAISE EXCEPTION 'Retained report closure material differs from its immutable record'; END IF;
            ELSE RAISE EXCEPTION 'Retained report proof kind is unsupported'; END IF;
        END LOOP;
        RETURN NEW;
    END $$"""))
    for table in (ADMISSIONS, REFERENCES):
        op.execute(sa.text(f"CREATE TRIGGER icheck_report_proof_guard BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_report_proof_guard()"))
        op.execute(sa.text(f"CREATE CONSTRAINT TRIGGER icheck_report_proof_complete AFTER INSERT ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION icheck_report_proof_complete()"))
    op.execute(sa.text("CREATE TRIGGER icheck_report_proof_guard BEFORE UPDATE ON service_report_instances FOR EACH ROW EXECUTE FUNCTION icheck_report_proof_guard()"))
    op.execute(sa.text("CREATE CONSTRAINT TRIGGER icheck_report_proof_complete AFTER INSERT OR UPDATE ON service_report_instances DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION icheck_report_proof_complete()"))


def upgrade():
    bind = op.get_bind(); _visible_drained(bind)
    op.create_table(ADMISSIONS,
        sa.Column("instance_id", sa.String(36), sa.ForeignKey("service_report_instances.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("principal_id", sa.String(36), sa.ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("reader_snapshot", sa.JSON(), nullable=False), *_namespace_columns())
    op.create_table(REFERENCES,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("instance_id", sa.String(36), sa.ForeignKey("service_report_instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("section_key", sa.String(128), nullable=False),
        sa.Column("replacement_request_id", sa.String(36), sa.ForeignKey("collector_source_replacement_requests.id", ondelete="RESTRICT")),
        sa.Column("retirement_id", sa.String(36), sa.ForeignKey("collector_source_retirements.id", ondelete="RESTRICT")),
        sa.Column("closure_receipt_id", sa.String(36), sa.ForeignKey("situation_closure_receipts.id", ondelete="RESTRICT")),
        *_namespace_columns(), sa.UniqueConstraint("instance_id", "section_key", name="uq_report_proof_section"),
        sa.CheckConstraint("(replacement_request_id IS NOT NULL AND retirement_id IS NULL AND closure_receipt_id IS NULL) OR (replacement_request_id IS NULL AND retirement_id IS NOT NULL AND closure_receipt_id IS NULL) OR (replacement_request_id IS NULL AND retirement_id IS NULL AND closure_receipt_id IS NOT NULL)", name="ck_report_proof_one_reference"))
    for table, fields in ((ADMISSIONS,("tenant_id","region_id","principal_id")),
        (REFERENCES,("tenant_id","region_id","instance_id","replacement_request_id","retirement_id","closure_receipt_id"))):
        for field in fields: op.create_index(f"ix_{table}_{field}",table,[field])
        if bind.dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
            predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate})"))
    if bind.dialect.name == "postgresql": _native_guards()


def downgrade():
    bind=op.get_bind(); _visible_drained(bind)
    for query in (f"SELECT 1 FROM {ADMISSIONS} LIMIT 1",f"SELECT 1 FROM {REFERENCES} LIMIT 1",
        "SELECT 1 FROM artifact_versions WHERE definition->>'format_version'='icheck.service-health-report/v2' LIMIT 1" if bind.dialect.name=="postgresql" else
        "SELECT 1 FROM artifact_versions WHERE json_extract(definition,'$.format_version')='icheck.service-health-report/v2' LIMIT 1"):
        if bind.execute(sa.text(query)).first(): raise RuntimeError("Cannot downgrade populated retained proof reports or templates")
    if bind.dialect.name=="postgresql":
        for table in ("service_report_instances",ADMISSIONS,REFERENCES):
            op.execute(sa.text(f"DROP TRIGGER icheck_report_proof_guard ON {table}"))
            op.execute(sa.text(f"DROP TRIGGER icheck_report_proof_complete ON {table}"))
        op.execute(sa.text("DROP FUNCTION icheck_report_proof_guard()")); op.execute(sa.text("DROP FUNCTION icheck_report_proof_complete()"))
    op.drop_table(REFERENCES); op.drop_table(ADMISSIONS)
