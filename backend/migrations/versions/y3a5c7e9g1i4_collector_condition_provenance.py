"""Sealed collector-condition origin and interpretation, not closure proof."""
from alembic import op
import sqlalchemy as sa

revision = "y3a5c7e9g1i4"
down_revision = "x2z4b6d8f0h3"
branch_labels = depends_on = None
TABLES = ("collector_condition_admissions", "collector_condition_sources", "collector_condition_receipts")


def namespace_columns():
    return [sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("region_id", sa.String(36), nullable=False)]


def ref(name, target, nullable=False):
    return sa.Column(name, sa.String(36), sa.ForeignKey(target, ondelete="RESTRICT"), nullable=nullable)


def upgrade():
    bind = op.get_bind()
    dependencies = ("collector_deployments", "collector_runs", "knowledge_projections", "agent_executions",
        "collection_envelopes", "artifact_versions", "collector_workers", "alert_condition_states", "alerts", "audit_events")
    if bind.dialect.name == "postgresql":
        for table in dependencies:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Collector condition migration requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE "+", ".join(dependencies)+" IN SHARE ROW EXCLUSIVE MODE"))
    elif bind.dialect.name != "sqlite":
        raise RuntimeError("Collector condition migration requires PostgreSQL or SQLite")
    for sql in (
        "SELECT 1 FROM collector_deployments WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL LIMIT 1",
        "SELECT 1 FROM collector_runs WHERE status='RUNNING' LIMIT 1",
        "SELECT 1 FROM knowledge_projections WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL OR status='PROCESSING' LIMIT 1",
        "SELECT 1 FROM agent_executions WHERE lease_token_hash IS NOT NULL OR status='RUNNING' LIMIT 1",
    ):
        if bind.execute(sa.text(sql)).first():
            raise RuntimeError("Drain Collector, Projection and Agent producers before collector condition upgrade")
    if bind.execute(sa.text("SELECT 1 FROM alerts WHERE dedup_key LIKE 'collector.condition:%' LIMIT 1")).first() or bind.execute(
        sa.text("SELECT 1 FROM alert_condition_states WHERE dedup_key LIKE 'collector.condition:%' LIMIT 1")).first():
        raise RuntimeError("Reconcile legacy reserved Collector condition keys without deleting history")
    op.create_table(TABLES[0], *namespace_columns(),
        ref("envelope_id", "collection_envelopes.id"), ref("run_id", "collector_runs.id"),
        ref("deployment_id", "collector_deployments.id"), ref("artifact_version_id", "artifact_versions.id"),
        ref("worker_id", "collector_workers.id"),
        ref("credential_grant_audit_id", "audit_events.id", nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False), sa.Column("context", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("envelope_id", name="uq_collector_condition_admission_envelope"),
        sa.CheckConstraint("length(payload)<=32768", name="ck_collector_condition_admission_payload"))
    op.create_table(TABLES[1], *namespace_columns(),
        ref("deployment_id", "collector_deployments.id"), ref("artifact_version_id", "artifact_versions.id"),
        sa.Column("assignment_sha256", sa.String(64), nullable=False),
        sa.Column("credential_identity", sa.String(64), nullable=False),
        sa.Column("condition_key", sa.String(64), nullable=False), sa.Column("entity_type", sa.String(64), nullable=False),
        sa.Column("entity_id", sa.String(255), nullable=False), sa.Column("dedup_key", sa.String(512), nullable=False),
        sa.Column("context", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "deployment_id", "artifact_version_id", "assignment_sha256",
            "credential_identity", "condition_key", "entity_type", "entity_id", name="uq_collector_condition_source_generation"),
        sa.UniqueConstraint("tenant_id", "region_id", "dedup_key", name="uq_collector_condition_source_key"))
    op.create_table(TABLES[2], *namespace_columns(),
        ref("admission_id", TABLES[0]+".id"), ref("source_id", TABLES[1]+".id"),
        ref("condition_state_id", "alert_condition_states.id"), ref("alert_id", "alerts.id", nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False), sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("disposition", sa.String(16), nullable=False), sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("admission_id", name="uq_collector_condition_receipt_admission"),
        sa.CheckConstraint("verdict IN ('active','quiet','unknown')", name="ck_collector_condition_receipt_verdict"),
        sa.CheckConstraint("disposition IN ('accepted','stale','duplicate','conflict')", name="ck_collector_condition_receipt_disposition"))
    for table in TABLES:
        for field in ("tenant_id", "region_id"):
            op.create_index(f"ix_{table}_{field}", table, [field])
    for field in ("envelope_id", "run_id", "deployment_id"):
        op.create_index(f"ix_{TABLES[0]}_{field}", TABLES[0], [field])
    op.create_index("ix_collector_condition_source_deployment", TABLES[1], ["tenant_id", "region_id", "deployment_id"])
    op.create_index("ix_collector_condition_receipt_source_time", TABLES[2], ["source_id", "observed_at"])
    admission_reference = """NOT EXISTS(SELECT 1 FROM collection_envelopes e JOIN collector_runs r ON r.id=e.run_id
        JOIN collector_deployments d ON d.id=r.deployment_id JOIN artifact_versions v ON v.id=r.artifact_version_id
        JOIN collector_workers w ON w.id=r.worker_id
        WHERE e.id=NEW.envelope_id AND e.tenant_id=NEW.tenant_id AND e.region_id=NEW.region_id
        AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id AND d.tenant_id=NEW.tenant_id AND d.region_id=NEW.region_id
        AND v.tenant_id=NEW.tenant_id AND v.region_id=NEW.region_id AND w.tenant_id=NEW.tenant_id AND w.region_id=NEW.region_id
        AND r.id=NEW.run_id AND d.id=NEW.deployment_id AND v.id=NEW.artifact_version_id AND w.id=NEW.worker_id
        AND e.kind='OBSERVATION' AND e.type='icheck.collector.condition/v1' AND e.observed_at=NEW.observed_at
        AND r.execution_admitted_at IS NOT NULL AND NEW.observed_at>=r.execution_admitted_at)"""
    source_reference = """NOT EXISTS(SELECT 1 FROM collector_deployments d JOIN artifact_versions v ON v.id=NEW.artifact_version_id
        WHERE d.id=NEW.deployment_id AND d.tenant_id=NEW.tenant_id AND d.region_id=NEW.region_id
        AND v.tenant_id=NEW.tenant_id AND v.region_id=NEW.region_id AND v.status='PUBLISHED')"""
    receipt_reference = """NOT EXISTS(SELECT 1 FROM collector_condition_admissions a
        JOIN collector_condition_sources s ON s.id=NEW.source_id JOIN alert_condition_states c ON c.id=NEW.condition_state_id
        WHERE a.id=NEW.admission_id AND a.tenant_id=NEW.tenant_id AND a.region_id=NEW.region_id
        AND s.tenant_id=NEW.tenant_id AND s.region_id=NEW.region_id AND c.tenant_id=NEW.tenant_id AND c.region_id=NEW.region_id
        AND a.deployment_id=s.deployment_id AND a.artifact_version_id=s.artifact_version_id AND a.observed_at=NEW.observed_at
        AND c.dedup_key=s.dedup_key AND c.entity_type=s.entity_type AND c.entity_id=s.entity_id
        AND c.source_rule_id IS NULL AND c.latest_alert_id IS NOT DISTINCT FROM NEW.alert_id)"""
    alert_reference = """NEW.dedup_key LIKE 'collector.condition:%' AND NOT EXISTS(SELECT 1 FROM collector_condition_sources s
        WHERE s.dedup_key=NEW.dedup_key AND s.tenant_id=NEW.tenant_id AND s.region_id=NEW.region_id
        AND s.entity_type=NEW.entity_type AND s.entity_id=NEW.entity_id AND NEW.rule_id IS NULL"""
    if bind.dialect.name == "postgresql":
        admission_pins = """NEW.context::jsonb #>> '{pins,deployment,id}' IS DISTINCT FROM NEW.deployment_id
            OR NEW.context::jsonb #>> '{pins,deployment,artifact_version_id}' IS DISTINCT FROM NEW.artifact_version_id
            OR NEW.context::jsonb #>> '{pins,worker,id}' IS DISTINCT FROM NEW.worker_id
            OR NOT EXISTS(SELECT 1 FROM collector_runs r WHERE r.id=NEW.run_id
                AND r.assignment_sha256=NEW.context::jsonb #>> '{pins,assignment_sha256}')
            OR NEW.context::jsonb->>'credential_grant_audit_id' IS DISTINCT FROM NEW.credential_grant_audit_id
            OR (NEW.credential_grant_audit_id IS NULL AND NEW.context::jsonb #> '{pins,credential_profile}' IS DISTINCT FROM 'null'::jsonb)
            OR (NEW.credential_grant_audit_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM audit_events g
                WHERE g.id=NEW.credential_grant_audit_id AND g.tenant_id=NEW.tenant_id AND g.region_id=NEW.region_id
                AND g.event_type='credential.grant.issued' AND g.entity_type='collector_run' AND g.entity_id=NEW.run_id
                AND g.actor_id=NEW.worker_id AND g.occurred_at<=NEW.observed_at
                AND g.details::jsonb->>'profile_id'=NEW.context::jsonb #>> '{pins,credential_profile,profile_id}'
                AND g.details::jsonb->'profile_revision'=NEW.context::jsonb #> '{pins,credential_profile,profile_revision}'))"""
        source_pins = """NEW.context::jsonb->>'assignment_sha256' IS DISTINCT FROM NEW.assignment_sha256
            OR NEW.context::jsonb #>> '{deployment,id}' IS DISTINCT FROM NEW.deployment_id
            OR NEW.context::jsonb #>> '{deployment,artifact_version_id}' IS DISTINCT FROM NEW.artifact_version_id
            OR NEW.context::jsonb #>> '{entity,type}' IS DISTINCT FROM NEW.entity_type
            OR NEW.credential_identity IS DISTINCT FROM (CASE WHEN NEW.context::jsonb->'credential_profile'='null'::jsonb
                THEN 'none' ELSE (NEW.context::jsonb #>> '{credential_profile,profile_id}')||':'||(NEW.context::jsonb #>> '{credential_profile,profile_revision}') END)
            OR NOT EXISTS(SELECT 1 FROM collector_condition_admissions a
                WHERE a.tenant_id=NEW.tenant_id AND a.region_id=NEW.region_id
                AND a.deployment_id=NEW.deployment_id AND a.artifact_version_id=NEW.artifact_version_id
                AND ((a.context::jsonb->'pins') - 'worker' - 'independently_verified' - 'authorizes_incident_closure')=NEW.context::jsonb)"""
        receipt_pins = """NOT EXISTS(SELECT 1 FROM collector_condition_admissions a
                JOIN collector_condition_sources s ON s.id=NEW.source_id
                JOIN alert_condition_states c ON c.id=NEW.condition_state_id
                WHERE a.id=NEW.admission_id
                AND ((a.context::jsonb->'pins') - 'worker' - 'independently_verified' - 'authorizes_incident_closure')=s.context::jsonb
                AND c.event_type=s.context::jsonb #>> '{definition,event_type}')
            OR NEW.result::jsonb->>'contract' IS DISTINCT FROM 'icheck.collector.condition/v1'
            OR NEW.result::jsonb->>'receipt_id' IS DISTINCT FROM NEW.id
            OR NEW.result::jsonb->>'admission_id' IS DISTINCT FROM NEW.admission_id
            OR NEW.result::jsonb->>'source_id' IS DISTINCT FROM NEW.source_id
            OR NEW.result::jsonb->>'alert_id' IS DISTINCT FROM NEW.alert_id
            OR NEW.result::jsonb->>'verdict' IS DISTINCT FROM NEW.verdict
            OR NEW.result::jsonb->>'observation_disposition' IS DISTINCT FROM NEW.disposition"""
        for table in TABLES:
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"""CREATE POLICY icheck_namespace_isolation ON {table}
                USING (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))
                WITH CHECK (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))"""))
        op.execute(sa.text(f"""CREATE FUNCTION icheck_guard_collector_condition_history() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP!='INSERT' THEN RAISE EXCEPTION 'Collector condition history is append-only'; END IF;
            IF TG_TABLE_NAME='{TABLES[0]}' THEN
                IF {admission_reference} OR {admission_pins} OR length(NEW.context::text)>131072
                    OR NEW.context::jsonb #> '{{pins,independently_verified}}' IS DISTINCT FROM 'false'::jsonb
                    OR NEW.context::jsonb #> '{{pins,authorizes_incident_closure}}' IS DISTINCT FROM 'false'::jsonb THEN
                    RAISE EXCEPTION 'Collector condition admission crosses origin or claims unearned authority'; END IF;
            ELSIF TG_TABLE_NAME='{TABLES[1]}' THEN
                IF {source_reference} OR {source_pins} OR NEW.dedup_key<>'collector.condition:'||NEW.id
                    OR length(NEW.assignment_sha256)<>64 OR length(NEW.context::text)>131072
                    OR NEW.context::jsonb->'entity'->>'id' IS DISTINCT FROM NEW.entity_id
                    OR NEW.context::jsonb->'definition'->>'entity_type' IS DISTINCT FROM NEW.entity_type
                    OR NOT EXISTS(SELECT 1 FROM artifact_versions v,
                        jsonb_array_elements(v.definition::jsonb->'condition_contracts') item
                        WHERE v.id=NEW.artifact_version_id AND item=NEW.context::jsonb->'definition'
                        AND item->>'key'=NEW.condition_key AND v.content_hash=NEW.context::jsonb->>'version_content_hash') THEN
                    RAISE EXCEPTION 'Collector condition source crosses declared definition or namespace'; END IF;
            ELSE
                IF {receipt_reference} OR {receipt_pins}
                    OR NEW.result::jsonb->'independently_verified' IS DISTINCT FROM 'false'::jsonb
                    OR NEW.result::jsonb->'authorizes_incident_closure' IS DISTINCT FROM 'false'::jsonb
                    OR (NEW.alert_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM alerts x JOIN collector_condition_sources s ON s.id=NEW.source_id
                        WHERE x.id=NEW.alert_id AND x.tenant_id=NEW.tenant_id AND x.region_id=NEW.region_id AND x.dedup_key=s.dedup_key)) THEN
                    RAISE EXCEPTION 'Collector condition receipt crosses source or claims unearned authority'; END IF;
            END IF; RETURN NEW; END; $$"""))
        for table in TABLES:
            op.execute(sa.text(f"CREATE TRIGGER icheck_guard_collector_condition_history BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_guard_collector_condition_history()"))
        op.execute(sa.text(f"""CREATE FUNCTION icheck_guard_collector_condition_alert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF {alert_reference} AND s.context::jsonb->'definition'->>'event_type'=NEW.event_type) THEN
                RAISE EXCEPTION 'Reserved Collector Alert key crosses source'; END IF; RETURN NEW; END; $$"""))
        op.execute(sa.text("CREATE TRIGGER icheck_guard_collector_condition_alert BEFORE INSERT OR UPDATE ON alerts FOR EACH ROW EXECUTE FUNCTION icheck_guard_collector_condition_alert()"))
    else:
        # SQLite accepts IS NOT DISTINCT FROM too, but use IS for older
        # installations while retaining null-safe pointer equality.
        receipt_reference = receipt_reference.replace("IS NOT DISTINCT FROM", "IS")
        admission_pins = """json_extract(NEW.context,'$.pins.deployment.id') IS NOT NEW.deployment_id
            OR json_extract(NEW.context,'$.pins.deployment.artifact_version_id') IS NOT NEW.artifact_version_id
            OR json_extract(NEW.context,'$.pins.worker.id') IS NOT NEW.worker_id
            OR NOT EXISTS(SELECT 1 FROM collector_runs r WHERE r.id=NEW.run_id
                AND r.assignment_sha256=json_extract(NEW.context,'$.pins.assignment_sha256'))
            OR json_extract(NEW.context,'$.credential_grant_audit_id') IS NOT NEW.credential_grant_audit_id
            OR (NEW.credential_grant_audit_id IS NULL AND json_type(NEW.context,'$.pins.credential_profile') IS NOT 'null')
            OR (NEW.credential_grant_audit_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM audit_events g
                WHERE g.id=NEW.credential_grant_audit_id AND g.tenant_id=NEW.tenant_id AND g.region_id=NEW.region_id
                AND g.event_type='credential.grant.issued' AND g.entity_type='collector_run' AND g.entity_id=NEW.run_id
                AND g.actor_id=NEW.worker_id AND g.occurred_at<=NEW.observed_at
                AND json_extract(g.details,'$.profile_id')=json_extract(NEW.context,'$.pins.credential_profile.profile_id')
                AND json_extract(g.details,'$.profile_revision')=json_extract(NEW.context,'$.pins.credential_profile.profile_revision')))"""
        pin_fields = ("definition", "version_content_hash", "version_material", "assignment_sha256", "deployment", "credential_profile", "entity")
        source_match = " AND ".join(
            f"json_extract(a.context,'$.pins.{field}') IS json_extract(NEW.context,'$.{field}')" for field in pin_fields)
        receipt_match = " AND ".join(
            f"json_extract(a.context,'$.pins.{field}') IS json_extract(s.context,'$.{field}')" for field in pin_fields)
        source_pins = f"""json_extract(NEW.context,'$.assignment_sha256') IS NOT NEW.assignment_sha256
            OR json_type(NEW.context) IS NOT 'object' OR (SELECT count(*) FROM json_each(NEW.context))<>7
            OR EXISTS(SELECT 1 FROM json_each(NEW.context) WHERE key NOT IN
                ('definition','version_content_hash','version_material','assignment_sha256','deployment','credential_profile','entity'))
            OR json_extract(NEW.context,'$.deployment.id') IS NOT NEW.deployment_id
            OR json_extract(NEW.context,'$.deployment.artifact_version_id') IS NOT NEW.artifact_version_id
            OR json_extract(NEW.context,'$.entity.type') IS NOT NEW.entity_type
            OR NEW.credential_identity IS NOT (CASE WHEN json_type(NEW.context,'$.credential_profile')='null'
                THEN 'none' ELSE json_extract(NEW.context,'$.credential_profile.profile_id')||':'||json_extract(NEW.context,'$.credential_profile.profile_revision') END)
            OR NOT EXISTS(SELECT 1 FROM collector_condition_admissions a
                WHERE a.tenant_id=NEW.tenant_id AND a.region_id=NEW.region_id
                AND a.deployment_id=NEW.deployment_id AND a.artifact_version_id=NEW.artifact_version_id AND {source_match})"""
        receipt_pins = f"""NOT EXISTS(SELECT 1 FROM collector_condition_admissions a
                JOIN collector_condition_sources s ON s.id=NEW.source_id
                JOIN alert_condition_states c ON c.id=NEW.condition_state_id
                WHERE a.id=NEW.admission_id AND {receipt_match}
                AND c.event_type=json_extract(s.context,'$.definition.event_type'))
            OR json_extract(NEW.result,'$.contract') IS NOT 'icheck.collector.condition/v1'
            OR json_extract(NEW.result,'$.receipt_id') IS NOT NEW.id
            OR json_extract(NEW.result,'$.admission_id') IS NOT NEW.admission_id
            OR json_extract(NEW.result,'$.source_id') IS NOT NEW.source_id
            OR json_extract(NEW.result,'$.alert_id') IS NOT NEW.alert_id
            OR json_extract(NEW.result,'$.verdict') IS NOT NEW.verdict
            OR json_extract(NEW.result,'$.observation_disposition') IS NOT NEW.disposition"""
        checks = {
            TABLES[0]: f"""({admission_reference}) OR {admission_pins} OR length(NEW.context)>131072
                OR json_type(NEW.context,'$.pins.independently_verified') IS NOT 'false'
                OR json_type(NEW.context,'$.pins.authorizes_incident_closure') IS NOT 'false'""",
            TABLES[1]: f"""({source_reference}) OR {source_pins} OR NEW.dedup_key<>'collector.condition:'||NEW.id
                OR length(NEW.assignment_sha256)<>64 OR length(NEW.context)>131072
                OR json_extract(NEW.context,'$.entity.id') IS NOT NEW.entity_id
                OR json_extract(NEW.context,'$.definition.entity_type') IS NOT NEW.entity_type
                OR NOT EXISTS(SELECT 1 FROM artifact_versions v,json_each(v.definition,'$.condition_contracts') item
                    WHERE v.id=NEW.artifact_version_id AND json(item.value)=json_extract(NEW.context,'$.definition')
                    AND json_extract(item.value,'$.key')=NEW.condition_key
                    AND v.content_hash=json_extract(NEW.context,'$.version_content_hash'))""",
            TABLES[2]: f"""({receipt_reference}) OR {receipt_pins}
                OR json_type(NEW.result,'$.independently_verified') IS NOT 'false'
                OR json_type(NEW.result,'$.authorizes_incident_closure') IS NOT 'false'
                OR (NEW.alert_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM alerts x JOIN collector_condition_sources s ON s.id=NEW.source_id
                    WHERE x.id=NEW.alert_id AND x.tenant_id=NEW.tenant_id AND x.region_id=NEW.region_id AND x.dedup_key=s.dedup_key))""",
        }
        for table in TABLES:
            for action in ("UPDATE", "DELETE"):
                op.execute(sa.text(f"CREATE TRIGGER icheck_{table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'Collector condition history is append-only'); END"))
            op.execute(sa.text(f"CREATE TRIGGER icheck_{table}_reference BEFORE INSERT ON {table} WHEN {checks[table]} BEGIN SELECT RAISE(ABORT,'Collector condition reference or authority has drifted'); END"))
        for table in (TABLES[0], TABLES[2]):
            op.execute(sa.text(f"""CREATE TRIGGER icheck_{table}_clock BEFORE INSERT ON {table}
                WHEN length(NEW.observed_at)<>26
                    OR NEW.observed_at NOT GLOB '????-??-?? ??:??:??.??????'
                    OR substr(NEW.observed_at,21,6) GLOB '*[^0-9]*'
                    OR strftime('%Y-%m-%d %H:%M:%S',substr(NEW.observed_at,1,19)) IS NOT substr(NEW.observed_at,1,19)
                BEGIN SELECT RAISE(ABORT,'Collector condition timestamp must be canonical UTC'); END"""))
        for action in ("INSERT", "UPDATE"):
            op.execute(sa.text(f"""CREATE TRIGGER icheck_collector_condition_alert_{action.lower()} BEFORE {action} ON alerts WHEN
                {alert_reference} AND json_extract(s.context,'$.definition.event_type')=NEW.event_type)
                BEGIN SELECT RAISE(ABORT,'Reserved Collector Alert key crosses source'); END"""))


def downgrade():
    bind = op.get_bind()
    for table in TABLES:
        if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
            raise RuntimeError("Collector condition downgrade requires visibility of all namespaces")
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Cannot downgrade recorded Collector condition provenance")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP TRIGGER icheck_guard_collector_condition_alert ON alerts"))
        op.execute(sa.text("DROP FUNCTION icheck_guard_collector_condition_alert()"))
    else:
        for action in ("insert", "update"):
            op.execute(sa.text(f"DROP TRIGGER icheck_collector_condition_alert_{action}"))
    for table in reversed(TABLES):
        op.drop_table(table)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_collector_condition_history()"))
