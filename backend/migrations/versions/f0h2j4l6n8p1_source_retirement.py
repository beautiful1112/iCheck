"""Permanent atomic source retirement and post-mutex producer fencing; drained."""
from alembic import op
import sqlalchemy as sa

revision = "f0h2j4l6n8p1"
down_revision = "e9g1i3k5m7o0"
branch_labels = depends_on = None
TABLE = "collector_source_retirements"
PARENTS = ("collector_deployments", "collector_runs", "knowledge_projections", "agent_executions",
    "collector_condition_sources", "collector_condition_admissions", "collector_condition_receipts",
    "alert_condition_states", "alerts", "situations", "situation_alerts", "situation_closure_ownerships",
    "collector_source_replacement_requests", "collector_source_replacement_reviews",
    "collector_source_replacement_revocations")


def _visible(bind, tables):
    if bind.dialect.name == "postgresql":
        for table in tables:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Source retirement migration requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE " + ", ".join(tables) + " IN ACCESS EXCLUSIVE MODE"))


def upgrade():
    bind = op.get_bind(); pg = bind.dialect.name == "postgresql"
    if bind.dialect.name not in {"postgresql", "sqlite"}:
        raise RuntimeError("Source retirement requires PostgreSQL or SQLite")
    _visible(bind, PARENTS)
    for query in (
        "SELECT 1 FROM collector_deployments WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL LIMIT 1",
        "SELECT 1 FROM collector_runs WHERE status='RUNNING' LIMIT 1",
        "SELECT 1 FROM knowledge_projections WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL OR status='PROCESSING' LIMIT 1",
        "SELECT 1 FROM agent_executions WHERE lease_token_hash IS NOT NULL OR status='RUNNING' LIMIT 1",
        "SELECT 1 FROM situation_closure_ownerships WHERE state='claimed' LIMIT 1",
    ):
        if bind.execute(sa.text(query)).first():
            raise RuntimeError("Drain API/Collector/Projection/Agent and closure ownership before source retirement migration")
    def ref(name, target, nullable=False):
        return sa.Column(name, sa.String(36), sa.ForeignKey(target + ".id", ondelete="RESTRICT"), nullable=nullable)
    op.create_table(TABLE, sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("region_id", sa.String(36), nullable=False),
        ref("request_id", "collector_source_replacement_requests"), ref("review_id", "collector_source_replacement_reviews"),
        ref("old_source_id", "collector_condition_sources"), ref("new_source_id", "collector_condition_sources"),
        ref("old_watermark_receipt_id", "collector_condition_receipts"), ref("new_receipt_id", "collector_condition_receipts"),
        ref("superseded_alert_id", "alerts", True), ref("executor_principal_id", "control_plane_principals"),
        sa.Column("executor_subject", sa.String(255), nullable=False), sa.Column("execution_key", sa.String(128), nullable=False),
        sa.Column("executor_snapshot", sa.JSON(), nullable=False), sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("old_state_snapshot", sa.JSON(), nullable=False), sa.Column("new_state_snapshot", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("old_source_id", name="uq_source_retirement_old_source"),
        sa.UniqueConstraint("request_id", name="uq_source_retirement_request"),
        sa.UniqueConstraint("tenant_id", "region_id", "execution_key", name="uq_source_retirement_execution_key"),
        sa.CheckConstraint("old_source_id <> new_source_id", name="ck_source_retirement_distinct_sources"))
    for column in ("tenant_id", "region_id", "old_source_id", "new_source_id"):
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])
    if pg:
        op.add_column("alerts", sa.Column("source_retirement_id", sa.String(36), nullable=True))
        op.create_foreign_key("fk_alert_source_retirement", "alerts", TABLE, ["source_retirement_id"], ["id"], ondelete="RESTRICT")
        op.add_column("collector_source_replacement_requests", sa.Column("prior_retirement_id", sa.String(36), nullable=True))
        op.create_foreign_key("fk_replacement_prior_retirement", "collector_source_replacement_requests", TABLE, ["prior_retirement_id"], ["id"], ondelete="RESTRICT")
        op.drop_constraint("ck_collector_condition_receipt_disposition", "collector_condition_receipts", type_="check")
        op.create_check_constraint("ck_collector_condition_receipt_disposition", "collector_condition_receipts",
            "disposition IN ('accepted','stale','duplicate','conflict','retired')")
    else:
        # SQLite supports a nullable inline reference on ADD COLUMN without
        # rebuilding Alerts and losing their existing provenance triggers.
        op.execute(sa.text(f"ALTER TABLE alerts ADD COLUMN source_retirement_id VARCHAR(36) REFERENCES {TABLE}(id) ON DELETE RESTRICT"))
        op.execute(sa.text(f"ALTER TABLE collector_source_replacement_requests ADD COLUMN prior_retirement_id VARCHAR(36) REFERENCES {TABLE}(id) ON DELETE RESTRICT"))
        triggers = list(bind.execute(sa.text("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND (tbl_name='collector_condition_receipts' OR instr(sql,'collector_condition_receipts')>0)" )).all())
        for name, _sql in triggers: op.execute(sa.text(f'DROP TRIGGER "{name}"'))
        with op.batch_alter_table("collector_condition_receipts", recreate="always") as batch:
            batch.drop_constraint("ck_collector_condition_receipt_disposition", type_="check")
            batch.create_check_constraint("ck_collector_condition_receipt_disposition",
                "disposition IN ('accepted','stale','duplicate','conflict','retired')")
        for _name, sql in triggers: op.execute(sa.text(sql))
    op.create_index("ix_alerts_source_retirement_id", "alerts", ["source_retirement_id"])
    op.create_index("ix_condition_admission_generation_clock", "collector_condition_admissions",
        ["tenant_id", "region_id", "deployment_id", "artifact_version_id", "observed_at"])
    if pg:
        _postgres()
    else:
        _sqlite()


def _postgres():
    op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)) WITH CHECK (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))"))
    op.execute(sa.text("""CREATE FUNCTION icheck_source_actor_permission(pid text,tid text,rid text,perm text) RETURNS boolean
        LANGUAGE sql STABLE AS $$ SELECT EXISTS(SELECT 1 FROM control_plane_principals p
        JOIN control_plane_role_bindings b ON b.principal_id=p.id JOIN control_plane_roles r ON r.id=b.role_id
        WHERE p.id=pid AND p.tenant_id=tid AND p.enabled
        AND (p.allowed_region_ids::jsonb='[]'::jsonb OR p.allowed_region_ids::jsonb ? rid)
        AND b.tenant_id=tid AND b.region_id=rid AND r.tenant_id=tid AND r.region_id=rid
        AND (r.permissions::jsonb ? perm OR r.permissions::jsonb ? '*')) $$"""))
    op.execute(sa.text("""CREATE FUNCTION icheck_source_actor_global(pid text,tid text,rid text) RETURNS boolean
        LANGUAGE sql STABLE AS $$ SELECT EXISTS(SELECT 1 FROM control_plane_role_bindings b WHERE b.principal_id=pid
        AND b.tenant_id=tid AND b.region_id=rid AND b.scope::jsonb->'all'='true'::jsonb) $$"""))
    op.execute(sa.text("""CREATE FUNCTION icheck_source_device_scope(pid text,tid text,rid text,did text) RETURNS boolean
        LANGUAGE sql STABLE AS $$ SELECT EXISTS(SELECT 1 FROM devices d WHERE d.id=did AND d.tenant_id=tid AND d.region_id=rid
        AND (icheck_source_actor_global(pid,tid,rid) OR EXISTS(SELECT 1 FROM control_plane_role_bindings b
        WHERE b.principal_id=pid AND b.tenant_id=tid AND b.region_id=rid
        AND ((b.scope::jsonb->'device_ids') ? did OR (b.scope::jsonb->'sites') ? d.site)))) $$"""))
    op.execute(sa.text("""CREATE FUNCTION icheck_source_actor_scope(pid text,tid text,rid text,sid text) RETURNS boolean
        LANGUAGE sql STABLE AS $$ SELECT EXISTS(SELECT 1 FROM collector_condition_sources s WHERE s.id=sid
        AND s.tenant_id=tid AND s.region_id=rid AND (icheck_source_actor_global(pid,tid,rid) OR (
        CASE WHEN s.context::jsonb #>> '{deployment,scope_device_id}' IS NOT NULL
            THEN icheck_source_device_scope(pid,tid,rid,s.context::jsonb #>> '{deployment,scope_device_id}')
            WHEN s.context::jsonb #>> '{deployment,scope_site}' IS NOT NULL THEN EXISTS(
                SELECT 1 FROM control_plane_role_bindings b WHERE b.principal_id=pid AND b.tenant_id=tid AND b.region_id=rid
                AND (b.scope::jsonb->'sites') ? (s.context::jsonb #>> '{deployment,scope_site}')) ELSE false END
        AND CASE WHEN s.entity_type='device' THEN icheck_source_device_scope(pid,tid,rid,s.entity_id)
        WHEN s.entity_type='endpoint' THEN EXISTS(SELECT 1 FROM endpoints e WHERE e.id=s.entity_id AND e.tenant_id=tid AND e.region_id=rid
            AND (EXISTS(SELECT 1 FROM ip_address_observations o WHERE o.endpoint_id=e.id AND o.tenant_id=tid AND o.region_id=rid AND icheck_source_device_scope(pid,tid,rid,o.collector_device_id))
                OR EXISTS(SELECT 1 FROM endpoint_attachments o WHERE o.endpoint_id=e.id AND o.tenant_id=tid AND o.region_id=rid AND icheck_source_device_scope(pid,tid,rid,o.collector_device_id))
                OR EXISTS(SELECT 1 FROM wireless_client_sessions o WHERE o.endpoint_id=e.id AND o.tenant_id=tid AND o.region_id=rid AND icheck_source_device_scope(pid,tid,rid,o.controller_id))))
        ELSE false END))) $$"""))
    op.execute(sa.text("""CREATE FUNCTION icheck_source_retirement_fence() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE sid text; ret collector_source_retirements%ROWTYPE; BEGIN
        IF TG_TABLE_NAME='collector_condition_receipts' THEN sid:=NEW.source_id;
        ELSE SELECT id INTO sid FROM collector_condition_sources WHERE dedup_key=CASE WHEN TG_OP='INSERT' THEN NEW.dedup_key ELSE OLD.dedup_key END
            AND tenant_id=CASE WHEN TG_OP='INSERT' THEN NEW.tenant_id ELSE OLD.tenant_id END
            AND region_id=CASE WHEN TG_OP='INSERT' THEN NEW.region_id ELSE OLD.region_id END; END IF;
        IF sid IS NULL THEN
            IF TG_TABLE_NAME='alerts' AND TG_OP<>'DELETE' THEN
                IF NEW.source_retirement_id IS NOT NULL THEN RAISE EXCEPTION 'Alert supersession requires an exact Collector source'; END IF;
            END IF;
            RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
        END IF;
        PERFORM 1 FROM collector_condition_sources WHERE id=sid FOR UPDATE;
        -- Separate post-lock statement gets a fresh READ COMMITTED snapshot.
        SELECT * INTO ret FROM collector_source_retirements WHERE old_source_id=sid;
        IF TG_TABLE_NAME='collector_condition_receipts' THEN
            IF ret.id IS NULL THEN
                IF NEW.disposition='retired' OR NEW.result::jsonb ? 'retirement_id' OR NEW.result::jsonb ? 'source_retired'
                    THEN RAISE EXCEPTION 'Unretired source cannot manufacture retirement evidence'; END IF;
            ELSE
                IF NEW.disposition<>'retired' OR NEW.result::jsonb->>'retirement_id' IS DISTINCT FROM ret.id
                    OR NEW.result::jsonb->'source_retired' IS DISTINCT FROM 'true'::jsonb
                    OR NEW.condition_state_id IS DISTINCT FROM ret.old_state_snapshot::jsonb->>'id'
                    THEN RAISE EXCEPTION 'Retired source cannot commit a current receipt'; END IF;
            END IF;
        ELSIF ret.id IS NOT NULL THEN
            IF TG_TABLE_NAME='alert_condition_states' AND TG_OP='INSERT' AND EXISTS(
                SELECT 1 FROM alert_condition_states c WHERE c.id=ret.old_state_snapshot::jsonb->>'id'
                AND c.dedup_key=NEW.dedup_key AND c.tenant_id=NEW.tenant_id AND c.region_id=NEW.region_id)
                THEN RETURN NEW; END IF;
            IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'Retired source history cannot be recreated or deleted'; END IF;
            IF TG_TABLE_NAME='alerts' THEN
                IF (to_jsonb(NEW)-'source_retirement_id') IS DISTINCT FROM (to_jsonb(OLD)-'source_retirement_id')
                    OR NEW.id IS DISTINCT FROM ret.superseded_alert_id
                    OR NEW.source_retirement_id IS DISTINCT FROM ret.id
                    OR (OLD.source_retirement_id IS NOT NULL AND OLD.source_retirement_id IS DISTINCT FROM NEW.source_retirement_id)
                    THEN RAISE EXCEPTION 'Superseded Alert history is immutable'; END IF;
            ELSIF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
                RAISE EXCEPTION 'Retired source watermark is immutable';
            END IF;
        ELSIF TG_TABLE_NAME='alerts' THEN
            IF NEW.source_retirement_id IS NOT NULL THEN RAISE EXCEPTION 'Alert supersession requires its exact permanent retirement'; END IF;
        END IF;
        RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END; END; $$"""))
    for table in ("collector_condition_receipts", "alerts", "alert_condition_states"):
        actions = "INSERT" if table == "collector_condition_receipts" else "INSERT OR UPDATE OR DELETE"
        op.execute(sa.text(f"CREATE TRIGGER icheck_00_source_retirement_fence BEFORE {actions} ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_source_retirement_fence()"))
    op.execute(sa.text("""CREATE FUNCTION icheck_source_generation_eligibility() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE sid text; prior text; BEGIN
        IF TG_TABLE_NAME='collector_source_replacement_requests' THEN
            PERFORM 1 FROM collector_condition_sources WHERE id IN (NEW.old_source_id,NEW.new_source_id) ORDER BY id FOR UPDATE NOWAIT;
            SELECT id INTO prior FROM collector_source_retirements WHERE old_source_id=NEW.old_source_id;
            IF NEW.prior_retirement_id IS DISTINCT FROM prior OR EXISTS(SELECT 1 FROM collector_source_retirements WHERE old_source_id=NEW.new_source_id)
                THEN RAISE EXCEPTION 'Replacement requires explicit historical retirement and an unretired target'; END IF;
        ELSE
            IF TG_TABLE_NAME='collector_source_qualification_requests' THEN sid:=NEW.source_id;
            ELSE SELECT source_id INTO sid FROM collector_source_qualification_requests WHERE id=NEW.request_id; END IF;
            PERFORM 1 FROM collector_condition_sources WHERE id=sid FOR UPDATE;
            IF EXISTS(SELECT 1 FROM collector_source_retirements WHERE old_source_id=sid)
                THEN RAISE EXCEPTION 'Retired source cannot regain qualification'; END IF;
        END IF; RETURN NEW; END; $$"""))
    for table in ("collector_source_replacement_requests", "collector_source_qualification_requests", "collector_source_qualification_reviews"):
        op.execute(sa.text(f"CREATE TRIGGER icheck_00_source_generation_eligibility BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_source_generation_eligibility()"))
    _postgres_cutover()


def _postgres_cutover():
    op.execute(sa.text("""CREATE FUNCTION icheck_source_snapshot_device(scp jsonb,tid text,rid text,did text) RETURNS boolean
        LANGUAGE sql STABLE AS $$ SELECT EXISTS(SELECT 1 FROM devices d WHERE d.id=did AND d.tenant_id=tid AND d.region_id=rid
        AND (scp->'all'='true'::jsonb OR (scp->'device_ids') ? did OR (scp->'sites') ? d.site)) $$"""))
    op.execute(sa.text("""CREATE FUNCTION icheck_source_snapshot_scope(scp jsonb,tid text,rid text,sid text) RETURNS boolean
        LANGUAGE sql STABLE AS $$ SELECT EXISTS(SELECT 1 FROM collector_condition_sources s WHERE s.id=sid AND s.tenant_id=tid AND s.region_id=rid
        AND (scp->'all'='true'::jsonb OR (CASE WHEN s.context::jsonb #>> '{deployment,scope_device_id}' IS NOT NULL
            THEN icheck_source_snapshot_device(scp,tid,rid,s.context::jsonb #>> '{deployment,scope_device_id}')
            WHEN s.context::jsonb #>> '{deployment,scope_site}' IS NOT NULL THEN (scp->'sites') ? (s.context::jsonb #>> '{deployment,scope_site}')
            ELSE false END AND CASE WHEN s.entity_type='device' THEN icheck_source_snapshot_device(scp,tid,rid,s.entity_id)
            WHEN s.entity_type='endpoint' THEN EXISTS(SELECT 1 FROM endpoints e WHERE e.id=s.entity_id AND e.tenant_id=tid AND e.region_id=rid
                AND (EXISTS(SELECT 1 FROM ip_address_observations o WHERE o.endpoint_id=e.id AND o.tenant_id=tid AND o.region_id=rid AND icheck_source_snapshot_device(scp,tid,rid,o.collector_device_id))
                    OR EXISTS(SELECT 1 FROM endpoint_attachments o WHERE o.endpoint_id=e.id AND o.tenant_id=tid AND o.region_id=rid AND icheck_source_snapshot_device(scp,tid,rid,o.collector_device_id))
                    OR EXISTS(SELECT 1 FROM wireless_client_sessions o WHERE o.endpoint_id=e.id AND o.tenant_id=tid AND o.region_id=rid AND icheck_source_snapshot_device(scp,tid,rid,o.controller_id))))
            ELSE false END))) $$"""))
    op.execute(sa.text("""CREATE FUNCTION icheck_guard_source_retirement() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE dep text; actor text; BEGIN
        IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Source retirement history is append-only'; END IF;
        IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('icheck.closure/v1/'||NEW.tenant_id||'/'||NEW.region_id,0))
            THEN RAISE EXCEPTION 'Source retirement closure fence is busy'; END IF;
        FOR dep IN SELECT DISTINCT deployment_id FROM collector_condition_sources WHERE id IN (NEW.old_source_id,NEW.new_source_id) ORDER BY deployment_id LOOP
            PERFORM 1 FROM collector_deployments WHERE id=dep FOR UPDATE; END LOOP;
        PERFORM 1 FROM collector_condition_sources WHERE id IN (NEW.old_source_id,NEW.new_source_id) ORDER BY id FOR UPDATE NOWAIT;
        PERFORM 1 FROM alert_condition_states WHERE dedup_key IN (SELECT dedup_key FROM collector_condition_sources WHERE id IN (NEW.old_source_id,NEW.new_source_id)) ORDER BY id FOR UPDATE NOWAIT;
        FOR actor IN SELECT DISTINCT id FROM control_plane_principals WHERE id IN (NEW.executor_principal_id,
            (SELECT author_principal_id FROM collector_source_replacement_requests WHERE id=NEW.request_id),
            (SELECT reviewer_principal_id FROM collector_source_replacement_reviews WHERE id=NEW.review_id)) ORDER BY id LOOP
            PERFORM 1 FROM control_plane_principals WHERE id=actor FOR SHARE;
            PERFORM 1 FROM control_plane_role_bindings WHERE principal_id=actor ORDER BY id FOR SHARE;
            PERFORM 1 FROM control_plane_roles WHERE id IN (SELECT role_id FROM control_plane_role_bindings WHERE principal_id=actor) ORDER BY id FOR SHARE;
        END LOOP;
        IF length(NEW.execution_key) NOT BETWEEN 8 AND 128 OR length(NEW.reason) NOT BETWEEN 10 AND 512
            OR NEW.created_at<statement_timestamp()-interval '5 seconds' OR NEW.created_at>clock_timestamp()+interval '5 seconds'
            OR jsonb_typeof(NEW.executor_snapshot::jsonb) IS DISTINCT FROM 'object'
            OR (SELECT count(*) FROM jsonb_object_keys(NEW.executor_snapshot::jsonb))<>2
            OR jsonb_typeof(NEW.executor_snapshot::jsonb->'scope') IS DISTINCT FROM 'object'
            OR jsonb_typeof(NEW.executor_snapshot::jsonb->'permissions') IS DISTINCT FROM 'array'
            OR jsonb_array_length(NEW.executor_snapshot::jsonb->'permissions') NOT BETWEEN 1 AND 128
            OR EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.executor_snapshot::jsonb->'permissions') permission
                WHERE jsonb_typeof(permission) IS DISTINCT FROM 'string' OR length(permission #>> '{}') NOT BETWEEN 1 AND 128)
            OR (SELECT count(DISTINCT permission) FROM jsonb_array_elements(NEW.executor_snapshot::jsonb->'permissions') permission)
                <>jsonb_array_length(NEW.executor_snapshot::jsonb->'permissions')
            OR NOT ((NEW.executor_snapshot::jsonb->'permissions') ? '*' OR (NEW.executor_snapshot::jsonb->'permissions') @> '["alerts.sources.replace","alerts.read","capabilities.read"]'::jsonb)
            OR NEW.result::jsonb->>'protocol' IS DISTINCT FROM 'icheck.collector.source-retirement/v1'
            OR NEW.result::jsonb->>'verification_basis' IS DISTINCT FROM 'peer_reviewed_external_attestation'
            OR NEW.result::jsonb->'physical_truth_automatically_verified' IS DISTINCT FROM 'false'::jsonb
            OR NEW.result::jsonb->'authorizes_incident_closure' IS DISTINCT FROM 'false'::jsonb
            OR (NEW.result::jsonb - 'protocol' - 'verification_basis' - 'physical_truth_automatically_verified' - 'authorizes_incident_closure' - 'created_at')
                IS DISTINCT FROM (to_jsonb(NEW) - 'tenant_id' - 'region_id' - 'result' - 'created_at')
            OR (NEW.result::jsonb->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at
            THEN RAISE EXCEPTION 'Source retirement result or executor snapshot is invalid'; END IF;
        IF NOT EXISTS(SELECT 1 FROM collector_source_replacement_requests q
            JOIN collector_source_replacement_reviews r ON r.id=NEW.review_id AND r.request_id=q.id
            JOIN collector_condition_sources sold ON sold.id=NEW.old_source_id
            JOIN collector_condition_sources snew ON snew.id=NEW.new_source_id
            JOIN alert_condition_states oc ON oc.dedup_key=sold.dedup_key
            JOIN alert_condition_states nc ON nc.dedup_key=snew.dedup_key
            JOIN collector_condition_receipts ro ON ro.id=NEW.old_watermark_receipt_id AND ro.source_id=sold.id
            JOIN collector_condition_receipts rn ON rn.id=NEW.new_receipt_id AND rn.source_id=snew.id
            JOIN collector_condition_admissions an ON an.id=rn.admission_id
            JOIN collector_source_qualification_reviews qr ON qr.id=q.new_qualification_review_id
            JOIN collector_source_qualification_requests qq ON qq.id=qr.request_id AND qq.source_id=snew.id
            JOIN collector_deployments d ON d.id=snew.deployment_id
            JOIN artifact_versions v ON v.id=snew.artifact_version_id
            JOIN collector_runs run ON run.id=an.run_id
            JOIN collector_workers w ON w.id=an.worker_id
            JOIN control_plane_principals p ON p.id=NEW.executor_principal_id
            JOIN control_plane_principals pa ON pa.id=q.author_principal_id
            JOIN control_plane_principals pr ON pr.id=r.reviewer_principal_id
            WHERE q.id=NEW.request_id AND q.old_source_id=sold.id AND q.new_source_id=snew.id AND q.prior_retirement_id IS NULL
            AND q.tenant_id=NEW.tenant_id AND q.region_id=NEW.region_id AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id
            AND sold.tenant_id=NEW.tenant_id AND sold.region_id=NEW.region_id AND snew.tenant_id=NEW.tenant_id AND snew.region_id=NEW.region_id
            AND oc.tenant_id=NEW.tenant_id AND oc.region_id=NEW.region_id AND nc.tenant_id=NEW.tenant_id AND nc.region_id=NEW.region_id
            AND ro.tenant_id=NEW.tenant_id AND ro.region_id=NEW.region_id AND rn.tenant_id=NEW.tenant_id AND rn.region_id=NEW.region_id
            AND an.tenant_id=NEW.tenant_id AND an.region_id=NEW.region_id AND qq.tenant_id=NEW.tenant_id AND qq.region_id=NEW.region_id
            AND qr.tenant_id=NEW.tenant_id AND qr.region_id=NEW.region_id AND run.tenant_id=NEW.tenant_id AND run.region_id=NEW.region_id
            AND d.tenant_id=NEW.tenant_id AND d.region_id=NEW.region_id AND v.tenant_id=NEW.tenant_id AND v.region_id=NEW.region_id
            AND w.tenant_id=NEW.tenant_id AND w.region_id=NEW.region_id
            AND p.tenant_id=NEW.tenant_id AND pa.tenant_id=NEW.tenant_id AND pr.tenant_id=NEW.tenant_id
            AND p.subject=NEW.executor_subject AND pa.subject=q.author_subject AND pr.subject=r.reviewer_subject
            AND p.enabled AND pa.enabled AND pr.enabled AND pr.principal_type='user'
            AND p.id<>pr.id AND p.subject<>pr.subject AND pa.id<>pr.id AND pa.subject<>pr.subject
            AND NEW.created_at>=r.created_at AND NEW.created_at<q.expires_at AND NEW.created_at<qq.expires_at
            AND NOT EXISTS(SELECT 1 FROM collector_source_replacement_revocations x WHERE x.review_id=r.id)
            AND NOT EXISTS(SELECT 1 FROM collector_source_qualification_revocations x WHERE x.review_id IN (q.old_qualification_review_id,q.new_qualification_review_id))
            AND NOT EXISTS(SELECT 1 FROM collector_source_retirements x WHERE x.old_source_id IN (sold.id,snew.id))
            AND nc.state IN ('active','quiet') AND rn.disposition='accepted' AND rn.verdict=nc.state
            AND rn.condition_state_id=nc.id AND rn.observed_at=nc.observed_at AND rn.alert_id IS NOT DISTINCT FROM nc.latest_alert_id
            AND rn.observed_at<=NEW.created_at AND NEW.created_at-rn.observed_at<=make_interval(secs=>(snew.context::jsonb #>> '{definition,max_age_seconds}')::int)
            AND ro.condition_state_id=oc.id AND ro.observed_at=oc.observed_at AND ro.disposition IN ('accepted','conflict') AND oc.observed_at<=nc.observed_at
            AND (an.context::jsonb->'pins')=(q.snapshot::jsonb #> '{material,new,qualification_snapshot,pins}')
            AND d.enabled AND d.artifact_version_id=snew.artifact_version_id AND v.status='PUBLISHED'
            AND v.content_hash=snew.context::jsonb->>'version_content_hash'
            AND v.definition::jsonb=snew.context::jsonb #> '{version_material,definition}'
            AND v.implementation::jsonb=snew.context::jsonb #> '{version_material,implementation}'
            AND v.tests::jsonb=snew.context::jsonb #> '{version_material,tests}'
            AND d.target::jsonb=snew.context::jsonb #> '{deployment,target}' AND d.configuration::jsonb=snew.context::jsonb #> '{deployment,configuration}'
            AND d.worker_selector::jsonb=snew.context::jsonb #> '{deployment,worker_selector}'
            AND d.scope_device_id IS NOT DISTINCT FROM snew.context::jsonb #>> '{deployment,scope_device_id}'
            AND d.scope_site IS NOT DISTINCT FROM snew.context::jsonb #>> '{deployment,scope_site}'
            AND run.assignment_sha256=snew.assignment_sha256 AND run.worker_id=an.worker_id AND run.artifact_version_id=snew.artifact_version_id
            AND w.token_issued_at=(an.context::jsonb #>> '{pins,worker,token_issued_at}')::timestamptz
            AND w.mtls_revision=(an.context::jsonb #>> '{pins,worker,mtls_revision}')::int
            AND NOT EXISTS(SELECT 1 FROM collector_condition_admissions a WHERE a.tenant_id=NEW.tenant_id AND a.region_id=NEW.region_id
                AND a.deployment_id=sold.deployment_id AND a.artifact_version_id=sold.artifact_version_id
                AND ((a.context::jsonb->'pins') - 'worker' - 'independently_verified' - 'authorizes_incident_closure')=sold.context::jsonb AND a.observed_at>nc.observed_at)
            AND (NEW.old_state_snapshot::jsonb->>'admitted_through_at')::timestamptz=(SELECT max(a.observed_at) FROM collector_condition_admissions a
                WHERE a.tenant_id=NEW.tenant_id AND a.region_id=NEW.region_id AND a.deployment_id=sold.deployment_id AND a.artifact_version_id=sold.artifact_version_id
                AND ((a.context::jsonb->'pins') - 'worker' - 'independently_verified' - 'authorizes_incident_closure')=sold.context::jsonb)
            AND icheck_source_actor_permission(p.id,NEW.tenant_id,NEW.region_id,'alerts.sources.replace')
            AND icheck_source_actor_permission(p.id,NEW.tenant_id,NEW.region_id,'alerts.read')
            AND icheck_source_actor_permission(p.id,NEW.tenant_id,NEW.region_id,'capabilities.read')
            AND icheck_source_actor_permission(pa.id,NEW.tenant_id,NEW.region_id,'alerts.manage')
            AND icheck_source_actor_permission(pa.id,NEW.tenant_id,NEW.region_id,'capabilities.read')
            AND icheck_source_actor_permission(pr.id,NEW.tenant_id,NEW.region_id,'alerts.sources.replace.qualify')
            AND icheck_source_actor_permission(pr.id,NEW.tenant_id,NEW.region_id,'capabilities.read')
            AND icheck_source_actor_permission(qq.author_principal_id,NEW.tenant_id,NEW.region_id,'alerts.manage')
            AND icheck_source_actor_permission(qq.author_principal_id,NEW.tenant_id,NEW.region_id,'capabilities.read')
            AND icheck_source_actor_permission(qr.reviewer_principal_id,NEW.tenant_id,NEW.region_id,'alerts.sources.qualify')
            AND icheck_source_actor_permission(qr.reviewer_principal_id,NEW.tenant_id,NEW.region_id,'capabilities.read')
            AND icheck_source_actor_scope(qq.author_principal_id,NEW.tenant_id,NEW.region_id,snew.id)
            AND icheck_source_actor_scope(qr.reviewer_principal_id,NEW.tenant_id,NEW.region_id,snew.id)
            AND ((q.snapshot::jsonb #> '{initiating_authority,permissions}') ? '*' OR (q.snapshot::jsonb #> '{initiating_authority,permissions}') @> '["alerts.manage","capabilities.read"]'::jsonb)
            AND icheck_source_actor_scope(p.id,NEW.tenant_id,NEW.region_id,sold.id) AND icheck_source_actor_scope(p.id,NEW.tenant_id,NEW.region_id,snew.id)
            AND icheck_source_actor_scope(pa.id,NEW.tenant_id,NEW.region_id,sold.id) AND icheck_source_actor_scope(pa.id,NEW.tenant_id,NEW.region_id,snew.id)
            AND icheck_source_actor_scope(pr.id,NEW.tenant_id,NEW.region_id,sold.id) AND icheck_source_actor_scope(pr.id,NEW.tenant_id,NEW.region_id,snew.id)
            AND icheck_source_snapshot_scope(NEW.executor_snapshot::jsonb->'scope',NEW.tenant_id,NEW.region_id,sold.id)
            AND icheck_source_snapshot_scope(NEW.executor_snapshot::jsonb->'scope',NEW.tenant_id,NEW.region_id,snew.id)
            AND icheck_source_snapshot_scope(q.snapshot::jsonb #> '{initiating_authority,scope}',NEW.tenant_id,NEW.region_id,sold.id)
            AND icheck_source_snapshot_scope(q.snapshot::jsonb #> '{initiating_authority,scope}',NEW.tenant_id,NEW.region_id,snew.id)
            AND (nc.state='quiet' AND (nc.latest_alert_id IS NULL OR EXISTS(SELECT 1 FROM alerts a WHERE a.id=nc.latest_alert_id AND a.status='RESOLVED' AND a.source_retirement_id IS NULL))
                OR nc.state='active' AND EXISTS(SELECT 1 FROM alerts a WHERE a.id=nc.latest_alert_id AND a.status IN ('OPEN','ACKNOWLEDGED') AND a.source_retirement_id IS NULL))
            AND NEW.superseded_alert_id IS NOT DISTINCT FROM (SELECT a.id FROM alerts a WHERE a.id=oc.latest_alert_id AND a.dedup_key=sold.dedup_key AND a.status IN ('OPEN','ACKNOWLEDGED') AND a.source_retirement_id IS NULL)
            AND NOT EXISTS(SELECT 1 FROM situation_alerts m JOIN situation_closure_ownerships o ON o.situation_id=m.situation_id
                WHERE m.alert_id=NEW.superseded_alert_id AND o.state='claimed' AND o.lease_expires_at>clock_timestamp())
            AND NEW.old_state_snapshot::jsonb-'observed_at'-'admitted_through_at'=jsonb_build_object('id',oc.id,'revision',oc.revision,'state',oc.state,'latest_alert_id',oc.latest_alert_id,'event_type',oc.event_type,'entity_type',oc.entity_type,'entity_id',oc.entity_id,'source_rule_id',oc.source_rule_id)
            AND (NEW.old_state_snapshot::jsonb->>'observed_at')::timestamptz=oc.observed_at
            AND NEW.new_state_snapshot::jsonb-'observed_at'=jsonb_build_object('id',nc.id,'revision',nc.revision,'state',nc.state,'latest_alert_id',nc.latest_alert_id,'event_type',nc.event_type,'entity_type',nc.entity_type,'entity_id',nc.entity_id,'source_rule_id',nc.source_rule_id)
            AND (NEW.new_state_snapshot::jsonb->>'observed_at')::timestamptz=nc.observed_at)
            THEN RAISE EXCEPTION 'Source retirement lineage, authority or current cutover clock is invalid'; END IF;
        RETURN NEW; END; $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_guard_source_retirement BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION icheck_guard_source_retirement()"))
    op.execute(sa.text("""CREATE FUNCTION icheck_source_retirement_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.superseded_alert_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM alerts a WHERE a.id=NEW.superseded_alert_id AND a.source_retirement_id=NEW.id)
            THEN RAISE EXCEPTION 'Source retirement must atomically link its superseded Alert'; END IF;
        IF NOT EXISTS(SELECT 1 FROM audit_events a WHERE a.tenant_id=NEW.tenant_id AND a.region_id=NEW.region_id
            AND a.entity_type='collector_source_retirement' AND a.entity_id=NEW.id AND a.event_type='collector.source.retired'
            AND a.actor_id=NEW.executor_subject AND a.details::jsonb->>'old_source_id'=NEW.old_source_id AND a.details::jsonb->>'new_source_id'=NEW.new_source_id
            AND a.details::jsonb->'authorizes_incident_closure'='false'::jsonb AND a.details::jsonb->'physical_truth_automatically_verified'='false'::jsonb)
            THEN RAISE EXCEPTION 'Source retirement must atomically retain its audit'; END IF;
        IF EXISTS(SELECT 1 FROM situation_alerts m WHERE m.alert_id=NEW.superseded_alert_id AND NOT EXISTS(
            SELECT 1 FROM situation_events e WHERE e.situation_id=m.situation_id AND e.tenant_id=NEW.tenant_id AND e.region_id=NEW.region_id
            AND e.event_type='collector.source.retired' AND e.details::jsonb->>'retirement_id'=NEW.id
            AND e.actor=NEW.executor_subject AND e.details::jsonb->>'superseded_alert_id'=NEW.superseded_alert_id
            AND e.details::jsonb->'measured_resolution'='false'::jsonb
            AND e.details::jsonb->'authorizes_incident_closure'='false'::jsonb))
            THEN RAISE EXCEPTION 'Source retirement must atomically retain all Situation events'; END IF;
        IF EXISTS(SELECT 1 FROM situations s
            JOIN situation_alerts affected ON affected.situation_id=s.id AND affected.alert_id=NEW.superseded_alert_id
            CROSS JOIN LATERAL (SELECT count(*) AS total,
                count(*) FILTER(WHERE a.status<>'RESOLVED' AND a.source_retirement_id IS NULL) AS active,
                coalesce(sum(a.occurrence_count),0) AS occurrences, min(a.first_seen) AS first_seen, max(a.last_seen) AS last_seen
                FROM situation_alerts m JOIN alerts a ON a.id=m.alert_id AND a.tenant_id=NEW.tenant_id AND a.region_id=NEW.region_id
                WHERE m.situation_id=s.id AND m.tenant_id=NEW.tenant_id AND m.region_id=NEW.region_id) projection
            WHERE s.tenant_id=NEW.tenant_id AND s.region_id=NEW.region_id AND (
                projection.total=0 OR projection.total>512
                OR projection.total<>(SELECT count(*) FROM situation_alerts m WHERE m.situation_id=s.id)
                OR s.alert_count<>projection.total OR s.active_alert_count<>projection.active
                OR s.occurrence_count<>projection.occurrences OR s.first_seen<>projection.first_seen OR s.last_seen<>projection.last_seen
                OR (projection.active=0 AND (s.status<>'resolved' OR s.priority_score<>0))
                OR (projection.active>0 AND s.status='resolved')))
            THEN RAISE EXCEPTION 'Source retirement must atomically refresh every complete Situation projection'; END IF;
        RETURN NEW; END; $$"""))
    op.execute(sa.text(f"CREATE CONSTRAINT TRIGGER icheck_source_retirement_commit AFTER INSERT ON {TABLE} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION icheck_source_retirement_commit()"))


def _sqlite():
    for action in ("UPDATE", "DELETE"):
        op.execute(sa.text(f"CREATE TRIGGER icheck_source_retirement_{action.lower()} BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,'Source retirement history is append-only'); END"))
    op.execute(sa.text(f"""CREATE TRIGGER icheck_guard_source_retirement BEFORE INSERT ON {TABLE} WHEN
        length(NEW.execution_key) NOT BETWEEN 8 AND 128 OR length(NEW.reason) NOT BETWEEN 10 AND 512
        OR json_extract(NEW.result,'$.protocol') IS NOT 'icheck.collector.source-retirement/v1'
        OR json_type(NEW.result,'$.authorizes_incident_closure') IS NOT 'false'
        OR json_type(NEW.result,'$.physical_truth_automatically_verified') IS NOT 'false'
        OR json_extract(NEW.result,'$.id') IS NOT NEW.id
        OR json_extract(NEW.result,'$.request_id') IS NOT NEW.request_id
        OR json_extract(NEW.result,'$.review_id') IS NOT NEW.review_id
        OR json_extract(NEW.result,'$.old_source_id') IS NOT NEW.old_source_id
        OR json_extract(NEW.result,'$.new_source_id') IS NOT NEW.new_source_id
        OR json_extract(NEW.result,'$.new_receipt_id') IS NOT NEW.new_receipt_id
        OR NOT EXISTS(SELECT 1 FROM collector_source_replacement_requests q
            JOIN collector_source_replacement_reviews r ON r.id=NEW.review_id AND r.request_id=q.id
            JOIN collector_condition_sources old ON old.id=NEW.old_source_id
            JOIN collector_condition_sources new ON new.id=NEW.new_source_id
            JOIN collector_condition_receipts ro ON ro.id=NEW.old_watermark_receipt_id AND ro.source_id=old.id
            JOIN collector_condition_receipts rn ON rn.id=NEW.new_receipt_id AND rn.source_id=new.id
            JOIN alert_condition_states oc ON oc.dedup_key=old.dedup_key
            JOIN alert_condition_states nc ON nc.dedup_key=new.dedup_key
            JOIN control_plane_principals p ON p.id=NEW.executor_principal_id
            WHERE q.id=NEW.request_id AND q.old_source_id=old.id AND q.new_source_id=new.id AND q.prior_retirement_id IS NULL
            AND q.tenant_id=NEW.tenant_id AND q.region_id=NEW.region_id AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id
            AND old.tenant_id=NEW.tenant_id AND old.region_id=NEW.region_id AND new.tenant_id=NEW.tenant_id AND new.region_id=NEW.region_id
            AND ro.tenant_id=NEW.tenant_id AND ro.region_id=NEW.region_id AND rn.tenant_id=NEW.tenant_id AND rn.region_id=NEW.region_id
            AND oc.tenant_id=NEW.tenant_id AND oc.region_id=NEW.region_id AND nc.tenant_id=NEW.tenant_id AND nc.region_id=NEW.region_id
            AND p.tenant_id=NEW.tenant_id AND p.subject=NEW.executor_subject AND p.enabled AND p.id<>r.reviewer_principal_id
            AND p.subject<>r.reviewer_subject AND NEW.created_at<q.expires_at
            AND NOT EXISTS(SELECT 1 FROM collector_source_replacement_revocations x WHERE x.review_id=r.id)
            AND NOT EXISTS(SELECT 1 FROM collector_source_retirements x WHERE x.old_source_id IN (old.id,new.id))
            AND nc.state IN ('active','quiet') AND rn.disposition='accepted' AND rn.verdict=nc.state
            AND rn.condition_state_id=nc.id AND rn.observed_at=nc.observed_at AND rn.alert_id IS nc.latest_alert_id
            AND ro.condition_state_id=oc.id AND ro.observed_at=oc.observed_at AND oc.observed_at<=nc.observed_at
            AND json_extract(NEW.old_state_snapshot,'$.id') IS oc.id AND json_extract(NEW.old_state_snapshot,'$.revision') IS oc.revision
            AND json_extract(NEW.new_state_snapshot,'$.id') IS nc.id AND json_extract(NEW.new_state_snapshot,'$.revision') IS nc.revision)
        BEGIN SELECT RAISE(ABORT,'Source retirement lineage or current cutover is invalid'); END"""))
    op.execute(sa.text("""CREATE TRIGGER icheck_source_retirement_receipt_fence BEFORE INSERT ON collector_condition_receipts WHEN
        (EXISTS(SELECT 1 FROM collector_source_retirements r WHERE r.old_source_id=NEW.source_id)
            AND (NEW.disposition<>'retired' OR NOT EXISTS(SELECT 1 FROM collector_source_retirements r WHERE r.old_source_id=NEW.source_id
                AND r.id=json_extract(NEW.result,'$.retirement_id') AND json_type(NEW.result,'$.source_retired')='true')))
        OR (NEW.disposition='retired' AND NOT EXISTS(SELECT 1 FROM collector_source_retirements r WHERE r.old_source_id=NEW.source_id))
        BEGIN SELECT RAISE(ABORT,'Retired source cannot commit a current receipt'); END"""))
    for action in ("INSERT", "UPDATE", "DELETE"):
        row = "NEW" if action == "INSERT" else "OLD"
        condition = f"EXISTS(SELECT 1 FROM collector_condition_sources s JOIN collector_source_retirements r ON r.old_source_id=s.id WHERE s.dedup_key={row}.dedup_key AND s.tenant_id={row}.tenant_id AND s.region_id={row}.region_id)"
        if action == "INSERT":
            condition += " AND NOT EXISTS(SELECT 1 FROM alert_condition_states c WHERE c.dedup_key=NEW.dedup_key AND c.tenant_id=NEW.tenant_id AND c.region_id=NEW.region_id)"
        op.execute(sa.text(f"CREATE TRIGGER icheck_retired_condition_{action.lower()} BEFORE {action} ON alert_condition_states WHEN {condition} BEGIN SELECT RAISE(ABORT,'Retired source watermark is immutable'); END"))
    columns = [column["name"] for column in sa.inspect(op.get_bind()).get_columns("alerts") if column["name"] != "source_retirement_id"]
    unchanged = " AND ".join(f'NEW."{column}" IS OLD."{column}"' for column in columns)
    op.execute(sa.text(f"""CREATE TRIGGER icheck_retired_alert_update BEFORE UPDATE ON alerts WHEN
        (NEW.source_retirement_id IS NOT OLD.source_retirement_id OR EXISTS(SELECT 1 FROM collector_condition_sources s
            JOIN collector_source_retirements r ON r.old_source_id=s.id WHERE s.dedup_key=OLD.dedup_key AND s.tenant_id=OLD.tenant_id AND s.region_id=OLD.region_id))
        AND NOT (OLD.source_retirement_id IS NULL AND NEW.source_retirement_id IS NOT NULL AND {unchanged}
            AND EXISTS(SELECT 1 FROM collector_source_retirements r JOIN collector_condition_sources s ON s.id=r.old_source_id
                WHERE r.id=NEW.source_retirement_id AND r.superseded_alert_id=NEW.id AND s.dedup_key=NEW.dedup_key
                AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id))
        BEGIN SELECT RAISE(ABORT,'Superseded Alert history is immutable'); END"""))
    for action in ("INSERT", "DELETE"):
        row = "NEW" if action == "INSERT" else "OLD"
        op.execute(sa.text(f"""CREATE TRIGGER icheck_retired_alert_{action.lower()} BEFORE {action} ON alerts WHEN
            EXISTS(SELECT 1 FROM collector_condition_sources s JOIN collector_source_retirements r ON r.old_source_id=s.id
                WHERE s.dedup_key={row}.dedup_key AND s.tenant_id={row}.tenant_id AND s.region_id={row}.region_id)
            {'OR NEW.source_retirement_id IS NOT NULL' if action == 'INSERT' else ''}
            BEGIN SELECT RAISE(ABORT,'Retired source Alert history cannot be recreated or deleted'); END"""))
    op.execute(sa.text("""CREATE TRIGGER icheck_source_generation_eligibility BEFORE INSERT ON collector_source_replacement_requests WHEN
        NEW.prior_retirement_id IS NOT (SELECT id FROM collector_source_retirements WHERE old_source_id=NEW.old_source_id)
        OR EXISTS(SELECT 1 FROM collector_source_retirements WHERE old_source_id=NEW.new_source_id)
        BEGIN SELECT RAISE(ABORT,'Replacement requires explicit retirement and an unretired target'); END"""))
    for table, source in (("collector_source_qualification_requests", "NEW.source_id"),
        ("collector_source_qualification_reviews", "(SELECT source_id FROM collector_source_qualification_requests WHERE id=NEW.request_id)")):
        op.execute(sa.text(f"CREATE TRIGGER icheck_retired_{table} BEFORE INSERT ON {table} WHEN EXISTS(SELECT 1 FROM {TABLE} WHERE old_source_id={source}) BEGIN SELECT RAISE(ABORT,'Retired source cannot regain qualification'); END"))


def downgrade():
    bind = op.get_bind(); pg = bind.dialect.name == "postgresql"
    _visible(bind, (*PARENTS, TABLE))
    for query in (f"SELECT 1 FROM {TABLE} LIMIT 1", "SELECT 1 FROM alerts WHERE source_retirement_id IS NOT NULL LIMIT 1",
        "SELECT 1 FROM collector_source_replacement_requests WHERE prior_retirement_id IS NOT NULL LIMIT 1",
        "SELECT 1 FROM collector_condition_receipts WHERE disposition='retired' LIMIT 1"):
        if bind.execute(sa.text(query)).first():
            raise RuntimeError("Retain permanent retirement and historical observations; downgrade is refused")
    _remove_guards(pg)
    op.drop_index("ix_condition_admission_generation_clock", "collector_condition_admissions")
    op.drop_index("ix_alerts_source_retirement_id", "alerts")
    if pg:
        op.drop_constraint("fk_alert_source_retirement", "alerts", type_="foreignkey")
        op.drop_constraint("fk_replacement_prior_retirement", "collector_source_replacement_requests", type_="foreignkey")
        op.drop_constraint("ck_collector_condition_receipt_disposition", "collector_condition_receipts", type_="check")
        op.create_check_constraint("ck_collector_condition_receipt_disposition", "collector_condition_receipts", "disposition IN ('accepted','stale','duplicate','conflict')")
    else:
        triggers = list(bind.execute(sa.text("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND (tbl_name='collector_condition_receipts' OR instr(sql,'collector_condition_receipts')>0)")).all())
        for name, _sql in triggers: op.execute(sa.text(f'DROP TRIGGER "{name}"'))
        with op.batch_alter_table("collector_condition_receipts", recreate="always") as batch:
            batch.drop_constraint("ck_collector_condition_receipt_disposition", type_="check")
            batch.create_check_constraint("ck_collector_condition_receipt_disposition", "disposition IN ('accepted','stale','duplicate','conflict')")
        for _name, sql in triggers: op.execute(sa.text(sql))
    op.drop_column("alerts", "source_retirement_id")
    op.drop_column("collector_source_replacement_requests", "prior_retirement_id")
    op.drop_table(TABLE)


def _remove_guards(pg):
    if pg:
        for table in ("collector_condition_receipts", "alerts", "alert_condition_states"):
            op.execute(sa.text(f"DROP TRIGGER icheck_00_source_retirement_fence ON {table}"))
        for table in ("collector_source_replacement_requests", "collector_source_qualification_requests", "collector_source_qualification_reviews"):
            op.execute(sa.text(f"DROP TRIGGER icheck_00_source_generation_eligibility ON {table}"))
        for name in ("icheck_guard_source_retirement", "icheck_source_retirement_commit"):
            op.execute(sa.text(f"DROP TRIGGER {name} ON {TABLE}"))
        for name in ("icheck_source_retirement_commit()", "icheck_guard_source_retirement()", "icheck_source_retirement_fence()",
            "icheck_source_generation_eligibility()", "icheck_source_actor_scope(text,text,text,text)",
            "icheck_source_snapshot_scope(jsonb,text,text,text)", "icheck_source_snapshot_device(jsonb,text,text,text)",
            "icheck_source_device_scope(text,text,text,text)", "icheck_source_actor_global(text,text,text)",
            "icheck_source_actor_permission(text,text,text,text)"):
            op.execute(sa.text(f"DROP FUNCTION {name}"))
    else:
        for name in ("icheck_source_retirement_update", "icheck_source_retirement_delete", "icheck_guard_source_retirement",
            "icheck_source_retirement_receipt_fence", "icheck_retired_condition_insert", "icheck_retired_condition_update", "icheck_retired_condition_delete",
            "icheck_retired_alert_update", "icheck_retired_alert_insert", "icheck_retired_alert_delete", "icheck_source_generation_eligibility",
            "icheck_retired_collector_source_qualification_requests", "icheck_retired_collector_source_qualification_reviews"):
            op.execute(sa.text(f"DROP TRIGGER {name}"))
