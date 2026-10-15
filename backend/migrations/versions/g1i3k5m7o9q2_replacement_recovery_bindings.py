"""Explicit replacement recovery criteria; v1 history unchanged, drained rollout."""
from alembic import op
import sqlalchemy as sa

revision = "g1i3k5m7o9q2"
down_revision = "f0h2j4l6n8p1"
branch_labels = depends_on = None
REQUESTS = "situation_recovery_policy_requests"
REVIEWS = "situation_recovery_policy_reviews"
PARENTS = ("collector_deployments", "collector_runs", "knowledge_projections", "agent_executions",
    "situation_closure_ownerships", REQUESTS, REVIEWS, "situation_recovery_policy_revocations",
    "collector_condition_sources", "collector_source_retirements", "collector_source_replacement_requests",
    "collector_source_replacement_reviews", "collector_source_replacement_revocations", "situation_closure_grants")


def _visible(bind):
    if bind.dialect.name == "postgresql":
        for table in PARENTS:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Replacement recovery migration requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE " + ", ".join(PARENTS) + " IN ACCESS EXCLUSIVE MODE"))


def upgrade():
    bind = op.get_bind(); pg = bind.dialect.name == "postgresql"
    if bind.dialect.name not in {"postgresql", "sqlite"}:
        raise RuntimeError("Replacement recovery requires PostgreSQL or SQLite")
    _visible(bind)
    for query in (
        "SELECT 1 FROM collector_deployments WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL LIMIT 1",
        "SELECT 1 FROM collector_runs WHERE status='RUNNING' LIMIT 1",
        "SELECT 1 FROM knowledge_projections WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL OR status='PROCESSING' LIMIT 1",
        "SELECT 1 FROM agent_executions WHERE lease_token_hash IS NOT NULL OR status='RUNNING' LIMIT 1",
        "SELECT 1 FROM situation_closure_ownerships WHERE state='claimed' LIMIT 1"):
        if bind.execute(sa.text(query)).first():
            raise RuntimeError("Drain API/Collector/Projection/Agent and closure ownership before replacement recovery migration")
    if pg:
        op.add_column(REQUESTS, sa.Column("proof_version", sa.Integer(), nullable=False, server_default="1"))
        op.create_check_constraint("ck_situation_recovery_policy_proof_version", REQUESTS, "proof_version IN (1,2)")
    else:
        # No table rebuild: preserve append-only/reference triggers and all
        # existing closure references to v1 policy history.
        op.execute(sa.text(f"ALTER TABLE {REQUESTS} ADD COLUMN proof_version INTEGER NOT NULL DEFAULT 1 CONSTRAINT ck_situation_recovery_policy_proof_version CHECK(proof_version IN (1,2))"))
    op.add_column(REQUESTS, sa.Column("replacement_bindings", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
    if pg:
        _postgres()
    else:
        _sqlite()


def _checks(pg, q):
    rows = f"jsonb_array_elements({q}.replacement_bindings::jsonb) AS entry(value)" if pg else f"json_each({q}.replacement_bindings) AS entry"
    field = lambda key: f"entry.value->>'{key}'" if pg else f"json_extract(entry.value,'$.{key}')"
    count = f"jsonb_array_length({q}.replacement_bindings::jsonb)" if pg else f"json_array_length({q}.replacement_bindings)"
    shape = (f"jsonb_typeof({q}.replacement_bindings::jsonb) IS DISTINCT FROM 'array' OR {count}>64 OR EXISTS(SELECT 1 FROM {rows} WHERE jsonb_typeof(entry.value) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(entry.value))<>3 OR EXISTS(SELECT 1 FROM jsonb_object_keys(entry.value) k WHERE k NOT IN ('old_source_id','retirement_id','replacement_review_id')) OR jsonb_typeof(entry.value->'old_source_id') IS DISTINCT FROM 'string' OR jsonb_typeof(entry.value->'retirement_id') IS DISTINCT FROM 'string' OR jsonb_typeof(entry.value->'replacement_review_id') IS DISTINCT FROM 'string')" if pg else
        f"json_type({q}.replacement_bindings) IS NOT 'array' OR {count}>64 OR EXISTS(SELECT 1 FROM {rows} WHERE entry.type IS NOT 'object' OR (SELECT count(*) FROM json_each(entry.value))<>3 OR EXISTS(SELECT 1 FROM json_each(entry.value) WHERE key NOT IN ('old_source_id','retirement_id','replacement_review_id')) OR json_type(entry.value,'$.old_source_id') IS NOT 'text' OR json_type(entry.value,'$.retirement_id') IS NOT 'text' OR json_type(entry.value,'$.replacement_review_id') IS NOT 'text')")
    current_rows = f"jsonb_array_elements({q}.source_bindings::jsonb) current(value)" if pg else f"json_each({q}.source_bindings) current"
    current_id = "current.value->>'source_id'" if pg else "json_extract(current.value,'$.source_id')"
    current_review = "current.value->>'qualification_review_id'" if pg else "json_extract(current.value,'$.qualification_review_id')"
    refs = f"""EXISTS(SELECT 1 FROM {rows}
        LEFT JOIN collector_source_retirements t ON t.id={field('retirement_id')} AND t.tenant_id={q}.tenant_id AND t.region_id={q}.region_id
        LEFT JOIN collector_source_replacement_reviews r ON r.id={field('replacement_review_id')} AND r.tenant_id={q}.tenant_id AND r.region_id={q}.region_id
        LEFT JOIN collector_source_replacement_requests m ON m.id=r.request_id AND m.tenant_id={q}.tenant_id AND m.region_id={q}.region_id
        WHERE t.id IS NULL OR r.id IS NULL OR m.id IS NULL OR t.old_source_id<>{field('old_source_id')} OR m.old_source_id<>{field('old_source_id')}
        OR NOT ((m.id=t.request_id AND r.id=t.review_id AND m.prior_retirement_id IS NULL AND m.new_source_id=t.new_source_id) OR m.prior_retirement_id=t.id)
        OR m.evidence_environment<>{q}.evidence_environment OR {q}.expires_at>m.expires_at OR {q}.created_at>=m.expires_at
        OR EXISTS(SELECT 1 FROM collector_source_replacement_revocations x WHERE x.review_id=r.id)
        OR EXISTS(SELECT 1 FROM collector_source_retirements x WHERE x.old_source_id=m.new_source_id)
        OR EXISTS(SELECT 1 FROM collector_source_qualification_revocations x WHERE x.review_id IN(m.old_qualification_review_id,m.new_qualification_review_id))
        OR EXISTS(SELECT 1 FROM {current_rows} WHERE {current_id}=m.old_source_id)
        OR NOT EXISTS(SELECT 1 FROM {current_rows} WHERE {current_id}=m.new_source_id AND {current_review}=m.new_qualification_review_id))"""
    retired_current = f"EXISTS(SELECT 1 FROM {current_rows} JOIN collector_source_retirements t ON t.old_source_id={current_id})"
    return f"""{q}.proof_version NOT IN (1,2) OR ({shape})
        OR ({q}.proof_version=1 AND {count}<>0) OR ({q}.proof_version=2 AND {count}=0)
        OR (SELECT count(DISTINCT {field('old_source_id')}) FROM {rows})<>{count}
        OR (SELECT count(DISTINCT {field('retirement_id')}) FROM {rows})<>{count}
        OR EXISTS(SELECT 1 FROM {rows} WHERE length({field('old_source_id')})<>36 OR length({field('retirement_id')})<>36 OR length({field('replacement_review_id')})<>36)
        OR ({refs}) OR ({retired_current})"""


def _postgres():
    checks = _checks(True, "q")
    op.execute(sa.text(f"""CREATE FUNCTION icheck_guard_replacement_recovery() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE q situation_recovery_policy_requests%ROWTYPE; dep text; pid text; source_id text; permission text; person text; BEGIN
        IF TG_TABLE_NAME='{REQUESTS}' THEN q:=NEW; permission:='alerts.manage'; pid:=NEW.author_principal_id;
        ELSE SELECT * INTO q FROM {REQUESTS} WHERE id=NEW.request_id AND tenant_id=NEW.tenant_id AND region_id=NEW.region_id;
            IF NOT FOUND THEN RAISE EXCEPTION 'Replacement recovery policy not found'; END IF;
            permission:='situations.recovery.qualify'; pid:=NEW.reviewer_principal_id; END IF;
        IF {checks} THEN RAISE EXCEPTION 'Replacement recovery version, references or mapping acceptance are invalid'; END IF;
        IF q.proof_version=1 THEN RETURN NEW; END IF;
        FOR dep IN SELECT DISTINCT s.deployment_id FROM collector_condition_sources s WHERE s.id IN (
            SELECT b->>'source_id' FROM jsonb_array_elements(q.source_bindings::jsonb) b
            UNION SELECT b->>'old_source_id' FROM jsonb_array_elements(q.replacement_bindings::jsonb) b
            UNION SELECT t.new_source_id FROM collector_source_retirements t JOIN jsonb_array_elements(q.replacement_bindings::jsonb) b ON t.id=b->>'retirement_id') ORDER BY s.deployment_id LOOP
            PERFORM 1 FROM collector_deployments WHERE id=dep FOR UPDATE; END LOOP;
        PERFORM 1 FROM collector_condition_sources s WHERE s.id IN (
            SELECT b->>'source_id' FROM jsonb_array_elements(q.source_bindings::jsonb) b
            UNION SELECT b->>'old_source_id' FROM jsonb_array_elements(q.replacement_bindings::jsonb) b
            UNION SELECT t.new_source_id FROM collector_source_retirements t JOIN jsonb_array_elements(q.replacement_bindings::jsonb) b ON t.id=b->>'retirement_id') ORDER BY s.id FOR UPDATE NOWAIT;
        -- Separate statement refresh after deployment waits; immutable q stays
        -- fixed, while retirement/revocation and actual role rows may change.
        IF {checks} THEN RAISE EXCEPTION 'Replacement recovery changed during producer mutex wait'; END IF;
        IF q.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'Replacement recovery cannot accept already expired criteria'; END IF;
        FOR person IN SELECT DISTINCT id FROM control_plane_principals WHERE id IN (
            SELECT pid UNION SELECT q.author_principal_id
            UNION SELECT m.author_principal_id FROM collector_source_replacement_requests m JOIN collector_source_replacement_reviews r ON r.request_id=m.id JOIN jsonb_array_elements(q.replacement_bindings::jsonb) b ON r.id=b->>'replacement_review_id'
            UNION SELECT r.reviewer_principal_id FROM collector_source_replacement_reviews r JOIN jsonb_array_elements(q.replacement_bindings::jsonb) b ON r.id=b->>'replacement_review_id'
            UNION SELECT a.author_principal_id FROM collector_source_qualification_requests a JOIN collector_source_qualification_reviews r ON r.request_id=a.id JOIN jsonb_array_elements(q.source_bindings::jsonb) b ON r.id=b->>'qualification_review_id'
            UNION SELECT r.reviewer_principal_id FROM collector_source_qualification_reviews r JOIN jsonb_array_elements(q.source_bindings::jsonb) b ON r.id=b->>'qualification_review_id') ORDER BY id LOOP
            PERFORM 1 FROM control_plane_principals WHERE id=person FOR SHARE NOWAIT;
            PERFORM 1 FROM control_plane_role_bindings WHERE principal_id=person ORDER BY id FOR SHARE NOWAIT;
            PERFORM 1 FROM control_plane_roles WHERE id IN(SELECT role_id FROM control_plane_role_bindings WHERE principal_id=person) ORDER BY id FOR SHARE NOWAIT;
        END LOOP;
        IF NOT icheck_source_actor_permission(pid,q.tenant_id,q.region_id,permission)
            OR NOT icheck_source_actor_permission(pid,q.tenant_id,q.region_id,'alerts.read')
            OR NOT icheck_source_actor_permission(pid,q.tenant_id,q.region_id,'capabilities.read')
            OR NOT icheck_source_actor_permission(q.author_principal_id,q.tenant_id,q.region_id,'alerts.manage')
            OR NOT icheck_source_actor_permission(q.author_principal_id,q.tenant_id,q.region_id,'alerts.read')
            OR NOT icheck_source_actor_permission(q.author_principal_id,q.tenant_id,q.region_id,'capabilities.read')
            THEN RAISE EXCEPTION 'Replacement recovery initiating actor or policy author lacks current authority'; END IF;
        FOR source_id IN SELECT b->>'source_id' FROM jsonb_array_elements(q.source_bindings::jsonb) b
            UNION SELECT b->>'old_source_id' FROM jsonb_array_elements(q.replacement_bindings::jsonb) b
            UNION SELECT t.new_source_id FROM collector_source_retirements t JOIN jsonb_array_elements(q.replacement_bindings::jsonb) b ON t.id=b->>'retirement_id' LOOP
            IF NOT icheck_source_actor_scope(pid,q.tenant_id,q.region_id,source_id)
                OR NOT icheck_source_actor_scope(q.author_principal_id,q.tenant_id,q.region_id,source_id)
                THEN RAISE EXCEPTION 'Replacement recovery actor lacks complete retained source scope'; END IF; END LOOP;
        IF EXISTS(SELECT 1 FROM jsonb_array_elements(q.replacement_bindings::jsonb) b
            JOIN collector_source_replacement_reviews r ON r.id=b->>'replacement_review_id'
            JOIN collector_source_replacement_requests m ON m.id=r.request_id
            JOIN control_plane_principals peer ON peer.id=r.reviewer_principal_id
            WHERE m.expires_at<=clock_timestamp() OR peer.principal_type<>'user'
            OR NOT ((m.snapshot::jsonb #> '{{initiating_authority,permissions}}') ? '*' OR (m.snapshot::jsonb #> '{{initiating_authority,permissions}}') @> '["alerts.manage","capabilities.read"]'::jsonb)
            OR NOT icheck_source_actor_permission(m.author_principal_id,q.tenant_id,q.region_id,'alerts.manage')
            OR NOT icheck_source_actor_permission(m.author_principal_id,q.tenant_id,q.region_id,'capabilities.read')
            OR NOT icheck_source_actor_permission(r.reviewer_principal_id,q.tenant_id,q.region_id,'alerts.sources.replace.qualify')
            OR NOT icheck_source_actor_permission(r.reviewer_principal_id,q.tenant_id,q.region_id,'capabilities.read')
            OR NOT icheck_source_actor_scope(m.author_principal_id,q.tenant_id,q.region_id,m.old_source_id)
            OR NOT icheck_source_actor_scope(m.author_principal_id,q.tenant_id,q.region_id,m.new_source_id)
            OR NOT icheck_source_actor_scope(r.reviewer_principal_id,q.tenant_id,q.region_id,m.old_source_id)
            OR NOT icheck_source_actor_scope(r.reviewer_principal_id,q.tenant_id,q.region_id,m.new_source_id)
            OR NOT icheck_source_snapshot_scope(m.snapshot::jsonb #> '{{initiating_authority,scope}}',q.tenant_id,q.region_id,m.old_source_id)
            OR NOT icheck_source_snapshot_scope(m.snapshot::jsonb #> '{{initiating_authority,scope}}',q.tenant_id,q.region_id,m.new_source_id))
            THEN RAISE EXCEPTION 'Replacement recovery mapping authority is no longer current'; END IF;
        IF EXISTS(SELECT 1 FROM jsonb_array_elements(q.source_bindings::jsonb) b
            JOIN collector_source_qualification_reviews r ON r.id=b->>'qualification_review_id'
            JOIN collector_source_qualification_requests a ON a.id=r.request_id
            JOIN control_plane_principals author ON author.id=a.author_principal_id
            JOIN control_plane_principals peer ON peer.id=r.reviewer_principal_id
            WHERE a.expires_at<=clock_timestamp() OR author.principal_type<>'user' OR peer.principal_type<>'user'
            OR EXISTS(SELECT 1 FROM collector_source_qualification_revocations x WHERE x.review_id=r.id)
            OR NOT icheck_source_actor_permission(a.author_principal_id,q.tenant_id,q.region_id,'alerts.manage')
            OR NOT icheck_source_actor_permission(a.author_principal_id,q.tenant_id,q.region_id,'capabilities.read')
            OR NOT icheck_source_actor_permission(r.reviewer_principal_id,q.tenant_id,q.region_id,'alerts.sources.qualify')
            OR NOT icheck_source_actor_permission(r.reviewer_principal_id,q.tenant_id,q.region_id,'capabilities.read')
            OR NOT icheck_source_actor_scope(a.author_principal_id,q.tenant_id,q.region_id,a.source_id)
            OR NOT icheck_source_actor_scope(r.reviewer_principal_id,q.tenant_id,q.region_id,a.source_id))
            THEN RAISE EXCEPTION 'Replacement recovery target qualification authority is no longer current'; END IF;
        RETURN NEW; END; $$"""))
    for table in (REQUESTS, REVIEWS):
        op.execute(sa.text(f"CREATE TRIGGER icheck_00_replacement_recovery BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_guard_replacement_recovery()"))
    op.execute(sa.text("""CREATE FUNCTION icheck_replacement_recovery_closure_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS(SELECT 1 FROM situation_recovery_policy_reviews r JOIN situation_recovery_policy_requests q ON q.id=r.request_id
            WHERE r.id=NEW.policy_review_id AND q.tenant_id=NEW.tenant_id AND q.region_id=NEW.region_id
            AND q.proof_version=1 AND q.replacement_bindings::jsonb='[]'::jsonb)
            THEN RAISE EXCEPTION 'Replacement recovery cannot authorize incompatible v1 closure'; END IF;
        RETURN NEW; END; $$"""))
    op.execute(sa.text("CREATE TRIGGER icheck_00_replacement_recovery_closure BEFORE INSERT ON situation_closure_grants FOR EACH ROW EXECUTE FUNCTION icheck_replacement_recovery_closure_barrier()"))


def _sqlite():
    op.execute(sa.text(f"CREATE TRIGGER icheck_00_replacement_recovery_request BEFORE INSERT ON {REQUESTS} WHEN {_checks(False, 'NEW')} BEGIN SELECT RAISE(ABORT,'Replacement recovery version, references or mapping acceptance are invalid'); END"))
    op.execute(sa.text(f"""CREATE TRIGGER icheck_00_replacement_recovery_review BEFORE INSERT ON {REVIEWS} WHEN EXISTS(
        SELECT 1 FROM {REQUESTS} q WHERE q.id=NEW.request_id AND ({_checks(False, 'q')}))
        BEGIN SELECT RAISE(ABORT,'Replacement recovery mapping acceptance changed'); END"""))
    op.execute(sa.text("""CREATE TRIGGER icheck_00_replacement_recovery_closure BEFORE INSERT ON situation_closure_grants WHEN NOT EXISTS(
        SELECT 1 FROM situation_recovery_policy_reviews r JOIN situation_recovery_policy_requests q ON q.id=r.request_id
        WHERE r.id=NEW.policy_review_id AND q.tenant_id=NEW.tenant_id AND q.region_id=NEW.region_id AND q.proof_version=1 AND q.replacement_bindings='[]')
        BEGIN SELECT RAISE(ABORT,'Replacement recovery cannot authorize incompatible v1 closure'); END"""))


def downgrade():
    bind = op.get_bind(); pg = bind.dialect.name == "postgresql"
    _visible(bind)
    if bind.execute(sa.text(f"SELECT 1 FROM {REQUESTS} WHERE proof_version<>1 OR replacement_bindings{'::jsonb' if pg else ''}<>'[]'{'::jsonb' if pg else ''} LIMIT 1")).first():
        raise RuntimeError("Retain replacement-aware recovery policies; downgrade is refused")
    if pg:
        for table in (REQUESTS, REVIEWS): op.execute(sa.text(f"DROP TRIGGER icheck_00_replacement_recovery ON {table}"))
        op.execute(sa.text("DROP TRIGGER icheck_00_replacement_recovery_closure ON situation_closure_grants"))
        op.execute(sa.text("DROP FUNCTION icheck_guard_replacement_recovery()"))
        op.execute(sa.text("DROP FUNCTION icheck_replacement_recovery_closure_barrier()"))
        op.drop_constraint("ck_situation_recovery_policy_proof_version", REQUESTS, type_="check")
    else:
        for name in ("icheck_00_replacement_recovery_request", "icheck_00_replacement_recovery_review", "icheck_00_replacement_recovery_closure"):
            op.execute(sa.text(f"DROP TRIGGER {name}"))
    op.drop_column(REQUESTS, "replacement_bindings")
    op.drop_column(REQUESTS, "proof_version")
