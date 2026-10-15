"""Explicit replacement closure v2; retain v1 and drain the coordinated rollout."""
from alembic import op
import sqlalchemy as sa

revision = "h2j4l6n8p0r3"
down_revision = "g1i3k5m7o9q2"
branch_labels = depends_on = None
GRANTS = "situation_closure_grants"
PARENTS = ("collector_deployments", "collector_runs", "knowledge_projections", "agent_executions",
    "situation_closure_ownerships", GRANTS, "situation_closure_requests", "situation_closure_receipts",
    "situation_recovery_policy_requests", "situation_recovery_policy_reviews", "collector_condition_sources",
    "collector_source_retirements", "collector_source_replacement_reviews", "agent_action_proposals")
V1 = "'icheck.reviewed-situation-closure/v1'"
VERSIONED = "('icheck.reviewed-situation-closure/v'||(SELECT proof_version::text FROM situation_closure_grants WHERE id=NEW.grant_id))"


def _visible_drained(bind):
    if bind.dialect.name == "postgresql":
        for table in PARENTS:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Replacement closure migration requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE " + ", ".join(PARENTS) + " IN ACCESS EXCLUSIVE MODE"))
    for query in (
        "SELECT 1 FROM collector_deployments WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL LIMIT 1",
        "SELECT 1 FROM collector_runs WHERE status='RUNNING' LIMIT 1",
        "SELECT 1 FROM knowledge_projections WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL OR status='PROCESSING' LIMIT 1",
        "SELECT 1 FROM agent_executions WHERE lease_token_hash IS NOT NULL OR status='RUNNING' LIMIT 1",
        "SELECT 1 FROM situation_closure_ownerships WHERE state='claimed' LIMIT 1"):
        if bind.execute(sa.text(query)).first():
            raise RuntimeError("Drain API/Collector/Projection/Agent and closure ownership before replacement closure migration")


def _once(value, old, new):
    # Preserve every existing guard. Unexpected installed code is a failed
    # rollout, never a reason to replace an entire function with weaker SQL.
    if value.count(old) != 1:
        raise RuntimeError("Installed closure guard differs from the reviewed migration predecessor")
    return value.replace(old, new, 1)


def _function(bind, name):
    return bind.execute(sa.text("SELECT pg_get_functiondef(CAST(:name AS regprocedure))"), {"name": name+"()"}).scalar_one()


def _receipt_contract(bind, *, reverse=False):
    pg = bind.dialect.name == "postgresql"
    name = "icheck_guard_situation_closure_receipts"
    sql = _function(bind, name) if pg else bind.execute(sa.text(
        "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=:name"), {"name": name}).scalar_one()
    versioned = VERSIONED if pg else VERSIONED.replace("proof_version::text", "CAST(proof_version AS TEXT)")
    changed = _once(sql, versioned if reverse else V1, V1 if reverse else versioned)
    if pg: op.execute(sa.text(changed))
    else: _replace_sqlite_trigger(name, changed)


def _replace_sqlite_trigger(name, sql):
    op.execute(sa.text("DROP TRIGGER " + name))
    op.execute(sa.text(sql))


def _compatibility(pg, *, reverse=False):
    condition = ("q.proof_version=1 AND q.replacement_bindings::jsonb='[]'::jsonb" if pg else "q.proof_version=1 AND q.replacement_bindings='[]'") if reverse else (
        "q.proof_version=NEW.proof_version AND ((NEW.proof_version=1 AND q.replacement_bindings::jsonb='[]'::jsonb) OR (NEW.proof_version=2 AND jsonb_array_length(q.replacement_bindings::jsonb)>0))" if pg else
        "q.proof_version=NEW.proof_version AND ((NEW.proof_version=1 AND q.replacement_bindings='[]') OR (NEW.proof_version=2 AND json_array_length(q.replacement_bindings)>0))")
    lookup = f"""SELECT 1 FROM situation_recovery_policy_reviews r JOIN situation_recovery_policy_requests q ON q.id=r.request_id
        WHERE r.id=NEW.policy_review_id AND q.tenant_id=NEW.tenant_id AND q.region_id=NEW.region_id AND {condition}"""
    if pg:
        op.execute(sa.text(f"""CREATE OR REPLACE FUNCTION icheck_replacement_recovery_closure_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF NOT EXISTS({lookup}) THEN RAISE EXCEPTION 'Replacement recovery cannot authorize incompatible v1 closure or mismatched v2 intent'; END IF;
            RETURN NEW; END; $$"""))
    else:
        _replace_sqlite_trigger("icheck_00_replacement_recovery_closure", f"""CREATE TRIGGER icheck_00_replacement_recovery_closure BEFORE INSERT ON situation_closure_grants WHEN NOT EXISTS({lookup})
            BEGIN SELECT RAISE(ABORT,'Replacement recovery cannot authorize incompatible v1 closure or mismatched v2 intent'); END""")


def _authority(bind):
    sql = _function(bind, "icheck_guard_replacement_recovery")
    sql = _once(sql, "icheck_guard_replacement_recovery()", "icheck_guard_replacement_closure_authority()")
    sql = _once(sql, "person text; BEGIN", "person text; g situation_closure_grants%ROWTYPE; policy_peer text; BEGIN")
    start = sql.index("IF TG_TABLE_NAME=")
    marker = "permission:='situations.recovery.qualify'; pid:=NEW.reviewer_principal_id; END IF;"
    end = sql.index(marker, start)+len(marker)
    sql = sql[:start]+"""IF TG_TABLE_NAME='situation_closure_grants' THEN g:=NEW; pid:=NEW.reviewer_principal_id; permission:='situations.closure.qualify';
        ELSE SELECT * INTO g FROM situation_closure_grants WHERE id=NEW.grant_id AND tenant_id=NEW.tenant_id AND region_id=NEW.region_id;
            IF TG_TABLE_NAME='situation_closure_requests' THEN pid:=NEW.owner_principal_id;
            ELSE SELECT owner_principal_id INTO pid FROM situation_closure_requests WHERE id=NEW.request_id; END IF;
            permission:='situations.close'; END IF;
        IF g.id IS NULL THEN RAISE EXCEPTION 'Closure grant not found'; END IF;
        IF g.proof_version=1 THEN RETURN NEW; END IF;
        SELECT p.* INTO q FROM situation_recovery_policy_requests p
            JOIN situation_recovery_policy_reviews r ON r.request_id=p.id WHERE r.id=g.policy_review_id
            AND p.tenant_id=NEW.tenant_id AND p.region_id=NEW.region_id;
        IF q.id IS NULL OR q.proof_version<>2 THEN RAISE EXCEPTION 'Explicit v2 closure policy not found'; END IF;
        """+sql[end:]
    sql = sql.replace("IF q.id IS NULL OR q.proof_version<>2", "SELECT reviewer_principal_id INTO policy_peer FROM situation_recovery_policy_reviews WHERE id=g.policy_review_id;\n        IF q.id IS NULL OR q.proof_version<>2")
    sql = _once(sql, "SELECT pid UNION SELECT q.author_principal_id", "SELECT pid UNION SELECT q.author_principal_id UNION SELECT policy_peer UNION SELECT g.reviewer_principal_id")
    sql = _once(sql, "OR NOT icheck_source_actor_permission(pid,q.tenant_id,q.region_id,'capabilities.read')", "OR (permission='situations.closure.qualify' AND NOT icheck_source_actor_permission(pid,q.tenant_id,q.region_id,'capabilities.read'))")
    sql = _once(sql, "OR NOT icheck_source_actor_scope(q.author_principal_id,q.tenant_id,q.region_id,source_id)", """OR NOT icheck_source_actor_scope(q.author_principal_id,q.tenant_id,q.region_id,source_id)
                OR NOT icheck_source_actor_scope(policy_peer,q.tenant_id,q.region_id,source_id)
                OR NOT icheck_source_actor_scope(g.reviewer_principal_id,q.tenant_id,q.region_id,source_id)""")
    sql = _once(sql, "RETURN NEW; END;", """IF g.expires_at<=clock_timestamp() OR EXISTS(SELECT 1 FROM situation_closure_revocations WHERE grant_id=g.id)
            OR EXISTS(SELECT 1 FROM situation_recovery_policy_revocations WHERE review_id=g.policy_review_id)
            OR NOT icheck_source_actor_permission(policy_peer,q.tenant_id,q.region_id,'situations.recovery.qualify')
            OR NOT icheck_source_actor_permission(policy_peer,q.tenant_id,q.region_id,'alerts.read')
            OR NOT icheck_source_actor_permission(policy_peer,q.tenant_id,q.region_id,'capabilities.read')
            OR NOT icheck_source_actor_permission(g.reviewer_principal_id,q.tenant_id,q.region_id,'situations.closure.qualify')
            OR NOT icheck_source_actor_permission(g.reviewer_principal_id,q.tenant_id,q.region_id,'alerts.read')
            OR NOT icheck_source_actor_permission(g.reviewer_principal_id,q.tenant_id,q.region_id,'capabilities.read')
            OR NOT EXISTS(SELECT 1 FROM control_plane_principals WHERE id=policy_peer AND principal_type='user')
            OR NOT EXISTS(SELECT 1 FROM control_plane_principals WHERE id=g.reviewer_principal_id AND principal_type='user')
            THEN RAISE EXCEPTION 'Replacement closure current grant or policy peer authority is unavailable'; END IF;
        RETURN NEW; END;""")
    op.execute(sa.text(sql))
    for table in (GRANTS, "situation_closure_requests", "situation_closure_receipts"):
        op.execute(sa.text(f"CREATE TRIGGER icheck_01_replacement_closure_authority BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_guard_replacement_closure_authority()"))


def _object(value, fields):
    keys = ",".join("'"+key+"'" for key in fields.split())
    return f"jsonb_typeof({value}) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys({value}))<>{len(fields.split())} OR EXISTS(SELECT 1 FROM jsonb_object_keys({value}) key WHERE key NOT IN ({keys}))"


def _clocks(value, fields):
    return " OR ".join(f"(jsonb_typeof({value}->'{field}') IS DISTINCT FROM 'string' OR {value}->>'{field}' !~ '(Z|[+-][0-9]{{2}}:[0-9]{{2}})$')" for field in fields.split())


def _ids(value, fields):
    return " OR ".join(f"(jsonb_typeof({value}->'{field}') IS DISTINCT FROM 'string' OR length({value}->>'{field}')<>36)" for field in fields.split())


def _proof():
    root = _object("NEW.proof::jsonb", "contract proof_basis membership_identity recovery related_actions owner_principal_id owner_subject reviewer_principal_id reviewer_subject acceptance_reference evidence_environment remediation_causality_proven physical_truth_automatically_verified")
    report = _object("p", "situation_id policy_review_id evaluated_at evidence_environment qualified_recovery production_qualified covers_situation member_count blockers membership source_evidence valid_until verification_basis authorizes_incident_closure closure_execution_available physical_truth_automatically_verified remediation_causality_proven")
    source = _object("item", "source_id qualification_review_id qualification_request_id condition_revision current_alert_id quiet_receipt_id quiet_admission_id quiet_observed_at quiet_window_start quiet_after quiet_sample_receipt_ids members")
    member = _object("member", "alert_id active_receipt_id active_source_id qualification_request_id qualification_review_id retirement_id replacement_request_id replacement_review_id")
    pin = _object("pin", "membership_id alert_id dedup_key event_type entity_type entity_id status first_seen last_seen occurrence_count source_retirement_id")
    op.execute(sa.text(f"""CREATE FUNCTION icheck_guard_replacement_closure_proof() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE g situation_closure_grants%ROWTYPE; q situation_recovery_policy_requests%ROWTYPE;
        p jsonb; item jsonb; member jsonb; pin jsonb; action jsonb; sid text; sample_id text; covered text[]:=ARRAY[]::text[];
        seen text[]:=ARRAY[]::text[]; samples text[]; previous_at timestamptz; start_at timestamptz; latest_at timestamptz; floor_at timestamptz;
        s collector_condition_sources%ROWTYPE; qr collector_source_qualification_requests%ROWTYPE;
        r collector_condition_receipts%ROWTYPE; ar collector_condition_receipts%ROWTYPE; st alert_condition_states%ROWTYPE;
        t collector_source_retirements%ROWTYPE; m collector_source_replacement_requests%ROWTYPE; a alerts%ROWTYPE;
    BEGIN
        SELECT * INTO g FROM situation_closure_grants WHERE id=NEW.grant_id;
        IF g.proof_version=1 THEN RETURN NEW; END IF;
        SELECT pol.* INTO q FROM situation_recovery_policy_requests pol JOIN situation_recovery_policy_reviews rv ON rv.request_id=pol.id WHERE rv.id=g.policy_review_id;
        p:=NEW.proof::jsonb->'recovery';
        IF {root} OR {report} OR {_clocks('p', 'evaluated_at valid_until')} OR p->>'verification_basis' IS DISTINCT FROM 'peer_reviewed_source_recovery/v2'
            OR octet_length(NEW.proof::text)>2097152
            OR p->'qualified_recovery' IS DISTINCT FROM 'true'::jsonb OR p->'covers_situation' IS DISTINCT FROM 'true'::jsonb
            OR p->'production_qualified' IS DISTINCT FROM to_jsonb(q.evidence_environment='production')
            OR p->'authorizes_incident_closure' IS DISTINCT FROM 'false'::jsonb OR p->'closure_execution_available' IS DISTINCT FROM 'false'::jsonb
            OR p->'physical_truth_automatically_verified' IS DISTINCT FROM 'false'::jsonb OR p->'remediation_causality_proven' IS DISTINCT FROM 'false'::jsonb
            OR jsonb_typeof(p->'membership') IS DISTINCT FROM 'array' OR jsonb_array_length(p->'membership') NOT BETWEEN 1 AND 512
            OR jsonb_typeof(p->'source_evidence') IS DISTINCT FROM 'array' OR jsonb_array_length(p->'source_evidence') NOT BETWEEN 1 AND 64
            OR jsonb_typeof(p->'member_count') IS DISTINCT FROM 'number' OR p->>'member_count' !~ '^[1-9][0-9]*$'
            OR (p->>'member_count')::int<>jsonb_array_length(p->'membership')
            OR jsonb_typeof(NEW.proof::jsonb->'related_actions') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.proof::jsonb->'related_actions')>256
            OR (p->>'evaluated_at')::timestamptz>NEW.committed_at OR (p->>'valid_until')::timestamptz<=NEW.committed_at
            OR (p->>'evaluated_at')::timestamptz>clock_timestamp() OR NEW.committed_at>clock_timestamp()
            OR (p->>'valid_until')::timestamptz>q.expires_at
            OR (p->>'valid_until')::timestamptz<=clock_timestamp()
            THEN RAISE EXCEPTION 'Replacement closure typed proof, literal flags or validity are invalid'; END IF;
        -- Keep the complete producer/source/role prefix from the authority
        -- trigger; lower state, membership and Alert locks never wait.
        FOR sid IN SELECT b->>'source_id' FROM jsonb_array_elements(q.source_bindings::jsonb) b ORDER BY b->>'source_id' LOOP
            PERFORM 1 FROM alert_condition_states cs JOIN collector_condition_sources src ON src.dedup_key=cs.dedup_key
                WHERE src.id=sid AND cs.tenant_id=NEW.tenant_id AND cs.region_id=NEW.region_id FOR UPDATE OF cs NOWAIT;
        END LOOP;
        PERFORM 1 FROM situations WHERE id=NEW.situation_id AND tenant_id=NEW.tenant_id AND region_id=NEW.region_id FOR UPDATE NOWAIT;
        PERFORM 1 FROM situation_alerts sm JOIN alerts al ON al.id=sm.alert_id WHERE sm.situation_id=NEW.situation_id ORDER BY al.id FOR UPDATE OF sm,al NOWAIT;
        FOR pin IN SELECT value FROM jsonb_array_elements(p->'membership') LOOP
            IF {pin} OR {_clocks('pin', 'first_seen last_seen')} OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.proof::jsonb->'membership_identity'->'members') x
                WHERE x=pin-'status'-'last_seen'-'occurrence_count'-'source_retirement_id')
                OR NOT EXISTS(SELECT 1 FROM situation_alerts sm JOIN alerts al ON al.id=sm.alert_id WHERE sm.id=pin->>'membership_id'
                    AND sm.situation_id=NEW.situation_id AND al.id=pin->>'alert_id' AND lower(al.status)=pin->>'status'
                    AND al.last_seen=(pin->>'last_seen')::timestamptz AND al.first_seen=(pin->>'first_seen')::timestamptz
                    AND al.occurrence_count=(pin->>'occurrence_count')::int AND al.source_retirement_id IS NOT DISTINCT FROM pin->>'source_retirement_id')
                THEN RAISE EXCEPTION 'Replacement closure frozen membership is invalid'; END IF;
            IF jsonb_typeof(pin->'occurrence_count') IS DISTINCT FROM 'number' OR pin->>'occurrence_count' !~ '^[1-9][0-9]*$'
                THEN RAISE EXCEPTION 'Replacement closure occurrence count must be a strict positive integer'; END IF;
        END LOOP;
        IF jsonb_array_length(p->'membership')<>(SELECT count(*) FROM situation_alerts WHERE situation_id=NEW.situation_id)
            THEN RAISE EXCEPTION 'Replacement closure does not cover all Situation members'; END IF;
        FOR item IN SELECT value FROM jsonb_array_elements(p->'source_evidence') LOOP
            IF {source} OR {_clocks('item', 'quiet_observed_at quiet_window_start quiet_after')}
                OR {_ids('item', 'source_id qualification_review_id qualification_request_id quiet_receipt_id quiet_admission_id')}
                OR item->>'source_id'=ANY(seen) OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(q.source_bindings::jsonb) b
                JOIN collector_source_qualification_reviews rv ON rv.id=b->>'qualification_review_id'
                WHERE b->>'source_id'=item->>'source_id' AND rv.id=item->>'qualification_review_id' AND rv.request_id=item->>'qualification_request_id')
                OR jsonb_typeof(item->'condition_revision') IS DISTINCT FROM 'number' OR item->>'condition_revision' !~ '^[1-9][0-9]*$'
                OR jsonb_typeof(item->'quiet_sample_receipt_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(item->'quiet_sample_receipt_ids') NOT BETWEEN 2 AND 256
                OR jsonb_typeof(item->'members') IS DISTINCT FROM 'array' OR jsonb_array_length(item->'members') NOT BETWEEN 1 AND 512
                THEN RAISE EXCEPTION 'Replacement closure source references are malformed'; END IF;
            seen:=array_append(seen,item->>'source_id');
            SELECT * INTO s FROM collector_condition_sources WHERE id=item->>'source_id';
            SELECT * INTO qr FROM collector_source_qualification_requests WHERE id=item->>'qualification_request_id';
            SELECT * INTO st FROM alert_condition_states WHERE dedup_key=s.dedup_key AND tenant_id=NEW.tenant_id AND region_id=NEW.region_id FOR UPDATE NOWAIT;
            latest_at:=(item->>'quiet_observed_at')::timestamptz; start_at:=(item->>'quiet_window_start')::timestamptz; floor_at:=(item->>'quiet_after')::timestamptz;
            IF s.id IS NULL OR qr.source_id<>s.id OR st.id IS NULL OR st.state<>'quiet' OR st.revision<>(item->>'condition_revision')::int
                OR st.observed_at<>latest_at OR st.latest_alert_id IS DISTINCT FROM item->>'current_alert_id'
                OR NOT floor_at<start_at OR start_at>latest_at OR latest_at>clock_timestamp()
                OR latest_at<clock_timestamp()-make_interval(secs=>LEAST(q.max_age_seconds,(s.context::jsonb #>> '{{definition,max_age_seconds}}')::int))
                OR (p->>'valid_until')::timestamptz>qr.expires_at
                OR (p->>'valid_until')::timestamptz>latest_at+make_interval(secs=>LEAST(q.max_age_seconds,(s.context::jsonb #>> '{{definition,max_age_seconds}}')::int))
                OR EXISTS(SELECT 1 FROM collector_condition_admissions adm WHERE adm.deployment_id=s.deployment_id AND adm.artifact_version_id=s.artifact_version_id
                    AND adm.context::jsonb #>> '{{pins,assignment_sha256}}'=s.assignment_sha256 AND adm.context::jsonb #>> '{{pins,definition,key}}'=s.condition_key
                    AND adm.context::jsonb #>> '{{pins,entity,id}}'=s.entity_id AND adm.context::jsonb #>> '{{pins,entity,type}}'=s.entity_type
                    AND adm.context::jsonb #> '{{pins,credential_profile}}' IS NOT DISTINCT FROM s.context::jsonb->'credential_profile' AND adm.observed_at>latest_at)
                THEN RAISE EXCEPTION 'Replacement closure current quiet state or admitted clock is invalid'; END IF;
            IF st.latest_alert_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM alerts WHERE id=st.latest_alert_id AND status='RESOLVED' AND source_retirement_id IS NULL)
                THEN RAISE EXCEPTION 'Replacement closure current Alert disagrees with quiet'; END IF;
            SELECT array_agg(value ORDER BY ord) INTO samples FROM jsonb_array_elements_text(item->'quiet_sample_receipt_ids') WITH ORDINALITY x(value,ord);
            IF cardinality(samples)<q.min_quiet_samples OR cardinality(samples)<>(SELECT count(DISTINCT value) FROM unnest(samples) value)
                OR samples[1]<>item->>'quiet_receipt_id' OR extract(epoch FROM latest_at-start_at)<q.min_quiet_seconds
                OR samples IS DISTINCT FROM (SELECT array_agg(id::text ORDER BY observed_at DESC,id) FROM collector_condition_receipts
                    WHERE source_id=s.id AND observed_at BETWEEN start_at AND latest_at AND disposition IN ('accepted','conflict'))
                THEN RAISE EXCEPTION 'Replacement closure samples omit or bridge evidence'; END IF;
            previous_at:=NULL;
            FOREACH sample_id IN ARRAY samples LOOP
                SELECT * INTO r FROM collector_condition_receipts WHERE id=sample_id;
                IF r.id IS NULL OR r.source_id<>s.id OR r.condition_state_id<>st.id OR r.verdict<>'quiet' OR r.disposition<>'accepted' OR r.observed_at<=floor_at
                    OR (previous_at IS NOT NULL AND (r.observed_at>=previous_at OR extract(epoch FROM previous_at-r.observed_at)>q.max_sample_gap_seconds))
                    OR (previous_at IS NULL AND (r.observed_at<>latest_at OR r.admission_id<>item->>'quiet_admission_id' OR r.alert_id IS DISTINCT FROM item->>'current_alert_id'))
                    THEN RAISE EXCEPTION 'Replacement closure quiet receipt provenance or ordered clocks are invalid'; END IF;
                previous_at:=r.observed_at;
            END LOOP;
            IF previous_at<>start_at THEN RAISE EXCEPTION 'Replacement closure window start is not an actual sample'; END IF;
            FOR member IN SELECT value FROM jsonb_array_elements(item->'members') LOOP
                IF {member} OR {_ids('member', 'alert_id active_receipt_id active_source_id qualification_request_id qualification_review_id')}
                    OR member->>'alert_id'=ANY(covered) THEN RAISE EXCEPTION 'Replacement closure member reference is malformed or repeated'; END IF;
                covered:=array_append(covered,member->>'alert_id');
                SELECT value INTO pin FROM jsonb_array_elements(p->'membership') WHERE value->>'alert_id'=member->>'alert_id';
                SELECT * INTO ar FROM collector_condition_receipts WHERE id=member->>'active_receipt_id';
                SELECT * INTO a FROM alerts WHERE id=member->>'alert_id';
                IF pin IS NULL OR ar.id IS NULL OR ar.source_id<>member->>'active_source_id' OR ar.alert_id<>a.id OR ar.verdict<>'active' OR ar.disposition<>'accepted'
                    OR NOT EXISTS(SELECT 1 FROM collector_source_qualification_reviews rv JOIN collector_source_qualification_requests rq ON rq.id=rv.request_id
                        JOIN collector_condition_sources src ON src.id=rq.source_id WHERE rv.id=member->>'qualification_review_id' AND rq.id=member->>'qualification_request_id'
                        AND src.id=ar.source_id AND src.dedup_key=a.dedup_key AND src.entity_type=a.entity_type AND src.entity_id=a.entity_id
                        AND src.context::jsonb #>> '{{definition,event_type}}'=a.event_type)
                    OR floor_at<GREATEST(ar.observed_at,a.last_seen)
                    THEN RAISE EXCEPTION 'Replacement closure historical active provenance is invalid'; END IF;
                IF member->>'retirement_id' IS NULL THEN
                    IF ar.source_id<>s.id OR member->>'qualification_review_id'<>item->>'qualification_review_id' OR member->>'replacement_request_id' IS NOT NULL
                        OR member->>'replacement_review_id' IS NOT NULL OR a.status<>'RESOLVED' OR a.source_retirement_id IS NOT NULL
                        THEN RAISE EXCEPTION 'Direct recovery cannot manufacture replacement authority'; END IF;
                ELSE
                    SELECT * INTO t FROM collector_source_retirements WHERE id=member->>'retirement_id';
                    SELECT rq.* INTO m FROM collector_source_replacement_requests rq JOIN collector_source_replacement_reviews rv ON rv.request_id=rq.id
                        WHERE rv.id=member->>'replacement_review_id' AND rq.id=member->>'replacement_request_id';
                    IF t.id IS NULL OR m.id IS NULL OR t.old_source_id<>ar.source_id OR m.old_source_id<>ar.source_id OR m.new_source_id<>s.id
                        OR m.old_qualification_review_id<>member->>'qualification_review_id'
                        OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(q.replacement_bindings::jsonb) b WHERE b->>'old_source_id'=ar.source_id
                            AND b->>'retirement_id'=t.id AND b->>'replacement_review_id'=member->>'replacement_review_id')
                        OR GREATEST(ar.observed_at,a.last_seen)>(t.old_state_snapshot::jsonb->>'admitted_through_at')::timestamptz
                        OR floor_at<(t.old_state_snapshot::jsonb->>'admitted_through_at')::timestamptz
                        OR (a.status='RESOLVED' AND a.source_retirement_id IS NOT NULL)
                        OR (a.status<>'RESOLVED' AND (a.source_retirement_id IS DISTINCT FROM t.id OR t.superseded_alert_id IS DISTINCT FROM a.id))
                        THEN RAISE EXCEPTION 'Replacement closure retirement or exact mapping provenance is invalid'; END IF;
                END IF;
            END LOOP;
            FOR action IN SELECT value FROM jsonb_array_elements(NEW.proof::jsonb->'related_actions') LOOP
                IF action->>'finished_at' IS NOT NULL AND floor_at<(action->>'finished_at')::timestamptz
                    THEN RAISE EXCEPTION 'Replacement closure quiet samples precede related terminal verification'; END IF;
            END LOOP;
        END LOOP;
        IF cardinality(covered)<>jsonb_array_length(p->'membership') THEN RAISE EXCEPTION 'Replacement closure coverage is incomplete'; END IF;
        RETURN NEW;
    END; $$"""))
    op.execute(sa.text("CREATE TRIGGER icheck_02_replacement_closure_proof BEFORE INSERT ON situation_closure_receipts FOR EACH ROW EXECUTE FUNCTION icheck_guard_replacement_closure_proof()"))


def upgrade():
    bind = op.get_bind(); pg = bind.dialect.name == "postgresql"
    if bind.dialect.name not in {"postgresql", "sqlite"}: raise RuntimeError("Replacement closure requires PostgreSQL or SQLite")
    _visible_drained(bind)
    if pg:
        op.add_column(GRANTS, sa.Column("proof_version", sa.Integer(), nullable=False, server_default="1"))
        op.create_check_constraint("ck_situation_closure_grant_proof_version", GRANTS, "proof_version IN (1,2)")
    else:
        op.execute(sa.text(f"ALTER TABLE {GRANTS} ADD COLUMN proof_version INTEGER NOT NULL DEFAULT 1 CONSTRAINT ck_situation_closure_grant_proof_version CHECK(proof_version IN (1,2))"))
    _compatibility(pg); _receipt_contract(bind)
    if pg:
        _authority(bind); _proof()
        op.execute(sa.text(_once(_function(bind, "icheck_closure_action_fence"), "a.status<>'RESOLVED'", "a.status<>'RESOLVED' AND a.source_retirement_id IS NULL")))


def downgrade():
    bind = op.get_bind(); pg = bind.dialect.name == "postgresql"
    _visible_drained(bind)
    if bind.execute(sa.text("SELECT 1 FROM situation_closure_grants WHERE proof_version<>1 LIMIT 1")).first():
        raise RuntimeError("Retain explicit replacement closure grants and owned history; downgrade is refused")
    _receipt_contract(bind, reverse=True); _compatibility(pg, reverse=True)
    if pg:
        for table in (GRANTS, "situation_closure_requests", "situation_closure_receipts"):
            op.execute(sa.text(f"DROP TRIGGER icheck_01_replacement_closure_authority ON {table}"))
        op.execute(sa.text("DROP TRIGGER icheck_02_replacement_closure_proof ON situation_closure_receipts"))
        op.execute(sa.text("DROP FUNCTION icheck_guard_replacement_closure_authority()"))
        op.execute(sa.text("DROP FUNCTION icheck_guard_replacement_closure_proof()"))
        op.execute(sa.text(_once(_function(bind, "icheck_closure_action_fence"), "a.status<>'RESOLVED' AND a.source_retirement_id IS NULL", "a.status<>'RESOLVED'")))
        op.drop_constraint("ck_situation_closure_grant_proof_version", GRANTS, type_="check")
    op.drop_column(GRANTS, "proof_version")
