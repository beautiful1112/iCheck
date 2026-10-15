"""Leased reviewed closure ledger, native action fence; no backfill or host enablement."""
from alembic import op
import sqlalchemy as sa

revision = "c7e9g1i3k5m8"
down_revision = "b6d8f0h2j4l7"
branch_labels = depends_on = None
TABLES = tuple("situation_closure_" + name for name in
    ("grants", "revocations", "requests", "ownerships", "attempts", "receipts"))


def ref(name, target, *, nullable=False):
    return sa.Column(name, sa.String(36), sa.ForeignKey(target + ".id", ondelete="RESTRICT"), nullable=nullable)


def col(name, kind, *, nullable=False):
    return sa.Column(name, kind, nullable=nullable)


def base():
    return [col("id", sa.String(36)), col("tenant_id", sa.String(36)), col("region_id", sa.String(36)),
        sa.PrimaryKeyConstraint("id")]


def upgrade():
    dialect = op.get_bind().dialect.name
    if dialect not in {"postgresql", "sqlite"}:
        raise RuntimeError("Reviewed Situation closure requires PostgreSQL or SQLite")
    dt = sa.DateTime(timezone=True)
    op.create_table(TABLES[0], *base(), col("request_key", sa.String(128)),
        ref("policy_review_id", "situation_recovery_policy_reviews"), col("proof_basis", sa.String(32)),
        ref("remediation_version_id", "artifact_versions", nullable=True), col("remediation_snapshot", sa.JSON(), nullable=True),
        ref("reviewer_principal_id", "control_plane_principals"), col("reviewer_subject", sa.String(255)),
        col("acceptance_reference", sa.String(1024)), col("reason", sa.String(512)), col("max_lease_seconds", sa.Integer()),
        col("expires_at", dt), col("created_at", dt),
        sa.UniqueConstraint("tenant_id", "region_id", "request_key", name="uq_situation_closure_grant_key"),
        sa.CheckConstraint("expires_at > created_at", name="ck_situation_closure_grant_lifetime"),
        sa.CheckConstraint("max_lease_seconds BETWEEN 5 AND 120", name="ck_situation_closure_grant_lease"),
        sa.CheckConstraint("proof_basis IN ('source_recovery','verified_remediation')", name="ck_situation_closure_grant_basis"))
    op.create_table(TABLES[1], *base(), ref("grant_id", TABLES[0]), ref("principal_id", "control_plane_principals"),
        col("subject", sa.String(255)), col("reason", sa.String(512)), col("created_at", dt),
        sa.UniqueConstraint("grant_id", name="uq_situation_closure_revocation"))
    op.create_table(TABLES[2], *base(), ref("situation_id", "situations"), ref("grant_id", TABLES[0]),
        col("request_key", sa.String(128)), ref("owner_principal_id", "control_plane_principals"), col("owner_subject", sa.String(255)),
        col("reason", sa.String(512)), col("lease_seconds", sa.Integer()), col("membership_identity", sa.JSON()), col("created_at", dt),
        sa.UniqueConstraint("tenant_id", "region_id", "situation_id", "request_key", name="uq_situation_closure_request_key"),
        sa.CheckConstraint("lease_seconds BETWEEN 5 AND 120", name="ck_situation_closure_request_lease"))
    op.create_table(TABLES[3], *base(), ref("situation_id", "situations"), ref("request_id", TABLES[2]),
        col("epoch", sa.Integer()), col("state", sa.String(16)), col("lease_expires_at", dt), col("updated_at", dt),
        sa.UniqueConstraint("situation_id", name="uq_situation_closure_ownership"),
        sa.CheckConstraint("epoch > 0", name="ck_situation_closure_ownership_epoch"),
        sa.CheckConstraint("state IN ('claimed','released','committed')", name="ck_situation_closure_ownership_state"))
    op.create_table(TABLES[4], *base(), ref("request_id", TABLES[2]), ref("ownership_id", TABLES[3]),
        col("epoch", sa.Integer()), col("token_hash", sa.String(64)), col("expires_at", dt), col("created_at", dt),
        sa.UniqueConstraint("ownership_id", "epoch", name="uq_situation_closure_attempt_epoch"),
        sa.CheckConstraint("epoch > 0 AND expires_at > created_at", name="ck_situation_closure_attempt_lifetime"))
    op.create_table(TABLES[5], *base(), ref("situation_id", "situations"), ref("grant_id", TABLES[0]),
        ref("request_id", TABLES[2]), ref("attempt_id", TABLES[4]), ref("ownership_id", TABLES[3]), col("epoch", sa.Integer()),
        ref("event_id", "situation_events"), col("event_sequence", sa.Integer()), col("proof", sa.JSON()), col("committed_at", dt),
        *[sa.UniqueConstraint(key, name="uq_situation_closure_receipt_" + name) for key, name in
            (("request_id", "request"), ("attempt_id", "attempt"), ("event_id", "event"))],
        sa.UniqueConstraint("ownership_id", "epoch", name="uq_situation_closure_receipt_epoch"))
    for table in TABLES:
        for column in ("tenant_id", "region_id"):
            op.create_index(f"ix_{table}_{column}", table, [column])
    for table, key in ((TABLES[0], "policy_review_id"), (TABLES[1], "grant_id"), (TABLES[2], "situation_id"),
        (TABLES[3], "situation_id"), (TABLES[4], "request_id"), (TABLES[5], "situation_id")):
        op.create_index(f"ix_{table}_{key}", table, [key])

    if dialect == "postgresql":
        j = lambda column, key: f"NEW.{column}::jsonb->>'{key}'"
    else:
        j = lambda column, key: f"json_extract(NEW.{column},'$.{key}')"
    ns = lambda alias: f"{alias}.tenant_id=NEW.tenant_id AND {alias}.region_id=NEW.region_id"
    human = lambda id, subject: f"EXISTS(SELECT 1 FROM control_plane_principals p WHERE p.id=NEW.{id} AND p.subject=NEW.{subject} AND p.tenant_id=NEW.tenant_id AND p.enabled AND p.principal_type='user')"
    checks = {
        TABLES[0]: f"""length(NEW.request_key) NOT BETWEEN 8 AND 128 OR length(NEW.acceptance_reference) NOT BETWEEN 10 AND 1024
            OR length(NEW.reason) NOT BETWEEN 10 AND 512 OR NOT ({human('reviewer_principal_id','reviewer_subject')})
            OR NOT EXISTS(SELECT 1 FROM situation_recovery_policy_reviews r JOIN situation_recovery_policy_requests q ON q.id=r.request_id
                WHERE r.id=NEW.policy_review_id AND {ns('r')} AND {ns('q')} AND NEW.expires_at<=q.expires_at
                AND NEW.created_at<q.expires_at AND NEW.reviewer_principal_id<>q.author_principal_id
                AND NEW.reviewer_subject<>q.author_subject AND NOT EXISTS(SELECT 1 FROM situation_recovery_policy_revocations x WHERE x.review_id=r.id))
            OR (NEW.proof_basis='source_recovery' AND (NEW.remediation_version_id IS NOT NULL OR {j('remediation_snapshot','id')} IS NOT NULL))
            OR (NEW.proof_basis='verified_remediation' AND NOT EXISTS(SELECT 1 FROM artifact_versions v
                WHERE v.id=NEW.remediation_version_id AND {ns('v')} AND v.status='PUBLISHED'
                AND v.id={j('remediation_snapshot','id')} AND v.content_hash={j('remediation_snapshot','content_hash')}
                AND v.created_by<>NEW.reviewer_subject AND (v.published_by IS NULL OR v.published_by<>NEW.reviewer_subject)))""",
        TABLES[1]: f"""length(NEW.reason) NOT BETWEEN 10 AND 512 OR NOT ({human('principal_id','subject')})
            OR NOT EXISTS(SELECT 1 FROM {TABLES[0]} g WHERE g.id=NEW.grant_id AND {ns('g')})""",
        TABLES[2]: f"""length(NEW.request_key) NOT BETWEEN 8 AND 128 OR length(NEW.reason) NOT BETWEEN 10 AND 512
            OR NOT EXISTS(SELECT 1 FROM situations s WHERE s.id=NEW.situation_id AND {ns('s')})
            OR NOT EXISTS(SELECT 1 FROM {TABLES[0]} g JOIN control_plane_principals p ON p.id=NEW.owner_principal_id
                WHERE g.id=NEW.grant_id AND {ns('g')} AND p.tenant_id=NEW.tenant_id AND p.enabled AND p.subject=NEW.owner_subject
                AND p.id<>g.reviewer_principal_id AND p.subject<>g.reviewer_subject AND NEW.lease_seconds<=g.max_lease_seconds
                AND NEW.created_at<g.expires_at AND NOT EXISTS(SELECT 1 FROM {TABLES[1]} x WHERE x.grant_id=g.id))
            OR {j('membership_identity','situation_id')} IS NULL OR {j('membership_identity','situation_id')}<>NEW.situation_id""",
        TABLES[3]: f"""NOT EXISTS(SELECT 1 FROM {TABLES[2]} q JOIN {TABLES[0]} g ON g.id=q.grant_id
                WHERE q.id=NEW.request_id AND q.situation_id=NEW.situation_id AND {ns('q')} AND {ns('g')}
                AND NEW.lease_expires_at<=g.expires_at)""",
        TABLES[4]: f"""length(NEW.token_hash)<>64 OR NOT EXISTS(SELECT 1 FROM {TABLES[3]} o WHERE o.id=NEW.ownership_id
                AND {ns('o')} AND o.request_id=NEW.request_id AND o.epoch=NEW.epoch AND o.state='claimed'
                AND o.lease_expires_at=NEW.expires_at)""",
        TABLES[5]: f"""NOT EXISTS(SELECT 1 FROM {TABLES[2]} q JOIN {TABLES[0]} g ON g.id=q.grant_id
                JOIN {TABLES[4]} a ON a.id=NEW.attempt_id JOIN {TABLES[3]} o ON o.id=a.ownership_id
                JOIN situation_events e ON e.id=NEW.event_id
                WHERE q.id=NEW.request_id AND q.situation_id=NEW.situation_id AND g.id=NEW.grant_id
                AND {ns('q')} AND {ns('g')} AND {ns('a')} AND {ns('o')} AND {ns('e')}
                AND a.request_id=q.id AND o.request_id=q.id AND o.id=NEW.ownership_id AND o.situation_id=q.situation_id
                AND a.epoch=NEW.epoch AND o.epoch=NEW.epoch AND o.state='claimed'
                AND NEW.committed_at>=a.created_at AND NEW.committed_at<a.expires_at AND NEW.committed_at<g.expires_at
                AND e.situation_id=q.situation_id AND e.sequence=NEW.event_sequence AND e.event_type='situation.closure.reviewed')
            OR {j('proof','contract')} IS NULL OR {j('proof','contract')}<>'icheck.reviewed-situation-closure/v1'""",
    }
    if dialect == "postgresql":
        checks[TABLES[0]] += """ OR (NEW.proof_basis='verified_remediation' AND NOT EXISTS(SELECT 1 FROM artifact_versions v
            WHERE v.id=NEW.remediation_version_id AND v.definition::jsonb=NEW.remediation_snapshot::jsonb->'definition'
            AND v.implementation::jsonb=NEW.remediation_snapshot::jsonb->'implementation'
            AND v.tests::jsonb=NEW.remediation_snapshot::jsonb->'tests'
            AND v.validation_report::jsonb=NEW.remediation_snapshot::jsonb->'validation_report'
            AND jsonb_array_length(v.definition::jsonb->'spec'->'change_contract'->'semantic_expectations')>0))"""
        checks[TABLES[5]] += """ OR NEW.proof::jsonb->'remediation_causality_proven' IS DISTINCT FROM 'false'::jsonb
            OR NEW.proof::jsonb->'physical_truth_automatically_verified' IS DISTINCT FROM 'false'::jsonb
            OR NEW.proof::jsonb->'recovery'->'qualified_recovery' IS DISTINCT FROM 'true'::jsonb
            OR NEW.proof::jsonb->'recovery'->'covers_situation' IS DISTINCT FROM 'true'::jsonb
            OR NEW.proof::jsonb->'recovery'->'blockers' IS DISTINCT FROM '[]'::jsonb
            OR NOT EXISTS(SELECT 1 FROM situation_closure_requests q WHERE q.id=NEW.request_id
                AND q.membership_identity::jsonb=NEW.proof::jsonb->'membership_identity'
                AND q.owner_principal_id=NEW.proof::jsonb->>'owner_principal_id'
                AND q.owner_subject=NEW.proof::jsonb->>'owner_subject')
            OR NOT EXISTS(SELECT 1 FROM situation_closure_grants g JOIN situation_recovery_policy_reviews r ON r.id=g.policy_review_id
                JOIN situation_recovery_policy_requests p ON p.id=r.request_id WHERE g.id=NEW.grant_id
                AND g.proof_basis=NEW.proof::jsonb->>'proof_basis' AND g.reviewer_principal_id=NEW.proof::jsonb->>'reviewer_principal_id'
                AND g.reviewer_subject=NEW.proof::jsonb->>'reviewer_subject'
                AND g.acceptance_reference=NEW.proof::jsonb->>'acceptance_reference'
                AND p.evidence_environment=NEW.proof::jsonb->>'evidence_environment'
                AND r.id=NEW.proof::jsonb->'recovery'->>'policy_review_id'
                AND NEW.situation_id=NEW.proof::jsonb->'recovery'->>'situation_id')
            OR NOT EXISTS(SELECT 1 FROM situation_closure_attempts a JOIN situation_closure_grants g ON g.id=NEW.grant_id
                WHERE a.id=NEW.attempt_id AND clock_timestamp()<a.expires_at AND clock_timestamp()<g.expires_at)"""
    else:
        checks[TABLES[5]] += """ OR json_type(NEW.proof,'$.remediation_causality_proven') IS NOT 'false'
            OR json_type(NEW.proof,'$.physical_truth_automatically_verified') IS NOT 'false'
            OR json_type(NEW.proof,'$.recovery.qualified_recovery') IS NOT 'true'
            OR json_type(NEW.proof,'$.recovery.covers_situation') IS NOT 'true'
            OR json_extract(NEW.proof,'$.recovery.blockers') IS NOT '[]'
            OR NOT EXISTS(SELECT 1 FROM situation_closure_requests q WHERE q.id=NEW.request_id
                AND json(q.membership_identity)=json(json_extract(NEW.proof,'$.membership_identity')))"""
    for table in TABLES:
        if dialect == "postgresql":
            for action in ("ENABLE", "FORCE"):
                op.execute(sa.text(f"ALTER TABLE {table} {action} ROW LEVEL SECURITY"))
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)) WITH CHECK (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))"))
            mutation = """IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Closure ownership cannot be deleted'; END IF;
                IF TG_OP='INSERT' AND (NEW.epoch<>1 OR NEW.state<>'claimed') THEN RAISE EXCEPTION 'Initial closure ownership must be claimed epoch one'; END IF;
                IF TG_OP='UPDATE' AND (NEW.id<>OLD.id OR NEW.situation_id<>OLD.situation_id OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id
                    OR NEW.epoch NOT BETWEEN OLD.epoch AND OLD.epoch+1 OR NEW.updated_at<OLD.updated_at
                    OR (NEW.epoch=OLD.epoch AND (NEW.request_id<>OLD.request_id OR NEW.lease_expires_at<>OLD.lease_expires_at
                        OR OLD.state<>'claimed' OR NEW.state NOT IN ('released','committed')))
                    OR (NEW.epoch=OLD.epoch+1 AND (NEW.state<>'claimed' OR (OLD.state='claimed' AND NEW.updated_at<OLD.lease_expires_at))))
                    THEN RAISE EXCEPTION 'Closure ownership transition is invalid'; END IF;
                IF TG_OP='UPDATE' AND NEW.state='committed' AND NOT EXISTS(SELECT 1 FROM situation_closure_receipts r WHERE r.ownership_id=NEW.id AND r.epoch=NEW.epoch AND r.request_id=NEW.request_id)
                    THEN RAISE EXCEPTION 'Closure ownership requires its committed receipt'; END IF;""" if table == TABLES[3] else "IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Situation closure history is append-only'; END IF;"
            op.execute(sa.text(f"CREATE FUNCTION icheck_guard_{table}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {mutation} IF {checks[table]} THEN RAISE EXCEPTION 'Situation closure references or proof are invalid'; END IF; RETURN NEW; END; $$"))
            op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table} BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_guard_{table}()"))
        else:
            op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table} BEFORE INSERT ON {table} WHEN {checks[table]} BEGIN SELECT RAISE(ABORT,'Situation closure references or proof are invalid'); END"))
            for action in ("UPDATE", "DELETE"):
                if table == TABLES[3] and action == "UPDATE":
                    condition = "NEW.id<>OLD.id OR NEW.situation_id<>OLD.situation_id OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id OR NEW.epoch NOT BETWEEN OLD.epoch AND OLD.epoch+1 OR NEW.updated_at<OLD.updated_at OR (NEW.epoch=OLD.epoch AND (OLD.state<>'claimed' OR NEW.state NOT IN ('released','committed') OR NEW.request_id<>OLD.request_id OR NEW.lease_expires_at<>OLD.lease_expires_at)) OR (NEW.epoch=OLD.epoch+1 AND (NEW.state<>'claimed' OR (OLD.state='claimed' AND NEW.updated_at<OLD.lease_expires_at)))"
                    condition += " OR (NEW.state='committed' AND NOT EXISTS(SELECT 1 FROM situation_closure_receipts r WHERE r.ownership_id=NEW.id AND r.epoch=NEW.epoch AND r.request_id=NEW.request_id))"
                    op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table}_update BEFORE UPDATE ON {table} WHEN ({condition}) OR ({checks[table]}) BEGIN SELECT RAISE(ABORT,'Closure ownership transition is invalid'); END"))
                else:
                    op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'Situation closure history is append-only'); END"))
    if dialect == "postgresql":
        op.execute(sa.text("""CREATE FUNCTION icheck_closure_action_fence() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE sid text; ns_t text; ns_r text; current_row situations%ROWTYPE;
        BEGIN
            IF TG_OP='DELETE' THEN ns_t:=OLD.tenant_id; ns_r:=OLD.region_id;
            ELSE ns_t:=NEW.tenant_id; ns_r:=NEW.region_id; END IF;
            IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('icheck.closure/v1/'||ns_t||'/'||ns_r,0))
                THEN RAISE EXCEPTION 'Situation closure/action fence is busy' USING ERRCODE='55P03'; END IF;
            IF TG_OP='DELETE' THEN RETURN OLD; END IF;
            SELECT situation_id INTO sid FROM investigations WHERE id=NEW.investigation_id AND tenant_id=ns_t AND region_id=ns_r;
            IF sid IS NULL THEN RETURN NEW; END IF;
            IF TG_OP='UPDATE' AND NEW.status NOT IN ('pending','approved','executing') THEN RETURN NEW; END IF;
            SELECT * INTO current_row FROM situations WHERE id=sid AND tenant_id=ns_t AND region_id=ns_r FOR UPDATE NOWAIT;
            IF EXISTS(SELECT 1 FROM situation_closure_ownerships o WHERE o.situation_id=sid AND o.state='claimed' AND o.lease_expires_at>clock_timestamp())
                THEN RAISE EXCEPTION 'Situation has an active reviewed closure lease'; END IF;
            IF NOT EXISTS(SELECT 1 FROM situation_alerts m JOIN alerts a ON a.id=m.alert_id WHERE m.situation_id=sid AND a.status<>'RESOLVED')
                AND EXISTS(SELECT 1 FROM situation_closure_receipts r WHERE r.situation_id=sid
                    AND r.proof::jsonb->'membership_identity'->>'correlation_key'=current_row.correlation_key
                    AND r.proof::jsonb->'membership_identity'->>'correlation_version'=current_row.correlation_version
                    AND r.proof::jsonb->'membership_identity'->>'primary_entity_type'=current_row.primary_entity_type
                    AND r.proof::jsonb->'membership_identity'->>'primary_entity_id'=current_row.primary_entity_id
                    AND jsonb_array_length(r.proof::jsonb->'membership_identity'->'members')=(SELECT count(*) FROM situation_alerts m WHERE m.situation_id=sid)
                    AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(r.proof::jsonb->'membership_identity'->'members') x
                        WHERE NOT EXISTS(SELECT 1 FROM situation_alerts m JOIN alerts a ON a.id=m.alert_id
                            WHERE m.situation_id=sid AND m.id=x->>'membership_id' AND a.id=x->>'alert_id'
                            AND a.dedup_key=x->>'dedup_key' AND a.event_type=x->>'event_type' AND a.entity_type=x->>'entity_type'
                            AND a.entity_id=x->>'entity_id' AND a.first_seen=(x->>'first_seen')::timestamptz)))
                THEN RAISE EXCEPTION 'Unchanged independently closed Situation cannot propose a new action'; END IF;
            RETURN NEW;
        END; $$"""))
        op.execute(sa.text("CREATE TRIGGER icheck_closure_action_fence BEFORE INSERT OR UPDATE OR DELETE ON agent_action_proposals FOR EACH ROW EXECUTE FUNCTION icheck_closure_action_fence()"))
        op.execute(sa.text("""CREATE FUNCTION icheck_closure_investigation_fence() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE ns_t text; ns_r text; sid text;
        BEGIN
            IF TG_OP='DELETE' THEN ns_t:=OLD.tenant_id; ns_r:=OLD.region_id; sid:=OLD.situation_id;
            ELSE ns_t:=NEW.tenant_id; ns_r:=NEW.region_id; sid:=NEW.situation_id; END IF;
            IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('icheck.closure/v1/'||ns_t||'/'||ns_r,0))
                THEN RAISE EXCEPTION 'Situation closure/action fence is busy' USING ERRCODE='55P03'; END IF;
            IF TG_OP='DELETE' AND (EXISTS(SELECT 1 FROM situation_closure_ownerships o WHERE o.situation_id=sid)
                OR EXISTS(SELECT 1 FROM situation_closure_receipts r, jsonb_array_elements(r.proof::jsonb->'related_actions') a WHERE a->>'investigation_id'=OLD.id))
                THEN RAISE EXCEPTION 'Retain investigation bound to reviewed closure history'; END IF;
            IF TG_OP='UPDATE' AND NEW.situation_id IS DISTINCT FROM OLD.situation_id
                AND EXISTS(SELECT 1 FROM situation_closure_ownerships o WHERE o.situation_id IN (OLD.situation_id,NEW.situation_id))
                THEN RAISE EXCEPTION 'Investigation cannot change its reviewed-closure Situation binding'; END IF;
            IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
        END; $$"""))
        op.execute(sa.text("CREATE TRIGGER icheck_closure_investigation_fence BEFORE INSERT OR UPDATE OR DELETE ON investigations FOR EACH ROW EXECUTE FUNCTION icheck_closure_investigation_fence()"))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in TABLES:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Closure downgrade requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE " + ", ".join(TABLES) + " IN ACCESS EXCLUSIVE MODE"))
    for table in TABLES:
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Retain populated Situation closure history; downgrade is refused")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP TRIGGER icheck_closure_investigation_fence ON investigations"))
        op.execute(sa.text("DROP FUNCTION icheck_closure_investigation_fence()"))
        op.execute(sa.text("DROP TRIGGER icheck_closure_action_fence ON agent_action_proposals"))
        op.execute(sa.text("DROP FUNCTION icheck_closure_action_fence()"))
    for table in reversed(TABLES):
        op.drop_table(table)
        if bind.dialect.name == "postgresql":
            op.execute(sa.text(f"DROP FUNCTION icheck_guard_{table}()"))
