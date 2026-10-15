"""Immutable indexed action routing, conservative historical backfill; drained rollout."""
from datetime import datetime, timezone
import json
from uuid import uuid4

from alembic import op
import sqlalchemy as sa

revision = "d8f0h2j4l6n9"
down_revision = "c7e9g1i3k5m8"
branch_labels = depends_on = None
ADMISSIONS = "action_target_admissions"
KEYS = "action_target_keys"
PARENTS = ("agent_action_proposals", "governed_change_plans", "investigations",
    "agent_executions", "situation_closure_ownerships")


def _routing(contract, targets):
    bindings = contract.get("authorization_target_paths", {}) if isinstance(contract, dict) else {}
    if not isinstance(bindings, dict) or not 0 < len(bindings) <= 16:
        return [], True
    keys = set(); unknown = False
    for path, kind in bindings.items():
        value = targets.get(path) if isinstance(targets, dict) else None
        if (not isinstance(kind, str) or kind not in {"device_id", "site"} or not isinstance(value, str)
            or not value.strip(" \t\n\r\f\v") or len(value) > (36 if kind == "device_id" else 255)):
            unknown = True
        else:
            keys.add((kind, value))
    return [{"kind": kind, "value": value} for kind, value in sorted(keys)], unknown


def _all_visible(bind, tables):
    if bind.dialect.name == "postgresql":
        for table in tables:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Action target migration requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE " + ", ".join(tables) + " IN ACCESS EXCLUSIVE MODE"))


def upgrade():
    bind = op.get_bind(); dialect = bind.dialect.name
    if dialect not in {"postgresql", "sqlite"}:
        raise RuntimeError("Action target admission requires PostgreSQL or SQLite")
    _all_visible(bind, PARENTS)
    if bind.execute(sa.text("SELECT 1 FROM agent_executions WHERE status='RUNNING' OR lease_token_hash IS NOT NULL LIMIT 1")).first():
        raise RuntimeError("Drain Agent executions before action target admission migration")
    if bind.execute(sa.text("SELECT 1 FROM situation_closure_ownerships WHERE state='claimed' LIMIT 1")).first():
        raise RuntimeError("Release retained closure claims before action target admission migration")
    ns = lambda: [sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("region_id", sa.String(36), nullable=False)]
    fk = lambda name, table, nullable=False: sa.Column(name, sa.String(36), sa.ForeignKey(table + ".id", ondelete="RESTRICT"), nullable=nullable)
    op.create_table(ADMISSIONS, sa.Column("id", sa.String(36), primary_key=True), *ns(),
        fk("proposal_id", "agent_action_proposals"), fk("investigation_id", "investigations"),
        fk("situation_id", "situations", True), fk("tool_id", "agent_tool_registrations"),
        fk("change_plan_id", "governed_change_plans", True), fk("routing_plan_id", "governed_change_plans", True), fk("rollback_of_change_plan_id", "governed_change_plans", True),
        sa.Column("origin", sa.String(32), nullable=False), sa.Column("unknown_targets", sa.Boolean(), nullable=False),
        sa.Column("contract_snapshot", sa.JSON(), nullable=False), sa.Column("target_snapshot", sa.JSON(), nullable=False),
        sa.Column("target_keys", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("proposal_id", name="uq_action_target_admission_proposal"),
        sa.CheckConstraint("id=proposal_id", name="ck_action_target_admission_identity"),
        sa.CheckConstraint("origin IN ('frozen_plan','frozen_rollback_plan','legacy_unknown')", name="ck_action_target_admission_origin"))
    op.create_table(KEYS, sa.Column("id", sa.String(36), primary_key=True), *ns(), fk("admission_id", ADMISSIONS),
        sa.Column("target_kind", sa.String(16), nullable=False), sa.Column("target_id", sa.String(255), nullable=False),
        sa.CheckConstraint("target_kind IN ('device_id','site')", name="ck_action_target_key_kind"),
        sa.UniqueConstraint("admission_id", "target_kind", "target_id", name="uq_action_target_key"))
    for table in (ADMISSIONS, KEYS):
        for column in ("tenant_id", "region_id"):
            op.create_index(f"ix_{table}_{column}", table, [column])
    op.create_index("ix_action_target_admissions_investigation_id", ADMISSIONS, ["investigation_id"])
    op.create_index("ix_action_target_admission_situation", ADMISSIONS, ["tenant_id", "region_id", "situation_id", "id"])
    op.create_index("ix_action_target_admission_unknown", ADMISSIONS, ["tenant_id", "region_id", "unknown_targets", "id"])
    op.create_index("ix_action_target_key_lookup", KEYS, ["tenant_id", "region_id", "target_kind", "target_id", "admission_id"])
    if dialect == "postgresql":
        _postgres()
        bind.execute(sa.text("SELECT icheck_seal_action_targets(id) FROM agent_action_proposals ORDER BY id"))
    else:
        _sqlite_backfill(bind)
        _sqlite()


def _postgres():
    for table in (ADMISSIONS, KEYS):
        op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)) WITH CHECK (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))"))
    op.execute(sa.text("""CREATE FUNCTION icheck_action_target_keys(c jsonb,t jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
        SELECT COALESCE(jsonb_agg(jsonb_build_object('kind',kind,'value',value) ORDER BY kind COLLATE "C",value COLLATE "C"),'[]'::jsonb)
        FROM (SELECT DISTINCT x.value AS kind,t->>x.key AS value FROM jsonb_each_text(
            CASE WHEN jsonb_typeof(c->'authorization_target_paths')='object' THEN c->'authorization_target_paths' ELSE '{}'::jsonb END) x
            WHERE (SELECT count(*) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(c->'authorization_target_paths')='object' THEN c->'authorization_target_paths' ELSE '{}'::jsonb END)) BETWEEN 1 AND 16
            AND x.value IN ('device_id','site') AND jsonb_typeof(t->x.key)='string' AND btrim(t->>x.key,E' \\t\\n\\r\\f\\013')<>''
            AND length(t->>x.key)<=CASE WHEN x.value='device_id' THEN 36 ELSE 255 END) keys;
        $$"""))
    op.execute(sa.text("""CREATE FUNCTION icheck_action_target_unknown(c jsonb,t jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
        SELECT NOT (jsonb_typeof(c->'authorization_target_paths')='object'
            AND (SELECT count(*) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(c->'authorization_target_paths')='object' THEN c->'authorization_target_paths' ELSE '{}'::jsonb END)) BETWEEN 1 AND 16)
            OR EXISTS(SELECT 1 FROM jsonb_each_text(CASE WHEN jsonb_typeof(c->'authorization_target_paths')='object' THEN c->'authorization_target_paths' ELSE '{}'::jsonb END) x
                WHERE x.value IS NULL OR x.value NOT IN ('device_id','site') OR jsonb_typeof(t->x.key) IS DISTINCT FROM 'string'
                OR btrim(t->>x.key,E' \\t\\n\\r\\f\\013')='' OR length(t->>x.key)>CASE WHEN x.value='device_id' THEN 36 ELSE 255 END)
            OR c->'authorization_target_paths' IS NULL;
        $$"""))
    op.execute(sa.text("""CREATE FUNCTION icheck_guard_action_target_admission() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE p agent_action_proposals%ROWTYPE; i investigations%ROWTYPE; g governed_change_plans%ROWTYPE; r governed_change_plans%ROWTYPE;
            c jsonb; t jsonb;
        BEGIN
            IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Action target admission history is append-only'; END IF;
            IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('icheck.closure/v1/'||NEW.tenant_id||'/'||NEW.region_id,0))
                THEN RAISE EXCEPTION 'Situation closure/action fence is busy' USING ERRCODE='55P03'; END IF;
            SELECT * INTO p FROM agent_action_proposals WHERE id=NEW.proposal_id AND tenant_id=NEW.tenant_id AND region_id=NEW.region_id;
            SELECT * INTO i FROM investigations WHERE id=p.investigation_id AND tenant_id=NEW.tenant_id AND region_id=NEW.region_id;
            SELECT * INTO g FROM governed_change_plans WHERE action_proposal_id=p.id AND tenant_id=NEW.tenant_id AND region_id=NEW.region_id;
            SELECT * INTO r FROM governed_change_plans WHERE id=p.rollback_of_change_plan_id AND tenant_id=NEW.tenant_id AND region_id=NEW.region_id;
            c:=COALESCE(g.tool_contract_snapshot::jsonb,r.tool_contract_snapshot::jsonb,'{}'::jsonb); t:=COALESCE(g.target_snapshot::jsonb,r.target_snapshot::jsonb,'{}'::jsonb);
            IF p.id IS NULL OR i.id IS NULL OR NEW.investigation_id<>i.id OR NEW.situation_id IS DISTINCT FROM i.situation_id
                OR NEW.tool_id<>p.tool_id OR NEW.change_plan_id IS DISTINCT FROM g.id
                OR NEW.routing_plan_id IS DISTINCT FROM COALESCE(g.id,r.id)
                OR NEW.rollback_of_change_plan_id IS DISTINCT FROM p.rollback_of_change_plan_id
                OR NEW.origin<>(CASE WHEN g.id IS NOT NULL THEN 'frozen_plan' WHEN r.id IS NOT NULL THEN 'frozen_rollback_plan' ELSE 'legacy_unknown' END)
                OR NEW.contract_snapshot::jsonb<>c OR NEW.target_snapshot::jsonb<>t
                OR NEW.target_keys::jsonb<>icheck_action_target_keys(c,t)
                OR NEW.unknown_targets IS DISTINCT FROM icheck_action_target_unknown(c,t)
                THEN RAISE EXCEPTION 'Action target admission references or routing are invalid'; END IF;
            RETURN NEW;
        END; $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_guard_action_target_admission BEFORE INSERT OR UPDATE OR DELETE ON {ADMISSIONS} FOR EACH ROW EXECUTE FUNCTION icheck_guard_action_target_admission()"))
    op.execute(sa.text("""CREATE FUNCTION icheck_derive_action_target_keys() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        INSERT INTO action_target_keys(id,tenant_id,region_id,admission_id,target_kind,target_id)
            SELECT gen_random_uuid()::text,NEW.tenant_id,NEW.region_id,NEW.id,x->>'kind',x->>'value' FROM jsonb_array_elements(NEW.target_keys::jsonb) x;
        RETURN NEW; END; $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_derive_action_target_keys AFTER INSERT ON {ADMISSIONS} FOR EACH ROW EXECUTE FUNCTION icheck_derive_action_target_keys()"))
    op.execute(sa.text("""CREATE FUNCTION icheck_guard_action_target_key() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Action target admission history is append-only'; END IF;
        IF NOT EXISTS(SELECT 1 FROM action_target_admissions a WHERE a.id=NEW.admission_id AND a.tenant_id=NEW.tenant_id AND a.region_id=NEW.region_id
            AND a.target_keys::jsonb @> jsonb_build_array(jsonb_build_object('kind',NEW.target_kind,'value',NEW.target_id)))
            THEN RAISE EXCEPTION 'Action target key references or routing are invalid'; END IF;
        RETURN NEW; END; $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_guard_action_target_key BEFORE INSERT OR UPDATE OR DELETE ON {KEYS} FOR EACH ROW EXECUTE FUNCTION icheck_guard_action_target_key()"))
    op.execute(sa.text("""CREATE FUNCTION icheck_seal_action_targets(pid text) RETURNS void LANGUAGE plpgsql AS $$
        DECLARE p agent_action_proposals%ROWTYPE; i investigations%ROWTYPE; g governed_change_plans%ROWTYPE; r governed_change_plans%ROWTYPE; c jsonb; t jsonb;
        BEGIN
            IF EXISTS(SELECT 1 FROM action_target_admissions WHERE proposal_id=pid) THEN RETURN; END IF;
            SELECT * INTO p FROM agent_action_proposals WHERE id=pid;
            IF p.id IS NULL THEN RETURN; END IF;
            SELECT * INTO i FROM investigations WHERE id=p.investigation_id AND tenant_id=p.tenant_id AND region_id=p.region_id;
            SELECT * INTO g FROM governed_change_plans WHERE action_proposal_id=p.id AND tenant_id=p.tenant_id AND region_id=p.region_id;
            SELECT * INTO r FROM governed_change_plans WHERE id=p.rollback_of_change_plan_id AND tenant_id=p.tenant_id AND region_id=p.region_id;
            c:=COALESCE(g.tool_contract_snapshot::jsonb,r.tool_contract_snapshot::jsonb,'{}'::jsonb); t:=COALESCE(g.target_snapshot::jsonb,r.target_snapshot::jsonb,'{}'::jsonb);
            INSERT INTO action_target_admissions(id,tenant_id,region_id,proposal_id,investigation_id,situation_id,tool_id,change_plan_id,routing_plan_id,rollback_of_change_plan_id,
                origin,unknown_targets,contract_snapshot,target_snapshot,target_keys,created_at)
                VALUES(p.id,p.tenant_id,p.region_id,p.id,p.investigation_id,i.situation_id,p.tool_id,g.id,COALESCE(g.id,r.id),p.rollback_of_change_plan_id,
                    CASE WHEN g.id IS NOT NULL THEN 'frozen_plan' WHEN r.id IS NOT NULL THEN 'frozen_rollback_plan' ELSE 'legacy_unknown' END,icheck_action_target_unknown(c,t),c,t,icheck_action_target_keys(c,t),clock_timestamp());
        END; $$"""))
    op.execute(sa.text("""CREATE FUNCTION icheck_action_target_plan_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        PERFORM icheck_seal_action_targets(NEW.action_proposal_id); RETURN NEW; END; $$"""))
    op.execute(sa.text("CREATE TRIGGER icheck_action_target_plan_insert AFTER INSERT ON governed_change_plans FOR EACH ROW EXECUTE FUNCTION icheck_action_target_plan_insert()"))
    op.execute(sa.text("""CREATE FUNCTION icheck_action_target_deferred() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        PERFORM icheck_seal_action_targets(NEW.id); RETURN NEW; END; $$"""))
    op.execute(sa.text("CREATE CONSTRAINT TRIGGER icheck_action_target_deferred AFTER INSERT ON agent_action_proposals DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION icheck_action_target_deferred()"))
    op.execute(sa.text("""CREATE FUNCTION icheck_action_target_parent_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF TG_TABLE_NAME='governed_change_plans' THEN
            IF TG_OP='INSERT' AND EXISTS(SELECT 1 FROM action_target_admissions WHERE proposal_id=NEW.action_proposal_id)
                THEN RAISE EXCEPTION 'Cannot replace retained unknown action routing with a later plan'; END IF;
            IF TG_OP='UPDATE' AND EXISTS(SELECT 1 FROM action_target_admissions WHERE routing_plan_id=OLD.id)
                AND (NEW.id<>OLD.id OR NEW.action_proposal_id<>OLD.action_proposal_id OR NEW.investigation_id<>OLD.investigation_id
                    OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id
                    OR NEW.target_snapshot::jsonb<>OLD.target_snapshot::jsonb OR NEW.tool_contract_snapshot::jsonb<>OLD.tool_contract_snapshot::jsonb)
                THEN RAISE EXCEPTION 'Retain immutable action target routing'; END IF;
        ELSIF TG_TABLE_NAME='agent_action_proposals' THEN
            IF EXISTS(SELECT 1 FROM action_target_admissions WHERE proposal_id=OLD.id)
                AND (NEW.id<>OLD.id OR NEW.investigation_id<>OLD.investigation_id OR NEW.tool_id<>OLD.tool_id
                    OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id
                    OR NEW.rollback_of_change_plan_id IS DISTINCT FROM OLD.rollback_of_change_plan_id)
                THEN RAISE EXCEPTION 'Retain immutable action target routing'; END IF;
        ELSE
            IF EXISTS(SELECT 1 FROM action_target_admissions WHERE investigation_id=OLD.id)
                AND (NEW.id<>OLD.id OR NEW.situation_id IS DISTINCT FROM OLD.situation_id OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id)
                THEN RAISE EXCEPTION 'Retain immutable action target Situation binding'; END IF;
        END IF;
        RETURN NEW; END; $$"""))
    for table, operations in (("governed_change_plans", "INSERT OR UPDATE"), ("agent_action_proposals", "UPDATE"), ("investigations", "UPDATE")):
        op.execute(sa.text(f"CREATE TRIGGER icheck_action_target_parent_guard BEFORE {operations} ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_action_target_parent_guard()"))


def _sqlite_backfill(bind):
    meta = sa.MetaData()
    admissions = sa.Table(ADMISSIONS, meta, autoload_with=bind)
    keys_table = sa.Table(KEYS, meta, autoload_with=bind)
    query = """SELECT p.id,p.tenant_id,p.region_id,p.investigation_id,p.tool_id,p.rollback_of_change_plan_id,i.situation_id,
        g.id AS change_plan_id,COALESCE(g.id,r.id) AS routing_plan_id,COALESCE(g.tool_contract_snapshot,r.tool_contract_snapshot) AS tool_contract_snapshot,
        COALESCE(g.target_snapshot,r.target_snapshot) AS target_snapshot FROM agent_action_proposals p
        JOIN investigations i ON i.id=p.investigation_id LEFT JOIN governed_change_plans g ON g.action_proposal_id=p.id
        LEFT JOIN governed_change_plans r ON r.id=p.rollback_of_change_plan_id ORDER BY p.id"""
    for row in bind.execute(sa.text(query)).mappings():
        contract = json.loads(row["tool_contract_snapshot"]) if row["tool_contract_snapshot"] else {}
        targets = json.loads(row["target_snapshot"]) if row["target_snapshot"] else {}
        keys, unknown = _routing(contract, targets)
        values = {key: row[key] for key in ("id", "tenant_id", "region_id", "investigation_id", "tool_id", "rollback_of_change_plan_id", "situation_id", "change_plan_id", "routing_plan_id")}
        values.update(proposal_id=row["id"], origin="frozen_plan" if row["change_plan_id"] else "frozen_rollback_plan" if row["routing_plan_id"] else "legacy_unknown",
            unknown_targets=unknown, contract_snapshot=contract, target_snapshot=targets, target_keys=keys, created_at=datetime.now(timezone.utc))
        bind.execute(admissions.insert().values(**values))
        for key in keys:
            bind.execute(keys_table.insert().values(id=str(uuid4()), tenant_id=row["tenant_id"], region_id=row["region_id"],
                admission_id=row["id"], target_kind=key["kind"], target_id=key["value"]))


def _sqlite():
    for table in (ADMISSIONS, KEYS):
        for action in ("UPDATE", "DELETE"):
            op.execute(sa.text(f"CREATE TRIGGER icheck_{table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'Action target admission history is append-only'); END"))
    op.execute(sa.text("""CREATE TRIGGER icheck_action_target_key_insert BEFORE INSERT ON action_target_keys WHEN NOT EXISTS(
        SELECT 1 FROM action_target_admissions a,json_each(a.target_keys) x WHERE a.id=NEW.admission_id AND a.tenant_id=NEW.tenant_id
        AND a.region_id=NEW.region_id AND json_extract(x.value,'$.kind')=NEW.target_kind AND json_extract(x.value,'$.value')=NEW.target_id)
        BEGIN SELECT RAISE(ABORT,'Action target key references or routing are invalid'); END"""))
    contract = "COALESCE(g.tool_contract_snapshot,r.tool_contract_snapshot,'{}')"
    targets = "COALESCE(g.target_snapshot,r.target_snapshot,'{}')"
    bindings = f"CASE WHEN json_type({contract},'$.authorization_target_paths')='object' THEN json_extract({contract},'$.authorization_target_paths') ELSE '{{}}' END"
    valid = "b.type='text' AND b.value IN ('device_id','site') AND v.type='text' AND trim(v.value,char(32)||char(9)||char(10)||char(13)||char(12)||char(11))<>'' AND length(v.value)<=CASE WHEN b.value='device_id' THEN 36 ELSE 255 END"
    count = f"(SELECT count(*) FROM json_each({bindings}))"
    keys = f"(SELECT json_group_array(json_object('kind',kind,'value',value)) FROM (SELECT DISTINCT b.value AS kind,v.value AS value FROM json_each({bindings}) b JOIN json_each({targets}) v ON v.key=b.key WHERE {valid} AND {count} BETWEEN 1 AND 16 ORDER BY kind COLLATE BINARY,value COLLATE BINARY))"
    unknown = f"(json_type({contract},'$.authorization_target_paths') IS NOT 'object' OR {count} NOT BETWEEN 1 AND 16 OR EXISTS(SELECT 1 FROM json_each({bindings}) b LEFT JOIN json_each({targets}) v ON v.key=b.key WHERE b.type<>'text' OR b.value NOT IN ('device_id','site') OR v.type IS NOT 'text' OR trim(v.value,char(32)||char(9)||char(10)||char(13)||char(12)||char(11))='' OR length(v.value)>CASE WHEN b.value='device_id' THEN 36 ELSE 255 END))"
    op.execute(sa.text(f"""CREATE TRIGGER icheck_action_target_admission_insert BEFORE INSERT ON action_target_admissions WHEN NOT EXISTS(
        SELECT 1 FROM agent_action_proposals p JOIN investigations i ON i.id=p.investigation_id AND i.tenant_id=p.tenant_id AND i.region_id=p.region_id
        LEFT JOIN governed_change_plans g ON g.action_proposal_id=p.id AND g.tenant_id=p.tenant_id AND g.region_id=p.region_id
        LEFT JOIN governed_change_plans r ON r.id=p.rollback_of_change_plan_id AND r.tenant_id=p.tenant_id AND r.region_id=p.region_id
        WHERE p.id=NEW.proposal_id AND p.tenant_id=NEW.tenant_id AND p.region_id=NEW.region_id
        AND NEW.investigation_id=i.id AND NEW.situation_id IS i.situation_id AND NEW.tool_id=p.tool_id
        AND NEW.change_plan_id IS g.id AND NEW.rollback_of_change_plan_id IS p.rollback_of_change_plan_id
        AND NEW.routing_plan_id IS COALESCE(g.id,r.id)
        AND NEW.origin=CASE WHEN g.id IS NOT NULL THEN 'frozen_plan' WHEN r.id IS NOT NULL THEN 'frozen_rollback_plan' ELSE 'legacy_unknown' END
        AND json(NEW.contract_snapshot)=json({contract})
        AND json(NEW.target_snapshot)=json({targets})
        AND json(NEW.target_keys)=json({keys}) AND NEW.unknown_targets={unknown})
        BEGIN SELECT RAISE(ABORT,'Action target admission references or routing are invalid'); END"""))
    op.execute(sa.text("""CREATE TRIGGER icheck_derive_action_target_keys AFTER INSERT ON action_target_admissions BEGIN
        INSERT INTO action_target_keys(id,tenant_id,region_id,admission_id,target_kind,target_id)
            SELECT lower(hex(randomblob(16))),NEW.tenant_id,NEW.region_id,NEW.id,json_extract(x.value,'$.kind'),json_extract(x.value,'$.value') FROM json_each(NEW.target_keys) x;
        END"""))
    op.execute(sa.text("""CREATE TRIGGER icheck_action_target_plan_insert BEFORE INSERT ON governed_change_plans
        WHEN EXISTS(SELECT 1 FROM action_target_admissions WHERE proposal_id=NEW.action_proposal_id)
        BEGIN SELECT RAISE(ABORT,'Cannot replace retained unknown action routing with a later plan'); END"""))
    guards = {
        "governed_change_plans": "EXISTS(SELECT 1 FROM action_target_admissions WHERE routing_plan_id=OLD.id) AND (NEW.id<>OLD.id OR NEW.action_proposal_id<>OLD.action_proposal_id OR NEW.investigation_id<>OLD.investigation_id OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id OR json(NEW.target_snapshot)<>json(OLD.target_snapshot) OR json(NEW.tool_contract_snapshot)<>json(OLD.tool_contract_snapshot))",
        "agent_action_proposals": "EXISTS(SELECT 1 FROM action_target_admissions WHERE proposal_id=OLD.id) AND (NEW.id<>OLD.id OR NEW.investigation_id<>OLD.investigation_id OR NEW.tool_id<>OLD.tool_id OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id OR NEW.rollback_of_change_plan_id IS NOT OLD.rollback_of_change_plan_id)",
        "investigations": "EXISTS(SELECT 1 FROM action_target_admissions WHERE investigation_id=OLD.id) AND (NEW.id<>OLD.id OR NEW.situation_id IS NOT OLD.situation_id OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id)",
    }
    for table, guard in guards.items():
        op.execute(sa.text(f"CREATE TRIGGER icheck_action_target_parent_guard_{table} BEFORE UPDATE ON {table} WHEN {guard} BEGIN SELECT RAISE(ABORT,'Retain immutable action target routing'); END"))


def downgrade():
    bind = op.get_bind(); _all_visible(bind, (ADMISSIONS, KEYS))
    if bind.execute(sa.text(f"SELECT 1 FROM {ADMISSIONS} LIMIT 1")).first():
        raise RuntimeError("Retain populated action target admission history; downgrade is refused")
    if bind.dialect.name == "postgresql":
        for table in ("governed_change_plans", "agent_action_proposals", "investigations"):
            op.execute(sa.text(f"DROP TRIGGER icheck_action_target_parent_guard ON {table}"))
        op.execute(sa.text("DROP TRIGGER icheck_action_target_deferred ON agent_action_proposals"))
        op.execute(sa.text("DROP TRIGGER icheck_action_target_plan_insert ON governed_change_plans"))
        for name, table in (("icheck_guard_action_target_key", KEYS), ("icheck_derive_action_target_keys", ADMISSIONS), ("icheck_guard_action_target_admission", ADMISSIONS)):
            op.execute(sa.text(f"DROP TRIGGER {name} ON {table}"))
        for function in ("icheck_action_target_parent_guard()", "icheck_action_target_deferred()", "icheck_action_target_plan_insert()",
            "icheck_guard_action_target_key()", "icheck_derive_action_target_keys()", "icheck_guard_action_target_admission()",
            "icheck_seal_action_targets(text)", "icheck_action_target_keys(jsonb,jsonb)", "icheck_action_target_unknown(jsonb,jsonb)"):
            op.execute(sa.text("DROP FUNCTION " + function))
    else:
        for table in ("governed_change_plans", "agent_action_proposals", "investigations"):
            op.execute(sa.text(f"DROP TRIGGER icheck_action_target_parent_guard_{table}"))
        op.execute(sa.text("DROP TRIGGER icheck_action_target_plan_insert"))
    op.drop_table(KEYS); op.drop_table(ADMISSIONS)
