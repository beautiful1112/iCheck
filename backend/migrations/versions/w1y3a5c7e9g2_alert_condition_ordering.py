"""Durable per-condition ordering; legacy state is not inferred quiet proof."""
from datetime import UTC
from itertools import groupby
from uuid import uuid4

from alembic import op
import sqlalchemy as sa

revision = "w1y3a5c7e9g2"
down_revision = "v0x2z4b6d8f1"
branch_labels = depends_on = None
TABLE = "alert_condition_states"


def upgrade():
    bind = op.get_bind()
    producers = ("collector_deployments", "collector_runs", "knowledge_projections", "agent_executions")
    if bind.dialect.name == "postgresql":
        for table in ("alerts", *producers):
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Alert condition migration requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE collector_deployments, collector_runs, knowledge_projections, agent_executions, alerts IN SHARE ROW EXCLUSIVE MODE"))
    elif bind.dialect.name != "sqlite":
        raise RuntimeError("Alert condition migration requires PostgreSQL or SQLite")
    for sql in (
        "SELECT 1 FROM collector_deployments WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL LIMIT 1",
        "SELECT 1 FROM collector_runs WHERE status='RUNNING' LIMIT 1",
        "SELECT 1 FROM knowledge_projections WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL OR status='PROCESSING' LIMIT 1",
        "SELECT 1 FROM agent_executions WHERE lease_token_hash IS NOT NULL OR status='RUNNING' LIMIT 1",
    ):
        if bind.execute(sa.text(sql)).first():
            raise RuntimeError("Drain Collector, Projection and Agent source producers before Alert ordering upgrade")
    if bind.execute(sa.text("SELECT 1 FROM alerts WHERE status IN ('OPEN','ACKNOWLEDGED') "
        "GROUP BY tenant_id,region_id,dedup_key HAVING count(*)>1 LIMIT 1")).first():
        raise RuntimeError("Reconcile duplicate active Alert conditions before migration")
    op.create_table(TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("region_id", sa.String(36), nullable=False),
        sa.Column("dedup_key", sa.String(512), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=True),
        sa.Column("entity_type", sa.String(64), nullable=True),
        sa.Column("entity_id", sa.String(255), nullable=True),
        sa.Column("source_rule_id", sa.String(36), nullable=True),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("latest_alert_id", sa.String(36), sa.ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "dedup_key", name="uq_alert_condition_source"),
        sa.CheckConstraint("state IN ('unobserved','active','quiet','conflict','unknown','legacy_unknown')", name="ck_alert_condition_state"),
        sa.CheckConstraint("revision>0", name="ck_alert_condition_revision"),
        sa.CheckConstraint("(state='unobserved' AND observed_at IS NULL) OR (state!='unobserved' AND observed_at IS NOT NULL)", name="ck_alert_condition_observation"),
        sa.CheckConstraint("(event_type IS NULL AND entity_type IS NULL AND entity_id IS NULL AND source_rule_id IS NULL) OR (event_type IS NOT NULL AND entity_type IS NOT NULL AND entity_id IS NOT NULL)", name="ck_alert_condition_identity"))
    for field in ("tenant_id", "region_id"):
        op.create_index(f"ix_{TABLE}_{field}", TABLE, [field])
    op.create_index("uq_alert_active_condition", "alerts", ["tenant_id", "region_id", "dedup_key"], unique=True,
        postgresql_where=sa.text("status IN ('OPEN','ACKNOWLEDGED')"), sqlite_where=sa.text("status IN ('OPEN','ACKNOWLEDGED')"))
    # Stream source-key groups and retain every old Alert unchanged. Neither a
    # resolved flag nor its actor string establishes historical quiet truth.
    alerts = sa.Table("alerts", sa.MetaData(), autoload_with=bind)
    states = sa.Table(TABLE, sa.MetaData(), autoload_with=bind)
    when = sa.case((alerts.c.resolved_at > alerts.c.last_seen, alerts.c.resolved_at), else_=alerts.c.last_seen)
    rows = bind.execute(sa.select(alerts).order_by(alerts.c.tenant_id, alerts.c.region_id,
        alerts.c.dedup_key, when.desc(), alerts.c.id).execution_options(stream_results=True, yield_per=500)).mappings()
    for _key, group in groupby(rows, key=lambda r: (r["tenant_id"], r["region_id"], r["dedup_key"])):
        row = next(group)
        source = (row["event_type"], row["entity_type"], row["entity_id"], row["rule_id"])
        ambiguous = any((other["event_type"], other["entity_type"], other["entity_id"], other["rule_id"]) != source for other in group)
        timestamp = max(row["last_seen"], row["resolved_at"] or row["last_seen"])
        now = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=UTC)
        bind.execute(states.insert().values(id=str(uuid4()), tenant_id=row["tenant_id"], region_id=row["region_id"],
            dedup_key=row["dedup_key"], event_type=None if ambiguous else row["event_type"], entity_type=None if ambiguous else row["entity_type"],
            entity_id=None if ambiguous else row["entity_id"], source_rule_id=None if ambiguous else row["rule_id"], state="legacy_unknown", observed_at=now,
            latest_alert_id=None if ambiguous else row["id"], revision=1, created_at=now, updated_at=now))
    rows.close()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)) WITH CHECK (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))"))
        op.execute(sa.text("""CREATE FUNCTION icheck_guard_alert_condition() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Alert condition watermarks cannot be deleted'; END IF;
            IF TG_OP='UPDATE' AND (NEW.id<>OLD.id OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id
                OR NEW.dedup_key<>OLD.dedup_key OR NEW.revision<>OLD.revision+1
                OR (OLD.observed_at IS NOT NULL AND (NEW.observed_at IS NULL OR NEW.observed_at<OLD.observed_at))
                OR (OLD.event_type IS NOT NULL AND (NEW.event_type IS DISTINCT FROM OLD.event_type
                    OR NEW.entity_type IS DISTINCT FROM OLD.entity_type OR NEW.entity_id IS DISTINCT FROM OLD.entity_id
                    OR NEW.source_rule_id IS DISTINCT FROM OLD.source_rule_id))
                OR (NEW.observed_at=OLD.observed_at AND NEW.state NOT IN (OLD.state,'conflict'))) THEN
                RAISE EXCEPTION 'Alert condition identity, revision or ordering has drifted'; END IF;
            IF NEW.latest_alert_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM alerts a WHERE a.id=NEW.latest_alert_id
                AND a.tenant_id=NEW.tenant_id AND a.region_id=NEW.region_id AND a.dedup_key=NEW.dedup_key
                AND a.event_type=NEW.event_type AND a.entity_type=NEW.entity_type AND a.entity_id=NEW.entity_id
                AND (a.rule_id IS NULL OR a.rule_id IS NOT DISTINCT FROM NEW.source_rule_id)) THEN
                RAISE EXCEPTION 'Alert condition reference crosses source or namespace'; END IF;
            RETURN NEW; END; $$"""))
        op.execute(sa.text(f"CREATE TRIGGER icheck_guard_alert_condition BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION icheck_guard_alert_condition()"))
    elif bind.dialect.name == "sqlite":
        op.execute(sa.text(f"CREATE TRIGGER icheck_alert_condition_delete BEFORE DELETE ON {TABLE} BEGIN SELECT RAISE(ABORT,'Alert condition watermarks cannot be deleted'); END"))
        op.execute(sa.text(f"""CREATE TRIGGER icheck_alert_condition_update BEFORE UPDATE ON {TABLE} WHEN
            NEW.id<>OLD.id OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id OR NEW.dedup_key<>OLD.dedup_key
            OR NEW.revision<>OLD.revision+1 OR (OLD.observed_at IS NOT NULL AND (NEW.observed_at IS NULL OR NEW.observed_at<OLD.observed_at))
            OR (OLD.event_type IS NOT NULL AND (NEW.event_type IS NOT OLD.event_type OR NEW.entity_type IS NOT OLD.entity_type OR NEW.entity_id IS NOT OLD.entity_id OR NEW.source_rule_id IS NOT OLD.source_rule_id))
            OR (NEW.observed_at=OLD.observed_at AND NEW.state NOT IN (OLD.state,'conflict'))
            BEGIN SELECT RAISE(ABORT,'Alert condition identity, revision or ordering has drifted'); END"""))
        for operation in ("INSERT", "UPDATE"):
            # SQLite's julianday loses microseconds. The ORM/backfill binds UTC
            # using this exact fixed-width form, which sorts at full precision.
            op.execute(sa.text(f"""CREATE TRIGGER icheck_alert_condition_time_{operation.lower()} BEFORE {operation} ON {TABLE}
                WHEN NEW.observed_at IS NOT NULL AND (length(NEW.observed_at)<>26
                    OR substr(NEW.observed_at,20,1)<>'.'
                    OR substr(NEW.observed_at,21,6) GLOB '*[^0-9]*'
                    OR strftime('%Y-%m-%d %H:%M:%S',substr(NEW.observed_at,1,19)) IS NOT substr(NEW.observed_at,1,19))
                BEGIN SELECT RAISE(ABORT,'Alert condition timestamp must be canonical UTC'); END"""))
            op.execute(sa.text(f"""CREATE TRIGGER icheck_alert_condition_reference_{operation.lower()} BEFORE {operation} ON {TABLE}
                WHEN NEW.latest_alert_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM alerts a WHERE a.id=NEW.latest_alert_id
                AND a.tenant_id=NEW.tenant_id AND a.region_id=NEW.region_id AND a.dedup_key=NEW.dedup_key
                AND a.event_type=NEW.event_type AND a.entity_type=NEW.entity_type AND a.entity_id=NEW.entity_id
                AND (a.rule_id IS NULL OR a.rule_id IS NEW.source_rule_id))
                BEGIN SELECT RAISE(ABORT,'Alert condition reference crosses source or namespace'); END"""))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": TABLE}).scalar():
        raise RuntimeError("Alert condition downgrade requires visibility of all namespaces")
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade recorded Alert condition watermarks")
    op.drop_table(TABLE)
    op.drop_index("uq_alert_active_condition", table_name="alerts")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_alert_condition()"))
