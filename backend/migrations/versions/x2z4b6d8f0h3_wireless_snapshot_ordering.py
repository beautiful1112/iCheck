"""Controller snapshot ordering without inferred legacy quiet or body truth."""
from datetime import UTC
from uuid import uuid4

from alembic import op
import sqlalchemy as sa

revision = "x2z4b6d8f0h3"
down_revision = "w1y3a5c7e9g2"
branch_labels = depends_on = None
TABLE = "wireless_snapshot_states"


def upgrade():
    bind = op.get_bind()
    tables = ("devices", "wireless_client_sessions", "alert_condition_states",
              "collector_deployments", "collector_runs", "knowledge_projections", "agent_executions")
    if bind.dialect.name == "postgresql":
        for table in tables:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Wireless snapshot migration requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE collector_deployments, collector_runs, knowledge_projections, agent_executions, devices, wireless_client_sessions, alert_condition_states IN SHARE ROW EXCLUSIVE MODE"))
    elif bind.dialect.name != "sqlite":
        raise RuntimeError("Wireless snapshot migration requires PostgreSQL or SQLite")
    for sql in (
        "SELECT 1 FROM collector_deployments WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL LIMIT 1",
        "SELECT 1 FROM collector_runs WHERE status='RUNNING' LIMIT 1",
        "SELECT 1 FROM knowledge_projections WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL OR status='PROCESSING' LIMIT 1",
        "SELECT 1 FROM agent_executions WHERE lease_token_hash IS NOT NULL OR status='RUNNING' LIMIT 1",
    ):
        if bind.execute(sa.text(sql)).first():
            raise RuntimeError("Drain Collector, Projection and Agent producers before wireless snapshot upgrade")
    if bind.execute(sa.text("""SELECT 1 FROM wireless_client_sessions s LEFT JOIN devices d ON d.id=s.controller_id
        WHERE d.id IS NULL OR d.tenant_id<>s.tenant_id OR d.region_id<>s.region_id LIMIT 1""")).first():
        raise RuntimeError("Reconcile legacy wireless controller namespace references before migration")
    op.create_table(TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("region_id", sa.String(36), nullable=False),
        sa.Column("controller_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "controller_id", name="uq_wireless_snapshot_controller"),
        sa.CheckConstraint("revision>0", name="ck_wireless_snapshot_revision"),
        sa.CheckConstraint("state IN ('unobserved','accepted','conflict','legacy_unknown')", name="ck_wireless_snapshot_state"),
        sa.CheckConstraint("(state='unobserved' AND observed_at IS NULL) OR (state<>'unobserved' AND observed_at IS NOT NULL)", name="ck_wireless_snapshot_time"),
        sa.CheckConstraint("length(payload)<=8388608", name="ck_wireless_snapshot_payload_bound"),
        sa.CheckConstraint("(state IN ('accepted','conflict') AND length(payload)>0) OR (state IN ('unobserved','legacy_unknown') AND payload='')", name="ck_wireless_snapshot_payload_state"))
    for field in ("tenant_id", "region_id", "controller_id"):
        op.create_index(f"ix_{TABLE}_{field}", TABLE, [field])
    metadata = sa.MetaData()
    sessions = sa.Table("wireless_client_sessions", metadata, autoload_with=bind)
    states = sa.Table(TABLE, metadata, autoload_with=bind)
    latest = sa.case((sessions.c.disconnected_at > sessions.c.last_seen, sessions.c.disconnected_at), else_=sessions.c.last_seen)
    rows = bind.execute(sa.select(sessions.c.tenant_id, sessions.c.region_id, sessions.c.controller_id,
        sa.func.max(latest).label("observed_at")).group_by(sessions.c.tenant_id, sessions.c.region_id, sessions.c.controller_id)
        .execution_options(stream_results=True, yield_per=500)).mappings()
    for row in rows:
        stamp = row["observed_at"]
        stamp = stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)
        bind.execute(states.insert().values(id=str(uuid4()), tenant_id=row["tenant_id"], region_id=row["region_id"],
            controller_id=row["controller_id"], state="legacy_unknown", observed_at=stamp,
            payload="", revision=1, created_at=stamp, updated_at=stamp))
    rows.close()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"""CREATE POLICY icheck_namespace_isolation ON {TABLE}
            USING (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))
            WITH CHECK (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))"""))
        op.execute(sa.text("""CREATE FUNCTION icheck_guard_wireless_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Wireless snapshot watermarks cannot be deleted'; END IF;
            IF TG_OP='UPDATE' AND (NEW.id<>OLD.id OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id
                OR NEW.controller_id<>OLD.controller_id OR NEW.revision<>OLD.revision+1
                OR (OLD.observed_at IS NOT NULL AND (NEW.observed_at IS NULL OR NEW.observed_at<OLD.observed_at))
                OR (NEW.observed_at=OLD.observed_at AND NOT
                    (OLD.state='accepted' AND NEW.state='conflict' AND NEW.payload=OLD.payload))) THEN
                RAISE EXCEPTION 'Wireless snapshot identity, revision or ordering has drifted'; END IF;
            IF NOT EXISTS(SELECT 1 FROM devices d WHERE d.id=NEW.controller_id
                AND d.tenant_id=NEW.tenant_id AND d.region_id=NEW.region_id) THEN
                RAISE EXCEPTION 'Wireless snapshot controller crosses namespace'; END IF;
            RETURN NEW; END; $$"""))
        op.execute(sa.text(f"CREATE TRIGGER icheck_guard_wireless_snapshot BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION icheck_guard_wireless_snapshot()"))
    else:
        op.execute(sa.text(f"CREATE TRIGGER icheck_wireless_snapshot_delete BEFORE DELETE ON {TABLE} BEGIN SELECT RAISE(ABORT,'Wireless snapshot watermarks cannot be deleted'); END"))
        op.execute(sa.text(f"""CREATE TRIGGER icheck_wireless_snapshot_update BEFORE UPDATE ON {TABLE} WHEN
            NEW.id<>OLD.id OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id
            OR NEW.controller_id<>OLD.controller_id OR NEW.revision<>OLD.revision+1
            OR (OLD.observed_at IS NOT NULL AND (NEW.observed_at IS NULL OR NEW.observed_at<OLD.observed_at))
            OR (NEW.observed_at=OLD.observed_at AND NOT
                (OLD.state='accepted' AND NEW.state='conflict' AND NEW.payload=OLD.payload))
            BEGIN SELECT RAISE(ABORT,'Wireless snapshot identity, revision or ordering has drifted'); END"""))
        for action in ("INSERT", "UPDATE"):
            op.execute(sa.text(f"""CREATE TRIGGER icheck_wireless_snapshot_time_{action.lower()} BEFORE {action} ON {TABLE}
                WHEN NEW.observed_at IS NOT NULL AND (length(NEW.observed_at)<>26
                    OR substr(NEW.observed_at,20,1)<>'.' OR substr(NEW.observed_at,21,6) GLOB '*[^0-9]*'
                    OR strftime('%Y-%m-%d %H:%M:%S',substr(NEW.observed_at,1,19)) IS NOT substr(NEW.observed_at,1,19))
                BEGIN SELECT RAISE(ABORT,'Wireless snapshot timestamp must be canonical UTC'); END"""))
            op.execute(sa.text(f"""CREATE TRIGGER icheck_wireless_snapshot_reference_{action.lower()} BEFORE {action} ON {TABLE}
                WHEN NOT EXISTS(SELECT 1 FROM devices d WHERE d.id=NEW.controller_id
                    AND d.tenant_id=NEW.tenant_id AND d.region_id=NEW.region_id)
                BEGIN SELECT RAISE(ABORT,'Wireless snapshot controller crosses namespace'); END"""))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": TABLE}).scalar():
        raise RuntimeError("Wireless snapshot downgrade requires visibility of all namespaces")
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade recorded wireless snapshot watermarks")
    op.drop_table(TABLE)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_wireless_snapshot()"))
