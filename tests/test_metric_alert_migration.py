"""Focused source migration/retention check, never the running database."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import getpass
import pytest

from sqlalchemy import create_engine,text,inspect


def test_metric_rule_migration_preserves_inventory_rules_and_blocks_history_loss(tmp_path):
    root=Path(__file__).resolve().parents[1]; path=tmp_path/"migration.sqlite"
    env={**os.environ,"ICHECK_DATABASE_URL":"sqlite+pysqlite:///"+str(path),"ICHECK_AUTO_CREATE_SCHEMA":"false","PYTHONPATH":str(root/"backend")}
    def migrate(revision,operation="upgrade",success=True):
        result=subprocess.run([sys.executable,"-m","alembic","-c",str(root/"alembic.ini"),operation,revision],env=env,cwd=root,capture_output=True,text=True)
        assert (result.returncode==0)==success,result.stderr[-2000:]
    migrate("t7x9z1c3e5g8")
    engine=create_engine(env["ICHECK_DATABASE_URL"])
    with engine.begin() as db:
        db.execute(text("INSERT INTO alert_rules(id,name,event_type,severity,enabled,conditions,cooldown_seconds,created_at,updated_at) VALUES('inventory','Inventory fixture','endpoint.ip.changed','WARNING',1,'{}',300,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
    migrate("u8z0b2d4f6h9")
    with engine.begin() as db:
        assert db.scalar(text("SELECT name FROM alert_rules WHERE id='inventory'"))=="Inventory fixture"
        assert db.scalar(text("SELECT version_num FROM alembic_version"))=="u8z0b2d4f6h9"
        columns={item["name"] for item in inspect(db).get_columns("metric_rule_changes")}
        assert {"target_snapshot","runtime_binding","previous_definition","plan_hash","status","tenant_id","region_id"}<=columns
        db.execute(text("INSERT INTO alert_rules(id,name,event_type,severity,enabled,conditions,cooldown_seconds,created_at,updated_at) VALUES('metric','Metric fixture','metric.prometheus','WARNING',0,'{}',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
        db.execute(text("""INSERT INTO metric_rule_changes(id,rule_id,expected_revision,definition,target_snapshot,backend_revision,compiled_rule,catalog_before,catalog_after,
            runtime_before_hash,runtime_binding,plan_hash,status,created_by,created_at) VALUES('retained','metric',0,'{}','{}',0,'{}','{}','{}',:hash,'{}',:hash,'proposed','fixture',CURRENT_TIMESTAMP)"""),{"hash":"a"*64})
    migrate("t7x9z1c3e5g8",operation="downgrade",success=False)
    with engine.begin() as db:
        assert db.scalar(text("SELECT count(*) FROM metric_rule_changes WHERE id='retained'"))==1
        assert db.scalar(text("SELECT count(*) FROM alert_rules WHERE id='inventory'"))==1
    engine.dispose()


def test_private_postgres_namespace_and_reviewed_plan_retention():
    from sqlalchemy.orm import Session
    from sqlalchemy.exc import DBAPIError
    from icheck.models import AlertRule,AlertSeverity,MetricRuleChange,new_id
    pg=os.getenv("ICHECK_METRIC_ALERT_TEST_POSTGRES_BIN")
    if not pg: pytest.skip("Explicit native PostgreSQL binary directory required")
    root=Path(__file__).resolve().parents[1]; pg=Path(pg)
    def run(arguments,env=None):
        result=subprocess.run(arguments,env=env,cwd=root,capture_output=True,text=True,timeout=60)
        assert result.returncode==0,result.stderr[-1500:]
    with tempfile.TemporaryDirectory(prefix="icheck-metric-alert-pg-") as temporary:
        directory=Path(temporary); data=directory/"data"
        run([str(pg/"initdb"),"-D",str(data),"--auth=trust","--no-locale","--encoding=UTF8"])
        run([str(pg/"pg_ctl"),"-D",str(data),"-l",str(directory/"postgres.log"),"-o",f"-k {directory} -c listen_addresses=''","-w","start"])
        try:
            run([str(pg/"createdb"),"-h",str(directory),"metric_alerts_test"])
            url=f"postgresql+psycopg://{getpass.getuser()}@/metric_alerts_test?host={directory}"
            env={**os.environ,"ICHECK_DATABASE_URL":url,"ICHECK_AUTO_CREATE_SCHEMA":"false","PYTHONPATH":str(root/"backend")}
            run([sys.executable,"-m","alembic","-c",str(root/"alembic.ini"),"upgrade","u8z0b2d4f6h9"],env=env)
            engine=create_engine(url); identifier,proposal=new_id(),new_id()
            with Session(engine) as db:
                db.add(AlertRule(id=identifier,name=identifier,event_type="metric.prometheus",severity=AlertSeverity.WARNING,enabled=False,conditions={},cooldown_seconds=0)); db.commit()
                db.add(MetricRuleChange(id=proposal,rule_id=identifier,expected_revision=0,definition={},target_snapshot={},backend_revision=0,
                    compiled_rule={},catalog_before={},catalog_after={},runtime_before_hash="a"*64,runtime_binding={},plan_hash="b"*64,status="proposed",created_by="fixture")); db.commit()
            with engine.begin() as db:
                db.exec_driver_sql("CREATE ROLE icheck_metric_rule_test NOLOGIN NOSUPERUSER NOBYPASSRLS")
                db.exec_driver_sql("GRANT USAGE ON SCHEMA public TO icheck_metric_rule_test")
                db.exec_driver_sql("GRANT SELECT ON alert_rules TO icheck_metric_rule_test")
                db.exec_driver_sql("GRANT SELECT,INSERT,UPDATE,DELETE ON metric_rule_changes TO icheck_metric_rule_test")
            with engine.begin() as db:
                db.exec_driver_sql("SET LOCAL ROLE icheck_metric_rule_test")
                assert db.scalar(text("SELECT count(*) FROM metric_rule_changes"))==0
                db.exec_driver_sql("SELECT set_config('icheck.tenant_id','00000000-0000-0000-0000-000000000001',true),set_config('icheck.region_id','00000000-0000-0000-0000-000000000002',true)")
                assert db.scalar(text("SELECT count(*) FROM metric_rule_changes WHERE id=:id"),{"id":proposal})==1
                for statement in ("UPDATE metric_rule_changes SET definition=jsonb_build_object('changed',true) WHERE id=:id",
                    "DELETE FROM metric_rule_changes WHERE id=:id","UPDATE metric_rule_changes SET tenant_id='other' WHERE id=:id"):
                    with pytest.raises(DBAPIError),db.begin_nested(): db.execute(text(statement),{"id":proposal})
                db.execute(text("UPDATE metric_rule_changes SET status='applying',approved_by='human' WHERE id=:id"),{"id":proposal})
                db.execute(text("UPDATE metric_rule_changes SET status='applied',applied_at=now() WHERE id=:id"),{"id":proposal})
                with pytest.raises(DBAPIError),db.begin_nested(): db.execute(text("UPDATE metric_rule_changes SET status='unknown' WHERE id=:id"),{"id":proposal})
                db.exec_driver_sql("SELECT set_config('icheck.tenant_id','other',true)")
                assert db.scalar(text("SELECT count(*) FROM metric_rule_changes"))==0
            engine.dispose()
        finally: run([str(pg/"pg_ctl"),"-D",str(data),"-m","fast","-w","stop"])
