import os
from pathlib import Path
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError

ROOT = Path(__file__).resolve().parents[1]
HEAD = "w1y3a5c7e9g2"
PREVIOUS = "v0x2z4b6d8f1"


def migrate(url, target, direction="upgrade", success=True):
    result = subprocess.run([sys.executable,"-m","alembic","-c",str(ROOT/"alembic.ini"),direction,target],
        cwd=ROOT,env={**os.environ,"ICHECK_DATABASE_URL":url,"ICHECK_AUTO_CREATE_SCHEMA":"false","PYTHONPATH":str(ROOT/"backend")},
        capture_output=True,text=True,timeout=120)
    assert (result.returncode==0) is success, (result.stdout+result.stderr)[-4000:]
    return result


def legacy(connection, *, id="old", key="source", status="RESOLVED", entity="device", last="2026-10-05 11:00:00", resolved="2026-10-05 11:01:00"):
    connection.execute(text("""INSERT INTO alerts (id,tenant_id,region_id,dedup_key,event_type,severity,status,title,
        description,entity_type,entity_id,occurrence_count,details,first_seen,last_seen,resolved_at)
        VALUES (:id,'tenant','region',:key,'device.cpu.high','WARNING',:status,'Historical condition','',
        'device',:entity,1,'{}',:last,:last,:resolved)"""),
        {"id":id,"key":key,"status":status,"entity":entity,"last":last,"resolved":resolved})


def test_empty_upgrade_downgrade_upgrade(tmp_path):
    url=f"sqlite+pysqlite:///{tmp_path/'empty.sqlite'}"
    migrate(url,HEAD)
    migrate(url,PREVIOUS,"downgrade")
    migrate(url,HEAD)
    engine=create_engine(url)
    with engine.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version"))==HEAD
        assert db.scalar(text("SELECT count(*) FROM alert_condition_states"))==0
    assert "uq_alert_active_condition" in {r["name"] for r in inspect(engine).get_indexes("alerts")}
    engine.dispose()


@pytest.fixture
def legacy_database(tmp_path):
    url=f"sqlite+pysqlite:///{tmp_path/'legacy.sqlite'}"
    migrate(url,PREVIOUS)
    engine=create_engine(url)
    yield url,engine
    engine.dispose()


def test_legacy_resolved_status_is_not_backfilled_as_quiet_truth(legacy_database):
    url,engine=legacy_database
    with engine.begin() as db:
        legacy(db)
    migrate(url,HEAD)
    with engine.connect() as db:
        row=db.execute(text("SELECT state,latest_alert_id,entity_id,observed_at FROM alert_condition_states")).one()
        assert row[:3]==("legacy_unknown","old","device")
        assert row[3].startswith("2026-10-05 11:01:00")
        assert db.scalar(text("SELECT status FROM alerts WHERE id='old'"))=="RESOLVED"
    refused=migrate(url,PREVIOUS,"downgrade",success=False)
    assert "Cannot downgrade recorded Alert condition watermarks" in refused.stdout+refused.stderr


def test_divergent_historical_source_identities_are_quarantined_without_rewriting_alerts(legacy_database):
    url,engine=legacy_database
    with engine.begin() as db:
        legacy(db,id="first",entity="first-target")
        legacy(db,id="second",entity="second-target",last="2026-10-05 11:02:00",resolved="2026-10-05 11:03:00")
    migrate(url,HEAD)
    with engine.connect() as db:
        assert db.execute(text("SELECT state,event_type,entity_id,latest_alert_id FROM alert_condition_states")).one()==("legacy_unknown",None,None,None)
        assert db.scalar(text("SELECT count(*) FROM alerts"))==2


def test_duplicate_active_legacy_rows_refuse_upgrade_without_merging(legacy_database):
    url,engine=legacy_database
    with engine.begin() as db:
        legacy(db,id="first",status="OPEN",resolved=None)
        legacy(db,id="second",status="ACKNOWLEDGED",resolved=None)
    result=migrate(url,HEAD,success=False)
    assert "Reconcile duplicate active Alert conditions" in result.stdout+result.stderr
    with engine.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version"))==PREVIOUS
        assert db.scalar(text("SELECT count(*) FROM alerts"))==2


@pytest.mark.parametrize("mutation", ["delete","time","revision","identity","reference"])
def test_actual_sqlite_watermark_guards(legacy_database,mutation):
    url,engine=legacy_database
    with engine.begin() as db:
        legacy(db)
        legacy(db,id="foreign",key="other-source")
    migrate(url,HEAD)
    sql={"delete":"DELETE FROM alert_condition_states WHERE dedup_key='source'",
        "time":"UPDATE alert_condition_states SET observed_at='2026-10-05 10:00:00',revision=revision+1 WHERE dedup_key='source'",
        "revision":"UPDATE alert_condition_states SET revision=revision+2 WHERE dedup_key='source'",
        "identity":"UPDATE alert_condition_states SET entity_id='wrong',revision=revision+1 WHERE dedup_key='source'",
        "reference":"UPDATE alert_condition_states SET latest_alert_id='foreign',revision=revision+1 WHERE dedup_key='source'"}[mutation]
    with engine.connect() as db:
        with pytest.raises(DBAPIError):
            db.execute(text(sql))
        db.rollback()


def test_sqlite_guards_preserve_microseconds_and_reject_noncanonical_time(legacy_database):
    url,engine=legacy_database
    with engine.begin() as db:
        legacy(db)
    migrate(url,HEAD)
    with engine.begin() as db:
        db.execute(text("UPDATE alert_condition_states SET observed_at='2026-10-05 11:01:00.000001',state='quiet',revision=revision+1"))
    for timestamp,state in (("2026-10-05 11:01:00.000000","quiet"),
        ("2026-10-05 11:01:00.000001","active"), ("2026-10-05T11:01:00.000002+00:00","quiet")):
        with engine.connect() as db:
            with pytest.raises(DBAPIError):
                db.execute(text("UPDATE alert_condition_states SET observed_at=:at,state=:state,revision=revision+1"),
                    {"at":timestamp,"state":state})
            db.rollback()
