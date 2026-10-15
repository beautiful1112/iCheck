"""SQLite DDL/guards only; non-owner FK/RLS behavior is tested natively."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError

ROOT = Path(__file__).resolve().parents[1]
TABLE = "investigation_tool_evidence_bindings"


@pytest.fixture(scope="module")
def migrated_database(tmp_path_factory):
    url = f"sqlite+pysqlite:///{tmp_path_factory.mktemp('tool-citations') / 'citations.sqlite'}"
    env = {**os.environ, "ICHECK_DATABASE_URL": url, "ICHECK_AUTO_CREATE_SCHEMA": "false", "PYTHONPATH": str(ROOT / "backend")}
    for direction, target in (("upgrade", "v0x2z4b6d8f1"), ("downgrade", "u9w1y3a5c7e0"), ("upgrade", "v0x2z4b6d8f1")):
        result = subprocess.run([sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"), direction, target],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stdout+result.stderr
    engine = create_engine(url)
    yield engine
    engine.dispose()


def seed(connection, *, foreign=False, duplicate=False, padding_area=None):
    from icheck.services.agent_runtime import _canonical_hash
    finished = "2026-10-05T12:00:00+00:00"
    result_hash = _canonical_hash({"ok": True})
    connection.execute(text("""INSERT INTO investigation_tool_calls
        (id,tenant_id,region_id,investigation_id,tool_id,iteration,call_hash,arguments,status,result,result_hash,finished_at,created_at)
        VALUES ('call','tenant','region','investigation','tool',1,:hash,'{}','succeeded',:result,:result_hash,:finished,:finished)"""),
        {"hash": "a"*64, "result": json.dumps({"ok": True}), "result_hash": result_hash, "finished": finished})
    connection.execute(text("""INSERT INTO investigation_evidence
        (id,tenant_id,region_id,investigation_id,evidence_type,evidence_id,summary,created_at)
        VALUES ('evidence','tenant','region',:investigation,'controlled','source','Controlled',:finished)"""),
        {"investigation": "foreign" if foreign else "investigation", "finished": finished})
    reference = {"id": "evidence", "evidence_type": "controlled", "evidence_id": "source",
        "observed_at": None, "created_at": finished, "summary_hash": _canonical_hash("Controlled")}
    values = {"snapshot": json.dumps({"tool_id": "tool", "call_hash": "a"*64,
        "arguments_hash": _canonical_hash({}), "result_hash": result_hash, "finished_at": finished}),
        "refs": json.dumps([reference, reference] if duplicate else [reference]), "finished": finished}
    if padding_area == "call":
        snapshot = json.loads(values["snapshot"])
        snapshot["padding"] = "x"*4096
        values["snapshot"] = json.dumps(snapshot)
    elif padding_area == "references":
        refs = json.loads(values["refs"])
        refs[0]["padding"] = "x"*1048576
        values["refs"] = json.dumps(refs)
    connection.execute(text(f"""INSERT INTO {TABLE}
        (id,tenant_id,region_id,investigation_id,tool_call_id,call_snapshot,reference_snapshot,recorded_at)
        VALUES ('binding','tenant','region','investigation','call',:snapshot,:refs,:finished)"""), values)


def test_empty_roundtrip_preserves_current_head_and_unique_call(migrated_database):
    with migrated_database.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "v0x2z4b6d8f1"
    assert ("tool_call_id",) in {tuple(value["column_names"]) for value in inspect(migrated_database).get_unique_constraints(TABLE)}


@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
def test_bound_history_is_immutable(migrated_database, operation):
    with migrated_database.connect() as connection:
        seed(connection)
        sql = f"UPDATE {TABLE} SET reference_snapshot='[]'" if operation == "UPDATE" else f"DELETE FROM {TABLE}"
        with pytest.raises(DBAPIError, match="immutable"):
            connection.execute(text(sql))
        connection.rollback()


@pytest.mark.parametrize("kwargs", [{"foreign": True}, {"duplicate": True}])
def test_raw_insert_cannot_bind_foreign_or_duplicate_references(migrated_database, kwargs):
    with migrated_database.connect() as connection:
        with pytest.raises(DBAPIError, match="does not match"):
            seed(connection, **kwargs)
        connection.rollback()


def test_populated_downgrade_refuses_loss_of_citation_history(migrated_database):
    spec = importlib.util.spec_from_file_location("citation_migration", ROOT / "backend/migrations/versions/v0x2z4b6d8f1_tool_evidence_bindings.py")
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with migrated_database.connect() as connection:
        seed(connection)
        migration.op = Operations(MigrationContext.configure(connection))
        with pytest.raises(RuntimeError, match="Cannot downgrade"):
            migration.downgrade()
        assert inspect(connection).has_table(TABLE)
        connection.rollback()


@pytest.mark.parametrize("padding_area", ["call", "references"])
def test_database_bounds_receipt_json_before_recovery(migrated_database, padding_area):
    with migrated_database.connect() as connection:
        with pytest.raises(DBAPIError, match="ck_tool_binding_.*size"):
            seed(connection, padding_area=padding_area)
        connection.rollback()
