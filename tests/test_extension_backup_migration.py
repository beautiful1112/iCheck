"""Current-head backup migration on an isolated, Unix-socket-only PostgreSQL."""
import getpass
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from icheck.models import (Artifact, ArtifactKind, ArtifactVersion, Device, DeviceConnection,
    ManagedExtensionInstallation, ManagedExtensionTest, new_id)


def test_extension_backup_migration_namespace_and_retention():
    binary = os.getenv("ICHECK_EXTENSION_TEST_POSTGRES_BIN")
    if not binary:
        pytest.skip("Explicit PostgreSQL binary directory required; never uses the running database")
    pg = Path(binary)
    root = Path(__file__).resolve().parents[1]
    def run(args, *, env=None, succeeds=True):
        result = subprocess.run(args, cwd=root, env=env, capture_output=True, text=True, timeout=90)
        assert (result.returncode == 0) is succeeds, result.stderr[-1500:]
    with tempfile.TemporaryDirectory(prefix="icheck-extension-pg-") as temporary:
        directory = Path(temporary)
        data = directory / "data"
        run([str(pg / "initdb"), "-D", str(data), "--auth=trust", "--no-locale", "--encoding=UTF8"])
        run([str(pg / "pg_ctl"), "-D", str(data), "-l", str(directory / "postgres.log"), "-o",
            f"-k {directory} -c listen_addresses=''", "-w", "start"])
        engine = None
        try:
            run([str(pg / "createdb"), "-h", str(directory), "extension_test"])
            url = f"postgresql+psycopg://{getpass.getuser()}@/extension_test?host={directory}"
            env = {**os.environ, "ICHECK_DATABASE_URL": url, "ICHECK_AUTO_CREATE_SCHEMA": "false", "PYTHONPATH": str(root / "backend")}
            command = [sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini")]
            run([*command, "upgrade", "u8z0b2d4f6h9"], env=env)
            engine = create_engine(url)
            artifact_id, version_id, device_id, connection_id, backup_id = [new_id() for _ in range(5)]
            with Session(engine) as db:
                db.add_all([Artifact(id=artifact_id, name="retained-extension", kind=ArtifactKind.TOOL, owner="fixture"),
                    Device(id=device_id, name="retained-device", kind="switch")]); db.flush()
                db.add_all([ArtifactVersion(id=version_id, artifact_id=artifact_id, version=1, created_by="fixture"),
                    DeviceConnection(id=connection_id, device_id=device_id, protocol="ssh", adapter_type="ssh", created_by="fixture")])
                db.commit()
            run([*command, "upgrade", "v9b1d3f5h7j0"], env=env)
            run([*command, "upgrade", "w0c2e4g6i8k1"], env=env)
            installation_id, test_id = new_id(), new_id()
            with engine.begin() as db:
                db.execute(text("""INSERT INTO managed_extension_installations
                    (id,artifact_id,active_version_id,revision,enabled,bindings,previous_bindings,tool_ids,last_health_status,created_by,updated_at)
                    VALUES(:id,:artifact,:version,1,true,'[]','[]','{}','discovered','fixture',now())"""),
                    {"id": installation_id, "artifact": artifact_id, "version": version_id})
            run([*command, "upgrade", "x1d3f5h7j9l2"], env=env)
            with Session(engine) as db:
                row = db.get(ManagedExtensionInstallation, installation_id)
                assert row.target_policy is None and row.previous_target_policy is None and row.bindings == []
                row.target_policy = {"mode": "authorized_inventory", "scope": {"all": True}}
                db.add(ManagedExtensionTest(id=test_id, request_key=new_id(), artifact_version_id=version_id,
                        version_hash="a" * 64, tool_name="read_interfaces", binding={}, created_by="fixture"))
                db.commit()
            insert = text("""INSERT INTO extension_configuration_backups
                (id,artifact_version_id,device_id,connection_id,tool_name,sha256,byte_count,encrypted_body,created_by,created_at)
                VALUES(:id,:version,:device,:connection,'backup_configuration',:digest,3,:body,'fixture',CURRENT_TIMESTAMP)""")
            params = {"id": backup_id, "version": version_id, "device": device_id, "connection": connection_id,
                "digest": "a" * 64, "body": b"synthetic-encrypted-envelope"}
            with engine.begin() as db:
                assert db.scalar(text("SELECT name FROM devices WHERE id=:id"), {"id": device_id}) == "retained-device"
                db.execute(insert, params)
                db.exec_driver_sql("CREATE ROLE extension_custody_test NOLOGIN NOSUPERUSER NOBYPASSRLS")
                db.exec_driver_sql("GRANT USAGE ON SCHEMA public TO extension_custody_test")
                db.exec_driver_sql("GRANT SELECT ON devices,device_connections,artifact_versions TO extension_custody_test")
                db.exec_driver_sql("GRANT SELECT,INSERT,UPDATE,DELETE ON extension_configuration_backups TO extension_custody_test")
                db.exec_driver_sql("GRANT SELECT,INSERT,UPDATE,DELETE ON managed_extension_installations,managed_extension_tests TO extension_custody_test")
            with engine.begin() as db:
                db.exec_driver_sql("SET LOCAL ROLE extension_custody_test")
                assert db.scalar(text("SELECT count(*) FROM extension_configuration_backups")) == 0
                db.exec_driver_sql("SELECT set_config('icheck.tenant_id','00000000-0000-0000-0000-000000000001',true),set_config('icheck.region_id','00000000-0000-0000-0000-000000000002',true)")
                assert db.scalar(text("SELECT count(*) FROM extension_configuration_backups")) == 1
                assert db.scalar(text("SELECT count(*) FROM managed_extension_installations")) == 1
                assert db.scalar(text("SELECT count(*) FROM managed_extension_tests")) == 1
                db.execute(text("UPDATE managed_extension_tests SET status='succeeded',completed_at=now() WHERE id=:id"), {"id": test_id})
                for sql, identifier in (("UPDATE managed_extension_tests SET result='{}' WHERE id=:id", test_id),
                    ("DELETE FROM managed_extension_tests WHERE id=:id", test_id),
                    ("UPDATE managed_extension_installations SET artifact_id='other' WHERE id=:id", installation_id)):
                    with pytest.raises(DBAPIError), db.begin_nested(): db.execute(text(sql), {"id": identifier})
                for sql in ("DELETE FROM extension_configuration_backups WHERE id=:id",
                    "UPDATE extension_configuration_backups SET sha256='changed' WHERE id=:id"):
                    with pytest.raises(DBAPIError), db.begin_nested():
                        db.execute(text(sql), {"id": backup_id})
                with pytest.raises(DBAPIError), db.begin_nested():
                    db.execute(insert, {**params, "id": new_id(), "device": new_id()})
                db.exec_driver_sql("SELECT set_config('icheck.tenant_id','other',true)")
                assert db.scalar(text("SELECT count(*) FROM extension_configuration_backups")) == 0
                assert db.scalar(text("SELECT count(*) FROM managed_extension_installations")) == 0
                assert db.scalar(text("SELECT count(*) FROM managed_extension_tests")) == 0
            run([*command, "downgrade", "u8z0b2d4f6h9"], env=env, succeeds=False)
            with engine.connect() as db:
                assert db.scalar(text("SELECT version_num FROM alembic_version")) == "x1d3f5h7j9l2"
                assert db.scalar(text("SELECT count(*) FROM extension_configuration_backups")) == 1
        finally:
            if engine is not None: engine.dispose()
            run([str(pg / "pg_ctl"), "-D", str(data), "-m", "fast", "-w", "stop"])
