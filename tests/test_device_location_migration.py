import os
from pathlib import Path
import subprocess
import sys

from sqlalchemy import create_engine, text


def test_location_migration_preserves_site_and_refuses_lossy_downgrade(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+pysqlite:///{tmp_path / 'locations.sqlite'}"
    env = {**os.environ, 'ICHECK_DATABASE_URL': url, 'ICHECK_AUTO_CREATE_SCHEMA': 'false'}
    def migrate(command, target, success=True):
        r = subprocess.run([sys.executable, '-m', 'alembic', '-c', str(root / 'alembic.ini'), command, target],
            cwd=root, env=env, text=True, capture_output=True, timeout=120)
        assert (r.returncode == 0) is success, r.stdout + r.stderr
        return r
    migrate('upgrade', 'r5v7x9z1c3e6')
    engine = create_engine(url)
    with engine.begin() as db:
        db.execute(text("INSERT INTO devices(id,name,kind,site,labels,onboarding_status,enabled,created_by,created_at,updated_at) VALUES('legacy','legacy','switch','LAB','{}','pending_verification',true,'test',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
    migrate('upgrade', 'head')
    with engine.begin() as db:
        assert db.execute(text("SELECT site,location FROM devices WHERE id='legacy'")).one() == ('LAB', '{}')
        db.execute(text("UPDATE devices SET location='{" + '"room":"NOC"' + "}' WHERE id='legacy'"))
    failed = migrate('downgrade', 'r5v7x9z1c3e6', success=False)
    assert 'Cannot discard populated device locations' in failed.stderr
    with engine.begin() as db:
        db.execute(text("UPDATE devices SET location='{}' WHERE id='legacy'"))
    migrate('downgrade', 'r5v7x9z1c3e6')
    migrate('upgrade', 'head')
    engine.dispose()
