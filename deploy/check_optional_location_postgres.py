"""Private temporary PostgreSQL acceptance; never connects to the live database."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
PG = Path('/usr/lib/postgresql/16/bin')


def run(command, *, env=None):
    r = subprocess.run(command, env=env, cwd=ROOT, capture_output=True, text=True, timeout=180)
    if r.returncode:
        raise RuntimeError(f'Synthetic acceptance command failed: {Path(command[0]).name}; {r.stderr[-2000:]}')
    return r.stdout


def main():
    with tempfile.TemporaryDirectory(prefix='icheck-location-r15-pg-') as directory:
        root = Path(directory); data = root / 'data'
        run([str(PG / 'initdb'), '-D', str(data), '--auth=trust', '--no-locale', '--encoding=UTF8'])
        run([str(PG / 'pg_ctl'), '-D', str(data), '-l', str(root / 'postgres.log'), '-o', f"-k {root} -c listen_addresses=''", '-w', 'start'])
        try:
            run([str(PG / 'createdb'), '-h', str(root), 'location_acceptance'])
            url = 'postgresql+psycopg://zhao@/location_acceptance?host=' + str(root)
            env = {**os.environ, 'ICHECK_DATABASE_URL': url, 'ICHECK_AUTO_CREATE_SCHEMA': 'false', 'PYTHONPATH': str(ROOT / 'backend')}
            run([sys.executable, '-m', 'alembic', '-c', str(ROOT / 'alembic.ini'), 'upgrade', 'r5v7x9z1c3e6'], env=env)
            from sqlalchemy import create_engine, text, select
            engine = create_engine(url)
            with engine.begin() as c:
                c.execute(text("INSERT INTO devices(id,name,kind,site,labels,onboarding_status,enabled,created_by,created_at,updated_at) VALUES('legacy','legacy','switch','LAB','{}','pending_verification',true,'test',now(),now())"))
            run([sys.executable, '-m', 'alembic', '-c', str(ROOT / 'alembic.ini'), 'upgrade', 'head'], env=env)
            checks = ['postgresql_migration_upgrade']
            with engine.connect() as c:
                assert c.execute(text("SELECT site,location FROM devices WHERE id='legacy'")).one() == ('LAB', {})
                checks.append('legacy_site_preserved')
            key = root / 'test.key'; key.write_bytes(os.urandom(32)); key.chmod(0o400)
            os.environ['ICHECK_DEVICE_MANAGED_SECRET_KEY_FILE'] = str(key)
            from icheck.config import get_settings
            get_settings.cache_clear()
            from sqlalchemy.orm import Session
            from icheck.database import set_session_namespace
            from icheck.services.tenancy import ensure_default_namespace
            from icheck.services.device_credentials import create
            from icheck.device_credential_schemas import DeviceCredentialCreate
            from icheck.device_schemas import DeviceOnboardCreate, DeviceMetadataUpdate
            from icheck.services.devices import onboard_device, update_device_metadata
            from icheck.models import Device, DeviceMonitoringEnrollment, DeviceConnection, utcnow
            from icheck.services.control_plane_auth import development_principal
            from icheck.services.monitoring import monitoring_snapshot
            with Session(engine, expire_on_commit=False) as db:
                set_session_namespace(db, '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
                ensure_default_namespace(db)
                p = create(db, DeviceCredentialCreate(name='synthetic', site='LAB', kind='snmp_v2c', community='test-only-community'), 'test')
                d = onboard_device(db, DeviceOnboardCreate(name='blank-site', kind='switch', management_ip='198.18.0.10',
                    location={'zone': 'East', 'rack': 'R1', 'height': 12}, created_by='test', request_monitoring=True,
                    connections=[{'protocol': 'snmp', 'credential_profile_ref': p['id']}]))
                assert d.site is None and d.connections[0].worker_selector == {'site': 'LAB'}
                assert len(db.scalars(select(DeviceMonitoringEnrollment)).all()) == 1
                assert monitoring_snapshot(db, development_principal()).targets == []
                checks += ['null_site_and_structured_location', 'credential_worker_scope_retained', 'monitoring_pending_verification']
                d.connections[0].verification_status = 'verified'; d.connections[0].last_verified_at = utcnow(); db.commit()
                targets = monitoring_snapshot(db, development_principal()).targets
                assert len(targets) == 1 and targets[0].site == 'LAB'
                checks.append('verified_target_uses_credential_site_not_physical_location')
                from icheck.services.control_plane_auth import PrincipalContext
                os.environ['ICHECK_MANAGED_MONITORING_GATEWAY_SUBJECT'] = 'synthetic-gateway'
                get_settings.cache_clear()
                gateway = PrincipalContext(principal_id=None, subject='synthetic-gateway', principal_type='service',
                    permissions=frozenset({'assets.read'}), role_names=(), authorization_scope={'sites':['LAB']}, auth_method='token')
                assert len(monitoring_snapshot(db, gateway).targets) == 1
                other = PrincipalContext(principal_id=None, subject='ordinary-reader', principal_type='user',
                    permissions=frozenset({'assets.read'}), role_names=(), authorization_scope={'sites':['LAB']}, auth_method='token')
                assert monitoring_snapshot(db, other).targets == []
                checks.append('protected_gateway_scope_without_inventory_reader_scope_expansion')
                updated = update_device_metadata(db, d.id, DeviceMetadataUpdate(expected_revision=1, kind='switch', actor='test', location={'room': 'NOC'}), actor='test')
                assert updated.revision == 2 and updated.identity_revision == 1
                checks.append('revisioned_location_edit_does_not_retarget')
            with engine.begin() as c:
                c.execute(text('CREATE ROLE location_reader NOLOGIN'))
                c.execute(text('GRANT SELECT ON devices TO location_reader'))
                c.execute(text('SET LOCAL ROLE location_reader'))
                c.execute(text("SET LOCAL icheck.tenant_id='00000000-0000-0000-0000-000000000001'"))
                c.execute(text("SET LOCAL icheck.region_id='00000000-0000-0000-0000-000000000099'"))
                assert c.scalar(text('SELECT count(*) FROM devices')) == 0
                checks.append('nonowner_rls_region_isolation')
            engine.dispose()
            print(json.dumps({'passed': True, 'database': 'private-temporary-postgresql16', 'checks': checks,
                'live_database_changed': False, 'device_network_calls': 0, 'model_calls': 0}))
        finally:
            run([str(PG / 'pg_ctl'), '-D', str(data), '-m', 'fast', '-w', 'stop'])


if __name__ == '__main__': main()
