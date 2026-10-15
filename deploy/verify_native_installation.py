"""Read-only native first-install acceptance checks; no device or AI calls.

Run as root on the disposable acceptance host after installation. The optional
password file belongs to that fixture, never to the distributed release.
Password verification creates a local browser session but changes no resources.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.cookiejar
import json
from pathlib import Path
import re
import ssl
import subprocess
import time
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, HTTPSHandler, HTTPCookieProcessor, HTTPRedirectHandler, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def verify(password_file=None):
    receipt = json.loads(Path('/var/lib/icheck-installer/installed.json').read_text())
    token = Path('/var/lib/icheck-preview-access/admin-access-token').read_text().strip()
    context = ssl.create_default_context(cafile='/etc/icheck-preview-ingress/preview-ca.pem')
    cookies = http.cookiejar.CookieJar()
    opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context), HTTPCookieProcessor(cookies))
    checks = []
    origin = 'https://127.0.0.1:8443'
    def get(path, *, authenticated=False, body=None):
        headers = {'Authorization': 'Bearer ' + token} if authenticated else {}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        with opener.open(Request(origin + path, headers=headers,
                         data=json.dumps(body).encode() if body is not None else None), timeout=60) as response:
            data = response.read(32_000_001)
            assert len(data) <= 32_000_000
            if response.headers.get('Content-Length'):
                assert len(data) == int(response.headers['Content-Length'])
            return data
    def api(path):
        return json.loads(get('/api/v1' + path, authenticated=True))
    for path in ('/assets/devices?limit=1', '/ai/providers?limit=1', '/ai/models?limit=1', '/agent/investigations?limit=1', '/endpoints?limit=1'):
        assert api(path) == []
        checks.append('empty:' + path.split('?')[0])
    assert api('/auth/me')['subject'] == 'admin'
    checks.append('admin_identity')
    for path in ('/api/v1/assets/devices?limit=1', '/api/v1/auth/bootstrap'):
        try:
            get(path, body={'subject': 'installer-verification-only', 'display_name': 'Rejected fixture'}
                if path.endswith('bootstrap') else None)
        except HTTPError as error:
            assert error.code == (404 if path.endswith('bootstrap') else 401)
            error.close()
        else:
            raise AssertionError('Unauthenticated authority boundary failed')
    checks.append('anonymous_inventory_rejected_and_bootstrap_hidden')
    collector = api('/collectors/health')
    assert collector['workers_online'] >= 1 and collector['deployments_total'] == 0
    assert any({'anthropic', 'openai_compatible', 'mcp'} <= set(worker['capabilities']) for worker in api('/agent/workers'))
    checks.append('collectors_and_multi_provider_worker_registered')
    setup = api('/grafana/setup')
    assert setup['storage_ready'] and len(setup['connections']) == 1
    connection = setup['connections'][0]['id']
    api('/grafana/connections/' + connection + '/health')
    assert api('/metric-alerts/setup')['runtime_provisioned']
    checks.append('grafana_prometheus_and_metric_rule_integration')
    assert api('/research/settings')['storage_ready']
    checks.append('encrypted_search_settings_ready')
    assert api('/autonomy/alert-policy')['enabled'] is False
    checks.append('automatic_ai_investigation_disabled')
    assets = 0
    for path in ('/login', '/grafana/login'):
        html = get(path).decode()
        sources = set(re.findall(r'<script[^>]+src=["\']([^"\']+)', html))
        assert sources
        for source in sources:
            if not source.startswith('/'):
                source = '/grafana/' + source if path.startswith('/grafana/') else '/' + source
            assert not source.startswith('//') and '://' not in source
            body = get(source)
            assert body and not body.lstrip().lower().startswith(b'<!doctype html')
            assets += 1
    checks.append('frontend_and_grafana_javascript_complete')
    if password_file:
        password = Path(password_file).read_text().removesuffix('\n')
        req = Request(origin + '/api/v1/auth/login', method='POST',
            headers={'Content-Type': 'application/json', 'Origin': origin},
            data=json.dumps({'username': 'admin', 'password': password}).encode())
        with opener.open(req, timeout=120) as response:
            assert response.status == 201
            cookie = response.headers['Set-Cookie']
            assert 'HttpOnly' in cookie and 'Secure' in cookie and 'samesite=strict' in cookie.lower()
            assert json.load(response)['csrf_token']
        assert json.loads(get('/api/v1/auth/me'))['subject'] == 'admin'
        checks.append('password_login_secure_cookie_and_authenticated_browser_session')
    restarts = {}
    for service in receipt['services']:
        result = subprocess.run(['systemctl', 'show', service, '-p', 'ActiveState', '-p', 'SubState',
                                 '-p', 'NRestarts', '-p', 'ExecStart'], capture_output=True, text=True, check=True)
        assert 'ActiveState=active' in result.stdout and 'SubState=running' in result.stdout
        restarts[service] = int(re.search(r'^NRestarts=(\d+)$', result.stdout, re.M)[1])
        assert 'docker' not in result.stdout
    checks.append('native_systemd_services_active')
    time.sleep(10)
    for service, count in restarts.items():
        state = subprocess.check_output(['systemctl', 'show', service, '-p', 'NRestarts',
                                         '-p', 'ActiveState', '-p', 'SubState'], text=True)
        assert 'ActiveState=active' in state and 'SubState=running' in state
        assert int(re.search(r'^NRestarts=(\d+)$', state, re.M)[1]) == count
    checks.append('native_services_stable_over_10s')
    sql = """SELECT json_agg(json_build_object('name',rolname,'superuser',rolsuper,
        'bypass',rolbypassrls,'createdb',rolcreatedb,'createrole',rolcreaterole))
        FROM pg_roles WHERE rolname IN ('icheck_owner','icheck_api','icheck_projection',
        'icheck_indicator','icheck_lease_reconciler','icheck_workflow_dispatch');"""
    roles = json.loads(subprocess.check_output(['runuser', '-u', 'postgres', '--', 'psql',
                       '-XAt', '-d', 'icheck', '-c', sql], text=True))
    assert len(roles) == 6
    for role in roles:
        assert not role['superuser'] and not role['createdb'] and not role['createrole']
        assert role['bypass'] is (role['name'] == 'icheck_owner')
    checks.append('migration_authority_separate_from_restricted_runtime_roles')
    query = """SELECT count(*) FROM (
        SELECT name FROM knowledge_projection_workers WHERE name='native-projection-01'
          AND state='ONLINE' AND last_heartbeat_at > now() - interval '120 seconds'
        UNION ALL SELECT name FROM service_indicator_workers WHERE name='native-indicator-01'
          AND state='ONLINE' AND last_heartbeat_at > now() - interval '120 seconds') workers;"""
    assert subprocess.check_output(['runuser', '-u', 'postgres', '--', 'psql', '-XAt',
                                    '-d', 'icheck', '-c', query], text=True).strip() == '2'
    checks.append('projection_and_indicator_workers_have_fresh_heartbeats')
    environment = Path('/etc/icheck/control-plane.env').read_text()
    assert 'ICHECK_CONTROL_PLANE_BOOTSTRAP_TOKEN=' not in environment
    for filename in ('collector.env', 'agent-worker.env'):
        assert 'ICHECK_DATABASE_URL=' not in Path('/etc/icheck', filename).read_text()
    checks.append('bootstrap_removed_and_remote_workers_database_free')
    return {'passed': True, 'tested_at': datetime.now(timezone.utc).isoformat(), 'checks': checks,
            'javascript_assets_checked': assets, 'native_services': len(receipt['services']), 'service_restart_counts': restarts,
            'application_release': receipt['application_release'], 'schema': receipt['schema'],
            'frontend_build': receipt['frontend_build'], 'device_probes': 0, 'paid_provider_calls': 0,
            'ca_sha256': hashlib.sha256(Path('/etc/icheck-preview-ingress/preview-ca.pem').read_bytes()).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--password-file', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.password_file)))
