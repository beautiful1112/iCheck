"""One-command, fresh-host native iCheck installer (Ubuntu 24.04 x86_64).

Only the self-extracting, checksum-verified distribution invokes this module.
No existing installation is adopted, upgraded, erased or reset. Child command
diagnostics stay in a root-only log; credentials never enter command arguments.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, build_opener

VERSION = '0.1.0-preview.r19.28'
HEAD = 'h1n3q5s7u9w2'
APP = 'icheck-engineering-preview-0-1-0-r19-28-public-linux-amd64'
TENANT = '00000000-0000-0000-0000-000000000001'
REGION = '00000000-0000-0000-0000-000000000002'
STATE = Path('/var/lib/icheck-installer')
ROOT = Path('/opt/icheck')
CONFIG = Path('/etc/icheck')
BASE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root',
            'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
WORKERS = {
    'integration-sync-worker': ('icheck_integration_sync', 'icheck-integration-sync'),
    'integration-alert-worker': ('icheck_integration_alert', 'icheck-integration-alert'),
    'projection-worker': ('icheck_projection', 'icheck-projection'),
    'indicator-worker': ('icheck_indicator', 'icheck-indicator'),
    'collector-lease-reconciler': ('icheck_lease_reconciler', 'icheck-lease-reconciler'),
    'workflow-dispatch-worker': ('icheck_workflow_dispatch', 'icheck-workflow-dispatch'),
}
SERVICES = ['icheck-control-plane', 'icheck-frontend', 'icheck-collector',
            'icheck-agent-worker', *['icheck-' + name for name in WORKERS],
            'icheck-prometheus', 'icheck-snmp-exporter', 'icheck-monitoring-gateway',
            'icheck-alertmanager', 'icheck-snmp-module-installer', 'grafana-server', 'nginx']
API_WAIT_SCRIPT = '''"""Local readiness only; worker registration still uses verified mTLS."""
import time
from urllib.request import ProxyHandler, HTTPRedirectHandler, build_opener
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
opener = build_opener(ProxyHandler({}), NoRedirect())
deadline = time.monotonic() + 600
while time.monotonic() < deadline:
    try:
        with opener.open('http://127.0.0.1:8000/api/v1/health', timeout=3) as response:
            if response.status == 200:
                raise SystemExit(0)
    except OSError:
        pass
    time.sleep(2)
raise SystemExit('Local iCheck API readiness deadline exceeded')
'''
API_WAIT_UNIT = '''[Unit]
After=icheck-control-plane.service nginx.service
Wants=icheck-control-plane.service nginx.service
[Service]
ExecStartPre=/usr/bin/python3 -I -B /opt/icheck/wait_for_native_api.py
TimeoutStartSec=630
'''
ARTIFACTS = {
    'node': ('https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz',
             'df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de'),
    'prometheus': ('https://github.com/prometheus/prometheus/releases/download/v3.13.3/prometheus-3.13.3.linux-amd64.tar.gz',
                   'b349c732d8a853e657d0e7ae1bbad4d11b586615fb65fdc59d896b9f869c001e'),
    'snmp': ('https://github.com/prometheus/snmp_exporter/releases/download/v0.30.1/snmp_exporter-0.30.1.linux-amd64.tar.gz',
             '026aac4e23447ed593a783eccab9089cd41d77d17c9d2a0ab84398e45a0bb93e'),
    'alertmanager': ('https://github.com/prometheus/alertmanager/releases/download/v0.34.1/alertmanager-0.34.1.linux-amd64.tar.gz',
                     '265b9d1e55ef0d5306a436018af6d2b686c2ce051f03d968f7464ecb1372a7e8'),
    'grafana': ('https://dl.grafana.com/oss/release/grafana-13.2.3.linux-amd64.tar.gz',
                '6107ad27016296aac38e0d7ffa8753ab540b5541ad27e94790f771289d733235'),
}


class InstallError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def announce(message):
    print('[iCheck] ' + message, flush=True)


def trusted(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if item.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise InstallError('Installer files must have protected root-owned ancestry')


def write_new(path, content, *, mode=0o600, owner='root', group=None):
    import grp
    user = pwd.getpwnam(owner)
    gid = grp.getgrnam(group).gr_gid if group else user.pw_gid
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'wb') as handle:
        os.fchown(handle.fileno(), user.pw_uid, gid)
        handle.write(content.encode() if isinstance(content, str) else content)
        handle.flush()
        os.fsync(handle.fileno())
        os.fchmod(handle.fileno(), mode)


def directory(path, *, owner='root', group=None, mode=0o750):
    import grp
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    if path.is_symlink():
        raise InstallError('Refusing linked installation directory')
    user = pwd.getpwnam(owner)
    os.chown(path, user.pw_uid, grp.getgrnam(group).gr_gid if group else user.pw_gid)
    path.chmod(mode)


def run(command, label, *, env=None, input=None, timeout=120):
    announce(label)
    result = subprocess.run([str(item) for item in command], input=input, text=True,
                            capture_output=True, cwd='/', env={**BASE_ENV, **(env or {})}, timeout=timeout)
    if result.returncode:
        # Diagnostics may contain secret-bearing URLs. Never echo or publish them.
        with (STATE / 'private-diagnostics.log').open('a') as log:
            os.chmod(log.name, 0o600)
            log.write(label + '\n' + result.stdout + '\n' + result.stderr + '\n')
        raise InstallError(label + ' failed; inspect the root-only diagnostic log')
    return result.stdout.strip()


def validate_inputs(address, cidrs, password):
    address = str(ipaddress.IPv4Address(address))
    parsed = ipaddress.ip_address(address)
    if parsed.is_unspecified or parsed.is_multicast or parsed.is_reserved:
        raise InstallError('Choose an explicit unicast server IPv4 address')
    networks = [ipaddress.ip_network(value.strip(), strict=True) for value in cidrs]
    private = [ipaddress.ip_network(value) for value in ('10.0.0.0/8', '172.16.0.0/12',
                                                       '192.168.0.0/16', '198.18.0.0/15')]
    if not 1 <= len(networks) <= 32 or any(n.version != 4 or not any(n.subnet_of(p) for p in private) for n in networks):
        raise InstallError('Specify 1-32 finite private IPv4 monitoring networks; no public catch-all')
    if not isinstance(password, str) or not 15 <= len(password) <= 256:
        raise InstallError('The administrator passphrase must have 15-256 characters')
    return address, list(dict.fromkeys(str(n) for n in networks))


def read_password_file(path):
    if not path.is_absolute():
        raise InstallError('Password file must have an absolute protected path')
    trusted(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 1024:
            raise InstallError('Password file must be a root-owned regular 0600 file, at most 1024 bytes')
        raw = handle.read(1025)
    if len(raw) > 1024:
        raise InstallError('Password file exceeds the size limit')
    return raw.decode('utf-8').removesuffix('\n')


def preflight():
    if os.geteuid() != 0:
        raise InstallError('Run this installer with sudo')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '24.04' or platform.machine() != 'x86_64':
        raise InstallError('This installer supports Ubuntu 24.04 x86_64 only')
    if not Path('/run/systemd/system').is_dir():
        raise InstallError('A booted systemd host is required, not a chroot or build container')
    for path in (ROOT, CONFIG, STATE, Path('/etc/icheck-workers'), Path('/etc/icheck-grafana'),
                 Path('/etc/icheck-preview-ingress'), Path('/var/lib/icheck'), Path('/var/lib/icheck-preview-pki'),
                 Path('/var/lib/icheck-preview-access'), Path('/var/lib/icheck-grafana')):
        if path.exists() or path.is_symlink():
            raise InstallError('Existing installation or partial state found; fresh-host installation refused')
    if shutil.which('psql') or shutil.which('nginx'):
        raise InstallError('Use a dedicated fresh host without an existing PostgreSQL or nginx installation')
    if shutil.disk_usage('/').free < 10 * 1024 ** 3:
        raise InstallError('At least 10 GiB free root disk space is required')
    mem = int(re.search(r'MemTotal:\s+(\d+)', Path('/proc/meminfo').read_text()).group(1))
    if mem < 2500000:
        raise InstallError('At least 3 GiB RAM is required for single-node evaluation')
    for port in (3000, 3001, 5432, 8000, 8443, 8444, 9090, 9093, 9116, 9120):
        with socket.socket() as listener:
            try:
                listener.bind(('0.0.0.0', port))
            except OSError:
                raise InstallError(f'Required port {port} is already in use') from None


def download(key, cache):
    url, expected = ARTIFACTS[key]
    target = cache / url.rsplit('/', 1)[1]
    run(['/usr/bin/curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
         '--proto-redir', '=https', '--connect-timeout', '20', '--max-time', '900', '--retry', '2',
         '--output', target, url], 'Download pinned ' + key, timeout=1000)
    with target.open('rb') as handle:
        if hashlib.file_digest(handle, 'sha256').hexdigest() != expected:
            raise InstallError('Downloaded artifact checksum mismatch: ' + key)
    return target


def unpack(archive, destination):
    destination.mkdir(mode=0o755)
    with tarfile.open(archive) as handle:
        members = handle.getmembers()
        if sum(m.size for m in members) > 3 * 1024 ** 3:
            raise InstallError('Archive exceeds expanded size bound')
        for item in members:
            if item.name.startswith('/') or '..' in Path(item.name).parts or not (item.isfile() or item.isdir() or item.issym() or item.islnk()):
                raise InstallError('Unsafe upstream archive member')
        handle.extractall(destination, filter='data')
    children = list(destination.iterdir())
    if len(children) != 1 or not children[0].is_dir():
        raise InstallError('Unexpected upstream archive layout')
    return children[0]


def load(name, path):
    trusted(path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def public_runtime_permissions(root):
    """Allow service users to traverse public binaries extracted under umask 077."""
    for path in [root, *root.rglob('*')]:
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)


def provision_packages(payload):
    # Only a previously fresh host reaches this point. Prevent distro nginx
    # from opening port 80 while dependencies are installed.
    run(['systemctl', 'mask', 'nginx.service'], 'Keep the default nginx site stopped')
    run(['apt-get', 'update'], 'Refresh signed Ubuntu package indexes', timeout=900)
    run(['apt-get', 'install', '-y', '--no-install-recommends', 'python3.12-venv', 'postgresql',
         'postgresql-client', 'nginx', 'curl', 'ca-certificates', 'openssl'],
        'Install native OS prerequisites', env={'DEBIAN_FRONTEND': 'noninteractive'}, timeout=1800)
    cache = STATE / 'downloads'
    directory(cache, mode=0o700)
    files = {name: download(name, cache) for name in ARTIFACTS}
    directory(ROOT, mode=0o755)
    directory(ROOT / 'backend-releases', mode=0o755)
    directory(ROOT / 'frontend-releases', mode=0o755)
    node = unpack(files['node'], STATE / 'node-unpack')
    shutil.move(str(node), ROOT / 'node')
    public_runtime_permissions(ROOT / 'node')
    run(['python3.12', '-m', 'venv', ROOT / 'backend-installer-venv'], 'Create installer environment')
    installer = ROOT / 'backend-installer-venv/bin/python'
    bundle = payload / APP
    run([installer, '-m', 'pip', 'install', '--no-index', '--only-binary=:all:', '--find-links',
         bundle / 'backend-wheelhouse', 'packaging==26.3'], 'Install bundled verifier dependency', timeout=300)
    operator = bundle / 'operator/deploy'
    run([installer, operator / 'stage_native_backend.py', '--service-accounts', 'prepare', '--acknowledge-accounts'],
        'Create isolated service accounts')
    run([installer, operator / 'stage_native_backend.py', bundle, '--units', operator / 'systemd'],
        'Stage verified application and pinned backend dependencies', timeout=1800)
    run([ROOT / 'node/bin/node', operator / 'stage_native_frontend.mjs', bundle / 'frontend'],
        'Stage the prebuilt web application', timeout=300)
    return files


def environment(path, values, group):
    text = ''.join(f'{k}={v}\n' for k, v in values.items())
    if any('\n' in str(value) or '\r' in str(value) for value in values.values()):
        raise InstallError('Invalid environment setting')
    write_new(path, text, mode=0o640, group=group)


def common_environment():
    return {'ICHECK_ENVIRONMENT': 'production', 'ICHECK_AUTO_CREATE_SCHEMA': 'false',
            'ICHECK_CONTROL_PLANE_AUTH_MODE': 'required', 'ICHECK_CONTROL_PLANE_SESSION_COOKIE_SECURE': 'true',
            'ICHECK_REQUIRE_GOVERNED_CHANGE_CONTRACTS': 'true', 'ICHECK_TENANT_ID': TENANT,
            'ICHECK_REGION_ID': REGION, 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}


def builtin_catalog_script():
    return '''from icheck.database import SessionLocal, set_session_namespace
from icheck.builtin_artifacts import ensure_snmp_exporter_artifact, ensure_snmp_topology_artifact, ensure_windows_exporter_artifact, ensure_psrp_cim_artifact
from icheck.builtin_activation_policies import ensure_builtin_activation_policies
with SessionLocal() as db:
    set_session_namespace(db, "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002")
    ensure_builtin_activation_policies(db,
        snmp_artifact=ensure_snmp_exporter_artifact(db),
        snmp_topology_artifact=ensure_snmp_topology_artifact(db),
        windows_exporter_artifact=ensure_windows_exporter_artifact(db),
        psrp_cim_artifact=ensure_psrp_cim_artifact(db))
    db.commit()
'''


def initial_snmp_configuration(modules):
    # Exporter 0.30 requires at least one auth entry. No shared device credential
    # is distributed: real devices use GUI-managed credentials and isolated runs.
    return {'modules': modules, 'auths': {'native_unconfigured': {
        'version': 2, 'community': secrets.token_urlsafe(32)}}}


def internal_worker_environment(profile, database_url):
    result = {**common_environment(), 'ICHECK_DATABASE_URL': database_url,
              'ICHECK_METRICS_ALLOWED_HOSTS': '127.0.0.1,localhost'}
    names = {'projection-worker': ('ICHECK_PROJECTION_WORKER_NAME', 'native-projection-01'),
             'indicator-worker': ('ICHECK_INDICATOR_WORKER_NAME', 'native-indicator-01')}
    if profile in names:
        key, value = names[profile]
        result[key] = value
    return result


def internal_workers_ready():
    query = """SELECT
        EXISTS (SELECT 1 FROM knowledge_projection_workers WHERE name='native-projection-01'
            AND state='ONLINE' AND last_heartbeat_at > now() - interval '120 seconds')
        AND EXISTS (SELECT 1 FROM service_indicator_workers WHERE name='native-indicator-01'
            AND state='ONLINE' AND last_heartbeat_at > now() - interval '120 seconds');"""
    result = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-XAt', '-d', 'icheck', '-c', query],
                            capture_output=True, text=True, timeout=30, env=BASE_ENV, cwd='/')
    if result.returncode:
        raise InstallError('Internal worker heartbeat query failed')
    return result.stdout.strip() == 't'


def database_role_statements(passwords):
    statements = [f"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '{password}';"
                  for role, password in passwords.items()]
    # Cross-namespace migrations require visibility through FORCE ROW LEVEL SECURITY.
    # Only the root-custodied migration owner receives it, never a runtime login.
    return statements + ['ALTER ROLE icheck_owner BYPASSRLS;',
        'CREATE DATABASE icheck OWNER icheck_owner;', 'REVOKE ALL ON DATABASE icheck FROM PUBLIC;',
        'GRANT CONNECT ON DATABASE icheck TO icheck_api;', 'GRANT TEMP ON DATABASE icheck TO icheck_owner;']


def database_setup(backend):
    import psycopg
    from psycopg import sql
    from icheck.checkpoint_schema import prepare_checkpoint_schema
    from icheck.worker_database_roles import inspect_worker_grants
    passwords = {role: secrets.token_urlsafe(36) for role in ['icheck_owner', 'icheck_api', *[v[0] for v in WORKERS.values()]]}
    statements = database_role_statements(passwords)
    run(['systemctl', 'start', 'postgresql'], 'Start local PostgreSQL')
    run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-d', 'postgres'],
        'Create dedicated database and restricted roles', input='\n'.join(statements))
    urls = {role: f'postgresql+psycopg://{role}:{password}@127.0.0.1:5432/icheck' for role, password in passwords.items()}
    owner_env = {'ICHECK_DATABASE_URL': urls['icheck_owner'], 'ICHECK_AUTO_CREATE_SCHEMA': 'false'}
    run([backend / 'bin/icheck-db', 'upgrade', '--acknowledge-drained'], 'Migrate the fresh database', env=owner_env, timeout=1800)
    with psycopg.connect(urls['icheck_owner'].replace('postgresql+psycopg:', 'postgresql:')) as db:
        db.execute('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
        db.execute('GRANT USAGE ON SCHEMA public TO icheck_api')
        names = db.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT LIKE 'checkpoint%' AND tablename <> 'alembic_version'").fetchall()
        for (name,) in names:
            db.execute(sql.SQL('GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.{} TO icheck_api').format(sql.Identifier(name)))
        db.execute('GRANT SELECT ON alembic_version TO icheck_api')
        db.execute('GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO icheck_api')
    announce('Prepare isolated LangGraph checkpoint schema and restricted worker grants')
    prepare_checkpoint_schema(urls['icheck_owner'], runtime_role='icheck_api')
    for profile, (role, _) in WORKERS.items():
        inspect_worker_grants(urls['icheck_owner'], profile=profile, role=role, apply=True)
    environment(CONFIG / 'migration.env', owner_env, 'root')
    return urls


def request(base, path, *, token=None, body=None, method='GET', ca=None, basic=None, timeout=120):
    headers = {'Content-Type': 'application/json', 'X-Icheck-Tenant-ID': TENANT, 'X-Icheck-Region-ID': REGION}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if basic:
        headers['Authorization'] = 'Basic ' + base64.b64encode(basic.encode()).decode()
    handlers = [ProxyHandler({}), NoRedirect()]
    if ca:
        handlers.append(HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))
    req = Request(base + path, headers=headers, method=method,
                  data=json.dumps(body).encode() if body is not None else None)
    with build_opener(*handlers).open(req, timeout=timeout) as response:
        raw = response.read(4_000_001)
        if len(raw) > 4_000_000:
            raise InstallError('Unexpected oversized local API response')
        return json.loads(raw) if raw else None


def startup_read(operation, *, deadline):
    """Retry transient reads only, within one shared worker-startup deadline.

    No resource creation, credentials, or other writes use this helper. Invalid
    authentication, TLS identities and non-transient HTTP errors fail immediately.
    """
    while time.monotonic() < deadline:
        try:
            return operation(min(120, max(0.1, deadline - time.monotonic())))
        except HTTPError as error:
            error.close()
            if error.code not in (502, 503, 504):
                raise
        except URLError as error:
            if not isinstance(error.reason, (TimeoutError, ConnectionError)):
                raise
        except (TimeoutError, ConnectionError):
            pass
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise InstallError('Authenticated startup reads did not become ready before the deadline')


def wait_ready(url, *, timeout=300):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with build_opener(ProxyHandler({})).open(url, timeout=5) as response:
                if response.status == 200:
                    return
        except (OSError, HTTPError):
            pass
        time.sleep(2)
    raise InstallError('A local service did not become ready: ' + url.split('/')[2])


def service_account(name):
    try:
        return pwd.getpwnam(name)
    except KeyError:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
             '--shell', '/usr/sbin/nologin', name], 'Create ' + name + ' service identity')
        return pwd.getpwnam(name)


def provisioning_umask():
    # Helpers intentionally create 0750 service-group directories. The outer
    # archive launcher uses 0077; carrying it into provisioning strips traversal
    # from those groups. Private files still explicitly request 0600/0700.
    os.umask(0o027)


def configure_integration_policy():
    """Share a deny-by-default origin policy across all connector consumers."""
    write_new(CONFIG / 'monitoring-integrations.env',
              '# Add only approved exact HTTPS origins. Empty means no access.\n'
              'ICHECK_MONITORING_INTEGRATION_ALLOWED_ORIGINS=\n', mode=0o600)
    for service in ('control-plane', 'integration-sync-worker',
                    'integration-alert-worker', 'workflow-dispatch-worker'):
        dropin = Path('/etc/systemd/system') / ('icheck-' + service + '.service.d')
        directory(dropin, mode=0o755)
        content = '[Service]\nEnvironmentFile=/etc/icheck/monitoring-integrations.env\n'
        if service == 'workflow-dispatch-worker':
            content += ('LoadCredential=integration-key:/etc/icheck/ai-managed-secret.key\n'
                        'Environment=ICHECK_AI_MANAGED_SECRET_KEY_FILE=%d/integration-key\n')
        write_new(dropin / 'monitoring-integrations.conf', content, mode=0o644)


def finish(payload, config):
    provisioning_umask()
    import yaml
    from icheck.monitoring_gateway import GatewayConfig
    bundle = payload / APP
    operator = bundle / 'operator/deploy'
    tools = bundle / 'tools'
    backend = ROOT / 'backend-releases' / APP
    python = backend / 'bin/python'
    access = load('native_access', tools / 'preview_native_access.py')
    ingress = load('native_ingress', tools / 'preview_native_ingress.py')
    monitor = load('native_monitor', tools / 'preview_native_monitoring.py')
    grafana = load('native_grafana', payload / 'installer/grafana/native_install.py')
    dashboards = load('native_dashboards', payload / 'installer/grafana/dashboards.py')
    directory(CONFIG, mode=0o755)
    directory(Path('/etc/icheck-workers'), mode=0o755)
    directory(Path('/var/lib/icheck'), owner='icheck', mode=0o700)
    directory(Path('/var/lib/icheck/extensions'), owner='icheck', mode=0o700)
    directory(Path('/var/backups/icheck'), mode=0o700)
    urls = database_setup(backend)
    values = {**common_environment(), 'ICHECK_DATABASE_URL': urls['icheck_api'],
        'ICHECK_CHECKPOINT_SETUP_MODE': 'verify', 'ICHECK_WORKER_MTLS_MODE': 'required',
        'ICHECK_WORKER_MTLS_TRUSTED_PROXIES': '127.0.0.1/32', 'ICHECK_CONTROL_PLANE_PASSWORD_LOGIN_ENABLED': 'true',
        'ICHECK_CONTROL_PLANE_LOCAL_BROWSER_LOGIN_ENABLED': 'false', 'ICHECK_CONTROL_PLANE_OIDC_ENABLED': 'false',
        'ICHECK_CONTROL_PLANE_TRUSTED_PROXY_ENABLED': 'false', 'ICHECK_CONTROL_PLANE_WORKLOAD_OIDC_ENABLED': 'false',
        'ICHECK_METRICS_ALLOWED_HOSTS': '127.0.0.1,localhost', 'ICHECK_GRAFANA_ALLOWED_HOSTS': '127.0.0.1',
        'ICHECK_MANAGED_MONITORING_GATEWAY_SUBJECT': 'preview-monitoring-gateway',
        'ICHECK_SANDBOX_ENABLED': 'true', 'ICHECK_SANDBOX_BACKEND': 'process',
        'ICHECK_EXTENSION_PACKAGES_ROOT': '/var/lib/icheck/extensions',
        'ICHECK_AI_ALLOWED_HOSTS': 'openrouter.ai,api.openai.com,api.anthropic.com,generativelanguage.googleapis.com,api.deepseek.com,dashscope.aliyuncs.com,dashscope-intl.aliyuncs.com',
        'ICHECK_ARTIFACT_SIGNATURE_POLICY': 'optional'}
    for key, filename in [('ICHECK_AI_MANAGED_SECRET_KEY_FILE', 'ai-managed-secret.key'),
                          ('ICHECK_DEVICE_MANAGED_SECRET_KEY_FILE', 'device-managed-secret.key'),
                          ('ICHECK_GRAFANA_SECRET_KEY_FILE', 'grafana-integration.key')]:
        path = CONFIG / filename
        write_new(path, os.urandom(32), mode=0o440, group='icheck')
        values[key] = str(path)
    environment(CONFIG / 'control-plane.env', values, 'icheck')
    access.prepare_api([config['address']])
    announce('Generate fresh HTTPS and worker mTLS certificates')
    ingress.prepare([config['address']])
    access.prepare_workers(config['cidrs'])
    # Standard exporter tests are capabilities, not permission to contact a device.
    collector_path = CONFIG / 'collector.env'
    collector = access.parse_environment(collector_path.read_text())
    collector['ICHECK_COLLECTOR_CAPABILITIES'] += ',node_exporter,cadvisor,vmware_exporter'
    collector_path.write_bytes(access.render_environment(collector))
    for profile, (role, account) in WORKERS.items():
        settings = internal_worker_environment(profile, urls[role])
        environment(CONFIG / (profile + '.env'), settings, account)
    environment(CONFIG / 'frontend.env', {'NODE_ENV': 'production', 'HOSTNAME': '127.0.0.1',
                'PORT': '3000', 'NEXT_TELEMETRY_DISABLED': '1'}, 'icheck-frontend')
    for unit in (operator / 'systemd').glob('*.service'):
        write_new(Path('/etc/systemd/system') / unit.name, unit.read_bytes(), mode=0o644)
    configure_integration_policy()
    # Remote-worker templates do not depend on a local API. This installer is
    # single-node, so gate first registration on local readiness after a reboot.
    write_new(ROOT / 'wait_for_native_api.py', API_WAIT_SCRIPT, mode=0o644)
    for service in ('icheck-collector', 'icheck-agent-worker'):
        dropin = Path('/etc/systemd/system') / (service + '.service.d')
        directory(dropin, mode=0o755)
        write_new(dropin / 'native-readiness.conf', API_WAIT_UNIT, mode=0o644)
    run(['systemctl', 'unmask', 'nginx.service'], 'Use the private iCheck HTTPS ingress')
    write_new(Path('/etc/systemd/system/nginx.service'), (bundle / 'config/nginx.service').read_bytes(), mode=0o644)
    # Keep four API workers out of a small single-node preview; processes remain scalable later.
    override = Path('/etc/systemd/system/icheck-control-plane.service.d')
    directory(override, mode=0o755)
    write_new(override / 'native-installer.conf', '[Service]\nExecStart=\nExecStart=/opt/icheck/.venv/bin/uvicorn icheck.main:app --host 127.0.0.1 --port 8000 --workers 1 --no-proxy-headers\nReadWritePaths=/var/lib/icheck-metric-rules\n', mode=0o644)
    directory(Path('/var/lib/icheck-metric-rules'), owner='icheck', group='icheck-prometheus', mode=0o750)
    write_new(Path('/var/lib/icheck-metric-rules/rules.yml'), json.dumps({'groups': [{'name': 'icheck.metric-rules', 'interval': '15s', 'rules': []}]}),
              owner='icheck', group='icheck-prometheus', mode=0o640)
    run(['systemctl', 'daemon-reload'], 'Load native service units')
    run([ROOT / 'backend-installer-venv/bin/python', operator / 'switch_native_backend.py', '--to', APP,
         '--expect', 'none', '--database-revision', HEAD, '--database-check-timeout-seconds', '120',
         '--acknowledge-drained', '--acknowledge-schema-compatible'], 'Activate the verified backend',
         env={'ICHECK_DATABASE_URL': urls['icheck_api']}, timeout=180)
    frontend_id = json.loads((bundle / 'frontend/native-release.json').read_text())['build_id']
    run([ROOT / 'node/bin/node', operator / 'switch_native_frontend.mjs', '--to', frontend_id,
         '--expect', 'none', '--acknowledge-drained'], 'Activate the paired frontend')
    run(['systemctl', 'enable', '--now', 'icheck-control-plane', 'icheck-frontend', 'nginx'], 'Start application and HTTPS')
    wait_ready('http://127.0.0.1:8000/api/v1/health')
    operator_user = 'icheck-operator'
    service_account(operator_user)
    access.bootstrap_admin(operator_user, username='admin', timeout_seconds=120)
    run(['systemctl', 'restart', 'icheck-control-plane'], 'Remove bootstrap authority from the running API')
    wait_ready('http://127.0.0.1:8000/api/v1/health')
    token = Path('/var/lib/icheck-preview-access/admin-access-token').read_text().strip()
    ca = Path('/etc/icheck-preview-ingress/preview-ca.pem')
    def api(path, body=None, method='GET', *, timeout=120):
        return request('https://127.0.0.1:8443/api/v1', path, token=token, body=body, method=method, ca=ca, timeout=timeout)
    identity = api('/auth/me')
    password = config.pop('password')
    api('/auth/principals/' + identity['principal_id'] + '/password',
        {'password': password, 'reason': 'Native first-install administrator setup'}, 'PUT')
    login = request('https://127.0.0.1:8443/api/v1', '/auth/login', method='POST', ca=ca,
                    body={'username': 'admin', 'password': password})
    if not login.get('csrf_token'):
        raise InstallError('Administrator password sign-in verification failed')
    del password
    # Install only public third-party binaries/configuration, never an existing host's files.
    directory(ROOT / 'bin', mode=0o755)
    upstream = {}
    for name in ('prometheus', 'snmp', 'alertmanager'):
        upstream[name] = unpack(Path(config['artifacts'][name]), STATE / (name + '-unpack'))
    for name, commands in {'prometheus': ['prometheus', 'promtool'], 'snmp': ['snmp_exporter'],
                           'alertmanager': ['alertmanager', 'amtool']}.items():
        for command in commands:
            shutil.copyfile(upstream[name] / command, ROOT / 'bin' / command)
            (ROOT / 'bin' / command).chmod(0o755)
    promdir = Path('/etc/icheck-workers/prometheus')
    directory(promdir, group='icheck-prometheus')
    prom = {'global': {'scrape_interval': '30s'}, 'rule_files': ['/var/lib/icheck-metric-rules/rules.yml'],
            'alerting': {'alertmanagers': [{'static_configs': [{'targets': ['127.0.0.1:9093']}]}]},
            'scrape_configs': [{'job_name': 'prometheus', 'static_configs': [{'targets': ['127.0.0.1:9090']}]}]}
    write_new(promdir / 'prometheus.yml', yaml.safe_dump(prom), group='icheck-prometheus', mode=0o640)
    snmpdir = Path('/etc/icheck-workers/snmp-exporter')
    directory(snmpdir, group='icheck-snmp-exporter')
    snmp = yaml.load((upstream['snmp'] / 'snmp.yml').read_bytes(), Loader=getattr(yaml, 'CSafeLoader', yaml.SafeLoader))
    modules = {name: snmp['modules'][name] for name in ('if_mib', 'system')}
    write_new(snmpdir / 'snmp.yml', yaml.safe_dump(initial_snmp_configuration(modules)), group='icheck-snmp-exporter', mode=0o640)
    runtime = Path('/etc/icheck-workers/snmp-runtime')
    directory(runtime, mode=0o755)
    write_new(runtime / 'modules.yml', yaml.safe_dump({'modules': modules}), mode=0o444)
    monitor.prepare(timeout_seconds=120)
    gateway_path = Path('/etc/icheck-workers/monitoring-gateway/config.json')
    gateway = json.loads(gateway_path.read_text())
    gateway['profiles']['preview-snmp']['allow_managed_snmp_credentials'] = True
    gateway['profiles']['preview-snmp']['snmp_auth_name'] = 'native_unconfigured'
    monitor.PREVIEW_LAB_CIDRS = config['cidrs']
    gateway = monitor.add_preview_plugin_profiles(gateway)
    GatewayConfig.model_validate(gateway)
    gateway_path.write_text(json.dumps(gateway, indent=2) + '\n')
    backend_id = next(row['id'] for row in api('/metrics/backends?limit=1000') if row['name'] == 'native-lab-prometheus')
    # The built-in catalog is reusable platform content, not demonstration inventory.
    run([python, '-I', '-B', '-c', builtin_catalog_script()], 'Initialize reusable built-in capabilities without demonstration data',
        env=access.parse_environment((CONFIG / 'control-plane.env').read_text()), timeout=300)
    alert_account = service_account('icheck-alertmanager')
    alertdir = Path('/etc/icheck-workers/alertmanager')
    directory(alertdir, group=alert_account.pw_name)
    role = api('/auth/roles', {'name': 'native-alert-receiver', 'description': 'Local Alertmanager ingestion only',
        'permissions': ['alerts.emit']}, 'POST')
    principal = api('/auth/principals', {'subject': 'icheck.alertmanager', 'display_name': 'Local Alertmanager',
        'principal_type': 'service', 'allowed_region_ids': [REGION]}, 'POST')
    api(f'/auth/principals/{principal["id"]}/bindings', {'role_id': role['id'], 'scope': {}}, 'POST')
    receiver = api(f'/auth/principals/{principal["id"]}/tokens', {'name': 'native-alert-receiver', 'expires_in_hours': 720}, 'POST')
    write_new(alertdir / 'receiver.token', receiver['access_token'] + '\n', group='icheck-alertmanager', mode=0o640)
    write_new(alertdir / 'alertmanager.yml', (bundle / 'config/alertmanager/alertmanager.yml.example').read_bytes(),
              group='icheck-alertmanager', mode=0o640)
    values = access.parse_environment((CONFIG / 'control-plane.env').read_text())
    values.update({'ICHECK_METRIC_RULE_DIRECTORY': '/var/lib/icheck-metric-rules', 'ICHECK_METRIC_RULE_BACKEND_ID': backend_id,
        'ICHECK_METRIC_RULE_TENANT_ID': TENANT, 'ICHECK_METRIC_RULE_REGION_ID': REGION,
        'ICHECK_METRIC_ALERT_WEBHOOK_SUBJECT': 'icheck.alertmanager', 'ICHECK_METRIC_ALERTMANAGER_URL': 'http://127.0.0.1:9093'})
    access.atomic_environment(values)
    override = Path('/etc/systemd/system/icheck-prometheus.service.d')
    directory(override, mode=0o755)
    write_new(override / 'lifecycle.conf', '[Service]\nExecStart=\nExecStart=/opt/icheck/bin/prometheus --config.file=/etc/icheck-workers/prometheus/prometheus.yml --storage.tsdb.path=/var/lib/icheck-prometheus --storage.tsdb.retention.time=15d --storage.tsdb.retention.size=2GB --web.listen-address=127.0.0.1:9090 --web.enable-lifecycle\n', mode=0o644)
    configure_grafana(payload, config, grafana, dashboards, api)
    run(['systemctl', 'daemon-reload'], 'Load monitoring service configuration')
    run(['systemctl', 'restart', 'icheck-control-plane'], 'Load local integration settings')
    wait_ready('http://127.0.0.1:8000/api/v1/health')
    run(['systemctl', 'enable', '--now', *SERVICES], 'Start native workers and monitoring services', timeout=180)
    verify_installation(api)
    receipt = {'version': VERSION, 'application_release': APP, 'schema': HEAD, 'frontend_build': frontend_id,
        'installed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'services': SERVICES,
        'login_url': f'https://{config["address"]}:8443/login', 'admin_username': 'admin',
        'monitoring_networks': config['cidrs'], 'site': 'LAB', 'devices_created': 0, 'providers_configured': 0,
        'automatic_ai_investigation_enabled': False, 'docker_required': False,
        'evaluation_tls_expires_in_days': 90, 'service_token_ttl_days': 30}
    write_new(STATE / 'installed.json', json.dumps(receipt, indent=2) + '\n')
    announce('Installation verified. Open ' + receipt['login_url'])
    announce('Username: admin. Use the passphrase you supplied. No shared default password exists.')
    announce('Evaluation CA: /etc/icheck-preview-ingress/preview-ca.pem. Verify and trust it on your own client.')
    announce('Separate Grafana login: sudo cat /etc/icheck-grafana/initial-admin-password (username admin).')
    announce('Credentials and monitoring targets remain empty. Configure them through the GUI.')


def configure_grafana(payload, config, grafana, dashboards, api):
    account = service_account('icheck-grafana')
    home = unpack(Path(config['artifacts']['grafana']), STATE / 'grafana-unpack')
    shutil.move(str(home), ROOT / 'grafana')
    public_runtime_permissions(ROOT / 'grafana')
    grafana.USERNAME = 'admin'
    conf = Path('/etc/icheck-grafana')
    directory(conf, group=account.pw_name)
    directory(conf / 'provisioning', group=account.pw_name)
    directory(conf / 'provisioning/datasources', group=account.pw_name)
    public_url = f'https://{config["address"]}:8443/grafana/'
    password = secrets.token_urlsafe(30)
    for name, content in {'initial-admin-password': password, 'secret-key': secrets.token_urlsafe(48),
                           'grafana.ini': grafana.grafana_config(public_url)}.items():
        write_new(conf / name, content, group=account.pw_name, mode=0o640)
    data = {'apiVersion': 1, 'datasources': [{'name': 'iCheck Prometheus', 'uid': 'icheck-prometheus',
        'type': 'prometheus', 'access': 'proxy', 'orgId': 1, 'url': 'http://127.0.0.1:9090',
        'isDefault': True, 'editable': False, 'jsonData': {'httpMethod': 'POST'}}]}
    write_new(conf / 'provisioning/datasources/prometheus.yaml', json.dumps(data), group=account.pw_name, mode=0o640)
    write_new(Path('/etc/systemd/system/grafana-server.service'),
              (payload / 'installer/grafana/grafana-server.service').read_bytes(), mode=0o644)
    nginx = Path('/etc/icheck-preview-ingress/nginx.conf')
    extended = grafana.ingress_with_grafana(nginx.read_text()).replace(
        'proxy_pass http://127.0.0.1:3001;\n', 'proxy_pass http://127.0.0.1:3001;\n            proxy_buffering off;\n')
    nginx.write_text(extended)
    run(['systemctl', 'daemon-reload'], 'Load Grafana service')
    run(['systemctl', 'enable', '--now', 'grafana-server'], 'Start native Grafana')
    wait_ready('http://127.0.0.1:3001/grafana/api/health')
    def call(path, body=None):
        return request('http://127.0.0.1:3001/grafana', path, basic='admin:' + password,
                       body=body, method='POST' if body is not None else 'GET')
    call('/apis/folder.grafana.app/v1/namespaces/default/folders', {'metadata': {'name': 'icheck'}, 'spec': {'title': 'iCheck'}})
    for dashboard in dashboards.baseline_dashboards(icheck_url=public_url.removesuffix('grafana/')):
        call('/apis/dashboard.grafana.app/v1/namespaces/default/dashboards', dashboard)
    account = call('/api/serviceaccounts', {'name': 'icheck-native', 'role': 'Editor'})
    issued = call(f'/api/serviceaccounts/{account["id"]}/tokens', {'name': 'icheck-native', 'secondsToLive': 2592000})
    api('/grafana/connections', {'name': 'native-grafana', 'api_url': 'http://127.0.0.1:3001/grafana',
        'public_url': public_url, 'token': issued['key'], 'shared_dataset_acknowledged': True}, 'POST')
    run(['nginx', '-t', '-c', nginx], 'Validate HTTPS and Grafana routes')
    run(['systemctl', 'restart', 'nginx'], 'Activate Grafana HTTPS routing')


def verify_installation(api):
    announce('Verify services, authenticated API, monitoring and empty inventory')
    for url in ('http://127.0.0.1:8000/api/v1/health', 'http://127.0.0.1:3000/login',
                'http://127.0.0.1:9090/-/ready', 'http://127.0.0.1:9093/-/ready',
                'http://127.0.0.1:9116/metrics', 'http://127.0.0.1:3001/grafana/api/health'):
        wait_ready(url)
    for service in SERVICES:
        if run(['systemctl', 'is-active', service], 'Check ' + service) != 'active':
            raise InstallError('Service is not active: ' + service)
    # Parallel worker initialization can temporarily delay even an authenticated
    # GET on a small host. Share a bounded deadline across all readiness reads;
    # never retry the earlier provisioning mutations or ignore authority errors.
    deadline = time.monotonic() + 600
    def read_api(path):
        return startup_read(lambda timeout: api(path, timeout=timeout), deadline=deadline)
    if read_api('/auth/me').get('subject') != 'admin':
        raise InstallError('Administrator identity check failed')
    if not read_api('/grafana/setup')['storage_ready'] or not read_api('/metric-alerts/setup')['runtime_provisioned']:
        raise InstallError('Local integration is not ready')
    try:
        startup_read(lambda timeout: request('http://127.0.0.1:8000/api/v1',
                     '/assets/devices?limit=1', timeout=timeout), deadline=deadline)
    except HTTPError as error:
        if error.code != 401:
            raise InstallError('Anonymous inventory check failed') from None
    else:
        raise InstallError('Anonymous inventory access must be rejected')
    if read_api('/assets/devices?limit=1') or read_api('/ai/providers?limit=1'):
        raise InstallError('Fresh installation unexpectedly contains devices or AI providers')
    # Several isolated Python services start together, including on small VMs.
    while time.monotonic() < deadline:
        collectors = read_api('/collectors/health')
        agents = read_api('/agent/workers?limit=100')
        if collectors.get('workers_online', 0) >= 1 and any(
                {'openai_compatible', 'anthropic', 'mcp'} <= set(worker.get('capabilities', [])) for worker in agents) and internal_workers_ready():
            break
        time.sleep(2)
    else:
        raise InstallError('Required local worker registration or heartbeat did not become ready')
    connections = read_api('/grafana/connections')
    if len(connections) != 1:
        raise InstallError('Expected one native Grafana connection')
    read_api('/grafana/connections/' + connections[0]['id'] + '/health')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--server-ip', help='Explicit IPv4 address bound for HTTPS')
    parser.add_argument('--monitor-cidr', action='append', help='Approved private monitoring subnet; repeatable')
    parser.add_argument('--password-file', type=Path, help='Optional protected root-owned 0600 file; never a password argument')
    parser.add_argument('--yes', action='store_true', help='Accept fresh-host installation after explicit inputs')
    parser.add_argument('--finish', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    trusted(Path(__file__).resolve())
    trusted(args.payload)
    if args.finish:
        finish(args.payload, json.load(sys.stdin))
        return
    preflight()
    announce('Fresh Ubuntu 24.04 native installation: PostgreSQL, nginx, Node.js, Prometheus, SNMP Exporter, Grafana and Alertmanager.')
    announce('No Docker. No existing installation will be overwritten. Network downloads are required.')
    address = args.server_ip or input('Server IPv4 address for HTTPS: ').strip()
    cidrs = args.monitor_cidr or [v.strip() for v in input('Approved monitoring subnet(s), comma-separated: ').split(',')]
    if args.password_file:
        password = read_password_file(args.password_file)
    else:
        if not sys.stdin.isatty():
            raise InstallError('Interactive terminal or protected --password-file required')
        password = getpass.getpass('Choose the admin passphrase (15-256 characters): ')
        if password != getpass.getpass('Confirm the admin passphrase: '):
            raise InstallError('Passphrases do not match')
    address, cidrs = validate_inputs(address, cidrs, password)
    with socket.socket() as check:
        try:
            check.bind((address, 0))
        except OSError:
            raise InstallError('The selected HTTPS address is not assigned to this host') from None
    if not args.yes and input('Install on this fresh host? [yes/no]: ').strip().lower() != 'yes':
        raise InstallError('Installation cancelled without changing services')
    directory(STATE, mode=0o700)
    write_new(STATE / 'started.json', json.dumps({'version': VERSION, 'status': 'in_progress'}))
    files = provision_packages(args.payload)
    data = {'address': address, 'cidrs': cidrs, 'password': password,
            'artifacts': {key: str(value) for key, value in files.items()}}
    # Credentials cross only a pipe, not argv, environment or a saved installer plan.
    result = subprocess.run([str(ROOT / 'backend-releases' / APP / 'bin/python'), '-I', '-B',
                             str(Path(__file__).resolve()), '--payload', str(args.payload), '--finish'],
                            input=json.dumps(data), text=True, env=BASE_ENV, cwd='/')
    if result.returncode:
        raise InstallError('Installation stopped. Retained state is protected; do not rerun or delete it blindly.')
    for path in STATE.glob('*-unpack'):
        shutil.rmtree(path)
    shutil.rmtree(STATE / 'downloads')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        if isinstance(error, InstallError):
            print('[iCheck] ' + str(error), file=sys.stderr)
        else:
            print('[iCheck] Installation stopped (' + type(error).__name__ + '); private details withheld.', file=sys.stderr)
        if STATE.is_dir():
            import traceback
            with (STATE / 'private-diagnostics.log').open('a') as output:
                os.chmod(output.name, 0o600)
                traceback.print_exc(file=output)
        raise SystemExit(1)
