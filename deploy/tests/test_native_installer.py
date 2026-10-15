"""Focused installer guardrails; no package installation or live network access."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tarfile
from unittest.mock import patch

import pytest

DEPLOY = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, DEPLOY / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


installer = module('native_installer')
builder = module('build_native_installer')


@pytest.mark.parametrize('cidrs', [['198.18.0.0/24'], ['10.20.0.0/16', '172.20.0.0/24'], ['192.168.42.0/24']])
def test_explicit_networks(cidrs):
    assert installer.validate_inputs('198.18.0.10', cidrs, 'Example-only-passphrase')[1] == cidrs


@pytest.mark.parametrize('cidrs', [[], ['0.0.0.0/0'], ['8.8.8.0/24'], ['::/0'], ['10.0.0.1/24'], ['10.0.0.0/24'] * 33])
def test_rejects_unbounded_or_invalid_networks(cidrs):
    with pytest.raises((ValueError, installer.InstallError)):
        installer.validate_inputs('198.18.0.10', cidrs, 'Example-only-passphrase')


@pytest.mark.parametrize('address', ['0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', 'example.test', '1.2.3.4\nanything'])
def test_server_address_is_not_command_or_config_input(address):
    with pytest.raises((ValueError, installer.InstallError)):
        installer.validate_inputs(address, ['198.18.0.0/24'], 'Example-only-passphrase')


@pytest.mark.parametrize('password', ['', 'admin', 'x' * 14, 'x' * 257, None])
def test_no_short_or_default_password(password):
    with pytest.raises(installer.InstallError):
        installer.validate_inputs('198.18.0.10', ['198.18.0.0/24'], password)


def test_deduplicate_networks():
    assert installer.validate_inputs('198.18.0.10', ['198.18.0.0/24'] * 2, 'Example-only-passphrase')[1] == ['198.18.0.0/24']


def test_no_host_configuration_or_credentials_in_defaults():
    assert installer.common_environment()['ICHECK_CONTROL_PLANE_AUTH_MODE'] == 'required'
    assert not any('TOKEN' in name or 'PASSWORD' in name for name in installer.common_environment())
    assert 'docker' not in installer.SERVICES
    assert 'icheck-agent-worker' in installer.SERVICES
    assert installer.HEAD == 'a4g6i8k0m2p5'


def test_all_downloads_pinned_https():
    for url, digest in installer.ARTIFACTS.values():
        assert url.startswith('https://')
        assert 'latest' not in url
        assert len(digest) == 64 and int(digest, 16)


def test_only_migration_owner_can_bypass_forced_namespace_rls():
    roles = ['icheck_owner', 'icheck_api', *[item[0] for item in installer.WORKERS.values()]]
    statements = installer.database_role_statements(dict.fromkeys(roles, 'synthetic-fixture-only'))
    assert [item for item in statements if ' BYPASSRLS;' in item] == ['ALTER ROLE icheck_owner BYPASSRLS;']
    for role in roles:
        assert any(item.startswith('CREATE ROLE ' + role + ' LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION') for item in statements)
    assert 'REVOKE ALL ON DATABASE icheck FROM PUBLIC;' in statements


def test_catalog_initialization_matches_application_keyword_contract():
    import ast
    import inspect
    from icheck.builtin_activation_policies import ensure_builtin_activation_policies
    tree = ast.parse(installer.builtin_catalog_script())
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name) and node.func.id == 'ensure_builtin_activation_policies')
    inspect.signature(ensure_builtin_activation_policies).bind(None, **dict.fromkeys(item.arg for item in call.keywords))
    assert len(call.keywords) == 4
    assert 'db.commit()' in installer.builtin_catalog_script()


def test_local_worker_readiness_is_bounded_and_has_no_credentials():
    compile(installer.API_WAIT_SCRIPT, '<readiness>', 'exec')
    assert 'time.monotonic() + 600' in installer.API_WAIT_SCRIPT
    assert 'timeout=3' in installer.API_WAIT_SCRIPT
    assert 'ProxyHandler({})' in installer.API_WAIT_SCRIPT
    assert 'TOKEN' not in installer.API_WAIT_SCRIPT
    assert 'ExecStartPre=/usr/bin/python3 -I -B /opt/icheck/wait_for_native_api.py' in installer.API_WAIT_UNIT
    assert 'TimeoutStartSec=630' in installer.API_WAIT_UNIT


def test_snmp_exporter_has_required_auth_but_no_shared_device_secret():
    first = installer.initial_snmp_configuration({'system': {'walk': ['1.3.6.1.2.1.1']}})
    second = installer.initial_snmp_configuration(first['modules'])
    assert list(first['auths']) == ['native_unconfigured']
    assert first['auths']['native_unconfigured']['version'] == 2
    assert len(first['auths']['native_unconfigured']['community']) >= 32
    assert first['auths'] != second['auths']
    assert first['modules'] == second['modules']


@pytest.mark.parametrize('profile,key', [('projection-worker', 'ICHECK_PROJECTION_WORKER_NAME'),
                                        ('indicator-worker', 'ICHECK_INDICATOR_WORKER_NAME')])
def test_named_internal_workers_receive_required_identity(profile, key):
    environment = installer.internal_worker_environment(profile, 'fixture-database-url')
    assert environment[key].startswith('native-')
    assert environment['ICHECK_DATABASE_URL'] == 'fixture-database-url'
    assert environment['ICHECK_AUTO_CREATE_SCHEMA'] == 'false'


@pytest.mark.parametrize('value,ready', [('t\n', True), ('f\n', False), ('', False)])
def test_worker_readiness_requires_database_heartbeats_not_just_processes(value, ready):
    with patch.object(installer.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, value, '')) as run:
        assert installer.internal_workers_ready() is ready
        query = run.call_args.args[0][-1]
        assert 'knowledge_projection_workers' in query and 'service_indicator_workers' in query
        assert query.count("state='ONLINE'") == 2
        assert query.count("interval '120 seconds'") == 2


def test_mutating_command_failure_keeps_diagnostics_private(tmp_path):
    failure = subprocess.CompletedProcess(['tool'], 1, 'private-stdout', 'private-stderr')
    with patch.object(installer, 'STATE', tmp_path), patch.object(installer.subprocess, 'run', return_value=failure):
        with pytest.raises(installer.InstallError) as error:
            installer.run(['tool'], 'Example operation')
    assert 'private-' not in str(error.value)
    assert (tmp_path / 'private-diagnostics.log').stat().st_mode & 0o777 == 0o600


def test_download_hash_mismatch_fails_before_unpack(tmp_path):
    url, _ = installer.ARTIFACTS['node']
    (tmp_path / url.rsplit('/', 1)[1]).write_bytes(b'wrong artifact')
    with patch.object(installer, 'run'):
        with pytest.raises(installer.InstallError, match='checksum'):
            installer.download('node', tmp_path)


def test_archive_traversal_is_rejected(tmp_path):
    path = tmp_path / 'bad.tar'
    with tarfile.open(path, 'w') as archive:
        item = tarfile.TarInfo('../escape')
        item.size = 1
        archive.addfile(item, io.BytesIO(b'x'))
    with pytest.raises(installer.InstallError, match='Unsafe'):
        installer.unpack(path, tmp_path / 'unpack')
    assert not (tmp_path / 'escape').exists()


def test_public_runtime_permissions_survive_private_installer_umask(tmp_path):
    root = tmp_path / 'runtime'
    (root / 'bin').mkdir(parents=True)
    binary = root / 'bin/node'
    binary.write_bytes(b'fixture')
    binary.chmod(0o700)
    (root / 'bin').chmod(0o700)
    root.chmod(0o700)
    data = root / 'LICENSE'
    data.write_text('fixture')
    data.chmod(0o600)
    outside = tmp_path / 'protected'
    outside.write_text('not runtime content')
    outside.chmod(0o600)
    (root / 'link').symlink_to(outside)
    installer.public_runtime_permissions(root)
    assert all(path.stat().st_mode & 0o777 == 0o755 for path in (root, root / 'bin', binary))
    assert data.stat().st_mode & 0o777 == 0o644
    assert outside.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('name', ['/etc/passwd', '../escape', builder.APP_ROOT + '/../escape', 'other/file'])
def test_builder_rejects_unexpected_members(name):
    assert not builder.valid_member(tarfile.TarInfo(name))


@pytest.mark.parametrize('kind', [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE])
def test_builder_rejects_links_and_special_files(kind):
    item = tarfile.TarInfo(builder.APP_ROOT + '/file')
    item.type = kind
    assert not builder.valid_member(item)


def test_builder_refuses_unqualified_app(tmp_path):
    archive = tmp_path / 'fake.tar.gz'
    archive.write_bytes(b'not the verified release')
    with pytest.raises(ValueError, match='qualified'):
        builder.build(archive, DEPLOY.parent, tmp_path / 'new.run')
    assert not (tmp_path / 'new.run').exists()


def test_launcher_help_never_installs(tmp_path):
    path = tmp_path / 'installer.run'
    path.write_bytes(builder.launcher('0' * 64))
    output = subprocess.run(['bash', str(path), '--help'], text=True, capture_output=True)
    assert output.returncode == 0
    assert 'No Docker' in output.stdout and 'fresh Ubuntu 24.04' in output.stdout


def test_launcher_rejects_tampered_payload(tmp_path):
    path = tmp_path / 'installer.run'
    path.write_bytes(builder.launcher('0' * 64) + b'tampered\n')
    output = subprocess.run(['bash', str(path), '--check'], text=True, capture_output=True)
    assert output.returncode == 1 and 'checksum failed' in output.stderr


def test_payload_line_offset_and_digest(tmp_path):
    import hashlib
    payload = b'opaque payload\n'
    header = builder.launcher(hashlib.sha256(payload).hexdigest())
    path = tmp_path / 'installer.run'
    path.write_bytes(header + payload)
    output = subprocess.run(['bash', str(path), '--check'], text=True, capture_output=True)
    assert output.returncode == 0 and 'verified' in output.stdout


def test_preflight_refuses_nonroot_before_state_changes():
    with patch.object(installer.os, 'geteuid', return_value=1000):
        with pytest.raises(installer.InstallError, match='sudo'):
            installer.preflight()


def test_duplicate_writes_do_not_replace_credentials(tmp_path):
    path = tmp_path / 'secret'
    path.write_bytes(b'original')
    with pytest.raises(FileExistsError):
        installer.write_new(path, b'replacement')
    assert path.read_bytes() == b'original'


def test_environment_rejects_line_injection(tmp_path):
    with pytest.raises(installer.InstallError, match='Invalid'):
        installer.environment(tmp_path / 'file', {'SAFE': 'value\nEVIL=true'}, 'root')
    assert not (tmp_path / 'file').exists()


def test_authenticated_requests_never_follow_redirects():
    assert installer.NoRedirect().redirect_request(None, None, 302, None, None, 'https://example.test/') is None


@pytest.mark.parametrize('existing', ['/opt/icheck', '/etc/icheck', '/var/lib/icheck-installer', '/var/lib/icheck-grafana'])
def test_preflight_refuses_existing_state(existing):
    original_read = Path.read_text
    def content(path, *args, **kwargs):
        if str(path) == '/etc/os-release':
            return 'ID=ubuntu\nVERSION_ID="24.04"\n'
        return original_read(path, *args, **kwargs)
    with patch.object(installer.os, 'geteuid', return_value=0), patch.object(installer.platform, 'machine', return_value='x86_64'), \
         patch.object(Path, 'read_text', content), patch.object(Path, 'is_dir', return_value=True), \
         patch.object(Path, 'exists', lambda path: str(path) == existing), patch.object(Path, 'is_symlink', return_value=False):
        with pytest.raises(installer.InstallError, match='Existing'):
            installer.preflight()


@pytest.mark.parametrize('os_release,arch', [('ID=debian\nVERSION_ID="12"', 'x86_64'),
                                           ('ID=ubuntu\nVERSION_ID="22.04"', 'x86_64'),
                                           ('ID=ubuntu\nVERSION_ID="24.04"', 'aarch64')])
def test_preflight_rejects_unqualified_platforms(os_release, arch):
    with patch.object(installer.os, 'geteuid', return_value=0), patch.object(Path, 'read_text', return_value=os_release), \
         patch.object(installer.platform, 'machine', return_value=arch):
        with pytest.raises(installer.InstallError, match='supports Ubuntu'):
            installer.preflight()


def test_password_file_rejects_relative_path():
    with pytest.raises(installer.InstallError, match='absolute'):
        installer.read_password_file(Path('password.txt'))


def test_password_file_never_follows_a_symlink(tmp_path):
    secret = tmp_path / 'input'
    secret.write_text('Synthetic-only-passphrase')
    link = tmp_path / 'link'
    link.symlink_to(secret)
    with patch.object(installer, 'trusted'):
        with pytest.raises(OSError):
            installer.read_password_file(link)


def test_password_file_refuses_unsafe_metadata(tmp_path):
    path = tmp_path / 'input'
    path.write_text('Synthetic-only-passphrase')
    path.chmod(0o644)
    with patch.object(installer, 'trusted'):
        with pytest.raises(installer.InstallError, match='0600'):
            installer.read_password_file(path)
