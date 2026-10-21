import inspect
import importlib.util
from pathlib import Path

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1]/(name+'.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_no_distributed_monitoring_allowlist():
    module = load('preview_native_monitoring')
    assert module.PREVIEW_LAB_CIDRS == []
    with pytest.raises(ValueError, match='Explicit approved CIDRs'):
        module.add_preview_plugin_profiles({'profiles': {}})


def test_admin_username_is_documented_and_no_password_is_baked_in():
    module = load('preview_native_access')
    signature = inspect.signature(module.bootstrap_admin)
    assert signature.parameters['username'].default == 'admin'
    assert 'password' not in signature.parameters
    for username in ('', 'bad user', '\nadmin', '-admin'):
        with pytest.raises(ValueError, match='simple administrator username'):
            module.bootstrap_admin('operator', username=username)


def test_source_export_excludes_browser_state_and_private_deployment_helpers(tmp_path):
    module = load('prepare_public_source')
    source = tmp_path / 'source'
    private = [
        'frontend/.playwright-cli/session.yml', 'frontend/playwright-report/index.html',
        'frontend/test-results/session.json', 'frontend/next-env.d.ts',
        'deploy/preview_monitoring_integrations.py', 'deploy/check_n1_n3_deployment.py',
        'deploy/verify_n1_n3_http.py',
    ]
    public = ['frontend/app/page.tsx', 'deploy/native_installer.py',
              'acceptance/public-preview-qualification.json']
    for name in private + public:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('synthetic fixture only')
    destination = tmp_path / 'public'
    module.export(source, destination)
    assert all(not (destination / name).exists() for name in private)
    assert all((destination / name).is_file() for name in public)


def test_publication_audit_rejects_tracked_browser_state(tmp_path, monkeypatch):
    module = load('audit_publication')
    path = tmp_path / 'frontend/.playwright-cli/session.yml'
    path.parent.mkdir(parents=True)
    path.write_text('synthetic fixture only')
    monkeypatch.setattr(module.subprocess, 'check_output',
                        lambda *args: b'frontend/.playwright-cli/session.yml\0')
    result = module.audit(tmp_path)
    assert not result['passed']
    assert result['failures'][0]['reason'] == 'runtime or secret-file path'
