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
