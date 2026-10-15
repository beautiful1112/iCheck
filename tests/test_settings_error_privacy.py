import os

import pytest
from pydantic import ValidationError

from icheck.config import Settings


def test_invalid_production_settings_do_not_echo_environment_secrets(monkeypatch):
    for key in tuple(os.environ):
        if key.startswith("ICHECK_"):
            monkeypatch.delenv(key)
    with pytest.raises(ValidationError) as rejected:
        Settings(_env_file=None, environment="production", auto_create_schema=False,
            control_plane_auth_mode="required", control_plane_session_cookie_secure=False,
            require_governed_change_contracts=True,
            database_url="postgresql+psycopg://runtime:private-database-password@localhost/icheck",
            agent_registration_token="private-agent-bootstrap-token")
    message = str(rejected.value)
    assert "production requires secure control-plane session cookies" in message
    assert "private-database-password" not in message
    assert "private-agent-bootstrap-token" not in message
