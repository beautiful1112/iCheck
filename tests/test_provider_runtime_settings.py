"""Timeout-only updates are stale-protected, secret-preserving and never infer."""
import json

import pytest
from sqlalchemy import select

from icheck.models import AIManagedConnection, AIProviderConfig, AuditEvent
from test_openrouter_setup import managed_key, provider_network, connect, configure, namespace_session, KEY
from test_password_login import required_auth, bootstrap, login


def update(client, connection, *, timeout=120, expected=20, revision=None, headers=None):
    return client.put(f"/api/v1/ai/providers/{connection['provider_id']}/runtime-settings", headers=headers or {}, json={
        "expected_request_timeout_seconds": expected, "request_timeout_seconds": timeout,
        "expected_connection_revision": revision if revision is not None else connection["revision"]})


def test_guided_new_default_and_timeout_only_update_preserve_all_dependencies(client, managed_key, provider_network):
    default = connect(client)
    assert default["request_timeout_seconds"] == 120
    second = connect(client, name="legacy", request_timeout_seconds=20)
    configure(client, second)
    before_models, before_routes = client.get('/api/v1/ai/models').json(), client.get('/api/v1/ai/routes').json()
    with namespace_session() as db:
        c = db.scalar(select(AIManagedConnection).where(AIManagedConnection.provider_id == second["provider_id"]))
        encrypted, outbound = c.encrypted_secret, c.outbound_enabled
    provider_network.clear()
    response = update(client, second)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json()["request_timeout_seconds"] == 120 and not provider_network
    read = client.get('/api/v1/ai/openrouter/setup').json()['connections']
    changed = next(x for x in read if x['provider_id'] == second['provider_id'])
    assert changed['revision'] == second['revision'] + 1 and changed['request_timeout_seconds'] == 120
    with namespace_session() as db:
        c = db.scalar(select(AIManagedConnection).where(AIManagedConnection.provider_id == second["provider_id"]))
        assert c.encrypted_secret == encrypted and c.outbound_enabled == outbound
        audit = db.scalar(select(AuditEvent).where(AuditEvent.event_type == 'ai.provider.runtime_settings_updated'))
        assert audit.details['previous_request_timeout_seconds'] == 20 and audit.details['inference_performed'] is False
    assert client.get('/api/v1/ai/models').json() == before_models
    assert client.get('/api/v1/ai/routes').json() == before_routes
    assert KEY not in response.text + json.dumps(read) + client.get('/api/v1/audit-events').text


@pytest.mark.parametrize('mismatch', ['revision', 'timeout', 'retired'])
def test_stale_or_retired_runtime_update_is_rejected_without_change(client, managed_key, mismatch):
    c = connect(client, request_timeout_seconds=20)
    if mismatch == 'retired':
        with namespace_session() as db:
            db.get(AIProviderConfig, c['provider_id']).enabled = False; db.commit()
    response = update(client, c, revision=2 if mismatch == 'revision' else 1, expected=60 if mismatch == 'timeout' else 20)
    assert response.status_code == 409
    assert client.get('/api/v1/ai/providers').json()[0]['request_timeout_seconds'] == 20


@pytest.mark.parametrize('timeout', [0, 121, 3600, 1.5])
def test_provider_attempt_bounds_cannot_be_expanded_past_supported_limit(client, managed_key, timeout):
    c = connect(client, request_timeout_seconds=20)
    assert update(client, c, timeout=timeout).status_code == 422


def test_noop_does_not_increment_connection_or_emit_update_audit(client, managed_key):
    c = connect(client, request_timeout_seconds=20)
    assert update(client, c, timeout=20).status_code == 200
    assert client.get('/api/v1/ai/openrouter/setup').json()['connections'][0]['revision'] == 1
    with namespace_session() as db:
        assert not db.scalars(select(AuditEvent).where(AuditEvent.event_type == 'ai.provider.runtime_settings_updated')).all()


def test_runtime_mutation_requires_csrf_and_human_ai_admin(client, managed_key, required_auth):
    _, headers = bootstrap(client)
    c = client.post('/api/v1/ai/openrouter/connections', headers=headers, json={
        'name': 'openrouter', 'api_key': KEY, 'approve_outbound': True, 'request_timeout_seconds': 20}).json()
    csrf = login(client).json()['csrf_token']
    assert update(client, c).status_code == 403
    assert update(client, c, headers={'X-Icheck-CSRF-Token': csrf}).status_code == 200
    client.cookies.clear()
    service = client.post('/api/v1/auth/principals', headers=headers, json={'subject': 'runtime-service', 'display_name': 'Service', 'principal_type': 'service'}).json()
    role = next(x for x in client.get('/api/v1/auth/roles', headers=headers).json() if x['name'] == 'admin')
    assert client.post(f"/api/v1/auth/principals/{service['id']}/bindings", headers=headers, json={'role_id': role['id'], 'scope': {'all': True}}).status_code == 201
    token = client.post(f"/api/v1/auth/principals/{service['id']}/tokens", headers=headers, json={'name': 'runtime-service', 'expires_in_hours': 1}).json()['access_token']
    assert update(client, c, headers={'Authorization': 'Bearer ' + token}).status_code == 403


def test_agent_prompt_explains_action_invariants_and_onboarding_tool_sequence():
    from icheck.services.model_reasoner import SYSTEM_PROMPT
    assert 'nonempty tool_requests' in SYSTEM_PROMPT
    assert 'credentials.list_device_profiles' in SYSTEM_PROMPT
    assert 'inventory.preview_onboarding' in SYSTEM_PROMPT
    assert 'Do not guess a missing site' in SYSTEM_PROMPT
