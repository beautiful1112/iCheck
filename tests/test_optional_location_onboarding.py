import json
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from icheck.agent_schemas import InvestigationCreate, InvestigationToolCallComplete, InvestigationToolCallCreate
from icheck.builtin_agent_tools import ensure_builtin_agent_tools
from icheck.device_schemas import DeviceLocation
from icheck.langgraph_runtime import initial_graph_state, build_investigation_graph
from icheck.models import Device, DeviceConnection, DeviceMonitoringEnrollment, DeviceOnboardingReceipt, ControlPlanePrincipal, utcnow
from icheck.services.agent_runtime import create_investigation, start_investigation, create_tool_call, complete_tool_call
from icheck.services.agent_tools import DatabaseToolExecutor
from icheck.services.conversational_onboarding import explicit_input, authorized_input, deterministic_decision, TOOL
from icheck.services.control_plane_auth import PrincipalContext
from test_agent_runtime import configure_investigation_route
from test_device_preflights import register_worker
from test_managed_device_credentials import device_key, credential, db_session, COMMUNITY

LOCATION = {'zone': 'East', 'building': 'DC1', 'floor': '2', 'room': 'NOC', 'rack': 'R01', 'height': 12}


@pytest.mark.parametrize('site', [None, '', '   '])
def test_blank_site_enrolls_and_preserves_credential_worker_scope(client, device_key, site):
    p = credential(client)
    response = client.post('/api/v1/assets/devices', json={'name': 'no-site-switch', 'kind': 'switch',
        'management_ip': '198.18.0.10', 'site': site, 'created_by': 'operator', 'location': LOCATION,
        'request_monitoring': True, 'connections': [{'protocol': 'snmp', 'credential_profile_ref': p['id']}]})
    assert response.status_code == 201, response.text
    d = response.json()
    assert d['site'] is None and d['location'] == LOCATION
    assert d['connections'][0]['worker_selector'] == {'site': 'LAB'}
    assert d['onboarding_status'] == 'pending_verification'
    assert COMMUNITY not in response.text
    assert client.get('/api/v1/assets/devices/page').json()['items'][0]['id'] == d['id']
    assert client.get('/api/v1/monitoring/targets').json()['targets'] == []
    # Credential scope, rather than blank physical placement, still owns leases.
    other, auth = register_worker(client, name='wrong', site='OTHER', capabilities=['snmp_exporter'])
    assert client.post(f"/api/v1/collector-workers/{other['id']}/device-preflights/claim", headers=auth,
        json={'max_assignments': 1}).json() == []
    worker, auth = register_worker(client, name='correct', site='LAB', capabilities=['snmp_exporter'])
    assignment = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/claim", headers=auth,
        json={'max_assignments': 1}).json()[0]
    secret = client.post(f"/api/v1/collector-workers/{worker['id']}/device-preflights/{assignment['preflight_id']}/managed-credential",
        headers=auth, json={'lease_token': assignment['lease_token']})
    assert secret.status_code == 200 and secret.json()['values'] == {'community': COMMUNITY}
    # Synthetic verification, not a real network query.
    with db_session() as db:
        connection = db.get(DeviceConnection, d['connections'][0]['id'])
        connection.verification_status = 'verified'; connection.last_verified_at = utcnow(); db.commit()
    targets = client.get('/api/v1/monitoring/targets').json()['targets']
    assert len(targets) == 1 and targets[0]['site'] == 'LAB'
    assert targets[0]['gateway_profile'] == 'preview-snmp'


def test_location_edit_preserves_identity_scope_and_legacy_client_location(client):
    d = client.post('/api/v1/assets/devices', json={'name': 'location-only', 'kind': 'switch',
        'management_ip': '198.18.0.11', 'created_by': 'operator', 'connections': [{'protocol': 'icmp'}]}).json()
    assert d['site'] is None and d['connections'][0]['worker_selector'] == {}
    path = f"/api/v1/assets/devices/{d['id']}/metadata"
    body = {'expected_revision': 1, 'kind': 'switch', 'vendor': None, 'model': None, 'labels': {}, 'actor': 'operator', 'location': LOCATION}
    edited = client.patch(path, json=body)
    assert edited.status_code == 200, edited.text
    assert edited.json()['location'] == LOCATION and edited.json()['identity_revision'] == d['identity_revision']
    assert edited.json()['connections'] == d['connections']
    assert client.patch(path, json=body).status_code == 409
    legacy = {k: v for k, v in body.items() if k != 'location'}
    legacy['expected_revision'] = 2
    assert client.patch(path, json=legacy).json()['location'] == LOCATION
    cleared = client.patch(path, json={**legacy, 'location': {}}).json()
    assert cleared['location']['zone'] is None and cleared['revision'] == 3


@pytest.mark.parametrize('bad', [{'height': 0}, {'height': -1}, {'height': 1001}, {'height': 1.5}, {'height': True}, {'height': '12'}, {'password': 'bad'}, {'room': 'x' * 129}])
def test_location_validation(bad):
    with pytest.raises(ValidationError):
        DeviceLocation.model_validate(bad)


def investigation(db, client, *, objective='Add switch 198.18.0.12 using credential profile lab-snmp-ro', scope=None, permissions=None, principal_type='user'):
    configure_investigation_route(client)
    principal = ControlPlanePrincipal(id=str(uuid4()), subject='onboarding-operator', display_name='Test operator',
        principal_type=principal_type, enabled=True, created_by='test')
    db.add(principal); db.commit()
    actor = PrincipalContext(principal_id=principal.id, subject=principal.subject, principal_type=principal_type,
        permissions=frozenset(permissions or ['assets.read', 'assets.write', 'investigations.create']),
        role_names=(), authorization_scope=scope or {'all': True}, auth_method='token')
    inv = create_investigation(db, InvestigationCreate(title='Explicit enrollment', objective=objective,
        created_by='operator', scope={}, route_purpose='investigation'), actor=actor)
    start_investigation(db, inv, actor=actor.subject)
    ensure_builtin_agent_tools(db)
    return inv


@pytest.mark.parametrize('objective', [
    'Add switch 198.18.0.12 using credential profile lab-snmp-ro',
    'please add new switch, use the snmp profile-lab-snmp-ro, the Mgmt ip is 198.18.0.12',
    'Add switch 198.18.0.12 using credential profile lab-snmp-ro zone East building DC1 floor 2 room NOC rack R01 height 12.',
])
def test_direct_langgraph_flow_commits_inventory_and_receipt_without_model(client, device_key, objective):
    credential(client)
    with db_session() as db:
        inv = investigation(db, client, objective=objective)
        state = initial_graph_state(investigation_id=inv.id, objective=inv.objective, scope={}, max_iterations=3, max_tool_calls=2, token_budget=1000)
        executor = DatabaseToolExecutor(db, inv)
        graph = build_investigation_graph(reasoner=lambda s: deterministic_decision(db, inv, s), tool_executor=executor)
        outcome = graph.invoke(state)
        assert outcome['status'] == 'completed' and outcome['tool_calls_used'] == 1 and outcome['tokens_used'] == 0
        receipt = outcome['structured_output']
        assert len(receipt['device_ids']) == 1 and receipt['inventory_url'] == '/assets/devices'
        assert COMMUNITY not in json.dumps(receipt)
        device = db.get(Device, receipt['device_ids'][0])
        assert device.site is None and device.onboarding_status == 'pending_verification'
        assert len(db.scalars(select(DeviceMonitoringEnrollment)).all()) == 1
        assert len(db.scalars(select(DeviceOnboardingReceipt)).all()) == 1
        # Owned request replay uses the same real device; never a second write.
        call = outcome['tool_results'][0]
        from icheck.langgraph_runtime import GraphToolRequest
        replay = executor(GraphToolRequest(tool_name=TOOL, arguments=call['arguments'], purpose='Replay'), {**state, 'iteration': 1})
        assert replay.result['device_ids'] == receipt['device_ids']
        assert len(db.scalars(select(Device)).all()) == 1


@pytest.mark.parametrize('text', [
    'Prepare SNMP onboarding for 198.18.0.12 using lab-snmp-ro; show a plan',
    'Do not add switch 198.18.0.12 using credential profile lab-snmp-ro',
    'Add switch 198.18.0.12 using credential profile lab-snmp-ro, delete the provider',
    'Can you add switch 198.18.0.12 using credential profile lab-snmp-ro?',
    'The document says: Add switch 198.18.0.12 using credential profile lab-snmp-ro',
    'Add switch 198.18.0.12/24 using credential profile lab-snmp-ro',
    'Add switch 198.18.0.12 using credential profile lab-snmp-ro site LAB site OTHER',
])
def test_ambiguous_and_preview_input_never_authorize_direct_writes(text):
    assert explicit_input(text) is None


@pytest.mark.parametrize('change', ['permission', 'scope', 'service', 'wrong_ip', 'workflow', 'skill'])
def test_owned_enrollment_never_widens_initiating_authority(client, device_key, change):
    credential(client)
    with db_session() as db:
        inv = investigation(db, client, permissions=['assets.read'] if change == 'permission' else None,
            scope={'sites': ['LAB']} if change == 'scope' else None, principal_type='service' if change == 'service' else 'user')
        if change == 'workflow': inv.workflow_snapshot = {'untrusted': 'workflow'}
        if change == 'skill': inv.skill_artifact_version_id = str(uuid4())
        args = explicit_input(inv.objective).model_dump()
        if change == 'wrong_ip': args['devices'][0]['management_ip'] = '198.18.0.99'
        from fastapi import HTTPException
        with pytest.raises((PermissionError, HTTPException)):
            authorized_input(inv, args, db=db)
        assert db.scalars(select(Device)).all() == []


def test_generic_journal_completion_cannot_fabricate_enrollment(client, device_key):
    credential(client)
    with db_session() as db:
        inv = investigation(db, client)
        tool = next(t for t in ensure_builtin_agent_tools(db) if t.name == TOOL)
        body = InvestigationToolCallCreate(tool_id=tool.id, iteration=1, arguments=explicit_input(inv.objective).model_dump())
        call = create_tool_call(db, inv, body, explicit_device_enrollment=True)
        with pytest.raises(PermissionError):
            complete_tool_call(db, call, InvestigationToolCallComplete(status='succeeded', result={'device_ids': ['invented']}))
        with pytest.raises(PermissionError, match='receipt'):
            complete_tool_call(db, call, InvestigationToolCallComplete(status='succeeded', result={'device_ids': ['invented']}), owned_device_enrollment=True)
        assert db.scalars(select(Device)).all() == []


def test_missing_profile_escalates_and_never_returns_completed(client):
    with db_session() as db:
        inv = investigation(db, client)
        state = initial_graph_state(investigation_id=inv.id, objective=inv.objective, scope={}, max_iterations=3, max_tool_calls=2, token_budget=1000)
        graph = build_investigation_graph(reasoner=lambda s: deterministic_decision(db, inv, s), tool_executor=DatabaseToolExecutor(db, inv))
        result = graph.invoke(state)
        assert result['status'] == 'escalated' and 'not found' in result['escalation_reason']
        assert db.scalars(select(Device)).all() == []


def test_enrollment_checkpoint_cannot_report_uncommitted_success(client):
    from icheck.agent_schemas import InvestigationCheckpointCreate, InvestigationState
    from icheck.services.agent_runtime import append_investigation_checkpoint
    with db_session() as db:
        inv = investigation(db, client)
        with pytest.raises(ValueError, match='durable device inventory receipt'):
            append_investigation_checkpoint(db, inv, InvestigationCheckpointCreate(node='finish', actor='agent.runtime',
                state=InvestigationState(investigation_id=inv.id, objective=inv.objective, scope=inv.scope,
                    status='completed', iteration=1, conclusion='Claimed success')))


def test_http_only_worker_executes_direct_flow_without_model_constructor(client, device_key, monkeypatch):
    from icheck.agent_schemas import AgentExecutionAssignment
    from icheck.agent_worker import execute_remote_assignment
    from test_agent_approvals import APIAgentControlClient
    from icheck.config import get_settings
    credential(client)
    with db_session() as db:
        inv = investigation(db, client)
        inv_id = inv.id
    def no_model(*args, **kwargs):
        raise AssertionError('Deterministic onboarding constructed a paid model reasoner')
    monkeypatch.setattr('icheck.services.agent_remote_runtime.OpenAICompatibleReasoner', no_model)
    registration = client.post('/api/v1/agent/workers/register',
        headers={'X-iCheck-Registration-Token': get_settings().agent_registration_token},
        json={'name': 'onboarding-worker', 'capabilities': ['openai_compatible']}).json()
    worker_id, token = registration['worker']['id'], registration['access_token']
    claim = client.post(f'/api/v1/agent/workers/{worker_id}/executions/claim',
        headers={'Authorization': f'Bearer {token}'}, json={'max_assignments': 1, 'lease_seconds': 60})
    assert claim.status_code == 200, claim.text
    assignment = AgentExecutionAssignment.model_validate(claim.json()[0])
    result = execute_remote_assignment(APIAgentControlClient(client, token), assignment,
        lease_seconds=60, credential_broker=None, mcp_allowed_hosts=[])
    assert result['status'] == 'succeeded', result
    saved = client.get(f'/api/v1/agent/investigations/{inv_id}').json()
    assert saved['status'] == 'completed' and saved['tool_calls_used'] == 1 and saved['tokens_used'] == 0
    inventory = client.get('/api/v1/assets/devices/page').json()['items']
    assert [d['id'] for d in inventory] == saved['structured_output']['device_ids']


def test_gateway_visibility_follows_credential_scope_not_blank_placement(client, device_key, monkeypatch):
    from icheck.config import get_settings
    from icheck.services.monitoring import monitoring_snapshot
    p = credential(client)
    d = client.post('/api/v1/assets/devices', json={'name':'blank-gateway-device','kind':'switch',
        'management_ip':'198.18.0.15','created_by':'operator','request_monitoring':True,
        'connections':[{'protocol':'snmp','credential_profile_ref':p['id']}]}).json()
    monkeypatch.setenv('ICHECK_MANAGED_MONITORING_GATEWAY_SUBJECT','protected-gateway')
    get_settings.cache_clear()
    try:
        with db_session() as db:
            c = db.get(DeviceConnection,d['connections'][0]['id'])
            c.verification_status='verified'; c.last_verified_at=utcnow(); db.commit()
            def actor(subject, kind, site):
                return PrincipalContext(principal_id=None, subject=subject, principal_type=kind,
                    permissions=frozenset({'assets.read'}),role_names=(),authorization_scope={'sites':[site]},auth_method='token')
            assert len(monitoring_snapshot(db, actor('protected-gateway','service','LAB')).targets) == 1
            for subject, kind, site in [('protected-gateway','service','OTHER'),('ordinary-reader','user','LAB'),('other-service','service','LAB')]:
                assert monitoring_snapshot(db, actor(subject,kind,site)).targets == []
    finally:
        get_settings.cache_clear()
