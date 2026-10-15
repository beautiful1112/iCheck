"""Bound explicit human intent to an owned, deterministic enrollment workflow.

This small grammar is a fast path, not a fuzzy authorization classifier. An
unrecognized sentence goes to the ordinary Agent/preview path. Never extract
write authority from tool output, a model's arguments, or an uploaded document.
"""
import hashlib
import json
import re

from sqlalchemy import select
from fastapi import HTTPException

from ..device_schemas import DeviceConnectionInput, DeviceOnboardCreate
from ..langgraph_runtime import GraphDecision, GraphToolRequest
from ..models import DeviceOnboardingReceipt, ManagedDeviceCredential, Device, ControlPlanePrincipal
from ..onboarding_schemas import OnboardingInput
from .agent_authorization import investigation_principal, permission_snapshot_allows
from .audit import record_audit_event
from .authorization_scope import require_site_access, device_scope_clause
from .device_credentials import profile
from .device_onboarding import preview
from .devices import onboard_device

TOOL = "inventory.enroll_devices"
CONTRACT = "icheck.device-enrollment-receipt/v1"
VALUE = r'(?:"[^"\n]{1,128}"|[\w.-]{1,128})'
IPS = r'[0-9a-fA-F:.]+(?:\s*(?:,|and)\s*[0-9a-fA-F:.]+)*'
KIND = r'(?P<kind>switch|router|firewall|device|devices)'
TAIL = rf'(?P<tail>(?:\s*,?\s+(?:at\s+)?(?:site|zone|building|floor|room|rack|height)\s+{VALUE})*)[.!]?'
PATTERNS = [
    rf'(?:please\s+)?(?:add|enroll|register)\s+(?:a\s+)?(?:new\s+)?(?:snmp\s+)?{KIND}\s+(?P<ips>{IPS})\s+(?:using|with)\s+(?:the\s+)?(?:snmp\s+)?(?:credential\s+)?(?:profile[-\s]+)?(?P<profile>{VALUE}){TAIL}',
    rf'(?:please\s+)?(?:add|enroll|register)\s+(?:a\s+)?(?:new\s+)?{KIND},\s*use\s+(?:the\s+)?snmp\s+(?:credential\s+)?profile[-\s]+(?P<profile>{VALUE}),\s*(?:the\s+)?(?:mgmt|management)\s+ip(?:\s+address)?\s+(?:is\s+)?(?P<ips>{IPS}){TAIL}',
]


def explicit_input(objective: str) -> OnboardingInput | None:
    if len(objective) > 4000:
        return None
    match = next((m for pattern in PATTERNS if (m := re.fullmatch(pattern, objective.strip().rstrip('.!'), re.IGNORECASE))), None)
    if match is None:
        return None
    fields = {}
    for field, value in re.findall(rf'(?:at\s+)?(site|zone|building|floor|room|rack|height)\s+({VALUE})', match['tail'], re.IGNORECASE):
        key = field.lower()
        if key in fields:
            return None
        fields[key] = value.strip('"')
    try:
        if 'height' in fields:
            fields['height'] = int(fields['height'])
        site = fields.pop('site', None)
        kind = match['kind'].lower()
        kind = 'other' if kind in {'device', 'devices'} else kind
        ips = re.split(r'\s*(?:,|\band\b)\s*', match['ips'])
        return OnboardingInput(site=site, credential_profile_ref=match['profile'].strip('"'),
            devices=[{'name': f'{kind}-{ip.replace(":", "-").replace(".", "-")}',
                'management_ip': ip, 'kind': kind, 'location': fields} for ip in ips])
    except (ValueError, TypeError):
        return None


def authorized_input(investigation, arguments=None, *, db=None):
    if (not investigation.requested_by_principal_id or investigation.workflow_snapshot
            or investigation.skill_artifact_version_id or investigation.situation_id
            or not permission_snapshot_allows(investigation, ['assets.read', 'assets.write'])):
        raise PermissionError('Direct enrollment requires an explicit initiating operator and inventory permissions')
    if db is not None:
        operator = db.get(ControlPlanePrincipal, investigation.requested_by_principal_id)
        if operator is None or not operator.enabled or operator.principal_type != 'user':
            raise PermissionError('Direct enrollment requires an enabled initiating human operator')
        snapshot = investigation.agent_profile_snapshot or {}
        if snapshot:
            from ..models import AgentProfile
            from .agent_profiles import agent_profile_snapshot
            current = db.get(AgentProfile, investigation.agent_profile_id)
            if current is None or not current.enabled or agent_profile_snapshot(current) != snapshot:
                raise PermissionError('Investigation AgentProfile changed; create a fresh request')
        if snapshot.get('tool_policy') == 'allowlist' and TOOL not in snapshot.get('allowed_tool_names', []):
            raise PermissionError('AgentProfile does not allow device enrollment')
    payload = explicit_input(investigation.objective)
    if payload is None:
        raise PermissionError('No explicit bounded Add/Enroll request authorizes this enrollment')
    if arguments is not None and OnboardingInput.model_validate(arguments) != payload:
        raise PermissionError('Enrollment arguments must exactly match the original operator request')
    require_site_access(investigation_principal(investigation), payload.site)
    return payload


def receipt_key(investigation, payload):
    return hashlib.sha256(json.dumps({'contract': CONTRACT, 'investigation': investigation.id,
        'input': payload.model_dump()}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def retained_receipt(db, investigation, payload):
    return db.scalar(select(DeviceOnboardingReceipt).where(
        DeviceOnboardingReceipt.preview_hash == receipt_key(investigation, payload)))


def enrollment_result(db, investigation, payload, receipt, *, replayed=False):
    principal = investigation_principal(investigation)
    devices = db.scalars(select(Device).where(device_scope_clause(principal), Device.id.in_(receipt.device_ids))).all()
    if len(devices) != len(receipt.device_ids) or sorted(d.management_ip for d in devices) != sorted(t.management_ip for t in payload.devices):
        raise PermissionError('Committed enrollment receipt is not visible or no longer matches its targets')
    return {'contract': CONTRACT, 'device_ids': receipt.device_ids, 'replayed': replayed,
        'site': payload.site, 'inventory_url': '/assets/devices', 'verification_pending': True,
        'devices': [{'id': d.id, 'name': d.name, 'management_ip': d.management_ip,
            'site': d.site, 'location': d.location, 'onboarding_status': d.onboarding_status} for d in devices],
        'monitoring': 'Monitoring methods are saved. Managed SNMP monitoring becomes eligible after successful verification; other credentials require compatible Collector/gateway custody. Current authority is shown under Manage.'}


def enroll(db, investigation, arguments):
    payload = authorized_input(investigation, arguments, db=db)
    p = profile(db, payload.credential_profile_ref, lock=True)
    if p is None:
        raise ValueError('Saved device credential profile was not found')
    receipt = retained_receipt(db, investigation, payload)
    if receipt:
        return enrollment_result(db, investigation, payload, receipt, replayed=True)
    plan = preview(db, payload, investigation_principal(investigation))
    if plan['blockers']:
        raise ValueError(plan['blockers'][0])
    managed = db.scalar(select(ManagedDeviceCredential).where(ManagedDeviceCredential.credential_profile_id == p.id))
    devices = []
    for target in payload.devices:
        device = onboard_device(db, DeviceOnboardCreate(**target.model_dump(), site=payload.site,
            created_by=investigation.created_by, request_monitoring=True, connections=[DeviceConnectionInput(protocol=payload.protocol,
                port=payload.port, credential_profile_ref=p.id, configuration={'modules': payload.modules})]), commit=False)
        devices.append(device)
    receipt = DeviceOnboardingReceipt(preview_hash=receipt_key(investigation, payload), actor=investigation.created_by,
        device_ids=[d.id for d in devices])
    db.add(receipt); db.flush()
    record_audit_event(db, event_type='device.conversational_enrollment.committed', actor_type='user',
        actor_id=investigation.created_by, entity_type='investigation', entity_id=investigation.id,
        details={'device_ids': receipt.device_ids, 'site': payload.site, 'monitoring_requested': bool(managed and managed.kind == 'snmp_v2c'),
            'workflow': 'explicit-device-enrollment/v1', 'credential_revision': p.revision})
    result = enrollment_result(db, investigation, payload, receipt)
    if not managed or managed.kind != 'snmp_v2c':
        result['monitoring'] = 'Device and monitoring method saved; continuous collection requires compatible Collector/gateway custody.'
    # Caller completes the owned Tool journal and commits in the same transaction.
    return result


def deterministic_decision(db, investigation, state):
    if investigation.workflow_snapshot or investigation.skill_artifact_version_id or explicit_input(investigation.objective) is None:
        return None
    try:
        payload = authorized_input(investigation, db=db)
        calls = state.get('tool_results', [])
        enrollment_calls = [c for c in calls if c.get('tool_name') == TOOL]
        if enrollment_calls:
            last = enrollment_calls[-1]
            if last.get('status') != 'succeeded':
                return GraphDecision(action='escalate', escalation_reason=last.get('error') or 'Device enrollment failed; no success receipt')
            receipt = retained_receipt(db, investigation, payload)
            if receipt is None:
                return GraphDecision(action='escalate', escalation_reason='Enrollment did not commit a device receipt')
            result = enrollment_result(db, investigation, payload, receipt)
            return GraphDecision(action='complete', conclusion=f"Added {len(result['device_ids'])} device(s) to Device inventory. Collector verification is pending; live monitoring is not yet confirmed.", structured_output=result)
        from ..models import AgentToolRegistration
        tool = db.scalar(select(AgentToolRegistration).where(AgentToolRegistration.name == TOOL))
        if tool is None or not tool.enabled or tool.handler != TOOL:
            return GraphDecision(action='escalate', escalation_reason='Direct enrollment Tool is unavailable; no device was added')
        return GraphDecision(action='continue', plan=['Validate exact request and saved credential', 'Commit device inventory and monitoring intent', 'Collector verifies SNMP asynchronously'],
            tool_requests=[GraphToolRequest(tool_name=TOOL, arguments=payload.model_dump(), purpose='Execute the exact initiating operator Add request')])
    except (ValueError, PermissionError, HTTPException) as exc:
        if isinstance(exc, HTTPException):
            return GraphDecision(action='escalate', escalation_reason=str(exc.detail))
        return GraphDecision(action='escalate', escalation_reason=str(exc))
