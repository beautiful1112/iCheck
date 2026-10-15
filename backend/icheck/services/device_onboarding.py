"""Pure AI onboarding previews; atomic, idempotent, human-only inventory approval."""
import hashlib
import ipaddress
import json
import re
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from ..device_schemas import DeviceConnectionInput, DeviceOnboardCreate
from ..models import CredentialProfile, Device, DeviceOnboardingReceipt
from ..onboarding_schemas import OnboardingInput
from .authorization_scope import device_scope_clause, require_site_access
from .audit import record_audit_event
from .devices import _connection_values, onboard_device
from .device_credentials import profile

CONTRACT = "icheck.device-onboarding-preview/v1"


def preview(db, payload, principal):
    require_site_access(principal, payload.site)
    p = profile(db, payload.credential_profile_ref)
    if p is None or not p.enabled or p.provider == "managed_ai":
        raise ValueError("Select an enabled device credential profile")
    if payload.site and p.worker_selector.get("site") not in {None, payload.site}:
        raise ValueError("Credential profile site does not match onboarding site")
    connection = DeviceConnectionInput(protocol=payload.protocol, port=payload.port,
        credential_profile_ref=p.id, configuration={"modules": payload.modules} if payload.protocol == "snmp" else {})
    _connection_values(db, connection, site=payload.site, actor=principal.subject)
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) for name in payload.modules):
        raise ValueError("Invalid SNMP module name")
    names, ips = [d.name for d in payload.devices], [d.management_ip for d in payload.devices]
    if len(set(names)) != len(names) or len(set(ips)) != len(ips):
        raise ValueError("The plan contains duplicate names or addresses")
    for ip in ips:
        address = ipaddress.ip_address(ip)
        if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
            raise ValueError("Onboarding targets must be unicast management addresses")
    canonical = payload.model_dump()
    canonical["credential_profile_ref"] = p.id
    binding = {"tenant": principal.tenant_id, "region": principal.region_id, "actor": principal.subject,
               "input": canonical, "credential_revision": p.revision, "credential_selector": p.worker_selector}
    digest = hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    conflicts = db.scalars(select(Device).where(or_(Device.name.in_(names), Device.management_ip.in_(ips)))).all()
    receipt = db.scalar(select(DeviceOnboardingReceipt).where(DeviceOnboardingReceipt.preview_hash == digest))
    blockers = ["A device name or IP already exists; revise the plan"] if conflicts and receipt is None else []
    return {"contract": CONTRACT, "preview_hash": digest, "input": canonical, "credential_name": p.name,
            "credential_revision": p.revision, "blockers": blockers, "requires_human_approval": True,
            "warnings": ["Saving starts bounded Collector preflight, not monitoring activation.",
                "Collector and gateway network allowlists still apply; this plan does not expand them.",
                "SSH, HTTPS API and Windows preflight verifies transport only; approved collectors and trust are separate."],
            "approval_url": "/assets/devices", "approved_device_ids": receipt.device_ids if receipt else []}


def approve(db, payload, principal):
    # Lock profile first: credential rotation cannot race snapshot validation.
    p = profile(db, payload.credential_profile_ref, lock=True)
    if p is None:
        raise ValueError("Credential profile is unavailable")
    plan = preview(db, OnboardingInput.model_validate(payload.model_dump(exclude={"preview_hash", "reason"})), principal)
    if plan["preview_hash"] != payload.preview_hash:
        raise ValueError("Plan or credential changed; request a fresh preview")
    if plan["approved_device_ids"]:
        return {"device_ids": plan["approved_device_ids"], "replayed": True}
    if plan["blockers"]:
        raise ValueError(plan["blockers"][0])
    try:
        created = [onboard_device(db, DeviceOnboardCreate(**target.model_dump(), site=payload.site,
            created_by=principal.subject, connections=[DeviceConnectionInput(protocol=payload.protocol,
                port=payload.port, credential_profile_ref=p.id,
                configuration={"modules": payload.modules} if payload.protocol == "snmp" else {})]), commit=False)
            for target in payload.devices]
        ids = [device.id for device in created]
        db.add(DeviceOnboardingReceipt(preview_hash=plan["preview_hash"], actor=principal.subject, device_ids=ids))
        record_audit_event(db, event_type="device.onboarding_plan.approved", actor_type="user", actor_id=principal.subject,
            entity_type="device_onboarding", entity_id=plan["preview_hash"],
            details={"preview_hash": plan["preview_hash"], "device_ids": ids, "reason": payload.reason})
        db.commit()
    except (IntegrityError, ValueError):
        db.rollback()
        raise ValueError("Device inventory changed; refresh the plan before approval") from None
    return {"device_ids": ids, "replayed": False}


def list_for_ai(db, arguments, principal):
    site = arguments.get("site") or None
    require_site_access(principal, site)
    rows = db.scalars(select(CredentialProfile).where(CredentialProfile.enabled.is_(True),
        CredentialProfile.provider != "managed_ai").order_by(CredentialProfile.name).limit(200)).all()
    items = [{"id": p.id, "name": p.name, "allowed_adapters": p.allowed_adapters,
              "site": p.worker_selector.get("site"),
              "snmp_modules": ["if_mib", "system"] if "snmp_exporter" in p.allowed_adapters else [],
              "module_note": "allowed_adapters are permissions, NOT exporter module names"} for p in rows
             if not site or not p.worker_selector or p.worker_selector == {"site": site}]
    return {"profiles": items}, []


def preview_for_ai(db, arguments, principal):
    return preview(db, OnboardingInput.model_validate(arguments), principal), []


def find_for_ai(db, arguments, principal):
    from ..schemas import normalize_ip
    from .agent_tools import _get_device
    site = arguments.get("site") or None
    require_site_access(principal, site)
    addresses = [normalize_ip(ip) for ip in arguments["management_ips"]]
    query = select(Device).where(device_scope_clause(principal), Device.management_ip.in_(addresses))
    if site:
        query = query.where(Device.site == site)
    rows = db.scalars(query.order_by(Device.name).limit(50)).all()
    results, evidence = [], []
    for row in rows:
        result, refs = _get_device(db, {"device_id": row.id}, principal)
        results.append(result); evidence.extend(refs)
    return {"devices": results, "missing_addresses": sorted(set(addresses) - {row.management_ip for row in rows})}, evidence
