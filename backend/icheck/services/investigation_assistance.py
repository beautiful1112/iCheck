"""Capability discovery and saved handoffs, without installation or remote I/O."""
from dataclasses import replace

from fastapi import HTTPException
from sqlalchemy import select

from ..agent_schemas import InvestigationCreate
from ..autonomy_schemas import CapabilityDiscovery, CapabilityNeed, CapabilityNeedRead
from ..models import (Artifact, ArtifactKind, ArtifactVersion, ArtifactVersionStatus,
                      Investigation, InvestigationCapabilityRequest, InvestigationToolCall)
from .agent_authorization import investigation_principal
from .agent_runtime import create_investigation, start_investigation
from .authorization_scope import scope_contains
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .situation_closure_reads import investigation_receipts_visible


def visible_investigation(db, identifier, principal, *, lock=False):
    if lock:
        from ..database import require_locking_transaction
        require_locking_transaction(db, purpose="Investigation continuation")
    query = select(Investigation).where(Investigation.id == identifier)
    row = db.scalar(query.with_for_update() if lock else query)
    if row is None or not scope_contains(db, principal, row.authorization_scope) or not investigation_receipts_visible(db, row, principal):
        raise HTTPException(404, "Investigation not found")
    return row


def request_document(row):
    return CapabilityNeedRead.model_validate(dict(
        id=row.id, investigation_id=row.investigation_id, kind=row.kind,
        description=row.description, reason=row.reason, suggested_tools=row.suggested_tools,
        created_at=row.created_at, studio_session_id=row.studio_session_id,
        studio_url=f"/studio/builder?capability_request={row.id}" + (f"&session={row.studio_session_id}" if row.studio_session_id else "")))


def save_request(db, investigation, payload: CapabilityNeed):
    assert_no_inline_secrets(payload.model_dump(), "capability_request")
    # The request is a control-plane draft, not a device operation or proof.
    from .capability_studio import _validate_authoring_text
    _validate_authoring_text(payload.description)
    _validate_authoring_text(payload.reason)
    db.execute(select(Investigation.id).where(Investigation.id == investigation.id).with_for_update())
    rows = list(db.scalars(select(InvestigationCapabilityRequest).where(
        InvestigationCapabilityRequest.investigation_id == investigation.id)))
    for row in rows:
        if row.kind == payload.kind and row.description == payload.description:
            return request_document(row)
    if len(rows) >= 10:
        raise ValueError("This investigation already has ten capability requests")
    row = InvestigationCapabilityRequest(investigation_id=investigation.id, **payload.model_dump())
    db.add(row)
    db.flush()
    record_audit_event(db, event_type="investigation.capability_requested", actor_type="agent",
        actor_id=investigation.created_by, entity_type="investigation", entity_id=investigation.id,
        details={"request_id": row.id, "kind": row.kind, "installation_authorized": False})
    db.commit()
    return request_document(row)


def discover(db, investigation, payload: CapabilityDiscovery):
    from .model_reasoner import OpenAICompatibleReasoner
    from .research import status
    # This constructor filters current tools through the same profile, Skill,
    # MCP availability, read-only and permission gates as the reasoner. No I/O.
    reasoner = OpenAICompatibleReasoner(db, investigation)
    query = payload.query.casefold().strip()
    tools = [tool for tool in reasoner.tool_catalog
             if not query or query in (tool["name"] + " " + tool["description"]).casefold()]
    principal = investigation_principal(investigation)
    artifacts = []
    if principal.permits("capabilities.read"):
        rows = db.execute(select(Artifact, ArtifactVersion).join(ArtifactVersion).where(
            Artifact.kind.in_([ArtifactKind.SKILL, ArtifactKind.WORKFLOW]),
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED).order_by(Artifact.name, ArtifactVersion.version.desc()).limit(101)).all()
        seen = set()
        for artifact, version in rows:
            if artifact.id in seen:
                continue
            seen.add(artifact.id)
            if query and query not in (artifact.name + " " + artifact.description).casefold():
                continue
            artifacts.append({"name": artifact.name, "kind": artifact.kind.value, "version_id": version.id,
                "description": artifact.description[:1000], "published_not_executed": True,
                "review_url": f"/studio/artifacts?artifact={artifact.id}"})
    return dict(tools=tools[:50], reusable_capabilities=artifacts[:20], research=status(db),
        truncated=len(tools) > 50 or len(artifacts) > 20,
        checks=["Tool permissions, execution mode and installed MCP availability checked",
                "Discover target identity with inventory.find_devices before device-specific calls",
                "Check saved connection readiness; never request raw credentials",
                "Check observation timestamps; catalog availability is not a live connection test",
                "Published workflows require their existing runtime authorization and change approvals"])


def followup(db, previous, payload, principal):
    if previous.status in {"pending", "running", "waiting_approval"}:
        raise ValueError("Wait for this run to finish or cancel it before continuing")
    assert_no_inline_secrets({"message": payload.message}, "investigation_followup")
    active = db.scalar(select(Investigation).where(Investigation.parent_investigation_id == previous.id,
        Investigation.status.in_(["pending", "running", "waiting_approval"])).limit(1))
    if active is not None:
        if active.objective == payload.message and active.created_by == principal.subject:
            return active  # A retried submission must not create another paid run.
        raise ValueError("A continuation is already running; open that run before adding another question")
    if payload.request_id:
        request = db.get(InvestigationCapabilityRequest, payload.request_id)
        if request is None or request.investigation_id != previous.id:
            raise ValueError("Capability request does not belong to this investigation")
        if request.suggested_tools:
            from .model_reasoner import OpenAICompatibleReasoner
            available = {tool["name"] for tool in OpenAICompatibleReasoner(db, previous).tool_catalog}
            if not set(request.suggested_tools).issubset(available):
                raise ValueError("Requested tools are not yet available to this investigation; review Studio first")
    # Explicit continuation starts a new bounded execution, never mutates the
    # old graph, resets its counters, or inherits an old change approval.
    actor = replace(principal, authorization_scope=dict(previous.authorization_scope))
    created = create_investigation(db, InvestigationCreate(title=previous.title,
        objective=payload.message, execution_mode="diagnose", scope=dict(previous.scope),
        created_by=principal.subject), actor=actor, commit=False)
    created.parent_investigation_id = previous.id
    record_audit_event(db, event_type="investigation.continued", actor_type="user", actor_id=principal.subject,
        entity_type="investigation", entity_id=created.id,
        details={"previous_id": previous.id, "request_id": payload.request_id, "mode": "diagnose"})
    start_investigation(db, created, actor=principal.subject, commit=False)
    db.commit()
    return created


def continuation_context(db, investigation, allowed_tool_ids):
    """Bounded historical evidence; never transfer another actor's wider scope."""
    principal = investigation_principal(investigation)
    identifier = investigation.parent_investigation_id
    history = []
    seen = {investigation.id}
    remaining = 24000
    import json
    for _ in range(3):
        if not identifier or identifier in seen:
            break
        seen.add(identifier)
        parent = visible_investigation(db, identifier, principal)
        entry = dict(investigation_id=parent.id, objective=parent.objective[:4000],
            conclusion=(parent.conclusion or parent.escalation_reason or "")[:4000], historical=True,
            evidence=[])
        calls = db.scalars(select(InvestigationToolCall).where(
            InvestigationToolCall.investigation_id == parent.id,
            InvestigationToolCall.tool_id.in_(allowed_tool_ids),
            InvestigationToolCall.status == "succeeded").order_by(InvestigationToolCall.created_at.desc()).limit(6))
        for call in calls:
            item = dict(call_id=call.id, observed_at=call.finished_at.isoformat() if call.finished_at else None,
                        result=call.result)
            size = len(json.dumps(item).encode())
            if size <= 4000 and remaining >= size + 8500:
                entry["evidence"].append(item)
                remaining -= size
        remaining -= len(json.dumps({**entry, "evidence": []}).encode())
        if remaining < 0:
            break
        history.append(entry)
        identifier = parent.parent_investigation_id
    return history
