"""Runtime-owned proposal/cutover identities and retained-result authorization."""
from fastapi import HTTPException
from sqlalchemy import select, literal, or_, exists

from ..database import session_namespace
from ..models import (AgentToolRegistration, InvestigationToolCall,
    CollectorConditionSource, CollectorSourceReplacementRequest, CollectorSourceRetirement)
from ..source_replacement_schemas import (SourceReplacementCreate, SourceReplacementProposalToolInput,
    SourceReplacementRequestRead, SourceReplacementApplyToolInput, SourceReplacementApply,
    SourceReplacementDetailRead, SourceRetirementRead, SourceReplacementReadToolInput)
from .agent_authorization import investigation_principal, assert_source_replacement_tool_contract
from .alert_conditions import as_utc
from .collector_conditions import canonical
from .source_qualifications import _row
from .source_replacements import _namespace_query, _scope, propose_source_replacement, source_replacement_detail
from .source_retirements import apply_source_replacement, read_source_retirement

PROPOSAL_PREFIX = "agent-replacement-proposal:"
APPLY_PREFIX = "agent-replacement-apply:"


def replacement_call_records(db, call):
    """Immutable domain identities survive mutable Tool registry changes."""
    namespace = session_namespace(db)
    call_namespace = call.tenant_id, call.region_id
    if namespace is not None and namespace != call_namespace:
        raise LookupError("Replacement Tool call is outside the selected namespace")
    # Some legacy development-only generic Tool completions have no selected
    # namespace. This ownership probe is restricted to the persisted call's
    # exact namespace; it never returns domain material or bypasses native RLS.
    proposal = db.scalar(select(CollectorSourceReplacementRequest).where(
        CollectorSourceReplacementRequest.tenant_id == call.tenant_id,
        CollectorSourceReplacementRequest.region_id == call.region_id,
        CollectorSourceReplacementRequest.request_key == PROPOSAL_PREFIX + call.id))
    retirement = db.scalar(select(CollectorSourceRetirement).where(
        CollectorSourceRetirement.tenant_id == call.tenant_id,
        CollectorSourceRetirement.region_id == call.region_id,
        CollectorSourceRetirement.execution_key == APPLY_PREFIX + call.id))
    return proposal, retirement


def assert_replacement_graph_result(db, investigation, request, result):
    """A completed delegated checkpoint must retain its exact journal/citations.

    Checkpoints are not domain receipts. Do not replay execution or refresh old
    peer/origin validity; scope and immutable ledger equality are still required.
    """
    from .agent_authorization import SOURCE_REPLACEMENT_HANDLERS
    from .tool_evidence_bindings import recorded_tool_evidence_ids
    call = _row(db, InvestigationToolCall, result.call_id)
    proposal, retirement = replacement_call_records(db, call)
    value = result.result
    replacement_shape = isinstance(value, dict) and (
        value.get("protocol") == "icheck.collector.source-retirement/v1"
        or isinstance(value.get("snapshot"), dict) and value["snapshot"].get("protocol") == "icheck.collector.source-replacement/v1"
        or isinstance(value.get("request"), dict) and isinstance(value["request"].get("snapshot"), dict)
        and value["request"]["snapshot"].get("protocol") == "icheck.collector.source-replacement/v1")
    tool = _row(db, AgentToolRegistration, call.tool_id)
    if not (proposal or retirement or replacement_shape or request.tool_name in SOURCE_REPLACEMENT_HANDLERS
        or tool.handler in SOURCE_REPLACEMENT_HANDLERS):
        return
    if (call.investigation_id != investigation.id or tool.name != request.tool_name
        or result.tool_name != request.tool_name or call.arguments != request.arguments
        or result.arguments != request.arguments or result.status != call.status
        or canonical(value) != canonical(call.result) or result.error != call.error
        or result.auxiliary_call_ids or result.governance is not None):
        raise ValueError("Delegated replacement result differs from its exact retained Tool journal")
    if call.status == "succeeded":
        evidence_ids = recorded_tool_evidence_ids(db, call)
        if evidence_ids is None or result.evidence_ids != evidence_ids:
            raise ValueError("Delegated replacement citations differ from the exact retained Tool binding")
    elif result.evidence_ids:
        raise ValueError("A failed replacement result cannot claim unbound evidence")
    actor = investigation_principal(investigation)
    if not investigation_replacements_visible(db, investigation, actor):
        raise LookupError("Delegated replacement history is unavailable in the current initiating scope")


def _call_principal(db, investigation, call, arguments):
    persisted = _row(db, InvestigationToolCall, call.id)
    tool = _row(db, AgentToolRegistration, persisted.tool_id)
    assert_source_replacement_tool_contract(tool)
    if (persisted.investigation_id != investigation.id or persisted.arguments != arguments
        or persisted.status not in {"running", "succeeded"}
        or (investigation.tenant_id, investigation.region_id) != session_namespace(db)):
        raise PermissionError("Source replacement does not bind this exact runtime journal and namespace")
    actor = investigation_principal(investigation)
    if not actor.principal_id:
        raise PermissionError("Source replacement requires a persisted initiating principal")
    return tool, actor


def replacement_from_agent_call(db, investigation, call, arguments):
    tool, actor = _call_principal(db, investigation, call, arguments)
    if tool.handler == "collector_sources.propose_replacement":
        payload = SourceReplacementProposalToolInput.model_validate(arguments)
        key = PROPOSAL_PREFIX + call.id
        previous = db.scalar(_namespace_query(db, CollectorSourceReplacementRequest).where(
            CollectorSourceReplacementRequest.request_key == key))
        if previous:
            if (previous.author_principal_id != actor.principal_id or previous.author_subject != actor.subject
                or as_utc(previous.expires_at) != as_utc(payload.expires_at)
                or any(canonical(getattr(previous, field)) != canonical(value)
                    for field, value in payload.model_dump(exclude={"expires_at"}).items())):
                raise ValueError("Replacement proposal journal differs from its immutable intent")
            source_replacement_detail(db, previous.id, actor)
            result = SourceReplacementRequestRead.model_validate(previous)
        else:
            values = SourceReplacementCreate(**payload.model_dump(), request_key=key)
            result = SourceReplacementRequestRead.model_validate(propose_source_replacement(db, values, actor))
    elif tool.handler == "collector_sources.apply_reviewed_replacement":
        payload = SourceReplacementApplyToolInput.model_validate(arguments)
        values = SourceReplacementApply(execution_key=APPLY_PREFIX + call.id, reason=payload.reason)
        result = apply_source_replacement(db, payload.request_id, values, actor)
    else:
        raise PermissionError("Only an owned replacement write handler can execute this journal")
    # The immutable domain result commits before Tool completion. A restarted
    # runtime recovers the exact result before attempting any fresh operation.
    db.commit()
    return result


def replacement_tool_scope(db, investigation, handler, arguments):
    actor = investigation_principal(investigation)
    if handler == "collector_sources.propose_replacement":
        payload = SourceReplacementProposalToolInput.model_validate(arguments)
        ids = [payload.old_source_id, payload.new_source_id]
    else:
        payload = (SourceReplacementApplyToolInput if handler.endswith("apply_reviewed_replacement")
            else SourceReplacementReadToolInput).model_validate(arguments)
        request = _row(db, CollectorSourceReplacementRequest, payload.request_id)
        ids = [request.old_source_id, request.new_source_id]
    _scope(db, [_row(db, CollectorConditionSource, identity) for identity in ids], actor)


def investigation_replacements_visible(db, investigation, requested):
    """Immutable keys, not a mutable handler, identify owned retained results."""
    namespace = session_namespace(db)
    if namespace is None: return False
    t, r = namespace
    owned_proposal = exists(select(CollectorSourceReplacementRequest.id).where(
        CollectorSourceReplacementRequest.tenant_id == t, CollectorSourceReplacementRequest.region_id == r,
        CollectorSourceReplacementRequest.request_key == literal(PROPOSAL_PREFIX) + InvestigationToolCall.id))
    owned_retirement = exists(select(CollectorSourceRetirement.id).where(
        CollectorSourceRetirement.tenant_id == t, CollectorSourceRetirement.region_id == r,
        CollectorSourceRetirement.execution_key == literal(APPLY_PREFIX) + InvestigationToolCall.id))
    call_ids = list(db.scalars(select(InvestigationToolCall.id).where(
        InvestigationToolCall.investigation_id == investigation.id,
        InvestigationToolCall.tenant_id == t, InvestigationToolCall.region_id == r,
        or_(owned_proposal, owned_retirement,
            InvestigationToolCall.result["request"]["snapshot"]["protocol"].as_string() == "icheck.collector.source-replacement/v1"))
        .order_by(InvestigationToolCall.id).limit(1001)))
    if len(call_ids)>1000: return False
    initiator = investigation_principal(investigation)
    try:
        for call_id in call_ids:
            call = _row(db, InvestigationToolCall, call_id)
            proposal, retirement = replacement_call_records(db, call)
            if proposal:
                for actor in (initiator, requested): source_replacement_detail(db, proposal.id, actor)
                if call.status == "succeeded" and canonical(call.result) != canonical(SourceReplacementRequestRead.model_validate(proposal).model_dump(mode="json")):
                    raise ValueError("Retained proposal result differs from its immutable request")
            if retirement:
                for actor in (initiator, requested): read_source_retirement(db, retirement.id, actor)
                if call.status == "succeeded":
                    retained = SourceRetirementRead.model_validate(call.result)
                    if retained != read_source_retirement(db, retirement.id, initiator):
                        raise ValueError("Retained cutover result differs from its immutable receipt")
            # Read-only get_replacement caches are also material reads. The
            # retained result supplies its identity even after registry edits.
            value = call.result
            if isinstance(value, dict) and isinstance(value.get("request"), dict):
                snapshot = value["request"].get("snapshot")
                if isinstance(snapshot, dict) and snapshot.get("protocol") == "icheck.collector.source-replacement/v1":
                    for actor in (initiator, requested): assert_retained_replacement_result(db, value, actor)
    except (LookupError, PermissionError, ValueError, HTTPException):
        return False
    return True


def assert_retained_replacement_result(db, value, actor, *, expected_request_id=None):
    retained = SourceReplacementDetailRead.model_validate(value)
    if expected_request_id is not None and retained.request.id != expected_request_id:
        raise ValueError("Retained replacement Tool result belongs to another request")
    detail = source_replacement_detail(db, retained.request.id, actor)
    if retained.request != detail.request or (retained.review is not None and retained.review != detail.review) or (
        retained.revocation is not None and retained.revocation != detail.revocation):
        raise ValueError("Retained replacement material differs from immutable history")
    if retained.producer_cutover_performed != (retained.retirement_id is not None):
        raise ValueError("Retained replacement cutover pointer is incomplete")
    if retained.retirement_id:
        receipt = read_source_retirement(db, retained.retirement_id, actor)
        if receipt.request_id != retained.request.id:
            raise ValueError("Retained replacement cutover belongs to another request")
    return retained
