"""Owned closure journals retain domain facts, never new execution authority."""
from sqlalchemy import select

from ..database import session_namespace
from ..models import (AgentToolRegistration, Investigation, InvestigationEvidence,
    InvestigationToolCall, SituationClosureGrant, SituationClosureReceipt, SituationClosureRequest)
from ..situation_closure_schemas import SituationClosureToolInput
from .agent_authorization import investigation_principal
from .collector_conditions import canonical
from .source_qualifications import _row

OWNED_PREFIX = "agent-closure:"
OWNED_TOOL_NAMES = frozenset({"situations.close_reviewed", "situations.close_reviewed_v2"})


def owned_closure_request_id(db, call):
    """Probe metadata only, including when the current handler was edited.

    Generic legacy completion may lack a selected namespace. That probe remains
    confined to the persisted call's exact namespace and returns no proof.
    Request keys are unique per Situation, so ambiguity must fail closed.
    """
    namespace = session_namespace(db)
    if namespace is not None and namespace != (call.tenant_id, call.region_id):
        raise LookupError("Closure Tool journal is outside the selected namespace")
    ids = list(db.scalars(select(SituationClosureRequest.id).where(
        SituationClosureRequest.tenant_id == call.tenant_id,
        SituationClosureRequest.region_id == call.region_id,
        SituationClosureRequest.request_key == OWNED_PREFIX + call.id).limit(2)))
    if len(ids) > 1:
        raise ValueError("Closure Tool ownership is ambiguous")
    return ids[0] if ids else None


def _owned_receipt(db, investigation, call, request_id):
    from .situation_closure import _owned_request
    from .situation_closure_reads import read_receipt
    if request_id is None or call.investigation_id != investigation.id:
        raise ValueError("Closure result requires its exact owned journal and request")
    receipt = db.scalar(select(SituationClosureReceipt).where(
        SituationClosureReceipt.request_id == request_id,
        SituationClosureReceipt.tenant_id == call.tenant_id,
        SituationClosureReceipt.region_id == call.region_id))
    if receipt is None:
        raise ValueError("Closure journal cannot complete before its durable receipt")
    actor = investigation_principal(investigation)
    request, _ = _owned_request(db, request_id, actor)
    intent = SituationClosureToolInput.model_validate(call.arguments)
    grant = _row(db, SituationClosureGrant, request.grant_id)
    if ((intent.situation_id, intent.grant_id, intent.reason, intent.proof_version) !=
        (request.situation_id, request.grant_id, request.reason, grant.proof_version)
        or investigation.situation_id != request.situation_id):
        raise ValueError("Closure journal intent differs from its exact immutable request")
    return read_receipt(db, receipt, actor)


def assert_owned_closure_completion(db, call, payload, evidence_ids):
    """Only the owned runtime may atomically record the exact receipt/citation."""
    investigation = _row(db, Investigation, call.investigation_id)
    receipt = _owned_receipt(db, investigation, call, owned_closure_request_id(db, call))
    if (payload.status != "succeeded" or payload.error is not None
        or canonical(payload.result) != canonical(receipt.model_dump(mode="json"))):
        raise ValueError("Closure Tool completion differs from its immutable receipt")
    assert_closure_citations(db, call, receipt, evidence_ids)


def assert_closure_citations(db, call, receipt, evidence_ids):
    if not isinstance(evidence_ids, list) or len(evidence_ids) != 1:
        raise ValueError("Closure Tool completion requires its exact receipt citation")
    evidence = _row(db, InvestigationEvidence, evidence_ids[0])
    if (evidence.investigation_id != call.investigation_id or evidence.evidence_type != "situation_closure_receipt"
        or evidence.evidence_id != receipt.id):
        raise ValueError("Closure citation does not bind this exact owned receipt")


def assert_closure_graph_result(db, investigation, request, result):
    """A cached Task cannot substitute a receipt, journal or evidence binding."""
    from .tool_evidence_bindings import recorded_tool_evidence_ids
    call = _row(db, InvestigationToolCall, result.call_id)
    request_id = owned_closure_request_id(db, call)
    tool = _row(db, AgentToolRegistration, call.tool_id)
    value = result.result
    proof = value.get("proof") if isinstance(value, dict) else None
    closure_shape = isinstance(proof, dict) and proof.get("contract") in {
        "icheck.reviewed-situation-closure/v1", "icheck.reviewed-situation-closure/v2"}
    if not (request_id or tool.handler == "situations.close_reviewed"
        or request.tool_name in OWNED_TOOL_NAMES or closure_shape):
        return
    if (call.investigation_id != investigation.id or tool.name != request.tool_name
        or result.tool_name != request.tool_name or call.arguments != request.arguments
        or result.arguments != request.arguments or result.status != call.status
        or canonical(value) != canonical(call.result) or result.error != call.error
        or result.auxiliary_call_ids or result.governance is not None):
        raise ValueError("Delegated closure result differs from its exact retained Tool journal")
    if call.status != "succeeded":
        raise ValueError("Owned closure cannot claim a terminal result without its durable receipt")
    receipt = _owned_receipt(db, investigation, call, request_id)
    if canonical(value) != canonical(receipt.model_dump(mode="json")):
        raise ValueError("Delegated closure result differs from its immutable receipt")
    evidence_ids = recorded_tool_evidence_ids(db, call)
    if evidence_ids is None or result.evidence_ids != evidence_ids:
        raise ValueError("Delegated closure citations differ from the exact retained Tool binding")
    assert_closure_citations(db, call, receipt, evidence_ids)
