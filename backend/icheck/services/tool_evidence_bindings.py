"""Exact-call citations: no investigation-wide guessing on result recovery."""
from datetime import UTC

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import InvestigationEvidence, InvestigationToolCall, InvestigationToolEvidenceBinding


def _timestamp(value):
    return None if value is None else value.replace(tzinfo=value.tzinfo or UTC).astimezone(UTC).isoformat()


def _reference(evidence):
    from .agent_runtime import _canonical_hash
    return {"id": evidence.id, "evidence_type": evidence.evidence_type,
        "evidence_id": evidence.evidence_id, "observed_at": _timestamp(evidence.observed_at),
        "created_at": _timestamp(evidence.created_at), "summary_hash": _canonical_hash(evidence.summary)}


def _call_snapshot(call):
    from .agent_runtime import _canonical_hash
    return {"tool_id": call.tool_id, "call_hash": call.call_hash,
        "arguments_hash": _canonical_hash(call.arguments), "result_hash": call.result_hash,
        "finished_at": _timestamp(call.finished_at)}


def bind_tool_evidence(db: Session, call: InvestigationToolCall, evidence_ids: list[str]):
    """Add before completion commit; never backfill uncertain historical calls."""
    if (call.status != "succeeded" or call.result_hash is None
        or len(evidence_ids) > 100 or len(evidence_ids) != len(set(evidence_ids))
        or any(not isinstance(value, str) or not 1 <= len(value) <= 36 for value in evidence_ids)):
        raise ValueError("Tool citation binding requires a terminal result and bounded unique references")
    rows = {row.id: row for row in db.scalars(select(InvestigationEvidence).where(
        InvestigationEvidence.id.in_(evidence_ids),
        InvestigationEvidence.investigation_id == call.investigation_id,
        InvestigationEvidence.tenant_id == call.tenant_id,
        InvestigationEvidence.region_id == call.region_id,
    ))}
    if len(rows) != len(evidence_ids):
        raise ValueError("Tool citation does not belong to this exact investigation and namespace")
    binding = InvestigationToolEvidenceBinding(investigation_id=call.investigation_id,
        tool_call_id=call.id, tenant_id=call.tenant_id, region_id=call.region_id,
        call_snapshot=_call_snapshot(call), reference_snapshot=[_reference(rows[value]) for value in evidence_ids])
    db.add(binding)
    db.flush()
    return binding


def recorded_tool_evidence_ids(db: Session, call: InvestigationToolCall) -> list[str] | None:
    """None means unbound/legacy; [] means a recorded result with no citations."""
    from .agent_runtime import _canonical_hash
    binding = db.scalar(select(InvestigationToolEvidenceBinding).where(
        InvestigationToolEvidenceBinding.tool_call_id == call.id,
        InvestigationToolEvidenceBinding.investigation_id == call.investigation_id,
        InvestigationToolEvidenceBinding.tenant_id == call.tenant_id,
        InvestigationToolEvidenceBinding.region_id == call.region_id,
    ))
    if binding is None:
        return None
    if (call.status != "succeeded" or call.result_hash != _canonical_hash(call.result)
        or binding.call_snapshot != _call_snapshot(call)
        or not isinstance(binding.reference_snapshot, list) or len(binding.reference_snapshot) > 100):
        raise ValueError("Recorded Tool citation binding no longer matches its terminal result")
    ids = [value["id"] for value in binding.reference_snapshot]
    if len(ids) != len(set(ids)):
        raise ValueError("Recorded Tool citation binding contains duplicate references")
    rows = {row.id: row for row in db.scalars(select(InvestigationEvidence).where(
        InvestigationEvidence.id.in_(ids), InvestigationEvidence.investigation_id == call.investigation_id,
        InvestigationEvidence.tenant_id == call.tenant_id, InvestigationEvidence.region_id == call.region_id))}
    if len(rows) != len(ids) or any(_reference(rows[value["id"]]) != value for value in binding.reference_snapshot):
        raise ValueError("Recorded Tool citation identity has drifted")
    return ids
