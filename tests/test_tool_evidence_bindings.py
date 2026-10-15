"""Generic references commit with a result and cannot be borrowed on replay."""
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from icheck.agent_schemas import InvestigationEvidenceCreate, InvestigationToolCallCreate, InvestigationToolCallComplete
from icheck.database import SessionLocal
from icheck.models import AuditEvent, Investigation, InvestigationEvidence, InvestigationToolCall, InvestigationToolEvidenceBinding, utcnow
from icheck.services.agent_runtime import add_evidence_reference, create_tool_call, complete_tool_call
from icheck.services.tool_evidence_bindings import recorded_tool_evidence_ids
from test_agent_approvals import _configure_route, _start_investigation

session = SessionLocal


def _register_tool(client, *, name, read_only, input_schema, output_schema):
    response = client.post(
        "/api/v1/agent/tools",
        json={
            "name": name,
            "description": f"Evidence binding Tool {name}",
            "transport": "internal",
            "handler": name,
            "input_schema": input_schema,
            "output_schema": output_schema,
            "risk_level": "observe" if read_only else "change",
            "read_only": read_only,
            "required_permissions": [],
            "created_by": "platform.admin",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def binding_case(client):
    _configure_route(client)
    tool = _register_tool(client, name="test.citations.read", read_only=True,
        input_schema={"type": "object"}, output_schema={"type": "object"})
    investigation_id = _start_investigation(client)
    with session() as db:
        investigation = db.get(Investigation, investigation_id)
        evidence = add_evidence_reference(db, investigation, InvestigationEvidenceCreate(
            evidence_type="controlled_observation", evidence_id="exact-source", summary="Controlled result evidence", observed_at=utcnow()))
        call = create_tool_call(db, investigation, InvestigationToolCallCreate(tool_id=tool["id"],
            iteration=1, arguments={"selector": "exact"}))
    return investigation_id, call.id, evidence.id


def finish(db, call_id, refs):
    return complete_tool_call(db, db.get(InvestigationToolCall, call_id),
        InvestigationToolCallComplete(status="succeeded", result={"ok": True}), evidence_ids=refs)


def test_exact_generic_binding_recovers_without_inventing_other_references(client):
    investigation_id, call_id, evidence_id = binding_case(client)
    with session() as db:
        call = finish(db, call_id, [evidence_id])
        add_evidence_reference(db, db.get(Investigation, investigation_id), InvestigationEvidenceCreate(
            evidence_type="controlled_observation", evidence_id="unrelated-source", summary="Must not be borrowed"))
        assert recorded_tool_evidence_ids(db, call) == [evidence_id]
        binding = db.scalar(select(InvestigationToolEvidenceBinding).where(InvestigationToolEvidenceBinding.tool_call_id == call_id))
        assert "summary" not in binding.reference_snapshot[0]
        assert len(binding.reference_snapshot[0]["summary_hash"]) == 64


@pytest.mark.parametrize("refs", [None, []])
def test_unbound_and_explicitly_empty_results_are_distinct(client, refs):
    _, call_id, _ = binding_case(client)
    with session() as db:
        assert recorded_tool_evidence_ids(db, finish(db, call_id, refs)) == refs


@pytest.mark.parametrize("field", ["arguments", "result", "result_hash", "evidence_id", "summary", "observed_at", "deleted"])
def test_result_or_reference_drift_never_synthesizes_replay_citations(client, field):
    _, call_id, evidence_id = binding_case(client)
    with session() as db:
        call = finish(db, call_id, [evidence_id])
        evidence = db.get(InvestigationEvidence, evidence_id)
        if field == "arguments": call.arguments = {"selector": "different"}
        elif field == "result": call.result = {"ok": False}
        elif field == "result_hash": call.result_hash = "f"*64
        elif field == "deleted": db.delete(evidence)
        elif field == "observed_at": evidence.observed_at = utcnow()+timedelta(minutes=1)
        else: setattr(evidence, field, "Changed source identity or summary")
        db.commit()
        with pytest.raises(ValueError, match="drifted|no longer matches"):
            recorded_tool_evidence_ids(db, call)


@pytest.mark.parametrize("invalid", ["foreign_investigation", "duplicate", "missing"])
def test_invalid_binding_rolls_back_result_and_completion_audit(client, invalid):
    _, call_id, evidence_id = binding_case(client)
    with session() as db:
        if invalid == "foreign_investigation":
            other = _start_investigation(client)
            foreign = add_evidence_reference(db, db.get(Investigation, other), InvestigationEvidenceCreate(
                evidence_type="controlled_observation", evidence_id="foreign-source", summary="Other investigation"))
            refs = [foreign.id]
        else:
            refs = [evidence_id, evidence_id] if invalid == "duplicate" else ["missing-reference"]
        with pytest.raises(ValueError, match="namespace|bounded unique"):
            finish(db, call_id, refs)
        assert db.get(InvestigationToolCall, call_id).status == "running"
        assert db.scalar(select(func.count()).select_from(InvestigationToolEvidenceBinding)) == 0
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(
            AuditEvent.event_type == "investigation.tool.completed", AuditEvent.entity_id == call_id)) == 0
        assert recorded_tool_evidence_ids(db, finish(db, call_id, [evidence_id])) == [evidence_id]
