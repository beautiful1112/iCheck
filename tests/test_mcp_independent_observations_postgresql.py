"""Opt-in migrated, non-owner PostgreSQL acceptance for retained target evidence."""
from __future__ import annotations

import os
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from icheck.database import set_session_namespace
from icheck.models import (
    AIModelConfig, AIModelRoute, AIProviderConfig, AgentActionProposal,
    AgentToolRegistration, Artifact, ArtifactKind, ArtifactVersion,
    ArtifactVersionStatus, ControlPlanePrincipal, Investigation,
    InvestigationToolCall, MCPServer, MCPToolActivation,
    MCPWriteIndependentObservation, MCPWriteIndependentReview, new_id, utcnow,
)
from icheck.services.action_reconciliation import (
    record_independent_mcp_observation, review_independent_mcp_observation,
)
from icheck.services.change_governance import _hash_document
from icheck.services.control_plane_auth import PrincipalContext
from icheck.services.tool_skills import tool_artifact_documents
from icheck.studio_schemas import GeneratedToolSpec


URL = os.getenv("ICHECK_MCP_INDEPENDENT_POSTGRES_TEST_URL")
ACK = os.getenv("ICHECK_MCP_INDEPENDENT_POSTGRES_ACK")
ROLE = "icheck_independent_runtime"


def _spec(read_only: bool) -> GeneratedToolSpec:
    if read_only:
        return GeneratedToolSpec.model_validate({
            "artifact_name": "recipient-verifier", "tool_name": "report.verify_recipient",
            "description": "Read one recipient's independent report receipt.",
            "mcp_server_name": "recipient", "mcp_tool_name": "verify_recipient",
            "input_schema": {
                "type": "object", "additionalProperties": False,
                "required": ["source_tool_call_id"],
                "properties": {"source_tool_call_id": {"type": "string"}},
            },
            "output_schema": {
                "type": "object", "additionalProperties": False,
                "required": ["source_tool_call_id", "verification_kind", "observed_target_state", "observed_at", "evidence_reference", "values"],
                "properties": {
                    "source_tool_call_id": {"type": "string"},
                    "verification_kind": {"enum": ["recipient_receipt"]},
                    "observed_target_state": {"enum": ["present", "absent", "unknown"]},
                    "observed_at": {"type": "string"},
                    "evidence_reference": {"type": "string"},
                    "values": {
                        "type": "object", "additionalProperties": False,
                        "required": ["recipient_id", "document_digest"],
                        "properties": {
                            "recipient_id": {"type": "string"},
                            "document_digest": {"type": "string"},
                        },
                    },
                },
            },
            "risk_level": "diagnose", "read_only": True,
            "fixtures": [{
                "name": "receipt", "arguments": {"source_tool_call_id": "fixture"},
                "expected_output": {
                    "source_tool_call_id": "fixture", "verification_kind": "recipient_receipt",
                    "observed_target_state": "present", "observed_at": "2026-10-08T00:00:00+00:00",
                    "evidence_reference": "receipt:fixture", "values": {
                        "recipient_id": "recipient-1", "document_digest": "digest-1",
                    },
                },
            }],
        })
    return GeneratedToolSpec.model_validate({
        "artifact_name": "report-send", "tool_name": "report.send",
        "description": "Send one exact report after human approval.",
        "mcp_server_name": "sender", "mcp_tool_name": "send_report",
        "input_schema": {
            "type": "object", "additionalProperties": False,
            "required": ["recipient_id", "report"],
            "properties": {
                "recipient_id": {"type": "string"},
                "report": {
                    "type": "object", "additionalProperties": False,
                    "required": ["content_hash"],
                    "properties": {"content_hash": {"type": "string"}},
                },
            },
        },
        "output_schema": {
            "type": "object", "additionalProperties": False,
            "required": ["accepted"], "properties": {"accepted": {"type": "boolean"}},
        },
        "risk_level": "change", "read_only": False, "requires_approval": True,
        "independent_verification": {
            "tool_name": "report.verify_recipient", "kind": "recipient_receipt",
            "bindings": [
                {"original_argument_path": "recipient_id", "observed_value_key": "recipient_id", "value_type": "string"},
                {"original_argument_path": "report.content_hash", "observed_value_key": "document_digest", "value_type": "string"},
            ],
        },
        "fixtures": [{
            "name": "send", "arguments": {"recipient_id": "recipient-1", "report": {"content_hash": "digest-1"}},
            "expected_output": {"accepted": True},
        }],
    })


@pytest.mark.skipif(
    not URL or ACK != "I_ACK_DISPOSABLE_MCP_INDEPENDENT_DB",
    reason="Dedicated migrated PostgreSQL independent-observation DB not acknowledged",
)
def test_native_independent_observation_is_exact_scoped_and_immutable():
    engine = create_engine(URL, poolclass=NullPool, isolation_level="READ COMMITTED")
    try:
        with engine.begin() as connection:
            assert connection.scalar(text("SELECT current_database()")) == "icheck_independent_acceptance"
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "g4j6l8n0p2r5"
            connection.execute(text(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{ROLE}') "
                f"THEN CREATE ROLE {ROLE} NOLOGIN; END IF; END $$"
            ))
            connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {ROLE}"))
            connection.execute(text(
                "GRANT SELECT ON agent_action_proposals, investigations, investigation_tool_calls, "
                "agent_tool_registrations, mcp_tool_activations, mcp_servers, artifact_versions, "
                f"control_plane_principals TO {ROLE}"
            ))
            connection.execute(text(
                f"GRANT UPDATE ON agent_action_proposals, investigation_tool_calls TO {ROLE}"
            ))
            connection.execute(text(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_write_independent_observations TO {ROLE}"
            ))
            connection.execute(text(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_write_independent_reviews TO {ROLE}"
            ))
            connection.execute(text(f"GRANT SELECT, INSERT ON audit_events TO {ROLE}"))

        tenant_id, region_id = str(uuid4()), str(uuid4())
        namespace = {"tenant_id": tenant_id, "region_id": region_id}
        now = utcnow()
        original_id, verifier_id = new_id(), new_id()
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            provider = AIProviderConfig(
                **namespace, name="independent-model", provider_type="openai_compatible",
                base_url="https://models.example.test/v1", auth_type="none", created_by="acceptance",
            )
            db.add(provider)
            db.flush()
            model = AIModelConfig(
                **namespace, provider_id=provider.id, display_name="Independent model",
                model_name="independent-model", created_by="acceptance",
            )
            db.add(model)
            db.flush()
            route = AIModelRoute(
                **namespace, purpose="investigation", primary_model_id=model.id,
                created_by="acceptance",
            )
            sender = MCPServer(
                **namespace, name="sender", endpoint_url="https://sender.example.test/rpc",
                created_by="acceptance",
            )
            recipient = MCPServer(
                **namespace, name="recipient", endpoint_url="https://recipient.example.test/rpc",
                created_by="acceptance",
            )
            recorder = ControlPlanePrincipal(
                **namespace, subject="recorder@example.test", display_name="Recorder",
                created_by="acceptance",
            )
            reviewer = ControlPlanePrincipal(
                **namespace, subject="reviewer@example.test", display_name="Reviewer",
                created_by="acceptance",
            )
            db.add_all((route, sender, recipient, recorder, reviewer))
            db.flush()
            pinned = []
            for read_only, server in ((False, sender), (True, recipient)):
                spec = _spec(read_only)
                definition, implementation, fixtures = tool_artifact_documents(spec)
                artifact = Artifact(
                    **namespace, name=spec.artifact_name, kind=ArtifactKind.TOOL,
                    description=spec.description, owner="acceptance",
                )
                tool = AgentToolRegistration(
                    **namespace, name=spec.tool_name, description=spec.description,
                    transport="mcp", handler=f"{server.name}/{spec.mcp_tool_name}",
                    input_schema=spec.input_schema, output_schema=spec.output_schema,
                    risk_level=spec.risk_level, read_only=spec.read_only,
                    required_permissions=[], enabled=True, created_by="acceptance",
                )
                db.add_all((artifact, tool))
                db.flush()
                version = ArtifactVersion(
                    **namespace, artifact_id=artifact.id, version=1,
                    status=ArtifactVersionStatus.PUBLISHED,
                    definition=definition, implementation=implementation, tests=fixtures,
                    content_hash=("b" if read_only else "a") * 64,
                    created_by="acceptance", published_at=now,
                )
                db.add(version)
                db.flush()
                activation = MCPToolActivation(
                    **namespace, server_id=server.id, artifact_version_id=version.id,
                    tool_registration_id=tool.id, tool_name=tool.name,
                    mcp_tool_name=spec.mcp_tool_name,
                    contract_sha256=("d" if read_only else "c") * 64,
                    input_schema_sha256="e" * 64, output_schema_sha256="f" * 64,
                    activated_by="acceptance", activation_reason="Disposable native acceptance.",
                )
                db.add(activation)
                db.flush()
                pinned.append((tool, version, activation))
            write_tool, write_version, write_activation = pinned[0]
            verifier_tool, verifier_version, verifier_activation = pinned[1]
            original_investigation = Investigation(
                **namespace, title="Unknown write", objective="Check one lost report send.",
                status="escalated", route_id=route.id, model_id=model.id,
                max_iterations=8, max_tool_calls=10, timeout_seconds=300,
                token_budget=1000, created_by="acceptance",
            )
            verifier_investigation = Investigation(
                **namespace, title="Recipient read", objective="Read the recipient receipt.",
                status="completed", route_id=route.id, model_id=model.id,
                max_iterations=8, max_tool_calls=10, timeout_seconds=300,
                token_budget=1000, created_by="acceptance",
            )
            db.add_all((original_investigation, verifier_investigation))
            db.flush()
            arguments = {"recipient_id": "recipient-1", "report": {"content_hash": "digest-1"}}
            result = {
                "source_tool_call_id": original_id, "verification_kind": "recipient_receipt",
                "observed_target_state": "present", "observed_at": now.isoformat(),
                "evidence_reference": "receipt:42",
                "values": {"recipient_id": "recipient-1", "document_digest": "digest-1"},
            }
            original = InvestigationToolCall(
                **namespace, id=original_id, investigation_id=original_investigation.id,
                tool_id=write_tool.id, iteration=1, call_hash="1" * 64,
                arguments=arguments, status="running", started_at=now - timedelta(minutes=1),
                artifact_version_id=write_version.id, artifact_content_hash=write_version.content_hash,
                artifact_activation_id=write_activation.id,
                artifact_activation_sha256=write_activation.contract_sha256,
            )
            verifier = InvestigationToolCall(
                **namespace, id=verifier_id, investigation_id=verifier_investigation.id,
                tool_id=verifier_tool.id, iteration=1, call_hash="2" * 64,
                arguments={"source_tool_call_id": original_id}, status="succeeded",
                result=result, result_hash=_hash_document(result),
                started_at=now - timedelta(seconds=10), finished_at=now,
                artifact_version_id=verifier_version.id,
                artifact_content_hash=verifier_version.content_hash,
                artifact_activation_id=verifier_activation.id,
                artifact_activation_sha256=verifier_activation.contract_sha256,
            )
            db.add_all((original, verifier))
            db.flush()
            proposal = AgentActionProposal(
                **namespace, investigation_id=original_investigation.id,
                tool_id=write_tool.id, tool_call_id=original_id,
                iteration=1, arguments=arguments, purpose="Send exactly one report.",
                plan_hash="4" * 64, status="executing", requested_by="acceptance",
                execution_started_at=now - timedelta(minutes=1),
            )
            db.add(proposal)
            db.commit()
            proposal_id, recorder_id, reviewer_id = proposal.id, recorder.id, reviewer.id
            verifier_investigation_id = verifier_investigation.id
            verifier_tool_id = verifier_tool.id
            verifier_version_id = verifier_version.id
            verifier_content_hash = verifier_version.content_hash
            verifier_activation_id = verifier_activation.id
            verifier_activation_hash = verifier_activation.contract_sha256

        actor = PrincipalContext(
            principal_id=recorder_id, subject="recorder@example.test", principal_type="user",
            permissions=frozenset({"changes.approve"}), role_names=("approver",),
            authorization_scope={"all": True}, auth_method="bearer",
        )
        reviewer_actor = PrincipalContext(
            principal_id=reviewer_id, subject="reviewer@example.test", principal_type="user",
            permissions=frozenset({"changes.approve"}), role_names=("approver",),
            authorization_scope={"all": True}, auth_method="bearer",
        )
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            observation = record_independent_mcp_observation(
                db, proposal_id, verifier_id,
                "The recipient and document matched the exact approved send.", actor=actor,
            )
            observation_id = observation.id
            assert observation.observed_target_state == "present"
            assert observation.bound_value_count == 2
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            with pytest.raises(PermissionError, match="independent"):
                review_independent_mcp_observation(
                    db, proposal_id, observation_id, "accept",
                    "The retained evidence matches the original target.", actor=actor,
                )
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            with pytest.raises(DBAPIError, match="separate-person"):
                db.execute(text("""INSERT INTO mcp_write_independent_reviews (
                    id, proposal_id, observation_id, decision, reviewed_by_principal_id,
                    reviewed_by, reason, reviewed_at, tenant_id, region_id
                ) SELECT :id, proposal_id, id, 'accept', recorded_by_principal_id,
                    recorded_by, 'A recorder cannot accept their own evidence.', now(),
                    tenant_id, region_id FROM mcp_write_independent_observations WHERE id=:source_id"""), {
                    "id": str(uuid4()), "source_id": observation_id,
                })
            db.rollback()
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            review = review_independent_mcp_observation(
                db, proposal_id, observation_id, "accept",
                "The pinned recipient read matches both approved identity fields.",
                actor=reviewer_actor,
            )
            review_id = review.id
            assert review.decision == "accept"
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            replay_review = review_independent_mcp_observation(
                db, proposal_id, observation_id, "accept",
                "The pinned recipient read matches both approved identity fields.",
                actor=reviewer_actor,
            )
            assert replay_review.id == review_id
            with pytest.raises(ValueError, match="already been reviewed"):
                review_independent_mcp_observation(
                    db, proposal_id, observation_id, "reject",
                    "A later replacement decision cannot erase the accepted review.",
                    actor=reviewer_actor,
                )
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            replay = record_independent_mcp_observation(
                db, proposal_id, verifier_id,
                "The recipient and document matched the exact approved send.", actor=actor,
            )
            assert replay.id == observation_id
            assert db.scalar(select(func.count(MCPWriteIndependentObservation.id))) == 1
        wrong_id = new_id()
        wrong_result = {
            **result, "values": {
                "recipient_id": "recipient-1", "document_digest": "wrong-document",
            },
        }
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            db.add(InvestigationToolCall(
                **namespace, id=wrong_id, investigation_id=verifier_investigation_id,
                tool_id=verifier_tool_id, iteration=2, call_hash="5" * 64,
                arguments={"source_tool_call_id": original_id}, status="succeeded",
                result=wrong_result, result_hash=_hash_document(wrong_result),
                started_at=now - timedelta(seconds=10), finished_at=now,
                artifact_version_id=verifier_version_id,
                artifact_content_hash=verifier_content_hash,
                artifact_activation_id=verifier_activation_id,
                artifact_activation_sha256=verifier_activation_hash,
            ))
            db.commit()
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            with pytest.raises(DBAPIError, match="observed target differs"):
                db.execute(text("""INSERT INTO mcp_write_independent_observations (
                    id, proposal_id, original_tool_call_id, verification_tool_call_id,
                    verification_kind, observed_target_state, observed_at, evidence_reference,
                    bound_value_count, verification_result_hash, recorded_by_principal_id,
                    recorded_by, reason, created_at, tenant_id, region_id
                ) SELECT :id, proposal_id, original_tool_call_id, :wrong_id,
                    verification_kind, observed_target_state, observed_at, evidence_reference,
                    bound_value_count, :wrong_hash, recorded_by_principal_id,
                    recorded_by, reason, now(), tenant_id, region_id
                  FROM mcp_write_independent_observations WHERE id=:source_id"""), {
                    "id": str(uuid4()), "source_id": observation_id,
                    "wrong_id": wrong_id, "wrong_hash": _hash_document(wrong_result),
                })
            db.rollback()
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            with pytest.raises(DBAPIError, match="binding count differs"):
                db.execute(text("""INSERT INTO mcp_write_independent_observations (
                    id, proposal_id, original_tool_call_id, verification_tool_call_id,
                    verification_kind, observed_target_state, observed_at, evidence_reference,
                    bound_value_count, verification_result_hash, recorded_by_principal_id,
                    recorded_by, reason, created_at, tenant_id, region_id
                ) SELECT :id, proposal_id, original_tool_call_id, verification_tool_call_id,
                    verification_kind, observed_target_state, observed_at, evidence_reference,
                    1, verification_result_hash, recorded_by_principal_id,
                    recorded_by, reason, now(), tenant_id, region_id
                  FROM mcp_write_independent_observations WHERE id=:source_id"""), {
                    "id": str(uuid4()), "source_id": observation_id,
                })
            db.rollback()
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            with pytest.raises(DBAPIError, match="immutable"):
                db.execute(text(
                    "UPDATE mcp_write_independent_observations SET reason='modified evidence' WHERE id=:id"
                ), {"id": observation_id})
            db.rollback()
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            with pytest.raises(DBAPIError, match="immutable"):
                db.execute(text(
                    "UPDATE mcp_write_independent_reviews SET reason='modified review' WHERE id=:id"
                ), {"id": review_id})
            db.rollback()
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            with pytest.raises(DBAPIError, match="Terminal Tool calls are immutable"):
                db.execute(text(
                    "UPDATE investigation_tool_calls SET result_hash=:hash WHERE id=:id"
                ), {"id": verifier_id, "hash": "f" * 64})
            db.rollback()
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            with pytest.raises(DBAPIError, match="permission denied"):
                db.execute(text(
                    "DELETE FROM investigation_tool_calls WHERE id=:id"
                ), {"id": verifier_id})
            db.rollback()
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            with pytest.raises(DBAPIError, match="Terminal Tool calls are immutable"):
                db.execute(text(
                    "DELETE FROM investigation_tool_calls WHERE id=:id"
                ), {"id": verifier_id})
            db.rollback()
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            with pytest.raises(DBAPIError, match="Unknown MCP write Tool calls are immutable"):
                db.execute(text(
                    "UPDATE investigation_tool_calls SET status='failed', error='test rollback', "
                    "finished_at=now() WHERE id=:id"
                ), {"id": original_id})
            db.rollback()
        normal_id = new_id()
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            db.add(InvestigationToolCall(
                **namespace, id=normal_id, investigation_id=verifier_investigation_id,
                tool_id=verifier_tool_id, iteration=3, call_hash="6" * 64,
                arguments={"source_tool_call_id": original_id}, status="running",
                started_at=now - timedelta(seconds=10),
            ))
            db.commit()
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, tenant_id, region_id)
            db.execute(text(
                "UPDATE investigation_tool_calls SET status='failed', error='normal completion', "
                "finished_at=now() WHERE id=:id"
            ), {"id": normal_id})
            assert db.get(InvestigationToolCall, normal_id).status == "failed"
            db.rollback()
        with Session(engine) as db:
            db.execute(text(f"SET ROLE {ROLE}"))
            set_session_namespace(db, str(uuid4()), str(uuid4()))
            assert db.scalar(select(func.count(MCPWriteIndependentObservation.id))) == 0
            assert db.scalar(select(func.count(MCPWriteIndependentReview.id))) == 0
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            assert db.get(InvestigationToolCall, original_id).status == "running"
            assert db.get(AgentActionProposal, proposal_id).status == "executing"
    finally:
        engine.dispose()
