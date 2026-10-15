from __future__ import annotations

import hashlib
import json

from icheck.database import SessionLocal
from icheck.models import (
    AgentExecution,
    AgentExecutionStatus,
    Artifact,
    ArtifactKind,
    ArtifactReplayCase,
    ArtifactReplayRun,
    ArtifactVersion,
    ArtifactVersionStatus,
    CapabilityStudioMessage,
    CapabilityStudioSession,
    CollectorDeployment,
    CollectorRun,
    CollectorRunStatus,
    CollectorWorker,
    Investigation,
    utcnow,
)
from icheck.sandbox import HardenedProcessSandboxExecutor

from test_capability_studio import (
    FIRST_SPEC,
    REFINED_SPEC,
    FakeStructuredOpener,
    configure_authoring_route,
    studio_payload,
)


def _generated_collector(client, monkeypatch, documents):
    configure_authoring_route(client)
    opener = FakeStructuredOpener(documents)
    monkeypatch.setattr(
        "icheck.services.structured_model.build_opener",
        lambda *_handlers: opener,
    )
    monkeypatch.setattr(
        "icheck.services.collectors.default_sandbox_executor",
        lambda: HardenedProcessSandboxExecutor(python_path="/usr/bin/python3"),
    )
    created = client.post(
        "/api/v1/capability-studio/sessions",
        json=studio_payload(),
    )
    assert created.status_code == 201, created.text
    generated = client.post(
        f"/api/v1/capability-studio/sessions/{created.json()['id']}/generate",
        json={"actor": "capability.author"},
    )
    assert generated.status_code == 200, generated.text
    return generated.json(), opener


def _revision(client, source_type: str, source_id: str, goal: str):
    return client.post(
        "/api/v1/capability-studio/sessions/from-runtime",
        json={
            "source_type": source_type,
            "source_id": source_id,
            "revision_goal": goal,
            "route_purpose": "capability.authoring",
            "actor": "capability.author",
        },
    )


def test_failed_replay_creates_idempotent_revision_and_new_validated_version(
    client,
    monkeypatch,
):
    generated, opener = _generated_collector(
        client,
        monkeypatch,
        [FIRST_SPEC, REFINED_SPEC],
    )
    source_version_id = generated["artifact_version_id"]
    with SessionLocal() as db:
        case = ArtifactReplayCase(
            artifact_id=generated["artifact_id"],
            name="runtime-revision-case",
            source_label="sanitized-test",
            configuration={},
            input_envelopes=[],
            expected_envelopes=[],
            input_sha256="1" * 64,
            expected_sha256="2" * 64,
            created_by="capability.reviewer",
        )
        db.add(case)
        db.flush()
        run = ArtifactReplayRun(
            case_id=case.id,
            artifact_version_id=source_version_id,
            status="failed",
            actual_sha256="3" * 64,
            mismatch_count=1,
            report={
                "mismatches": [
                    {
                        "index": 0,
                        "change_type": "changed",
                        "expected_sha256": "4" * 64,
                        "actual_sha256": "5" * 64,
                    }
                ],
                "raw_output": "TOPSECRET-RAW-OUTPUT",
            },
            executed_by="capability.reviewer",
        )
        db.add(run)
        db.commit()
        run_id = run.id

    created = _revision(
        client,
        "artifact_replay_run",
        run_id,
        "Revise the Collector so the historical contract passes again.",
    )
    assert created.status_code == 201, created.text
    session = created.json()
    assert session["status"] == "draft"
    assert session["artifact_id"] == generated["artifact_id"]
    assert session["artifact_version_id"] == source_version_id
    assert session["revision_source_artifact_version_id"] == source_version_id
    assert session["revision_source_type"] == "artifact_replay_run"
    assert session["current_spec"] == FIRST_SPEC
    assert len(session["revision_evidence_sha256"]) == 64
    serialized = json.dumps(session)
    assert "TOPSECRET-RAW-OUTPUT" not in serialized
    assert "raw_output" not in serialized
    assert "expected_sha256" in serialized

    repeated = _revision(
        client,
        "artifact_replay_run",
        run_id,
        "A different retry must return the existing revision session.",
    )
    assert repeated.status_code == 201, repeated.text
    assert repeated.json()["id"] == session["id"]
    assert len(repeated.json()["messages"]) == len(session["messages"])

    refined = client.post(
        f"/api/v1/capability-studio/sessions/{session['id']}/messages",
        json={
            "actor": "capability.author",
            "content": "Preserve the contract and correct the bounded replay mismatch.",
        },
    )
    assert refined.status_code == 200, refined.text
    revised = refined.json()
    assert revised["status"] == "validated"
    assert revised["artifact_version_id"] != source_version_id
    assert revised["revision_source_artifact_version_id"] == source_version_id
    assert revised["current_spec"] == {
        **REFINED_SPEC,
        "artifact_name": FIRST_SPEC["artifact_name"],
    }
    second_prompt = opener.requests[1][0].data.decode("utf-8")
    assert "TOPSECRET-RAW-OUTPUT" not in second_prompt
    assert session["revision_evidence_sha256"] in second_prompt

    audit_text = json.dumps(client.get("/api/v1/audit-events?limit=1000").json())
    assert "TOPSECRET-RAW-OUTPUT" not in audit_text
    assert "capability.revision_session.created" in audit_text


def test_failed_collector_run_requires_pinned_version_and_hashes_raw_error(
    client,
    monkeypatch,
):
    generated, _opener = _generated_collector(client, monkeypatch, [FIRST_SPEC])
    with SessionLocal() as db:
        deployment = CollectorDeployment(
            name="runtime-revision-deployment",
            artifact_version_id=generated["artifact_version_id"],
            target={"url": "https://secret-target.example.test/data"},
            configuration={"unsafe": "must-not-project"},
            worker_selector={},
            schedule_seconds=300,
            enabled=True,
            created_by="collector.operator",
        )
        worker = CollectorWorker(
            name="runtime-revision-worker",
            capabilities=["http_json_sandbox"],
            labels={},
            auth_token_hash="6" * 64,
        )
        db.add_all([deployment, worker])
        db.flush()
        run = CollectorRun(
            deployment_id=deployment.id,
            artifact_version_id=generated["artifact_version_id"],
            worker_id=worker.id,
            lease_token_hash="7" * 64,
            status=CollectorRunStatus.FAILED,
            error="password=TOPSECRET-COLLECTOR-ERROR",
            started_at=utcnow(),
            finished_at=utcnow(),
        )
        legacy_run = CollectorRun(
            deployment_id=deployment.id,
            artifact_version_id=None,
            worker_id=worker.id,
            lease_token_hash="8" * 64,
            status=CollectorRunStatus.FAILED,
            error="legacy failure",
            started_at=utcnow(),
            finished_at=utcnow(),
        )
        db.add_all([run, legacy_run])
        db.commit()
        run_id = run.id
        legacy_id = legacy_run.id

    created = _revision(
        client,
        "collector_run",
        run_id,
        "Revise the Collector to handle this failed runtime condition safely.",
    )
    assert created.status_code == 201, created.text
    body = json.dumps(created.json())
    assert "TOPSECRET-COLLECTOR-ERROR" not in body
    assert "secret-target" not in body
    assert "must-not-project" not in body
    assert hashlib.sha256(
        "password=TOPSECRET-COLLECTOR-ERROR".encode()
    ).hexdigest() in body

    legacy = _revision(
        client,
        "collector_run",
        legacy_id,
        "This legacy run must fail closed without exact version provenance.",
    )
    assert legacy.status_code == 409
    assert "predates immutable" in legacy.text


def test_failed_agent_execution_binds_exact_workflow_without_inputs(client):
    route, model = configure_authoring_route(client)
    workflow_spec = {
        "artifact_name": "runtime-revision-workflow",
        "description": "A generated workflow under revision.",
        "trigger": {"trigger_type": "manual"},
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        },
        "start_node": "finish",
        "nodes": [{"node_id": "finish", "title": "Finish", "node_type": "end"}],
        "max_runtime_seconds": 60,
        "max_total_tool_calls": 1,
        "max_total_tokens": 1000,
    }
    with SessionLocal() as db:
        artifact = Artifact(
            name="runtime-revision-workflow",
            kind=ArtifactKind.WORKFLOW,
            description="Generated workflow.",
            owner="capability.author",
            labels={"generated": True},
        )
        db.add(artifact)
        db.flush()
        version = ArtifactVersion(
            artifact_id=artifact.id,
            version=1,
            status=ArtifactVersionStatus.VALIDATED,
            definition={},
            implementation={},
            tests=[],
            validation_report={},
            content_hash="9" * 64,
            created_by="capability.author",
        )
        db.add(version)
        db.flush()
        studio = CapabilityStudioSession(
            title="Workflow source",
            artifact_kind="workflow",
            status="validated",
            route_purpose="capability.authoring",
            brief="Create the generated workflow used for revision testing.",
            target_url="",
            sample_document={},
            current_spec=workflow_spec,
            artifact_id=artifact.id,
            artifact_version_id=version.id,
            created_by="capability.author",
        )
        db.add(studio)
        db.flush()
        db.add(
            CapabilityStudioMessage(
                session_id=studio.id,
                role="assistant",
                content="Validated workflow.",
                content_hash=hashlib.sha256(b"Validated workflow.").hexdigest(),
                structured_content={
                    "spec": workflow_spec,
                    "artifact_version_id": version.id,
                },
            )
        )
        investigation = Investigation(
            title="Failed generated workflow",
            objective="Execute a generated workflow.",
            scope={},
            status="failed",
            route_id=route["id"],
            model_id=model["id"],
            max_iterations=3,
            max_tool_calls=3,
            timeout_seconds=60,
            token_budget=1000,
            iterations_used=2,
            tool_calls_used=1,
            tokens_used=300,
            workflow_artifact_version_id=version.id,
            workflow_input={"password": "TOPSECRET-WORKFLOW-INPUT"},
            workflow_snapshot={},
            created_by="workflow.operator",
            escalation_reason="TOPSECRET-ESCALATION",
        )
        db.add(investigation)
        db.flush()
        execution = AgentExecution(
            investigation_id=investigation.id,
            status=AgentExecutionStatus.FAILED,
            attempt_count=1,
            error="TOPSECRET-AGENT-ERROR",
            finished_at=utcnow(),
        )
        db.add(execution)
        db.commit()
        execution_id = execution.id
        version_id = version.id

    created = _revision(
        client,
        "agent_execution",
        execution_id,
        "Revise the Workflow using only the bounded failure evidence.",
    )
    assert created.status_code == 201, created.text
    session = created.json()
    assert session["artifact_kind"] == "workflow"
    assert session["revision_source_artifact_version_id"] == version_id
    assert session["current_spec"] == workflow_spec
    body = json.dumps(session)
    assert "TOPSECRET-WORKFLOW-INPUT" not in body
    assert "TOPSECRET-ESCALATION" not in body
    assert "TOPSECRET-AGENT-ERROR" not in body
