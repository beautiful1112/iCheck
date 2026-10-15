from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..artifact_replay_schemas import (
    ArtifactReplayCaseCreate,
    ArtifactReplayCaseRead,
    ArtifactReplayRunRead,
)
from ..models import (
    Artifact,
    ArtifactKind,
    ArtifactReplayCase,
    ArtifactReplayRun,
    ArtifactVersion,
    ArtifactVersionStatus,
    utcnow,
)
from ..sandbox import SandboxExecutor, default_sandbox_executor
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets


MAX_REPLAY_DOCUMENT_BYTES = 2_000_000
MAX_REPORTED_MISMATCHES = 50


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_encoded(value)).hexdigest()


def replay_case_read(case: ArtifactReplayCase) -> ArtifactReplayCaseRead:
    return ArtifactReplayCaseRead(
        id=case.id,
        artifact_id=case.artifact_id,
        name=case.name,
        source_label=case.source_label,
        input_count=len(case.input_envelopes),
        expected_count=len(case.expected_envelopes),
        input_sha256=case.input_sha256,
        expected_sha256=case.expected_sha256,
        configuration_sha256=_hash(case.configuration),
        created_by=case.created_by,
        created_at=case.created_at,
    )


def create_replay_case(
    db: Session,
    artifact: Artifact,
    payload: ArtifactReplayCaseCreate,
    *,
    actor: str,
) -> ArtifactReplayCase:
    if artifact.kind != ArtifactKind.COLLECTOR:
        raise ValueError("Replay cases currently support only Collector Artifacts")
    input_envelopes = [
        item.model_dump(mode="json", exclude_none=True)
        for item in payload.input_envelopes
    ]
    expected_envelopes = [
        item.model_dump(mode="json", exclude_none=True)
        for item in payload.expected_envelopes
    ]
    assert_no_inline_secrets(payload.configuration, "replay.configuration")
    assert_no_inline_secrets(input_envelopes, "replay.input_envelopes")
    assert_no_inline_secrets(expected_envelopes, "replay.expected_envelopes")
    document = {
        "configuration": payload.configuration,
        "input": input_envelopes,
        "expected": expected_envelopes,
    }
    if len(_encoded(document)) > MAX_REPLAY_DOCUMENT_BYTES:
        raise ValueError(
            f"Replay case exceeds {MAX_REPLAY_DOCUMENT_BYTES} bytes"
        )
    case = ArtifactReplayCase(
        artifact_id=artifact.id,
        name=payload.name,
        source_label=payload.source_label,
        configuration=payload.configuration,
        input_envelopes=input_envelopes,
        expected_envelopes=expected_envelopes,
        input_sha256=_hash(input_envelopes),
        expected_sha256=_hash(expected_envelopes),
        created_by=actor,
    )
    db.add(case)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="artifact.replay_case.created",
            actor_type="user",
            actor_id=actor,
            entity_type="artifact_replay_case",
            entity_id=case.id,
            details={
                "artifact_id": artifact.id,
                "input_count": len(input_envelopes),
                "expected_count": len(expected_envelopes),
                "input_sha256": case.input_sha256,
                "expected_sha256": case.expected_sha256,
                "source_label": case.source_label,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Replay case name already exists for this Artifact") from exc
    db.refresh(case)
    return case


def _replay_version(
    db: Session,
    case: ArtifactReplayCase,
    version_id: str,
) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == version_id)
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
    )
    if version is None:
        raise LookupError("Artifact version not found")
    if version.artifact_id != case.artifact_id:
        raise ValueError("Replay case and Artifact version do not belong together")
    if version.status not in {
        ArtifactVersionStatus.VALIDATED,
        ArtifactVersionStatus.PUBLISHED,
        ArtifactVersionStatus.DEPRECATED,
    }:
        raise ValueError("Replay requires a validated, published, or deprecated version")
    if version.artifact.kind != ArtifactKind.COLLECTOR:
        raise ValueError("Replay version must be a Collector Artifact")
    if version.collector_definition is None:
        raise ValueError("Collector definition is missing")
    if version.implementation.get("runtime") != "python_sandbox_v1":
        raise ValueError(
            "Historical replay currently supports python_sandbox_v1 collectors"
        )
    return version


def _comparison_report(
    expected: list[dict[str, Any]],
    actual: list[dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    total = max(len(expected), len(actual))
    mismatches: list[dict[str, Any]] = []
    mismatch_count = 0
    for index in range(total):
        expected_item = expected[index] if index < len(expected) else None
        actual_item = actual[index] if index < len(actual) else None
        if expected_item == actual_item:
            continue
        mismatch_count += 1
        if len(mismatches) < MAX_REPORTED_MISMATCHES:
            mismatches.append(
                {
                    "index": index,
                    "change_type": (
                        "unexpected"
                        if expected_item is None
                        else "missing"
                        if actual_item is None
                        else "changed"
                    ),
                    "expected_sha256": (
                        _hash(expected_item) if expected_item is not None else None
                    ),
                    "actual_sha256": (
                        _hash(actual_item) if actual_item is not None else None
                    ),
                }
            )
    return mismatch_count, {
        "expected_count": len(expected),
        "actual_count": len(actual),
        "matching_count": total - mismatch_count,
        "mismatch_count": mismatch_count,
        "mismatches_truncated": mismatch_count > len(mismatches),
        "mismatches": mismatches,
    }


def run_replay_case(
    db: Session,
    case: ArtifactReplayCase,
    version_id: str,
    *,
    actor: str,
    sandbox_executor: SandboxExecutor | None = None,
) -> ArtifactReplayRun:
    version = _replay_version(db, case, version_id)
    definition = version.collector_definition
    if definition is None:
        raise ValueError("Collector definition is missing")
    run = ArtifactReplayRun(
        case_id=case.id,
        artifact_version_id=version.id,
        status="error",
        executed_by=actor,
        report={},
    )
    db.add(run)
    db.flush()
    try:
        executor = sandbox_executor or default_sandbox_executor()
        actual = executor.transform(
            version.implementation,
            case.input_envelopes,
            {**definition.defaults, **case.configuration},
            list(definition.output_kinds),
        )
        assert_no_inline_secrets(actual, "replay.actual_output")
        actual_sha256 = _hash(actual)
        mismatch_count, report = _comparison_report(
            case.expected_envelopes,
            actual,
        )
        run.status = "passed" if mismatch_count == 0 else "failed"
        run.actual_sha256 = actual_sha256
        run.mismatch_count = mismatch_count
        run.report = {
            **report,
            "input_sha256": case.input_sha256,
            "expected_sha256": case.expected_sha256,
            "actual_sha256": actual_sha256,
            "artifact_content_hash": version.content_hash,
            "isolation": version.validation_report.get("isolation"),
        }
    except Exception as exc:
        error_text = str(exc)[:10_000]
        run.status = "error"
        run.actual_sha256 = None
        run.mismatch_count = 0
        run.report = {
            "error_type": type(exc).__name__,
            "error_sha256": hashlib.sha256(
                error_text.encode("utf-8")
            ).hexdigest(),
            "input_sha256": case.input_sha256,
            "expected_sha256": case.expected_sha256,
            "artifact_content_hash": version.content_hash,
        }
    run.finished_at = utcnow()
    record_audit_event(
        db,
        event_type="artifact.replay.completed",
        actor_type="user",
        actor_id=actor,
        entity_type="artifact_replay_run",
        entity_id=run.id,
        outcome="success" if run.status == "passed" else "failure",
        details={
            "case_id": case.id,
            "artifact_version_id": version.id,
            "status": run.status,
            "mismatch_count": run.mismatch_count,
            "input_sha256": case.input_sha256,
            "expected_sha256": case.expected_sha256,
            "actual_sha256": run.actual_sha256,
        },
    )
    db.commit()
    db.refresh(run)
    return run


def replay_run_read(run: ArtifactReplayRun) -> ArtifactReplayRunRead:
    return ArtifactReplayRunRead.model_validate(run)
