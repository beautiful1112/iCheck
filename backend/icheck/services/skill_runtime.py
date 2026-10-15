from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..agent_schemas import InvestigationCreate
from ..models import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    Investigation,
)
from ..schema_validation import validate_instance
from ..skill_runtime_schemas import PublishedSkillRead, SkillInvestigationCreate
from .agent_runtime import create_investigation, start_investigation
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext
from .tool_skills import (
    assert_skill_runtime_compatible,
    skill_runtime_snapshot,
)


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def skill_version(db: Session, version_id: str) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == version_id)
        .options(selectinload(ArtifactVersion.artifact))
    )
    if version is None:
        raise LookupError("Skill version not found")
    return version


def published_skill_read(version: ArtifactVersion) -> PublishedSkillRead:
    spec = version.definition["spec"]
    return PublishedSkillRead(
        artifact_id=version.artifact_id,
        artifact_name=version.artifact.name,
        version_id=version.id,
        version=version.version,
        skill_name=spec["skill_name"],
        description=spec["description"],
        input_schema=spec["input_schema"],
        output_schema=spec["output_schema"],
        allowed_tools=spec["allowed_tools"],
        max_iterations=spec["max_iterations"],
        max_tool_calls=spec["max_tool_calls"],
        max_total_tokens=spec["max_total_tokens"],
        content_hash=version.content_hash or "",
    )


def list_published_skills(db: Session) -> list[ArtifactVersion]:
    return list(
        db.scalars(
            select(ArtifactVersion)
            .join(ArtifactVersion.artifact)
            .where(
                Artifact.kind == ArtifactKind.SKILL,
                ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
            )
            .options(selectinload(ArtifactVersion.artifact))
            .order_by(Artifact.name, ArtifactVersion.version.desc())
        ).all()
    )


def create_skill_investigation(
    db: Session,
    version: ArtifactVersion,
    payload: SkillInvestigationCreate,
    *,
    principal: PrincipalContext,
    actor: str,
) -> tuple[Investigation, Any]:
    spec, report = assert_skill_runtime_compatible(db, version)
    assert_no_inline_secrets(payload.skill_input, "skill.input")
    validate_instance(payload.skill_input, spec.input_schema, "skill input")
    required_permissions = report["required_permissions"]
    if not principal.permits(*required_permissions):
        raise PermissionError(
            "Principal lacks one or more permissions required by the Skill"
        )
    objective = f"Execute published diagnostic Skill {spec.skill_name!r}."
    if payload.operator_context:
        objective += f" Operator context: {payload.operator_context}"
    investigation = create_investigation(
        db,
        InvestigationCreate(
            title=payload.title or spec.description[:255],
            objective=objective,
            scope=payload.scope,
            route_purpose=payload.route_purpose,
            created_by=actor,
        ),
        actor=principal,
        commit=False,
    )
    investigation.skill_artifact_version_id = version.id
    investigation.skill_input = payload.skill_input
    investigation.skill_snapshot = skill_runtime_snapshot(version, spec)
    investigation.max_iterations = min(
        investigation.max_iterations,
        spec.max_iterations,
    )
    investigation.max_tool_calls = min(
        investigation.max_tool_calls,
        spec.max_tool_calls,
    )
    investigation.token_budget = min(
        investigation.token_budget,
        spec.max_total_tokens,
    )
    record_audit_event(
        db,
        event_type="skill.investigation.bound",
        actor_type="user",
        actor_id=actor,
        entity_type="investigation",
        entity_id=investigation.id,
        details={
            "skill_artifact_version_id": version.id,
            "skill_content_hash": version.content_hash,
            "skill_input_sha256": _hash(payload.skill_input),
            "allowed_tools": spec.allowed_tools,
            "budgets": {
                "max_iterations": investigation.max_iterations,
                "max_tool_calls": investigation.max_tool_calls,
                "token_budget": investigation.token_budget,
            },
        },
    )
    return start_investigation(db, investigation, actor=actor)
