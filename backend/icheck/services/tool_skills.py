from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AgentToolRegistration,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    Investigation,
)
from ..schema_validation import validate_instance, validate_schema
from ..studio_schemas import GeneratedSkillSpec, GeneratedToolSpec
from .collectors import assert_no_inline_secrets


TOOL_FORMAT_VERSION = "icheck.tool/v1"
TOOL_RUNTIME = "icheck_mcp_tool_v1"
SKILL_FORMAT_VERSION = "icheck.skill/v1"
SKILL_RUNTIME = "icheck_agent_skill_v1"


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _strict_object_schema(schema: dict[str, Any], label: str) -> None:
    validate_schema(schema, label)
    if schema.get("type") != "object":
        raise ValueError(f"{label} must declare type object")
    if not isinstance(schema.get("properties"), dict):
        raise ValueError(f"{label} must declare properties")
    if schema.get("additionalProperties") is not False:
        raise ValueError(f"{label} must set additionalProperties false")


def _tool_spec_document(spec: GeneratedToolSpec) -> dict[str, Any]:
    document = spec.model_dump(mode="json")
    # Preserve the canonical bytes of v1 Tool Artifacts published before this
    # optional lookup designation existed. Only explicitly authored bindings
    # become part of a new immutable Artifact's identity.
    if spec.outcome_lookup_tool_name is None:
        document.pop("outcome_lookup_tool_name", None)
    if spec.outcome_lookup_correlation is None:
        document.pop("outcome_lookup_correlation", None)
    if spec.independent_verification is None:
        document.pop("independent_verification", None)
    return document


def validate_tool_spec(spec: GeneratedToolSpec) -> dict[str, Any]:
    document = _tool_spec_document(spec)
    assert_no_inline_secrets(document, "tool specification")
    _strict_object_schema(spec.input_schema, "tool.input_schema")
    _strict_object_schema(spec.output_schema, "tool.output_schema")
    for fixture in spec.fixtures:
        validate_instance(
            fixture.arguments,
            spec.input_schema,
            f"tool fixture {fixture.name!r} arguments",
        )
        validate_instance(
            fixture.expected_output,
            spec.output_schema,
            f"tool fixture {fixture.name!r} output",
        )
    report = {
        "runtime": TOOL_RUNTIME,
        "isolation": "declarative_mcp_contract",
        "spec_sha256": _hash(document),
        "tool_name": spec.tool_name,
        "transport": spec.transport,
        "mcp_server_name": spec.mcp_server_name,
        "risk_level": spec.risk_level,
        "read_only": spec.read_only,
        "requires_approval": spec.requires_approval,
        "change_contract": (
            spec.change_contract.model_dump(mode="json")
            if spec.change_contract
            else None
        ),
        "required_permissions": sorted(spec.required_permissions),
        "fixture_count": len(spec.fixtures),
        "activation": "separate_review_required",
    }
    if spec.outcome_lookup_tool_name is not None:
        report["outcome_lookup_tool_name"] = spec.outcome_lookup_tool_name
    if spec.outcome_lookup_correlation is not None:
        report["outcome_lookup_correlation"] = spec.outcome_lookup_correlation.model_dump(mode="json")
    if spec.independent_verification is not None:
        report["independent_verification"] = spec.independent_verification.model_dump(mode="json")
    return report


def tool_artifact_documents(
    spec: GeneratedToolSpec,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    report = validate_tool_spec(spec)
    return (
        {
            "format_version": TOOL_FORMAT_VERSION,
            "spec": _tool_spec_document(spec),
        },
        {
            "runtime": TOOL_RUNTIME,
            "transport": "mcp",
            "handler": f"{spec.mcp_server_name}/{spec.mcp_tool_name}",
            "activation": "separate_review_required",
        },
        [
            {
                "name": fixture.name,
                "arguments": fixture.arguments,
                "expected_output": fixture.expected_output,
                "input_schema_sha256": _hash(spec.input_schema),
                "output_schema_sha256": _hash(spec.output_schema),
            }
            for fixture in spec.fixtures
        ],
    )


def validate_tool_artifact_contract(
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
) -> dict[str, Any]:
    if set(definition) != {"format_version", "spec"}:
        raise ValueError("tool definition has unsupported fields")
    if definition.get("format_version") != TOOL_FORMAT_VERSION:
        raise ValueError("tool format_version is unsupported")
    spec = GeneratedToolSpec.model_validate(definition.get("spec"))
    expected = tool_artifact_documents(spec)
    if definition != expected[0]:
        raise ValueError("tool definition is not canonical")
    if implementation != expected[1]:
        raise ValueError("tool implementation contract is invalid")
    if tests != expected[2]:
        raise ValueError("tool fixture contract is invalid")
    return validate_tool_spec(spec)


def skill_tool_catalog(db: Session) -> list[dict[str, Any]]:
    tools = db.scalars(
        select(AgentToolRegistration)
        .where(AgentToolRegistration.enabled.is_(True))
        .order_by(AgentToolRegistration.name)
    ).all()
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "risk_level": tool.risk_level,
            "read_only": tool.read_only,
            "required_permissions": sorted(tool.required_permissions),
            "change_contract": tool.change_contract,
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema,
            "timeout_seconds": tool.timeout_seconds,
            "max_result_bytes": tool.max_result_bytes,
        }
        for tool in tools
    ]


def _tool_dependency(tool: AgentToolRegistration) -> dict[str, Any]:
    return {
        "id": tool.id,
        "name": tool.name,
        "transport": tool.transport,
        "handler": tool.handler,
        "risk_level": tool.risk_level,
        "read_only": tool.read_only,
        "required_permissions": sorted(tool.required_permissions),
        "change_contract_sha256": (
            _hash(tool.change_contract) if tool.change_contract else None
        ),
        "input_schema_sha256": _hash(tool.input_schema),
        "output_schema_sha256": _hash(tool.output_schema),
        "timeout_seconds": tool.timeout_seconds,
        "max_result_bytes": tool.max_result_bytes,
    }


def validate_skill_spec(
    db: Session,
    spec: GeneratedSkillSpec,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    document = spec.model_dump(mode="json")
    assert_no_inline_secrets(document, "skill specification")
    _strict_object_schema(spec.input_schema, "skill.input_schema")
    _strict_object_schema(spec.output_schema, "skill.output_schema")
    tools = {
        tool.name: tool
        for tool in db.scalars(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name.in_(spec.allowed_tools),
                AgentToolRegistration.enabled.is_(True),
            )
        ).all()
    }
    missing = sorted(set(spec.allowed_tools) - set(tools))
    if missing:
        raise ValueError(f"skill references unavailable tools {missing}")
    state_changing = sorted(
        name for name, tool in tools.items() if not tool.read_only
    )
    if state_changing:
        raise ValueError(
            "diagnostic skills may reference only read-only tools; "
            f"state-changing tools were requested {state_changing}"
        )
    dependencies = [_tool_dependency(tools[name]) for name in spec.allowed_tools]
    required_permissions = sorted(
        {
            permission
            for tool in tools.values()
            for permission in tool.required_permissions
        }
    )
    return (
        {
            "runtime": SKILL_RUNTIME,
            "isolation": "bounded_read_only_agent_skill",
            "spec_sha256": _hash(document),
            "skill_name": spec.skill_name,
            "tool_dependencies": dependencies,
            "required_permissions": required_permissions,
            "budgets": {
                "max_iterations": spec.max_iterations,
                "max_tool_calls": spec.max_tool_calls,
                "max_total_tokens": spec.max_total_tokens,
            },
            "evidence_required": True,
            "read_only": True,
        },
        dependencies,
    )


def skill_artifact_documents(
    db: Session,
    spec: GeneratedSkillSpec,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    report, dependencies = validate_skill_spec(db, spec)
    return (
        {
            "format_version": SKILL_FORMAT_VERSION,
            "spec": spec.model_dump(mode="json"),
        },
        {
            "runtime": SKILL_RUNTIME,
            "policy_precedence": "platform",
            "read_only": True,
        },
        [
            {
                "name": "Deterministic skill contract validation",
                "expected_spec_sha256": report["spec_sha256"],
                "tool_dependencies": dependencies,
            }
        ],
    )


def validate_skill_artifact_contract(
    db: Session,
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
) -> dict[str, Any]:
    if set(definition) != {"format_version", "spec"}:
        raise ValueError("skill definition has unsupported fields")
    if definition.get("format_version") != SKILL_FORMAT_VERSION:
        raise ValueError("skill format_version is unsupported")
    spec = GeneratedSkillSpec.model_validate(definition.get("spec"))
    expected = skill_artifact_documents(db, spec)
    if definition != expected[0]:
        raise ValueError("skill definition is not canonical")
    if implementation != expected[1]:
        raise ValueError("skill implementation contract is invalid")
    if tests != expected[2]:
        raise ValueError("skill dependency contract is invalid")
    report, _ = validate_skill_spec(db, spec)
    return report


def assert_skill_runtime_compatible(
    db: Session,
    version: ArtifactVersion,
    *,
    allow_deprecated: bool = False,
) -> tuple[GeneratedSkillSpec, dict[str, Any]]:
    if version.artifact.kind != ArtifactKind.SKILL:
        raise ValueError("Runtime version must be a Skill Artifact")
    allowed_statuses = {ArtifactVersionStatus.PUBLISHED}
    if allow_deprecated:
        allowed_statuses.add(ArtifactVersionStatus.DEPRECATED)
    if version.status not in allowed_statuses:
        raise ValueError("Only published Skill versions can execute")
    if version.implementation != {
        "runtime": SKILL_RUNTIME,
        "policy_precedence": "platform",
        "read_only": True,
    }:
        raise ValueError("Skill runtime contract is unsupported")
    if version.definition.get("format_version") != SKILL_FORMAT_VERSION:
        raise ValueError("Skill format_version is unsupported")
    spec = GeneratedSkillSpec.model_validate(version.definition.get("spec"))
    report, current_dependencies = validate_skill_spec(db, spec)
    if len(version.tests) != 1:
        raise ValueError("Published Skill dependency snapshot is missing")
    stored_dependencies = version.tests[0].get("tool_dependencies")
    if stored_dependencies != current_dependencies:
        raise ValueError(
            "Published Skill tool dependencies drifted from the live registry"
        )
    return spec, report


def skill_runtime_snapshot(
    version: ArtifactVersion,
    spec: GeneratedSkillSpec,
) -> dict[str, Any]:
    return {
        "format_version": version.definition["format_version"],
        "content_hash": version.content_hash,
        "skill_name": spec.skill_name,
        "description": spec.description,
        "instructions": spec.instructions,
        "input_schema": spec.input_schema,
        "output_schema": spec.output_schema,
        "allowed_tools": spec.allowed_tools,
        "success_criteria": spec.success_criteria,
        "escalation_conditions": spec.escalation_conditions,
        "evidence_required": spec.evidence_required,
        "tool_dependencies": version.tests[0]["tool_dependencies"],
    }


def assert_bound_skill_runtime_compatible(
    db: Session,
    investigation: Investigation,
) -> tuple[GeneratedSkillSpec, dict[str, Any]] | None:
    if not investigation.skill_snapshot:
        return None
    if investigation.skill_artifact_version_id is None:
        raise ValueError("Bound Skill Artifact version is unavailable")
    version = db.get(ArtifactVersion, investigation.skill_artifact_version_id)
    if version is None:
        raise ValueError("Bound Skill Artifact version is unavailable")
    spec, report = assert_skill_runtime_compatible(
        db,
        version,
        allow_deprecated=True,
    )
    if investigation.skill_snapshot != skill_runtime_snapshot(version, spec):
        raise ValueError("Bound Skill snapshot does not match its published version")
    return spec, report


def assert_skill_tool_allowed(
    db: Session,
    investigation: Investigation,
    tool: AgentToolRegistration,
) -> None:
    if not investigation.skill_snapshot:
        return
    assert_bound_skill_runtime_compatible(db, investigation)
    snapshot = investigation.skill_snapshot or {}
    allowed_tools = snapshot.get("allowed_tools")
    dependencies = snapshot.get("tool_dependencies")
    if not isinstance(allowed_tools, list) or tool.name not in allowed_tools:
        raise PermissionError(
            f"Skill does not allow tool {tool.name!r}"
        )
    if not isinstance(dependencies, list):
        raise ValueError("Skill dependency snapshot is missing")
    stored = next(
        (
            item
            for item in dependencies
            if isinstance(item, dict) and item.get("name") == tool.name
        ),
        None,
    )
    if stored != _tool_dependency(tool):
        raise ValueError(
            f"Skill dependency {tool.name!r} drifted from the live registry"
        )
