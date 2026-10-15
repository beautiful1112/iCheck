from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field

from .schemas import APIModel


class SkillRuntimeModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class PublishedSkillRead(SkillRuntimeModel):
    artifact_id: str
    artifact_name: str
    version_id: str
    version: int
    skill_name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    allowed_tools: list[str]
    max_iterations: int
    max_tool_calls: int
    max_total_tokens: int
    content_hash: str


class SkillInvestigationCreate(SkillRuntimeModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    skill_input: dict[str, Any]
    scope: dict[str, Any] = Field(default_factory=dict)
    operator_context: str | None = Field(default=None, max_length=4000)
    route_purpose: str = Field(
        default="investigation",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    actor: str = Field(min_length=1, max_length=255)
