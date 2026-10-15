"""Freeze governed Tool identity before execution; legacy calls remain unbound."""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AgentToolRegistration, ArtifactVersion, ArtifactVersionStatus,
    Investigation, InvestigationToolCall, MCPToolActivation,
)


def tool_artifact_provenance(db: Session, tool: AgentToolRegistration) -> dict:
    if tool.transport != "mcp":
        return {}
    namespace = (tool.tenant_id, tool.region_id)
    activations = db.scalars(select(MCPToolActivation).where(
        MCPToolActivation.tool_registration_id == tool.id,
        MCPToolActivation.status == "active",
        MCPToolActivation.tenant_id == namespace[0],
        MCPToolActivation.region_id == namespace[1],
    ).limit(2)).all()
    if not activations:
        return {}  # Ungoverned registrations cannot contribute versioned quality.
    if len(activations) != 1:
        raise ValueError("Tool has ambiguous active Artifact provenance")
    activation = activations[0]
    version = db.scalar(select(ArtifactVersion).where(
        ArtifactVersion.id == activation.artifact_version_id,
        ArtifactVersion.tenant_id == namespace[0], ArtifactVersion.region_id == namespace[1],
    ))
    if (version is None or version.status != ArtifactVersionStatus.PUBLISHED
        or not re.fullmatch(r"[0-9a-f]{64}", version.content_hash or "")
        or not re.fullmatch(r"[0-9a-f]{64}", activation.contract_sha256 or "")):
        raise ValueError("Tool Artifact provenance is unavailable")
    return {
        "artifact_version_id": version.id,
        "artifact_content_hash": version.content_hash,
        "artifact_activation_id": activation.id,
        "artifact_activation_sha256": activation.contract_sha256,
    }


def assert_tool_execution_provenance(
    db: Session, investigation: Investigation, tool: AgentToolRegistration,
    arguments: dict, activation: MCPToolActivation, version: ArtifactVersion,
) -> None:
    calls = list(db.scalars(select(InvestigationToolCall).where(
        InvestigationToolCall.investigation_id == investigation.id,
        InvestigationToolCall.tool_id == tool.id,
        InvestigationToolCall.status == "running",
        InvestigationToolCall.tenant_id == investigation.tenant_id,
        InvestigationToolCall.region_id == investigation.region_id,
    ).limit(33)).all())
    matching = [call for call in calls if call.arguments == arguments]
    if len(calls) > 32 or len(matching) > 1:
        raise ValueError("Tool execution has ambiguous running-call provenance")
    call = matching[0] if matching else None
    # Existing checkpoints and direct adapter tests have no new pin. Never
    # backfill them from the current activation or count them as quality proof.
    if call is None or call.artifact_version_id is None:
        return
    namespace = (investigation.tenant_id, investigation.region_id)
    # The handler may share a long-lived, expire_on_commit=False runtime session.
    # Refresh the actual activation/version; an identity-map hit is not evidence
    # that an intervening upgrade or quarantine did not occur.
    current_activation = db.scalar(select(MCPToolActivation).where(
        MCPToolActivation.id == activation.id, MCPToolActivation.status == "active",
        MCPToolActivation.tool_registration_id == tool.id,
        MCPToolActivation.tenant_id == namespace[0], MCPToolActivation.region_id == namespace[1],
    ).execution_options(populate_existing=True))
    current_version = db.scalar(select(ArtifactVersion).where(
        ArtifactVersion.id == version.id, ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
        ArtifactVersion.tenant_id == namespace[0], ArtifactVersion.region_id == namespace[1],
    ).execution_options(populate_existing=True))
    if (
        current_activation is None or current_version is None
        or any((row.tenant_id, row.region_id) != namespace for row in (tool, activation, version))
        or current_activation.artifact_version_id != version.id
        or call.artifact_version_id != version.id
        or call.artifact_content_hash != version.content_hash
        or call.artifact_activation_id != activation.id
        or call.artifact_activation_sha256 != activation.contract_sha256
    ):
        raise ValueError("Tool Artifact provenance changed before execution")
