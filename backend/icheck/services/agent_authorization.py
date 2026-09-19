from __future__ import annotations

from collections.abc import Iterable

from ..models import AgentToolRegistration, Investigation


def permission_snapshot_allows(
    investigation: Investigation,
    required_permissions: Iterable[str],
) -> bool:
    snapshot = set(investigation.permission_snapshot or [])
    return "*" in snapshot or all(
        permission in snapshot for permission in required_permissions
    )


def require_tool_permissions(
    investigation: Investigation,
    tool: AgentToolRegistration,
) -> None:
    if not permission_snapshot_allows(
        investigation,
        tool.required_permissions or [],
    ):
        raise PermissionError(
            "Investigation permission snapshot does not authorize this tool"
        )
