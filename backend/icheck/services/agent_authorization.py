from __future__ import annotations

from collections.abc import Iterable
from fastapi import HTTPException

from ..database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID
from ..models import AgentToolRegistration, Investigation
from .control_plane_auth import PrincipalContext
from ..grafana_tools import GRAFANA_TOOLS
from ..metric_alert_tools import METRIC_ALERT_TOOLS
from ..research_tools import RESEARCH_TOOLS


# Runtime-owned scope requirements apply even if a caller registers another
# Tool name for the same internal handler. They cannot be waived by model input.
GRAFANA_HANDLERS = frozenset(tool["name"] for tool in GRAFANA_TOOLS)
METRIC_ALERT_HANDLERS = frozenset(tool["name"] for tool in METRIC_ALERT_TOOLS)
RESEARCH_HANDLERS = frozenset(tool["name"] for tool in RESEARCH_TOOLS)
NAMESPACE_WIDE_INTERNAL_HANDLERS = frozenset({"quality.get_execution_health", "quality.get_remediation_outcomes"}) | GRAFANA_HANDLERS | METRIC_ALERT_HANDLERS
SITUATION_REVIEWED_HANDLERS = frozenset({"situations.get_recovery_evidence", "situations.close_reviewed"})
SOURCE_REPLACEMENT_HANDLERS = frozenset({"collector_sources.get_replacement",
    "collector_sources.propose_replacement", "collector_sources.apply_reviewed_replacement"})
OWNED_SOURCE_REPLACEMENT_HANDLERS = SOURCE_REPLACEMENT_HANDLERS - {"collector_sources.get_replacement"}


def assert_source_replacement_tool_contract(tool):
    if tool.name in SOURCE_REPLACEMENT_HANDLERS and tool.handler != tool.name:
        raise PermissionError("Reserved source replacement Tool cannot substitute a handler")
    if tool.handler not in SOURCE_REPLACEMENT_HANDLERS:
        return
    writing = tool.handler in OWNED_SOURCE_REPLACEMENT_HANDLERS
    if (tool.transport != "internal" or tool.read_only is writing or tool.change_contract is not None
        or tool.risk_level != ("change" if writing else "diagnose")):
        raise PermissionError("Source replacement Tool has an invalid owned control-plane contract")


def source_replacement_permissions(tool):
    required = ["alerts.read", "capabilities.read"]
    if tool.handler == "collector_sources.propose_replacement": required.append("alerts.manage")
    if tool.handler == "collector_sources.apply_reviewed_replacement": required.append("alerts.sources.replace")
    return required


def assert_reviewed_situation_tool_contract(tool) -> None:
    if tool.name in SITUATION_REVIEWED_HANDLERS and tool.handler != tool.name:
        raise PermissionError("Reserved reviewed Situation Tool name cannot substitute a handler")
    if tool.handler not in SITUATION_REVIEWED_HANDLERS:
        return
    closing = tool.handler == "situations.close_reviewed"
    if (tool.transport != "internal" or tool.read_only is closing or tool.change_contract is not None
        or tool.risk_level != ("change" if closing else "diagnose")):
        raise PermissionError("Reviewed Situation handler has an invalid runtime-owned control-plane contract")


def tool_advertisement_allows(investigation, tool) -> bool:
    """Hide unavailable owned contexts; historical runtime recovery stays separate."""
    if not tool_scope_allows(investigation, tool):
        return False
    if (tool.name in GRAFANA_HANDLERS or tool.handler in GRAFANA_HANDLERS
            or tool.name == "metrics.backends.list" or tool.handler == "metrics.backends.list"):
        try:
            require_tool_permissions(investigation, tool)
        except (PermissionError, ValueError, HTTPException):
            return False
        return True
    if tool.name == "inventory.enroll_devices" or tool.handler == "inventory.enroll_devices":
        try:
            require_tool_permissions(investigation, tool)
        except (PermissionError, ValueError, HTTPException):
            return False
        return True
    if tool.handler in SOURCE_REPLACEMENT_HANDLERS or tool.name in SOURCE_REPLACEMENT_HANDLERS:
        try: assert_source_replacement_tool_contract(tool)
        except PermissionError: return False
        if not investigation.requested_by_principal_id: return False
        if tool.handler == "collector_sources.apply_reviewed_replacement":
            from ..config import get_settings
            if not get_settings().enable_reviewed_source_replacement: return False
        return permission_snapshot_allows(investigation, source_replacement_permissions(tool))
    if tool.handler not in SITUATION_REVIEWED_HANDLERS and tool.name not in SITUATION_REVIEWED_HANDLERS:
        return True
    try:
        assert_reviewed_situation_tool_contract(tool)
    except PermissionError:
        return False
    if not investigation.requested_by_principal_id:
        return False
    permissions = ["alerts.read"]
    if tool.handler == "situations.close_reviewed":
        from ..config import get_settings
        if not investigation.situation_id or not get_settings().enable_reviewed_situation_closure:
            return False
        permissions.append("situations.close")
    return permission_snapshot_allows(investigation, permissions)


def tool_scope_allows(investigation: Investigation, tool: AgentToolRegistration) -> bool:
    if getattr(investigation, "execution_mode", "standard") == "diagnose" and (
        not tool.read_only or tool.risk_level == "change" or tool.change_contract is not None
    ):
        return False
    if (getattr(investigation, "scope", None) or {}).get("capability_task") == "grafana-dashboard":
        allowed = GRAFANA_HANDLERS | RESEARCH_HANDLERS | {"metrics.backends.list", "metrics.query_instant", "metrics.query_range", "metrics.get_device_range"}
        if tool.transport != "internal" or tool.handler not in allowed or not tool.read_only or tool.change_contract is not None:
            return False
    return not (
        tool.transport == "internal" and tool.handler in NAMESPACE_WIDE_INTERNAL_HANDLERS
        and (investigation.authorization_scope or {}).get("all") is not True
    )


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
    from ..integration_tools import INTEGRATION_TOOLS
    integration_handlers = {item["name"] for item in INTEGRATION_TOOLS}
    if tool.name in integration_handlers or tool.handler in integration_handlers:
        if (tool.name != tool.handler or tool.transport != "internal" or not tool.read_only
                or tool.change_contract is not None
                or not permission_snapshot_allows(investigation, ["alerts.read", "assets.read", "metrics.read"])):
            raise PermissionError("External evidence requires its native scoped read-only contract")
    from ..autonomy_tools import AUTONOMY_TOOLS
    assistance = {item["name"] for item in AUTONOMY_TOOLS}
    if tool.name in assistance or tool.handler in assistance:
        if (tool.name != tool.handler or tool.transport != "internal" or not tool.read_only
                or tool.change_contract is not None or not permission_snapshot_allows(investigation, ["investigations.read"])):
            raise PermissionError("Investigation assistance requires its native read-only contract")
    if tool.name in RESEARCH_HANDLERS and tool.handler != tool.name:
        raise PermissionError("Reserved research Tool cannot substitute a handler")
    if tool.handler in RESEARCH_HANDLERS and (tool.transport != "internal" or not tool.read_only
            or tool.change_contract is not None or not permission_snapshot_allows(investigation, ["investigations.read"])):
        raise PermissionError("Research requires its native public-reference-only contract")
    if not tool_scope_allows(investigation, tool):
        raise PermissionError("Investigation task or scope does not authorize this Tool")
    if tool.name == "metrics.backends.list" and tool.handler != tool.name:
        raise PermissionError("Reserved metric discovery Tool cannot substitute its handler")
    if tool.handler == "metrics.backends.list" and (tool.transport != "internal" or not tool.read_only
            or tool.change_contract is not None or not permission_snapshot_allows(investigation, ["metrics.read"])):
        raise PermissionError("Metric backend discovery requires its native read-only metrics.read contract")
    if tool.name in GRAFANA_HANDLERS and tool.handler != tool.name:
        raise PermissionError("Reserved Grafana Tool cannot substitute its handler")
    if tool.handler in GRAFANA_HANDLERS and (tool.transport != "internal" or not tool.read_only
            or tool.change_contract is not None or not permission_snapshot_allows(investigation, ["metrics.read"])):
        raise PermissionError("Grafana Tools must use their native read/propose contract; confirmation is human-owned")
    if tool.name == "inventory.enroll_devices" and tool.handler != tool.name:
        raise PermissionError("Reserved enrollment Tool cannot substitute its handler")
    if tool.handler == "inventory.enroll_devices":
        if (tool.name != tool.handler or tool.transport != "internal" or tool.read_only
                or tool.risk_level != "change" or tool.change_contract is not None):
            raise PermissionError("Direct enrollment requires its runtime-owned change contract")
        from .conversational_onboarding import authorized_input
        authorized_input(investigation)
    if tool.name == "platform.diagnose_ai_runtime" and tool.handler != tool.name:
        raise PermissionError("Reserved runtime diagnosis Tool cannot substitute its handler")
    if tool.handler == "platform.diagnose_ai_runtime" and (tool.transport != "internal" or not tool.read_only
            or not permission_snapshot_allows(investigation, ["investigations.read"])):
        raise PermissionError("Runtime diagnosis requires its read-only investigation permission")
    onboarding_handlers = {"inventory.find_devices", "credentials.list_device_profiles", "inventory.preview_onboarding", "inventory.preview_activation"}
    if tool.name in onboarding_handlers and tool.handler != tool.name:
        raise PermissionError("Reserved device onboarding Tool cannot substitute a handler")
    if tool.handler in onboarding_handlers:
        required = ["assets.activate"] if tool.handler == "inventory.preview_activation" else ["assets.read"]
        if tool.transport != "internal" or not tool.read_only or not permission_snapshot_allows(investigation, required):
            raise PermissionError("Device onboarding preview requires its runtime-owned read-only permissions")
    assert_reviewed_situation_tool_contract(tool)
    assert_source_replacement_tool_contract(tool)
    if tool.handler in SOURCE_REPLACEMENT_HANDLERS and (
        not investigation.requested_by_principal_id or
        not permission_snapshot_allows(investigation, source_replacement_permissions(tool))):
        raise PermissionError("Source replacement Tool requires a persisted initiating identity and owned snapshot permissions")
    if tool.handler in SITUATION_REVIEWED_HANDLERS and not permission_snapshot_allows(investigation,
        ["alerts.read", "situations.close"] if tool.handler == "situations.close_reviewed" else ["alerts.read"]):
        raise PermissionError("Reviewed Situation Tool requires its runtime-owned snapshot permissions")
    if not tool_scope_allows(investigation, tool):
        raise PermissionError("Investigation scope does not authorize this namespace-wide Tool")
    if not permission_snapshot_allows(
        investigation,
        tool.required_permissions or [],
    ):
        raise PermissionError(
            "Investigation permission snapshot does not authorize this tool"
        )


def investigation_principal(
    investigation: Investigation,
) -> PrincipalContext:
    return PrincipalContext(
        principal_id=investigation.requested_by_principal_id,
        subject=investigation.created_by,
        principal_type="investigation_snapshot",
        permissions=frozenset(investigation.permission_snapshot or []),
        role_names=("investigation-snapshot",),
        authorization_scope=dict(investigation.authorization_scope or {}),
        auth_method="investigation_snapshot",
        tenant_id=investigation.tenant_id or DEFAULT_TENANT_ID,
        region_id=investigation.region_id or DEFAULT_REGION_ID,
        tenant_slug=investigation.tenant_id or DEFAULT_TENANT_ID,
        region_code=investigation.region_id or DEFAULT_REGION_ID,
    )
