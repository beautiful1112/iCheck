from __future__ import annotations

import hashlib
from typing import Any

from langgraph.types import interrupt
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..agent_schemas import (
    InvestigationEvidenceCreate,
    InvestigationToolCallComplete,
    InvestigationToolCallCreate,
)
from ..langgraph_runtime import (
    GraphToolRequest,
    GraphToolResult,
    InvestigationGraphState,
)
from ..models import (
    Alert,
    AlertSeverity,
    AlertStatus,
    AgentToolRegistration,
    Device,
    DeviceConnection,
    Endpoint,
    EndpointAttachment,
    IPAddressObservation,
    Investigation,
    WirelessClientSession,
)
from ..metric_schemas import PrometheusInstantQuery
from ..schemas import normalize_ip, normalize_mac
from .agent_runtime import (
    add_evidence_reference,
    complete_tool_call,
    create_tool_call,
)
from .metrics import get_metric_backend, query_instant


def _get_device(
    db: Session,
    arguments: dict[str, Any],
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    device = db.scalar(
        select(Device)
        .where(Device.id == arguments["device_id"])
        .options(
            selectinload(Device.connections).selectinload(
                DeviceConnection.activation
            )
        )
    )
    if device is None:
        raise LookupError("Device not found")
    result = {
        "id": device.id,
        "name": device.name,
        "kind": device.kind,
        "management_ip": device.management_ip,
        "site": device.site,
        "onboarding_status": device.onboarding_status,
        "connections": [
            {
                "id": connection.id,
                "protocol": connection.protocol,
                "verification_status": connection.verification_status,
                "activation_status": (
                    connection.activation.status if connection.activation else None
                ),
                "runtime_status": (
                    connection.activation.runtime_status
                    if connection.activation
                    else None
                ),
                "health_reason": (
                    connection.activation.health_reason
                    if connection.activation
                    else None
                ),
            }
            for connection in device.connections[:32]
        ],
    }
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="device",
            evidence_id=device.id,
            summary=(
                f"Device {device.name} is {device.onboarding_status} with "
                f"{len(device.connections)} monitoring connection(s)."
            ),
            observed_at=device.updated_at,
        )
    ]


def _list_open_alerts(
    db: Session,
    arguments: dict[str, Any],
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    limit = int(arguments.get("limit", 20))
    query = select(Alert).where(
        Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED])
    )
    severity = arguments.get("severity")
    if severity:
        query = query.where(Alert.severity == AlertSeverity(severity))
    alerts = list(
        db.scalars(
            query.order_by(Alert.last_seen.desc(), Alert.id).limit(limit)
        ).all()
    )
    result = {
        "alerts": [
            {
                "id": alert.id,
                "severity": alert.severity.value,
                "status": alert.status.value,
                "title": alert.title,
                "entity_type": alert.entity_type,
                "entity_id": alert.entity_id,
                "last_seen": alert.last_seen.isoformat(),
                "occurrence_count": alert.occurrence_count,
            }
            for alert in alerts
        ]
    }
    evidence = [
        InvestigationEvidenceCreate(
            evidence_type="alert",
            evidence_id=alert.id,
            summary=(
                f"{alert.severity.value} alert {alert.title!r} is "
                f"{alert.status.value}."
            ),
            observed_at=alert.last_seen,
        )
        for alert in alerts
    ]
    return result, evidence


def _endpoint_from_selector(
    db: Session,
    arguments: dict[str, Any],
) -> Endpoint:
    selectors = [
        key
        for key in ("endpoint_id", "mac_address", "ip_address")
        if arguments.get(key)
    ]
    if len(selectors) != 1:
        raise ValueError(
            "Exactly one of endpoint_id, mac_address, or ip_address is required"
        )
    selector = selectors[0]
    if selector == "endpoint_id":
        endpoint = db.get(Endpoint, arguments[selector])
    elif selector == "mac_address":
        endpoint = db.scalar(
            select(Endpoint).where(
                Endpoint.mac_address == normalize_mac(arguments[selector])
            )
        )
    else:
        address = normalize_ip(arguments[selector])
        endpoint_ids = list(
            db.scalars(
                select(Endpoint.id)
                .join(IPAddressObservation)
                .where(IPAddressObservation.ip_address == address)
                .distinct()
                .limit(2)
            ).all()
        )
        if len(endpoint_ids) > 1:
            raise ValueError(
                "IP address matches multiple historical endpoints; use a MAC "
                "address or endpoint ID"
            )
        endpoint = db.get(Endpoint, endpoint_ids[0]) if endpoint_ids else None
    if endpoint is None:
        raise LookupError("Endpoint not found")
    return endpoint


def _get_endpoint_history(
    db: Session,
    arguments: dict[str, Any],
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    endpoint = _endpoint_from_selector(db, arguments)
    limit = int(arguments.get("limit", 50))
    ip_history = list(
        db.scalars(
            select(IPAddressObservation)
            .where(IPAddressObservation.endpoint_id == endpoint.id)
            .order_by(
                IPAddressObservation.active.desc(),
                IPAddressObservation.last_seen.desc(),
                IPAddressObservation.id,
            )
            .limit(limit)
        ).all()
    )
    wired_history = list(
        db.scalars(
            select(EndpointAttachment)
            .where(EndpointAttachment.endpoint_id == endpoint.id)
            .order_by(
                EndpointAttachment.active.desc(),
                EndpointAttachment.last_seen.desc(),
                EndpointAttachment.id,
            )
            .limit(limit)
        ).all()
    )
    wireless_history = list(
        db.scalars(
            select(WirelessClientSession)
            .where(WirelessClientSession.endpoint_id == endpoint.id)
            .order_by(
                WirelessClientSession.active.desc(),
                WirelessClientSession.last_seen.desc(),
                WirelessClientSession.id,
            )
            .limit(limit)
        ).all()
    )
    result = {
        "id": endpoint.id,
        "mac_address": endpoint.mac_address,
        "hostname": endpoint.hostname,
        "vendor": endpoint.vendor,
        "first_seen": endpoint.first_seen.isoformat(),
        "last_seen": endpoint.last_seen.isoformat(),
        "ip_history": [
            {
                "address": item.ip_address,
                "source": item.source.value,
                "collector_device_id": item.collector_device_id,
                "vlan_id": item.vlan_id,
                "active": item.active,
                "first_seen": item.first_seen.isoformat(),
                "last_seen": item.last_seen.isoformat(),
            }
            for item in ip_history
        ],
        "wired_history": [
            {
                "source": item.source.value,
                "collector_device_id": item.collector_device_id,
                "interface_name": item.interface_name,
                "vlan_id": item.vlan_id,
                "active": item.active,
                "first_seen": item.first_seen.isoformat(),
                "last_seen": item.last_seen.isoformat(),
            }
            for item in wired_history
        ],
        "wireless_history": [
            {
                "controller_id": item.controller_id,
                "ip_address": item.ip_address,
                "access_point": item.access_point,
                "ssid": item.ssid,
                "band": item.band,
                "channel": item.channel,
                "vlan_id": item.vlan_id,
                "rssi": item.rssi,
                "snr": item.snr,
                "active": item.active,
                "connected_at": (
                    item.connected_at.isoformat() if item.connected_at else None
                ),
                "disconnected_at": (
                    item.disconnected_at.isoformat()
                    if item.disconnected_at
                    else None
                ),
                "first_seen": item.first_seen.isoformat(),
                "last_seen": item.last_seen.isoformat(),
            }
            for item in wireless_history
        ],
    }
    return result, [
        InvestigationEvidenceCreate(
            evidence_type="endpoint",
            evidence_id=endpoint.id,
            summary=(
                f"Endpoint {endpoint.mac_address} has {len(ip_history)} IP, "
                f"{len(wired_history)} wired, and {len(wireless_history)} "
                "wireless history record(s) in this bounded result."
            ),
            observed_at=endpoint.last_seen,
        )
    ]


def _query_instant_metrics(
    db: Session,
    arguments: dict[str, Any],
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    backend = get_metric_backend(db, arguments["backend_id"])
    query = arguments["query"]
    result = query_instant(
        db,
        backend,
        PrometheusInstantQuery(
            query=query,
            time=arguments.get("time"),
            timeout_seconds=int(arguments.get("timeout_seconds", 10)),
            limit=int(arguments.get("limit", 100)),
            actor="agent.runtime",
        ),
    )
    query_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()
    series_count = len(result.result) if isinstance(result.result, list) else 1
    return result.model_dump(mode="json"), [
        InvestigationEvidenceCreate(
            evidence_type="metric_query",
            evidence_id=f"{backend.id}:{query_hash}",
            summary=(
                f"Instant metric query against {backend.name!r} returned "
                f"{series_count} {result.result_type} result item(s); query "
                f"SHA-256 is {query_hash}."
            ),
            observed_at=result.queried_at,
        )
    ]


INTERNAL_HANDLERS = {
    "inventory.get_device": _get_device,
    "alerts.list_open": _list_open_alerts,
    "inventory.get_endpoint_history": _get_endpoint_history,
    "metrics.query_instant": _query_instant_metrics,
}


def execute_internal_tool(
    db: Session,
    tool: AgentToolRegistration,
    arguments: dict[str, Any],
) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
    if tool.transport != "internal":
        raise RuntimeError("MCP tool execution requires the future MCP gateway")
    handler = INTERNAL_HANDLERS.get(tool.handler)
    if handler is None:
        raise RuntimeError(f"Internal tool handler {tool.handler!r} is unavailable")
    return handler(db, arguments)


class DatabaseToolExecutor:
    def __init__(self, db: Session, investigation: Investigation):
        self.db = db
        self.investigation = investigation

    def __call__(
        self,
        request: GraphToolRequest,
        state: InvestigationGraphState,
    ) -> GraphToolResult:
        tool = self.db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == request.tool_name
            )
        )
        if tool is None:
            raise LookupError(f"Agent tool {request.tool_name!r} not found")
        if tool.transport != "internal" or tool.handler not in INTERNAL_HANDLERS:
            raise ValueError(
                f"Agent tool {request.tool_name!r} is not executable by this worker"
            )
        from .agent_authorization import require_tool_permissions

        require_tool_permissions(self.investigation, tool)
        if not tool.read_only:
            from .agent_approvals import (
                finish_action_proposal,
                propose_action,
                validate_resumed_action,
            )
            proposal = propose_action(
                self.db,
                self.investigation,
                tool,
                iteration=state["iteration"],
                arguments=request.arguments,
                purpose=request.purpose,
            )
            resume_value = interrupt(
                {
                    "kind": "action_approval",
                    "proposal_id": proposal.id,
                    "investigation_id": self.investigation.id,
                    "tool_name": tool.name,
                    "purpose": proposal.purpose,
                    "arguments": proposal.arguments,
                    "plan_hash": proposal.plan_hash,
                }
            )
            if not isinstance(resume_value, dict) or not isinstance(
                resume_value.get("proposal_id"), str
            ):
                raise ValueError("Approval resume payload is invalid")
            proposal = validate_resumed_action(
                self.db,
                resume_value["proposal_id"],
                investigation=self.investigation,
                tool=tool,
                arguments=request.arguments,
                purpose=request.purpose,
            )
            call = create_tool_call(
                self.db,
                self.investigation,
                InvestigationToolCallCreate(
                    tool_id=tool.id,
                    iteration=state["iteration"],
                    arguments=request.arguments,
                ),
                approved_proposal=proposal,
            )
            try:
                result, evidence_payloads = execute_internal_tool(
                    self.db,
                    tool,
                    request.arguments,
                )
                evidence_ids = [
                    add_evidence_reference(
                        self.db,
                        self.investigation,
                        evidence_payload,
                    ).id
                    for evidence_payload in evidence_payloads
                ]
                complete_tool_call(
                    self.db,
                    call,
                    InvestigationToolCallComplete(
                        status="succeeded",
                        result=result,
                    ),
                )
                finish_action_proposal(self.db, proposal, call=call)
                return GraphToolResult(
                    call_id=call.id,
                    tool_name=tool.name,
                    arguments=request.arguments,
                    status="succeeded",
                    result=result,
                    evidence_ids=evidence_ids,
                )
            except Exception as exc:
                complete_tool_call(
                    self.db,
                    call,
                    InvestigationToolCallComplete(
                        status="failed",
                        error=str(exc)[:10_000],
                    ),
                )
                finish_action_proposal(
                    self.db,
                    proposal,
                    call=call,
                    error=str(exc)[:10_000],
                )
                return GraphToolResult(
                    call_id=call.id,
                    tool_name=tool.name,
                    arguments=request.arguments,
                    status="failed",
                    error=str(exc)[:10_000],
                )
        call = create_tool_call(
            self.db,
            self.investigation,
            InvestigationToolCallCreate(
                tool_id=tool.id,
                iteration=state["iteration"],
                arguments=request.arguments,
            ),
        )
        try:
            result, evidence_payloads = execute_internal_tool(
                self.db,
                tool,
                request.arguments,
            )
            evidence_ids = [
                add_evidence_reference(
                    self.db,
                    self.investigation,
                    evidence_payload,
                ).id
                for evidence_payload in evidence_payloads
            ]
            complete_tool_call(
                self.db,
                call,
                InvestigationToolCallComplete(
                    status="succeeded",
                    result=result,
                ),
            )
            return GraphToolResult(
                call_id=call.id,
                tool_name=tool.name,
                arguments=request.arguments,
                status="succeeded",
                result=result,
                evidence_ids=evidence_ids,
            )
        except Exception as exc:
            complete_tool_call(
                self.db,
                call,
                InvestigationToolCallComplete(
                    status="failed",
                    error=str(exc)[:10_000],
                ),
            )
            return GraphToolResult(
                call_id=call.id,
                tool_name=tool.name,
                arguments=request.arguments,
                status="failed",
                error=str(exc)[:10_000],
            )
