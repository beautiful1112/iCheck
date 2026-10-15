from __future__ import annotations

import json
from urllib.error import HTTPError

import pytest
from sqlalchemy import select

from icheck.agent_runtime_protocol import RemoteToolExecutor
from icheck.database import SessionLocal
from icheck.models import (
    AgentToolRegistration,
    Alert,
    AlertStatus,
    MCPOAuthScopeChallenge,
    MCPServer,
    MCPToolActivation,
)
from icheck.services.agent_remote_runtime import DelegatedMCPRuntime
from icheck.services.mcp_gateway import (
    MCPGatewayError,
    mcp_tool_available_for_investigation,
)
from icheck.services.mcp_scope_challenges import (
    MCPInsufficientScopeError,
    parse_insufficient_scope_challenge,
    resolve_mcp_scope_challenges,
)

from test_mcp_gateway import (
    BASE_SPEC,
    FakeMCPOpener,
    _attest_tool,
    _configure_investigation,
    _credential_profile,
    _publish_tool,
    _runtime,
    _server,
    _tool_advertisement,
)


RESOURCE_METADATA_URL = (
    "https://mcp.example.test/.well-known/oauth-protected-resource/rpc"
)


class InsufficientScopeMCPCallOpener(FakeMCPOpener):
    def open(self, request, timeout):
        document = json.loads(request.data.decode("utf-8"))
        if document["method"] == "tools/call":
            raise HTTPError(
                request.full_url,
                403,
                "Forbidden",
                {
                    "WWW-Authenticate": (
                        'Bearer error="insufficient_scope", '
                        'scope="network:diagnose", '
                        f'resource_metadata="{RESOURCE_METADATA_URL}"'
                    )
                },
                None,
            )
        return super().open(request, timeout)


def test_insufficient_scope_parser_is_typed_and_fail_closed():
    parsed = parse_insufficient_scope_challenge(
        403,
        {
            "WWW-Authenticate": (
                'Bearer error="insufficient_scope", '
                'scope="network:diagnose network:read network:diagnose", '
                f'resource_metadata="{RESOURCE_METADATA_URL}"'
            )
        },
    )
    assert parsed == MCPInsufficientScopeError(
        required_scopes=("network:diagnose", "network:read"),
        resource_metadata_url=RESOURCE_METADATA_URL,
    )
    assert parse_insufficient_scope_challenge(
        401,
        {
            "WWW-Authenticate": (
                'Bearer error="insufficient_scope", scope="network:diagnose"'
            )
        },
    ) is None
    assert parse_insufficient_scope_challenge(
        403,
        {"WWW-Authenticate": 'Bearer error="invalid_token"'},
    ) is None
    assert parse_insufficient_scope_challenge(
        403,
        {"WWW-Authenticate": 'Basic error="insufficient_scope"'},
    ) is None
    assert parse_insufficient_scope_challenge(
        403,
        {"WWW-Authenticate": 'Bearer error="insufficient_scope", scope=""'},
    ) is None


def test_worker_protocol_returns_only_bounded_scope_challenge(monkeypatch):
    class ScopeClient:
        request_dispatched = False
        def __init__(self, *_args, **_kwargs):
            pass

        def call_tool(self, *_args, **_kwargs):
            raise MCPInsufficientScopeError(
                required_scopes=("network:diagnose",),
                resource_metadata_url=RESOURCE_METADATA_URL,
            )

    monkeypatch.setattr(
        "icheck.agent_runtime_protocol.MCPHTTPClient",
        ScopeClient,
    )
    executor = RemoteToolExecutor(
        client=None,
        execution_id="execution",
        lease_token="lease-token",
        mcp_allowed_hosts=["mcp.example.test"],
    )
    result = executor._run_mcp(
        {
            "invocation_id": "a" * 64,
            "endpoint": "https://mcp.example.test/rpc",
            "mcp_tool_name": "lookup_dns_record",
            "arguments": {"name": "router.example.test"},
            "output_schema": BASE_SPEC["output_schema"],
            "read_only": True,
            "tool_call_id": "scope-test-call",
            "metadata": {"icheck/toolCallId": "scope-test-call"},
        }
    )
    assert result == {
        "kind": "mcp_result",
        "invocation_id": "a" * 64,
        "status": "scope_required",
        "required_scopes": ["network:diagnose"],
        "resource_metadata_url": RESOURCE_METADATA_URL,
    }


def test_dispatched_write_scope_challenge_requires_reconciliation(monkeypatch):
    class ScopeAfterDispatchClient:
        request_dispatched = True

        def __init__(self, *_args, **_kwargs):
            pass

        def call_tool(self, *_args, **_kwargs):
            raise MCPInsufficientScopeError(
                required_scopes=("network:change",),
                resource_metadata_url=RESOURCE_METADATA_URL,
            )

    monkeypatch.setattr("icheck.agent_runtime_protocol.MCPHTTPClient", ScopeAfterDispatchClient)
    executor = RemoteToolExecutor(
        client=None, execution_id="execution", lease_token="lease-token",
        mcp_allowed_hosts=["mcp.example.test"],
    )
    result = executor._run_mcp({
        "invocation_id": "b" * 64,
        "endpoint": "https://mcp.example.test/rpc",
        "mcp_tool_name": "flush_dns_cache",
        "arguments": {"name": "router.example.test"},
        "output_schema": BASE_SPEC["output_schema"],
        "read_only": False,
        "tool_call_id": "write-scope-call",
        "metadata": {"icheck/toolCallId": "write-scope-call"},
    })
    assert result == {"kind": "mcp_result", "invocation_id": "b" * 64,
        "status": "outcome_unknown"}


def test_local_and_delegated_runtime_persist_scope_step_up_without_opening_circuit(
    client,
    monkeypatch,
):
    version_id = _publish_tool(client)
    profile = _credential_profile(client)
    server_document = _server(client, profile["id"])
    advertised = [_tool_advertisement(BASE_SPEC)]
    healthy_opener = FakeMCPOpener(advertised)
    monkeypatch.setattr(
        "icheck.services.mcp_gateway.build_opener",
        lambda *_handlers: healthy_opener,
    )
    checked = client.post(
        f"/api/v1/mcp/servers/{server_document['id']}/check"
    )
    assert checked.status_code == 200, checked.text
    attestation = _attest_tool(
        client,
        server_document,
        version_id,
        healthy_opener,
    )
    activated = client.post(
        f"/api/v1/mcp/servers/{server_document['id']}/activations",
        json={
            "artifact_version_id": version_id,
            "attestation_id": attestation["id"],
            "canary_percent": 100,
            "circuit_failure_threshold": 1,
            "reason": "Exercise governed runtime scope escalation.",
            "actor": "platform.approver",
        },
    )
    assert activated.status_code == 201, activated.text
    investigation_id = _configure_investigation(client)
    scope_opener = InsufficientScopeMCPCallOpener(advertised)

    with SessionLocal() as db:
        server = db.get(MCPServer, server_document["id"])
        assert server is not None
        server.auth_mode = "oauth_authorization_code"
        server.oauth_status = "connected"
        server.oauth_requested_scopes = ["network:read"]
        server.oauth_granted_scopes = ["network:read"]
        db.commit()

        investigation, worker, execution, local_runtime = _runtime(
            db,
            investigation_id,
            scope_opener,
        )
        tool = db.scalar(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name == BASE_SPEC["tool_name"]
            )
        )
        assert tool is not None
        with pytest.raises(MCPGatewayError, match="operator-approved"):
            local_runtime.execute(
                db,
                tool,
                {"name": "router.example.test"},
                investigation=investigation,
                tool_call_id="local-scope-call",
            )
        db.commit()

        challenge = db.scalar(
            select(MCPOAuthScopeChallenge).where(
                MCPOAuthScopeChallenge.status == "pending"
            )
        )
        assert challenge is not None
        assert challenge.challenged_scopes == ["network:diagnose"]
        assert set(challenge.requested_scopes) == {
            "network:read",
            "network:diagnose",
        }
        assert challenge.resource_metadata_url == RESOURCE_METADATA_URL
        activation = db.get(MCPToolActivation, activated.json()["id"])
        assert activation is not None
        assert activation.failed_calls == 0
        assert activation.consecutive_failures == 0
        assert activation.circuit_state == "closed"
        assert tool.enabled is True
        assert mcp_tool_available_for_investigation(
            db,
            tool.id,
            investigation.id,
        ) is False
        alert = db.scalar(
            select(Alert).where(Alert.event_type == "mcp.oauth.scope.required")
        )
        assert alert is not None
        assert alert.status == AlertStatus.OPEN
        resolve_mcp_scope_challenges(
            db,
            server=server,
            granted_scopes=["network:read", "network:diagnose"],
            actor="platform.approver",
        )
        db.commit()
        db.refresh(challenge)
        db.refresh(alert)
        assert challenge.status == "resolved"
        assert alert.status == AlertStatus.RESOLVED
        assert alert.resolved_by == "platform.approver"

        def scope_interrupt(payload):
            return {
                "kind": "mcp_result",
                "invocation_id": payload["invocation_id"],
                "status": "scope_required",
                "required_scopes": ["network:admin"],
                "resource_metadata_url": RESOURCE_METADATA_URL,
            }

        monkeypatch.setattr(
            "icheck.services.agent_remote_runtime.interrupt",
            scope_interrupt,
        )
        delegated_runtime = DelegatedMCPRuntime(
            worker=worker,
            execution=execution,
            allowed_hosts=["mcp.example.test"],
        )
        from icheck.agent_schemas import InvestigationToolCallCreate
        from icheck.services.agent_runtime import create_tool_call
        call = create_tool_call(db, investigation, InvestigationToolCallCreate(
            tool_id=tool.id, iteration=1, arguments={"name": "router.example.test"}))
        with pytest.raises(MCPGatewayError, match="operator-approved"):
            delegated_runtime.execute(
                db,
                tool,
                {"name": "router.example.test"},
                investigation=investigation,
                tool_call_id=call.id,
            )
        db.commit()
        delegated_challenge = db.scalar(
            select(MCPOAuthScopeChallenge).where(
                MCPOAuthScopeChallenge.status == "pending"
            )
        )
        assert delegated_challenge is not None
        assert delegated_challenge.challenged_scopes == ["network:admin"]
        db.refresh(activation)
        assert activation.failed_calls == 0
        assert activation.circuit_state == "closed"

    listed = client.get("/api/v1/mcp/oauth/scope-challenges?limit=10")
    assert listed.status_code == 200, listed.text
    assert {item["status"] for item in listed.json()} == {
        "pending",
        "resolved",
    }
