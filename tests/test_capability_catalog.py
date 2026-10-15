from __future__ import annotations

import hashlib
import json

from icheck.database import SessionLocal
from icheck.models import (
    AgentToolRegistration,
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    MCPServer,
    MCPToolActivation,
    utcnow,
)
from icheck.services.tool_skills import skill_artifact_documents
from icheck.studio_schemas import GeneratedSkillSpec

from test_mcp_gateway import BASE_SPEC, _publish_tool


def _hash(value):
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _activate_tool(version_id: str) -> str:
    with SessionLocal() as db:
        server = MCPServer(
            name=BASE_SPEC["mcp_server_name"],
            endpoint_url="https://mcp.example.test/rpc",
            enabled=True,
            created_by="platform.admin",
        )
        tool = AgentToolRegistration(
            name=BASE_SPEC["tool_name"],
            description=BASE_SPEC["description"],
            transport="mcp",
            handler=(
                f'{BASE_SPEC["mcp_server_name"]}/'
                f'{BASE_SPEC["mcp_tool_name"]}'
            ),
            input_schema=BASE_SPEC["input_schema"],
            output_schema=BASE_SPEC["output_schema"],
            risk_level=BASE_SPEC["risk_level"],
            read_only=True,
            required_permissions=BASE_SPEC["required_permissions"],
            timeout_seconds=BASE_SPEC["timeout_seconds"],
            max_result_bytes=BASE_SPEC["max_result_bytes"],
            enabled=True,
            created_by="capability.publisher",
        )
        db.add_all([server, tool])
        db.flush()
        activation = MCPToolActivation(
            server_id=server.id,
            artifact_version_id=version_id,
            tool_registration_id=tool.id,
            status="active",
            tool_name=tool.name,
            mcp_tool_name=BASE_SPEC["mcp_tool_name"],
            contract_sha256="a" * 64,
            input_schema_sha256=_hash(tool.input_schema),
            output_schema_sha256=_hash(tool.output_schema),
            activated_by="capability.publisher",
            activation_reason="Catalog acceptance test",
        )
        db.add(activation)
        db.commit()
        return tool.id


def _publish_declarative_report() -> None:
    with SessionLocal() as db:
        artifact = Artifact(
            name="weekly-capacity-report",
            kind=ArtifactKind.REPORT,
            description="Bounded weekly network capacity report.",
            owner="network.operations",
            labels={
                "tags": ["network", "capacity", "token-private"],
                "api_token": "must-never-leave-the-catalog",
            },
        )
        db.add(artifact)
        db.flush()
        db.add(
            ArtifactVersion(
                artifact_id=artifact.id,
                version=1,
                status=ArtifactVersionStatus.PUBLISHED,
                definition={"template": "weekly"},
                implementation={"runtime": "declarative"},
                tests=[],
                validation_report={"isolation": "not_executable"},
                content_hash="b" * 64,
                created_by="capability.author",
                published_by="capability.publisher",
                published_at=utcnow(),
            )
        )
        db.commit()


def _publish_skill_with_live_tool(tool_id: str) -> str:
    spec = GeneratedSkillSpec.model_validate(
        {
            "artifact_name": "dns-triage-skill",
            "skill_name": "dns.triage",
            "description": "Investigate DNS failures with bounded evidence.",
            "instructions": (
                "Look up the requested record, preserve the returned evidence, "
                "and explain whether resolution is healthy."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name"],
                "properties": {"name": {"type": "string"}},
            },
            "output_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["summary"],
                "properties": {"summary": {"type": "string"}},
            },
            "allowed_tools": [BASE_SPEC["tool_name"]],
            "success_criteria": ["DNS evidence is attached"],
            "escalation_conditions": ["The lookup tool is unavailable"],
            "evidence_required": True,
            "read_only": True,
            "max_iterations": 3,
            "max_tool_calls": 4,
            "max_total_tokens": 4000,
        }
    )
    with SessionLocal() as db:
        definition, implementation, tests = skill_artifact_documents(db, spec)
        report = tests[0]
        artifact = Artifact(
            name=spec.artifact_name,
            kind=ArtifactKind.SKILL,
            description=spec.description,
            owner="network.operations",
            labels={"tags": ["dns", "diagnostic"]},
        )
        db.add(artifact)
        db.flush()
        version = ArtifactVersion(
            artifact_id=artifact.id,
            version=1,
            status=ArtifactVersionStatus.PUBLISHED,
            definition=definition,
            implementation=implementation,
            tests=tests,
            validation_report={
                "tool_dependencies": report["tool_dependencies"],
                "required_permissions": BASE_SPEC["required_permissions"],
            },
            content_hash="c" * 64,
            created_by="capability.author",
            published_by="capability.publisher",
            published_at=utcnow(),
        )
        db.add(version)
        db.commit()
        version_id = version.id
    with SessionLocal() as db:
        assert db.get(AgentToolRegistration, tool_id) is not None
    return version_id


def test_catalog_projects_safe_runtime_readiness_and_filters(client):
    tool_version_id = _publish_tool(client)
    _publish_declarative_report()

    initial = client.get("/api/v1/capability-catalog?limit=500")
    assert initial.status_code == 200, initial.text
    document = initial.json()
    assert document["total"] == 2
    assert document["scan_truncated"] is False
    assert document["counts"] == {
        "ready": 0,
        "blocked": 1,
        "declarative": 1,
        "active": 0,
        "inactive": 1,
        "not_required": 1,
    }
    tool = next(item for item in document["items"] if item["kind"] == "tool")
    assert tool["artifact_version_id"] == tool_version_id
    assert tool["readiness"] == "blocked"
    assert tool["activation_state"] == "inactive"
    assert tool["blockers"] == ["activation_required"]
    assert tool["required_permissions"] == ["network.diagnostics.read"]
    serialized = json.dumps(document)
    assert "input_schema" not in serialized
    assert "must-never-leave-the-catalog" not in serialized
    assert "token-private" not in serialized

    filtered = client.get(
        "/api/v1/capability-catalog?kind=report&readiness=declarative&q=network"
    )
    assert filtered.status_code == 200, filtered.text
    assert filtered.json()["total"] == 1
    report = filtered.json()["items"][0]
    assert report["name"] == "weekly-capacity-report"
    assert report["tags"] == ["network", "capacity"]
    assert report["readiness"] == "declarative"
    assert report["activation_state"] == "not_required"

    assert client.get("/api/v1/capability-catalog?q=").status_code == 422
    assert client.get("/api/v1/capability-catalog?limit=501").status_code == 422


def test_catalog_detects_activation_health_and_skill_dependency_drift(client):
    tool_version_id = _publish_tool(client)
    tool_id = _activate_tool(tool_version_id)
    skill_version_id = _publish_skill_with_live_tool(tool_id)

    ready = client.get("/api/v1/capability-catalog?readiness=ready&limit=500")
    assert ready.status_code == 200, ready.text
    by_id = {
        item["artifact_version_id"]: item for item in ready.json()["items"]
    }
    assert by_id[tool_version_id]["activation_state"] == "active"
    assert by_id[tool_version_id]["dependency_count"] == 1
    assert by_id[skill_version_id]["activation_state"] == "not_required"
    assert by_id[skill_version_id]["dependency_count"] == 1

    with SessionLocal() as db:
        server = db.query(MCPServer).filter_by(
            name=BASE_SPEC["mcp_server_name"]
        ).one()
        server.protocol_version = "2025-01-01"
        db.commit()
    protocol_blocked = client.get(
        "/api/v1/capability-catalog?readiness=blocked&limit=500"
    )
    protocol_items = {
        item["artifact_version_id"]: item
        for item in protocol_blocked.json()["items"]
    }
    assert "mcp_protocol_unsupported" in protocol_items[tool_version_id]["blockers"]

    with SessionLocal() as db:
        server = db.query(MCPServer).filter_by(
            name=BASE_SPEC["mcp_server_name"]
        ).one()
        server.protocol_version = "2026-07-28"
        tool = db.get(AgentToolRegistration, tool_id)
        assert tool is not None
        tool.enabled = False
        db.commit()

    blocked = client.get("/api/v1/capability-catalog?readiness=blocked&limit=500")
    assert blocked.status_code == 200, blocked.text
    by_id = {
        item["artifact_version_id"]: item for item in blocked.json()["items"]
    }
    assert "tool_registration_disabled" in by_id[tool_version_id]["blockers"]
    assert by_id[skill_version_id]["blockers"] == ["dependency_drift"]


def test_catalog_paginates_after_readiness_projection(client):
    _publish_tool(client)
    _publish_declarative_report()
    first = client.get("/api/v1/capability-catalog?offset=0&limit=1")
    second = client.get("/api/v1/capability-catalog?offset=1&limit=1")
    assert first.status_code == second.status_code == 200
    assert first.json()["total"] == second.json()["total"] == 2
    assert first.json()["truncated"] is True
    assert second.json()["truncated"] is False
    assert (
        first.json()["items"][0]["artifact_version_id"]
        != second.json()["items"][0]["artifact_version_id"]
    )


def test_catalog_reports_bounded_scan(client, monkeypatch):
    _publish_tool(client)
    _publish_declarative_report()
    monkeypatch.setattr(
        "icheck.services.capability_catalog.CATALOG_SCAN_LIMIT",
        1,
    )
    response = client.get("/api/v1/capability-catalog?limit=500")
    assert response.status_code == 200, response.text
    assert response.json()["scan_truncated"] is True
    assert response.json()["total"] == 1
