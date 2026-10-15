import json
import hashlib
from datetime import timedelta
from uuid import uuid4

import pytest
from icheck.activation_schemas import GeneratedActivationPolicySpec
from icheck.config import get_settings
from icheck.database import SessionLocal
from icheck.models import (
    ActivationPolicyProposal,
    AuditEvent,
    ArtifactVersion,
    ArtifactVersionStatus,
    CollectorDeployment,
    CollectorWorker,
    CredentialProfile,
    Device,
    DeviceActivationPolicy,
    utcnow,
)
from sqlalchemy import func, select, update
from icheck.services.structured_model import (
    OpenAICompatibleStructuredGenerator,
    StructuredGenerationResult,
    StructuredModelUnavailable,
)
from test_capability_studio import FakeStructuredOpener, configure_authoring_route


def _published_http_artifact(client):
    created = client.post(
        "/api/v1/artifacts",
        json={
            "name": "lab-controller-proposal-source",
            "kind": "collector",
            "description": "Read controller inventory",
            "owner": "lab",
            "labels": {},
            "initial_version": {
                "definition": {
                    "purpose": "Read inventory",
                    "target_url_example": "https://controller.example.test/api/v1/inventory",
                },
                "implementation": {"runtime": "builtin", "adapter": "http_json"},
                "tests": [],
                "created_by": "lab.admin",
                "collector_definition": {
                    "adapter_type": "http_json",
                    "mode": "poll",
                    "output_kinds": ["observation"],
                    "target_schema": {
                        "type": "object",
                        "required": ["url"],
                        "properties": {"url": {"type": "string", "minLength": 1}},
                        "additionalProperties": False,
                    },
                    "config_schema": {"type": "object"},
                    "defaults": {
                        "records_path": "items",
                        "envelope_kind": "observation",
                        "record_type": "inventory.asset",
                    },
                },
            },
        },
    )
    assert created.status_code == 201, created.text
    version_id = created.json()["versions"][0]["id"]
    for action in ("validate", "publish"):
        response = client.post(
            f"/api/v1/artifact-versions/{version_id}/{action}",
            json={"actor": "lab.admin"},
        )
        assert response.status_code == 200, response.text
    return version_id


def _device(
    client,
    *,
    protocol="https_api",
    name="lab-wifi-controller-proposal",
    address="10.31.0.22",
    site="LAB",
):
    created = client.post(
        "/api/v1/assets/devices",
        json={
            "name": name,
            "kind": "wireless_controller",
            "management_ip": address,
            "vendor": "Example Networks",
            "model": "Controller 100",
            "site": site,
            "connections": [{"protocol": protocol}],
            "created_by": "lab.admin",
        },
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def _suggestion(**changes):
    return GeneratedActivationPolicySpec.model_validate({
        "name": "lab-controller-inventory",
        "rationale": "Collect read-only inventory through the reviewed API path.",
        "target_template": {
            "url": "https://${management_ip}:${port}/api/v1/inventory",
        },
        "configuration_defaults": {},
        "worker_selector": {"site": "${site}"},
        "execution_mode": "scheduled",
        "schedule_seconds": 300,
        **changes,
    })


class FakeGenerator:
    def __init__(self, spec):
        self.spec = spec
        self.calls = []

    def generate(self, **kwargs):
        self.calls.append(kwargs)
        return StructuredGenerationResult(
            document=self.spec,
            route_id="route-test",
            model_id="model-test",
            tokens_used=17,
        )


def _request(version_id, *, device_id=None, brief=None):
    return {
        "protocol": "https_api",
        "artifact_version_id": version_id,
        "brief": brief or "Draft read-only controller inventory from /api/v1/inventory.",
        "device_id": device_id,
        "actor": "lab.admin",
    }


def test_ai_activation_suggestion_is_scoped_review_only_and_creates_no_policy(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    device_id = _device(client)
    fake = FakeGenerator(_suggestion())
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda _db: fake,
    )
    response = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json=_request(version_id, device_id=device_id),
    )
    assert response.status_code == 200, response.text
    proposal = response.json()
    assert proposal["draft"]["artifact_version_id"] == version_id
    assert proposal["draft"]["protocol"] == "https_api"
    assert proposal["draft"]["target_template"]["url"].startswith("https://")
    assert proposal["route_id"] == "route-test"
    assert proposal["tokens_used"] == 17
    assert "unverified" in " ".join(proposal["warnings"]).lower()
    assert client.get("/api/v1/assets/activation-policies").json() == []
    prompt = fake.calls[0]["prompt_document"]
    assert prompt["device_context"]["site"] == "LAB"
    assert prompt["device_context"]["verification_status"] == "pending"
    assert "source_path_example" not in prompt["collector"]
    assert "controller.example.test" not in json.dumps(prompt)
    assert "10.31.0.22" not in json.dumps(prompt)
    assert "credential" not in json.dumps(prompt).lower()
    assert fake.calls[0]["route_purpose"] == "capability.authoring"
    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "device.activation_policy.proposed"},
    )
    assert audits.status_code == 200, audits.text
    assert len(audits.json()) == 1
    assert len(audits.json()[0]["details"]["proposal_sha256"]) == 64
    assert "10.31.0.22" not in json.dumps(audits.json())

    fake.spec = _suggestion(schedule_seconds=600)
    refined = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json={
            **_request(version_id, device_id=device_id, brief="Increase the schedule to ten minutes."),
            "prior_suggestion": {
                **proposal["draft"], "rationale": proposal["rationale"],
            },
        },
    )
    assert refined.status_code == 422  # Client must not return fixed protocol/actor fields to the model.

    prior = {
        key: proposal["draft"][key]
        for key in (
            "name", "target_template", "configuration_defaults",
            "worker_selector", "execution_mode", "schedule_seconds",
        )
    }
    prior["rationale"] = proposal["rationale"]
    refined = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json={
            **_request(version_id, device_id=device_id, brief="Increase the schedule to ten minutes."),
            "prior_suggestion": prior,
        },
    )
    assert refined.status_code == 200, refined.text
    assert refined.json()["draft"]["schedule_seconds"] == 600
    assert fake.calls[-1]["prompt_document"]["prior_suggestion"] == prior
    assert client.get("/api/v1/assets/activation-policies").json() == []

    created = client.post("/api/v1/assets/activation-policies", json=proposal["draft"])
    assert created.status_code == 201, created.text
    assert created.json()["status"] == "draft"
    validated = client.post(
        f"/api/v1/assets/activation-policies/{created.json()['id']}/validate",
        json={"actor": "lab.admin"},
    )
    assert validated.status_code == 200, validated.text
    assert validated.json()["status"] == "validated"


def test_saved_proposal_scope_preview_explains_current_target_credential_and_workers(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    device_id = _device(client)
    fake = FakeGenerator(_suggestion())
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda _db: fake,
    )
    proposed = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json=_request(version_id, device_id=device_id),
    )
    assert proposed.status_code == 200, proposed.text
    proposal_id = proposed.json()["proposal_id"]
    preview_url = (
        f"/api/v1/assets/activation-policy-proposals/{proposal_id}/scope-preview"
        "?actor=lab.admin"
    )

    pending = client.get(preview_url)
    assert pending.status_code == 200, pending.text
    assert "verification" in " ".join(pending.json()["blockers"]).lower()
    assert pending.json()["rendered_target"] == {
        "url": "https://10.31.0.22:443/api/v1/inventory",
    }
    assert "10.31.0.22" not in json.dumps(fake.calls[0]["prompt_document"])

    with SessionLocal() as db:
        device = db.get(Device, device_id)
        connection = device.connections[0]
        connection.verification_status = "verified"
        connection.worker_selector = {"environment": "lab"}
        connection.credential_profile_ref = "lab-readonly-profile"
        db.add(CredentialProfile(
            name="lab-readonly-profile", provider="environment",
            secret_ref="env://SCOPE_PREVIEW_SECRET",
            allowed_adapters=["http_json"],
            worker_selector={"environment": "lab"},
            enabled=True, created_by="lab.admin",
        ))
        db.add(CollectorWorker(
            name="lab-preview-worker", site="LAB", capabilities=["http_json"],
            labels={"environment": "lab"}, auth_token_hash="a" * 64,
        ))
        db.commit()
        counts_before = tuple(db.scalar(select(func.count()).select_from(model)) for model in (
            DeviceActivationPolicy, CollectorDeployment, AuditEvent,
        ))

    preview = client.get(preview_url)
    assert preview.status_code == 200, preview.text
    scope = preview.json()
    assert scope["advisory_only"] is True
    assert scope["blockers"] == []
    assert scope["credential_source"] == "connection"
    assert scope["credential_profile_ref"] == "lab-readonly-profile"
    assert scope["credential_profile_enabled"] is True
    assert scope["credential_adapter_allowed"] is True
    assert scope["credential_worker_selector"] == {"environment": "lab"}
    assert scope["policy_worker_selector"] == {"site": "LAB"}
    assert scope["connection_worker_selector"] == {"environment": "lab"}
    assert scope["effective_worker_selector"] == {"site": "LAB", "environment": "lab"}
    assert scope["registered_worker_matches_in_scan"] == 1
    assert scope["fresh_worker_matches_in_scan"] == 1
    assert "SCOPE_PREVIEW_SECRET" not in json.dumps(scope)
    assert len(fake.calls) == 1
    with SessionLocal() as db:
        assert counts_before == tuple(db.scalar(select(func.count()).select_from(model)) for model in (
            DeviceActivationPolicy, CollectorDeployment, AuditEvent,
        ))
        device = db.get(Device, device_id)
        device.connections[0].worker_selector = {"site": "OTHER"}
        db.commit()
    conflicted = client.get(preview_url)
    assert conflicted.status_code == 200
    assert any("conflicts" in item for item in conflicted.json()["blockers"])
    with SessionLocal() as db:
        device = db.get(Device, device_id)
        device.connections[0].worker_selector = {"environment": "lab"}
        profile = db.scalar(select(CredentialProfile).where(
            CredentialProfile.name == "lab-readonly-profile",
        ))
        profile.enabled = False
        db.commit()
    disabled = client.get(preview_url)
    assert disabled.status_code == 200
    assert disabled.json()["credential_profile_enabled"] is False
    assert any("disabled" in item for item in disabled.json()["blockers"])


def test_saved_proposal_scope_preview_rejects_retarget_and_tampered_snapshot(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    device_id = _device(client)
    other_id = _device(client, name="other-proposal-preview-device", address="10.32.0.22")
    fake = FakeGenerator(_suggestion())
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda _db: fake,
    )
    proposed = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json=_request(version_id, device_id=device_id),
    )
    proposal_id = proposed.json()["proposal_id"]
    url = (
        f"/api/v1/assets/activation-policy-proposals/{proposal_id}/scope-preview"
        "?actor=lab.admin"
    )
    assert client.get(url, params={"actor": "lab.admin", "device_id": other_id}).status_code == 409
    with SessionLocal() as db:
        row = db.get(ActivationPolicyProposal, proposal_id)
        row.result_snapshot = {**row.result_snapshot, "rationale": "changed after sealing"}
        db.commit()
    tampered = client.get(url)
    assert tampered.status_code == 409
    assert "digest mismatch" in tampered.text


def test_unbound_saved_proposal_scope_preview_requires_explicit_device(client, monkeypatch):
    version_id = _published_http_artifact(client)
    device_id = _device(client)
    fake = FakeGenerator(_suggestion())
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda _db: fake,
    )
    proposed = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json=_request(version_id),
    )
    assert proposed.status_code == 200, proposed.text
    url = (
        f"/api/v1/assets/activation-policy-proposals/{proposed.json()['proposal_id']}/scope-preview"
    )
    unbound = client.get(url, params={"actor": "lab.admin"})
    assert unbound.status_code == 200, unbound.text
    assert unbound.json()["rendered_target"] is None
    assert any("Choose an authorized device" in item for item in unbound.json()["blockers"])
    selected = client.get(url, params={"actor": "lab.admin", "device_id": device_id})
    assert selected.status_code == 200, selected.text
    assert selected.json()["device_id"] == device_id
    assert selected.json()["rendered_target"]["url"].startswith("https://10.31.0.22")
    assert len(fake.calls) == 1


def test_edited_policy_draft_scope_preview_uses_exact_fields_without_writes(client):
    version_id = _published_http_artifact(client)
    device_id = _device(client)
    draft = {
        "name": "edited-controller-inventory",
        "protocol": "https_api",
        "artifact_version_id": version_id,
        "target_template": {
            "url": "https://${management_ip}:${port}/api/v2/edited-inventory",
        },
        "configuration_defaults": {},
        "worker_selector": {"site": "${site}"},
        "execution_mode": "scheduled",
        "schedule_seconds": 600,
        "created_by": "lab.admin",
    }
    with SessionLocal() as db:
        counts_before = tuple(db.scalar(select(func.count()).select_from(model)) for model in (
            DeviceActivationPolicy, CollectorDeployment, AuditEvent,
        ))
    url = "/api/v1/assets/activation-policies/draft-scope-preview"
    preview = client.post(url, json={"draft": draft, "device_id": device_id})
    assert preview.status_code == 200, preview.text
    scope = preview.json()
    assert scope["advisory_only"] is True
    assert len(scope["draft_sha256"]) == 64
    assert scope["rendered_target"] == {
        "url": "https://10.31.0.22:443/api/v2/edited-inventory",
    }
    assert scope["policy_worker_selector"] == {"site": "LAB"}
    assert "verification" in " ".join(scope["blockers"]).lower()
    assert "proposal_id" not in scope
    with SessionLocal() as db:
        assert counts_before == tuple(db.scalar(select(func.count()).select_from(model)) for model in (
            DeviceActivationPolicy, CollectorDeployment, AuditEvent,
        ))

    unsafe = client.post(url, json={
        "draft": {**draft, "target_template": {
            "url": "https://${management_ip}/api?token=plaintext",
        }},
        "device_id": device_id,
    })
    assert unsafe.status_code == 422
    assert "credential" in unsafe.text.lower()
    unsafe_save = client.post("/api/v1/assets/activation-policies", json={
        **draft, "target_template": {"url": "https://${management_ip}/api?token=plaintext"},
    })
    assert unsafe_save.status_code == 422
    assert client.get("/api/v1/assets/activation-policies").json() == []

    invalid = client.post(url, json={
        "draft": {**draft, "target_template": {"url": "http://${management_ip}/api"}},
    })
    assert invalid.status_code == 200, invalid.text
    assert invalid.json()["rendered_target"] is None
    assert any("HTTPS URL" in item for item in invalid.json()["blockers"])
    invalid_saved = client.post("/api/v1/assets/activation-policies", json={
        **draft, "name": "invalid-http-controller-policy",
        "target_template": {"url": "http://${management_ip}/api"},
    })
    assert invalid_saved.status_code == 201, invalid_saved.text
    refused_validation = client.post(
        f"/api/v1/assets/activation-policies/{invalid_saved.json()['id']}/validate",
        json={"actor": "lab.admin"},
    )
    assert refused_validation.status_code == 422
    assert "HTTPS URL" in refused_validation.text


def test_ai_activation_rejects_unsafe_output_and_secret_brief(client, monkeypatch):
    version_id = _published_http_artifact(client)
    device_id = _device(client)
    fake = FakeGenerator(_suggestion(target_template={"url": "http://${management_ip}/api"}))
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda _db: fake,
    )
    request = _request(version_id, device_id=device_id)
    insecure = client.post("/api/v1/assets/activation-policy-proposals", json=request)
    assert insecure.status_code == 422
    assert "HTTPS URL" in insecure.text

    fake.spec = _suggestion(target_template={"url": "https://${management_ip}/api?token=abc"})
    query_secret = client.post("/api/v1/assets/activation-policy-proposals", json=request)
    assert query_secret.status_code == 422
    assert "credential query keys" in query_secret.text

    fake.spec = _suggestion(worker_selector={"site": "OTHER"})
    wrong_site = client.post("/api/v1/assets/activation-policy-proposals", json=request)
    assert wrong_site.status_code == 422
    assert "device site" in wrong_site.text

    fake.spec = _suggestion(rationale="Use token=cleartext for the controller")
    secret_rationale = client.post("/api/v1/assets/activation-policy-proposals", json=request)
    assert secret_rationale.status_code == 422
    assert "rationale" in secret_rationale.text

    fake.spec = _suggestion(
        target_template={"url": "https://10.31.0.22/api/v1/inventory"}
    )
    literal_target = client.post(
        "/api/v1/assets/activation-policy-proposals", json=request
    )
    assert literal_target.status_code == 422
    assert "management IP" in literal_target.text

    forged_prior = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json={
            **request,
            "prior_suggestion": _suggestion(
                target_template={"url": "https://10.31.0.22/api/v1/inventory"}
            ).model_dump(mode="json"),
        },
    )
    assert forged_prior.status_code == 422
    assert "management IP" in forged_prior.text

    before = len(fake.calls)
    brief_secret = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json=_request(version_id, device_id=device_id, brief="Use password=cleartext in the API request"),
    )
    assert brief_secret.status_code == 422
    assert len(fake.calls) == before

    raw_ip = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json=_request(
            version_id, device_id=device_id,
            brief="Collect read-only inventory from 10.31.0.22 directly.",
        ),
    )
    assert raw_ip.status_code == 422
    assert "management IP" in raw_ip.text
    assert len(fake.calls) == before
    assert client.get("/api/v1/assets/activation-policies").json() == []


def test_ai_activation_uses_configured_structured_model_route(client, monkeypatch):
    version_id = _published_http_artifact(client)
    device_id = _device(client)
    route, model = configure_authoring_route(client)
    opener = FakeStructuredOpener([_suggestion().model_dump(mode="json")])
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda db: OpenAICompatibleStructuredGenerator(db, opener=opener),
    )
    response = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json=_request(version_id, device_id=device_id),
    )
    assert response.status_code == 200, response.text
    assert response.json()["route_id"] == route["id"]
    assert response.json()["model_id"] == model["id"]
    sent = json.loads(opener.requests[0][0].data)
    assert sent["response_format"]["json_schema"]["strict"] is True
    assert sent["response_format"]["json_schema"]["name"] == (
        "icheck_activation_policy_proposal"
    )
    assert "10.31.0.22" not in json.dumps(sent)
    assert "controller.example.test" not in json.dumps(sent)
    assert client.get("/api/v1/assets/activation-policies").json() == []


def test_ai_activation_rejects_incompatible_device_and_missing_model_route(client):
    version_id = _published_http_artifact(client)
    device_id = _device(client, protocol="icmp")
    incompatible = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json=_request(version_id, device_id=device_id),
    )
    assert incompatible.status_code == 422
    assert "no connection" in incompatible.text

    unavailable = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json=_request(version_id),
    )
    assert unavailable.status_code == 503
    assert "model route" in unavailable.text


def test_scoped_operator_can_propose_only_for_authorized_device(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    allowed_id = _device(client)
    denied_id = _device(
        client,
        name="other-wifi-controller-proposal",
        address="10.32.0.22",
        site="OTHER",
    )
    fake = FakeGenerator(_suggestion())
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda _db: fake,
    )
    outside_owned = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json={
            **_request(version_id, device_id=denied_id),
            "actor": "lab.operator@example.test",
        },
    )
    assert outside_owned.status_code == 200, outside_owned.text
    fake.calls.clear()
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    try:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            headers={"X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token"},
            json={"subject": "admin@example.test", "display_name": "Admin"},
        )
        assert bootstrap.status_code == 201, bootstrap.text
        admin_headers = {
            "Authorization": f"Bearer {bootstrap.json()['token']['access_token']}"
        }
        roles = client.get("/api/v1/auth/roles", headers=admin_headers).json()
        operator_role = next(item for item in roles if item["name"] == "operator")
        principal = client.post(
            "/api/v1/auth/principals",
            headers=admin_headers,
            json={"subject": "lab.operator@example.test", "display_name": "Lab Operator"},
        )
        assert principal.status_code == 201, principal.text
        principal_id = principal.json()["id"]
        binding = client.post(
            f"/api/v1/auth/principals/{principal_id}/bindings",
            headers=admin_headers,
            json={"role_id": operator_role["id"], "scope": {"sites": ["LAB"]}},
        )
        assert binding.status_code == 201, binding.text
        token = client.post(
            f"/api/v1/auth/principals/{principal_id}/tokens",
            headers=admin_headers,
            json={"name": "lab-policy-token", "expires_in_hours": 24},
        )
        assert token.status_code == 201, token.text
        headers = {"Authorization": f"Bearer {token.json()['access_token']}"}
        assert client.get("/api/v1/artifacts", headers=headers).status_code == 403
        catalog = client.get("/api/v1/assets/activation-collectors", headers=headers)
        assert catalog.status_code == 200, catalog.text
        assert catalog.json()[0]["artifact_version_id"] == version_id
        paged_catalog = client.get(
            "/api/v1/assets/activation-collectors/page",
            headers=headers, params={"protocol": "https_api", "limit": 1},
        )
        assert paged_catalog.status_code == 200, paged_catalog.text
        assert paged_catalog.json()["items"][0]["artifact_version_id"] == version_id
        exact_contract = client.get(
            f"/api/v1/assets/activation-collectors/{version_id}", headers=headers,
        )
        assert exact_contract.status_code == 200, exact_contract.text
        assert exact_contract.json()["artifact_version_id"] == version_id

        denied = client.post(
            "/api/v1/assets/activation-policy-proposals",
            headers=headers,
            json=_request(version_id, device_id=denied_id),
        )
        assert denied.status_code == 404
        assert fake.calls == []
        outside_recovery = client.post(
            f"/api/v1/assets/activation-policy-proposals/{outside_owned.json()['proposal_id']}/interrupt",
            headers=headers,
            json={"actor": "lab.operator@example.test", "reason": "Attempt outside the authorized device site."},
        )
        assert outside_recovery.status_code == 404

        allowed = client.post(
            "/api/v1/assets/activation-policy-proposals",
            headers=headers,
            json=_request(version_id, device_id=allowed_id),
        )
        assert allowed.status_code == 200, allowed.text
        assert allowed.json()["draft"]["created_by"] == "lab.operator@example.test"
        assert "10.31.0.22" not in json.dumps(fake.calls[0]["prompt_document"])
        admin_proposal = client.post(
            "/api/v1/assets/activation-policy-proposals",
            headers=admin_headers,
            json=_request(version_id, device_id=allowed_id),
        )
        assert admin_proposal.status_code == 200, admin_proposal.text
        own_history = client.get(
            "/api/v1/assets/activation-policy-proposals",
            headers=headers, params={"device_id": allowed_id, "actor": "admin@example.test"},
        )
        assert own_history.status_code == 200
        assert [row["id"] for row in own_history.json()] == [allowed.json()["proposal_id"]]
        hidden_record = client.get(
            f"/api/v1/assets/activation-policy-proposals/{admin_proposal.json()['proposal_id']}",
            headers=headers,
        )
        assert hidden_record.status_code == 404
        hidden_scope = client.get(
            f"/api/v1/assets/activation-policy-proposals/{admin_proposal.json()['proposal_id']}/scope-preview",
            headers=headers,
        )
        assert hidden_scope.status_code == 404
        hidden_recovery = client.post(
            f"/api/v1/assets/activation-policy-proposals/{admin_proposal.json()['proposal_id']}/interrupt",
            headers=headers,
            json={"actor": "lab.operator@example.test", "reason": "A controlled stale request recovery check."},
        )
        assert hidden_recovery.status_code == 404
        denied_history = client.get(
            "/api/v1/assets/activation-policy-proposals",
            headers=headers, params={"device_id": denied_id},
        )
        assert denied_history.status_code == 404
        denied_record = client.get(
            f"/api/v1/assets/activation-policy-proposals/{allowed.json()['proposal_id']}",
            headers=headers,
        )
        assert denied_record.status_code == 200
        allowed_scope = client.get(
            f"/api/v1/assets/activation-policy-proposals/{allowed.json()['proposal_id']}/scope-preview",
            headers=headers,
        )
        assert allowed_scope.status_code == 200, allowed_scope.text
        assert allowed_scope.json()["device_id"] == allowed_id
        edited_preview = client.post(
            "/api/v1/assets/activation-policies/draft-scope-preview",
            headers=headers,
            json={"draft": allowed.json()["draft"], "device_id": allowed_id},
        )
        assert edited_preview.status_code == 200, edited_preview.text
        assert edited_preview.json()["device_id"] == allowed_id
        denied_edited_preview = client.post(
            "/api/v1/assets/activation-policies/draft-scope-preview",
            headers=headers,
            json={"draft": allowed.json()["draft"], "device_id": denied_id},
        )
        assert denied_edited_preview.status_code == 404
        outside_scope = client.get(
            f"/api/v1/assets/activation-policy-proposals/{outside_owned.json()['proposal_id']}/scope-preview",
            headers=headers,
        )
        assert outside_scope.status_code == 404
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()


def test_ai_activation_history_refinement_and_request_key_replay(client, monkeypatch):
    version_id = _published_http_artifact(client)
    device_id = _device(client)
    fake = FakeGenerator(_suggestion())
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda _db: fake,
    )
    key = str(uuid4())
    payload = {**_request(version_id, device_id=device_id), "request_key": key}
    first = client.post("/api/v1/assets/activation-policy-proposals", json=payload)
    assert first.status_code == 200, first.text
    first_result = first.json()
    assert first_result["proposal_id"]
    assert first_result["parent_id"] is None

    replay = client.post("/api/v1/assets/activation-policy-proposals", json=payload)
    assert replay.status_code == 200, replay.text
    assert replay.json() == first_result
    assert len(fake.calls) == 1
    changed = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json={**payload, "brief": "Change the read-only polling schedule to ten minutes."},
    )
    assert changed.status_code == 409
    assert len(fake.calls) == 1

    fake.spec = _suggestion(schedule_seconds=600)
    child = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json={
            **_request(
                version_id, device_id=device_id,
                brief="Change the read-only polling schedule to ten minutes.",
            ),
            "parent_id": first_result["proposal_id"],
            "request_key": str(uuid4()),
        },
    )
    assert child.status_code == 200, child.text
    assert child.json()["parent_id"] == first_result["proposal_id"]
    assert child.json()["draft"]["schedule_seconds"] == 600
    assert fake.calls[-1]["prompt_document"]["prior_suggestion"]["schedule_seconds"] == 300

    with SessionLocal() as db:
        version = db.get(ArtifactVersion, version_id)
        version.status = ArtifactVersionStatus.DEPRECATED
        db.commit()
    retired_replay = client.post(
        "/api/v1/assets/activation-policy-proposals", json=payload
    )
    assert retired_replay.status_code == 200, retired_replay.text
    assert retired_replay.json() == first_result
    assert len(fake.calls) == 2

    history = client.get(
        "/api/v1/assets/activation-policy-proposals",
        params={"device_id": device_id, "actor": "lab.admin"},
    )
    assert history.status_code == 200, history.text
    assert len(history.json()) == 2
    assert history.json()[0]["result"] == child.json()
    recovered = client.get(
        f"/api/v1/assets/activation-policy-proposals/{first_result['proposal_id']}",
        params={"actor": "lab.admin"},
    )
    assert recovered.status_code == 200
    assert recovered.json()["result"] == first_result
    assert client.get("/api/v1/assets/activation-policies").json() == []


def test_ai_activation_failed_key_is_not_charged_twice(client, monkeypatch):
    version_id = _published_http_artifact(client)
    fake = FakeGenerator(_suggestion(target_template={"url": "http://unsafe.example/api"}))
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda _db: fake,
    )
    payload = {**_request(version_id), "request_key": str(uuid4())}
    failed = client.post("/api/v1/assets/activation-policy-proposals", json=payload)
    assert failed.status_code == 422
    replay = client.post("/api/v1/assets/activation-policy-proposals", json=payload)
    assert replay.status_code == 409
    assert len(fake.calls) == 1
    history = client.get(
        "/api/v1/assets/activation-policy-proposals",
        params={"actor": "lab.admin"},
    )
    assert history.status_code == 200
    assert history.json()[0]["status"] == "failed"
    assert history.json()[0]["failure_code"] == "ValueError"
    assert history.json()[0]["tokens_used"] == 17
    assert history.json()[0]["result"] is None


def test_ai_activation_in_flight_key_is_not_reinvoked(client, monkeypatch):
    version_id = _published_http_artifact(client)
    fake = FakeGenerator(_suggestion())
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda _db: fake,
    )
    payload = {**_request(version_id), "request_key": str(uuid4())}
    digest_document = {
        "actor": payload["actor"],
        "protocol": payload["protocol"],
        "artifact_version_id": version_id,
        "device_id": None,
        "parent_id": None,
        "prior_suggestion": None,
        "brief": payload["brief"],
    }
    request_sha256 = hashlib.sha256(json.dumps(
        digest_document, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    with SessionLocal() as db:
        db.add(ActivationPolicyProposal(
            artifact_version_id=version_id,
            protocol="https_api",
            actor=payload["actor"],
            request_key=payload["request_key"],
            request_sha256=request_sha256,
            brief=payload["brief"],
            status="generating",
            result_snapshot={},
            tokens_used=0,
        ))
        db.commit()
    replay = client.post("/api/v1/assets/activation-policy-proposals", json=payload)
    assert replay.status_code == 409
    assert "in flight" in replay.text
    assert fake.calls == []


def test_stale_ai_proposal_requires_explicit_interrupt_and_never_replays(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    fake = FakeGenerator(_suggestion())
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda _db: fake,
    )
    payload = {**_request(version_id), "request_key": str(uuid4())}
    digest_document = {
        "actor": payload["actor"],
        "protocol": payload["protocol"],
        "artifact_version_id": version_id,
        "device_id": None,
        "parent_id": None,
        "prior_suggestion": None,
        "brief": payload["brief"],
    }
    request_sha256 = hashlib.sha256(json.dumps(
        digest_document, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    with SessionLocal() as db:
        fresh = ActivationPolicyProposal(
            artifact_version_id=version_id,
            protocol="https_api",
            actor="lab.admin",
            request_key=payload["request_key"],
            request_sha256=request_sha256,
            brief=payload["brief"],
            status="generating",
            result_snapshot={},
            tokens_used=0,
        )
        db.add(fresh)
        db.commit()
        proposal_id = fresh.id
    url = f"/api/v1/assets/activation-policy-proposals/{proposal_id}/interrupt"
    action = {"actor": "lab.admin", "reason": "Model request exceeded its maximum safe waiting period."}
    blank_reason = client.post(url, json={"actor": "lab.admin", "reason": "           "})
    assert blank_reason.status_code == 422
    too_early = client.post(url, json=action)
    assert too_early.status_code == 409
    assert "two-hour" in too_early.text
    with SessionLocal() as db:
        db.execute(
            update(ActivationPolicyProposal)
            .where(ActivationPolicyProposal.id == proposal_id)
            .values(created_at=utcnow() - timedelta(hours=3))
        )
        db.commit()
    interrupted = client.post(url, json=action)
    assert interrupted.status_code == 200, interrupted.text
    assert interrupted.json()["status"] == "failed"
    assert interrupted.json()["failure_code"] == "Interrupted"
    assert interrupted.json()["result"] is None
    assert client.post(url, json=action).status_code == 200
    replay = client.post("/api/v1/assets/activation-policy-proposals", json=payload)
    assert replay.status_code == 409
    assert fake.calls == []
    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "device.activation_policy.proposal_interrupted"},
    )
    assert audits.status_code == 200
    assert len(audits.json()) == 1
    assert audits.json()[0]["details"]["external_charge_unknown"] is True


@pytest.mark.parametrize("model_fails", [False, True])
def test_late_ai_result_cannot_overwrite_interrupted_receipt(
    client, monkeypatch, model_fails,
):
    version_id = _published_http_artifact(client)
    request_key = str(uuid4())

    class LateGenerator(FakeGenerator):
        def generate(self, **kwargs):
            generated = super().generate(**kwargs)
            with SessionLocal() as db:
                db.execute(
                    update(ActivationPolicyProposal)
                    .where(ActivationPolicyProposal.request_key == request_key)
                    .values(status="failed", failure_code="Interrupted")
                )
                db.commit()
            if model_fails:
                raise StructuredModelUnavailable("Synthetic late provider failure")
            return generated

    fake = LateGenerator(_suggestion())
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda _db: fake,
    )
    response = client.post(
        "/api/v1/assets/activation-policy-proposals",
        json={**_request(version_id), "request_key": request_key},
    )
    assert response.status_code == 409, response.text
    assert "late model result was discarded" in response.text
    history = client.get(
        "/api/v1/assets/activation-policy-proposals",
        params={"actor": "lab.admin"},
    )
    assert history.status_code == 200
    assert history.json()[0]["failure_code"] == "Interrupted"
    assert history.json()[0]["result"] is None
    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "device.activation_policy.proposal_late_result_discarded"},
    )
    assert len(audits.json()) == 1
    assert audits.json()[0]["details"]["known_token_usage"] == (0 if model_fails else 17)
