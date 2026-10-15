"""Known provider usage survives structured-output rejection and fallback."""

import json
from contextlib import contextmanager
from urllib.error import URLError

from icheck.database import SessionLocal, set_session_namespace
from icheck.services.control_plane_auth import development_principal
from icheck.models import AIModelRoute
from icheck.services.ai_settings import AIProviderUnavailable
from icheck.services.structured_model import OpenAICompatibleStructuredGenerator
from icheck.services.structured_model import StructuredModelUnavailable
from icheck.ai_failure_diagnostics import schema_field_names
from pydantic import BaseModel, ConfigDict
import pytest
from test_activation_policy_proposals import (
    _published_http_artifact,
    _request,
    _suggestion,
)
from test_capability_studio import (
    FakeStructuredOpener,
    FakeStructuredResponse,
    configure_authoring_route,
    studio_payload,
)


@pytest.mark.parametrize(("node", "rule"), [
    ({"node_id":"done","title":"Done","node_type":"end","objective":"private fixture output"}, "workflow_end_must_be_terminal"),
    ({"node_id":"review","title":"Review","node_type":"agent_loop","tool_name":"inventory.get_device"}, "workflow_agent_loop_cannot_declare_tool"),
])
def test_workflow_shape_errors_use_safe_local_rules(node, rule):
    from icheck.studio_schemas import WorkflowNode
    from icheck.ai_failure_diagnostics import model_validation_diagnostic
    from pydantic import ValidationError
    with pytest.raises(ValidationError) as failure:
        WorkflowNode.model_validate(node)
    result = model_validation_diagnostic(failure.value, stage="capability_authoring",
        known_fields=schema_field_names(WorkflowNode.model_json_schema()))
    assert result["validation_errors"] == [{"path":"$", "rule":rule}]
    assert "private fixture output" not in json.dumps(result)


def test_capability_schema_errors_report_local_fields_without_values_or_unknown_keys(client):
    configure_authoring_route(client)
    class Nested(BaseModel):
        model_config = ConfigDict(extra="forbid")
        description: str
    class Output(BaseModel):
        model_config = ConfigDict(extra="forbid")
        specification: Nested
    private = "private-provider-content-not-for-logs"
    opener = FakeStructuredOpener([{"specification":{"description":42}, private:private}])
    with SessionLocal() as db:
        principal = development_principal()
        set_session_namespace(db, principal.tenant_id, principal.region_id)
        with pytest.raises(StructuredModelUnavailable) as failure:
            OpenAICompatibleStructuredGenerator(db, opener=opener).generate(route_purpose="capability.authoring",
                response_model=Output, schema_name="safe_output", system_prompt="Return the local schema only",
                prompt_document={"brief":"Fixture only"}, entity_type="capability_studio_session", entity_id="fixture", actor_id="lab.admin")
        error = failure.value
        assert error.token_usage == 42 and error.external_charge_unknown is False
        assert error.diagnostic["validation_stage"] == "capability_authoring"
        assert {"path":"specification.description", "rule":"string_type"} in error.diagnostic["validation_errors"]
        assert {"path":"<unknown-field>", "rule":"extra_forbidden"} in error.diagnostic["validation_errors"]
        assert private not in str(error) + json.dumps(error.diagnostic)
    assert schema_field_names(Output.model_json_schema()) == {"specification", "description"}
    audit = client.get("/api/v1/audit-events?event_type=capability.model.failed").json()
    assert audit[0]["details"]["diagnostic"]["code"] == "model_schema_invalid"
    assert private not in json.dumps(audit)


def test_studio_failure_diagnostic_survives_draft_rollback(client, monkeypatch):
    configure_authoring_route(client)
    private = "private-model-field-and-value"
    opener = FakeStructuredOpener([{private:private}])
    monkeypatch.setattr("icheck.services.structured_model.build_opener", lambda *_: opener)
    created = client.post("/api/v1/capability-studio/sessions", json=studio_payload())
    identity = created.json()["id"]
    response = client.post(f"/api/v1/capability-studio/sessions/{identity}/generate", json={"actor":"lab.admin"})
    assert response.status_code == 503 and "Rejected output" in response.text
    audits = client.get(f"/api/v1/audit-events?entity_id={identity}").json()
    failures = [row for row in audits if row["event_type"].endswith("generation.failed")]
    assert len(failures) == 1
    assert failures[0]["details"]["diagnostic"]["code"] == "model_schema_invalid"
    assert private not in json.dumps(audits) + response.text


def _with_fallback(client, *, token_budget: int):
    route, model = configure_authoring_route(client)
    second = client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": model["provider_id"],
            "display_name": "Fallback capability author",
            "model_name": "capability-author-fallback",
            "capabilities": ["chat", "json_schema"],
            "max_output_tokens": 4096,
            "default_parameters": {"max_tokens": 9999},
            "created_by": "platform.admin",
        },
    )
    assert second.status_code == 201, second.text
    with SessionLocal() as db:
        bound = db.get(AIModelRoute, route["id"])
        bound.fallback_model_ids = [second.json()["id"]]
        bound.token_budget = token_budget
        db.commit()
    return route


def _proposal(client, version_id: str):
    return client.post(
        "/api/v1/assets/activation-policy-proposals",
        json=_request(version_id),
    )


def test_schema_rejected_candidate_usage_is_counted_and_caps_fallback(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    _with_fallback(client, token_budget=100)
    opener = FakeStructuredOpener([{}, _suggestion().model_dump(mode="json")])
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda db: OpenAICompatibleStructuredGenerator(db, opener=opener),
    )
    response = _proposal(client, version_id)
    assert response.status_code == 200, response.text
    assert response.json()["tokens_used"] == 84
    assert response.json()["external_charge_unknown"] is False
    sent = [json.loads(request.data) for request, _ in opener.requests]
    assert [payload["max_tokens"] for payload in sent] == [100, 58]
    history = client.get(
        "/api/v1/assets/activation-policy-proposals", params={"actor": "lab.admin"},
    ).json()
    assert history[0]["tokens_used"] == 84
    assert history[0]["external_charge_unknown"] is False
    failure = client.get(
        "/api/v1/audit-events",
        params={"event_type": "capability.model.failed"},
    ).json()
    assert len(failure) == 1
    assert failure[0]["details"]["token_usage"] == 42
    completed = client.get(
        "/api/v1/audit-events",
        params={"event_type": "capability.model.completed"},
    ).json()
    assert completed[0]["details"]["token_usage"] == 84


def test_budget_exhaustion_after_provider_response_seals_known_usage(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    _with_fallback(client, token_budget=60)
    opener = FakeStructuredOpener([{}, _suggestion().model_dump(mode="json")])
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda db: OpenAICompatibleStructuredGenerator(db, opener=opener),
    )
    response = _proposal(client, version_id)
    assert response.status_code == 503, response.text
    assert "token budget" in response.text
    assert len(opener.requests) == 2
    sent = [json.loads(request.data) for request, _ in opener.requests]
    assert [payload["max_tokens"] for payload in sent] == [60, 18]
    history = client.get(
        "/api/v1/assets/activation-policy-proposals", params={"actor": "lab.admin"},
    ).json()
    assert history[0]["status"] == "failed"
    assert history[0]["tokens_used"] == 84
    assert history[0]["external_charge_unknown"] is False
    budget = client.get(
        "/api/v1/audit-events",
        params={"event_type": "capability.model.budget_exceeded"},
    ).json()
    assert len(budget) == 1
    assert budget[0]["details"]["cumulative_token_usage"] == 84


def test_unknown_first_charge_is_visible_even_when_fallback_succeeds(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    _with_fallback(client, token_budget=100)

    class UncertainOpener:
        def __init__(self):
            self.calls = 0

        def open(self, request, timeout):
            self.calls += 1
            if self.calls == 1:
                raise URLError("synthetic provider timeout")
            return FakeStructuredResponse(_suggestion().model_dump(mode="json"))

    opener = UncertainOpener()
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda db: OpenAICompatibleStructuredGenerator(db, opener=opener),
    )
    response = _proposal(client, version_id)
    assert response.status_code == 200, response.text
    assert opener.calls == 2
    assert response.json()["tokens_used"] == 42
    assert response.json()["external_charge_unknown"] is True
    history = client.get(
        "/api/v1/assets/activation-policy-proposals", params={"actor": "lab.admin"},
    ).json()
    assert history[0]["external_charge_unknown"] is True


def test_known_failure_exhausts_budget_before_fallback(client, monkeypatch):
    version_id = _published_http_artifact(client)
    _with_fallback(client, token_budget=42)
    opener = FakeStructuredOpener([{}])
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda db: OpenAICompatibleStructuredGenerator(db, opener=opener),
    )
    response = _proposal(client, version_id)
    assert response.status_code == 503, response.text
    assert "exhausted the route token budget" in response.text
    assert len(opener.requests) == 1
    history = client.get(
        "/api/v1/assets/activation-policy-proposals", params={"actor": "lab.admin"},
    ).json()
    assert history[0]["tokens_used"] == 42
    assert history[0]["external_charge_unknown"] is False


def test_malformed_provider_usage_preserves_charge_uncertainty(client, monkeypatch):
    version_id = _published_http_artifact(client)
    configure_authoring_route(client)

    class MalformedUsageResponse(FakeStructuredResponse):
        def __init__(self):
            self.body = json.dumps({
                "usage": {"total_tokens": "forty-two"},
                "choices": [{"message": {"content": "{}"}}],
            }).encode("utf-8")

    class MalformedUsageOpener:
        def open(self, request, timeout):
            return MalformedUsageResponse()

    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda db: OpenAICompatibleStructuredGenerator(db, opener=MalformedUsageOpener()),
    )
    response = _proposal(client, version_id)
    assert response.status_code == 503, response.text
    history = client.get(
        "/api/v1/assets/activation-policy-proposals", params={"actor": "lab.admin"},
    ).json()
    assert history[0]["tokens_used"] == 0
    assert history[0]["external_charge_unknown"] is True


def test_unrepresentable_provider_usage_is_not_written_as_token_counter(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    configure_authoring_route(client)

    class HugeUsageResponse(FakeStructuredResponse):
        def __init__(self):
            self.body = json.dumps({
                "usage": {"total_tokens": 3_000_000_000},
                "choices": [{"message": {"content": "{}"}}],
            }).encode("utf-8")

    class HugeUsageOpener:
        def open(self, request, timeout):
            return HugeUsageResponse()

    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda db: OpenAICompatibleStructuredGenerator(db, opener=HugeUsageOpener()),
    )
    response = _proposal(client, version_id)
    assert response.status_code == 503, response.text
    history = client.get(
        "/api/v1/assets/activation-policy-proposals", params={"actor": "lab.admin"},
    ).json()
    assert history[0]["tokens_used"] == 0
    assert history[0]["external_charge_unknown"] is True


def test_post_request_credential_cleanup_failure_is_not_marked_charge_free(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    configure_authoring_route(client)
    opener = FakeStructuredOpener([_suggestion().model_dump(mode="json")])

    @contextmanager
    def failing_cleanup(_db, _provider):
        yield {}
        raise AIProviderUnavailable("Synthetic credential cleanup failure")

    monkeypatch.setattr(
        "icheck.services.structured_model._models_request_headers", failing_cleanup,
    )
    monkeypatch.setattr(
        "icheck.services.activation_proposals.OpenAICompatibleStructuredGenerator",
        lambda db: OpenAICompatibleStructuredGenerator(db, opener=opener),
    )
    response = _proposal(client, version_id)
    assert response.status_code == 503, response.text
    assert len(opener.requests) == 1
    history = client.get(
        "/api/v1/assets/activation-policy-proposals", params={"actor": "lab.admin"},
    ).json()
    assert history[0]["external_charge_unknown"] is True
    assert history[0]["tokens_used"] == 0


def test_studio_failure_keeps_provider_reported_usage(client, monkeypatch):
    configure_authoring_route(client)
    opener = FakeStructuredOpener([{}])
    monkeypatch.setattr(
        "icheck.services.structured_model.build_opener", lambda *_: opener,
    )
    created = client.post(
        "/api/v1/capability-studio/sessions", json=studio_payload(),
    )
    assert created.status_code == 201, created.text
    result = client.post(
        f"/api/v1/capability-studio/sessions/{created.json()['id']}/generate",
        json={"actor": "capability.author"},
    )
    assert result.status_code == 503, result.text
    session = client.get(
        f"/api/v1/capability-studio/sessions/{created.json()['id']}"
    ).json()
    assert session["status"] == "failed"
    assert session["tokens_used"] == 42
    audits = client.get(
        "/api/v1/audit-events",
        params={"event_type": "capability.studio.generation.failed"},
    ).json()
    assert audits[0]["details"]["token_usage"] == 42
    assert audits[0]["details"]["external_charge_unknown"] is False
