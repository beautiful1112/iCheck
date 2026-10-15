from datetime import timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from icheck.collector_condition_schemas import COLLECTOR_CONDITION_V1, CollectorConditionDefinition, CollectorConditionObservation, evaluate_condition
from icheck.database import SessionLocal
from icheck.models import (Alert, AlertConditionState, AlertStatus, ArtifactVersion, CollectorConditionAdmission,
    CollectorConditionReceipt, CollectorConditionSource, CollectorDeployment, CollectorRun, CollectorWorker,
    KnowledgeProjection, KnowledgeProjectionStatus, utcnow)
from icheck.services.collector_conditions import project_condition
from icheck.services.alert_conditions import observe_unknown_condition
from icheck.services.alerts import resolve_by_dedup_key
from test_knowledge_projection import _post_envelope, _project_one

session = SessionLocal
SPEC = {"key": "cpu.high", "event_type": "device.cpu.high", "entity_type": "device",
    "title": "High CPU", "operator": "gt", "expected": 90, "max_age_seconds": 300}


def fixture(client, *, credential_profile_ref=None):
    device = client.post("/api/v1/devices", json={"name": "condition-device", "kind": "switch", "site": "HQ"}).json()
    response = client.post("/api/v1/artifacts", json={"name": "condition-observer", "kind": "collector",
        "owner": "platform-team", "initial_version": {"definition": {"condition_contracts": [SPEC]},
            "implementation": {"runtime": "builtin", "adapter": "http_json"}, "tests": [{"name": "shape", "fixture": {}}],
            "created_by": "author", "collector_definition": {"adapter_type": "http_json", "mode": "poll",
                "output_kinds": ["observation"], "target_schema": {"type": "object", "required": ["url"]}}}})
    assert response.status_code == 201, response.text
    version_id = response.json()["versions"][0]["id"]
    assert client.post(f"/api/v1/artifact-versions/{version_id}/validate", json={"actor": "reviewer"}).status_code == 200
    published = client.post(f"/api/v1/artifact-versions/{version_id}/publish", json={"actor": "publisher"})
    assert published.status_code == 200, published.text
    deployment = client.post("/api/v1/collector-deployments", json={"name": "condition-deployment",
        "artifact_version_id": version_id, "scope_device_id": device["id"],
        "scope_device_identity_revision": device["identity_revision"], "scope_site": "HQ",
        "target_classification": "registered_device", "target": {"url": "https://condition-device/data"},
        "credential_profile_ref": credential_profile_ref,
        "worker_selector": {"site": "HQ"}, "created_by": "operator"})
    assert deployment.status_code == 201, deployment.text
    from icheck.collector_api import settings
    registered = client.post("/api/v1/collector-workers/register", json={"name": "condition-worker", "site": "HQ",
        "capabilities": ["http_json"], "labels": {"io_supervisor_v1": True}},
        headers={"X-iCheck-Registration-Token": settings.collector_registration_token})
    assert registered.status_code == 200, registered.text
    worker = registered.json()["worker"]
    headers = {"Authorization": f'Bearer {registered.json()["access_token"]}'}
    claimed = client.post(f'/api/v1/collector-workers/{worker["id"]}/leases/claim',
        json={"max_assignments": 1, "lease_seconds": 120}, headers=headers)
    assert claimed.status_code == 200 and len(claimed.json()) == 1, claimed.text
    assignment = claimed.json()[0]
    admitted = client.post(f'/api/v1/collector-runs/{assignment["run_id"]}/admit',
        json={"lease_token": assignment["lease_token"], "assignment_sha256": assignment["assignment_sha256"]}, headers=headers)
    assert admitted.status_code == 200, admitted.text
    return {"device": device, "version_id": version_id, "deployment_id": deployment.json()["id"],
        "worker_id": worker["id"], "assignment": assignment, "headers": headers, "at": utcnow()}


def envelope(c, value, *, at=None, key=None, **extra):
    return {"kind": "observation", "type": COLLECTOR_CONDITION_V1, "source": "vendor-label",
        "observed_at": (at or c["at"]).isoformat(), "idempotency_key": key,
        "payload": {"condition_key": "cpu.high", "value": value, **extra}}


def submit(client, c, value, *, at=None, key=None, **extra):
    response = _post_envelope(client, c["assignment"], c["headers"], envelope(c, value, at=at, key=key, **extra))
    assert response.status_code == 200, response.text
    projection_id, status = _project_one()
    assert status == KnowledgeProjectionStatus.SUCCEEDED
    with session() as db:
        return db.get(KnowledgeProjection, projection_id).result_summary


@pytest.mark.parametrize("value,expected", [(91, True), (90, False), (None, None), (True, None), ("99", None)])
def test_typed_predicate_never_coerces_missing_boolean_or_string_into_numeric_recovery(value, expected):
    definition = CollectorConditionDefinition.model_validate(SPEC)
    observation = CollectorConditionObservation(condition_key="cpu.high", value=value)
    assert evaluate_condition(definition, observation) is expected


def test_collector_cannot_supply_a_verdict_or_authority_claim():
    with pytest.raises(ValidationError):
        CollectorConditionObservation.model_validate({"condition_key": "cpu.high", "value": 10, "state": "quiet",
            "independently_verified": True})
    with pytest.raises(ValidationError):
        CollectorConditionDefinition.model_validate({**SPEC, "expected": True})


def test_active_unknown_and_newer_quiet_share_exact_pinned_source_not_closure_authority(client):
    c = fixture(client)
    active = submit(client, c, 99)
    unknown = submit(client, c, True, at=c["at"]+timedelta(seconds=1))
    assert active["verdict"] == "active" and unknown["verdict"] == "unknown"
    assert active["source_id"] == unknown["source_id"] and unknown["alert_status"] == "open"
    quiet = submit(client, c, 10, at=c["at"]+timedelta(seconds=2))
    assert quiet["verdict"] == "quiet" and quiet["alert_status"] == "resolved"
    assert quiet["independently_verified"] is False and quiet["authorizes_incident_closure"] is False
    with session() as db:
        assert db.scalar(select(func.count()).select_from(CollectorConditionSource)) == 1
        assert db.scalar(select(func.count()).select_from(CollectorConditionReceipt)) == 3
        capture = db.scalar(select(CollectorConditionAdmission))
        assert capture.context["worker_auth_method"] == "bearer_only"
        assert capture.context["pins"]["version_content_hash"]
        assert capture.context["pins"]["entity"]["identity_revision"] == c["device"]["identity_revision"]


def test_same_time_different_measurements_conflict_even_when_both_claim_high(client):
    c = fixture(client)
    first = submit(client, c, 99)
    second = submit(client, c, 98)
    assert second["observation_disposition"] == "conflict" and second["condition_state"] == "conflict"
    assert second["occurrence_count"] == first["occurrence_count"] == 1
    duplicate = submit(client, c, 98)
    assert duplicate["condition_state"] == "conflict" and duplicate["occurrence_count"] == 1
    submit(client, c, 95, at=c["at"]+timedelta(seconds=1))
    with session() as db:
        assert db.scalar(select(AlertConditionState)).state == "active"
        assert db.scalar(select(Alert)).occurrence_count == 2


def test_same_time_equal_measurement_is_idempotent_and_old_recovery_is_stale(client):
    c = fixture(client)
    first = submit(client, c, 99, at=c["at"]+timedelta(seconds=2))
    retry = submit(client, c, 99, at=c["at"]+timedelta(seconds=2))
    old = submit(client, c, 10, at=c["at"]+timedelta(seconds=1))
    assert retry["observation_disposition"] == "duplicate" and retry["occurrence_count"] == 1
    assert old["observation_disposition"] == "stale" and old["alert_status"] == "open"
    assert old["source_id"] == first["source_id"]


def test_quiet_before_first_active_blocks_older_creation_without_fabricating_alert(client):
    c = fixture(client)
    quiet = submit(client, c, 10, at=c["at"]+timedelta(seconds=2))
    old = submit(client, c, 99, at=c["at"]+timedelta(seconds=1))
    assert quiet["alert_id"] is None and quiet["verdict"] == "quiet"
    assert old["observation_disposition"] == "stale" and old["alert_id"] is None
    with session() as db:
        assert db.scalar(select(func.count()).select_from(Alert)) == 0


def test_generic_alert_input_cannot_impersonate_reserved_collector_source(client):
    c = fixture(client)
    result = submit(client, c, 99)
    with session() as db:
        key = db.get(CollectorConditionSource, result["source_id"]).dedup_key
        with pytest.raises(ValueError, match="sealed envelope"):
            resolve_by_dedup_key(db, key, "fake-recovery", c["at"]+timedelta(seconds=1))
        with pytest.raises(ValueError, match="sealed envelope"):
            observe_unknown_condition(db, key, c["at"]+timedelta(seconds=1),
                source_identity=("device.cpu.high", "device", c["device"]["id"], None))
        db.rollback()
    response = client.post("/api/v1/alerts/events", json={"dedup_key": key, "event_type": "device.cpu.high",
        "entity_type": "device", "entity_id": c["device"]["id"], "title": "Impersonated source"})
    assert response.status_code == 409 and "sealed envelope" in response.text
    assert client.post(f'/api/v1/alerts/{result["alert_id"]}/resolve', json={"actor": "manual-operator"}).status_code == 200
    with session() as db:
        assert db.scalar(select(AlertConditionState)).state == "active"


@pytest.mark.parametrize("field", ["worker_token", "deployment", "definition", "envelope", "device"])
def test_projection_refuses_drift_after_sealed_acceptance(client, field):
    from icheck.models import CollectionEnvelope, Device
    c = fixture(client)
    response = _post_envelope(client, c["assignment"], c["headers"], envelope(c, 10))
    assert response.status_code == 200, response.text
    with session() as db:
        if field == "worker_token":
            db.get(CollectorWorker, c["worker_id"]).token_issued_at = utcnow()+timedelta(seconds=1)
        elif field == "deployment":
            db.get(CollectorDeployment, c["deployment_id"]).configuration = {"different": True}
        elif field == "definition":
            version = db.get(ArtifactVersion, c["version_id"])
            version.definition = {"condition_contracts": [{**SPEC, "expected": 5}]}
        elif field == "envelope":
            row = db.scalar(select(CollectionEnvelope))
            row.payload = {"condition_key": "cpu.high", "value": 99}
        else:
            db.get(Device, c["device"]["id"]).site = "other-site"
        db.commit()
    _projection_id, status = _project_one()
    assert status == KnowledgeProjectionStatus.DEAD_LETTER
    with session() as db:
        assert db.scalar(select(func.count()).select_from(CollectorConditionReceipt)) == 0
        assert db.scalar(select(func.count()).select_from(Alert)) == 0
        assert db.scalar(select(func.count()).select_from(CollectorConditionAdmission)) == 1


def test_condition_idempotency_reuse_for_changed_value_is_error_not_silent_duplicate(client):
    c = fixture(client)
    first = _post_envelope(client, c["assignment"], c["headers"], envelope(c, 99, key="same-id"))
    assert first.status_code == 200 and first.json()["accepted"] == 1, first.text
    retry = _post_envelope(client, c["assignment"], c["headers"], envelope(c, 99, key="same-id"))
    assert retry.status_code == 200 and retry.json()["duplicates"] == 1, retry.text
    changed = _post_envelope(client, c["assignment"], c["headers"], envelope(c, 10, key="same-id"))
    assert changed.status_code == 409 and "different observation" in changed.text
    with session() as db:
        assert db.scalar(select(func.count()).select_from(CollectorConditionAdmission)) == 1


def test_failed_batch_rolls_back_prior_sealed_acceptance(client):
    c = fixture(client)
    response = client.post(f'/api/v1/collector-runs/{c["assignment"]["run_id"]}/envelopes',
        headers=c["headers"], json={"lease_token": c["assignment"]["lease_token"],
            "envelopes": [envelope(c, 99), envelope(c, 10, condition_key="not-declared")]})
    assert response.status_code == 409
    with session() as db:
        assert db.scalar(select(func.count()).select_from(CollectorConditionAdmission)) == 0
        assert db.scalar(select(func.count()).select_from(KnowledgeProjection)) == 0


def test_recovered_projection_receipt_is_exact_historical_result_not_another_mutation(client):
    from icheck.models import CollectionEnvelope
    c = fixture(client)
    original = submit(client, c, 99)
    with session() as db:
        row = db.scalar(select(CollectionEnvelope))
        assert project_condition(db, row) == original
        db.commit()
        assert db.scalar(select(Alert)).occurrence_count == 1
        assert db.scalar(select(func.count()).select_from(CollectorConditionReceipt)) == 1


@pytest.mark.parametrize("kind", ["before_admission", "future", "wrong_entity", "caller_verdict"])
def test_invalid_measurement_never_creates_acceptance_provenance(client, kind):
    c = fixture(client)
    frame = envelope(c, 99)
    if kind == "before_admission":
        frame["observed_at"] = (c["at"]-timedelta(minutes=1)).isoformat()
    elif kind == "future":
        frame["observed_at"] = (c["at"]+timedelta(minutes=6)).isoformat()
    elif kind == "wrong_entity":
        frame["payload"]["entity_id"] = "another-device"
    else:
        frame["payload"]["state"] = "quiet"
    response = _post_envelope(client, c["assignment"], c["headers"], frame)
    assert response.status_code == 409, response.text
    with session() as db:
        assert db.scalar(select(func.count()).select_from(CollectorConditionAdmission)) == 0
        assert db.scalar(select(func.count()).select_from(KnowledgeProjection)) == 0


def grant(client, c):
    response = client.post(f'/api/v1/collector-runs/{c["assignment"]["run_id"]}/credential-grant',
        headers=c["headers"], json={"lease_token": c["assignment"]["lease_token"]})
    assert response.status_code == 200, response.text
    return response.json()


def credential_case(client):
    response = client.post("/api/v1/credential-profiles", json={"name": "condition-profile", "provider": "vault",
        "secret_ref": "vault-kv2://kv/condition/v1#token", "allowed_adapters": ["http_json"],
        "worker_selector": {"site": "HQ"}, "created_by": "security"})
    assert response.status_code == 201, response.text
    c = fixture(client, credential_profile_ref=response.json()["id"])
    c["profile_id"] = response.json()["id"]
    return c


def rotate(client, c):
    response = client.post(f'/api/v1/credential-profiles/{c["profile_id"]}/rotate', json={
        "expected_revision": 0, "secret_ref": "vault-kv2://kv/condition/v2#token",
        "reason": "Controlled credential generation change", "actor": "security"})
    assert response.status_code == 200, response.text


def test_credentialed_condition_requires_actual_grant_before_observation(client):
    c = credential_case(client)
    no_grant = _post_envelope(client, c["assignment"], c["headers"], envelope(c, 99))
    assert no_grant.status_code == 409 and "matching issued credential grant" in no_grant.text
    grant(client, c)
    before = _post_envelope(client, c["assignment"], c["headers"], envelope(c, 99))
    assert before.status_code == 409 and "precedes its credential grant" in before.text
    result = submit(client, c, 99, at=utcnow())
    with session() as db:
        admission = db.get(CollectorConditionAdmission, result["admission_id"])
        assert admission.credential_grant_audit_id == admission.context["credential_grant_audit_id"]
        assert admission.credential_grant_audit_id
        assert admission.context["pins"]["credential_profile"]["profile_revision"] == 0


def test_credential_revision_changes_source_generation_and_cannot_recover_previous_alert(client):
    c = credential_case(client)
    grant(client, c)
    high = submit(client, c, 99, at=utcnow())
    rotate(client, c)
    grant(client, c)
    low = submit(client, c, 10, at=utcnow())
    assert low["source_id"] != high["source_id"] and low["alert_id"] is None
    with session() as db:
        assert db.get(Alert, high["alert_id"]).status == AlertStatus.OPEN
        assert db.scalar(select(func.count()).select_from(CollectorConditionSource)) == 2


def test_credential_rotation_after_acceptance_is_dead_letter_not_recovery(client):
    c = credential_case(client)
    grant(client, c)
    response = _post_envelope(client, c["assignment"], c["headers"], envelope(c, 10, at=utcnow()))
    assert response.status_code == 200, response.text
    rotate(client, c)
    _id, status = _project_one()
    assert status == KnowledgeProjectionStatus.DEAD_LETTER
    with session() as db:
        assert db.scalar(select(func.count()).select_from(CollectorConditionAdmission)) == 1
        assert db.scalar(select(func.count()).select_from(CollectorConditionReceipt)) == 0


def test_delayed_measurement_exceeding_version_freshness_is_unknown_not_quiet(client, monkeypatch):
    c = fixture(client)
    active = submit(client, c, 99)
    response = _post_envelope(client, c["assignment"], c["headers"],
        envelope(c, 10, at=c["at"]+timedelta(seconds=1)))
    assert response.status_code == 200, response.text
    monkeypatch.setattr("icheck.services.collector_conditions.utcnow", lambda: c["at"]+timedelta(seconds=302))
    _projection_id, status = _project_one()
    assert status == KnowledgeProjectionStatus.SUCCEEDED
    with session() as db:
        assert db.get(Alert, active["alert_id"]).status == AlertStatus.OPEN
        receipt = db.scalar(select(CollectorConditionReceipt).order_by(CollectorConditionReceipt.observed_at.desc()))
        assert receipt.verdict == "unknown" and receipt.result["condition_state"] == "unknown"
