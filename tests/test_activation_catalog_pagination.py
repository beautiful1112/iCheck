"""Large Studio activation catalogs remain searchable without hidden 500-row caps."""

from uuid import uuid4

from sqlalchemy import select

from icheck.database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace
from icheck.models import (
    Artifact, ArtifactKind, ArtifactVersion, ArtifactVersionStatus,
    CollectorDefinition, CollectorDeploymentMode, CollectorMode,
    DeviceActivationPolicy,
)


def _add_entry(db, index: int, *, tenant_id: str, region_id: str):
    artifact_id, version_id = str(uuid4()), str(uuid4())
    artifact = Artifact(
        id=artifact_id, tenant_id=tenant_id, region_id=region_id,
        kind=ArtifactKind.COLLECTOR, name=f"collector-{index:03d}",
        description="Paged catalog acceptance", owner="test.operator",
    )
    version = ArtifactVersion(
        id=version_id, tenant_id=tenant_id, region_id=region_id,
        artifact_id=artifact_id, version=1, status=ArtifactVersionStatus.PUBLISHED,
        created_by="test.operator",
    )
    definition = CollectorDefinition(
        tenant_id=tenant_id, region_id=region_id,
        artifact_version_id=version_id, adapter_type="http_json",
        mode=CollectorMode.POLL,
        target_schema={"type": "object", "properties": {"index": {"const": index}}},
        config_schema={"type": "object"}, defaults={},
    )
    policy = DeviceActivationPolicy(
        tenant_id=tenant_id, region_id=region_id,
        name=f"policy-{index:03d}", version=1,
        status=ArtifactVersionStatus.DRAFT,
        protocol="https_api", adapter_type="http_json",
        artifact_version_id=version_id,
        target_template={}, configuration_defaults={}, worker_selector={},
        execution_mode=CollectorDeploymentMode.SCHEDULED, schedule_seconds=300,
        created_by="test.operator",
    )
    # Explicitly flush the referenced rows: PostgreSQL enforces these FKs,
    # while SQLite's in-memory fixture does not enable them by default.
    db.add(artifact)
    db.flush()
    db.add(version)
    db.flush()
    db.add_all((definition, policy))
    return version_id


def _all_pages(client, path: str, *, limit: int = 100):
    items, cursor = [], None
    while True:
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        response = client.get(path, params=params)
        assert response.status_code == 200, response.text
        body = response.json()
        assert len(body["items"]) <= limit
        items.extend(body["items"])
        if body["next_cursor"] is None:
            break
        assert body["next_cursor"] != cursor
        cursor = body["next_cursor"]
    return items


def test_paged_activation_catalogs_reach_items_beyond_the_old_editor_limits(client):
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        version_ids = [
            _add_entry(db, index, tenant_id=DEFAULT_TENANT_ID, region_id=DEFAULT_REGION_ID)
            for index in range(525)
        ]
        db.flush()
        first_artifact = db.scalar(select(Artifact).where(Artifact.name == "collector-000"))
        assert first_artifact is not None
        second_version_id = str(uuid4())
        db.add(ArtifactVersion(
            id=second_version_id, tenant_id=DEFAULT_TENANT_ID,
            region_id=DEFAULT_REGION_ID, artifact_id=first_artifact.id,
            version=2, status=ArtifactVersionStatus.PUBLISHED,
            created_by="test.operator",
        ))
        db.add(CollectorDefinition(
            tenant_id=DEFAULT_TENANT_ID, region_id=DEFAULT_REGION_ID,
            artifact_version_id=second_version_id, adapter_type="http_json",
            mode=CollectorMode.POLL, target_schema={"type": "object"},
            config_schema={"type": "object"}, defaults={},
        ))
        db.add(DeviceActivationPolicy(
            tenant_id=DEFAULT_TENANT_ID, region_id=DEFAULT_REGION_ID,
            name="policy-000", version=2, status=ArtifactVersionStatus.DRAFT,
            protocol="https_api", adapter_type="http_json",
            artifact_version_id=second_version_id,
            target_template={}, configuration_defaults={}, worker_selector={},
            execution_mode=CollectorDeploymentMode.SCHEDULED, schedule_seconds=300,
            created_by="test.operator",
        ))
        db.commit()
    with SessionLocal() as db:
        other_tenant, other_region = str(uuid4()), str(uuid4())
        set_session_namespace(db, other_tenant, other_region)
        _add_entry(db, 999, tenant_id=other_tenant, region_id=other_region)
        db.commit()

    collectors = _all_pages(client, "/api/v1/assets/activation-collectors/page?protocol=https_api")
    assert len(collectors) == 526
    assert len({row["artifact_version_id"] for row in collectors}) == 526
    assert [row["version"] for row in collectors[:2]] == [2, 1]
    assert collectors[-1]["artifact_version_id"] == version_ids[-1]
    assert "target_schema" not in collectors[-1]  # Summaries stay bounded.
    detail = client.get(f"/api/v1/assets/activation-collectors/{version_ids[-1]}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["target_schema"]["properties"]["index"]["const"] == 524

    policies = _all_pages(client, "/api/v1/assets/activation-policies/page")
    assert len(policies) == 526
    assert len({row["id"] for row in policies}) == 526
    assert [row["version"] for row in policies[:2]] == [2, 1]
    assert policies[-1]["name"] == "policy-524"
    one_collector = client.get(
        "/api/v1/assets/activation-collectors/page",
        params={"protocol": "https_api", "limit": 1},
    ).json()
    second_collector = client.get(
        "/api/v1/assets/activation-collectors/page",
        params={"protocol": "https_api", "limit": 1,
                "cursor": one_collector["next_cursor"]},
    ).json()
    assert [one_collector["items"][0]["version"], second_collector["items"][0]["version"]] == [2, 1]
    assert client.get(
        "/api/v1/assets/activation-collectors/page",
        params={"protocol": "https_api", "name_prefix": "collector-52"},
    ).json()["items"][-1]["artifact_name"] == "collector-524"
    assert client.get(
        "/api/v1/assets/activation-policies/page",
        params={"name_prefix": "policy-52"},
    ).json()["items"][-1]["name"] == "policy-524"
    assert client.get(
        "/api/v1/assets/activation-collectors/page", params={"protocol": "snmp"},
    ).json()["items"] == []
    assert client.get(
        "/api/v1/assets/activation-collectors/page",
        params={"protocol": "https_api", "name_prefix": "collector-%"},
    ).json()["items"] == []  # Search metacharacters are literal.
    assert client.get(
        "/api/v1/assets/activation-collectors/page",
        params={"protocol": "invalid"},
    ).status_code == 400
    assert client.get(
        "/api/v1/assets/activation-collectors/page",
        params={"protocol": "https_api", "cursor": str(uuid4())},
    ).status_code == 400
    assert client.get(
        "/api/v1/assets/activation-policies/page", params={"cursor": str(uuid4())},
    ).status_code == 400
    assert client.get(
        "/api/v1/assets/activation-collectors/page", params={"limit": 101},
    ).status_code == 422
