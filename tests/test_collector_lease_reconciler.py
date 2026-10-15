"""Expired Collector leases close without another Worker request."""

from datetime import timedelta

from sqlalchemy import select

from icheck.collector_lease_reconciler import reconcile_once
from icheck.database import (
    DEFAULT_REGION_ID, DEFAULT_TENANT_ID, SessionLocal, set_session_namespace,
)
from icheck.models import (
    AuditEvent, CollectorDeployment, CollectorDeploymentMode, CollectorRun,
    CollectorRunStatus, Device, utcnow,
)

from test_collector_execution_admission import _admit, _claimed_external, _envelopes
from test_collectors import register_collector_worker


def _expire(deployment_id):
    with SessionLocal() as db:
        deployment = db.get(CollectorDeployment, deployment_id)
        deployment.lease_expires_at = utcnow() - timedelta(seconds=1)
        db.commit()


def _reconcile(*, limit=100):
    with SessionLocal() as db:
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        return reconcile_once(db, limit=limit)


def test_abandoned_external_run_is_terminal_and_idempotent(client):
    deployment, assignment, headers = _claimed_external(client)
    assert _admit(client, assignment, headers).status_code == 200
    _expire(deployment["id"])
    assert _reconcile() == 1
    assert _reconcile() == 0

    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        saved = db.get(CollectorDeployment, deployment["id"])
        assert run.status.value == "cancelled"
        assert run.finished_at is not None
        assert run.stats["cancel_reason"] == "lease_expired"
        assert saved.lease_token_hash is None
        assert saved.lease_worker_id is None
        assert saved.enabled is True
        assert saved.next_run_at > run.finished_at
        events = list(db.scalars(select(AuditEvent).where(
            AuditEvent.entity_id == run.id,
            AuditEvent.event_type == "collector.run.lease_expired",
        )).all())
        assert len(events) == 1
    assert _admit(client, assignment, headers).status_code == 409
    assert _envelopes(client, assignment, headers).status_code == 409


def test_reassignment_reconciles_previous_run_before_new_claim(client):
    deployment, assignment, _headers = _claimed_external(client)
    second, second_headers = register_collector_worker(
        client, name="lease-replacement-worker", site="LAB",
    )
    _expire(deployment["id"])
    claimed = client.post(
        f"/api/v1/collector-workers/{second['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60},
        headers=second_headers,
    )
    assert claimed.status_code == 200, claimed.text
    assert len(claimed.json()) == 1
    with SessionLocal() as db:
        old = db.get(CollectorRun, assignment["run_id"])
        new = db.get(CollectorRun, claimed.json()[0]["run_id"])
        assert old.status.value == "cancelled"
        assert old.stats["cancel_reason"] == "lease_expired"
        assert new.status.value == "running"
        assert list(db.scalars(select(AuditEvent).where(
            AuditEvent.entity_id == old.id,
            AuditEvent.event_type == "collector.run.lease_expired",
        )).all())


def test_rejected_reassignment_still_finalizes_old_run(client):
    deployment, assignment, _headers = _claimed_external(client)
    second, second_headers = register_collector_worker(
        client, name="lease-rejected-worker", site="LAB",
    )
    _expire(deployment["id"])
    with SessionLocal() as db:
        db.add(Device(
            name="new-owner-after-lease", kind="switch",
            management_ip="198.18.60.10", site="LAB",
            created_by="lease-test",
        ))
        db.commit()
    claimed = client.post(
        f"/api/v1/collector-workers/{second['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60},
        headers=second_headers,
    )
    assert claimed.status_code == 200, claimed.text
    assert claimed.json() == []
    with SessionLocal() as db:
        old = db.get(CollectorRun, assignment["run_id"])
        saved = db.get(CollectorDeployment, deployment["id"])
        assert old.status.value == "cancelled"
        assert saved.enabled is False
        assert saved.lease_token_hash is None


def test_expired_on_demand_run_is_not_rescheduled(client):
    deployment, _assignment, _headers = _claimed_external(client)
    with SessionLocal() as db:
        saved = db.get(CollectorDeployment, deployment["id"])
        saved.execution_mode = CollectorDeploymentMode.ON_DEMAND
        db.commit()
    _expire(deployment["id"])
    assert _reconcile() == 1
    with SessionLocal() as db:
        assert db.get(CollectorDeployment, deployment["id"]).next_run_at is None


def test_lease_missing_expiry_is_closed_fail_safe(client):
    deployment, assignment, _headers = _claimed_external(client)
    with SessionLocal() as db:
        saved = db.get(CollectorDeployment, deployment["id"])
        saved.lease_expires_at = None
        db.commit()
    assert _reconcile() == 1
    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        assert run.status.value == "cancelled"
        assert db.get(CollectorDeployment, deployment["id"]).lease_token_hash is None


def test_legacy_run_with_cleared_lease_is_repaired_once(client):
    deployment, assignment, headers = _claimed_external(client)
    with SessionLocal() as db:
        saved = db.get(CollectorDeployment, deployment["id"])
        saved.lease_worker_id = None
        saved.lease_token_hash = None
        saved.lease_expires_at = None
        db.commit()
    assert _reconcile(limit=1) == 1
    assert _reconcile(limit=1) == 0
    with SessionLocal() as db:
        run = db.get(CollectorRun, assignment["run_id"])
        saved = db.get(CollectorDeployment, deployment["id"])
        assert run.status == CollectorRunStatus.CANCELLED
        assert run.stats["cancel_reason"] == "lease_owner_lost"
        assert saved.enabled is True
        assert saved.next_run_at > run.finished_at
        assert len(list(db.scalars(select(AuditEvent).where(
            AuditEvent.entity_id == run.id,
            AuditEvent.event_type == "collector.run.orphan_reconciled",
        )).all())) == 1
    assert _admit(client, assignment, headers).status_code == 409


def test_legacy_orphan_does_not_revoke_newer_valid_lease(client):
    deployment, assignment, _headers = _claimed_external(client)
    second, second_headers = register_collector_worker(
        client, name="orphan-newer-worker", site="LAB",
    )
    _expire(deployment["id"])
    claimed = client.post(
        f"/api/v1/collector-workers/{second['id']}/leases/claim",
        json={"max_assignments": 1, "lease_seconds": 60},
        headers=second_headers,
    )
    assert claimed.status_code == 200, claimed.text
    current = claimed.json()[0]
    with SessionLocal() as db:
        old = db.get(CollectorRun, assignment["run_id"])
        old.status = CollectorRunStatus.RUNNING
        old.finished_at = None
        db.commit()
    assert _reconcile() == 1
    with SessionLocal() as db:
        old = db.get(CollectorRun, assignment["run_id"])
        new = db.get(CollectorRun, current["run_id"])
        saved = db.get(CollectorDeployment, deployment["id"])
        assert old.status == CollectorRunStatus.CANCELLED
        assert old.stats["cancel_reason"] == "lease_owner_lost"
        assert new.status == CollectorRunStatus.RUNNING
        assert saved.lease_token_hash == new.lease_token_hash
        assert saved.lease_worker_id == new.worker_id
    assert _admit(client, current, second_headers).status_code == 200


def test_legacy_on_demand_orphan_stays_idle(client):
    deployment, assignment, _headers = _claimed_external(client)
    with SessionLocal() as db:
        saved = db.get(CollectorDeployment, deployment["id"])
        saved.execution_mode = CollectorDeploymentMode.ON_DEMAND
        saved.lease_worker_id = None
        saved.lease_token_hash = None
        saved.lease_expires_at = None
        db.commit()
    assert _reconcile() == 1
    with SessionLocal() as db:
        assert db.get(CollectorRun, assignment["run_id"]).status.value == "cancelled"
        assert db.get(CollectorDeployment, deployment["id"]).next_run_at is None


