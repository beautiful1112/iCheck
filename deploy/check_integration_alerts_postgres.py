"""Temporary PostgreSQL cluster and synthetic source; no installed services."""
from datetime import timedelta
from check_monitoring_integrations_postgres import main


def verify(engine, identifier, principal):
    from sqlalchemy import select, text, func
    from sqlalchemy.orm import Session
    from sqlalchemy.exc import DBAPIError
    from icheck.database import set_session_namespace
    from icheck.models import (MonitoringIntegrationConnection as Connection, MonitoringIntegrationSync as Sync,
        MonitoringIntegrationResource as Resource, MonitoringIntegrationBinding as Binding,
        MonitoringIntegrationAlertFeed as Feed, MonitoringIntegrationEvent as Event, Device, Alert,
        AIProviderConfig, AIModelConfig, AIModelRoute, Investigation, AgentExecution, AgentExecutionStatus,
        AlertInvestigationPolicy, AlertInvestigationEvent, utcnow)
    from icheck.services import integration_alerts as alerts, monitoring_integrations as integrations
    from icheck.integration_schemas import AlertFeedUpdate
    from icheck.worker_database_roles import inspect_worker_grants

    class Source:
        suppressed = "0"
        clock = str(int(utcnow().timestamp()))

        def __init__(self, endpoint, token, **bounds):
            assert token == "synthetic-integration-token"

        def request(self, payload, **bounds):
            method = payload["method"]
            if method == "apiinfo.version":
                result = "7.4.2"
            elif method == "problem.get":
                result = [{"eventid": "200"}]
            elif method == "event.get":
                result = [{"eventid": "200", "objectid": "300", "source": "0", "object": "0", "value": "1",
                    "name": "Fixture loss", "severity": "4", "clock": self.clock,
                    "acknowledged": "0", "suppressed": self.suppressed, "r_eventid": "0", "hosts": [{"hostid": "100"}]}]
            elif method == "host.get":
                result = [{"hostid": "100", "host": "fixture", "name": "Fixture", "status": "0", "hostgroups": [{"groupid": "2"}]}]
            else:
                raise AssertionError("Unexpected synthetic method")
            return {"jsonrpc": "2.0", "id": payload["id"], "result": result}

    integrations.TRANSPORT = Source
    ns = {"tenant_id": principal.tenant_id, "region_id": principal.region_id}
    with engine.begin() as db:
        db.exec_driver_sql("CREATE ROLE alert_reader LOGIN NOSUPERUSER NOBYPASSRLS")
        db.exec_driver_sql("REVOKE TEMP ON DATABASE integration_acceptance FROM PUBLIC")
        db.exec_driver_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    report = inspect_worker_grants(str(engine.url), profile="integration-alert-worker", role="alert_reader", apply=True)
    assert report["complete"], report

    with Session(engine, expire_on_commit=False) as db:
        set_session_namespace(db, **ns)
        connection = db.get(Connection, identifier)
        connection.enabled = True
        device = Device(name="Fixture", kind="network", **ns)
        sync = Sync(connection_id=identifier, connection_revision=2, status="completed", host_ids=["100"],
                    cursor=1, total=1, observed=1, created_by="fixture", **ns)
        db.add_all([device, sync]); db.flush()
        resource = Resource(connection_id=identifier, connection_revision=2, remote_id="100",
            name="Fixture", monitoring_enabled=True, observed_at=utcnow(), last_run_id=sync.id, **ns)
        db.add(resource); db.flush()
        db.add(Binding(resource_id=resource.id, connection_id=identifier, device_id=device.id, revision=1,
            connection_revision=2, source_name="Fixture", device_identity_revision=device.identity_revision,
            reviewed_by="fixture", **ns))
        db.commit()
        alerts.update_feed(db, identifier, AlertFeedUpdate(expected_revision=2, expected_feed_revision=0,
            enabled=True, confirm=True), principal)

    def worker(db):
        db.execute(text("SET LOCAL ROLE alert_reader"))
        set_session_namespace(db, **ns)

    def due():
        with Session(engine) as db:
            feed = db.get(Feed, identifier)
            feed.next_run_at, feed.phase = utcnow() - timedelta(seconds=1), "reconcile"
            db.commit()

    # No namespace means no source visibility, even to a worker with valid grants.
    with engine.begin() as db:
        db.exec_driver_sql("SET LOCAL ROLE alert_reader")
        for table in ("monitoring_integration_alert_feeds", "monitoring_integration_events"):
            assert db.scalar(text(f"SELECT row_security_active('{table}')"))
            assert db.scalar(text(f"SELECT count(*) FROM {table}")) == 0
    # Concurrent workers skip a connection already locked for a poll/configuration.
    with Session(engine) as owner, Session(engine) as contender:
        owner.get(Connection, identifier, with_for_update=True)
        worker(contender)
        assert alerts.poll_once(contender) is False
        owner.rollback()
    for _ in range(2):
        with Session(engine) as db:
            worker(db)
            assert alerts.poll_once(db)
    with Session(engine, expire_on_commit=False) as db:
        event = db.scalar(select(Event))
        alert_id = event.alert_id
        assert alert_id and db.scalar(select(func.count()).select_from(Alert)) == 1
        provider = AIProviderConfig(name="Fixture", provider_type="openai_compatible",
            base_url="https://fixture.invalid/v1", created_by="fixture", **ns)
        db.add(provider); db.flush()
        model = AIModelConfig(provider_id=provider.id, model_name="fixture", display_name="Fixture", created_by="fixture", **ns)
        db.add(model); db.flush()
        route = AIModelRoute(purpose="fixture", primary_model_id=model.id, created_by="fixture", **ns)
        policy = AlertInvestigationPolicy(updated_by="fixture", **ns)
        db.add_all([route, policy]); db.flush()
        investigation = Investigation(title="Fixture", objective="Read only", execution_mode="diagnose",
            status="running", route_id=route.id, model_id=model.id, max_iterations=2, max_tool_calls=2,
            timeout_seconds=60, token_budget=1000, created_by="fixture", **ns)
        db.add(investigation); db.flush()
        execution = AgentExecution(investigation_id=investigation.id, **ns)
        db.add(execution)
        db.add(AlertInvestigationEvent(policy_id=policy.id, policy_revision=1, alert_id=alert_id,
            investigation_id=investigation.id, group_key="fixture", status="dispatched", reason="fixture", **ns))
        db.commit()
        execution_id = execution.id

    Source.suppressed = "1"
    due()
    # Projection, event cursor and cancellation all roll back together.
    with Session(engine) as db:
        worker(db)
        alerts._poll_locked(db, db.get(Connection, identifier, with_for_update=True), db.get(Feed, identifier, with_for_update=True))
        db.rollback()
    with Session(engine) as db:
        assert db.get(AgentExecution, execution_id).status == AgentExecutionStatus.QUEUED
        assert db.scalar(select(Event)).stopped_at is None
    with Session(engine) as db:
        worker(db)
        assert alerts.poll_once(db)
    with Session(engine) as db:
        assert db.get(AgentExecution, execution_id).status == AgentExecutionStatus.CANCELLED
        assert db.scalar(select(Event)).stopped_at
        assert db.get(Alert, alert_id).status.value == "open"

    denied = (
        "UPDATE monitoring_integration_alert_feeds SET enabled=false",
        "UPDATE monitoring_integration_connections SET encrypted_token='x'",
        "UPDATE monitoring_integration_bindings SET revision=revision+1",
        "DELETE FROM monitoring_integration_events",
        "SELECT * FROM credential_profiles",
    )
    for sql in denied:
        with Session(engine) as db:
            worker(db)
            try:
                db.execute(text(sql))
            except DBAPIError:
                db.rollback()
            else:
                raise AssertionError("Worker exceeded its permission boundary")
    return ["alert_feed_rls", "skip_locked_no_duplicate_poll", "restricted_worker_projection",
        "durable_event_identity", "atomic_cancellation_rollback", "worker_cancels_queued_investigation",
        "suppression_not_resolution", "worker_cannot_enable_rotate_map_delete_or_read_device_secrets"]


if __name__ == "__main__":
    main(extra_checks=verify)
