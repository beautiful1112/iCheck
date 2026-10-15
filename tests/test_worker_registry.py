"""Cached registry objects cannot reverse the persisted drain barrier."""
import pytest

from icheck.agent_schemas import AgentExecutionClaim, AgentWorkerHeartbeat, AgentWorkerRegister
from icheck.collector_schemas import CollectorLeaseClaim, CollectorWorkerHeartbeat, CollectorWorkerRegister
from icheck.database import SessionLocal
from icheck.device_schemas import DevicePreflightClaim
from icheck.models import AgentWorker, AgentWorkerState, CollectorWorker, CollectorWorkerState, utcnow
from icheck.services import agent_execution, collectors, devices


@pytest.mark.parametrize("kind", ["collector", "preflight", "agent"])
def test_cached_online_worker_cannot_claim_after_committed_drain(kind):
    model = AgentWorker if kind == "agent" else CollectorWorker
    state = AgentWorkerState if kind == "agent" else CollectorWorkerState
    with SessionLocal() as db:
        worker = model(name="stale-admission", capabilities=["http_json"], labels={"io_supervisor_v1": True},
            auth_token_hash="a" * 64, state=state.ONLINE, last_heartbeat_at=utcnow())
        db.add(worker)
        db.commit()
        with SessionLocal() as editor:
            editor.get(model, worker.id).state = state.DRAINING
            editor.commit()
        assert worker.state == state.ONLINE
        with pytest.raises(ValueError, match="Only online"):
            if kind == "collector": collectors.claim_deployments(db, worker, CollectorLeaseClaim())
            elif kind == "preflight": devices.claim_device_preflights(db, worker, DevicePreflightClaim())
            else: agent_execution.claim_agent_executions(db, worker, AgentExecutionClaim())


@pytest.mark.parametrize("kind", ["collector", "agent"])
def test_cached_heartbeat_and_reregistration_preserve_committed_drain(kind):
    model = AgentWorker if kind == "agent" else CollectorWorker
    state = AgentWorkerState if kind == "agent" else CollectorWorkerState
    with SessionLocal() as db:
        worker = model(name="drain-is-sticky", capabilities=["http_json"], labels={},
            auth_token_hash="a" * 64, state=state.ONLINE, last_heartbeat_at=utcnow())
        db.add(worker)
        db.commit()
        with SessionLocal() as editor:
            editor.get(model, worker.id).state = state.DRAINING
            editor.commit()
        assert worker.state == state.ONLINE
        if kind == "collector":
            result = collectors.heartbeat_worker(db, worker, CollectorWorkerHeartbeat(state="online"))
            registered, _ = collectors.register_worker(db, CollectorWorkerRegister(name=worker.name, capabilities=["http_json"], labels={}))
        else:
            result = agent_execution.heartbeat_agent_worker(db, worker, AgentWorkerHeartbeat(state="online"))
            registered, _ = agent_execution.register_agent_worker(db, AgentWorkerRegister(name=worker.name, capabilities=["http_json"], labels={}))
        assert result.state == registered.state == state.DRAINING
