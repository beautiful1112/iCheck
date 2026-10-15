"""Durable, namespace-local ownership across model calls and authoring commits.

Never hold a database lock over the model transport. Its own audit may commit;
the durable lease, rather than that transaction, fences late responses.
"""
from dataclasses import dataclass
from datetime import UTC, timedelta
import hashlib
import json
import secrets
from typing import Callable
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, selectinload

from ..collector_schemas import ArtifactCreate
from ..models import Artifact, AuditEvent, CapabilityStudioGenerationAttempt as Attempt, CapabilityStudioSession, utcnow
from ..studio_schemas import CapabilityStudioSessionRead
from .artifact_lifecycle import lock_artifact_version, prepare_artifact_mutation
from .audit import record_audit_event
from .collectors import create_artifact, create_artifact_version, validate_artifact_version
from .structured_model import (
    OpenAICompatibleStructuredGenerator,
    StructuredGenerationResult,
    StructuredModelUnavailable,
)
from .ai_authoring_quota import AuthoringQuotaConflict, AuthoringQuotaExceeded


LEASE_SECONDS = 1800
ACTIVE_PHASES = {"generating", "generated", "draft"}


class StudioGenerationConflict(ValueError):
    """Another owner, uncertain external outcome, or changed review intent."""


class StudioGenerationFailed(ValueError):
    pass


def digest(document, *, limit=1_048_576):
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    if len(encoded) > limit:
        raise ValueError("Studio generation record exceeds its storage bound")
    return hashlib.sha256(encoded).hexdigest()


def _now(db):
    # Worker clock skew must not decide whether another owner can be stolen.
    if db.get_bind().dialect.name == "postgresql":
        return db.scalar(select(func.clock_timestamp()))
    return utcnow()


def _future(db):
    return _now(db) + timedelta(seconds=LEASE_SECONDS)


def _expired(db, attempt):
    return attempt.lease_expires_at.replace(tzinfo=UTC) <= _now(db)


def lock_studio_session(db: Session, session_id: str) -> CapabilityStudioSession:
    prepare_artifact_mutation(db, purpose="Studio authoring transactions")
    with db.no_autoflush:
        session = db.scalar(select(CapabilityStudioSession).where(CapabilityStudioSession.id == session_id)
            .options(selectinload(CapabilityStudioSession.messages)).with_for_update()
            .execution_options(populate_existing=True))
    if session is None:
        raise LookupError("Capability Studio session not found in the selected namespace")
    return session


def _attempt(db, attempt_id):
    return db.scalar(select(Attempt).where(Attempt.id == attempt_id).with_for_update()
        .execution_options(populate_existing=True))


def _audit(db, session, attempt, suffix, *, outcome="success", external_charge_unknown=None, diagnostic=None):
    record_audit_event(db, event_type=f"capability.studio.generation.{suffix}",
        actor_type="user", actor_id=attempt.actor, entity_type="capability_studio_session",
        entity_id=session.id, outcome=outcome, details={"generation_attempt_id": attempt.id,
            "request_sha256": attempt.request_sha256, "artifact_version_id": attempt.artifact_version_id,
            "failure_code": attempt.failure_code, "prompt_sha256": attempt.prompt_sha256,
            "model_document_sha256": attempt.model_document_sha256, "candidate_sha256": attempt.candidate_sha256,
            "result_sha256": attempt.result_sha256, "route_id": attempt.route_id, "model_id": attempt.model_id,
            "token_usage": attempt.tokens_used, "usage_recorded": attempt.usage_recorded,
            **({"diagnostic": diagnostic} if diagnostic is not None else {}),
            **({"external_charge_unknown": external_charge_unknown}
               if external_charge_unknown is not None else {})})


def _snapshot(attempt):
    if not attempt.result_snapshot or digest(attempt.result_snapshot) != attempt.result_sha256:
        raise StudioGenerationConflict("Recorded Studio outcome failed integrity verification")
    result = CapabilityStudioSessionRead.model_validate(attempt.result_snapshot)
    if (result.generation_attempt_id != attempt.id or result.artifact_id != attempt.artifact_id
        or result.artifact_version_id != attempt.artifact_version_id or result.status != "validated"):
        raise StudioGenerationConflict("Recorded Studio outcome is not bound to its exact candidate")
    return result


def _reconcile_completed_usage(db, session, attempt):
    """Recover known usage from an exact attempt audit, never infer response bytes."""
    if attempt.usage_recorded:
        return
    completed = list(db.scalars(select(AuditEvent).where(
        AuditEvent.event_type == "capability.model.completed", AuditEvent.outcome == "success",
        AuditEvent.entity_type == "capability_studio_generation_attempt", AuditEvent.entity_id == attempt.id)))
    if not completed:
        return  # Unknown does not mean a free or unexecuted provider request.
    if len(completed) != 1:
        raise StudioGenerationConflict("Model usage has multiple completed audits; operator reconciliation is required")
    details = completed[0].details
    tokens = details.get("token_usage")
    if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
        raise StudioGenerationConflict("Completed model usage audit is invalid")
    if not details.get("route_id") or not details.get("model_id"):
        raise StudioGenerationConflict("Completed model usage audit has no route or model identity")
    attempt.tokens_used, attempt.usage_recorded = tokens, True
    attempt.route_id, attempt.model_id = details["route_id"], details["model_id"]
    session.tokens_used += tokens


@dataclass
class StudioGeneration:
    db: Session
    session_id: str
    attempt_id: str
    owner_sha256: str
    gateway: object

    def owned(self):
        session = lock_studio_session(self.db, self.session_id)
        attempt = _attempt(self.db, self.attempt_id)
        if (attempt is None or attempt.session_id != session.id
            or session.generation_attempt_id != attempt.id or attempt.owner_sha256 != self.owner_sha256
            or attempt.status not in ACTIVE_PHASES or _expired(self.db, attempt)):
            raise StudioGenerationConflict("Studio generation ownership changed or expired; reconcile the recorded request")
        attempt.lease_expires_at = _future(self.db)
        attempt.updated_at = utcnow()
        return session, attempt

    def generate(self, **kwargs):
        """Gateway proxy: account a completed model result exactly once."""
        session, attempt = self.owned()
        if attempt.model_document_sha256:
            if (attempt.model_schema != kwargs["schema_name"]
                or digest(attempt.model_document, limit=262_144) != attempt.model_document_sha256):
                raise StudioGenerationConflict("Saved model proposal failed schema or integrity verification")
            result = StructuredGenerationResult(document=kwargs["response_model"].model_validate(attempt.model_document),
                route_id=attempt.route_id, model_id=attempt.model_id, tokens_used=attempt.tokens_used)
            # Release before deterministic compilation. No new model call.
            self.db.commit()
            return result
        # Research happens only for a new authoring request, never on a replay
        # of its retained model response. It cannot change a completed candidate.
        from ..config import get_settings
        if get_settings().research_enabled:
            from .research_authoring import references, AUTHORING_RESEARCH_POLICY
            # Release the ownership lock before bounded public network reads.
            self.db.commit()
            evidence = references(kwargs["prompt_document"], db=self.db)
            session, attempt = self.owned()
            kwargs = {**kwargs, "system_prompt": kwargs["system_prompt"] + AUTHORING_RESEARCH_POLICY,
                      "prompt_document": {**kwargs["prompt_document"], "public_research": evidence}}
            from ..models import CapabilityStudioMessage
            content = "Public reference research: " + evidence["status"]
            self.db.add(CapabilityStudioMessage(session_id=session.id, role="system",
                content=content, content_hash=hashlib.sha256(content.encode()).hexdigest(),
                structured_content={"public_research": {key: value for key, value in evidence.items() if key != "documents"},
                    "research_documents": [{key: value for key, value in doc.items() if key != "text"}
                                           for doc in evidence.get("documents", [])]}))
        attempt.model_schema = kwargs["schema_name"]
        attempt.prompt_sha256 = digest({"purpose": kwargs["route_purpose"], "schema": kwargs["schema_name"],
            "system": kwargs["system_prompt"], "prompt": kwargs["prompt_document"]})
        self.db.commit()
        result = self.gateway.generate(**{**kwargs, "entity_type": "capability_studio_generation_attempt", "entity_id": self.attempt_id})
        document = result.document.model_dump(mode="json")
        document_sha = digest(document, limit=262_144)
        if result.tokens_used < 0:
            raise ValueError("Model usage cannot be negative")
        # Even a late response is accounted, but it cannot change the current
        # spec, candidate, status, or messages belonging to a newer request.
        session = lock_studio_session(self.db, self.session_id)
        attempt = _attempt(self.db, self.attempt_id)
        if attempt is None or attempt.session_id != session.id:
            raise StudioGenerationConflict("Studio generation record disappeared")
        owned = (session.generation_attempt_id == attempt.id and attempt.owner_sha256 == self.owner_sha256
            and attempt.status in ACTIVE_PHASES and not _expired(self.db, attempt))
        if not attempt.model_document_sha256:
            if attempt.usage_recorded and (attempt.tokens_used != result.tokens_used
                or attempt.route_id != result.route_id or attempt.model_id != result.model_id):
                raise StudioGenerationConflict("Model response contradicts its previously reconciled usage")
            attempt.model_document = document
            attempt.model_document_sha256 = document_sha
            attempt.route_id, attempt.model_id = result.route_id, result.model_id
            if not attempt.usage_recorded:
                attempt.tokens_used = result.tokens_used
                attempt.usage_recorded = True
                session.tokens_used += result.tokens_used
            attempt.updated_at = utcnow()
        elif attempt.model_document_sha256 != document_sha:
            raise StudioGenerationConflict("A different model response already owns this request")
        if owned:
            attempt.status = "generated"
            attempt.lease_expires_at = _future(self.db)
        self.db.commit()
        if not owned:
            raise StudioGenerationConflict("Late model response recorded without candidate admission")
        return result

    def save_spec(self, spec):
        session, attempt = self.owned()
        session.route_id, session.model_id = attempt.route_id, attempt.model_id
        session.current_spec = spec.model_dump(mode="json")
        session.updated_at = utcnow()
        self.db.commit()
        return session

    def candidate(self, payload: ArtifactCreate):
        session, attempt = self.owned()
        candidate_sha = digest(payload.model_dump(mode="json"))
        if attempt.artifact_version_id:
            if attempt.candidate_sha256 != candidate_sha:
                raise StudioGenerationConflict("Compiled candidate changed; use a new authoring request")
            version = lock_artifact_version(self.db, attempt.artifact_version_id)
            if version.artifact_id != attempt.artifact_id:
                raise StudioGenerationConflict("Recorded candidate ownership is inconsistent")
            artifact = version.artifact
        else:
            if session.artifact_id:
                artifact = self.db.get(Artifact, session.artifact_id)
                if artifact is None:
                    raise ValueError("Studio Artifact no longer exists")
                artifact = create_artifact_version(self.db, artifact, payload.initial_version, commit=False)
            else:
                artifact = create_artifact(self.db, payload, commit=False)
            # MAX is safe only while the shared Artifact identity lock is still
            # held. The version and its Studio reference commit together.
            version = max(artifact.versions, key=lambda item: item.version)
            attempt.artifact_id, attempt.artifact_version_id = artifact.id, version.id
            attempt.candidate_sha256 = candidate_sha
        session.artifact_id, session.artifact_version_id = artifact.id, version.id
        session.updated_at = utcnow()
        attempt.status = "draft"
        self.db.commit()
        return artifact, version

    def validate(self, version, actor, *, sandbox_executor=None):
        _, attempt = self.owned()
        if version.id != attempt.artifact_version_id:
            raise StudioGenerationConflict("Validation does not own the recorded candidate")
        # The Studio owner lock is held before the Artifact identity/version
        # locks, through validation, message, audit, and outcome snapshot.
        return validate_artifact_version(self.db, version, actor, sandbox_executor=sandbox_executor, commit=False)

    def finish(self):
        # validate() still holds both ownership and version locks. Flush first
        # so refreshing relationships includes this operation's new message.
        self.db.flush()
        session, attempt = self.owned()
        if (session.artifact_version_id != attempt.artifact_version_id
            or session.artifact_id != attempt.artifact_id or session.status != "validated"):
            raise StudioGenerationConflict("Validated outcome lost its exact candidate ownership")
        attempt.status = "validated"
        self.db.flush()
        result = CapabilityStudioSessionRead.model_validate(session)
        snapshot = result.model_dump(mode="json")
        attempt.result_sha256 = digest(snapshot)
        attempt.result_snapshot = snapshot
        _audit(self.db, session, attempt, "completed")
        self.db.commit()
        return result

    def fail(self, exc):
        self.db.rollback()
        try:
            session, attempt = self.owned()
        except (StudioGenerationConflict, LookupError):
            self.db.rollback()
            return
        if isinstance(exc, StructuredModelUnavailable) and not attempt.usage_recorded:
            # Provider-reported usage is a lower bound if another attempt's
            # charge is unknown, but must not disappear with the failed draft.
            attempt.tokens_used = exc.token_usage
            attempt.usage_recorded = True
            session.tokens_used += exc.token_usage
        elif isinstance(exc, (AuthoringQuotaExceeded, AuthoringQuotaConflict)):
            attempt.usage_recorded = True  # Admission failed before provider I/O.
        attempt.status, attempt.failure_code = "failed", type(exc).__name__[:64]
        attempt.updated_at = utcnow()
        session.status, session.updated_at = "failed", utcnow()
        _audit(self.db, session, attempt, "failed", outcome="failure",
            diagnostic=exc.diagnostic if isinstance(exc, StructuredModelUnavailable) else None,
            external_charge_unknown=(
                exc.external_charge_unknown
                if isinstance(exc, StructuredModelUnavailable) else False
                if isinstance(exc, (AuthoringQuotaExceeded, AuthoringQuotaConflict)) else None
            ))
        self.db.commit()


def run_studio_generation(db: Session, session: CapabilityStudioSession, *, actor: str,
    followup: str | None, request_key: str | None, generator, operation: Callable):
    prepare_artifact_mutation(db, purpose="Studio authoring transactions")
    session_id = session.id
    request_key = str(UUID(request_key)) if request_key else str(uuid4())
    request_document = {"actor": actor, "followup": followup, "kind": session.artifact_kind}
    request_sha = digest(request_document)
    context = None
    try:
        session = lock_studio_session(db, session_id)
        if session.artifact_kind != request_document["kind"]:
            raise StudioGenerationConflict("Studio authoring kind changed before claiming the request")
        existing = db.scalar(select(Attempt).where(Attempt.session_id == session.id, Attempt.request_key == request_key)
            .with_for_update().execution_options(populate_existing=True))
        if existing:
            if existing.request_sha256 != request_sha or digest(existing.request_document) != existing.request_sha256:
                raise StudioGenerationConflict("Request key is already bound to another authoring intent")
            if existing.status == "validated":
                result = _snapshot(existing)
                db.commit()
                return result
            if existing.status in {"failed", "interrupted"}:
                raise StudioGenerationFailed(f"Recorded generation is {existing.status} ({existing.failure_code}); use a new request key for a new iteration")
        current = _attempt(db, session.generation_attempt_id) if session.generation_attempt_id else None
        if current and current.status in ACTIVE_PHASES:
            if not _expired(db, current):
                raise StudioGenerationConflict("Studio generation is already in progress; retry its request after completion")
            if existing and current.id == existing.id and existing.model_document_sha256:
                # Recover only saved bytes, never repeat an uncertain model call.
                pass
            else:
                _reconcile_completed_usage(db, session, current)
                current.status, current.failure_code = "interrupted", "lease_expired_external_outcome_uncertain"
                current.updated_at = utcnow()
                _audit(db, session, current, "interrupted", outcome="failure")
                session.status, session.updated_at = "failed", utcnow()
                if existing:
                    db.commit()
                    raise StudioGenerationConflict("Interrupted model outcome is uncertain; start an explicitly new request")
        if existing and (session.generation_attempt_id != existing.id or existing.status not in ACTIVE_PHASES):
            raise StudioGenerationConflict("Request is no longer the current resumable generation")
        owner = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        if existing:
            attempt = existing
            attempt.owner_sha256, attempt.lease_expires_at = owner, _future(db)
            _audit(db, session, attempt, "resumed")
        else:
            attempt = Attempt(session_id=session.id, request_key=request_key, request_sha256=request_sha,
                request_document=request_document, actor=actor, owner_sha256=owner, lease_expires_at=_future(db))
            db.add(attempt)
            db.flush()
            session.generation_attempt_id = attempt.id
            if followup:
                from .capability_studio import _message
                db.add(_message(session, role="user", content=followup))
            _audit(db, session, attempt, "claimed")
        session.status, session.updated_at = "generating", utcnow()
        context = StudioGeneration(db, session.id, attempt.id, owner, generator or OpenAICompatibleStructuredGenerator(db))
        db.commit()
        return operation(db, session, actor=actor, generator=context, generation=context)
    except (DBAPIError, ConnectionError):
        # Unknown commit/process outcomes are reconciled from the durable phase
        # after lease expiry; don't relabel a committed success as a failure.
        db.rollback()
        raise
    except Exception as exc:
        if context:
            context.fail(exc)
        else:
            db.rollback()
        raise
