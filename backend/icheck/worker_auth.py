from __future__ import annotations

import hashlib
import secrets

from .models import AgentWorker, CollectorWorker


class WorkerAuthenticationError(ValueError):
    pass


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_worker_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def authenticate_worker(
    worker: CollectorWorker,
    authorization: str | None,
) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise WorkerAuthenticationError("Collector worker bearer token is required")
    if not secrets.compare_digest(worker.auth_token_hash, hash_token(token)):
        raise WorkerAuthenticationError("Invalid collector worker token")


def authenticate_agent_worker(
    worker: AgentWorker,
    authorization: str | None,
) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise WorkerAuthenticationError("Agent worker bearer token is required")
    if not secrets.compare_digest(worker.auth_token_hash, hash_token(token)):
        raise WorkerAuthenticationError("Invalid agent worker token")
