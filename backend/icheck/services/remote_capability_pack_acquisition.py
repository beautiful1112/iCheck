from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..capability_pack_schemas import (
    CapabilityPackInstallCreate,
    CapabilityPackInstallationRead,
    CapabilityPackPreviewCreate,
    CapabilityPackPreviewRead,
    SignedCapabilityPack,
)
from ..models import (
    ArtifactTrustKey,
    RemoteCapabilityCatalogEntry,
    RemoteCapabilityCatalogSnapshot,
    RemoteCapabilityCatalogSource,
    utcnow,
)
from ..remote_catalog_schemas import RemoteCatalogPackActionCreate
from ..sandbox import SandboxUnavailable
from ..database import require_locking_transaction
from .audit import record_audit_event
from .artifact_portability import ensure_trust_key_usable
from .trust_namespace import assert_selected_trust_namespace
from .capability_pack_revocations import active_pack_revocation
from .capability_packs import (
    PACK_MAX_BYTES,
    install_capability_pack,
    lock_pack_resources,
    pack_trust_requirements,
    preview_capability_pack,
)
from .remote_capability_catalogs import validate_remote_catalog_url
from .trust_authority import lock_trust_authorities


REMOTE_PACK_TIMEOUT_SECONDS = 20


class RemotePackUnavailable(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for remote capability packs",
            headers,
            fp,
        )


@dataclass(frozen=True)
class _EntryContext:
    entry: RemoteCapabilityCatalogEntry
    source: RemoteCapabilityCatalogSource
    snapshot: RemoteCapabilityCatalogSnapshot


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def fetch_remote_capability_pack(
    url: str,
    *,
    max_bytes: int = PACK_MAX_BYTES,
    timeout_seconds: int = REMOTE_PACK_TIMEOUT_SECONDS,
) -> bytes:
    request = Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "User-Agent": "iCheck-remote-pack/0.1",
        },
    )
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            content_type = response.headers.get_content_type()
            if content_type not in {"application/json", "text/json"}:
                raise RemotePackUnavailable(
                    "Remote capability pack did not return JSON"
                )
            body = response.read(max_bytes + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RemotePackUnavailable(
            "Remote capability pack fetch failed"
        ) from exc
    if len(body) > max_bytes:
        raise RemotePackUnavailable(
            f"Remote capability pack exceeded {max_bytes} bytes"
        )
    return body


def _current_entry_context(
    db: Session,
    entry_id: str,
    *,
    allowed_hosts: list[str],
    lock: bool = False,
    pack_payload: CapabilityPackPreviewCreate | None = None,
) -> _EntryContext:
    entry = db.scalar(select(RemoteCapabilityCatalogEntry).where(
        RemoteCapabilityCatalogEntry.id == entry_id).execution_options(populate_existing=True))
    if entry is None:
        raise LookupError("Remote capability catalog entry not found")
    assert_selected_trust_namespace(db, entry)
    source_query = select(RemoteCapabilityCatalogSource).where(RemoteCapabilityCatalogSource.id == entry.source_id)
    if lock:
        source_query = source_query.with_for_update(read=True)
    source = db.scalar(source_query.execution_options(populate_existing=True))
    snapshot = db.scalar(select(RemoteCapabilityCatalogSnapshot).where(
        RemoteCapabilityCatalogSnapshot.id == entry.snapshot_id).execution_options(populate_existing=True))
    if source is None or snapshot is None:
        raise ValueError("Remote capability catalog entry history is incomplete")
    assert_selected_trust_namespace(db, source)
    assert_selected_trust_namespace(db, snapshot)
    trust_key = db.get(ArtifactTrustKey, source.trust_key_id)
    snapshot_trust_key = db.scalar(
        select(ArtifactTrustKey).where(
            ArtifactTrustKey.tenant_id == snapshot.tenant_id,
            ArtifactTrustKey.region_id == snapshot.region_id,
            ArtifactTrustKey.fingerprint_sha256
            == snapshot.key_fingerprint_sha256,
            ArtifactTrustKey.enabled.is_(True),
        )
    )
    if not source.enabled:
        raise ValueError("Remote capability catalog source is disabled")
    if trust_key is None or not trust_key.enabled:
        raise ValueError("Remote capability catalog trust key is unavailable")
    if snapshot_trust_key is None:
        raise ValueError("Remote capability catalog snapshot signer is unavailable")
    if lock:
        requirements = pack_trust_requirements(db, pack_payload.signed_pack) if pack_payload else {}
        for identity in (trust_key.id, snapshot_trust_key.id):
            requirements.setdefault(identity, set()).add("remote_catalog")
        lock_trust_authorities(db, requirements)
    ensure_trust_key_usable(db, trust_key, expected_purpose="remote_catalog")
    ensure_trust_key_usable(db, snapshot_trust_key, expected_purpose="remote_catalog")
    if (
        snapshot.source_id != source.id
        or entry.source_id != source.id
        or source.latest_sequence != snapshot.sequence
        or source.latest_index_digest_sha256 != snapshot.index_digest_sha256
    ):
        raise ValueError("Remote capability catalog entry is not current")
    if _as_utc(snapshot.expires_at) <= utcnow():
        raise ValueError("Remote capability catalog entry has expired")
    validate_remote_catalog_url(
        entry.download_url,
        allowed_hosts=allowed_hosts,
    )
    return _EntryContext(entry=entry, source=source, snapshot=snapshot)


def _verified_payload(
    context: _EntryContext,
    raw_document: bytes,
) -> CapabilityPackPreviewCreate:
    if len(raw_document) > PACK_MAX_BYTES:
        raise ValueError(
            f"Remote capability pack exceeds {PACK_MAX_BYTES} bytes"
        )
    try:
        signed = SignedCapabilityPack.model_validate_json(raw_document)
    except (ValidationError, ValueError) as exc:
        raise ValueError("Remote capability pack document is invalid") from exc
    pack = signed.pack
    entry = context.entry
    mismatches: list[str] = []
    if pack.name != entry.pack_name:
        mismatches.append("name")
    if pack.version != entry.pack_version:
        mismatches.append("version")
    if pack.platform_api != entry.platform_api:
        mismatches.append("platform_api")
    if pack.digest_sha256 != entry.pack_digest_sha256:
        mismatches.append("digest")
    if signed.signature.key_fingerprint_sha256 != (
        entry.pack_key_fingerprint_sha256
    ):
        mismatches.append("signer")
    if pack.predecessor_digest_sha256 != entry.predecessor_digest_sha256:
        mismatches.append("predecessor")
    if len(pack.artifacts) != entry.artifact_count:
        mismatches.append("artifact_count")
    if len(pack.dependencies) != entry.dependency_count:
        mismatches.append("dependency_count")
    if mismatches:
        raise ValueError(
            "Remote capability pack does not match signed catalog entry: "
            + ", ".join(mismatches)
        )
    return CapabilityPackPreviewCreate(signed_pack=signed)


def _distribution_snapshot(context: _EntryContext) -> dict[str, str | int]:
    return {
        "catalog_id": context.source.catalog_id,
        "source_id": context.source.id,
        "snapshot_id": context.snapshot.id,
        "entry_id": context.entry.id,
        "sequence": context.snapshot.sequence,
        "index_digest_sha256": context.snapshot.index_digest_sha256,
        "download_host": urlsplit(context.entry.download_url).hostname or "",
    }


def _reason_hash(reason: str) -> str:
    return hashlib.sha256(reason.encode("utf-8")).hexdigest()


def _record_failure(
    db: Session,
    *,
    entry_id: str,
    actor: str,
    reason: str,
    action: str,
    exc: Exception,
) -> None:
    db.rollback()
    record_audit_event(
        db,
        event_type="capability.remote_pack.acquisition_failed",
        actor_type="user",
        actor_id=actor,
        entity_type="remote_capability_catalog_entry",
        entity_id=entry_id,
        outcome="failure",
        details={
            "action": action,
            "error_type": type(exc).__name__,
            "error_sha256": hashlib.sha256(
                f"{type(exc).__name__}:{str(exc)}".encode("utf-8")
            ).hexdigest(),
            "reason_sha256": _reason_hash(reason),
        },
    )
    db.commit()


def _acquire_verified_payload(
    db: Session,
    entry_id: str,
    *,
    allowed_hosts: list[str],
) -> tuple[_EntryContext, CapabilityPackPreviewCreate, int]:
    require_locking_transaction(db, purpose="Remote pack acquisitions")
    context = _current_entry_context(
        db,
        entry_id,
        allowed_hosts=allowed_hosts,
    )
    if active_pack_revocation(db, context.entry.pack_digest_sha256) is not None:
        raise ValueError("Remote capability pack is revoked")
    raw_document = fetch_remote_capability_pack(context.entry.download_url)
    payload = _verified_payload(context, raw_document)
    fetched_url = context.entry.download_url
    # Absent revocations and concurrent installs need a common digest lock.
    # Take resources before domain/key authority, matching upload and feeds.
    lock_pack_resources(db, payload.signed_pack.pack)
    context = _current_entry_context(db, entry_id, allowed_hosts=allowed_hosts, lock=True, pack_payload=payload)
    if context.entry.download_url != fetched_url:
        raise ValueError("Remote catalog entry changed during download")
    payload = _verified_payload(context, raw_document)
    if active_pack_revocation(db, context.entry.pack_digest_sha256) is not None:
        raise ValueError("Remote capability pack is revoked")
    return context, payload, len(raw_document)


def preview_remote_catalog_pack(
    db: Session,
    entry_id: str,
    payload: RemoteCatalogPackActionCreate,
    *,
    allowed_hosts: list[str],
    actor: str,
) -> CapabilityPackPreviewRead:
    require_locking_transaction(db, purpose="Remote pack acquisitions")
    try:
        context, pack_payload, downloaded_bytes = _acquire_verified_payload(
            db,
            entry_id,
            allowed_hosts=allowed_hosts,
        )
        preview = preview_capability_pack(db, pack_payload)
        record_audit_event(
            db,
            event_type="capability.remote_pack.previewed",
            actor_type="user",
            actor_id=actor,
            entity_type="remote_capability_catalog_entry",
            entity_id=entry_id,
            details={
                **_distribution_snapshot(context),
                "pack_digest_sha256": context.entry.pack_digest_sha256,
                "downloaded_bytes": downloaded_bytes,
                "installable": preview.installable,
                "blockers": preview.blockers,
                "reason_sha256": _reason_hash(payload.reason),
            },
        )
        db.commit()
        return preview
    except (LookupError, RemotePackUnavailable, ValidationError, ValueError) as exc:
        _record_failure(
            db,
            entry_id=entry_id,
            actor=actor,
            reason=payload.reason,
            action="preview",
            exc=exc,
        )
        raise


def install_remote_catalog_pack(
    db: Session,
    entry_id: str,
    payload: RemoteCatalogPackActionCreate,
    *,
    allowed_hosts: list[str],
    actor: str,
) -> CapabilityPackInstallationRead:
    require_locking_transaction(db, purpose="Remote pack acquisitions")
    try:
        context, pack_payload, _ = _acquire_verified_payload(
            db,
            entry_id,
            allowed_hosts=allowed_hosts,
        )
        install_payload = CapabilityPackInstallCreate(
            signed_pack=pack_payload.signed_pack,
            reason=payload.reason,
            actor=actor,
        )
        frozen_distribution = _distribution_snapshot(context)

        def validate_distribution_for_commit():
            current = _current_entry_context(db, entry_id, allowed_hosts=allowed_hosts, lock=True, pack_payload=pack_payload)
            if _distribution_snapshot(current) != frozen_distribution:
                raise ValueError("Remote catalog distribution changed before commit")
            _verified_payload(current, pack_payload.signed_pack.model_dump_json().encode())

        return install_capability_pack(
            db,
            install_payload,
            actor=actor,
            distribution_channel="remote_catalog",
            distribution_snapshot=frozen_distribution,
            before_commit_validation=validate_distribution_for_commit,
        )
    except (
        LookupError,
        RemotePackUnavailable,
        SandboxUnavailable,
        ValidationError,
        ValueError,
    ) as exc:
        _record_failure(
            db,
            entry_id=entry_id,
            actor=actor,
            reason=payload.reason,
            action="install",
            exc=exc,
        )
        raise
