from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import ValidationError
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased

from ..database import require_locking_transaction
from ..models import (
    ArtifactTrustKey,
    CapabilityPackInstallation,
    CapabilityPackRevocation,
    RemoteCapabilityCatalogEntry,
    RemoteCapabilityCatalogSnapshot,
    RemoteCapabilityCatalogSource,
    utcnow,
)
from ..capability_pack_schemas import PLATFORM_API
from ..remote_catalog_schemas import (
    SIGNED_REMOTE_CATALOG_FORMAT,
    RemoteCatalogEntryListRead,
    RemoteCatalogEntryRead,
    RemoteCatalogRefreshCreate,
    RemoteCatalogSnapshotRead,
    RemoteCatalogSourceCreate,
    RemoteCatalogSourceStateCreate,
    SignedRemoteCatalogIndex,
)
from .artifact_portability import ensure_trust_key_usable, verify_trusted_digest_signature
from .audit import record_audit_event
from .capability_transparency import append_capability_transparency_record
from .trust_namespace import assert_selected_trust_namespace, selected_trust_namespace
from .trust_authority import lock_trust_keys


REMOTE_CATALOG_MAX_BYTES = 5_000_000
REMOTE_CATALOG_TIMEOUT_SECONDS = 10
REMOTE_CATALOG_CLOCK_SKEW = timedelta(minutes=5)
REMOTE_CATALOG_MAX_LIFETIME = timedelta(days=366)


class RemoteCatalogUnavailable(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for remote capability catalogs",
            headers,
            fp,
        )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _host_allowed(hostname: str, allowed_hosts: list[str]) -> bool:
    host = hostname.rstrip(".").lower()
    for pattern in allowed_hosts:
        normalized = pattern.rstrip(".").lower()
        if normalized.startswith("*."):
            suffix = normalized[1:]
            if host.endswith(suffix) and host != normalized[2:]:
                return True
        elif host == normalized:
            return True
    return False


def validate_remote_catalog_url(
    url: str,
    *,
    allowed_hosts: list[str],
) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Remote capability catalog URLs must use HTTPS")
    if parsed.username or parsed.password:
        raise ValueError("Remote capability catalog URLs must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError(
            "Remote capability catalog URLs must not contain query or fragment data"
        )
    if not _host_allowed(parsed.hostname, allowed_hosts):
        raise ValueError(
            "Remote capability catalog host is not in "
            "ICHECK_CAPABILITY_CATALOG_ALLOWED_HOSTS"
        )
    return url


def fetch_remote_catalog_document(
    url: str,
    *,
    max_bytes: int = REMOTE_CATALOG_MAX_BYTES,
    timeout_seconds: int = REMOTE_CATALOG_TIMEOUT_SECONDS,
) -> bytes:
    request = Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "User-Agent": "iCheck-remote-catalog/0.1",
        },
    )
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            content_type = response.headers.get_content_type()
            if content_type not in {"application/json", "text/json"}:
                raise RemoteCatalogUnavailable(
                    "Remote capability catalog did not return JSON"
                )
            body = response.read(max_bytes + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RemoteCatalogUnavailable(
            "Remote capability catalog fetch failed"
        ) from exc
    if len(body) > max_bytes:
        raise RemoteCatalogUnavailable(
            f"Remote capability catalog exceeded {max_bytes} bytes"
        )
    return body


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _index_payload(index: Any) -> dict[str, Any]:
    return index.model_dump(mode="json", exclude={"digest_sha256"})


def _failure_hash(exc: Exception) -> str:
    return hashlib.sha256(
        f"{type(exc).__name__}:{str(exc)}".encode("utf-8")
    ).hexdigest()


def _record_refresh_failure(
    db: Session,
    source: RemoteCapabilityCatalogSource,
    *,
    actor: str,
    exc: Exception,
) -> None:
    db.rollback()
    source = db.get(RemoteCapabilityCatalogSource, source.id)
    if source is None:
        return
    source.last_refresh_status = "failed"
    source.last_refresh_at = utcnow()
    source.last_error_sha256 = _failure_hash(exc)
    source.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="capability.remote_catalog.refresh_failed",
        actor_type="user",
        actor_id=actor,
        entity_type="remote_capability_catalog_source",
        entity_id=source.id,
        details={
            "catalog_id": source.catalog_id,
            "index_host": urlsplit(source.index_url).hostname,
            "error_type": type(exc).__name__,
            "error_sha256": source.last_error_sha256,
        },
    )
    db.commit()


def get_remote_catalog_source(
    db: Session,
    source_id: str,
) -> RemoteCapabilityCatalogSource:
    source = db.get(RemoteCapabilityCatalogSource, source_id)
    if source is None:
        raise LookupError("Remote capability catalog source not found")
    assert_selected_trust_namespace(db, source)
    return source


def list_remote_catalog_sources(
    db: Session,
    *,
    limit: int,
) -> list[RemoteCapabilityCatalogSource]:
    tenant_id, region_id = selected_trust_namespace(db)
    return list(
        db.scalars(
            select(RemoteCapabilityCatalogSource)
            .where(
                RemoteCapabilityCatalogSource.tenant_id == tenant_id,
                RemoteCapabilityCatalogSource.region_id == region_id,
            )
            .order_by(RemoteCapabilityCatalogSource.name)
            .limit(limit)
        ).all()
    )


def create_remote_catalog_source(
    db: Session,
    payload: RemoteCatalogSourceCreate,
    *,
    allowed_hosts: list[str],
    actor: str,
) -> RemoteCapabilityCatalogSource:
    index_url = validate_remote_catalog_url(
        payload.index_url,
        allowed_hosts=allowed_hosts,
    )
    trust_key = db.get(ArtifactTrustKey, payload.trust_key_id)
    if trust_key is None:
        raise ValueError("Remote capability catalog trust key does not exist")
    ensure_trust_key_usable(db, trust_key, expected_purpose="remote_catalog")
    source = RemoteCapabilityCatalogSource(
        tenant_id=trust_key.tenant_id,
        region_id=trust_key.region_id,
        name=payload.name,
        catalog_id=payload.catalog_id,
        index_url=index_url,
        trust_key_id=trust_key.id,
        created_by=actor,
    )
    db.add(source)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="capability.remote_catalog.created",
            actor_type="user",
            actor_id=actor,
            entity_type="remote_capability_catalog_source",
            entity_id=source.id,
            details={
                "catalog_id": source.catalog_id,
                "index_host": urlsplit(index_url).hostname,
                "trust_key_id": trust_key.id,
                "key_fingerprint_sha256": trust_key.fingerprint_sha256,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Remote capability catalog name or index URL already exists"
        ) from exc
    db.refresh(source)
    return source


def set_remote_catalog_source_state(
    db: Session,
    source_id: str,
    payload: RemoteCatalogSourceStateCreate,
    *,
    actor: str,
) -> RemoteCapabilityCatalogSource:
    source = get_remote_catalog_source(db, source_id)
    if payload.enabled:
        trust_key = db.get(ArtifactTrustKey, source.trust_key_id)
        if trust_key is None or not trust_key.enabled:
            raise ValueError(
                "Remote capability catalog trust key is unavailable"
            )
        ensure_trust_key_usable(db, trust_key, expected_purpose="remote_catalog")
    if source.enabled == payload.enabled:
        return source
    source.enabled = payload.enabled
    source.updated_at = utcnow()
    record_audit_event(
        db,
        event_type=(
            "capability.remote_catalog.enabled"
            if payload.enabled
            else "capability.remote_catalog.disabled"
        ),
        actor_type="user",
        actor_id=actor,
        entity_type="remote_capability_catalog_source",
        entity_id=source.id,
        details={
            "catalog_id": source.catalog_id,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    db.commit()
    db.refresh(source)
    return source


def _verified_remote_index(
    db: Session,
    *,
    source: RemoteCapabilityCatalogSource,
    raw_document: bytes,
    allowed_hosts: list[str],
) -> tuple[SignedRemoteCatalogIndex, dict[str, str]]:
    if len(raw_document) > REMOTE_CATALOG_MAX_BYTES:
        raise ValueError(
            f"Remote capability catalog exceeds {REMOTE_CATALOG_MAX_BYTES} bytes"
        )
    try:
        signed = SignedRemoteCatalogIndex.model_validate_json(raw_document)
    except (ValidationError, ValueError) as exc:
        raise ValueError("Remote capability catalog document is invalid") from exc
    index = signed.index
    material = _index_payload(index)
    if _canonical_hash(material) != index.digest_sha256:
        raise ValueError("Remote capability catalog digest does not match")
    verification = verify_trusted_digest_signature(
        db,
        signed.signature,
        expected_digest_sha256=index.digest_sha256,
        signed_format_version=SIGNED_REMOTE_CATALOG_FORMAT,
        expected_purpose="remote_catalog",
    )
    if verification["trust_key_id"] != source.trust_key_id:
        raise ValueError("Remote capability catalog signer is not pinned to source")
    if index.catalog_id != source.catalog_id:
        raise ValueError("Remote capability catalog identity does not match source")
    now = utcnow()
    issued_at = _as_utc(index.issued_at)
    expires_at = _as_utc(index.expires_at)
    if issued_at > now + REMOTE_CATALOG_CLOCK_SKEW:
        raise ValueError("Remote capability catalog is issued in the future")
    if expires_at <= now:
        raise ValueError("Remote capability catalog has expired")
    if expires_at - issued_at > REMOTE_CATALOG_MAX_LIFETIME:
        raise ValueError("Remote capability catalog lifetime exceeds 366 days")
    for entry in index.entries:
        validate_remote_catalog_url(
            entry.download_url,
            allowed_hosts=allowed_hosts,
        )
    return signed, verification


def _installation_states(
    db: Session,
    pack_digests: list[str],
) -> dict[str, str]:
    tenant_id, region_id = selected_trust_namespace(db)
    rows = db.execute(
        select(
            CapabilityPackInstallation.pack_digest_sha256,
            CapabilityPackInstallation.lifecycle_status,
        ).where(
            CapabilityPackInstallation.tenant_id == tenant_id,
            CapabilityPackInstallation.region_id == region_id,
            CapabilityPackInstallation.pack_digest_sha256.in_(pack_digests),
        )
    ).all()
    return {row.pack_digest_sha256: row.lifecycle_status for row in rows}


def _revoked_digests(
    db: Session,
    pack_digests: list[str],
) -> set[str]:
    tenant_id, region_id = selected_trust_namespace(db)
    return set(
        db.scalars(
            select(CapabilityPackRevocation.pack_digest_sha256).where(
                CapabilityPackRevocation.tenant_id == tenant_id,
                CapabilityPackRevocation.region_id == region_id,
                CapabilityPackRevocation.pack_digest_sha256.in_(pack_digests),
                CapabilityPackRevocation.effective_at <= utcnow(),
            )
        ).all()
    )


def _render_entries(
    db: Session,
    rows: list[
        tuple[
            RemoteCapabilityCatalogEntry,
            RemoteCapabilityCatalogSource,
            RemoteCapabilityCatalogSnapshot,
        ]
    ],
) -> list[RemoteCatalogEntryRead]:
    tenant_id, region_id = selected_trust_namespace(db)
    digests = list(
        dict.fromkeys(row[0].pack_digest_sha256 for row in rows)
    )
    states = _installation_states(db, digests) if digests else {}
    revoked = _revoked_digests(db, digests) if digests else set()
    signer_fingerprints = list(
        dict.fromkeys(
            row[0].pack_key_fingerprint_sha256 for row in rows
        )
    )
    candidates = db.scalars(select(ArtifactTrustKey).where(
        ArtifactTrustKey.tenant_id == tenant_id,
        ArtifactTrustKey.region_id == region_id,
        ArtifactTrustKey.fingerprint_sha256.in_(signer_fingerprints),
        ArtifactTrustKey.enabled.is_(True),
    )).all()
    trusted_signers: set[str] = set()
    for key in candidates:
        try:
            ensure_trust_key_usable(db, key, expected_purpose="capability_pack")
        except ValueError:
            continue
        trusted_signers.add(key.fingerprint_sha256)
    return [
        RemoteCatalogEntryRead(
            id=entry.id,
            source_id=entry.source_id,
            snapshot_id=entry.snapshot_id,
            pack_name=entry.pack_name,
            pack_version=entry.pack_version,
            platform_api=entry.platform_api,
            pack_digest_sha256=entry.pack_digest_sha256,
            pack_key_fingerprint_sha256=(
                entry.pack_key_fingerprint_sha256
            ),
            predecessor_digest_sha256=(
                entry.predecessor_digest_sha256
            ),
            download_url=entry.download_url,
            artifact_count=entry.artifact_count,
            dependency_count=entry.dependency_count,
            source_name=source.name,
            sequence=snapshot.sequence,
            issued_at=snapshot.issued_at,
            expires_at=snapshot.expires_at,
            installation_state=states.get(
                entry.pack_digest_sha256,
                "not_installed",
            ),
            revoked=entry.pack_digest_sha256 in revoked,
            pack_signer_trusted=(
                entry.pack_key_fingerprint_sha256 in trusted_signers
            ),
            platform_compatible=entry.platform_api == PLATFORM_API,
        )
        for entry, source, snapshot in rows
    ]


def _snapshot_read(
    db: Session,
    snapshot: RemoteCapabilityCatalogSnapshot,
) -> RemoteCatalogSnapshotRead:
    rows = [
        (entry, source, snapshot)
        for entry, source in db.execute(
            select(
                RemoteCapabilityCatalogEntry,
                RemoteCapabilityCatalogSource,
            )
            .join(
                RemoteCapabilityCatalogSource,
                RemoteCapabilityCatalogSource.id
                == RemoteCapabilityCatalogEntry.source_id,
            )
            .where(
                RemoteCapabilityCatalogEntry.snapshot_id == snapshot.id
            )
            .order_by(
                RemoteCapabilityCatalogEntry.pack_name,
                RemoteCapabilityCatalogEntry.pack_version,
            )
        ).all()
    ]
    return RemoteCatalogSnapshotRead(
        id=snapshot.id,
        source_id=snapshot.source_id,
        sequence=snapshot.sequence,
        issued_at=snapshot.issued_at,
        expires_at=snapshot.expires_at,
        index_digest_sha256=snapshot.index_digest_sha256,
        key_fingerprint_sha256=snapshot.key_fingerprint_sha256,
        signature_sha256=snapshot.signature_sha256,
        entry_count=snapshot.entry_count,
        refresh_reason=snapshot.refresh_reason,
        refreshed_by=snapshot.refreshed_by,
        refreshed_at=snapshot.refreshed_at,
        entries=_render_entries(db, rows),
    )


def _lock_catalog_signer(db: Session, source: RemoteCapabilityCatalogSource) -> None:
    """Hold current authority through publication, domain before managed key."""
    lock_trust_keys(db, [source.trust_key_id], expected_purpose="remote_catalog")


def refresh_remote_catalog(
    db: Session,
    source_id: str,
    payload: RemoteCatalogRefreshCreate,
    *,
    allowed_hosts: list[str],
    actor: str,
) -> RemoteCatalogSnapshotRead:
    require_locking_transaction(db, purpose="Remote catalog refreshes")
    source = get_remote_catalog_source(db, source_id)
    if not source.enabled:
        raise ValueError("Remote capability catalog source is disabled")
    try:
        validate_remote_catalog_url(
            source.index_url,
            allowed_hosts=allowed_hosts,
        )
        fetched_url = source.index_url
        raw_document = fetch_remote_catalog_document(fetched_url)
        signed, verification = _verified_remote_index(
            db,
            source=source,
            raw_document=raw_document,
            allowed_hosts=allowed_hosts,
        )
        index = signed.index
        locked = db.scalar(
            select(RemoteCapabilityCatalogSource)
            .where(RemoteCapabilityCatalogSource.id == source.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if locked is None or not locked.enabled or locked.index_url != fetched_url:
            raise ValueError(
                "Remote capability catalog source changed before refresh"
            )
        _lock_catalog_signer(db, locked)
        # Network fetch and lock waits may outlive containment, rotation or
        # validity windows. Reverify the exact bytes against locked live state.
        signed, verification = _verified_remote_index(
            db, source=locked, raw_document=raw_document, allowed_hosts=allowed_hosts,
        )
        index = signed.index
        existing = db.scalar(
            select(RemoteCapabilityCatalogSnapshot).where(
                RemoteCapabilityCatalogSnapshot.source_id == locked.id,
                RemoteCapabilityCatalogSnapshot.sequence == index.sequence,
            )
        )
        if existing is not None:
            if existing.index_digest_sha256 != index.digest_sha256:
                raise ValueError(
                    "Remote catalog sequence already exists with different content"
                )
            locked.last_refresh_status = "succeeded"
            locked.last_refresh_at = utcnow()
            locked.last_error_sha256 = None
            locked.updated_at = utcnow()
            record_audit_event(
                db,
                event_type="capability.remote_catalog.refresh_replayed",
                actor_type="user",
                actor_id=actor,
                entity_type="remote_capability_catalog_snapshot",
                entity_id=existing.id,
                details={
                    "source_id": locked.id,
                    "catalog_id": locked.catalog_id,
                    "sequence": index.sequence,
                    "index_digest_sha256": index.digest_sha256,
                    "reason_sha256": hashlib.sha256(
                        payload.reason.encode("utf-8")
                    ).hexdigest(),
                },
            )
            db.commit()
            return _snapshot_read(db, existing)
        if (
            locked.latest_sequence is not None
            and index.sequence <= locked.latest_sequence
        ):
            raise ValueError(
                "Remote catalog sequence must advance monotonically"
            )
        snapshot = RemoteCapabilityCatalogSnapshot(
            tenant_id=locked.tenant_id,
            region_id=locked.region_id,
            source_id=locked.id,
            sequence=index.sequence,
            issued_at=_as_utc(index.issued_at),
            expires_at=_as_utc(index.expires_at),
            index_digest_sha256=index.digest_sha256,
            key_fingerprint_sha256=verification[
                "key_fingerprint_sha256"
            ],
            signature_sha256=verification["signature_sha256"],
            entry_count=len(index.entries),
            refresh_reason=payload.reason,
            refreshed_by=actor,
        )
        db.add(snapshot)
        db.flush()
        for entry in index.entries:
            db.add(
                RemoteCapabilityCatalogEntry(
                    tenant_id=locked.tenant_id,
                    region_id=locked.region_id,
                    source_id=locked.id,
                    snapshot_id=snapshot.id,
                    **entry.model_dump(mode="python"),
                )
            )
        locked.latest_sequence = index.sequence
        locked.latest_index_digest_sha256 = index.digest_sha256
        locked.last_refresh_status = "succeeded"
        locked.last_refresh_at = utcnow()
        locked.last_error_sha256 = None
        locked.updated_at = utcnow()
        append_capability_transparency_record(
            db,
            event_type="capability.remote_catalog.refreshed",
            entity_type="remote_capability_catalog_snapshot",
            entity_id=snapshot.id,
            subject_digest_sha256=index.digest_sha256,
            details={
                "source_id": locked.id,
                "catalog_id": locked.catalog_id,
                "sequence": index.sequence,
                "key_fingerprint_sha256": verification[
                    "key_fingerprint_sha256"
                ],
                "entry_count": len(index.entries),
            },
        )
        record_audit_event(
            db,
            event_type="capability.remote_catalog.refreshed",
            actor_type="user",
            actor_id=actor,
            entity_type="remote_capability_catalog_snapshot",
            entity_id=snapshot.id,
            details={
                "source_id": locked.id,
                "catalog_id": locked.catalog_id,
                "sequence": index.sequence,
                "index_digest_sha256": index.digest_sha256,
                "key_fingerprint_sha256": verification[
                    "key_fingerprint_sha256"
                ],
                "entry_count": len(index.entries),
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        db.commit()
        db.refresh(snapshot)
        return _snapshot_read(db, snapshot)
    except (
        IntegrityError,
        RemoteCatalogUnavailable,
        ValidationError,
        ValueError,
    ) as exc:
        _record_refresh_failure(db, source, actor=actor, exc=exc)
        if isinstance(exc, IntegrityError):
            raise ValueError(
                "Remote capability catalog snapshot conflicts with history"
            ) from exc
        raise


def list_current_remote_catalog_entries(
    db: Session,
    *,
    q: str | None,
    source_id: str | None,
    offset: int,
    limit: int,
) -> RemoteCatalogEntryListRead:
    tenant_id, region_id = selected_trust_namespace(db)
    # An enabled bit alone does not establish current trust: a purpose,
    # validity window or distributed-domain policy may also deny this signer.
    usable_key_ids: list[str] = []
    for key in db.scalars(select(ArtifactTrustKey).where(
        ArtifactTrustKey.tenant_id == tenant_id,
        ArtifactTrustKey.region_id == region_id,
        ArtifactTrustKey.enabled.is_(True),
    )).all():
        try:
            ensure_trust_key_usable(db, key, expected_purpose="remote_catalog")
        except ValueError:
            continue
        usable_key_ids.append(key.id)
    source_trust_key = aliased(ArtifactTrustKey)
    snapshot_trust_key = aliased(ArtifactTrustKey)
    criteria: list[Any] = [
        RemoteCapabilityCatalogEntry.tenant_id == tenant_id,
        RemoteCapabilityCatalogEntry.region_id == region_id,
        RemoteCapabilityCatalogSource.enabled.is_(True),
        source_trust_key.id.in_(usable_key_ids),
        snapshot_trust_key.id.in_(usable_key_ids),
        RemoteCapabilityCatalogSnapshot.sequence
        == RemoteCapabilityCatalogSource.latest_sequence,
        RemoteCapabilityCatalogSnapshot.expires_at > utcnow(),
    ]
    if source_id:
        criteria.append(RemoteCapabilityCatalogEntry.source_id == source_id)
    if q:
        pattern = f"%{q.strip()}%"
        criteria.append(
            or_(
                RemoteCapabilityCatalogEntry.pack_name.ilike(pattern),
                RemoteCapabilityCatalogSource.name.ilike(pattern),
            )
        )
    joins = (
        select(
            RemoteCapabilityCatalogEntry,
            RemoteCapabilityCatalogSource,
            RemoteCapabilityCatalogSnapshot,
        )
        .join(
            RemoteCapabilityCatalogSource,
            and_(
                RemoteCapabilityCatalogSource.id == RemoteCapabilityCatalogEntry.source_id,
                RemoteCapabilityCatalogSource.tenant_id == RemoteCapabilityCatalogEntry.tenant_id,
                RemoteCapabilityCatalogSource.region_id == RemoteCapabilityCatalogEntry.region_id,
            ),
        )
        .join(
            RemoteCapabilityCatalogSnapshot,
            and_(
                RemoteCapabilityCatalogSnapshot.id == RemoteCapabilityCatalogEntry.snapshot_id,
                RemoteCapabilityCatalogSnapshot.source_id == RemoteCapabilityCatalogSource.id,
                RemoteCapabilityCatalogSnapshot.tenant_id == RemoteCapabilityCatalogEntry.tenant_id,
                RemoteCapabilityCatalogSnapshot.region_id == RemoteCapabilityCatalogEntry.region_id,
            ),
        )
        .join(
            source_trust_key,
            and_(
                source_trust_key.id == RemoteCapabilityCatalogSource.trust_key_id,
                source_trust_key.tenant_id == RemoteCapabilityCatalogSource.tenant_id,
                source_trust_key.region_id == RemoteCapabilityCatalogSource.region_id,
            ),
        )
        .join(
            snapshot_trust_key,
            and_(
                snapshot_trust_key.fingerprint_sha256 == RemoteCapabilityCatalogSnapshot.key_fingerprint_sha256,
                snapshot_trust_key.tenant_id == RemoteCapabilityCatalogSnapshot.tenant_id,
                snapshot_trust_key.region_id == RemoteCapabilityCatalogSnapshot.region_id,
            ),
        )
        .where(*criteria)
    )
    total = int(
        db.scalar(
            select(func.count()).select_from(joins.subquery())
        )
        or 0
    )
    rows = db.execute(
        joins.order_by(
            RemoteCapabilityCatalogEntry.pack_name,
            RemoteCapabilityCatalogEntry.pack_version.desc(),
        )
        .offset(offset)
        .limit(limit)
    ).all()
    return RemoteCatalogEntryListRead(
        items=_render_entries(db, list(rows)),
        total=total,
        offset=offset,
        limit=limit,
    )
