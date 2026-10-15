"""Transaction-held publisher authority and namespace-local resource locks."""
from __future__ import annotations

import hashlib
import base64
import binascii
from collections.abc import Iterable

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..database import require_locking_transaction
from ..models import ArtifactTrustKey, OrganizationTrustDomain
from .trust_namespace import selected_trust_namespace


def lock_publisher_resource(db: Session, kind: str, identity: str, *, shared: bool = False) -> None:
    """Serialize an absent-row identity without a platform-wide bottleneck."""
    require_locking_transaction(db, purpose="Publisher mutations")
    if db.get_bind().dialect.name != "postgresql":
        return
    tenant_id, region_id = selected_trust_namespace(db)
    material = "\0".join(("icheck.publisher-lock/v1", tenant_id, region_id, kind, identity))
    key = int.from_bytes(hashlib.sha256(material.encode()).digest()[:8], "big", signed=True)
    function = "pg_advisory_xact_lock_shared" if shared else "pg_advisory_xact_lock"
    db.execute(text(f"SELECT {function}(:key)"), {"key": key})


def lock_trust_keys(db: Session, key_ids: Iterable[str], *, expected_purpose: str) -> dict[str, ArtifactTrustKey]:
    return lock_trust_authorities(db, {identity: {expected_purpose} for identity in key_ids})


def lock_trust_authorities(db: Session, requirements: dict[str, set[str]]) -> dict[str, ArtifactTrustKey]:
    """Refresh and retain shared authority, sorted domains before sorted keys."""
    from .artifact_portability import ensure_trust_key_usable

    require_locking_transaction(db, purpose="Publisher mutations")
    tenant_id, region_id = selected_trust_namespace(db)
    identities = sorted(requirements)
    metadata = {row.id: (row.trust_source, row.trust_domain_id) for row in db.execute(
        select(ArtifactTrustKey.id, ArtifactTrustKey.trust_source, ArtifactTrustKey.trust_domain_id).where(
            ArtifactTrustKey.id.in_(identities), ArtifactTrustKey.tenant_id == tenant_id,
            ArtifactTrustKey.region_id == region_id))}
    if len(metadata) != len(identities):
        raise ValueError("Publisher trust key is unavailable in the selected namespace")
    domain_ids = sorted({domain for source, domain in metadata.values() if source == "trust_bundle" and domain})
    # Bundle reconciliation takes a domain lock before touching managed keys.
    # Retain references too, so subsequent signature checks use refreshed rows.
    domains = []
    for identity in domain_ids:
        domain = db.scalar(select(OrganizationTrustDomain).where(
            OrganizationTrustDomain.id == identity, OrganizationTrustDomain.tenant_id == tenant_id,
            OrganizationTrustDomain.region_id == region_id,
        ).with_for_update(read=True).execution_options(populate_existing=True))
        if domain is None:
            raise ValueError("Distributed trust key domain is unavailable in the selected namespace")
        domains.append(domain)
    keys = {}
    for identity in identities:
        key = db.scalar(select(ArtifactTrustKey).where(
            ArtifactTrustKey.id == identity, ArtifactTrustKey.tenant_id == tenant_id,
            ArtifactTrustKey.region_id == region_id,
        ).with_for_update(read=True).execution_options(populate_existing=True))
        if key is None or (key.trust_source, key.trust_domain_id) != metadata[identity]:
            raise ValueError("Publisher signer changed before acceptance")
        for purpose in sorted(requirements[identity]):
            ensure_trust_key_usable(db, key, expected_purpose=purpose)
        keys[identity] = key
    return keys


def assert_rotation_replay(accepted, signed) -> None:
    """A durable outcome may replay only the exact originally verified proof."""
    for prefix, signature in (("current", signed.current_signature), ("next", signed.next_signature)):
        direction = "from" if prefix == "current" else "to"
        try:
            body = base64.b64decode(signature.signature_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Rotation retry proof does not match accepted signatures") from exc
        if (len(body) != 64
            or signature.signed_digest_sha256 != accepted.statement_digest_sha256
            or signature.key_fingerprint_sha256 != getattr(accepted, f"{direction}_key_fingerprint_sha256")
            or hashlib.sha256(body).hexdigest() != getattr(accepted, f"{prefix}_signature_sha256")):
            raise ValueError("Rotation retry proof does not match accepted signatures")
