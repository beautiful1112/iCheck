# Organization trust distribution

iCheck separates the bootstrap decision from routine signer distribution.
Administrators first pin an offline Ed25519 **public** root locally, then bind
that fingerprint and an organization identity to a trust domain. iCheck never
accepts or stores the corresponding private key.

Trust is tenant-and-region local. Each namespace separately pins the public
root and accepts its organization domain, even if the publisher's fingerprint,
name and organization ID are identical elsewhere. Local key names/fingerprints
and domain names/organization IDs remain unique inside that namespace. Each pin
has a distinct database ID, purpose/validity policy, revocation state and bundle
head. A public fingerprint identifies signing material; it does not grant trust
across namespaces. Trust bundle reconciliation and recovery trustee lookup must
never select a same-fingerprint record from another tenant or region.

The same signed pack, catalog index, trust bundle or advisory can therefore be
accepted independently without a publisher manufacturing a different key or
signature for each tenant. Revocation feeds require local ingestion and
quarantine only that namespace's runtime consumers. Authenticated service calls
must bind an explicit namespace; unbound unauthenticated local callers may only
use the default namespace, never a global signer lookup.

Migration `e7f9h1j3l5n8` replaces the former global trust/catalog uniqueness
rules without rewriting pin IDs, revocations, root references or catalog
history. Downgrade is refused before any changes if duplicate identities now
exist across namespaces. PostgreSQL downgrade also requires a migration role
able to inspect all namespace rows; production application roles retain RLS.
On 2026-10-03, PostgreSQL 16.15 acceptance verified data-bearing migration
preservation, each duplicate-identity downgrade guard and refusal of an
RLS-limited migration role without schema/data changes. Authenticated HTTP
subjects and raw SQL use a non-owner role; identical signed documents still
require independent local acceptance and revocation stays local. Catalog
refresh additionally locks current domain/key authority and rejects containment
committed during real lock waits. The combined database suite passed 57 tests,
including 24 publisher cases; focused catalog/trust regression passed 17 tests.
See the PostgreSQL acceptance contract (private development evidence; not distributed).

These cases use fixture publisher transport. Production upgrade/backup
datasets, authority/recovery races in other trust mutations, whole-server
failover and live trust-recovery ceremonies remain separate gates.

The management surface is:

    UI   /studio/catalog/trust
    POST /api/v1/artifact-trust-keys
    POST /api/v1/organization-trust/domains
    GET  /api/v1/organization-trust/domains
    POST /api/v1/organization-trust/domains/{id}/state
    POST /api/v1/organization-trust/domains/{id}/bundles/preview
    POST /api/v1/organization-trust/domains/{id}/bundles/import
    POST /api/v1/organization-trust/domains/{id}/rotate-root
    UI   /studio/catalog/trust/recovery
    GET  /api/v1/organization-trust/bundles
    GET  /api/v1/organization-trust/bundles/{id}/export
    GET  /api/v1/organization-trust/root-rotations

Domain creation is an out-of-band bootstrap operation. The authority must be an
enabled, unexpired, locally registered key whose purposes include
trust_bundle; a key learned from another trust bundle cannot silently become
the local root. Creation binds the selected tenant and region, retains a shared
lock on that local root through commit, and rechecks its validity after the
domain, audit event and transparency record have been flushed. Revocation that
wins the lock first prevents creation; revocation that waits commits only after
the accepted creation. A key expiring before commit rolls back all three rows.
PostgreSQL `READ COMMITTED` with autocommit disabled is required. Domain creation
accepts an optional `idempotency_key` of 16–128 characters. The key is hashed
before storage and scoped to the selected tenant and region. A committed
creation has an append-only receipt binding the effective actor and canonical
request digest to the domain ID. An exact retry returns that domain's current
state without revalidating the now-historical root or adding audit and
transparency records. Reusing the key for another actor, root, organization or
policy returns a conflict. Concurrent exact retries serialize on a
namespace-local lock and produce one domain and receipt. A revoked root or a
later root rotation does not erase the original accepted result. The Studio
creation form retains the key across an uncertain response and reuses it when
the unchanged request is retried; browser session storage retains the pending
key across a reload when the same fields are re-entered, if storage is
available. Legacy clients that omit the key still receive
a uniqueness conflict after an uncertain successful creation and must inspect
the namespace-local organization identity before retrying.

Migration `u3w5y7a9c1e4` adds the receipt table with namespace RLS and
runtime update/delete guards. A populated or RLS-hidden downgrade is refused;
an empty migration roundtrip remains possible. This seals application-runtime
history, not database-owner tamper resistance or independent publisher signing.

## Signed bundle contract

An external release process creates:

    icheck.organization-trust-bundle.signed/v1
      bundle: icheck.organization-trust-bundle/v1
      signature: Ed25519(root, domain-separated canonical bundle digest)

The bundle binds:

- the exact organization identity;
- an exact next sequence number;
- timezone-bearing issue and expiry times;
- one to 256 Ed25519 public keys;
- each key's name, canonical fingerprint, validity window, state, and explicit
  purposes; and
- a canonical SHA-256 digest over all unsigned bundle material.

Accepted purposes are:

    artifact_bundle
    capability_pack
    capability_revocation
    remote_catalog
    trust_bundle
    transparency_witness
    environment_promotion

The local-only `trust_recovery` purpose is deliberately excluded from signed
organization bundles. It authorizes pre-pinned emergency trustees only and
cannot be delegated through routine distribution.

Existing signing paths now require the matching purpose. For example, a key
distributed only for capability_pack cannot sign an Artifact bundle, remote
catalog, or revocation feed. Local trust-domain policy constrains allowed
purposes, maximum bundle lifetime, and maximum key lifetime; signed input
cannot enlarge those limits.

The document is bounded to 1 MB, must be current within five minutes of clock
skew, and must be signed by the domain's exact pinned authority. Sequences are
strictly contiguous rather than merely increasing. This makes a missing
revocation snapshot visible and blocks replay, rollback, and sequence gaps.

## Complete-snapshot and revocation semantics

A bundle is the complete managed-key snapshot for its trust domain:

- a new active key is added;
- an existing active key may update its name, purposes, or validity under the
  local policy;
- an explicit revoked key becomes a durable disabled tombstone;
- a previously managed key omitted from the next snapshot is revoked; and
- a revoked fingerprint cannot be reactivated by a later bundle.

The authority root cannot manage, replace, or revoke itself through its own
distribution bundle. Disabling the trust domain is the immediate break-glass
control: every distributed key fails verification without deleting provenance.
Root replacement is never inferred from a routine bundle.

## Dual-control root rotation

A planned root change uses a separate
icheck.organization-trust-root-rotation.signed/v1 envelope. Its canonical
statement binds the organization identity, latest accepted trust-bundle
sequence and digest, current and next fingerprints, and an expiry window of at
most 24 hours. The current and next Ed25519 roots must both sign the same
statement digest, and the next public root must already be pinned locally with
the trust_bundle purpose.

Acceptance refreshes the exclusively locked domain and holds shared locks on
both current and successor key authority. It records both signature hashes,
changes the pinned authority, retires old-root recovery policies, and appends
audit and transparency evidence in one transaction. Old-root bundles are
rejected immediately. The pending rotation rechecks both keys and the signed
statement expiry at commit. Revocation that wins a key lock first or expiry
before commit rolls back the pin change, ledger and evidence; revocation that
waits follows the accepted rotation. A rejected rotation also rolls back its
calling transaction, so it cannot be accidentally committed by later session
reuse. An exact retry may return the original receipt only
while the accepted root and bundle head still match; both signature-byte hashes,
fingerprints and signed digest must match the accepted proof. A retry never
rotates twice, restores an older root, or adds another audit record. Both public
keys and earlier receipts remain in history.

Root rotation requires PostgreSQL `READ COMMITTED` with autocommit disabled.
The whole mutation transaction binds its selected tenant/region, including
calls from Sessions with automatic ORM filtering initially disabled. A disabled
domain or an unusable successor key cannot be bypassed by a cached object.

If the current root is unavailable and cannot co-sign, the separate
[emergency trust-root recovery](./trust-root-recovery.md) ceremony requires a
current-root-authorized trustee policy, M-of-N trustee signatures, proof of the
next root, a mandatory delay, different proposer/executor identities, and live
witness quorum both before execution and before the domain can be re-enabled.

Preview verifies the entire envelope and calculates per-key actions without
persisting anything. Import locks and rechecks the domain, then applies all key
changes, the immutable receipt, the domain sequence/head, audit evidence, and
the capability-transparency record in one transaction. A failure rolls back
the complete change.

Import refreshes the exclusively locked domain, holds shared current-root
authority, and locks its managed keys in stable order before reconciliation.
Previously cached policy, sequence, expiry or key state cannot substitute for
these reads. Only owned managed rows are mutated; an independently created
local or foreign-domain pin is protected by the namespace-local uniqueness
constraints. Unrelated domains and matching fingerprints in another namespace
do not share these locks. Bundle, root and active-key expiry are checked again
after reconciliation and audit work, before commit.

Bundle import and domain containment require PostgreSQL `READ COMMITTED` with
autocommit disabled and bind the whole selected tenant/region transaction.
Containment refreshes locked state even for a no-op retry; a stale disabled
object cannot skip a new disable request after another transaction re-enables
the domain. Retries preserve the accepted state and its original audit.

Bundle sequence replays remain rejected, including after a lost response.
Reconcile that response through the accepted receipt/history instead of
submitting the same sequence as a new import. A response-path exception after
a successful commit does not roll back or duplicate the durable receipt.

The receipt stores the accepted public signed envelope so an administrator can
export the exact JSON value for recovery review or peer transfer. Exports
contain public keys and signatures only; no private material exists in iCheck.

## Runtime enforcement

Every signature verification checks:

1. enabled state and irreversible local revocation;
2. the purpose required by the consuming contract;
3. key not-before and expiry;
4. enabled trust-domain state for distributed keys; and
5. that the key was reconciled by the domain's latest complete snapshot.

This enforcement covers Artifact imports, capability packs and signer
rotations, revocation feeds, remote catalogs and catalog-key rotations,
organization trust bundles, external transparency witnesses, and environment
promotion authorities.

Accepted domain creation/state changes and bundle imports enter the same
[capability transparency chain](./capability-transparency.md) as the rest of
the capability supply chain. External witness signatures and automated
quorum-backed cross-region gossip are implemented with purpose-isolated keys.
Durable automated witness and promotion transport is implemented by a
separately deployable leased worker, including endpoint mTLS and certificate
rotation. Verified private-key-free HSM/KMS recovery signing is implemented.
Live control-plane/CI identity-provider acceptance, vendor gateway acceptance,
and live multi-region recovery drills remain later M6 controls. Signed
cross-environment promotion receipts are described in
[governed capability promotion](./capability-promotions.md).
