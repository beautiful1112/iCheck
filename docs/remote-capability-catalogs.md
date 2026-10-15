# Remote capability catalogs

iCheck remote catalogs discover signed organization pack metadata without
turning discovery into an installation or execution path.

    POST /api/v1/remote-capability-catalogs
    GET  /api/v1/remote-capability-catalogs
    POST /api/v1/remote-capability-catalogs/{source_id}/refresh
    POST /api/v1/remote-capability-catalogs/{source_id}/state
    POST /api/v1/remote-capability-catalogs/{source_id}/rotate-trust-key
    GET  /api/v1/remote-capability-catalogs/key-rotations
    GET  /api/v1/remote-capability-catalogs/entries/current
    POST /api/v1/remote-capability-catalogs/entries/{entry_id}/preview
    POST /api/v1/remote-capability-catalogs/entries/{entry_id}/install
    UI   /studio/catalog/remote

Source creation requires global capabilities.manage. It pins a local display
name, the exact signed catalog ID, one HTTPS index URL, and one existing
currently usable, purpose-authorized Ed25519 Artifact trust key in the selected
tenant and region. Names and index URLs are unique within that namespace, not
across the whole platform. Two namespaces may pin the same publisher, public
fingerprint and URL independently; accepting, disabling, rotating, revoking or
advancing one source does not change another namespace's trust or catalog head.
There is no implicit platform-wide shared-trust policy. The URL host must be in
ICHECK_CAPABILITY_CATALOG_ALLOWED_HOSTS; credentials, query data, fragments,
plain HTTP, redirects, and non-allowlisted entry download hosts are rejected.
Fetches use a ten-second timeout and a 5 MB response ceiling.

## Signed index contract

The remote authority publishes icheck.capability-catalog-index/v1, wraps it in
icheck.capability-catalog-index.signed/v1, and signs the domain-separated
catalog digest. The index contains:

- a pinned catalog identity and strictly increasing positive sequence;
- timezone-bearing issue and expiry timestamps with at most 366 days of
  lifetime;
- up to 2,000 unique pack name/version and digest entries;
- exact platform API, pack digest, declared pack signer fingerprint,
  predecessor digest, bounded artifact/dependency counts, and HTTPS download
  URL.

Refresh rechecks the current host allowlist, bounded transport, canonical
digest, enabled pinned key, signature, catalog identity, clock window, expiry,
sequence, uniqueness, and every entry URL. Same-sequence replay is idempotent
only when the digest is identical. Sequence rollback and same-sequence
substitution fail closed.

Refresh requires PostgreSQL `READ COMMITTED` with autocommit disabled; other
transaction settings fail before fetching. After fetching and initial
validation, it takes an exclusive source lock that refreshes cached state,
then shared locks on the current signing domain and key. Domains precede
managed keys, matching bundle reconciliation. It reverifies the exact fetched
bytes, pinned identity, signer policy and validity under those locks before
acceptance. A source changed or disabled during fetch, a newer head committed
by another Session, or key/domain containment committed during a lock wait
cannot be bypassed by cached ORM objects. The locks last through publication.

The catalog signature authenticates the index publisher, not a pack payload.
Discovery separately reports whether each declared pack signer is currently
trusted and whether the declared platform API matches iCheck.
Signer readiness honors the local purpose, validity window, enabled domain and
latest distributed snapshot, not only the key's enabled bit. Current listings
join signer fingerprints within the snapshot's namespace; expired, revoked or
contained local pins cannot borrow a peer tenant's same-fingerprint key.

## Governed pack acquisition

A manage-authorized operator provides a human reason and explicitly previews
one current entry. The control plane rejects disabled, expired, superseded,
revoked, or no-longer-allowlisted entries before opening a network connection.
It fetches JSON through no-redirect HTTPS transport with a 20-second timeout
and 25 MB ceiling. The signed pack must exactly match the catalog-pinned name,
version, platform API, digest, signer fingerprint, predecessor digest, Artifact
count, and dependency count.

The ordinary pack boundary then independently verifies the canonical pack
digest and Ed25519 signature, every embedded Artifact digest/content hash,
dependencies, target validators, revocation state, and lineage. Preview returns
only the bounded plan and blockers; the downloaded signed document is neither
persisted nor returned to the browser.

Install never trusts or reuses the preview response. It refetches the URL,
repeats the current-snapshot and exact-identity checks, and reruns the complete
pack preview inside the installation path. A successful installation records
`distribution_channel=remote_catalog` plus the catalog, source, immutable
snapshot, entry, sequence, index digest, and download host. It still ends at
validated: publication, activation, rollout, scheduling, and execution remain
separate governed actions.

Downloads complete before acceptance locks are taken. The service then locks
the namespace-local pack lineage/digests, rechecks the current catalog under a
shared source lock, and holds current catalog/pack signer authority through
installation. A source disabled or head advanced during download fails closed.
The frozen distribution identity and snapshot/key expiry are checked again
after Artifact validation, immediately before commit. Uploads and signed
revocation feeds use the same digest boundary: if revocation commits first,
installation is rejected; if installation commits first, the feed sees the new
installation when quarantining it. Matching digests in other namespaces do not
share this lock. Unsupported PostgreSQL transactions fail before fetching or
writing a failure audit.

## Persistence and projection

Successful refresh stores an immutable snapshot and normalized metadata
entries; it does not retain a raw response body or any Artifact implementation.
The current discovery endpoint returns only the newest unexpired snapshot from
enabled sources. It joins local installation/tombstone state and signed
revocation state at read time. Disabling a source immediately removes its
entries from current discovery without deleting history.

Refresh failure records a stable error type and SHA-256 in the source and audit
ledger, never a response body. The prior signed snapshot remains discoverable
only while enabled and unexpired. Source create, refresh, enable, and disable
actions record the authenticated actor and hash the human reason where
applicable.

## Catalog signing-key rotation

Changing a pinned source key is not an ordinary settings edit. The external
authority creates an
`icheck.capability-catalog-key-rotation.signed/v1` envelope over the exact
catalog ID, latest accepted sequence and index digest, current and next key
fingerprints, and a timezone-bearing validity window of at most 24 hours. Both
the current and next Ed25519 keys must sign the same statement digest, and both
public keys must already be enabled in the local trust registry.

Acceptance refreshes the exclusively locked source, holds current and successor
signer authority for shared reads, changes the pinned key, and writes the
rotation ledger with both signature hashes. Disabled sources and stale cached
state cannot bypass these checks. Exact retries require the accepted signature
bytes/digests and unchanged accepted key/head, release their transaction locks,
and never create another rotation or audit. Conflicting or forged retries are
rejected. Old-key indexes are then
rejected. A current snapshot remains discoverable only while both the newly
pinned source key and the key that actually signed that immutable snapshot are
enabled. Revoking the old key therefore hides its old snapshot until a new-key
snapshot is accepted; it never silently reattributes old evidence to the new
key.

Acquisition is deliberately operator-initiated and synchronous. It does not
schedule background network work, copy a pack into the browser, publish,
activate, deploy, schedule, or execute a capability. Preview success and
hashed failures are audited without retaining response bodies. Accepted
snapshots and rotations also enter the local
[capability transparency chain](./capability-transparency.md). Trust keys may
now be distributed through a locally pinned
[organization trust domain](./organization-trust-distribution.md). External
witness quorum and automated quorum-backed gossip are implemented separately.
Durable witness and promotion delivery with endpoint mTLS rotation is
implemented separately. Verified HSM/KMS recovery signing is implemented;
live CI identity-provider and vendor gateway/drill
acceptance, and recovery exercises remain separate work. Health-gated
automatic rollout rings are implemented on the local lifecycle surface.
Signed cross-environment receipts and manual atomic publication are governed
on the separate promotion surface.

## Database verification

On 2026-10-03, PostgreSQL 16.15 acceptance verified namespace-local publisher
identity/migrations and catalog refresh under a non-owner runtime role. The
combined database suite passed 112 tests, including 24 publisher identity/refresh
cases and 55 rotation/pack transaction cases. Planned rotations, post-download
acceptance, expiry during validation, exact retry and bounded transaction-loss
recovery now have real PostgreSQL checks. Signed transport uses fixture bytes:
this does not accept live publisher HTTPS, every bundle/uninstall/publication/
dependency race, whole-server failover, production upgrade/backup datasets or
live recovery ceremonies. See
the acceptance contract (private development evidence; not distributed).

The full ordinary backend regression passed 548 tests against the final
implementation. The existing Starlette TestClient deprecation warning is
non-failing; no integrated demo ran.
