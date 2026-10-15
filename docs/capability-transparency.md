# Capability transparency chain

iCheck maintains one append-only hash chain per tenant/region namespace for the
security-sensitive capability ecosystem lifecycle:

    GET /api/v1/capability-transparency/checkpoint
    GET /api/v1/capability-transparency/records
    GET /api/v1/capability-transparency/verify
    UI  /studio/catalog/transparency
    UI  /studio/catalog/transparency/witnesses

The chain currently includes organization trust-domain creation/state changes,
accepted trust bundles, dual-signed organization-root rotations, remote catalog
snapshots, dual-signed catalog key rotations, capability-pack installs and
upgrades, signed revocation feeds, compatible pack uninstalls, recovery-policy
authorization, and emergency root re-anchor proposal/execution/cancellation.
Failed cross-environment promotion acceptances also stay in the audit ledger,
while a successful exact-target promotion receipt advances the chain. Failed
previews and fetches remain in the ordinary audit ledger rather than advancing
the success chain.

## Record contract

Every successful event appends
`icheck.capability-transparency-record/v1` in the same database transaction as
the governed state change. The canonical SHA-256 material contains:

- a strictly increasing sequence;
- the previous record digest, beginning with 64 zeroes;
- event and entity identity;
- the signed index, statement, pack, or feed digest that is the event subject;
- a bounded metadata-only detail map; and
- the UTC event timestamp.

The namespace-local checkpoint row is locked before sequence allocation. It stores a
stable random log identity, epoch, last sequence, and head digest. PostgreSQL
therefore serializes concurrent writers of that namespace through one explicit ordering point,
and a failed state transaction also rolls back its transparency record and
checkpoint update. The log identity is not inferred from a hostname or region,
so regional comparisons cannot accidentally merge unrelated chains.
The legacy default namespace retains its `global` checkpoint identity; other
namespaces use distinct stable row keys and random log IDs. Record sequence,
digest and witness identities are unique inside a namespace. Witness policy is
also namespace-local. Gossip compares replicas of the same log identity; an
independent tenant/region log is not a replica to merge.

The record never stores signed response bodies, Artifact implementations,
credentials, or raw errors. Pack/catalog names, versions, counts, fingerprints,
channels, and reason hashes are sufficient to correlate with their dedicated
immutable ledgers.

## External checkpoint witnesses

The external witness surface is:

    POST /api/v1/transparency-witnessing/witnesses
    GET  /api/v1/transparency-witnessing/witnesses
    POST /api/v1/transparency-witnessing/witnesses/{id}/state
    GET  /api/v1/transparency-witnessing/policy
    PUT  /api/v1/transparency-witnessing/policy
    POST /api/v1/transparency-witnessing/checkpoint-offers
    GET  /api/v1/transparency-witnessing/checkpoint-offers
    POST /api/v1/transparency-witnessing/checkpoint-offers/{id}/attestations
    GET  /api/v1/transparency-witnessing/checkpoint-offers/{id}/attestations
    GET  /api/v1/transparency-witnessing/checkpoint-offers/{id}/gossip
    POST /api/v1/transparency-witnessing/gossip
    GET  /api/v1/transparency-witnessing/gossip
    POST /api/v1/transparency-witnessing/gossip/fork-alerts/reconcile

Durable checkpoint delivery is exposed separately:

    UI   /studio/catalog/exchange
    POST /api/v1/ecosystem-transport/endpoints
    POST /api/v1/ecosystem-transport/witness-offers/{id}/dispatch
    GET  /api/v1/ecosystem-transport/jobs
    GET  /api/v1/ecosystem-transport/workers
    GET  /api/v1/ecosystem-transport/health

An administrator pins each independent witness's Ed25519 public key with the
dedicated transparency_witness purpose, then binds one stable witness identity
and region to that exact key. Private witness keys remain outside iCheck. A
checkpoint offer contains
icheck.capability-transparency-checkpoint-statement/v1 and canonically binds
the log ID, epoch, sequence, head, issue time, and expiry.

Each external witness returns
icheck.capability-transparency-witness-attestation.signed/v1. Acceptance
recomputes the attestation digest, verifies its domain-separated Ed25519
signature, requires the registered identity's pinned key and purpose, binds all
checkpoint fields, rejects future/expired/overlong signatures, and prevents
rollback or conflicting attestations through the local offer ledger. The
configurable quorum is 1 to 16; signature lifetime is 1 to 720 hours.

Quorum is live rather than historical. An attestation stops counting if its
witness or trust domain is disabled, its key is revoked/expired/stale, its
signature is no longer valid, or its own/checkpoint expiry passes. A gossip
document cannot be exported until the currently valid unique-witness count
reaches policy.

## Cross-region gossip

icheck.capability-transparency-gossip/v1 carries one checkpoint plus its
independent signed attestations. Source region is descriptive metadata; trust
comes from the checkpoint-bound witness signatures, not from that label.
Import revalidates every signature and the current local quorum, rejects
duplicate witnesses and a different log identity/epoch, and stores a
content-addressed observation. Reimport of the exact same document is
idempotent.

The comparison statuses are:

- consistent: the remote sequence and digest equal the local head;
- behind: the remote sequence names an older record in the local chain;
- ahead: the remote sequence is newer than the local head; and
- fork: the remote digest conflicts with the local record at that sequence.

Initial status is immutable evidence. Current status is recalculated on read,
so an ahead observation can become consistent or fork after local replication.
Fork evidence is retained and audited as a failure outcome.

A verified initial `fork` bypasses optional threshold rules and atomically
creates a mandatory critical Alert. Its dedupe identity binds log, epoch,
sequence, and the conflicting remote head. Exact gossip replay creates neither
a new observation nor a new occurrence; independent regional documents for the
same conflict share one Alert and increase its occurrence count. The Alert
contains bounded digest, witness-count, region, and observation references,
then enters the ordinary Situation correlation and Workflow alert-trigger
paths. Each fork observation stores its Alert ID. The admin-only reconciliation
route backfills any pre-existing fork rows that have no alert link, using
row-locked bounded batches.

Witness registration, checkpoint publication, signature ingestion, and gossip
comparison use the ordinary audit ledger but deliberately do not append to the
chain they are witnessing. This avoids a self-referential checkpoint that
changes merely because it was signed.

## Verification boundary

The verify endpoint recomputes every record from genesis and checks sequence
continuity, previous-digest links, each record digest, and the stored head. The
Studio page shows the result and exact failure sequence.

On 2026-10-02, authenticated API tests installed the same pack payload in two
tenants under separate trusted signatures and verified separate log IDs,
sequence-one records, valid chains and cross-tenant read denial. An actual
SQLite Alembic upgrade preserved an old record, accepted the same sequence and
digest in another namespace, and refused unsafe downgrade. First-writer state
creation now uses an idempotent insert followed by a row lock. These checks do
not substitute for live PostgreSQL concurrency and RLS acceptance.

This makes mutation detectable against a checkpoint observed outside the
database, and the implemented quorum/gossip layer can persist evidence of a
conflicting regional head. Checkpoint offers now have durable automated HTTPS
delivery to pinned independent witnesses. Every returned signature still
passes the ordinary ingest verification path, so the control plane never
receives a witness private key. Once an offer has a live quorum, the same
Worker automatically delivers its gossip document to pinned regional peers
and accepts only an exact receipt from the ordinary gossip-ingest path. Manual
gossip export/import remains available as an operator fallback.

Production completion still requires independently deployed witness services,
live endpoint-mTLS interoperability acceptance, retention/backup policy for
witness evidence, and regional partition/recovery acceptance. Outbound
mTLS/rotation, automated quorum-backed gossip, and mandatory fork
Alert/Situation routing are complete; those deployment gates do not change
record or signature semantics.
