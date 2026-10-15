# Governed capability promotion

iCheck treats cross-environment promotion as signed qualification evidence, not
as a shortcut around target governance. A source environment exports a
canonical statement for an already installed and currently eligible signed
capability pack. An external Ed25519 promotion authority signs that statement.
The exact target environment then revalidates both the envelope and its own
current pack state before accepting an immutable receipt.

The management surface is:

    UI   /studio/catalog/promotions
    GET  /api/v1/capability-promotions/policy
    PUT  /api/v1/capability-promotions/policy
    POST /api/v1/capability-promotions/sources
    GET  /api/v1/capability-promotions/sources
    POST /api/v1/capability-promotions/sources/{id}/state
    POST /api/v1/capability-promotions/sources/{id}/key-rotation-statements
    POST /api/v1/capability-promotions/sources/{id}/rotate-key
    GET  /api/v1/capability-promotions/key-rotations
    GET  /api/v1/capability-promotions/key-rotations/{id}/export
    POST /api/v1/capability-promotions/statements
    POST /api/v1/capability-promotions/preview
    POST /api/v1/capability-promotions/accept
    GET  /api/v1/capability-promotions/receipts
    GET  /api/v1/capability-promotions/receipts/{id}/export
    GET  /api/v1/capability-promotions/publications
    POST /api/v1/capability-promotions/receipts/{id}/publication-preview
    POST /api/v1/capability-promotions/receipts/{id}/publish
    GET  /api/v1/capability-promotions/source-witness-policy
    PUT  /api/v1/capability-promotions/source-witness-policy
    GET  /api/v1/capability-promotions/source-checkpoint-bindings
    PUT  /api/v1/capability-promotions/sources/{id}/checkpoint-binding
    GET  /api/v1/capability-promotions/receipts/{id}/source-witness-evidence

Automated delivery is deliberately separate:

    UI   /studio/catalog/exchange
    POST /api/v1/ecosystem-transport/promotion-deliveries
    GET  /api/v1/ecosystem-transport/jobs

## Environment and trust boundary

The local policy pins:

- a stable environment identity;
- its development, test, staging, or production stage;
- the one source stage accepted by this target;
- a maximum signed-attestation lifetime of 1 to 168 hours;
- publication disabled or explicit manual atomic publication; and
- whether the publisher must differ from the receipt acceptor.

Environment identity and stage become immutable after the first accepted
receipt. A source registration binds organization identity, source environment,
source stage, and one exact Ed25519 public key. The key must have the dedicated
environment_promotion purpose. If it came from organization trust distribution,
the source organization must match that trust domain. Disable is an immediate
break-glass control.

New witness and promotion purposes are opt-in. Omitting `purposes` while
registering an ordinary local trust key does not silently grant either
transparency_witness or environment_promotion authority.

Each tenant/region owns one policy, independent source names/environment IDs,
and independent signed-statement and target-pack receipts. Identical signed
proofs can be accepted in another namespace only after its own local pins and
pack validation. Policy lookup uses the selected namespace, not a literal
`global` primary key. Existing legacy policy IDs and their audit references are
preserved; new policy IDs are opaque.

Migration `m5o7q9s1u3w6` adds the singleton and scoped identity constraints
without rewriting policy, source, receipt or publication history. It requires
visibility of every namespace and rejects an ambiguous legacy namespace before
changing schema. Downgrade refuses new policy IDs or cross-namespace duplicate
identities; it never renames or deletes records to make the old application fit.

## Planned promotion key handover

The dedicated promotion page exports a short-lived handover statement, accepts
an externally dual-signed document, and displays exportable history. Neither
the browser nor server needs a private key. Both current and successor keys
must be usable Ed25519 keys with `environment_promotion` purpose. Distributed
keys must also belong to the source organization and an enabled trust domain.
A revoked or lost current key uses the separate
[pre-authorized emergency recovery](./promotion-emergency-recovery.md) ceremony;
there is no unsigned override in this planned path. Planned handover retires
the old source's recorded recovery pre-authorization.

The canonical `icheck.capability-promotion-key-rotation/v1` statement binds
organization, source and exact target environments/stages, both fingerprints,
the target's latest accepted source sequence and statement digest, and issue
and expiry times. The `icheck.capability-promotion-key-rotation.signed/v1`
envelope carries both domain-separated signatures over the same digest. Maximum
lifetime is 24 hours, with five minutes of allowed future clock skew. The
document limit is 64 KiB; unknown fields and private-key fields are rejected.

Publish every unexpired accepted but unpublished receipt before the handover.
This drain rule avoids stranding qualification that still depends on the old
pin. If admission advances the source head after export, export and sign a new
statement; an older signed head cannot rotate current authority. Expired
receipts do not block a planned change or gain renewed validity from it.

Handover retains shared policy authority, exclusive source authority and sorted
shared signer/domain locks through commit. It rechecks time, pins, context and
pending receipts after flush and earlier before-commit callbacks. Pin update,
immutable signed snapshot, original authenticated operator/reason, audit and
transparency commit together. Failure rolls them all back. The accepted source
sequence and head are preserved; no key is revoked, and no capability is
published, activated or executed by the handover.

An exact completed retry returns the original immutable rotation record even
after containment or a later handover. It does not repin the source, reset an
advanced head, add history, or grant new authority. Changed signature bytes,
signed fields or successor key ID are not an exact replay. List/export queries
remain tenant/region local. Migration `n6p8r0t2v4x7` adds sealed rotation history
without rewriting existing sources. A downgrade requires visibility of every
namespace and refuses any recorded handover rather than deleting its evidence.

## Signed statement contract

The source creates
`icheck.capability-promotion-attestation/v1`. Its canonical digest binds:

- organization, source environment/stage, and exact target
  environment/stage;
- the source's strictly increasing promotion sequence;
- pack name, version, digest, original pack-signer fingerprint, Artifact count,
  and canonical Artifact-set digest;
- source transparency log ID, epoch, sequence, and head;
- an external validation-evidence digest; and
- issue and expiry times.

Statement generation rechecks the source installation first. The pack must be
the installed lineage head, unrevoked, signed by a currently usable
capability_pack key, composed only of validated/published Artifact versions,
and backed by still-published external dependencies. Generation writes audit
evidence but does not alter the transparency chain it references and never
signs or stores a private key.

The external authority returns
`icheck.capability-promotion-attestation.signed/v1` with a domain-separated
Ed25519 signature over the statement digest.

## Required independent source checkpoint witnesses

The promotion Studio subpage configures a target-local witness allowlist,
required quorum from 0 to 16, and maximum evidence age from 1 to 720 hours.
Zero explicitly means not required and is the compatibility default; reading
an unset policy does not create it. Requiring quorum needs enough enabled,
purpose-scoped independent keys. Pin each source's reviewed transparency log ID
and epoch separately. Changing a binding requires draining unexpired accepted
but unpublished receipts and never resets the promotion sequence.

Attach the existing `icheck.capability-transparency-gossip/v1` export as
`source_checkpoint_evidence` in the signed promotion envelope. The target
checks that its canonical checkpoint matches the pinned source log/epoch and
every log, epoch, sequence and head field in the signed promotion statement.
The gossip `source_region` label is informational, not proof of environment or
organization identity. Environment identity still comes from the pinned
promotion signer and signed statement.

Every supplied witness proof must have a valid canonical digest and signature,
exact checkpoint binding, enabled local witness pin and currently usable
`transparency_witness` key/domain. Checkpoint lifetime is at most 168 hours;
checkpoint and witness expiry, age and five-minute clock skew apply again at
commit. A witness cannot predate the checkpoint beyond that skew or outlive
it. A newly issued witness wrapper cannot refresh an aged checkpoint. Duplicate
identities or fingerprints are rejected, and neither the environment-promotion
signer nor the pack signer counts as an independent witness. Only allowlisted
identities contribute to the required quorum. These checks prove independent
cryptographic pins, not independent hosting or operators; deployment review
and live witness acceptance remain necessary.

Acceptance and publication retain policy/source authority, existing witness
policy and checkpoint-binding rows, sorted witness rows and one combined
sorted signer/domain batch through commit. There is no network or model call
under these locks. Late expiry or authority changes roll back the whole
decision. Acceptance records a sealed witness decision with exact evidence
digest, verified signer provenance, policy snapshot and authenticated operator
in the same transaction as the receipt. Publication verifies those saved
bindings and the current witness policy again.

Tightening policy can block an unpublished historical receipt lacking the new
evidence. Existing receipts cannot be amended with a different checkpoint
document: exact retries return the original history and never renew authority.
When no evidence is supplied, optional serialization omits the new field so
legacy signed envelopes and snapshots remain unchanged. The combined envelope
remains bounded to 256 KiB and at most 16 witness proofs.

Migration `o7q9s1u3w5y8` adds namespace-local policy, binding and sealed decision
tables without modifying legacy signed rows. Downgrade requires visibility of
every namespace and refuses recorded controls or evidence rather than silently
dropping a release safety requirement.

## Target acceptance

Preview is non-mutating. It verifies canonical digest, size, issue/expiry
window, dedicated key purpose, exact pinned source identity, exact local target,
required source stage, and exact-next source sequence. It then independently
rechecks the local installation:

1. exact pack name/version/digest and original signer;
2. current installed lineage head and no uninstall or revocation;
3. exact Artifact count and canonical Artifact-set digest;
4. every referenced Artifact remains validated or published;
5. every external dependency remains the exact published version; and
6. the original pack-signing key is still usable.

Acceptance locks and repeats those checks, stores the exact signed envelope and
signature provenance, advances the source sequence, and appends audit plus
capability-transparency evidence in one transaction. Sequence gaps, rollback,
cross-target replay, stage mismatch, content drift, and duplicate target-pack
promotion fail closed. Exact replay of an already accepted envelope is
idempotent.

A receipt qualifies the exact installed pack for that environment. Acceptance
never publishes automatically and never activates, deploys, schedules, or
executes an Artifact.

## Governed target publication

Publication is disabled by default. When manual publication is enabled, an
authorized operator first previews one accepted receipt. The target rechecks
the unexpired receipt, enabled pinned source and key, installed lineage head,
pack signer and revocation state, exact Artifact set, and external dependencies.
If four-eyes policy is enabled, the receipt acceptor cannot be the publisher.

The operation publishes every eligible pack-owned `installed`, `upgraded`, or
`retained` version in one transaction. A `reused` version is outside pack
ownership and must already be published. A Collector candidate with any canary
rollout record must use the dedicated canary promotion path; cross-environment
evidence cannot bypass it. Any blocker rolls back the whole decision.

Success stores one immutable, content-addressed publication record with the
exact candidate/already-published/reused version sets and policy snapshot. It
also appends audit and capability-transparency evidence. Exact retry is
idempotent. Runtime activation, deployment, scheduling, and execution remain
separate governance decisions.

Admission and publication retain shared policy authority; acceptance takes an
exclusive source boundary to advance sequence, while publication retains a
shared source boundary. Policy changes and source enable/disable operations use
the corresponding exclusive boundary, including when a row does not yet exist.
Source registration and re-enablement retain their current signer/domain
authority. No model or remote transport runs while these locks are held.

Pack lineage/digest precede sorted signer domains and keys, installation rows,
the full sorted Artifact/dependency identity batch, and version rows. Both the
original pack signer and pinned environment signer are refreshed and retained.
Domain disable, key revocation and bundle reconciliation therefore cannot race
between verification and a new committed outcome. Current dependency rows are refreshed under retained shared locks;
an earlier ORM snapshot cannot admit a revoked dependency. Single-version and
batch publishers use the same order, avoiding a version-row/identity-lock cycle.
Publication retries release locks while the caller Session remains open.
Post-commit response failures preserve the original durable publication, while
pre-commit failure rolls back every member and its publication/audit decision.
Unrelated constraint conflicts fail closed rather than returning an unchecked
row after rollback. PostgreSQL requires `READ COMMITTED` with autocommit disabled
and the whole mutation binds its selected tenant/region.

Publication verifies the original signed snapshot and its binding to every
receipt field, signer fingerprint and signature hash. The current target,
required source stage, maximum lifetime, publication mode and distinct-publisher
policy apply again. After flush and earlier before-commit callbacks, a final
check refuses an expired attestation or signer and rolls back member heads,
sequence, receipt/publication, transparency and audit together. Statement
issuance also checks signer and statement expiry immediately before commit.

An exact completed receipt/publication retry returns historical evidence with
its original operator and reason, even after containment. It does not renew
authority, advance sequence, republish members or add another audit/chain event.
A receipt retry must carry the exact originally verified signed envelope;
changed signature bytes are not an idempotent replay. Read-only previews are
informational snapshots, not authorization to commit a later change.

These boundaries do not accept every publisher trust mutation, physical server
crash/failover, production dataset, live HTTPS transport or recovery ceremony.
Expiry is checked at the final pre-commit decision; production replication and
long-duration capacity require their own acceptance.

## Durable delivery

A promotion-target endpoint pins one exact HTTPS URL, target environment, and
stage. The source queues an already signed envelope; transport never creates a
signature. The standalone worker adds an idempotency key, optionally resolves a
server-side Bearer credential, and posts the ordinary target acceptance
request. The target therefore executes the same source-key, sequence, target
identity, pack, Artifact, dependency, and revocation checks used for manual
transfer.

The worker treats success as provisional until the returned receipt exactly
matches source environment, target environment/stage, promotion sequence,
statement digest, and pack digest. Mismatch is permanent failure. Transient
network, rate-limit, and server failures use bounded exponential retry. Job
payloads and credentials are never returned by the management API.

## Remaining production gates

The signed protocol, target acceptance, and durable attestation transport are
implemented. Pack artifact replication remains separate: the exact pack must
already exist at the target. Exchange endpoint mTLS is implemented; CI/CD
identity federation acceptance and live multi-environment handover/witness
and emergency recovery acceptance remain production work. Required
source-checkpoint witness policy, planned dual-signed key handover and manual
four-eyes promotion-to-publication policy integration are implemented.
Pre-authorized emergency recovery is also implemented in its separate Studio
subpage, with a mandatory delay, independent trustee/witness quorums, a distinct
authenticated executor and witnessed explicit restoration. It does not force
pending receipt publication, reset accepted heads or grant autonomous action
authority. Its external environment-signing integration and live drill remain
separate from the existing root-recovery gateway.
