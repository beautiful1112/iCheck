# Emergency environment-promotion key recovery

This is a pre-authorized recovery of one disabled promotion source's public-key
pin. It is separate from [planned dual-signed handover](./capability-promotions.md)
and organization-root recovery. Losing a key does not grant an administrator
an unsigned override. Recovery does not publish, activate, deploy or execute
capabilities, reset qualification history, or automatically reenable the source.

The operator surface is `/studio/catalog/promotions/recovery`, linked from the
promotion Studio page, not the L1 homepage. It accepts only public policy,
ceremony and witness documents. Private keys remain outside iCheck. The
implemented transfer path is export, external signing, upload/paste and review;
the existing root-recovery HSM/KMS gateway is not automatically an
environment-recovery signer. Provider/gateway integration for these new
purpose-separated formats and live ceremonies remain acceptance work.

## Pre-incident authorization

While the source is enabled and its current `environment_promotion` key is
usable, export a recovery policy statement and obtain that key's signature.
The policy binds the source record, organization, both environment identities
and stages, current fingerprint, monotonically increasing policy version,
sorted trustee/witness fingerprints, quorums, delay and evidence-age bounds.

- Choose 2–8 distinct locally pinned `trust_recovery` trustee keys and a quorum
  of at least two. Distributed trustees are not accepted.
- Choose 2–8 distinct locally registered witness fingerprints and a quorum
  of at least two. Their current keys require `transparency_witness` purpose.
- Old authority, trustees and witnesses must have mutually distinct
  fingerprints. The eventual successor must also differ from all of them.
- The mandatory delay is 1–72 hours; maximum evidence age is 1–168 hours.
- The signed authorization must be accepted within its positive, at-most-24-hour
  signing window; allowed future clock skew is five minutes.

Acceptance records the original signed policy, authority public key and
signature hash, local trustee/witness IDs, authenticated operator, reason and
transparency sequence. Its signing window controls initial acceptance, not
daily expiry of the recorded pre-authorization. At incident time iCheck
verifies the sealed historical signature without requiring a lost or revoked
old key to become usable again. Current successor, trustee and witness
authority still applies.

Only the latest unretired policy matching the source pin and exact local
target is usable. A new policy retires its predecessor. Planned handover
retires the old pre-authorization too. Returning an exact historical policy
retry never reauthorizes it or changes its original provenance.

## Incident and restoration sequence

1. **Contain.** Disable the exact source using its ordinary state API. The
   state change is recorded in the local transparency chain. Containment
   remains available even when the old key is revoked.
2. **Witness the incident head.** Obtain independently signed gossip for the
   target's current local log ID, epoch, sequence and head, covering the
   recorded policy and containment. A remote source checkpoint cannot replace
   this local incident head.
3. **Export and sign.** Export the incident statement for an independent
   successor. The successor and pre-authorized trustee quorum sign the same
   statement. It binds the policy digest, ceremony UUID, old/new fingerprints,
   exact source/target, preserved accepted source sequence/head, initial
   checkpoint digest and issue/expiry times. Lifetime is 2–168 hours and must
   leave more time than the mandatory delay when proposed.
4. **Preview and propose.** The preview performs current proof checks, writes
   no audit, transparency, policy, ceremony or event rows, and returns
   `authorizes_execution: false`. Proposal independently repeats verification
   and records the sealed statement, original proof, actual authenticated
   proposer, reason, earliest execution time and transparency sequence.
5. **Wait and execute.** A different authenticated operator executes only after
   the recorded delay, using a fresh witnessed current local checkpoint that
   covers proposal. The source must still be contained; policy, accepted head,
   signer pins, purpose/domain authority, signatures and times must still pass.
   Execution changes only the pin, records the sealed outcome and consumes the
   policy. The source stays disabled.
6. **Witness and restore.** Obtain another current local checkpoint covering
   execution, then explicitly reenable the source with its witness evidence.
   The ordinary source-state API enforces this gate too; another UI cannot
   bypass it. Restoration records its actual actor and verified evidence.

Every supplied witness proof is checked, not just those needed for quorum:
current local pin, purpose/domain authority, canonical signature and digest,
matching checkpoint, expiry, age and positive time window. Duplicate witness
identities/fingerprints and old/new/trustee self-witnessing fail closed. Only
pre-authorized witness IDs with the exact signed fingerprints count toward
quorum. Distinct public keys do not prove independent hosting or operators;
that requires the separate live drill.

A pending ceremony can be cancelled without signatures from the unavailable
old key. Cancellation retains the original documents and records a terminal
event; it does not reenable the source. A pending ceremony blocks reenabling
until cancelled. Executed ceremonies cannot be cancelled, and cancelled ones
cannot execute. After the first witnessed restoration, later ordinary
disable/enable cycles do not reuse that old ceremony as a new recovery grant.

Unlike planned handover, emergency recovery does **not** require publishing
unexpired pending receipts. Qualification made with a potentially compromised
key must not be forced into publication. Those receipts remain immutable and
their accepted source head is preserved; their historical retries still
return original evidence, but current-pin publication checks refuse them
after recovery. New qualification must use the recovered authority and normal
contiguous sequence and publication policy.

## Public wire and API contract

All routes require `capabilities.manage` in the selected tenant/region. Actor
fields remain compatible with existing clients, but authenticated requests use
the actual Principal, not a body-supplied executor name. History queries are
namespace local and bounded to 500 records; optional `source_id` filters apply.
Typed documents reject unknown fields, including private-key fields. Public
documents and combined proof-bearing requests are bounded to 256 KiB.

| Document | Format | Required signatures |
|---|---|---|
| Policy statement | `icheck.promotion-recovery-policy/v1` | None until wrapped |
| Signed policy | `icheck.promotion-recovery-policy.signed/v1` | Current source authority |
| Incident statement | `icheck.promotion-key-recovery/v1` | None until wrapped |
| Signed incident ceremony | `icheck.promotion-key-recovery.signed/v1` | Successor and trustee quorum |

Statements use the existing canonical JSON SHA-256 digest excluding
`digest_sha256`. Each Ed25519 signature signs the UTF-8 message
`SIGNED_FORMAT + "\n" + digest_sha256`; policy and ceremony signatures are
therefore purpose separated from root recovery, handover and pack signatures.
The signed policy carries `authority_signature`; the signed ceremony carries
`next_signature` and `trustee_signatures`. Evidence uses the existing typed
transparency gossip document, not arbitrary JSON or an unsigned acknowledgement.

The prefix is `/api/v1/capability-promotions`:

| Method and suffix | Result |
|---|---|
| `POST /sources/{id}/recovery-policy-statements` | Public policy signing template |
| `POST /sources/{id}/recovery-policies` | Accept externally signed pre-authorization |
| `GET /recovery-policies` | Recorded policy history |
| `POST /sources/{id}/state` | Explicit containment, or witnessed restoration with `checkpoint_evidence` |
| `POST /sources/{id}/key-recovery-statements` | Public successor/trustee signing template |
| `POST /sources/{id}/key-recoveries/preview` | Read-only current proof assessment |
| `POST /sources/{id}/key-recoveries` | Propose sealed incident ceremony |
| `GET /key-recoveries` | Ceremony history with derived pending/executed/cancelled status |
| `POST /key-recoveries/{id}/execute` | Delayed, distinct-operator pin recovery with fresh evidence |
| `POST /key-recoveries/{id}/cancel` | Preserve proof and record cancellation |
| `GET /recovery-events` | Exportable retirement, execution, cancellation and restoration evidence |

Exact completed proposal, execution, cancellation and policy retries return
the original outcome without new pin changes, history, audit or transparency.
An execution retry after a later handover cannot restore an older pin. Changed
proposal signatures, selected successor or initial checkpoint evidence are
not an exact replay.

## Persistence and transaction boundary

Migration `p8r0t2v4x6z9`, after `o7q9s1u3w5y8`, adds three namespace-local sealed
tables: pre-authorized policies, incident ceremonies and append-only lifecycle
events. It does not rewrite existing source or signed history rows. PostgreSQL
and SQLite guards reject updates/deletes of recorded recovery rows. Unique
terminal-event constraints prevent both execution and cancellation of one
ceremony. A downgrade requires visibility of all namespaces and refuses any
recorded recovery history before dropping schema.

Mutations retain policy/source authority, relevant sealed configuration,
sorted witness rows and one combined sorted signer/domain batch before
locking the local transparency head. No network or model call happens under
these locks. Pin changes, sealed decisions, audit and transparency commit
together or all roll back. Current signer/evidence time and authority are
checked after flush and earlier before-commit callbacks. PostgreSQL requires
`READ COMMITTED`, without autocommit. This is not a claim of tamper-proof
whole-database administration, arbitrary uncooperative row insertion,
independent witness infrastructure or physical-server failover.

## Verified code and remaining acceptance

The full backend suite passes **623 tests**. This slice adds 20 ordinary API
cases using real signatures plus one SQLite migration-preservation/sealing
case with explicitly synthetic metadata. It covers revoked-old-key recovery,
quorums, invalid proof, containment, delay, distinct executor, restoration,
later-pin historical retries, read-only previews and real accepted-but-unpublished
receipt preservation/current-pin publication refusal.

The full PostgreSQL **16.15** suite passes **561 tests**, including 32 new
native recovery cases: both actual lock-wait commit orders, cached authority
refresh, late expiry rollback, real backend termination, controlled post-commit
response loss, authenticated second operator, namespace isolation, non-owner
immutable SQL guards, transaction-mode preflight and unsafe downgrade refusal.

Frontend type-check and production build pass with isolated Node **22.23.3**.
Mocked Playwright checks cover public downloads/uploads, rejected-input
preservation, preview, delayed controls, separate execution/restoration
checkpoint submissions, actual outcome display and inspected desktop/390-pixel
layout without horizontal overflow. Synthetic browser responses are not live
cryptographic admission. Database/role fixtures were removed and the private
socket-only PostgreSQL and browser/frontend fixtures stopped. No production
migration, deployment, live ceremony or integrated demo was run.

M6/M7 and the full-product objective remain open. Live independent trustee/
witness operations, environment-specific external signing integration,
multi-environment transport, remaining publisher lifecycle transaction paths,
representative production datasets/scale and the
[real-lab gates](./lab-acceptance.md) still require their own acceptance.
