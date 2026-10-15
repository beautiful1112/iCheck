# Collector source qualification

This is an external human-attestation prerequisite, not automatic physical
truth, causal attribution to a remediation action, or incident-closure authority.
Original admissions, source generations, receipts and resolved-state projections
retain `independently_verified: false` and their original meaning.

## Operator workflow

A Situation's Collector Alert links to `/assets/condition-sources/{source_id}`.
The link comes from the immutable source's actual Alert deduplication key, not
an operator-controlled `details.source_id`. The dedicated page shows logical
state, the bounded receipt history and exact source material. Governance forms
are collapsed; nothing is added to the L1 homepage.

1. A persisted human with `alerts.manage` and `capabilities.read` proposes validation of one accepted
   typed active/quiet baseline receipt. Record an external validation reference,
   the evidence environment, reason and future expiry within thirty days.
2. A different persisted human with `alerts.sources.qualify` independently
   validates condition semantics, exact source identity and observation-clock
   controls. All three explicit boolean attestations, an acceptance reference
   and reason are required. The Collector author, validator and publisher cannot
   act as that independent peer. Custom reviewer roles should also include
   `alerts.read` and `capabilities.read` for this UI. Collector implementation
   material keeps its existing read permission; a generic Alert viewer cannot
   read the full source or qualification snapshots. These permissions do not
   grant change execution.
3. Check current quiet evidence for the selected acceptance and exact current
   Alert episode. Later polling receipts reuse the accepted source generation;
   they do not require another human review per sample.
4. Withdraw acceptance with an append-only revocation. Revocation remains
   possible after origin drift, expiry or loss of the original author's role,
   provided the revoker retains current qualification permission and scope.
   The revocation API does not require implementation-read permission; removing
   that permission blocks acceptance/proof but cannot prevent withdrawal.

Source detail/history and proposals expose Collector implementation material,
so they require `capabilities.read`. Current implementation-read permission for
the author and peer is also rechecked after origin waits and during quiet checks.
The non-material quiet result needs only `alerts.read` and object scope.

The disabled-auth development principal and service/AI principals cannot propose
or independently accept source validation. Service principals with read access
can query the read-only check; they cannot turn it into closure permission.
Evidence environments are human attestations: `controlled_fixture`, `live_lab`
and `production`. The software cannot establish the honesty or quality of an
external reference. A production-labelled proposal additionally requires a
sealed verified Worker mTLS admission under an enabled mTLS policy. A fixture
or lab qualification never becomes production-qualified merely because a
quiet check passed. No live/production semantic acceptance was performed here.

## What is pinned and rechecked

The proposal records full canonical material, not another standalone hash job:
the declared typed predicate and freshness bound; published Collector version
material and governance actors; exact assignment/target/configuration/selector;
Device/entity identity; credential profile generation; Worker token-issued-at
and mTLS identity/revision; admission authentication method and mTLS policy.
Existing admission/content hashes remain normal security fields.

Peer acceptance repeats current origin and human role/scope checks. Quiet checks
also repeat them and inspect the current condition clock. They require an
accepted, typed quiet receipt at that exact clock, a current resolved Alert
episode, an earlier accepted active receipt for that episode, a non-future
measurement within the version's freshness bound, unexpired acceptance and no
revocation. Same-time conflicts, unknown values, stale measurements, manual
Alert resolution and a new credential/source generation cannot supply proof.
Some invalid/hidden/drifted origins fail the request closed rather than returning
a blocker list; absence of a successful check is never success evidence.

The response is point-in-time evidence only. It explicitly declares
`verification_basis: peer_reviewed_external_attestation`,
`physical_truth_automatically_verified: false`, `covers_situation: false` and
`authorizes_incident_closure: false`. It does not prove that a particular action
caused recovery. The browser invalidates successful displays after measurement
freshness/acceptance expiry, on refresh, namespace change, denial or a new check.
A still-visible earlier result is never a current authority grant.

A separate [Situation recovery policy](situation-recovery-policies.md) can now
bind these accepted sources to reusable sampling criteria and check the full
correlated membership set. Its whole-Situation result does not change this
single-source endpoint's `covers_situation: false` contract and still grants no
closure or causal remediation authority.

## API and storage

- `GET /api/v1/collector-condition-sources/{id}`: logical source and receipt
  history, default limit 50, maximum 100, explicit truncation.
- `GET` / `POST /api/v1/collector-condition-sources/{id}/qualifications`:
  bounded proposal/review/revocation history or a new proposal.
- `POST /api/v1/source-qualification-requests/{id}/review`: independent peer
  attestation; one immutable review per proposal.
- `POST /api/v1/source-qualification-reviews/{id}/revoke`: retained revocation.
- `GET /api/v1/collector-condition-sources/{id}/quiet-evidence?review_id=...&alert_id=...`:
  fresh check for one exact Alert only; it changes no condition/Alert/Situation.

Requests use a source-local request key; exact retries return the same row.
Changed author/material/reference or a revoked review cannot be silently
overwritten/reactivated. Review and revocation retries are also exact. There is
no Worker ownership/lease or loss-recovery protocol for incident closure in
these routes. History caps are disclosed; deep-history pagination remains a
broader UI/scale acceptance item, not a claim of complete historical browsing.

Migration `a5c7e9g1i3k6` adds three append-only tables after `z4b6d8f0h2j5`.
PostgreSQL guards reference namespace, source/baseline/peer identity and false
authority flags, with forced tenant/region RLS. Current permissions and scope
are application-service checks, not a claim that a compromised direct database
writer cannot forge a human attestation. SQLite ORM checks are fixture checks;
production database enforcement requires the actual migration. Populated or
namespace-hidden downgrade is refused. Nothing upgrades old logical receipts
to independently verified truth or backfills fabricated peer acceptance.

Operations use READ COMMITTED, non-autocommit transactions and origin -> source
-> proof-row ordering. A single source's deployment is locked before its current
condition and any later run pins are checked. No Situation lock or reverse Alert
row lock is introduced. A full Situation-wide closure transaction still needs
its own exhaustive membership/authority/ownership protocol; callers must not
compose these HTTP responses into a closure grant themselves.
In particular, an aggregate gate must lock its entire deployment set before
taking any shared Worker/Device resources. Sequentially composing single-source
lock chains can deadlock with a Collector writer for another deployment on the
same Worker. Exhaustive membership and drift checks remain a separate gate.

## Verification and remaining release gates

The final affected ordinary repeat passes 122 cases. The native repeat passes
157 cases, including 53 new source
qualification cases and 104 existing condition, ordering and Situation cases.
It uses the migrated schema and a non-owner/non-BYPASSRLS role, real origin lock
waits, direct SQL history/reference guards, namespace-hidden reads and guarded
downgrades. Real bearer API tests cover peer acceptance, quiet checks, history
and revocation without overriding principal/permission dependencies. Generic
Alert viewers cannot read implementation snapshots; current implementation-read
loss is checked after actual waits and does not prevent retained revocation.
The complete ordinary core repeat passes 1,332 with 24 skips and eight warnings
before that final permission guard; the final affected repeats verify the narrow
permission delta separately. This is not a whole-product acceptance signoff.

Typing, strict full lint and production frontend build pass. Isolated browser
fixtures check the focused page; they are not independent vendor acceptance or
an integrated demo. See the verification record (private development evidence; not distributed)
for the final ordinary repeat and browser/cleanup status.

Situation-wide qualified recovery, independent reviewed closure, indexed action
routing, exact ownership/loss recovery, Agent Tools and a focused receipt UI are
implemented in their subsequent components. Their proofs remain non-causal and
non-authorizing outside the separate governed closure path. Still required:
explicit reviewed generation replacements; deep history/unknown reconciliation;
actual new-Tool Worker loss/transport recovery; production identity/CA/mTLS/secrets
and coordinated rollout; sustained load/restart; broader accessibility and live
model/vendor semantics; six-class GUI lab acceptance. All three reviewed host
gates remain off. No production cutover or live collection/action was performed.
