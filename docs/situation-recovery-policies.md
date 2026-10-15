# Situation recovery policies

A reusable recovery policy binds independently accepted exact Collector source
generations to reviewed sampling criteria. A fresh check covers every correlated
Alert in one Situation, including historical episodes. This is observed source
recovery, not permission to close an incident or proof that a particular repair
caused recovery. The API explicitly returns `authorizes_incident_closure: false`,
`closure_execution_available: false`, `remediation_causality_proven: false` and
`physical_truth_automatically_verified: false`.

## Operator workflow

Open **Recovery evidence** from a Situation. The focused
`/situations/{id}/recovery` page keeps policy authoring and detailed source
receipts out of the L1 homepage.

1. Independently qualify each exact source through its
   [source acceptance page](collector-source-qualification.md). A payload source
   label, generic resolved Alert or unvalidated source is not a substitute.
2. Propose reusable criteria as a persisted human with `alerts.manage` and
   `capabilities.read`. Bind one source acceptance review per exact generation;
   set the evidence environment, minimum samples and duration, maximum polling
   gap, maximum latest-measurement age, expiry and external validation reference.
3. A different persisted human with `situations.recovery.qualify` and
   `capabilities.read` explicitly accepts the criteria. The author and reviewer
   must retain current permission, material-read access and source scope.
4. Load the policy by request ID and check every Situation member. Read-only
   callers need a persisted identity with `alerts.read` and full object scope,
   not Collector implementation access. AI/service identities may read this
   evidence but cannot create or independently accept policies.
5. Revoke acceptance with an append-only entry. Current qualification permission
   and source scope remain necessary; original peers, origin freshness and
   material-read permission are not prerequisites for emergency withdrawal.

Acceptance applies to a reusable template, not each polling iteration or each
incident. A new Situation still requires new current recovery evidence. Exact
request/review/revocation retries retain their immutable IDs; changing material,
identity or criteria under the same key is a conflict. Revoked acceptance cannot
be reactivated by retry.

## Evidence criteria and coverage

The policy's evidence environment must equal every source acceptance environment.
It cannot relabel a fixture or lab acceptance as production. Policy expiry is
future, at most thirty days away, and no later than any source acceptance. Age
and polling-gap limits cannot exceed the published source freshness bound.

Every correlated Alert must be visible and resolved, match the actual immutable
source deduplication key and typed entity/event identity, and have an earlier
accepted active receipt whose sealed provenance also matches the qualified
Worker/source origin. A new Worker acceptance cannot retroactively validate an
old active episode from another authentication generation, even when both
receipts retain the same source ID. One fresh current quiet witness may cover
several old episodes of the same source. It does not rewrite those episodes or invent a
separate historical quiet receipt. A subsequent active episode invalidates
recovery until the source produces another qualifying quiet window.

Count only strictly ordered, distinct accepted quiet receipts. Duplicate or
stale receipts do not contribute samples. Active, unknown and conflicting
observations reset the window; a gap exceeding the reviewed maximum starts a
new observed segment. Every counted receipt's sealed provenance is checked
against the independently accepted generation. At least two samples and a
positive observed duration are mandatory. Measurements between polls are not
automatically verified physical truth.

Limits are explicit: at most 64 policy sources, 512 Situation memberships and
256 candidate quiet receipts per source window. An incomplete or clipped check
cannot qualify. These are safety bounds, not a fleet-capacity acceptance claim.
Unused policy bindings are also revalidated; an omitted required source cannot
hide revoked acceptance. Credential, Worker, Device or version drift cannot
inherit authority across generations. Explicit reviewed replacement mapping is
not implemented; its full [replacement contract](reviewed-source-generation-replacement.md)
includes active old episodes and quiet new sources without synthetic Alerts.
Until that implementation is accepted, rotated generations require new independent acceptance and a
new policy, and unsupported old members continue to block complete coverage.

The response contains membership and active/quiet receipt IDs, condition
revisions, observed clocks and policy/source review IDs, but no Collector code.
`covers_situation` describes complete mapping of the checked memberships;
`qualified_recovery` additionally requires all evidence and policy checks to
pass. Both describe this transaction only. The browser clears proof on a new
operation, denial or namespace change, ignores delayed responses from an older
namespace, and expires successful evidence at `valid_until`.

## Transaction and storage contract

The complete sorted deployment set is locked before entering any origin chain.
This avoids taking a shared Worker lock while waiting on a second selected
deployment. Lower origin locks use PostgreSQL `NOWAIT`: contention with an
unrelated producer aborts the entire proof transaction instead of waiting while
holding another origin chain. The API rolls back and returns a retryable 409;
the caller must retry the full check, not reuse a partial report.

Situation is locked last. No reverse Alert row lock is taken. Memberships,
Alert state, parent identity, full reader scope and projected membership count
are read again after the parent wait. A changed set fails closed; the checker
does not acquire new source chains while holding the parent. Measurement,
qualification, policy and certificate deadlines are checked again after waiting.
Native operation requires PostgreSQL READ COMMITTED without DBAPI autocommit.
Pending caller edits are rejected before any evidence assembly.

Migration `b6d8f0h2j4l7` adds request, independent review and revocation ledgers
with forced tenant/region RLS, guarded source references and append-only native
SQL/ORM history. It does not rewrite existing source clocks, receipts, generic
resolved-state events or qualifications. Downgrade refuses populated history
or namespace-limited visibility. SQLite remains a development fixture path;
UTC output normalization does not relax timezone requirements on client input.

| API | Purpose |
| --- | --- |
| `POST /api/v1/situation-recovery-policies` | Propose exact reusable criteria |
| `GET /api/v1/situation-recovery-policies/{request_id}` | Non-material policy and review history |
| `POST /api/v1/situation-recovery-policies/{request_id}/review` | Independent acceptance |
| `POST /api/v1/situation-recovery-policy-reviews/{review_id}/revoke` | Retained withdrawal |
| `GET /api/v1/situations/{id}/recovery-evidence?policy_review_id=...` | Fresh exhaustive recovery check |

## Separate reviewed closure execution

Recovery evidence remains a prerequisite, not execution authority. The separate
[reviewed closure backend](reviewed-situation-closure.md) consumes this shared
checker at admission and finalization, with independent grants, current owners,
bounded leases/attempt epochs, structured related-action checks, atomic durable
receipts and lost-response recovery. It adds runtime-owned Agent Tools and a
default-off host switch without changing this report's non-authorizing flags.
Both initiating snapshot scope and current persisted scope are enforced.

Indexed immutable action routing and the separate focused closure page now
provide scoped candidate discovery, authority review/revocation, exact admission
and historical receipt recovery. This recovery page still contains no close
button. Explicit reviewed generation replacements, deep history/reconciliation
and sustained fleet acceptance remain open. Current observations and historical
closure receipts stay separate; neither is repair-causality or physical-truth
proof.
