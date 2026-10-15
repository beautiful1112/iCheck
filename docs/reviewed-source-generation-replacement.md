# Reviewed source generation replacement

Internal governance, atomic cutover, public replacement API/GUI and runtime-owned
Agent Tools are implemented. Replacement-aware recovery and compatible v2
closure have separate default-off deployment gates. Implementation and isolated
acceptance do not authorize product rollout or a live cutover.
Replacement allows a user to evolve a Collector inside iCheck while preserving historical
measurements and making a new independently accepted generation authoritative.
It must cover both already-resolved old episodes and old episodes still active
at takeover, including a new generation that has only quiet observations and
has never created an Alert. Exact proposal, peer review, revocation and scoped
historical-read services and their additive ledger migration now exist. Atomic
retirement, producer fencing and current projection updates now exist as internal
services with an additive migration. Versioned replacement recovery now has its
own criteria and read-only checker. The closure path now has typed retained
references, action-relative samples, versioned grants/receipts, web controls and
an owned v2 AI Tool. The replacement workflow now has its own focused child page,
typed API and runtime-owned Agent execution. Actual new-Tool Worker interruption,
complete delegated/report integration and product release acceptance remain
required. Review alone changes no source, Alert or
Situation and does not authorize incident closure.

## Implemented governance boundary

The internal service retains both exact source qualification snapshots, their
baseline receipt references, normalized predicate/entity and the initiating
author's permissions/scope. Proposal and review require current persisted
authority and both source scopes. Acceptance requires a different persisted
human, excludes either Collector's author/validator/publisher and cannot be
reactivated after revocation. Exact retries preserve immutable request/review
identity; changed material fails closed.

Old provenance is checked against retained typed admissions and receipts
without restarting a disabled old producer or demanding unexpired historical
qualification. Revoked old semantics remain unusable. The new generation needs
current exact origin, unrevoked/unexpired independent acceptance and current
source-author/peer authority. Changed event/entity kind, predicate, threshold
or unit is rejected; a new version/title/freshness bound may evolve. Quiet-only
sources are supported without manufacturing an Alert.

Historical detail requires current and initiating read/material permissions
over both retained sources, without refreshing source origin, original peers
or expiry. Review/revocation/history never alters measured status, clocks,
occurrences or resolution. Native ledgers force namespace RLS, validate exact
qualification/snapshot lineage, reject raw history edits and refuse populated
downgrade. Migration requires all-namespace visibility and drained relevant
ownership. It has been exercised only in disposable fixtures, not deployed on
the product database. No replacement endpoint or executable Tool was registered
at this earlier governance-only boundary. The retirement migration has only been exercised in disposable
fixtures; coordinated migration, runtime-role grants and capability rollout must
precede deployment of the new code against an older product schema.

The preceding governance-only verification passed 167 ordinary cases and 158 migrated non-owner
PostgreSQL cases, including 55 replacement cases. Native checks cover raw
snapshot forgery, append-only history, actual namespace RLS, post-lock-wait
authority/revocation changes and refused populated/runtime downgrade. Older
downgrade tests now compare the original migration head instead of hard-coding
a prior head. The private database/role objects and server were cleaned up.
These are subcomponent checks, not full native, frontend, live-source or
replacement-execution acceptance. See the
verification record (private development evidence; not distributed).

## Internal cutover boundary

`apply_source_replacement` requires an unexpired, unrevoked exact mapping,
current new-source qualification, a persisted executor independent of the human
reviewer, and both initiating and current `alerts.sources.replace`, `alerts.read`
and material-read authority over both sources and every affected Situation.
`ICHECK_ENABLE_REVIEWED_SOURCE_REPLACEMENT=false` is the default. Only deployment
examples have been updated; no actual host execution gate has been enabled.

One transaction appends `collector_source_retirements`, links only the old active
Alert, recomputes affected Situation projections, and retains distinct events
and audit. The immutable receipt records executor authority, both state snapshots,
the old sealed-admission clock, accepted mapping and exact cutover receipts.
Measured Alert status, clocks, occurrence count and condition state are not
rewritten. Already-resolved episodes retain their measured resolution and need
no supersession link. New quiet sources need no synthetic Alert.

The target clock must cover both the old projected watermark and already-sealed
old admissions, including those still waiting for projection. Delayed old
observations receive a retained `retired` disposition without advancing the old
state or creating current evidence. PostgreSQL receipt writers check retirement
after the conflicting source mutex; lower source/origin contention fails fast.
Native commit checks require the supersession link, audit, all affected events
and complete Situation counts/clocks to commit together.

Current lists, dashboard counts, Agent open-alert reads, correlation and Situation
counts exclude superseded episodes. `/alerts?include_superseded=true` explicitly
includes retained history; measured status remains unchanged. A historical
retirement read checks both sources, both cutover receipts and every retained
Alert pointer under initiating and current read scope, without requalifying old
origin or requiring execution authority. Original retirement remains permanent
through later generation changes. A separate historical revalidation must
explicitly name that original retirement; it cannot retire the old source again.

Migration `f0h2j4l6n8p1` forces namespace RLS and append-only/native reference
guards. Upgrade requires all-namespace visibility and drained relevant ownership;
populated downgrade is refused. SQLite trigger preservation is exercised as
development portability, not production concurrency acceptance. No product
database migration, live cutover, exporter change or physical operation has run.
Final affected verification passes 281 ordinary cases and 397 migrated non-owner
PostgreSQL cases, including 66 retirement cases. The native run covers real
deployment/source waits and both producer/cutover orderings, raw forgery/RLS,
deferred incomplete-transaction refusal, repeated evolution, scoped historical
reads, drained migration and existing source/recovery/lifecycle/closure behavior.
One existing Starlette/AnyIO deprecation warning remains in each run. Fixture
database/role counts were `0|0`, the server stopped and its owned root was removed.
These are affected internal-service checks, not full-feature, frontend/live or
product rollout acceptance. See the
cutover verification record (private development evidence; not distributed).

## Evidence and authority

An exact source generation continues to identify its version, assignment,
credential revision, condition and entity. Updating code, credentials or Worker
ownership never aliases a new generation to an old source ID. The new source
needs its own [independent qualification](collector-source-qualification.md).
Replacement is an additional explicit equivalence decision, not inherited
qualification and not a substitute for fresh measurements.

The request retains the old source's qualified historical material, the exact
new source and its accepted qualification, both object identities, the normalized
condition predicate and an external validation reference. Old retained
admissions and receipts must match their historical source material without
requiring a retired Worker or credential to become current again. Revoked or
unqualified historical semantics cannot be silently laundered by replacement.

The normalized event/entity kind, predicate operator, expected value and unit
must agree. Titles and implementations may evolve; protocols need not match.
Entity correspondence needs independent identity validation. A different issue,
unit or threshold is a new condition or a separately governed reconciliation,
not an automatic equivalent replacement. Unknown/custom entity scopes remain
global unless an actual supported object ACL exists.

A different persisted human accepts the mapping, explicitly validating old
history, new identity, semantic equivalence and clock ordering. Current material
read and scope over both generations are mandatory. The requester cannot accept
its own declaration. A separate execution permission authorizes retirement;
review and execution remain distinct, with the executor independent of the
reviewer. AI may propose and execute an accepted control-plane intent under its
own current and initiating authority; it cannot manufacture peer attestation.

Approval is immutable, expiring and revocable. Retirement is an immutable fact
that does not disappear on later approval expiry/revocation. Revocation removes
future mapping/recovery authority, not old measurements, the completed takeover
or its audit. Re-enabling an old version cannot reactivate its retired generation;
a fresh generation needs fresh acceptance.

## Takeover and active episodes

Application rechecks current roles/snapshots, both source scopes, independent
review, new origin qualification and source freshness. The target generation
must be current, unretired and have a fresh accepted active or quiet observation.
Unknown/conflicting targets cannot take over. Its latest accepted observation
must cover the old generation's projected and already-sealed admission clocks; an older new quiet poll
cannot hide a later old active sample.

One atomic transaction records permanent retirement, the exact cutover receipt
and old condition watermark, the accepted mapping and executor, affected Alert
supersession, distinct lifecycle events and audit. A nullable retirement link
marks the old active episode superseded; original Alert status, first/last-seen
clocks, occurrence count and measured resolution clock remain intact. No quiet
receipt, synthetic Alert or false measured resolution is created.

| Takeover state | Current monitoring outcome | Recovery evidence |
|---|---|---|
| New source active | Old active episode is archived; the actual new active episode remains current | Not recovered |
| New source quiet with no Alert | Old active episode is archived without creating a new fake episode | Later qualified new-source quiet window can cover mapped old members |
| Old episode already resolved | Measured old resolution remains historical | New-source evidence still needs independent mapping and fresh sampling |
| New source unknown, conflicting, stale or older | No takeover or partial retirement | Fail closed with an explicit blocker |

Current open lists, dashboard/critical counts, Situation projections, impact
calculations and Agent open-alert Tools exclude superseded episodes consistently.
Historical pages retain and label them as superseded, not measured quiet.
Recomputed Situation status is still not independent incident-closure authority.
No physical device operation or exporter reconfiguration occurs in takeover.

Accepted but delayed old envelopes stay historical. Projection recognizes an
exact retired source from immutable sealed provenance before interpreting it
as current evidence, retains a distinct retired disposition, and never advances
condition state, reopens an old episode or produces a current Alert. Replays
return their original durable result. Missing/altered provenance cannot use
retirement as a validation bypass.

## Repeated evolution

A source has at most one permanent retirement. Later replacement generations
must themselves be unretired current sources; cycles and resurrection are
refused. Reusing an execution key with different material conflicts, while a
committed exact retry reads its unchanged historical result without replaying
retirement or needing still-valid execution authority.

Further evolution can independently revalidate an old historical source against
the latest current generation, retaining the original retirement fact. New
approval is explicit and bounded; expired intermediate mappings are not silently
treated as current authority. Historical retirement metadata and a new mapping
must not be presented as proof of an intermediate source's current validity.

## Recovery and closure integration

Internal recovery v2 is implemented separately from cutover, behind
`ICHECK_ENABLE_REPLACEMENT_RECOVERY=false`. New criteria explicitly name the permanent
retirement and accepted mapping review for each historical source, with the
target already present in the policy's current source bindings. An accepted
proposal without completed retirement cannot silently replace monitoring
authority. Initial mapping may name the applied review; later revalidation must
bind the same original retirement and the latest unretired target explicitly.

The complete sorted deployment prefix must include current and historical
binding sources before any lower origin locks. Every mapping, including one
unused by the current membership, needs exact namespace/lineage, current peer
scope, unrevoked acceptance and a bounded expiry no later than target source
qualification. Neither retired intermediate generations nor expired mappings
may be traversed as an implicit alias chain.

New proof shapes must distinguish direct-source evidence from mapped historical
active evidence, permanent retirement, accepted mapping and actual current quiet
receipts. Introduce an explicit compatible proof/protocol boundary rather than
placing new authority inside a v1 proof. Existing direct policies and committed
v1 receipts remain unchanged. Non-material recovery output should retain typed
references, not copy full Collector implementations or executor scope snapshots.
All direct, original/delegated Agent and report readers must authorize the added
references before new proofs can become closure inputs. The current service and
native grant guard explicitly reject using a v2 policy for incompatible v1
closure. This is a rollout barrier, not completion of closure integration.

A newly accepted recovery policy explicitly selects its current source bindings
and exact historical replacement reviews. Older policies gain no implicit
replacement mapping. Every referenced source/review is scoped and validated,
including bindings not represented by current Situation membership.

Members from a retired generation retain their original active receipts and
source identity. An accepted replacement maps those members to the new source's
actual quiet window. New quiet samples are neither copied into the old source
nor joined across generation boundaries to meet sample count/duration. Active,
unknown and conflicting new observations and excessive sample gaps reset the
new window under the existing recovery criteria.

The checker supports a quiet new source with no `latest_alert_id`: it verifies
its sealed current state and receipts directly instead of demanding a fabricated
episode. The implemented new quiet window begins after every mapped old active/last-seen
clock. The compatible closure slice must additionally select samples strictly
after every related action's terminal verification. Retired members must have exact
supersession/retirement provenance; simply editing status or deleting membership
cannot qualify coverage. Unmapped and unsupported members still block complete
recovery. Bounds must fail closed rather than clip to success.

Proof distinguishes historical active origin, retirement, accepted mapping and
new quiet origin. Fresh deadlines include current policy/source/mapping validity.
Reviewed closure remains a separate operation with its own grant and owned
transaction; neither replacement nor observed recovery grants closure or
establishes repair causality/automatic physical truth.

Historical receipts remain readable under their complete retained scope without
fresh origin or peer qualification. New proof/reference shapes require explicit
compatible schema/protocol handling and coordinated deployment. Old direct
receipts remain unchanged. Generic Agent caches, delegated Task results and
report attachments cannot bypass historical read authorization.

### Internal recovery v2 boundary

Policies add `proof_version` and `replacement_bindings`. V1 has no replacements;
v2 requires at least one exact `{old_source_id, retirement_id,
replacement_review_id}` binding. The target and its qualification come from the
immutable mapping request and must already appear in current `source_bindings`.
Original applied reviews may cover their own completed retirement. Later A→C
revalidation explicitly names the permanent A→B retirement; A→B→C is not an
implicit alias. All bindings are checked, including unused mappings.

The checker preserves old active receipt provenance and the permanent retirement
watermark. It groups direct and mapped members by their exact current target,
then counts only that target's distinct accepted quiet samples after every
member's active/last-seen clock. Unknown/active/conflicting samples and excessive
gaps reset the window. A newer sealed but unprojected admission blocks a stale
quiet state. A quiet target with no Alert is checked directly; no measured Alert
or source state is changed. Membership pins explicitly include retirement.

Proofs identify historical active source/qualification, retirement/mapping and
current quiet source/qualification/receipts separately and use
`peer_reviewed_source_recovery/v2`. They omit Collector implementation and
executor permission/scope snapshots. Ordinary scoped readers need `alerts.read`,
not material or execution permission. Qualification, mapping and policy peers
still need their actual current authority; withdrawal fails closed. Policy
detail and emergency revocation do not require fresh old origin, original peers
or an enabled execution gate.

Migration `g1i3k5m7o9q2` adds defaults without rewriting v1 policy/review IDs or
giving them implicit replacement authority. Native guards reject malformed or
unrelated bindings, retired targets, withdrawn roles/reviews and incompatible
v1 closure grants. They acquire the complete current/historical/cutover-target
deployment prefix before lower mutexes, refresh after waits and use wall-clock
expiry. The application additionally reattests exact current Worker/origin
material; the SQL binding guard is not standalone Worker attestation. Upgrade
requires all-namespace visibility and drained ownership; populated v2 downgrade
is refused. Only deployment examples have the new default-off flag; the actual
host and product database have not been changed.

The existing recovery-policy/detail/proof API can exercise this boundary with
the gate enabled in an isolated, authenticated fixture. This is not a new public
replacement apply endpoint or complete GUI/Agent/protocol rollout. Explicit
[v2 closure](reviewed-situation-closure.md) now provides compatible grants,
action-relative samples, typed retained references and a separate owned AI Tool.
Complete delegated/report integration, actual Worker-loss recovery, replacement
cutover full-feature acceptance and live/scale rollout remain required before
enabling the complete replacement feature. The public GUI/runtime implementation
is recorded in the 8 October workflow section below.

The preceding recovery-only affected ordinary verification passes 322 cases, including 41 replacement
recovery cases. The migrated non-owner PostgreSQL repeat passes 461, including
64 replacement recovery cases; a separately added populated-v1 upgrade case
passes too. These are 462 distinct affected native cases across two final runs,
not one 462-case or whole-product run. Native checks include actual waits,
withdrawn roles, wall-clock expiry, raw/RLS/append-only guards, repeated and
unused mappings, authenticated non-material API and existing closure/history
compatibility. One existing Starlette/AnyIO warning remains per run. Fixture
database/runtime-role counts reached `0|0`; the private server was stopped and
its owned root removed. No frontend/browser/live acceptance was repeated. See
the recovery v2 verification record (private development evidence; not distributed).

## Storage and transaction contract

Internal ledgers separate exact requests, independent acceptance, append-only
revocation and permanent retirement. Native references bind the full selected
namespace, source/review lineage, cutover state, superseded Alert and event/audit.
All retained material is immutable; only the guarded nullable Alert retirement
link changes once. SQLite supports development fixtures, not native concurrency
acceptance. PostgreSQL forces RLS and rejects forged references, mutable
retirement links, resurrection and destructive populated downgrade.

The short namespace writer fence precedes the complete sorted deployment set.
Old/new sources and states are acquired in a consistent order; lower origin
and proof locks fail fast before any Situation parent. Parents are locked last
and all mutable eligibility, scope and deadlines are rechecked after waits.
No lock is held while waiting for external I/O or a human review.

Native old-receipt writers and retirement share the source mutex. A writer must
check retirement after acquiring the conflicting lock and refresh after any
wait. A pre-lock snapshot must not permit an accepted sample to commit after
cutover. Retired observation receipts cannot change the accepted state or Alert
watermark. Either writer/cutover ordering has an explicit, testable result.

A new additive migration requires all-namespace visibility and drained relevant
API/Collector/Projection/Agent ownership before DDL. Deployment keeps the new
execution gate off until native migration and coordinated capability rollout
are accepted. It never deletes old data to make upgrade/downgrade pass. Existing
digests remain provenance references; this feature uses retained material and
ordinary comparisons, not a standalone SHA256 verification job.

## Operator and Agent surfaces

A focused source replacement page is linked from source acceptance and source
history, not added to the AI-first home. It separates bounded scoped discovery,
exact older-record lookup, proposal, independent review/revocation, explicit
application and historical read recovery. Candidates and accepted records never
claim fresh execution eligibility. Retry identities pin immutable submitted
material; namespace changes, role denial and operation generations erase stale
context and reject delayed responses. There is no browser host-gate control.

Runtime-owned Tools separate non-authorizing reads/proposals from reviewed
application. Reserved handlers, aliases, permissions, transport and Investigation
snapshot/binding cannot be overridden by a generated Tool registration. Durable
Tool-call identity owns exact retry behavior; a lost commit response recovers
the original retirement receipt without another mutation. No generic physical
action proposal, raw internal-handler call or external MCP wrapper substitutes
for runtime-owned retirement authority.

### Implemented public workflow — 8 October 2026

The source-qualification page links to
`/assets/condition-sources/{id}/replacements`; source and terminal detail are not
added to the AI-first home. Discovery lists are bounded, namespace-scoped and
explicitly non-authorizing. Exact target, qualification-review and request ID
entry supports records omitted from discovery. The page separates proposal,
independent human review, retained revocation, explicit permanent cutover and
historical receipt inspection. Successful cutover labels the old source retired
without changing its measured `active` or resolved history.

Public routes under `/api/v1` are:

- `GET /collector-condition-sources/{id}/replacement-workspace`
- `POST /source-replacement-requests`
- `GET /source-replacement-requests/{id}`
- `POST /source-replacement-requests/{id}/review`
- `POST /source-replacement-reviews/{id}/revoke`
- `POST /source-replacement-requests/{id}/apply`
- `GET /source-retirements/{id}`

Real bearer-authenticated routes use current persisted authority, initiating
scope and the existing independent-review/atomic-retirement services. Fresh
application requires execution permission and the default-off host gate; an
exact committed retry needs historical read authority, not fresh execution
permission, gate, origin or peer validity. A browser submission pins its request,
execution key and normalized reason after an uncertain response. Namespace
changes clear private state and reject delayed old-namespace responses. There
is no browser gate control or automatic incident closure.

Three additive builtins expose `collector_sources.propose_replacement`,
`collector_sources.get_replacement` and
`collector_sources.apply_reviewed_replacement`. The model supplies intent,
not runtime request/execution keys. Proposal and application use reserved
`agent-replacement-` identities derived from the durable Tool call; public API
clients cannot claim them. The runtime commits the domain fact before completing
the Tool journal, and an exact retry recovers it without another retirement.
Reserved handler/alias contracts cannot turn these writes into generic internal
execution or an external MCP substitute. Human review is deliberately not an
Agent Tool.

A bounded Agent loop can propose, pause for human acceptance, read fresh review
metadata with a new optional `check_key`, then explicitly apply. Replaying the
old read retains its historical pending result rather than silently claiming a
fresh approval. Original Investigation history authorizes immutable domain
references even after registry edits; that is not completion of delegated Task
or report reference handling. SQLite request read clocks are normalized to UTC
so committed proposal retry retains the same typed identity.

The final workflow passes 26 ordinary cases plus four builtin cases, and all
26 workflow cases in a freshly migrated non-owner PostgreSQL fixture with real
bearer authorization. Earlier affected backend and native retirement/replacement
regressions pass 205 and 121 cases at the preceding fresh-read boundary; these
are separate runs, not one full current-product suite. Frontend 41 helper cases,
typing, targeted lint and build pass. Controlled browser checks cover exact
lost-response retry, retained retired labels, narrow layout and namespace
privacy; responses are fixtures, not live-device evidence. Both private database
clusters and the isolated browser/frontend were cleaned up. No new migration,
product database write, actual host-gate enablement or integrated demo occurred.
See the public workflow verification record (private development evidence; not distributed).

### Implemented delegated recovery boundary — 8 October 2026

Runtime bootstrap and cached Tool replay now use the original Investigation
receipt-scope guard before exposing retained material. Replacement Task results
are checked against the immutable domain join, call identity, arguments, terminal
journal result and exact evidence bindings. Permission/snapshot narrowing denies
history even after a handler edit; withdrawn write authority or current origin,
peer and host gate does not invalidate an authorized historical read. Generic
completion cannot substitute an owned result after a committed domain write.
Read-only authorization transactions end before external model/checkpoint I/O.

Eight native fault cases kill both the real Worker and restricted API before
domain commit, after domain commit, after journal commit and after Task checkpoint
for proposal and application. A replacement Worker claims after natural lease
expiry and retains one exact call, domain fact and citation set. These tests assert
a nonterminal root checkpoint before takeover. Two subsequent actual Worker/API
SIGKILL cases separately cover loss after terminal root save but before execution
completion: the existing scheduler reconciles the durable terminal Investigation
once with no additional attempt, model or Tool call. Checkpoint-only completion
without a terminal Investigation remains fail-closed in two ordinary/native cases.
The final affected history/Worker/graph ordinary repeat passes 43 cases. See the
separate finalization record (private development evidence; not distributed).

Affected ordinary runs pass 77 broader cases and 33 final targeted cases. Native
runs pass 29 source cases and 16 retained compatibility/fence cases, 45 distinct
passes across separate boundaries rather than one full native-product suite.
The runtime recovery record (private development evidence; not distributed)
records failures, corrected native setup and cleanup. Report integration is still
unimplemented: the existing report contract contains service-indicator snapshots,
not retained replacement/closure proof references.

## Required acceptance

Completion requires ordinary affected tests, migrated non-owner PostgreSQL/RLS
and raw-SQL guards, real bearer API authorization, frontend typing/lint/tests/build,
and controlled browser journeys at desktop and narrow widths. Required cases
include active-to-active and active-to-quiet takeover, no new Alert episode,
resolved historical members, new-generation-only sampling, repeated evolution,
revocation/expiry, target/condition mismatch, role/snapshot narrowing, unknown
targets, contention and both producer/cutover orderings. Audit/event failure
must roll back retirement, supersession and projections together.

The eight implemented source-Tool Worker/API interruption cases prove no replay
at their nonterminal-root boundaries; two additional cases verify committed
terminal-root reconciliation separately. Remaining closure-Tool/production
transport loss requires its own acceptance. The additive retained-report v2
contract now explicitly binds replacement requests, retirements and closure
receipts to immutable reader admissions and exact foreign-key references.
Direct saved reports, attachments/exports and Agent proof/history readers check
current live-role and capture-time scope without renewing execution authority.
Its downstream delivery/archive/purge and sparse-scope/load acceptance remain
separate from existing metric-report checks. See the
report component record (private development evidence; not distributed).
Representative
sustained history/sparse-scope load and restart/drained rollout, production
identity/transport/secrets and live model/vendor/six-class GUI lab acceptance
remain separate product release gates. The integrated demo stays deferred until
implementation and required acceptance are complete.
