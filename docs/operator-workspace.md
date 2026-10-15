# AI L1 operator workspace

## Target preview experience as of 12 October 2026

Keep AI Operator as home: conversation, current task/progress, short findings,
and actions requiring human attention. Execution internals expand on demand.
Do not fill home with inventory tables, metric charts, schemas or services.

| Entry | Destination and responsibility |
| --- | --- |
| AI Operator | Conversation, investigation, findings and next action |
| Assets | Devices, enrollment, interfaces, IP/MAC and Wi-Fi history |
| Dashboards | Authenticated Grafana landing and contextual dashboard links |
| Alerts | Evidence, acknowledgement and start-investigation action |
| Capability Studio | Conversation-first builder and installed capability library |
| Activity | Investigation/run history and approvals, reusing existing routes |
| Settings | AI, monitoring connections, plugins, credentials and access |

Services and Service Intelligence leave navigation and supported routes. Remove
Services fetches from home/onboarding dependencies. Preserve alert/investigation
evidence using Situation storage; removing the business-service product does not
mean deleting incident history.

Metric charts open in Grafana. Device pages retain identity, collection settings
and freshness/status with **Open in Grafana** carrying target/time context. AI
answers contain findings and evidence links, not a second chart renderer.
Legacy `/visualizations` should show a Grafana destination or migration notice.

Use normal links/new tabs initially. Grafana has its own authenticated session;
explain the first sign-in and keep anonymous access off. Connection errors link
to Settings without blocking inventory/AI work. See the
[Grafana design](grafana-monitoring-design.md) and [Studio redesign](capability-studio.md).

Source changes now remove Services/Situations navigation and service-visualization
output intents. Home reads `/api/v1/operator/summary`, which counts scoped inventory
and source alerts without querying Situation or Service Catalog tables. Selecting
an alert seeds investigation context without requiring a Situation. Existing
alert, acknowledgement, investigation and historical APIs remain intact.

The Services route redirects to Assets; Situation root/detail/recovery/closure
routes redirect to Alerts; legacy metric visualizations open Grafana; old
visualization proposals redirect to Dashboard changes. No migration deletes
historical records. Inventory topology remains an evidence view, without the old
Situation context parameter. The simplified Studio is described in
[Capability Studio](capability-studio.md).

These source changes are not deployed. Dated contracts below describe the old UI
and retained backend behavior, not completion of the new engineer demo. Complete
target activation/fresh-metric and live AI acceptance remain required.

### v0.1 r10: root-cause and configuration repair

Escalated investigations now include **Root cause and proposed repair**, with
safe provider diagnostics, retained evidence count and a proposed configuration
repair link. This panel does not require a functioning model. Key health is not
model inference health. The guided AI page supports an opt-in inference/schema
test, explicit route replacement and dependency-aware module retirement.
**Retry original task after repair** starts a new scoped investigation under
current permissions; it preserves the original failure and never bypasses device
enrollment/activation approval. This first self-iteration path repairs model
configuration, not arbitrary trusted source code. See
[AI configuration](ai-provider-configuration.md) for the exact boundary.

The durable local recovery APIs (private development evidence; not distributed)
now expose admitted plans, owned operation receipts, completion and exact-family
containment time without private Vault references or credentials. The dedicated
MCP administration page must distinguish verified issuer proof and local cleanup
from a separate reconnect decision. Original unknown outcomes and old-family
uncertainty remain visible; completion must not offer a bypass. Operational Tool
launch/pin replacement, history/proof/retry UI and browser/accessibility acceptance
remain open. This backend phase changes no L1 homepage.

The local Vault provider protocol (private development evidence; not distributed)
added no administration UI or public completion endpoint. Future history
must distinguish retained issuer proof, an admitted local plan, an owned fence,
per-version deletion receipts, local completion and a separate reconnect
decision. Preserve the original unknown outcome and old-family uncertainty;
do not present provider completion alone as a connected credential or allow
pasted receipts to bypass server authorization. This remains dedicated MCP
administration work, not content for the L1 homepage.

The exact transaction recovery APIs (private development evidence; not distributed)
add a durable claim and selected governed containment/verifier pins under each
consent history row. The administration UI must show `awaiting_evidence` and
`issuer_verified` separately from completed local cleanup. Remote proof must
cover an exclusive transaction family; it must not imply broad client-wide
revocation, reconnect authority or resolution of an unknown original action.
Historical proof does not disable or delete another current generation. Pending
new attempts remain fenced until local finalization. The operational workflow
launcher, safe unavailable-pin replacement, proof links, retry and normal
browser/accessibility acceptance remain open. The L1 homepage is unchanged.

The new consent history API (private development evidence; not distributed)
retains generations and unresolved attempts without tokens or Vault paths.
The forthcoming MCP administration page must distinguish an admitted unknown
outcome, acknowledged compensation, an owned stored-but-unpublished receipt,
local replacement/revocation and independently verified family containment.
It must not offer reconnect or an old-generation recovery as a bypass. Normal
browser/proof/history and accessibility acceptance remain open; this source
phase changes no homepage or frontend.

The current recovery authority checks (private development evidence; not distributed)
enforce current credentials and grants on the server, including after lock waits.
The forthcoming administration flow must handle permission withdrawal without
offering a bypass or discarding a previously retained operation receipt. This
source phase adds no recovery browser flow and does not change the homepage.

The new recovery API source (private development evidence; not distributed)
does not yet add a browser recovery flow. That flow belongs under MCP
administration, with exact target context, approved containment/verifier links,
independent human review, pending cleanup and retained history. Do not add raw
credentials or recovery configuration to the L1 homepage. The UI must not accept
a pasted revocation claim, bypass corrupt/legacy evidence gaps, conflate recovery
with Tool activation, or reconnect without separate consent. Normal GUI,
conditional/retry/accessibility and packaged acceptance remain open.

Current r51 GUI clearance (private development evidence; not distributed)
renders the active-only summary explicitly and verifies normal consent, reasoned
revoke and reconnect. Actual SQL-null fields clear cleanup custody without
discarding generation history. No Tool or Investigation is created by consent.
The earlier Worker/Agent authoring flow is inherited at its own boundary, not
repeated or newly claimed here. Two focused rendered states pass; private
cleanup is complete. Unknown-family/legacy-intent recovery, remaining lifecycle/
policy, full accessibility and native/production/lab gates still prevent release.

The earlier source qualification (private development evidence; not distributed)
repairs SQL-null storage and explicitly labels the summary “Active tool calls.”
Seventeen focused checks pass, including actual populated PostgreSQL and hidden-
namespace guards. Source head k8 is not frozen r50 or installed r30; a new
combined candidate and packaged checks remain. No call history is erased, no
runtime authority is added, and full-design/native/accessibility/lab gates remain.

Earlier r50 GUI evidence (private development evidence; not distributed)
separates consent, conversational publication, packaged attestation, explicit
activation and a bounded Agent read with evidence. Worker receipts label their
source/version/time and expire without reload; they never replace consent or
grant authority. Normal revoke and separate deactivation retain successful
history. The fleet call summary covers active activations only and needs an
explicit label. Cleared OAuth custody persists as JSON `null` rather than SQL
NULL, incorrectly blocking the actual downgrade guard; repair and qualify a new
backend before release. Private fixtures are cleaned up, installed r30 is
unchanged, and broader/full accessibility/native/production/lab gates remain.

## Product role

The default iCheck route is an operator workspace, not a traditional monitoring
dashboard and not a general-purpose chatbot. A durable `Situation` is the
operational issue record and a durable `Investigation` is the AI reasoning
record. Conversation authors an objective; it is not the system of record.

The home screen answers five questions:

1. What outcome should the AI operator investigate next?
2. What is it investigating now, and is that execution making progress?
3. Which persisted evidence and tool calls support the current conclusion?
4. What uncertainty, approval, or collection gap requires a human?
5. Which alert situation should become the next investigation?

Raw endpoint lists, IP/MAC history, and Wi-Fi sessions remain in the dedicated
`/assets/endpoints` drill-down. Device configuration and protocol detail remain
in `/assets/devices`; bounded log evidence remains in `/logs`. AI provider and
model configuration remains in `/settings/ai`.

The shared browser shell puts a keyboard-only **Skip to main content** control
before navigation. Tab reveals it; Enter moves focus to the page's `main`
landmark, and the next Tab continues within main content. It applies to the
operator home and the other routes that use this shell. This bypasses repeated
navigation but does not establish full keyboard, screen-reader, focus-order or
contrast acceptance for every page.

The home brand link has an explicit **iCheck home** name; the icon-only return
link in Observability settings has an explicit **Back to AI operator** name.

On narrow screens, primary navigation is a modal Sheet with a linked title and
description. Closed navigation is absent from the tab order; open navigation
traps keyboard focus and hides the background. Escape, close and backdrop
dismissal return focus to the visible trigger. Expanding to desktop closes the
drawer and moves focus to the persistent desktop navigation. The
r22 authenticated browser check (private development evidence; not distributed)
covers these paths plus route navigation and real session sign-out. This is one
Chromium navigation slice, not whole-product accessibility acceptance.

Navigation actions styled as buttons render as one link, not a link containing
a second button. This applies to the Assets, Studio, Situation, Report and
settings routes. The frontend lint and native-build commands reject that
nested pattern if it is reintroduced. It does not substitute for a full
assistive-technology review of those pages.

Secondary text uses the `muted-foreground` token rather than pale, page-local
gray values. Light surfaces use `#536176`; explicit `data-text-surface="dark"`
containers use `#b8c3d4`. The desktop/mobile navigation, AI composer, dark
administration headers and topology canvas opt into that dark token. The
topology inspector remains a light surface. Normal-text contrast regressions
cover the declared light/dark backgrounds; gradients, overlays and populated
states still need rendered review.

MCP fields connect visible labels to unique control IDs, including conditional
OAuth fields and canary limits. Log query fields also have explicit label
associations. Other selectors receive an explicit accessible name, including
conditional service, identity, catalog and recovery controls. Native builds
run `check-accessible-selects.mjs`: a select must have an explicit ARIA name,
a matching label/ID or a wrapping label. This narrow source guard cannot verify
dynamic names, referenced ARIA text, rendered focus order or full WCAG compliance.
Catalog header navigation wraps instead of clipping its heading and actions.

Home distinguishes unavailable data from a verified empty result. While the
control plane is unavailable, counts remain unknown and neither worker status
nor Situations claim a healthy zero. Failed overview reads clear scoped material
and stop the displayed execution stream. Namespace/storage changes clear the
home selection and evidence and invalidate prior read generations; a delayed
old response cannot restore its old overview. These safeguards do not replace
server-side authorization or complete authenticated browser acceptance.

Home reads the current account's permissions before loading each data family.
Viewer and approver accounts can review authorized evidence without requesting
the Skill, Workflow, AI Profile or quota APIs that require additional access.
The objective composer is available only with `investigations.create`, and
cancellation requires `investigations.cancel`. An account with only
`investigations.read` can keep its evidence workspace connected while inventory,
Situations and Worker data remain visibly unavailable. The
r21 browser record (private development evidence; not distributed)
covers real required-auth PostgreSQL sessions for these three permission sets,
plus narrow-screen rendering and sign-out. Full accessibility and production
identity acceptance remain open.

## Legacy implemented information architecture

```text
/
├── objective composer
│   ├── create + start an autonomous durable investigation
│   ├── select a published diagnostic Skill + typed input
│   └── select a published manual Workflow + typed input
├── operational attention strip
│   ├── active investigations
│   ├── approvals waiting
│   ├── open/critical situations
│   └── known inventory/evidence coverage
├── selected investigation
│   ├── objective and execution status
│   ├── confidence, budgets, and attempt
│   ├── conclusion or escalation reason
│   ├── resumable live execution trace
│   ├── evidence ledger
│   ├── tool activity
│   └── explicit uncertainty
└── attention rail
    ├── collector workers, queue, and recent failures
    └── prioritized Situations that can seed a bound investigation

/investigations   status-filtered, keyset-paged durable investigation history
/assets/devices   device onboarding, activation, and runtime health
/assets/endpoints endpoint IP/MAC, wired attachment, and Wi-Fi controller state
/situations        prioritized issue queue and rapid evidence selection
/situations/{id}   canonical focused evidence, impact, review, and timeline view
/services          governed ownership, SLOs, components, and KPI evidence
/topology         published, live, scope-filtered topology views
/visualizations   published, scope-filtered service-indicator views
/reports          published deterministic service-health snapshots
/logs             bounded device-scoped or globally authorized Loki evidence
/settings/ai      providers, models, secret references, routing budgets
/studio/workflows published Workflow runtime, trigger/schedule activation,
                  Report binding, and durable outboxes
/studio?create=workflow  conversational governed Workflow authoring entry
/login            one-time bearer exchange into an HttpOnly browser session
```

Investigation history is a dedicated route rather than a scrolling list on the
AI L1 home. Home loads only the most recent authorized slice to select current
work; `/investigations` supports status filtering and stable keyset pagination,
and each row opens the persisted trace in the operator workspace. The API
rechecks the caller's namespace and object scope for each page and cursor;
revoked access cannot reuse an old cursor. The legacy bounded-list route remains
for existing clients. A history page may scan past hidden rows to fill an
authorized page, so production-scale sparse-scope latency still needs a load
gate. Topology and service visualizations are dedicated evidence surfaces rather
than dashboard blocks on the AI L1 home. They run immutable published selector
contracts against current inventory or normalized indicator history and apply
the caller's object scope. Workflow runtime administration
is also a dedicated route; its activation and outbox controls are intentionally
not placed on the home. Schedule administration may bind one exact visible
Report version to a governed MCP delivery Workflow; current scoped values are
generated only at each occurrence. Its outbox shows an immutable provider
receipt only after the governed Workflow has completed with validated producer
and subsequent post-check execution evidence and no rollback. Dispatch is
displayed separately from verified delivery; legacy receipts retain an
unverified label. Situation selection can bind the objective composer,
open the stable `/situations/{id}` evidence URL, or create and start a scoped
Investigation. The AI L1 home keeps separate controls for seeding an
Investigation and opening focused evidence so navigation never silently starts
work.

Situation `resolved` currently describes the correlated Alert-state lifecycle,
not independent proof that the AI's original purpose succeeded. Manual and
all-Alert-state timeline events now expose their distinct `resolution_basis`
and explicitly deny independent verification and AI closure authority. The
existing UI keeps its ordinary lifecycle rendering; a separate proof/review
surface for immutable verified-closure receipts is planned, not delivered by
this backend-hardening slice. Do not infer it from a green status, an Agent
conclusion, an outcome-health score or successful restoration.

## API contract

The workspace consumes existing control-plane APIs; it has no UI-only execution
state:

| Purpose | API |
|---|---|
| Create an investigation | `POST /api/v1/agent/investigations` |
| Run a published Skill | `POST /api/v1/skill-runtime/skills/{version_id}/investigations` |
| Run a published Workflow | `POST /api/v1/workflow-runtime/workflows/{version_id}/investigations` |
| Start and enqueue it | `POST /api/v1/agent/investigations/{id}/start` |
| Select recent work | `GET /api/v1/agent/investigations/page?limit=30` |
| Browse durable history | `GET /api/v1/agent/investigations/page?limit=50&status={status}&cursor={id}` |
| Read execution ownership/status | `GET /api/v1/agent/investigations/{id}/execution` |
| Read durable product trace | `GET .../{id}/checkpoints`, `/evidence`, `/tool-calls` |
| Read/reconnect execution trace | `GET /api/v1/agent/executions/{id}/events` and `/events/stream` |
| Stop active work | `POST /api/v1/agent/executions/{id}/cancel` |
| Prioritized situations | `GET /api/v1/dashboard/summary` |
| Situation queue | `GET /api/v1/situations` |
| Situation evidence/timeline | `GET /api/v1/situations/{id}` |
| Situation impact context | `GET /api/v1/situations/{id}/impact` |
| Situation hypotheses | `GET /api/v1/situations/{id}/hypotheses` |
| Governed impact proposals | `GET /api/v1/situations/{id}/impact-assessments` |
| Review AI proposals | `POST .../{proposal_id}/accept` or `/reject` |
| Governed service facts | `GET /api/v1/services` and `GET /api/v1/services/{id}` |
| Service indicator evidence | `GET /api/v1/services/{id}/indicators` and nested `/observations` |
| Acknowledge or resolve | `POST /api/v1/situations/{id}/acknowledge`, `/resolve` |
| Collection gaps | `GET /api/v1/collectors/health` |
| Projection gaps | `GET /api/v1/knowledge-projections/health` |

| Agent capacity | `GET /api/v1/agent/workers` |
| Published topology views | `GET /api/v1/topology/views` |
| Scope-filtered current topology | `GET /api/v1/topology/views/{artifact_id}/render` |
| Situation-focused published topology | `GET .../render?situation_id={id}` |
| Published service visualizations | `GET /api/v1/visualizations` |
| Scope-filtered visualization render | `GET /api/v1/visualizations/{artifact_id}/render` |
| Published service-health reports | `GET /api/v1/reports` |
| Scoped deterministic report snapshot | `GET /api/v1/reports/{artifact_id}/generate` |

The live execution stream uses the selected tenant and region in EventSource
query parameters because native EventSource cannot set custom headers. Its
browser wrapper rejects an event if the session or namespace changed after
connection and closes open streams when that context is invalidated. Durable
execution events remain the source of truth after reconnect.

SSE starts after the greatest persisted event sequence already loaded. The UI
deduplicates by event ID, updates graph-node progress as it arrives, and refreshes
the durable product state after graph and terminal events. The persisted event
feed, not model prose, is the progress authority.

## Truthful empty and failure states

The previous home page included representative endpoint, alert, device, and
coverage values when no API URL was configured. That behavior has been removed.
The workspace uses `NEXT_PUBLIC_ICHECK_API_URL`, defaulting to the local API
address for development, and reports the control plane as unavailable if reads
fail. Empty inventory, zero workers, no evidence, and no alerts are shown as
real empty states. They are never replaced with demo data.

An investigation may legitimately exist in `pending` state without an execution;
the UI treats the execution endpoint's `404` as that domain state rather than a
workspace failure.

## Safety boundary

Service reports remain in the dedicated `/reports` inspection workspace. It
distinguishes live preview from exact-version fresh capture and retained
historical snapshots; capture time and the separate snapshot/Artifact hashes
are visible. Scoped keyset history and authenticated PDF/HTML/CSV/JSON exports
reuse saved values, recheck current ownership/provenance/integrity, and verify
downloaded bytes before saving. Historical capture scope is explicitly labeled
as historical, not current authorization. Retention is no automatic deletion;
export is not delivery proof, and downloaded files cannot be revoked later.
See [service-health reports](./service-health-reports.md).

- The browser uses a short-lived HttpOnly session and rotating CSRF token.
  Client-supplied actor labels are ignored in required-auth mode; provider
  credentials and infrastructure credential values never enter the page.
- Autonomous and Skill projections are read-only. A Workflow may reference a
  state-changing tool only through its statically validated approval,
  post-check, and rollback graph; execution still interrupts on the exact plan
  and requires four-eyes authorization.
- Cancellation is cooperative for running work and immediate for queued work;
  both paths are persisted and audited.
- Confidence and uncertainty are displayed separately. A conclusion without
  evidence does not become authoritative because it is rendered by the UI.
- Topology and service-visualization output intents create evidence-bound,
  authorization-scoped proposals. Their dedicated review pages require a
  reasoned global human publish before an immutable Artifact becomes live.
- Collector and Knowledge Projection health are shown as Worker, queue, lag,
  retry, failure, and dead-letter counts; the UI does not invent a percentage
  coverage score.

## Verified and remaining

Earlier GUI boundary: r48 (private development evidence; not distributed).
The OAuth journey (private development evidence; not distributed) verifies normal
reference/server creation, consent, upstream revocation, denied consent and
reconnect after soft deletion. R48 reads the exact Vault metadata version for
CAS; metadata denial/malformed replies and races fail closed without retry.
OAuth alone creates no attestation, Tool activation or Agent run. Three focused
states have zero automated findings; actual Tab/Enter Revoke focus is reviewed.
Private runtime, credential and database fixtures are cleaned up; inactive
candidate/stage artifacts are retained. Packaged OAuth refresh/step-up/in-flight,
broader GUI/accessibility and deployment/production/live/lab gates remain.

The later OAuth Worker journey (private development evidence; not distributed)
and handoff readiness addendum (private development evidence; not distributed)
qualify separate normal GUI publication, packaged Vault-backed attestation,
reasoned activation and one exact pinned Agent read/citation. After reasoned
OAuth revocation, the retained tool is still advertised but its fresh executor
rejects current OAuth state before Vault/MCP I/O. One failed attempt, no evidence
and the fixture's subsequent reason failure remain; separate deactivation removes
registration authority. Three private one-shots exit zero and cleanup passes.
Completed/denied contrast incompletes and wider accessibility remain gates.
Refresh/step-up/in-flight and production/native/lab are not accepted.

The latest refresh journey (private development evidence; not distributed)
and current addendum (private development evidence; not distributed)
verify serial Attestor/Agent refresh after real expiry on unchanged r48. One
pinned Agent read completes; normal revocation/deactivation and cleanup pass,
and the original loss alert explicitly remains OPEN. Fresh views still show
the old token expiry: Worker-local rotation is not reflected in control-plane
summary state. Add non-secret authenticated, assignment-bound observations with
clear provenance/freshness; neither a Worker receipt nor the displayed expiry
may confer OAuth/Tool authority. The retained concurrent refresh failure also
requires distributed coordination before issuer redemption. At that packaged
boundary neither repair is implemented. This does not clear broader GUI/full accessibility, step-up/
in-flight/recovery, native/production/live/load or physical-lab gates.

The current source coordination repair (private development evidence; not distributed)
and latest addendum (private development evidence; not distributed)
qualify exact-key reservation before redemption, durable uncertainty and
version-targeted revocation/compensation with 80 distinct focused passes.
Neither the frozen r48 GUI nor installed r30 contains it. The source observation record (private development evidence; not distributed)
and its readiness addendum (private development evidence; not distributed)
now qualify Provider/Attestor/Agent non-secret receipts and assignment-bound
generation/profile handling, plus consent/revoke metadata fences. Eighty-five
distinct focused checks pass. The UI separates control-plane expiry from sourced
observed freshness and labels stale/uncertain/unavailable metadata without granting
authority.

The PostgreSQL custody record (private development evidence; not distributed)
and current addendum (private development evidence; not distributed)
qualify 58 distinct source checks, including actual migrated non-owner lock waits,
current worker/profile containment and durable original-target cleanup after
profile edits or pre-I/O process loss. Missing legacy cleanup custody requires
administrative recovery; receipts and cleanup intents grant no execution authority.
The private database is stopped. Package the combined source and check its normal
GUI lifecycle/freshness next; frozen r48 and installed r30 contain none of these
repairs. Unknown-token/cross-store and legacy-intent recovery, step-up/in-flight,
live issuer/Vault and the original platform/deployment/accessibility/physical-lab
gates remain.

Earlier GUI boundary: r47 (private development evidence; not distributed).
The execution record (private development evidence; not distributed) checks
normal GUI publication without runtime authority, separate packaged Attestor
evidence and explicit activation, bounded Skill/Agent loops, MCP canary
promotion and deactivation. The Skill produces typed output with actual retained
citations; the MCP Agent calls one synthetic HTTPS read. Promotion requires the
persisted success gate. Deactivation removes the tool from the eligible catalog;
the next run escalates without a call. R47 fixes enabled activation contrast and
real-time freshness. The five-second clock and exact submit/post-prompt guards
disable expired activation/recovery; actual browser expiry needs no refresh.
Completed-Skill clipped contrast checks remain incomplete; broader MCP/GUI and
production/native/live/lab acceptance remain gates, not implied by this fixture.
The private harness requires only `--authoring-fixture --execution-fixture`,
rejects rich/collector/condition mixtures and bounds both completions and MCP
requests. Explicit SIGUSR1/SIGUSR2 dispatch packaged Attestor/Agent once after
GUI queueing; no native service is enabled. Fixtures retain only public decision
summaries and MCP method names, not prompts, headers, secrets or arguments.
Initial fixture failures and cleanup are preserved in the record; no demo ran.

The earlier 10 October recovery increment (private development evidence; not distributed)
keeps r47 unchanged. Optional `--execution-fail-first-mcp-call` requires the
separate execution fixture and injects one failure only on the exact synthetic
read; schema attestation remains available. The fixture retains public MCP
method/status outcomes, not headers or arguments. Seven new cases have terminal
passes across corrected segments, with original test failures retained.

The actual failed call opens the circuit, disables the Tool and produces a
critical alert/audit. A blocked run has no eligible Tool and makes no call.
Actual keyboard Re-attest queues fresh packaged Worker evidence; passing it
does not itself enable Tool execution or close the circuit. After refresh,
the normal Recover prompt needs a separate reasoned approval, consumes the
fresh evidence and restores a 10% canary. Only the circuit alert resolves;
failed-call history and the original loss alert remain. An excluded cohort run
has zero calls. A bounded search of 32 additional normal GUI-generated IDs found
no eligible candidate; normal Stop cancels each before claim. Promotion stays
disabled, with recovered success/promotion explicitly unverified. Three focused
states have zero automated findings and visible actual Tab/Enter focus. Cleanup
deactivates the fixture Tool and removes all private runtime/credential/database
resources. Broader OAuth/fleet/in-flight and native/production/lab gates remain.

The subsequent recovered-canary evidence (private development evidence; not distributed)
closes the selected eligible 10% success/promotion gap in a fresh GUI replay.
The thirteenth generated candidate is eligible, eleven are stopped unclaimed,
and an excluded run makes no call. The actual packaged Agent completes two
decisions, one exact-version MCP call and one retained evidence/binding. Only
then is Promote 100% enabled; its separate reasoned approval returns HTTP 200.
Normal deactivation follows. The original loss alert stays open, failed history
remains and no incident-closure receipt exists. All private resources are removed.
Promotion-ready/promoted MCP states have zero automated findings; four completed-
investigation contrast incompletes remain for manual review. No new source/build/
tests/native changes or demo occurred. This is not representative fleet,
production custody/mTLS, live-model/device or full accessibility acceptance.

Earlier richer-authoring boundary: r46 (private development evidence; not distributed).
The richer-authoring record (private development evidence; not distributed)
checks local file uploads, selected read-only OpenAPI GET generation, bounded
fixed-SSH sample mapping, explicit publication and a non-publishable numeric-
OID MIB proposal. The MIB gate still requires external compilation, installation
and live-device validation. Publishing the other drafts does not activate or
execute them. Refinement/version preservation and negative OpenAPI checks were
performed on r45; three core modes are freshly replayed on r46. Stable editor/
upload names and the named governance aside support actual keyboard focus and
scrolling. Scrolled-state contrast incompletes remain recorded; no full
accessibility, live-model/device, native rollout or demo claim is made.
The private deterministic model requires explicit `--authoring-fixture` and
`--rich-authoring-fixture`; it rejects collection/condition combinations and
unknown/mixed inputs. It never enables automatic collection or execution.

At the earlier r44 boundary,
The cutover/recovery record (private development evidence; not distributed)
checks an explicit synthetic retirement, original-intent retry after response
loss and peer revocation, confirmed receipt preservation when its following
metadata read fails, reload-based history recovery, real review expiry and
consented historical revalidation. The retained receipt is keyboard-scrollable
with named visible focus and zero automated findings. Expired-review and
accepted-history states have zero automated findings. Mapping summaries update
after exact reads without a manual discovery refresh. The five-second clock
guard disables expired review/apply; fresh execution requires an independent
executor. An uncertain intent stays pinned; a confirmed receipt is read-only
history and cannot become a new intent after a metadata error. Historical
revalidation binds the original retirement and cannot retire the source again.
Synthetic account attestations do not establish physical truth or closure.

At the preceding r43 boundary,
The source-governance record (private development evidence; not distributed)
checks source/mapping proposals, author self-review fences, scoped-peer review
and revocation through normal required-auth controls. Revoked qualification
cannot supply quiet proof; measurements and review history remain. Three
expanded evidence regions support actual Tab/PageDown with visible focus and
zero automated findings. Source-retirement history has a source guard only;
permanent cutover/retained receipt/recovery GUI remains unaccepted. Controlled
peer account attestations are not physical validation or closure authority.

The inherited Wi-Fi data-path record (private development evidence; not distributed)
checks normal controller enrollment/authoring/publication, separate policy
approval, actual explicit one-shot collection/projection, SQL/API/Endpoints
fields and due-after-withdrawal dispatch. Verification evidence is a named
keyboard-scrollable region; populated RSSI and success text remain readable.
This synthetic acquisition/storage does not qualify physical devices or native
services. The inherited
remaining-type record (private development evidence; not distributed)
covers basic collector/view/MCP/Skill generation, validation and publication;
earlier populated evidence (private development evidence; not distributed)
retains workflow/topology/report/Situation and AI settings checks. Candidate
boundaries are explicit; the historical slice below is not a full-product claim.

Authoring preserves a separate explicit human Publish action. Opening a new
capability form disables publication of the previously selected draft; Cancel
returns to its review. Generation and validation never imply publication or
device execution. Missing indicator samples remain UNKNOWN. Provider health
only establishes a configured endpoint response, not model-quality acceptance.

Published collectors still require a separate activation policy/deployment.
Published MCP contracts remain outside the callable registry until separately
attested and activated. Diagnostic Skill publication records its read-only
dependencies and hard budgets; it does not execute the Skill. Populated Studio
history is a named Authoring conversation region: Tab focuses it, visible
keyboard focus remains, and PageDown scrolls its contents.

Interactive topology is a named group with independently named node buttons,
full operational labels, selected state and visible keyboard focus. Enter or
Space selects; Space does not scroll the page. The selected-node description
list contains one-level term/value pairs. Service icon actions remain named
even while disabled. These contracts have source regressions and focused real
Chromium checks, not complete assistive-technology certification.

`acceptance/serve_private_authenticated_browser.py --authoring-fixture` adds
registered built-in tools and a clearly synthetic alert in its generated private
database, and serves bounded deterministic loopback completion contracts. Use
its emitted endpoint/model in the GUI; no browser API interception is required.
This option explicitly enables the private Landlock/seccomp authoring sandbox
for generated collector validation, with network access denied. It does not
enable native services, collector dispatch or automatic actions.
The fixture removes inherited HTTP proxies, stores only completion contract
names, and stops its children/removes tokens and generated databases/roles on
termination. It does not execute an Agent loop, collect from a device or accept
a real LLM. Normal physical-lab GUI/systemd acceptance remains separate.

The separate `--condition-fixture` option creates two synthetic source
generations through actual packaged Worker registration/admission/sealed
condition envelopes and one explicit packaged Projection invocation. It does
not contact a device, invoke a Collector adapter/model, retire a source or close
an incident. Its review-only peer is bound to the fixture site; the emitted
`source-peer-token` path refers to an owned mode-0600 file, never a printed
token. Synthetic references must stay in the controlled-fixture environment.
This option leaves permanent cutover and automatic actions disabled, caps helper
API requests at eighty, uses the selected package's explicit namespace and
removes operator/registration/peer token files and generated database roles
when the fixture terminates. These fixture guarantees do not accept production
SQL roles, transport, independent physical attestations or a device lab.

Adding `--condition-cutover-fixture` requires `--condition-fixture` and cannot
be combined with model-authoring or collector fixtures. It selects old active
and target quiet measurements and enables reviewed replacement only inside the
generated private API; seeding itself performs no retirement. A normal GUI
proposal, scoped peer review and explicit author Apply are still required.
`--lose-first-cutover-response` then truncates one actual committed Apply
response. `--lose-first-cutover-refresh` optionally truncates one actual mapping
read only after a successful receipt has been delivered. Both require the
explicit cutover fixture and fabricate no API result or database write.
They exercise separate uncertain-intent and confirmed-history recovery paths;
their retained receipt is not a repair or incident-closure receipt. The native
host gate and all automatic actions remain unchanged. Public shutdown metadata
records only response counts and exact request/receipt IDs, never tokens,
headers, reasons or execution keys. All private token/database/child cleanup
rules above still apply. This does not authorize native deployment.

Adding `--collector-fixture` requires `--authoring-fixture`. It serves a bounded
synthetic loopback HTTPS controller and emits two explicit signal operations:
`SIGUSR1` runs the selected packaged Collector once; `SIGUSR2` runs Projection
once. Each handles at most one assignment/preflight or projection batch; the
fixture admits at most six sequential requests and terminates overdue work.
Nothing dispatches automatically. Configure the emitted HTTPS port, site
`BROWSER-FIXTURE` and URL in normal GUI forms, then separately publish the
collector/policy and approve the verified device. Preflight is TCP reachability,
not authentication proof. The collector allows only loopback and trusts the
fixture's private CA without disabling TLS verification. Check actual run,
projection and persisted endpoint state after each child exits; exit zero alone
does not establish success. This option adds collection but not a demo or native
service, and its control-plane ingress is isolated HTTP, not production TLS/mTLS.
Cleanup also removes the temporary registration token and synthetic CA/key.

Verified for this slice:

- frontend lint under Node 22;
- isolated real-browser acceptance of a direct `/situations/{id}` load,
  queue/detail round-trip, accessible navigation, five bounded read-only
  Situation API requests, and no implicit Investigation creation;
- production Vinext build including `/`, `/situations`,
  `/situations/{id}`, `/approvals`,
  `/assets/devices`, `/assets/endpoints`, `/logs`, `/settings/ai`,
  `/studio/workflows`, and `/topology`;
- backend execution lifecycle, cursor event reads, SSE resume, cancellation,
  worker completion, graph checkpoint/resume, Skill restrictions, Workflow
  fixed/agent-loop execution, and alert-trigger idempotency tests.
- Knowledge Projection Worker availability, active queue, oldest ready age,
  hourly completion, retry, and dead-letter signals without exposing raw
  envelope payloads.
- deterministic, bounded Situation impact paths, schema-validated Agent Tool
  access, and Situation-focused rendering through immutable published topology
  contracts.
- persisted evidence-linked hypothesis confidence history plus strict,
  authorized-node-bound service-impact proposals with reasoned human review.
- revision-checked service ownership, criticality, SLO/RTO/RPO, scoped
  components, Situation graph edges, and immutable proposal snapshots.
- freshness-aware operational/business indicator evidence with deterministic
  thresholds, durable Situation edges, immutable assessment snapshots, and a
  dedicated Prometheus polling configuration/run-health surface.
- governed generic API/business evidence through exact published Collector or
  schedule Workflow versions, with schema-checked Tool mappings, first-class
  provenance, and no unrestricted HTTP scheduler.

Still required before production acceptance:

- enterprise OIDC/trusted-proxy federation onto the implemented session;
- live PostgreSQL worker process-kill/restart/resume acceptance;
- live-provider and real-lab end-to-end browser acceptance;
- broader dependency discovery and richer investigation-generated
  visualization types beyond the governed topology
  proposal contract;
- accessibility and browser compatibility review with representative data
  volumes.
