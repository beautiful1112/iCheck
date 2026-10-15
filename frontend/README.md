# iCheck operator interface

## Dependency cleanup — 14 October 2026

The frontend now declares eight runtime dependencies. The unused UI starter
components, D1/Drizzle notes example and placeholder SVG assets were removed after
tracing imports from all application routes, tests and build entrypoints. The
application uses the Python/PostgreSQL API; no product data lived in that empty
D1 schema. React DOM remains required by Next.js even without a direct app import.
Existing Sites/Vite/Wrangler development/build commands remain supported and their
dependencies are retained. The native production build and all 178 frontend tests
pass. See [the cleanup audit](../docs/repository-maintenance.md).

## Current redesign target

The [12 October goal](../docs/codex-goal.md) supersedes earlier frontend
priorities. Keep AI Operator; replace the complex Studio with a conversation-first
builder and library; remove Services and Service Intelligence; and send all
monitoring metric visualization to Grafana. Add authenticated dashboard links
from navigation, devices, alerts and AI results. Do not add another chart library.

See [operator navigation](../docs/operator-workspace.md),
[Studio UX](../docs/capability-studio.md) and
[Grafana integration](../docs/grafana-monitoring-design.md). This is the target,
not an implementation/deployment claim. The dated notes below are historical;
unfinished OAuth administration does not precede Grafana/Studio in the preview.

The home route is an AI L1 operator workspace: intent, investigations, evidence,
operational attention and human approvals. Device enrollment, endpoint IP/MAC
and Wi-Fi history, topology, workflow authoring and administration have dedicated
pages rather than occupying the homepage.

`/settings/ai` prioritizes guided OpenRouter onboarding: write-only masked key
entry, explicit endpoint approval, authenticated key/catalog health, compatible
model selection and atomic route setup. Advanced external-reference/provider
forms are collapsed by default. Key fields clear on submission and workspace
changes; no key is persisted in browser storage. Revision fences and explicit
replacement protect existing routes. See
[AI configuration](../docs/ai-provider-configuration.md) for backend custody and
the r8 deployment record (private development evidence; not distributed)
for synthetic desktop/mobile flows and separate live HTTPS verification.

The latest durable local backend (private development evidence; not distributed)
adds guarded start/read/execute endpoints beneath the attempt's
`family-recovery/local` URL. Dedicated MCP administration must show plan admission,
owned fence/deletion receipts and completion separately from reconnect eligibility.
History keeps original unknown outcomes and old-family uncertainty. Native API
acceptance passes, but this phase adds no frontend code/build or browser flow.
Conditional server adoption, governed Tool launch/pin replacement and the normal
administration/proof/retry/accessibility journey remain unfinished.

The preceding local Vault provider source (private development evidence; not distributed)
added no public completion API or frontend change. The dedicated MCP
administration page must eventually show issuer proof, admitted local plans,
owned operation receipts and completion separately from reconnect eligibility.
Original unknown outcomes and any old-family uncertainty remain visible.
The durable backend above now supplies local execution APIs. Conditional
server adoption and normal history/proof/retry/accessibility acceptance remain.

The exact transaction recovery backend (private development evidence; not distributed)
adds per-attempt start/read/confirm endpoints and public governed Tool pins.
The dedicated administration UI needs capability selection, exact public context,
separate approved action/verifier links and independent review. `issuer_verified`
does not mean local cleanup or reconnect is permitted. A historical row must not
disable another currently connected generation. Workflow launch/pin replacement,
normal proof/history/retry and accessibility acceptance remain open; no frontend
code or build changes are included in this source phase.

The preceding consent custody backend (private development evidence; not distributed)
adds bounded token-free generation history at
`/mcp/servers/{server_id}/oauth/consents`. The dedicated administration UI must
distinguish pending/unknown/compensation/stored-unpublished phases from connected,
superseded and local-revoked history. Acknowledged compensation is not independent
family proof; neither reconnect nor an older-generation recovery may bypass it.
That UI, proof links, conditional/retry and accessibility acceptance remain open.
This phase changes no frontend code/build and does not run a browser demo.

The preceding recovery authority source (private development evidence; not distributed)
rechecks live human credentials and grants at each recovery decision. Its
future administration UI must display retained pending/complete receipts and
permission-denial outcomes without accepting credential IDs or provider claims.
This backend-only phase adds no browser flow or frontend build.

The OAuth recovery backend source (private development evidence; not distributed)
now provides governed start/read/confirm APIs. Its administration UI and
proof/history are the next frontend work, separate from the L1 homepage.
Recovery needs approved containment, a separate verifier and a different human
reviewer; credentials and pasted “revoked” claims are not form inputs. R51's
frozen frontend is unchanged; no recovery browser acceptance is claimed yet.

## Requirements

- Node.js 22.13 or newer
- A running iCheck API for operational data. API failures remain unavailable or
  denied; the production UI does not substitute demo inventory.

## Development

```bash
npm ci
NEXT_PUBLIC_ICHECK_API_URL=http://localhost:8000/api/v1 npm run dev
```

## Native server build

The non-container server target uses Next.js standalone output. From this
directory, with the locked dependencies installed:

```bash
npm run build:native
npm run package:native -- --out /tmp/icheck-release/frontend
ICHECK_FRONTEND_PORT=3000 node /tmp/icheck-release/frontend/start.mjs
```

The output directory must not already exist. The package includes the server,
dependencies, static/public assets, release manifest and cache directory. The
manifest, server and assets must have the same build ID. Packaging rejects
environment files and escaping symlinks and never merges into an existing
release. The runner defaults to loopback and rejects public binding.

The default browser API URL is `/api/v1`, baked in at build time. A trusted TLS
ingress routes that path directly to the API and other requests to the frontend.
Do not put AI tokens or device credentials in frontend environment variables.
Rebuild to change the public API URL; the runner rejects a conflicting runtime
URL. A separate credential-free HTTPS API URL can be selected at build time,
with API CORS/session settings configured appropriately.

Use [the native release procedure](../docs/native-release.md) and
[the systemd template](../deploy/systemd/icheck-frontend.service) for installed
deployment. Starting the frontend alone does not establish API, identity, lab
or demo acceptance.

Native builds also check for links containing buttons and unnamed selectors.
The selector guard covers explicit ARIA names and label associations, including
conditional panels, but cannot establish rendered accessibility. Secondary text
uses light/dark surface tokens; contrast and naming regressions can be run with
`node --test tests/gui-accessibility.test.mjs` under the supported Node version.
Real authenticated Chromium checks remain a separate acceptance step.

Current r51 rendered qualification (private development evidence; not distributed)
shows “Active tool calls” and “No calls on active tools.” Native build
`3lcEZKmlYRXPPaGJjPeM7` passes build/typing/guards and 54 HTTP routes/77 asset
byte comparisons. Normal consent, revoke and fresh-generation reconnect pass
with packaged SQL-null clearance. Connected/final-revoked states have zero
automated violations/incompletes; the final full-page screenshot is inspected.
This adds no manual keyboard/mobile/full accessibility or Worker/Agent claim.
Private fixtures are cleaned up; installed r30 and full release/demo gates remain.

Earlier source SQL-null/summary qualification (private development evidence; not distributed)
changes the metric card to “Active tool calls” and “No calls on active tools.”
It does not change aggregation or retained history. One new wording regression
and scoped changed-page lint pass. Backend head `k8n0q2s4u6w9` repairs SQL-null
custody with populated PostgreSQL qualification. R50 still contains the old
label/storage semantics; a new native build/package and selected rendered
qualification remain. Full accessibility/native/lab/demo gates stay open.

The earlier r50 GUI record (private development evidence; not distributed)
qualifies separate consent and sourced Attestor/Agent receipt versions, plus
ready-to-expired aging without reload. Remove the redundant synchronous clock
setter inside the effect: asynchronous metadata load initializes it, subsequent
five-second ticks age receipts. The reproduced scoped lint failure is preserved;
corrected lint/native build/typing and 54 HTTP routes/77 byte-equal assets pass.
Native build `tTxAhNuREIMhR_T5VO2TV` uses Node 22.23.3. Two selected rendered states
have zero automated violations/incompletes; this does not clear manual/full
accessibility gates. Separate revoke/deactivation retains successful history;
the call summary is active-only and needs clearer wording. The packaged backend
JSON-null storage defect blocks release. Fixtures are cleaned up; installed r30
and the integrated-demo gate are unchanged.

The earlier r48 OAuth record (private development evidence; not distributed)
checks normal Vault-reference/server forms, consent, revocation, denied consent
and reconnect through the packaged API. Connected/revoked/provider-denied states
have zero automated violations/incompletes without exclusions. Actual Tab/Enter
reaches visible Revoke with a reviewed violet focus ring. No UI source/build/
regressions changed or were repeated; the r47 frontend is inherited. The browser
ignores only the disposable issuer's self-signed certificate; API/helpers use its
CA, and production browser TLS is not accepted. One issuer favicon 404 is recorded.
Private runtime, credential and database fixtures are cleaned up; inactive
candidate/stage artifacts are retained. Broader conditional/manual/mobile/assistive-
technology acceptance, recorded contrast incompletes and deployment/live/lab
gates remain. No integrated demo ran.

The later OAuth Worker journey (private development evidence; not distributed)
uses the same unchanged frontend. Normal GUI consent, publication, attestation,
activation and an exact-tool profile precede one packaged Agent read; revocation
then fences a fresh executor before remote I/O. A separate normal prompt
deactivates the retained canary. Completed/denied pages have zero automated
violations but retain two/one contrast incompletes; the revoked state has none.
Missing authoring-route admission and observer mistakes remain recorded, not
hidden by reruns. No UI code/build/regression suite is repeated. Broader/manual
accessibility, OAuth refresh/step-up/in-flight and deployment/live/lab gates remain.

The latest refresh journey (private development evidence; not distributed)
does not change or rebuild this frontend. Actual packaged Worker rotations to
Vault versions 2 and 3 succeed after natural expiry, but fresh server views still
display the original expired timestamp. SQL agrees: Worker-local refresh has no
summary reporting path. This is an open UI/data freshness defect, not accepted
expiry display. Add assignment-bound non-secret observations and show their
source/freshness separately from control-plane state; stale or revoked receipts
cannot create authority. The concurrent credential regression is also open.
Earlier accessibility limits are inherited, not rechecked or cleared. Private
fixtures are removed; the frozen candidate and demo gate are unchanged.

The later source coordination repair (private development evidence; not distributed)
passes focused concurrent/recovery/fencing checks without changing this frontend.
It is not included in r48. The source observation repair (private development evidence; not distributed)
now implements authenticated, generation-bound Worker metadata and separate
control-plane/observed expiry. The UI shows source/time/version plus stale,
expired or uncertain state on the five-second clock. Five focused helper cases
pass; the product API/lease/checkpoint handoff is source-qualified. A combined
frontend/backend/migration build and packaged normal browser journey remain.
The later PostgreSQL custody qualification (private development evidence; not distributed)
passes actual lock, containment, durable cleanup and data-bearing migration guards
with 40 native cases in a 58-distinct-case phase; these are not browser checks.
Its new source head is `j7m9p1r3t5v8`. Build the combined candidate and check normal
GUI refresh/freshness/quarantine/reconnect/revoke next. Cross-store/unknown-token
and legacy-intent recovery, step-up/in-flight, full accessibility and deployment/
live/lab gates remain; r48 and installed r30 are unchanged.

The earlier r47 execution record (private development evidence; not distributed)
checks publication separately from packaged Worker attestation/activation,
bounded read-only Skill/MCP Agent execution, promotion and deactivation. R47
repairs enabled activation contrast and live attestation freshness. A shared
exact server/version/status/expiry helper is checked at render, submit and
after a recovery prompt; a five-second clock clears expired evidence without
discovery refresh. Actual 15-minute browser expiry and enabled-control axe
checks pass. Twenty-five GUI source and three freshness-helper cases pass;
four unchanged r44 helper cases remain inherited. The completed Skill has
zero violations but five contrast-incomplete clipped nodes; full accessibility
and broader conditional/mobile/manual/assistive-technology checks remain open.
Private synthetic execution is not production identity/custody, native rollout,
physical device or live LLM acceptance. No integrated demo ran.

The earlier 10 October r47 recovery record (private development evidence; not distributed)
additionally checks blocked, freshly verified recovery-enabled and recovered
10% canary states: zero automated violations/incompletes with no exclusions.
Actual Tab/Enter on Re-attest and Recover shows visible focus and performs the
normal queue/approval mutations. Fresh evidence alone cannot close the circuit;
recovery needs explicit approval. An excluded run makes no call. The bounded
32-candidate GUI search found no eligible ID, so recovered success/promotion
remain open and the disabled promotion state is retained. No frontend code
changed or build/regressions repeated; the original Skill contrast incompletes
and broader conditional/manual/mobile/assistive-technology gates remain.
Private fixtures are cleaned up; this is not production or demo acceptance.

The subsequent recovered-canary record (private development evidence; not distributed)
checks the eligible recovered 10% call, separately enabled reasoned promotion
and normal deactivation. Promotion-ready and promoted states have zero automated
violations/incompletes without exclusions. The completed investigation has zero
violations but four contrast-incomplete nodes, retained for manual review.
Screenshots are inspected; no new keyboard or full accessibility claim is made.
No UI code/build/tests changed or repeated. The earlier unsuccessful search and
clipped Skill checks remain unchanged; broader conditional/manual/mobile/
assistive-technology, native/production/live/lab gates and demo deferral remain.

The earlier r46 richer-authoring record (private development evidence; not distributed)
checks actual GUI settings/file uploads, selected OpenAPI GET and fixed-SSH
sample validation/publication, and an unpublished MIB numeric-OID proposal.
Separate editor labels and concise upload names remain stable after file
selection. The named governance aside supports real Tab/PageDown/Home and
visible focus even with publication disabled. Twenty-three fresh GUI source
regressions pass; four replacement-helper cases remain inherited from r44,
not freshly run. The focused scrolled form/MIB states retain two/one incomplete
contrast nodes, while populated SSH validation and the MIB Home state have zero
automated findings. No rules are excluded; whole-product/mobile/assistive-
technology acceptance remains open. Publication is not activation, SSH dispatch,
external MIB attestation or live collection. No integrated demo ran.

The earlier r44 cutover/recovery record (private development evidence; not distributed)
checks explicit synthetic retirement, lost-response original-intent retry after
peer revocation, confirmed-receipt metadata-loss handling, reload-based history
recovery, real review expiry and historical revalidation without re-retirement.
R44 fixes bounded mapping-summary updates and adds live clock/identity guards.
A confirmed receipt remains history after a metadata error; it does not create
another uncertain intent. The populated retained receipt passes real
Tab/PageDown and axe, with expired-review and accepted-history states checked
separately. Twenty-one accessibility/authoring regressions and four replacement
helper cases pass. The cutover gate is fixture-only, not changed on the native
host. Richer authoring, full accessibility and installed/production/live/lab
acceptance remain gates; no integrated demo ran.

The preceding r43 source-governance record (private development evidence; not distributed)
checks normal qualification/mapping proposals, blocked self-review, scoped-peer
review and reasoned revocation. Revoked qualification cannot supply quiet
proof; history remains. Three populated evidence panels support actual
Tab/PageDown, named focus and zero automated findings. The fourth retained
retirement panel has a source guard only; permanent cutover/receipt/recovery
GUI remains open. The source has twenty accessibility/authoring regressions.
Synthetic account attestations do not establish physical truth, production
qualification or incident closure. Native/live/full accessibility gates remain.

The inherited r42 Wi-Fi data-path record (private development evidence; not distributed)
checks normal GUI controller enrollment, collector/policy publication, separate
approval and withdrawal. Actual packaged one-shot collection/projection stores
IP/MAC/controller/AP/SSID/RSSI; SQL, API and populated Endpoints agree. Success
and RSSI text contrast, and named verification evidence with real Tab/PageDown
scrolling, pass on rebuilt r42. Focused populated Devices/Endpoints have zero
automated violations or incomplete findings, not full accessibility acceptance.
That boundary has nineteen accessibility/authoring regressions. Synthetic loopback
acquisition does not replace production transport/native/live-lab acceptance.

The inherited remaining-type GUI record (private development evidence; not distributed)
adds synthetic Wi-Fi collector, service view, MCP tool and diagnostic Skill
generation/validation/publication. Named Studio history supports visible
keyboard focus and PageDown scrolling. Collector publication remains separate
from deployment, MCP publication from registry activation, and Skill publication
from Agent execution. The service view preserves UNKNOWN with zero samples.
The earlier populated GUI record (private development evidence; not distributed)
covers governed model/workflow/topology/report authoring with deterministic
loopback model responses and real API/database state. It records source guards,
current and predecessor browser checks separately, including remaining SVG,
small-label and transient-state observations. A new authoring form cannot
publish an old selected draft. Synthetic checks do not replace live-provider,
installed-service or physical-lab acceptance.

## Hosted build

The existing `npm run build` and `npm start` commands retain the Vinext and
Cloudflare target. They are not the native systemd server commands. Rebuild the
chosen target before packaging; do not combine outputs from different builds.

The dashboard registers one optional WebMCP action in browsers that support the
proposal: `acknowledge_alert`. It uses the same acknowledgement function as the
visible alert control.

